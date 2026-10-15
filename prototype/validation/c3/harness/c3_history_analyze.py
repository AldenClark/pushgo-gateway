#!/usr/bin/env python3
"""Arithmetic/dbstat reduction of existing C3 receipts; no benchmark execution."""
import argparse,csv,json
from pathlib import Path

def stats(d):return {x['name']:x['bytes'] for x in d['dbstat']}
def delta_cost(cold,active,names,n):
    a,b=stats(cold),stats(active)
    return {k:(b.get(k,0)-a.get(k,0))/n for k in b if names(k)}
def ismsg(k):return k=='messages' or k.startswith('messages_') or k.startswith('sqlite_autoindex_messages_')
def istarget(k):return k=='targets' or k.startswith('targets_') or k.startswith('sqlite_autoindex_targets_')
def csvwrite(path,rows):
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def run(a):
    out=Path(a.out);scale=json.loads((out/'native-scale/history-results.json').read_text());width=json.loads((out/'native-width/history-width-results.json').read_text());layout=json.loads((out/'layout/fanout-body-results.json').read_text())
    identities=[]
    for c in width['cases']:
        costs=delta_cost(c['cold'],c['before_delete'],ismsg,c['rows']); table=costs.pop('messages')
        identities.append({'op_bytes':c['op_id_bytes'],'order':c['identifier_order'],'rows':c['rows'],'table_B_per_message':table,'index_B_per_message':sum(costs.values()),'total_B_per_message':table+sum(costs.values()),'free_pages_after_delete':c['after_delete']['freelist_count'],'free_pages_consumed_by_reinsert':c['free_pages_consumed_on_reinsert'],'db_growth_on_reinsert_B':c['after_reinsert']['physical']['db_bytes']-c['after_delete']['physical']['db_bytes']})
    target=scale['active_fanout'];target_cost=delta_cost(target['cold'],target['active'],istarget,target['recipient_rows']);target_total=sum(target_cost.values())
    projections=[]
    for rate in [1,64,128,256]:
        n=rate*30*86400
        for op in [16,46,128]:
            costs=[x['total_B_per_message'] for x in identities if x['op_bytes']==op]
            projections.append({'messages_per_second':rate,'days':30,'identity_messages':n,'op_bytes':op,'identity_GB_low':n*min(costs)/1e9,'identity_GB_high':n*max(costs)/1e9})
    active=[]
    for rate in [1,64,128,256]:
        for days in [7,30]:
            n=rate*days*86400
            for fanout in [1,16,32]:
                active.append({'messages_per_second':rate,'hold_days':days,'active_messages':n,'fanout':fanout,'target_rows':n*fanout,'target_GB':n*fanout*target_total/1e9,'shared_448B_GB':n*448/1e9,'shared_1KiB_GB':n*1024/1e9,'shared_4KiB_GB':n*4096/1e9})
    csvwrite(out/'identity-costs.csv',identities);csvwrite(out/'identity-30d-projections.csv',projections);csvwrite(out/'active-fanout-projections.csv',active)
    operations=[]
    for s in scale['stages']:
        operations.append({'seeded_rows':s['seeded_identity_rows'],'actual_rows':s['disk_after_truncate_checkpoint']['identity_rows'],'db_bytes':s['disk_after_truncate_checkpoint']['physical']['db_bytes'],'status':s['status'],'duplicate':s['duplicate'],'new_admission':s['new_admission']})
    result={'scope':'Measured local synthetic SQLite plus explicitly arithmetic extrapolations; no soak or sustained throughput acceptance','native_provenance':json.loads((out/'execution.json').read_text()),'python_layout_provenance':{k:v for k,v in layout.items() if k!='cases'},'identity_costs':identities,'target_dbstat_B_per_target':target_cost,'target_total_B_per_target':target_total,'identity_30d_projections':projections,'active_fanout_projections':active,'native_operations':operations,'native_gc':scale['gc'],'native_after_accept_ack':[{k:x['disk_after_truncate_checkpoint'][k] for k in ['identity_rows','target_rows','logical_payload_bytes','sqlite_version']} for x in scale['stages']],'python_layout_cases':layout['cases']}
    (out/'analysis.json').write_text(json.dumps(result,indent=2)+'\n')
    lines=['# C3 final synthetic history/storage evidence','','Contract: full30-day identity retention with no identity count/byte quota and no early eviction. ACK/completion releases shared body and queue targets; compact identity persists until retention. Consequently there is no fixed hard-disk ceiling.','','Provenance: see execution.json for frozen source/tree and native binary hashes, first-run exit status, commands and runtime binding. schema_version=1 is the prototype manifest value; layout/schema.sql is the verbatim schema. Python supplemental SQLite version: '+layout['sqlite_version']+'. Native SQLx SQLite version: '+scale['cold']['sqlite_version']+'.','','## Measured compact identity + indexes','','|op bytes|order|table B/message|index B/message|total B/message|','|---:|---|---:|---:|---:|']
    for x in identities:lines.append(f"|{x['op_bytes']}|{x['order']}|{x['table_B_per_message']:.3f}|{x['index_B_per_message']:.3f}|{x['total_B_per_message']:.3f}|")
    lines+=['','Measured six100k histories. Actual26B channel,32B delivery/message IDs,64B fingerprint; op16/46/128 cover controlled legal widths including generated46. Empty-table dbstat baselines subtracted. Order/field distributions affect layout. Fully ACKed identities hold0 body bytes and0 targets; recipient count does not multiply identity history.','','## Thirty-day arithmetic extrapolation','','|business messages/s|identities30d|op16 GB range|default op46 GB range|op128 GB range|','|---:|---:|---:|---:|---:|']
    for rate in [1,64,128,256]:
        rows=[x for x in projections if x['messages_per_second']==rate];lines.append('|'+str(rate)+'|'+str(rows[0]['identity_messages'])+'|'+'|'.join(f"{x['identity_GB_low']:.3f}–{x['identity_GB_high']:.3f}" for x in rows)+'|')
    lines+=['','GB means10^9bytes. Extrapolations are not30-day soak or admission/delivery capacity evidence. WAL, fragmentation, directory/filesystem overhead and operational headroom remain additional.','','## Measured active targets and shared body','',f'Native10k-target internal physical row-layout probe: **{target_total:.4f}B/target including all indexes**, cold subtracted. Includes pull_owner, owner_generation, control_epoch and owner/token indexes. Native provider token fixture163B; target/device IDs32B. The product allows at most32 channel subscribers; direct SQL10k-target seeding exceeds that API contract and measures only physical row layout, never valid single-message API workload or completion rate.','']
    for k,v in target_cost.items():lines.append(f'- {k}: {v:.4f}B/target.')
    lines+=['','Python fixed-schema probe uses256 business messages per case and includes identical owner/generation/epoch columns plus triggers; direct SQL probe is storage layout only. Body448B/1KiB/4KiB is shared once per message. The message+index column includes the shared body and all message metadata/index page overhead; logical body sizes remain separate. Differences from native10k-target B/target reflect page fill, fixture key distribution, row counts and SQLite version; none is a universal bound. The direct SQL release is not native ACK evidence.','','|fanout|body B/message|messages|targets|target B/target|message+index B/message|','|---:|---:|---:|---:|---:|---:|']
    for c in layout['cases']:lines.append(f"|{c['fanout']}|{c['body_bytes']}|{c['messages']}|{c['targets']}|{c['target_bytes_per_row']:.3f}|{c['message_plus_index_bytes_per_row']:.3f}|")
    lines+=['','Active demand arithmetic for legal fanout1/16/32,7d/30d holds and all requested rates is in active-fanout-projections.csv. Formula:M=business messages/s×hold_seconds; targets=M×fanout; shared body=M×body_bytes; target disk≈targets×measured native B/target. Active admission backpressure can refuse these hypothetical backlogs; this is not a promise to accept them.','','## Native operation cost and expiry cleanup','','|seeded identities|actual rows|DB B|status p50/p95/max us|duplicate p50/p95/max us|accept p50/p95/max us|','|---:|---:|---:|---|---|---|']
    for o in operations:
        cells=['/'.join(str(o[k][p]) for p in ['p50_us','p95_us','max_us']) for k in ['status','duplicate','new_admission']];lines.append(f"|{o['seeded_rows']}|{o['actual_rows']}|{o['db_bytes']}|"+'|'.join(cells)+'|')
    g=scale['gc'];lines+=['','Each timing cell has50 actual sequential native-store samples; fresh acceptance has1 recipient and is followed by native ACK. History was inserted via bounded500-row direct seed batches, not1m production admissions. At each measured scale, native actual accept+ACK left0 target rows and0 logical body bytes while preserving10,050/100,100/1,000,150 identity rows. Warm local short-run evidence; no sustained throughput, network/provider latency or production capacity claim.','',f"Native maintenance deleted{g['expired_sample']} eligible rows in{g['batches']} commits of at most{g['max_deletes_per_batch']}. Timings:{g['maintenance']}. DB after logical deletion:{g['after_logical_delete']['physical']['db_bytes']}B, free pages:{g['after_logical_delete']['freelist_count']}. After TRUNCATE checkpoint:{g['after_truncate_checkpoint']['physical']}. Other identities retain full30d.",'','Freelist pages remain physically allocated. Native width cases reinsert10k same identities and show actual free-page consumption. Every case returns from90,000 to100,000 identities with0 targets/body bytes. No VACUUM ran. Physical DB shrink is not claimed.','','|op bytes|order|free pages after delete|pages consumed by10k reinserts|DB growth B|','|---:|---|---:|---:|---:|' ,'','Limit: local synthetic database/storage and native API evidence only. No30d soak, OS ENOSPC, power-loss recovery or production/provider capacity acceptance.']
    limit=lines.pop(); lines.pop()
    for x in identities: lines.append(f"|{x['op_bytes']}|{x['order']}|{x['free_pages_after_delete']}|{x['free_pages_consumed_by_reinsert']}|{x['db_growth_on_reinsert_B']}|")
    lines.extend(['',limit])
    (out/'analysis.md').write_text('\n'.join(lines)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',required=True);run(p.parse_args())
