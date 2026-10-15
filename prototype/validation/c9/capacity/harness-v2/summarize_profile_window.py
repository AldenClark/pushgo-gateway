#!/usr/bin/env python3
"""Offline histogram differences in a conservative interior of the measured window."""
import argparse,json,math,pathlib,struct
def lines(path):return [json.loads(line) for line in path.read_text().splitlines()]
def histogram(first,last):
    buckets=[b-a for a,b in zip(first.get('buckets',[0]*32),last.get('buckets',[0]*32))]
    assert all(n>=0 for n in buckets)
    count=sum(buckets);total=last.get('total_us',0)-first.get('total_us',0)
    result={'samples':count,'total_us':total,'mean_us':total/count if count else None,'buckets':buckets}
    for q in (50,95,99):
        accumulated=0;rank=math.ceil(count*q/100);value=None
        if rank:
            for index,n in enumerate(buckets):
                accumulated+=n
                if accumulated>=rank:value=(1<<index)-1 if index<31 else None;break
        result[f'p{q}_upper_us']=value
    return result
def summarize(root,anchor):
    meta=json.loads((root/'telemetry.json').read_text());scale=meta['mach_numer']/meta['mach_denom']/1e6
    clock=json.loads(anchor.read_text())
    cutoff_unix_ms=(clock['unix_ns_mid']+(meta['measurement_cutoff_mach_ticks']-clock['mach_ticks'])*clock['numer']/clock['denom'])/1e6
    captures=[r for r in lines(root/'peer/captures.jsonl') if r.get('event')=='received' and r['op_id']!='c5:capacity:-1']
    finishes=[r for r in lines(root/'peer/requests.jsonl') if r.get('event')=='provider_finished' and r['unix_ms']<=cutoff_unix_ms]
    low=min(r['unix_ms'] for r in captures);high=min(max(r['unix_ms'] for r in finishes),cutoff_unix_ms)
    stats=[json.loads(line) for line in (root/'gateway.log').read_text().splitlines() if line.startswith('{')]
    stats=[r for r in stats if r.get('kind')=='stats' and low<=r['unix_ms']<=high]
    assert len(stats)>=2
    first,last=stats[0],stats[-1]
    paths={}
    for name in ('accept','fanout','claim','receipt'):
        before=first['profile']['paths'][name];after=last['profile']['paths'][name]
        paths[name]={'phases':{phase:histogram(before['phases'].get(phase,{}),data) for phase,data in after['phases'].items()},
            'statements':{statement:histogram(before['statements'].get(statement,{}),data) for statement,data in after['statements'].items()}}
    offers=lines(root/'offers.jsonl');first_offer=min(r['offer_mach_ticks'] for r in offers)
    requests=[r for r in lines(root/'requests.jsonl') if r['path']=='/message' and r['label']!='c5:capacity:-1']
    accepted_http=[r for r in requests if r['status']==200 and not r['error']]
    record=struct.Struct('<QQQ32s32sB7x');commits=[]
    with (root/'commits.bin').open('rb') as stream:
        while raw:=stream.read(record.size):
            tick,attempt,sequence,delivery,device,state=record.unpack(raw)
            if state==1 and delivery.decode() not in meta['excluded_acknowledged_warmup_ids'] and tick<=meta['measurement_cutoff_mach_ticks']:commits.append(tick)
    return {'scope':'conservative first/last STATS inside first measured Provider receive through last Provider finish before cutoff; setup/cold/postACK excluded',
        'stats_first_unix_ms':first['unix_ms'],'stats_last_unix_ms':last['unix_ms'],'stats_snapshots_interior':len(stats),
        'interior_seconds':(last['unix_ms']-first['unix_ms'])/1000,
        'stats_receipt_commits_first':first['receipt_commits'],'stats_receipt_commits_last':last['receipt_commits'],
        'stats_receipt_commit_delta':last['receipt_commits']-first['receipt_commits'],
        'cutoff_wall_selection_assumption':clock['assumption'],'stats_are_full_window':False,
        'histogram_semantics':'log2 microsecond bucket upper bounds from cumulative bucket subtraction; not exact percentiles; max cannot be subtracted',
        'paths':paths,'timings':{name:histogram(first['timings'][name],data) for name,data in last['timings'].items() if isinstance(data,dict)},
        'precise_clock_durations':{'all_http_accepted_completed':len(accepted_http)==len(offers),
            'http_accepted_messages':len(accepted_http),'offered_messages':len(offers),
            'last_successful_http_from_first_actual_offer_ms':(max(r['http_end_mach_ticks'] for r in accepted_http)-first_offer)*scale if accepted_http else None,
            'last_in_window_target_commit_from_first_actual_offer_ms':(max(commits)-first_offer)*scale if commits else None,
            'last_in_window_commit_minus_planned_10s_ms':(max(commits)-first_offer)*scale-10000 if commits else None,
            'planned_input_seconds':10,'in_window_commit_targets':len(commits)},
        'interpretation':['network wraps transport.send including credential owner, HTTP and bounded reply parsing; not pure Mock RTT',
            'network_inflight is not actual Provider HTTP request count',
            'queue starts at durable accepted_at; excludes caller offer-to-HTTP-start queue',
            'receipt spans settle gate/connection/SQL/COMMIT; nested phases cannot be summed',
            'MySQL pool_acquire includes owner checking whereas PG uses its mutex; compare semantics first',
            'Counters.sql is nominal charging; receipt Usage is a four-SQL reconciliation bundle, not one engine statement']}
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('run',type=pathlib.Path);parser.add_argument('--anchor',required=True,type=pathlib.Path)
    a=parser.parse_args();print(json.dumps(summarize(a.run,a.anchor),indent=2))
