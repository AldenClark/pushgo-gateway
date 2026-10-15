#!/usr/bin/env python3
"""Reduce exactly the approved final8; reuse immutable control/core receipts."""
import importlib.util,json,pathlib
HERE=pathlib.Path(__file__).resolve().parent;OUT=HERE.parent
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
matrix=module('m',HERE/'run_c2_matrix.py');a=module('a',HERE/'analyse_c2.py')
rows=[];brief=[]
for case in matrix.final_cases():
    run=OUT/'runs'/case['label'];r=a.reduce(run);rows.append(r)
    phases=a.base.lines(run/'phases.jsonl');by={p['phase']:p for p in phases};rss=a.base.lines(run/'rss.jsonl')
    completed=by.get('first-all-targets-sql-visible',by.get('idle-complete'))['fixture_stats']
    direct=r['direct_timing_phase_deltas'].get('first-all-targets-sql-visible',{})
    result=json.loads((run/'result.json').read_text());assert r['failure'] is None and result['daemon_exited'] and result['log_readers_joined']
    b={'run':run.name,'ceiling':case['budget'],'status':'PASSED','binary_sha256':r['binary_sha256'],
       'messages':r['messages_planned'],'verified_targets':r['actual_unique_targets_excluding_warmup'],
       'first_sql_s':r['first_sql_all_receipts_visible_seconds'],'post_offer_drain_s':r['post_input_drain_seconds'],
       'producer_backlog_peak':r['producer_backlog_peak'],
       'second_half_db_backlog_growth_targets':r['capacity_stages'][0]['second_half_db_backlog_growth_targets'] if r['capacity_stages'] else None,
       'peak_owned':completed.get('peak_owned_attempts'),'peak_network':completed.get('peak_network_inflight'),'peak_receipt':completed.get('peak_receipts_owned'),
       'rss_peak_mib':max((v['proc_rss_bytes']/1048576 for v in rss if isinstance(v.get('proc_rss_bytes'),(float,int))),default=None),
       'network_mean_ms':direct.get('network',{}).get('mean_us',0)/1000 if direct else None,
       'receipt_mean_ms':direct.get('receipt',{}).get('mean_us',0)/1000 if direct else None,
       'receipt_commit_mean_ms':direct.get('receipt_commit',{}).get('mean_us',0)/1000 if direct else None,
       'input_cpu':r['capacity_stages'][0]['kernel'] if r['capacity_stages'] else r['phase_kernel'].get('idle-complete'),
       'post_drain_resources':[{k:p[k] for k in ['phase','allocator','provider_resources','owned_attempts','network_inflight','receipts_owned']} for p in r['allocator_and_provider_resources_by_phase'] if p['phase'] in ['idle-complete','complete','falloff-idle-start','falloff-idle-end']]}
    brief.append(b);print(json.dumps({k:v for k,v in b.items() if k not in ['post_drain_resources','binary_sha256','input_cpu']}))
(OUT/'final8-full-summary.json').write_text(json.dumps(rows,indent=2)+'\n')
(OUT/'final8-comparison.json').write_text(json.dumps(brief,indent=2)+'\n')
