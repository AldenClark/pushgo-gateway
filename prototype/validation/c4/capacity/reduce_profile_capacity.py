#!/usr/bin/env python3
"""Read retained C3 receipts. Profiling is caller wall time, not engine-only time."""
import importlib.util,json,pathlib,sys
HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('c2',HERE/'analyse_c2.py');c2=importlib.util.module_from_spec(spec);spec.loader.exec_module(c2)

def histogram_delta(before,after):
    if 'buckets' not in after:return {'status':'not_observed'}
    a=before.get('buckets',[0]*32);b=after['buckets']
    if len(a)!=32 or len(b)!=32:return {'status':'schema_mismatch'}
    counts=[right-left for left,right in zip(a,b)]
    total=after['total_us']-before.get('total_us',0)
    if any(v<0 for v in counts) or total<0:return {'status':'counter_reset'}
    n=sum(counts)
    def upper(percent):
        if not n:return None
        threshold=(n*percent+99)//100;seen=0
        for index,count in enumerate(counts):
            seen+=count
            if seen>=threshold:return (1<<index)-1 if index<31 else (1<<64)-1
    return {'samples':n,'total_us':total,'mean_us':total/n if n else None,
            'p50_upper_us':upper(50),'p95_upper_us':upper(95),'p99_upper_us':upper(99),
            'buckets':counts,'cumulative_max_us':after['max_us'],
            'max_semantics':'cumulative max, not a phase max reconstructed from differences'}

def profile_delta(before,after):
    answer={}
    for path,entry in after.get('paths',{}).items():
        previous=before.get('paths',{}).get(path,{})
        answer[path]={group:{name:histogram_delta(previous.get(group,{}).get(name,{}),hist)
                      for name,hist in entry.get(group,{}).items()} for group in ['phases','statements']}
    return answer

def reduce(run):
    row=c2.reduce(run);phases=c2.base.lines(run/'phases.jsonl');by={p['phase']:p for p in phases}
    pairs=[('load','first-all-targets-sql-visible'),('ack-start','ack-complete'),
           ('cleanup-start','cleanup-complete'),('db-lock-acquired','db-lock-released')]
    for stage in json.loads((run/'plan.json').read_text()).get('capacity_stages') or []:
        rate=stage['messages_per_second'];pairs.append((f'rate-{rate}',f'rate-end-{rate}'))
    row['path_profile_windows']={}
    for start,end in pairs:
        if start not in by or end not in by:continue
        a=by[start]['fixture_stats'] or {};b=by[end]['fixture_stats'] or {}
        row['path_profile_windows'][start+'__'+end]={'elapsed_seconds':by[end]['elapsed']-by[start]['elapsed'],
          'profile':profile_delta(a.get('profile',{}),b.get('profile',{}))}
    result=json.loads((run/'result.json').read_text())
    row['performance_eligible']=row['performance_eligible'] and result.get('shared_mock_server_joined',False)
    peer=run/'peer';captures=0;finishes=0;token_requests=0
    if (peer/'captures.jsonl').exists():
        with (peer/'captures.jsonl').open() as f:
            for line in f:
                value=json.loads(line)
                captures+=int(value.get('event')=='received')
    if (peer/'requests.jsonl').exists():
        with (peer/'requests.jsonl').open() as f:
            for line in f:
                value=json.loads(line);finishes+=int(value.get('event')=='provider_finished');token_requests+=int(value.get('event')=='token_request')
    row['persistent_peer_stream_counts']={'captures':captures,'finished':finishes,'token_requests':token_requests,'source':'complete append-only streams, never the256-row ring'}
    row['profile_semantics']={'phase':'caller wall includes errors/cancel/executor scheduling; cancelled worker may continue',
      'pool_acquire':'pool wait plus checkout/ping', 'begin':'worker queue plus BEGIN after checkout',
      'statement_inclusive':'SQLx dispatch/result plus SQLite SQL and trigger work; not trigger-exclusive',
      'commit':'worker queue plus COMMIT/WAL durability',
      'overlap':'gate_hold contains nested fanout/maintenance; do not sum nested phases or different axis peaks',
      'quantiles':'fixed32log2microsecond buckets provide upper bounds, not exact p95/p99; overflow bucket unbounded',
      'claims':'instrumented full-candidate before/after only; no architecture ranking or production provider evidence'}
    return row
if __name__=='__main__':print(json.dumps([reduce(pathlib.Path(p)) for p in sys.argv[1:]],indent=2,sort_keys=True))
