#!/usr/bin/env python3
"""Reduce existing C2 completion-window counters; no processes or DB writes."""
import importlib.util,json,pathlib,statistics
HERE=pathlib.Path(__file__).resolve().parent;OUT=HERE.parent
spec=importlib.util.spec_from_file_location('a',HERE/'analyse_c2.py');a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
def delta_mean(before,after,name):
    n=after.get(name+'_samples',0)-before.get(name+'_samples',0)
    total=after.get(name+'_total_us',0)-before.get(name+'_total_us',0)
    return {'samples':n,'mean_us':total/n if n>0 else None}
def reduce(run):
    phases=a.base.lines(run/'phases.jsonl');by={p['phase']:p for p in phases};start=by['load'];end=by['first-all-targets-sql-visible']
    frames=[(start['unix_ms'],start['fixture_stats'])]
    for line in (run/'gateway-0.log').read_text().splitlines():
        if line.startswith('{'):
            v=json.loads(line)
            if v.get('kind')=='stats' and start['unix_ms']<v['unix_ms']<end['unix_ms']:frames.append((v['unix_ms'],v))
    frames.append((end['unix_ms'],end['fixture_stats']));frames.sort(key=lambda x:x[0])
    duration=end['elapsed']-start['elapsed'];offered=30 if '64-long' in run.name else 10
    bounds=[0,10,20,30] if offered==30 else [0,5,10]
    if duration>bounds[-1]+.05:bounds.append(duration)
    wire=[v for v in a.base.lines(run/'mock.jsonl') if v['event']=='finished' and v['op_id']!='dual:sustained:-01']
    intervals=[]
    for left,right in zip(bounds,bounds[1:]):
        ta,sa=min(frames,key=lambda f:abs(f[0]-(start['unix_ms']+left*1000)))
        tb,sb=min(frames,key=lambda f:abs(f[0]-(start['unix_ms']+right*1000)))
        if tb<=ta:continue
        verbs={k:sb['dbcounts'].get(k,0)-sa['dbcounts'].get(k,0) for k in set(sa['dbcounts'])|set(sb['dbcounts'])}
        mock=[v['finish_ms']-v['start_ms'] for v in wire if ta<v['finish_ms']<=tb]
        timing=a.timing_delta(sa,sb)
        intervals.append({'requested_seconds':[left,right],'observed_seconds':[(ta-start['unix_ms'])/1000,(tb-start['unix_ms'])/1000],
          'completed_timing_samples':{k:{q:v.get(q) for q in ['samples','mean_us','p95_upper_us','p99_upper_us']} for k,v in timing.items()},
          'gate_wait':delta_mean(sa,sb,'gate_wait'),'admission_commit':delta_mean(sa,sb,'admission_commit'),'receipt_commit':delta_mean(sa,sb,'receipt_commit'),
          'querycounts_delta':verbs,'querycount_events_per_second':sum(verbs.values())/((tb-ta)/1000),
          'mock_completed_count':len(mock),'mock_handler_mean_ms':statistics.mean(mock) if mock else None,
          'end_gauges':{k:sb.get(k) for k in ['owned_attempts','network_inflight','receipts_owned','provider_owned','claim_reservations']}})
    reduced=a.reduce(run)
    return {'run':run.name,'binary_sha256':reduced['binary_sha256'],'windows':intervals,'cpu_load_through_first_receipt_visibility':reduced['phase_kernel']['first-all-targets-sql-visible'],
      'input_window_cpu':reduced['capacity_stages'][0]['kernel'],'limits':'Completion-window populations, not offer-cohort distributions. Quantiles are log2 upper bounds. SQL events are not transactions/pagework. Aggregate gate/receipt contention cannot quantitatively separate trigger/claim/maintenance, mock GIL/TCP/client scheduling. Different axis peaks are not simultaneous and must not be summed.'}
if __name__=='__main__':
    rows=[reduce(OUT/'runs'/name) for name in ['offer64-long-r1-c2','offer128-r1-c2','offer128-r2-c2','offer256-r1-c2','offer256-r2-c2']]
    (OUT/'core-c2-completion-window-trends.json').write_text(json.dumps(rows,indent=2)+'\n')
    for r in rows:
        print(r['run'])
        for w in r['windows']:
            t=w['completed_timing_samples'];print(w['observed_seconds'],{k:round(t.get(k,{}).get('mean_us',0)/1000,3) if t.get(k,{}).get('mean_us') is not None else None for k in ['network','receipt','receipt_commit','queue']},'gate_ms',round(w['gate_wait']['mean_us']/1000,3) if w['gate_wait']['mean_us'] is not None else None,'mock_ms',round(w['mock_handler_mean_ms'],3) if w['mock_handler_mean_ms'] is not None else None)
