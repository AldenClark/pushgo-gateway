#!/usr/bin/env python3
"""Read exactly two finite equal-history boundary receipts; no test execution."""
import importlib.util,json,pathlib,statistics
HERE=pathlib.Path(__file__).resolve().parent;OUT=HERE.parent
spec=importlib.util.spec_from_file_location('a',HERE/'analyse_c2.py');a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
def slope(points):
    if len(points)<2:return None
    xs=[p[0] for p in points];ys=[p[1] for p in points];xm=statistics.mean(xs);ym=statistics.mean(ys)
    return sum((x-xm)*(y-ym) for x,y in points)/sum((x-xm)**2 for x in xs)
def describe(values):return {'min':min(values),'median':statistics.median(values),'max':max(values)} if values else None
rows=[];full=[]
for name,rate,duration in [('final-bound32x60',32,60),('final-bound64x30',64,30)]:
    run=OUT/'runs'/name;r=a.reduce(run);full.append(r);phases=a.base.lines(run/'phases.jsonl');by={p['phase']:p for p in phases};load=by['load'];end=by['first-all-targets-sql-visible'];start=load['unix_ms']
    snaps=a.base.lines(run/'snapshots.jsonl');points=[s for s in snaps if s['label'].startswith(f'rate-{rate}-second-')]
    tail=[s for s in points if s['elapsed']-load['elapsed']>=duration/2]
    pending=lambda s:sum(v for k,v in s['states'].items() if k!='provider_accepted')
    producers=[p for p in a.base.lines(run/'producer.jsonl') if duration/2<=p['elapsed']-load['elapsed']<=duration]
    requests=[q for q in a.base.lines(run/'requests.jsonl') if q['path']=='/message' and q['label']!='dual:sustained:-01']
    first=next(s for s in snaps if s['elapsed']>=load['elapsed'] and s['states']=={'provider_accepted':30720})
    raw=[]
    for line in (run/'gateway-0.log').read_text().splitlines():
        if line.startswith('{'):
            v=json.loads(line)
            if v.get('kind')=='stats' and start<=v['unix_ms']<=end['unix_ms']:raw.append(v)
    mid=min(raw,key=lambda v:abs(v['unix_ms']-start-duration*500))
    rate_end=by[f'rate-end-{rate}']['fixture_stats']
    firsthalf=a.timing_delta(load['fixture_stats'],mid);secondhalf=a.timing_delta(mid,rate_end)
    gauge_tail=[v for v in raw if duration*500<=v['unix_ms']-start<=duration*1000]
    row={'run':name,'status':'PASSED' if r['failure'] is None else 'FAILED','offered_message_rate':rate,'input_seconds':duration,'messages':1920,'verified_targets':r['actual_unique_targets_excluding_warmup'],
      'first_sql_all_receipts_visible_s':r['first_sql_all_receipts_visible_seconds'],'producer_backlog_peak':r['producer_backlog_peak'],
      'second_half_producer_waiting':describe([p['producer_waiting'] for p in producers]),
      'second_half_producer_slope_messages_per_s':slope([(p['elapsed'],p['producer_waiting']) for p in producers]),
      'second_half_db_backlog_targets':describe([pending(p) for p in tail]),
      'second_half_db_backlog_slope_targets_per_s':slope([(p['elapsed'],pending(p)) for p in tail]),
      'second_half_inflight_gauges':{k:describe([p[k] for p in gauge_tail]) for k in ['owned_attempts','network_inflight','receipts_owned']},
      'last_http_start_to_all_sql_visible_ms':first['unix_ms']-max(q['start_ms'] for q in requests),
      'last_http_response_to_all_sql_visible_ms':first['unix_ms']-max(q['unix_ms'] for q in requests),
      'queue_first_half':firsthalf.get('queue'),'queue_second_half':secondhalf.get('queue'),
      'receipt_first_half':firsthalf.get('receipt'),'receipt_second_half':secondhalf.get('receipt'),
      'rss_peak_mib':max(v['proc_rss_bytes']/1048576 for v in a.base.lines(run/'rss.jsonl') if isinstance(v.get('proc_rss_bytes'),(float,int))),
      'limit':'Finite equal1920-message/30720-target observation, not repeated or soak evidence. SQL visibility includes observer sampling delay; it is not an exact last-target commit timestamp. Quantiles are log2 bucket upper bounds; gauges sampled independently.'}
    rows.append(row);print(json.dumps({k:v for k,v in row.items() if k not in ['queue_first_half','queue_second_half','receipt_first_half','receipt_second_half']}))
    print('queue first/second mean_us',row['queue_first_half']['mean_us'],row['queue_second_half']['mean_us'])
(OUT/'final-boundary2-comparison.json').write_text(json.dumps(rows,indent=2)+'\n');(OUT/'final-boundary2-full-summary.json').write_text(json.dumps(full,indent=2)+'\n')
(OUT/'final10-full-summary.json').write_text(json.dumps(json.loads((OUT/'final8-full-summary.json').read_text())+full,indent=2)+'\n')
