"""Reduce the retained, fixed local receipts; no service or database writes."""
import collections, json, math, pathlib, re, statistics, sys

def lines(path):
    return [json.loads(s) for s in path.read_text().splitlines()] if path.exists() else []

def pct(values, p):
    return sorted(values)[max(0,math.ceil(len(values)*p)-1)] if values else None

def distribution(values):
    return {'count':len(values), 'p50':pct(values,.5), 'p95':pct(values,.95),
            'p99':pct(values,.99), 'max':max(values) if values else None}

def cpu_seconds(value):
    if not value: return None
    parts = value.split(':')
    return sum(float(part)*60**i for i,part in enumerate(reversed(parts)))

def reduce(run):
    plan=json.loads((run/'plan.json').read_text()); result=json.loads((run/'result.json').read_text())
    phases=lines(run/'phases.jsonl'); requests=lines(run/'requests.jsonl')
    snapshots=lines(run/'snapshots.jsonl'); mock=lines(run/'mock.jsonl'); rss=lines(run/'rss.jsonl')
    eligible=result['failure'] is None and bool(result['exit_codes']) and result['exit_codes'][-1]==0
    scene=plan['scenario']; warm=f'dual:{scene}:-01'
    phase_by={v['phase']:v for v in phases}
    final=next((v for v in reversed(snapshots) if v['label']=='provider-complete'),None) or next((v for v in reversed(snapshots) if v['label'] in ('final','idle-final')), {})
    rows=[v for v in final.get('dispatch_rows',[]) if v['op_id']!=warm]
    registers={r['response']['data']['device_key']:format(int(r['label'].split('-')[1])+20261014,'064x')
               for r in requests if r['label'].startswith('register-') and r['status']==200}
    starts=collections.defaultdict(list); finishes=collections.defaultdict(list)
    for r in mock:
        key=(r['provider'],r['op_id'],r['delivery_id'],r['token'])
        (starts if r['event']=='started' else finishes)[key].append(r)
    callers={}
    for request in requests:
        if request['path']=='/message' and request['label']!=warm:
            callers[request['label']]=min(callers.get(request['label'],request['start_ms']),request['start_ms'])
    caller_queues={}; caller_receipts={}
    queues={}; timestamp_tails={}; network={}; completion_intent_gaps=[]
    for row in rows:
        provider=row['provider'].lower()
        key=(provider,row['op_id'],row['delivery_id'],registers[row['device_key']])
        if starts[key]:
            queues.setdefault(provider,[]).append(min(r['start_ms'] for r in starts[key])-row['accepted_at'])
        if row['op_id'] in callers:
            if starts[key]: caller_queues.setdefault(provider,[]).append(min(r['start_ms'] for r in starts[key])-callers[row['op_id']])
            if row['completed_at'] is not None: caller_receipts.setdefault(provider,[]).append(row['completed_at']-callers[row['op_id']])
        if row['completed_at'] is not None:
            timestamp_tails.setdefault(provider,[]).append(row['completed_at']-row['accepted_at'])
            success=[r for r in finishes[key] if r['status']==200 and not r['response_error']]
            if success: completion_intent_gaps.append(row['completed_at']-max(r['finish_ms'] for r in success))
        for r in finishes[key]: network.setdefault(provider,[]).append(r['finish_ms']-r['start_ms'])
    loads=[r for r in requests if r['path']=='/message' and r['label']!=warm]
    start=phase_by.get('idle' if scene=='idle' else 'load')
    end=phase_by.get('idle-complete' if scene=='idle' else 'provider-complete')
    elapsed=end['elapsed']-start['elapsed'] if start and end else None
    db_delta=None; cpu_delta=None
    if start and end and start['fixture_stats'] and end['fixture_stats'] and scene!='recovery':
        before=start['fixture_stats']['dbcounts']; after=end['fixture_stats']['dbcounts']
        db_delta={k:after.get(k,0)-before.get(k,0) for k in set(before)|set(after)}
        cpu_delta=cpu_seconds(end.get('process_cpu_time'))-cpu_seconds(start.get('process_cpu_time'))
    peak=[]
    for usage in run.glob('rusage-*.log'):
        found=re.search(r'(\d+)\s+maximum resident set size',usage.read_text())
        if found: peak.append(int(found[1])/1048576)
    rss_phase={}
    for name in ('cold','idle','load','settle'):
        vals=[r['proc_rss_bytes']/1048576 for r in rss if r['phase']==name and isinstance(r.get('proc_rss_bytes'),(int,float))]
        rss_phase[name]={'median_mib':statistics.median(vals) if vals else None,'max_mib':max(vals) if vals else None}
    fixture_stats=[]
    for path in run.glob('gateway-*.log'):
        for line in path.read_text().splitlines():
            if line.startswith('{'):
                try:
                    entry=json.loads(line)
                    if entry.get('kind')=='stats': fixture_stats.append(entry)
                except ValueError: pass
    # Provider-complete was historically marked after a quadratic independent
    # wire check. Use the first SQL observation of the entire final target set
    # instead, keeping the original phase window visible for audit.
    first_visible = next((s for s in snapshots if start and s['elapsed'] >= start['elapsed']
                          and s.get('states') == {'provider_accepted':len(final.get('dispatch_rows',[]))}
                          and final.get('dispatch_rows')), None)
    visible_seconds = first_visible['elapsed']-start['elapsed'] if first_visible and start else None
    stat_candidates = [s for s in fixture_stats if start and s['unix_ms']>=start['unix_ms']]
    if first_visible and end and abs(end['elapsed']-first_visible['elapsed'])<=1:
        nearest_stats = {'unix_ms':end['unix_ms'],'dbcounts':end['fixture_stats']['dbcounts']}
    else:
        nearest_stats = min(stat_candidates, key=lambda s:abs(s['unix_ms']-first_visible['unix_ms'])) if stat_candidates and first_visible else None
    visible_db_delta = {k:nearest_stats['dbcounts'].get(k,0)-start['fixture_stats']['dbcounts'].get(k,0)
                        for k in set(nearest_stats['dbcounts'])|set(start['fixture_stats']['dbcounts'])} if nearest_stats and start and scene!='recovery' else None
    if visible_db_delta and any(v<0 for v in visible_db_delta.values()):visible_db_delta=None
    offers = {}
    if plan.get('capacity_stages'):
        offset = 0
        by_label = {s['label']:s for s in snapshots}
        for stage in plan['capacity_stages']:
            rate=stage['messages_per_second'];origin=by_label.get(f'rate-{rate}-start')
            if origin:
                for i in range(rate*stage['duration_seconds']):offers[f'dual:{scene}:{offset+i:03d}']=origin['unix_ms']+i*1000/rate
            offset+=rate*stage['duration_seconds']
    offer_tails={}
    for row in rows:
        if row['op_id'] in offers and row['completed_at'] is not None:
            offer_tails.setdefault(row['provider'].lower(),[]).append(row['completed_at']-offers[row['op_id']])
    wire=[r for group in starts.values() for r in group if r['op_id']!=warm]
    mock_accepts=[r for r in wire if r['planned_status']==200]
    return {'run':run.name,'scenario':scene,'engine':plan['engine'],'provider_budget':plan['provider_budget'],'binary_sha256':plan['binary_sha256'],
            'failure':result['failure'],'performance_eligible':eligible,'unique_durable_jobs':len(rows) if final else None,
            'stored_completed_row_metrics_available':bool(final),
            'last_observed_states':snapshots[-1].get('states') if snapshots else None,
            'last_observed_target_count_including_warmup':sum(snapshots[-1].get('states',{}).values()) if snapshots else None,'accepted_job_states':final.get('states'),
            'load_until_all_success_visible_seconds':elapsed,
            'first_sql_all_receipts_visible_seconds':visible_seconds,
            'jobs_per_second_until_first_sql_all_receipts_visible':len(rows)/visible_seconds if eligible and rows and visible_seconds else None,
            'db_statement_delta_to_nearest_visibility_sample':visible_db_delta,
            'db_stat_visibility_sample_offset_ms':nearest_stats['unix_ms']-first_visible['unix_ms'] if nearest_stats else None,
            'completed_jobs_per_second':len(rows)/elapsed if eligible and rows and elapsed else None,
            'input_http_latency_ms':distribution([r['latency_ms'] for r in loads if r['status']==200]),
            'input_http_statuses':dict(collections.Counter(r['status'] for r in loads)),
            'queue_to_first_network_ms':{k:distribution(v) for k,v in queues.items()},
            'caller_to_first_network_ms':{k:distribution(v) for k,v in caller_queues.items()},
            'caller_to_persisted_receipt_ms':{k:distribution(v) for k,v in caller_receipts.items()},
            'reconstructed_offer_to_receipt_timestamp_ms':{k:distribution(v) for k,v in offer_tails.items()},
            'stored_timestamp_delivery_ms':{k:distribution(v) for k,v in timestamp_tails.items()},
            'mock_http_duration_ms':{k:distribution(v) for k,v in network.items()},
            'response_to_completion_intent_ms':distribution(completion_intent_gaps),
            'rss':rss_phase,'time_l_peak_rss_mib':peak,
            'db_completed_statement_delta':db_delta,'db_statement_total':sum(db_delta.values()) if db_delta else None,
            'phase_process_cpu_seconds':cpu_delta,'sql_stat_sample_count':len(fixture_stats),
            'sampled_tasks_range':[min(r['tasks'] for r in fixture_stats),max(r['tasks'] for r in fixture_stats)] if fixture_stats else None,
            'sampled_leased_peak':max((r['leased_rows'] for r in snapshots),default=0),
            'sampled_running_peak':max((r.get('running_rows',0) for r in snapshots),default=0),
            'retained_payload_bytes':final.get('retained_payload_bytes'),
            'database_file_bytes_after_shutdown':result.get('database_file_bytes_after_shutdown'),
            'mock_peak_http':result['mock_peak_attempts'],
            'attempt_distribution':dict(collections.Counter(r['attempt_count'] for r in rows)) if final else None,
            'external_attempts':len(wire),'repeated_external_attempts':len(wire)-len({(r['provider'],r['op_id'],r['delivery_id'],r['token']) for r in wire}),
            'mock_accepted_duplicates':len(mock_accepts)-len({(r['provider'],r['op_id'],r['delivery_id'],r['token']) for r in mock_accepts}),
            'unknown_wire_response_count':sum(bool(r['response_error']) for r in mock if r['event']=='finished')}

if __name__=='__main__':
    values=[reduce(pathlib.Path(p)) for p in sys.argv[1:]]
    print(json.dumps(values,indent=2,sort_keys=True))
