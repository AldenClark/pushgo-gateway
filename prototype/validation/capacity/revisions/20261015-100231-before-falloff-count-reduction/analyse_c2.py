#!/usr/bin/env python3
"""Read-only C2 receipts. Never calls a daemon or infers commitment from timestamps."""
import collections, importlib.util, json, pathlib, sys
spec=importlib.util.spec_from_file_location('c1base',pathlib.Path(__file__).with_name('analyse_c1_base.py'))
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)

def kernel_delta(start,end):
    if not start or not end:return None
    a=start.get('kernel');b=end.get('kernel')
    if not a or not b or a['exit_code'] or b['exit_code']:return None
    before=a['metrics'];after=b['metrics']
    if before['pid']!=after['pid']:return None
    return {'user_cpu_seconds':(after['userCPU_ns']-before['userCPU_ns'])/1e9,
            'system_cpu_seconds':(after['systemCPU_ns']-before['systemCPU_ns'])/1e9,
            'interrupt_wakes':after['interrupt_wakes']-before['interrupt_wakes'],
            'package_idle_wakes':after['pkgIdle_wakes']-before['pkgIdle_wakes'],
            'cpu_source':'raw Mach ticks converted by retained helper numer/denom; not ps percent',
            'kernel_interrupt_definition':'ri_interrupt_wkups, not total wakeups'}

def timing_delta(before,after):
    """Fixed-memory log2 phase deltas; no exact percentile reconstruction."""
    answer={}
    for name,last in after.get('timings',{}).items():
        if not isinstance(last,dict) or 'buckets' not in last:continue
        first=before.get('timings',{}).get(name,{})
        counts=[b-a for a,b in zip(first.get('buckets',[0]*32),last['buckets'])]
        if len(counts)!=32 or any(v<0 for v in counts):
            answer[name]={'status':'unavailable_counter_reset_or_schema_mismatch'};continue
        n=sum(counts);total=last['total_us']-first.get('total_us',0)
        def upper(percent):
            threshold=(n*percent+99)//100;seen=0
            if not n:return None
            for index,count in enumerate(counts):
                seen+=count
                if seen>=threshold:return (1<<index)-1 if index<31 else (1<<64)-1
        answer[name]={'samples':n,'total_us':total,'mean_us':total/n if n else None,
                      'p50_upper_us':upper(50),'p95_upper_us':upper(95),'p99_upper_us':upper(99),
                      'cumulative_max_us':last['max_us'],'phase_buckets':counts,
                      'semantics':'log2 microsecond bucket upper bounds; not exact sample percentiles; cumulative_max is not phase-only max'}
    return answer

def reduce(run):
    value=base.reduce(run)
    plan=json.loads((run/'plan.json').read_text());result=json.loads((run/'result.json').read_text())
    phases=base.lines(run/'phases.jsonl');snaps=base.lines(run/'snapshots.jsonl')
    offers=base.lines(run/'offers.jsonl');producer=base.lines(run/'producer.jsonl');requests=base.lines(run/'requests.jsonl')
    byphase={p['phase']:p for p in phases}
    final=next((s for s in reversed(snaps) if s['label']=='provider-complete'),{})
    rows=final.get('dispatch_rows',[]);load=byphase.get('load');n=len(rows)
    first=next((s for s in snaps if load and s['elapsed']>=load['elapsed'] and s.get('states')=={'provider_accepted':n} and n),None)
    value['audit_after_verification_window']={key:value.pop(key,None) for key in [
        'load_until_all_success_visible_seconds','completed_jobs_per_second',
        'db_completed_statement_delta','db_statement_total','phase_process_cpu_seconds']}
    value['caller_to_stored_receipt_intent_ms']=value.pop('caller_to_persisted_receipt_ms',None)
    value['stored_receipt_intent_from_accepted_ms']=value.pop('stored_timestamp_delivery_ms',None)
    value.pop('reconstructed_offer_to_receipt_timestamp_ms',None)
    offer_times={r['op_id']:r['unix_ms']+(r['scheduled_monotonic']-r['submitted_monotonic'])*1000 for r in offers}
    offer_intent=collections.defaultdict(list)
    for row in rows:
        if row['op_id'] in offer_times and row['completed_at'] is not None:
            offer_intent[row['provider'].lower()].append(row['completed_at']-offer_times[row['op_id']])
    value['recorded_offer_to_stored_receipt_intent_ms']={k:base.distribution(v) for k,v in offer_intent.items()}
    value['first_sql_all_receipts_visible_seconds']=first['elapsed']-load['elapsed'] if first else None
    value['post_input_drain_seconds']=max(0,first['elapsed']-byphase['sustained-input-stop']['elapsed']) if first and 'sustained-input-stop' in byphase else None
    value['messages_planned']=sum(s['messages_per_second']*s['duration_seconds'] for s in plan.get('capacity_stages') or []) or len({r['op_id'] for r in offers})
    value['targets_per_message']=plan['target_count_per_message']
    value['actual_unique_targets_excluding_warmup']=value.pop('unique_durable_jobs') if final or plan['scenario']=='idle' else None
    value['unique_message_operations_accepted_http']=len({r['label'] for r in requests if r['path']=='/message' and r['status']==200 and not r['label'].endswith(':-01')})
    value['message_count_accepted_http_success']=result.get('producer_final',{}).get('accepted')
    value['producer_backlog_peak']=max((r['producer_waiting'] for r in producer),default=None)
    value['producer_http_inflight_peak']=max((r['http_inflight'] for r in producer),default=None)
    value['offer_submission_lag_ms']=base.distribution([(r['submitted_monotonic']-r['scheduled_monotonic'])*1000 for r in offers])
    value['backlog_definition']=plan['backlog_definition']
    stages=[]
    for stage in plan.get('capacity_stages') or []:
        rate=stage['messages_per_second'];start=byphase.get(f'rate-{rate}');end=byphase.get(f'rate-end-{rate}')
        samples=[s for s in snaps if s['label'].startswith(f'rate-{rate}-')]
        def pending(s):return sum(c for state,c in s.get('states',{}).items() if state not in ['provider_accepted','permanent_failed','terminal_failed','expired'])
        points=[{'elapsed':s['elapsed'],'accepted_targets':sum(s['states'].values()),
                 'committed_receipts':s['states'].get('provider_accepted',0),
                 'accepted_db_backlog_targets':pending(s)} for s in samples]
        relevant=[r for r in producer if start and end and start['elapsed']<=r['elapsed']<=end['elapsed']]
        growth=points[-1]['accepted_db_backlog_targets']-points[len(points)//2]['accepted_db_backlog_targets'] if len(points)>1 else None
        producer_growth=relevant[-1]['producer_waiting']-relevant[len(relevant)//2]['producer_waiting'] if len(relevant)>1 else None
        # A short finite lane can disprove sustainability; no linear extrapolation
        # can prove an unbounded steady state from ten/thirty seconds.
        stages.append({'offered_messages_per_second':rate,'offered_targets_per_second':rate*plan['target_count_per_message'],
            'duration_seconds':stage['duration_seconds'],'backlog_samples':points,
            'second_half_db_backlog_growth_targets':growth,'second_half_producer_backlog_growth_messages':producer_growth,
            'short_lane_classification':'not_sustained_backlog_grows' if (growth is not None and growth>0) or (producer_growth is not None and producer_growth>0) else 'bounded_observation_only',
            'kernel':kernel_delta(start,end),
            'start_fixture_stats':start.get('fixture_stats') if start else None,
            'end_fixture_stats':end.get('fixture_stats') if end else None,
            'direct_timing_phase_delta':timing_delta(start.get('fixture_stats') or {},end.get('fixture_stats') or {}) if start and end else None})
    value['capacity_stages']=stages
    value['phase_kernel']={b:kernel_delta(byphase.get(a),byphase.get(b)) for a,b in [('cold','setup'),('idle','idle-complete'),('load','first-all-targets-sql-visible'),('falloff-idle-start','falloff-idle-end')]}
    value['allocator_and_provider_resources_by_phase']=[{
        'phase':p['phase'],'unix_ms':p['unix_ms'],
        'allocator':(p.get('fixture_stats') or {}).get('allocator'),
        'provider_resources':(p.get('fixture_stats') or {}).get('provider_resources'),
        'owned_attempts':(p.get('fixture_stats') or {}).get('owned_attempts'),
        'network_inflight':(p.get('fixture_stats') or {}).get('network_inflight'),
        'receipts_owned':(p.get('fixture_stats') or {}).get('receipts_owned')
        } for p in phases]
    value['direct_timing_phase_deltas']={b:timing_delta(byphase.get(a,{}).get('fixture_stats') or {},byphase.get(b,{}).get('fixture_stats') or {}) for a,b in [('idle','idle-complete'),('load','first-all-targets-sql-visible'),('falloff-idle-start','falloff-idle-end')]}
    value['duration_counter_definitions']={
      'admission_commit':'direct tx.commit await; sample/total_us/max_us',
      'receipt_commit':'direct receipt tx.commit await; sample/total_us/max_us',
      'gate_wait':'all gate acquisition wait; sample/total_us/max_us',
      'network':'provider execution; sample/total_us/max_us',
      'receipt':'provider completion through gate wait and receipt commit; sample/total_us/max_us',
      'percentiles':'C2 timings32bucket phase deltas produce log2 bucket upper bounds only; aggregate samples,total,max alone provide none'}
    value['sql_definition']=plan['sql_oracle']
    value['receipt_latency_limit']='stored receipt_at is intent timestamp; committed receipt timing is SQL visibility and fixture receipt/commit stats, never inferred exact from intent timestamp'
    value['source_identity']=plan['source_identity'];value['ttl_mapping']=plan['ttl_mapping']
    value['performance_eligible']=value['performance_eligible'] and result.get('sampler_joined',False)
    value['vmmap_summaries']=[p.name for p in run.glob('vmmap-*.txt')]
    value['memory_claim']='RSS/VM, malloc zone bytes_in_use/bytes_reserved/blocks_in_use and owned gauges; bounded falloff object/owner evidence, not a general leak proof'
    return value

if __name__=='__main__':print(json.dumps([reduce(pathlib.Path(p)) for p in sys.argv[1:]],indent=2,sort_keys=True))
