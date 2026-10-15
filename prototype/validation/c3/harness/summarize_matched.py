#!/usr/bin/env python3
"""Read completed matched lane receipts only. No SQLite, service or process calls."""
import json,math,pathlib,sys
OUT=pathlib.Path(__file__).resolve().parent.parent

def lines(p):
    if not p.exists():return []
    return [json.loads(s) for s in p.read_text().splitlines() if s.startswith('{')]

def summarize(run):
    r=json.loads((run/'profile-summary.json').read_text())[0]
    phases=lines(run/'phases.jsonl');by={x['phase']:x for x in phases}
    result={key:r.get(key) for key in ['run','performance_eligible','messages_planned','message_count_accepted_http_success','actual_unique_targets_excluding_warmup','first_sql_all_receipts_visible_seconds','post_input_drain_seconds','jobs_per_second_until_first_sql_all_receipts_visible','producer_backlog_peak','phase_kernel','time_l_peak_rss_mib','db_statement_delta_to_nearest_visibility_sample','db_stat_visibility_sample_offset_ms','direct_timing_phase_deltas','persistent_peer_stream_counts']}
    result['stages']=[{k:s.get(k) for k in ['offered_messages_per_second','second_half_db_backlog_growth_targets','second_half_producer_backlog_growth_messages','short_lane_classification']}|{'input_end_db_backlog_targets':s['backlog_samples'][-1]['accepted_db_backlog_targets']} for s in r.get('capacity_stages',[])]
    window=r['path_profile_windows'].get('load__first-all-targets-sql-visible')
    if not window:return result
    elapsed=window['elapsed_seconds'];profile=window['profile']
    totals={name:{phase:h.get('total_us',0)/1e6 for phase,h in data['phases'].items()} for name,data in profile.items()}
    hold=sum(v.get('gate_hold',0) for v in totals.values())
    result['load_to_firstsql_marker']={'elapsed_seconds':elapsed,'mutually_exclusive_gate_hold_seconds':hold,'gate_hold_fraction':hold/elapsed,'path_phase_totals_seconds':totals,'maintenance_targets':profile.get('maintenance',{}).get('statements',{}).get('maintenance_targets'),
      'semantics':'completed caller timers across marker snapshots; boundary calls may straddle; gate holds share one mutex and sum exclusively, nested fanout/maintenance excluded; total waits across calls are not wall time'}
    direct=r['direct_timing_phase_deltas']['first-all-targets-sql-visible']
    result['network_duration_integral_mean_slots']=direct['network']['total_us']/1e6/elapsed
    start,end=by['load']['unix_ms'],by['first-all-targets-sql-visible']['unix_ms']
    samples=[{**by['load']['fixture_stats'],'unix_ms':start}]
    samples += [s for s in lines(run/'gateway-0.log') if start<s.get('unix_ms',0)<end]
    samples += [{**by['first-all-targets-sql-visible']['fixture_stats'],'unix_ms':end}]
    samples=sorted(samples,key=lambda s:s['unix_ms'])
    gauges={}
    for key in ['owned_attempts','network_inflight','receipts_owned']:
        area=sum((b['unix_ms']-a['unix_ms'])*a[key] for a,b in zip(samples,samples[1:]))
        gauges[key]={'time_weighted_left_sample_mean':area/(end-start),'sample_max':max(s[key] for s in samples),'sample_count':len(samples),'cumulative_peak_at_end':samples[-1].get('peak_'+key)}
    result['sampled_occupancy']=gauges
    result['occupancy_semantics']='left-rectangle estimate from1Hzstats plus exactphase boundaries; not exact integral; peaks independent and never added; global H32x2=64'
    excluded=set(json.loads((run/'acknowledged-warmup-identities.json').read_text()))
    durations=[s['finish_ms']-s['start_ms'] for s in lines(run/'mock.jsonl') if s.get('event')=='finished' and s['delivery_id'] not in excluded]
    durations.sort()
    result['complete_mock_provider_duration_ms']={'count':len(durations),'mean':sum(durations)/len(durations),'p95':durations[math.ceil(.95*len(durations))-1],'p99':durations[math.ceil(.99*len(durations))-1],'fixed_adapter_delay_ms':20,'meaning':'received to response write completion; not durable receipt or remote consumption'}
    return result
if __name__=='__main__':
    runs=[pathlib.Path(p) for p in sys.argv[1:]] if len(sys.argv)>1 else sorted((OUT/'runs').glob('matched-observerfix-*'))
    print(json.dumps([summarize(r) for r in runs if (r/'profile-summary.json').exists()],indent=2,sort_keys=True))
