#!/usr/bin/env python3
"""Offline finite comparison; no provider or fixture launch."""
import hashlib,json,math,pathlib
OUT=pathlib.Path(__file__).resolve().parents[1]
def lines(path):
    with path.open() as f:
        for line in f:yield json.loads(line)
def dist(values):
    values.sort();n=len(values)
    return {'samples':n,'mean_ms':sum(values)/n if n else None,
        **{f'p{p}_ms':values[math.ceil(n*p/100)-1] if n else None for p in (50,95,99)}}
results=[]
for label in ('10e-offer256-r1','19cc-offer256-r1','19cc-offer256-r2','10e-offer256-r2'):
    run=OUT/'runs'/label
    exact=json.loads((run/'exact-commit-summary.json').read_text())
    profile=json.loads((run/'profile-summary.json').read_text())[0]
    telemetry=json.loads((run/'telemetry.json').read_text());scale=telemetry['mach_numer']/telemetry['mach_denom']/1_000_000
    offers={r['op_id']:r for r in lines(run/'offers.jsonl')}
    requests=[r for r in lines(run/'requests.jsonl') if r['path']=='/message' and r['label'] in offers]
    assert len(requests)==len(offers)==2560
    frontend={
        'offer_to_http_start':dist([(r['http_start_mach_ticks']-offers[r['label']]['offer_mach_ticks'])*scale for r in requests]),
        'http_start_to_response':dist([(r['http_end_mach_ticks']-r['http_start_mach_ticks'])*scale for r in requests]),
        'offer_to_response':dist([(r['http_end_mach_ticks']-offers[r['label']]['offer_mach_ticks'])*scale for r in requests])}
    mock_durations={provider:[] for provider in ('fcm','apns')}
    for event in lines(run/'mock.jsonl'):
        if event['event']=='finished' and event['op_id'] in offers:
            assert event['status']==200 and not event['response_error']
            mock_durations[event['provider']].append(event['finish_ms']-event['start_ms'])
    assert all(len(v)==20480 for v in mock_durations.values())
    window=profile['path_profile_windows']['load__first-all-targets-sql-visible']
    phases={path:data['phases'] for path,data in window['profile'].items()}
    total_gate_hold=sum(p.get('gate_hold',{}).get('total_us',0) for p in phases.values())
    results.append({'run':label,'binary_sha256':profile['binary_sha256'],
        'exact_offer_to_target_post_commit':exact,'frontend_mach_distributions_ms':frontend,
        'first_sql_seconds':profile['first_sql_all_receipts_visible_seconds'],
        'completion_rate_targets_per_second_including_drain':profile['jobs_per_second_until_first_sql_all_receipts_visible'],
        'producer_waiting_peak_messages':profile['producer_backlog_peak'],
        'active_http_peak_messages':profile['producer_http_inflight_peak'],
        'stages':profile['capacity_stages'],'phase_kernel':profile['phase_kernel'],
        'gateway_time_l_peak_rss_mib':profile['time_l_peak_rss_mib'],
        'window_seconds':window['elapsed_seconds'],
        'gate_hold_wall_fraction':total_gate_hold/(window['elapsed_seconds']*1_000_000),
        'path_phase_histogram_bounds':phases,
        'direct_histogram_bounds':profile['direct_timing_phase_deltas']['first-all-targets-sql-visible'],
        'provider_mock_duration_ms':{p:dist(v) for p,v in mock_durations.items()},
        'ignored_legacy_reducer_fields':{'reason':'register token seed20261014 differs actual route seed20261015; shifted per-target joins and incomplete14of16 distribution',
            'fields':['queue_to_first_network_ms','caller_to_first_network_ms','mock_http_duration_ms','response_to_completion_intent_ms'],
            'raw_receipts_retained_unchanged':True},
        'semantic_limits':['commit timestamp is callback immediately after successful COMMIT await, not internal fsync instant',
            'phase quantiles are logarithmic upper bounds; caller scheduling and worker queue included',
            'gate hold overlaps BEGIN/SQL/COMMIT; do not sum nested or percentile values',
            'finite driver retains planned input/wire rows; driver RAM is excluded from Gateway RSS',
            'synthetic loopback fixed20ms provider; ten-second input does not establish sustained capacity']})
(OUT/'abba4-comparison.json').write_text(json.dumps(results,indent=2)+'\n')
text=['# C4 finite SQLite 10e/19cc comparison','',
      '2560 offered messages / 40960 targets per lane, ten-second input, ABBA order; H32/Q32, 20ms loopback provider. All rows below require complete offered denominators and zero telemetry loss.', '',
      '| lane | offer→target COMMIT p95 ms | p99 ms | first SQL all s | target/s incl drain | producer waiting peak | active HTTP peak | Gateway peak RSS MiB |',
      '|---|---:|---:|---:|---:|---:|---:|---:|']
for row in results:
    e=row['exact_offer_to_target_post_commit']['success']
    text.append(f"| {row['run']} | {e['p95_observed_ms']:.3f} | {e['p99_observed_ms']:.3f} | {row['first_sql_seconds']:.3f} | {row['completion_rate_targets_per_second_including_drain']:.1f} | {row['producer_waiting_peak_messages']} | {row['active_http_peak_messages']} | {max(row['gateway_time_l_peak_rss_mib']):.2f} |")
text+=['','Commit means the observed successful COMMIT-await completion callback; it does not timestamp the earlier internal fsync. Per-target nearest-rank percentiles use one shared Mach monotonic clock and complete sample streams, excluding only independently ACK-verified warmup identities.','',
       'Producer waiting is submitted−HTTP-started and excludes active HTTP. Active HTTP is HTTP-started−finished. Phase histograms remain log2 upper bounds and cannot be added; gate hold includes nested BEGIN/SQL/COMMIT. Finite Python driver memory is separate from measured Gateway RSS.','',
       'This is a local synthetic comparison of the two frozen C variants with identical measurement patches. No CURRENT/C32 ranking or sustainable256-message/s claim is made. Detailed front queue, gate wait/hold, pool, BEGIN, SQL, COMMIT, provider and resource evidence is in abba4-comparison.json.', '',
       'Legacy reducer caveat: its register token seed is20261014, while the C3 route seed is20261015. Its four token-joined fields are excluded (queue_to_first_network_ms, caller_to_first_network_ms, mock_http_duration_ms, response_to_completion_intent_ms). The provider duration distributions in this C4 report instead use all40960 original finished records with actual operation identity; exact commit and native phase histograms are unaffected. Raw legacy reductions remain preserved.']
(OUT/'abba4-comparison.md').write_text('\n'.join(text)+'\n')
print('\n'.join(text))
