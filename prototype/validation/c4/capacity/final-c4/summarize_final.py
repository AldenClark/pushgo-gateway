#!/usr/bin/env python3
"""Offline final-C4 followup report; local paths, intentionally not portable."""
import hashlib,json,math,os,pathlib,re
OUT=pathlib.Path(__file__).resolve().parent
def lines(p):
    with p.open() as f:
        for line in f:yield json.loads(line)
def dist(v):
    v.sort();n=len(v)
    return {'samples':n,'mean_ms':sum(v)/n if n else None,
        **{f'p{p}_ms':v[math.ceil(n*p/100)-1] if n else None for p in (50,95,99)}}
rows=[];pids=[]
for repeat in (1,2):
    run=OUT/'runs'/('c4-final-offer256-r'+str(repeat))
    exact=json.loads((run/'exact-commit-summary.json').read_text())
    profile=json.loads((run/'profile-summary.json').read_text())[0]
    telemetry=json.loads((run/'telemetry.json').read_text());result=json.loads((run/'result.json').read_text())
    assert exact['offered_targets']==40960 and exact['outcomes']=={'accepted':40960}
    assert all(telemetry[k]==0 for k in ['dropped','invalid_ids','write_errors']) and telemetry['writer_joined']
    assert result['failure'] is None and result['exit_codes']==[0]
    assert all(result[k] for k in ['daemon_exited','log_readers_joined','sampler_joined','shared_mock_server_joined'])
    for log in run.glob('gateway-*.log'):
        pids += [int(m.group(1)) for m in re.finditer(r'^READY pid=(\d+)',log.read_text(),re.M)]
    offers={r['op_id']:r for r in lines(run/'offers.jsonl')}
    requests=[r for r in lines(run/'requests.jsonl') if r['path']=='/message' and r['label'] in offers]
    assert len(offers)==len(requests)==2560
    scale=telemetry['mach_numer']/telemetry['mach_denom']/1_000_000
    frontend={'offer_to_http_start':dist([(r['http_start_mach_ticks']-offers[r['label']]['offer_mach_ticks'])*scale for r in requests]),
        'http_start_to_response':dist([(r['http_end_mach_ticks']-r['http_start_mach_ticks'])*scale for r in requests]),
        'offer_to_response':dist([(r['http_end_mach_ticks']-offers[r['label']]['offer_mach_ticks'])*scale for r in requests])}
    mock={p:[] for p in ('fcm','apns')}
    for event in lines(run/'mock.jsonl'):
        if event['event']=='finished' and event['op_id'] in offers:
            assert event['status']==200 and not event['response_error']
            mock[event['provider']].append(event['finish_ms']-event['start_ms'])
    assert all(len(v)==20480 for v in mock.values())
    window=profile['path_profile_windows']['load__first-all-targets-sql-visible']
    paths={path:data['phases'] for path,data in window['profile'].items()}
    stage=profile['capacity_stages'][0]
    rss_samples=[v for v in lines(run/'rss.jsonl') if isinstance(v.get('proc_rss_bytes'),(int,float))]
    last_rss=rss_samples[-1] if rss_samples else None
    rows.append({'run':run.name,'source_identity':profile['source_identity'],'binary_sha256':profile['binary_sha256'],
        'messages':2560,'offered_targets':40960,'successful_targets':40960,'admission_failed':0,'provider_failed':0,'timeout':0,'unfinished':0,'dropped':0,
        'exact_offer_to_post_commit':exact,'frontend_mach_ms':frontend,
        'first_sql_seconds':profile['first_sql_all_receipts_visible_seconds'],
        'target_per_second_including_drain':profile['jobs_per_second_until_first_sql_all_receipts_visible'],
        'producer_waiting_peak':profile['producer_backlog_peak'],'active_http_peak':profile['producer_http_inflight_peak'],
        'input_end_db_backlog_targets':stage['backlog_samples'][-1]['accepted_db_backlog_targets'],
        'second_half_db_backlog_growth_targets':stage['second_half_db_backlog_growth_targets'],
        'second_half_producer_waiting_growth_messages':stage['second_half_producer_backlog_growth_messages'],
        'gateway_peak_rss_mib':profile['time_l_peak_rss_mib'],
        'last_valid_rss_sample':last_rss,
        'rss_recovery_limit':'last observed sample during ACK; no fixed post-load/ACK idle recovery window in these sustained lanes; do not claim return-to-idle RSS',
        'phase_kernel':profile['phase_kernel'],
        'window_seconds':window['elapsed_seconds'],'path_phase_histogram_bounds':paths,
        'gate_hold_wall_fraction':sum(p.get('gate_hold',{}).get('total_us',0) for p in paths.values())/(window['elapsed_seconds']*1_000_000),
        'direct_histogram_bounds':profile['direct_timing_phase_deltas']['first-all-targets-sql-visible'],
        'complete_provider_mock_ms':{p:dist(v) for p,v in mock.items()},
        'ignored_legacy_fields':['queue_to_first_network_ms','caller_to_first_network_ms','mock_http_duration_ms','response_to_completion_intent_ms']})
for pid in pids:
    try:os.kill(pid,0)
    except ProcessLookupError:pass
    else:raise AssertionError('owned fixture still alive '+str(pid))
summary={'status':'PASSED_FINAL_C4_2_QUIET','source_commit':'d925b97fe30068b66aefb66e33284831df6d8e4f',
    'product_implementation_commit':'f8ed62f94ce44e285414f1a0f6894878763f4dbe','owned_fixture_pids_all_exited':pids,
    'scope':'separate finalC4 SQLite-only two-lane regression; oldABBA4 unchanged; noPGperformance or causal singlevariable comparison',
    'boundary':'sharedMachclock actualoffer to callback immediately after successfulCOMMITawait changed>0 beforepooldrop; notfsyncinstant',
    'lanes':rows}
(OUT/'final-c4-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
text=['# Final C4 SQLite finite followup','',
    'Source d925b97, implementation f8ed62f; two final-source lanes reported separately from prior10e/19cc ABBA.', '',
    '| lane | messages | offered/success | failed/timeout/unfinished/dropped | p95 ms | p99 ms | first SQL s | target/s incl drain | producer waiting | active HTTP | peak RSS MiB |',
    '|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|']
for row in rows:
    e=row['exact_offer_to_post_commit']['success']
    text.append(f"| {row['run']} | 2560 | 40960/40960 | 0/0/0/0 | {e['p95_observed_ms']:.3f} | {e['p99_observed_ms']:.3f} | {row['first_sql_seconds']:.3f} | {row['target_per_second_including_drain']:.1f} | {row['producer_waiting_peak']} | {row['active_http_peak']} | {max(row['gateway_peak_rss_mib']):.2f} |")
text+=['','Exact nearest-rank sample quantiles cover all offered targets. Callback timing is the observed post-COMMIT-await completion boundary, not physical fsync time. Producer waiting excludes active HTTP. Rates include drain and do not establish sustained capacity. Same original driver/provider/resources/deadlines and observer modules; original four token-joined legacy fields excluded, complete mock durations independently reconstructed. All owned fixtures and observers joined/exited.', '',
    '| lane | DB backlog at input end | second-half DB growth | second-half producer waiting growth | CPU user/system seconds load→SQL marker | last RSS MiB / phase | gate hold wall fraction |',
    '|---|---:|---:|---:|---|---|---:|']
for row in rows:
    cpu=row['phase_kernel']['first-all-targets-sql-visible'];rss=row['last_valid_rss_sample']
    text.append(f"| {row['run']} | {row['input_end_db_backlog_targets']} | {row['second_half_db_backlog_growth_targets']} | {row['second_half_producer_waiting_growth_messages']} | {cpu['user_cpu_seconds']:.6f}/{cpu['system_cpu_seconds']:.6f} | {rss['proc_rss_bytes']/1048576:.3f} / {rss['phase']} | {row['gate_hold_wall_fraction']:.4f} |")
text+=['','Last RSS is an ACK-phase sample, not a fixed recovery window. Peak RSS covers the whole owned fixture including measurement observer; no return-to-idle claim. Faster samples cannot be attributed to facade, Health, PG feature or any individual change, and do not reconstruct the older approximately5s difference. Stage values below are caller-wall means in microseconds; full histograms preserve samples and log2 upper bounds.', '',
    '| lane/path | gate wait | gate hold | pool | BEGIN | SQL inclusive | COMMIT |',
    '|---|---:|---:|---:|---:|---:|---:|']
for row in rows:
    for path in ('accept','claim','receipt'):
        p=row['path_phase_histogram_bounds'][path]
        text.append('| '+row['run']+'/'+path+' | '+' | '.join(f"{p[name]['mean_us']:.3f}" for name in ('gate_wait','gate_hold','pool_acquire','begin','statement_inclusive','commit'))+' |')
(OUT/'final-c4-summary.md').write_text('\n'.join(text)+'\n')
files={}
for p in OUT.rglob('*'):
    if p.is_file() and 'source' not in p.relative_to(OUT).parts and p.suffix not in ['.tar','.sqlite','.bin'] and p.name not in ['final-handoff-manifest.json','c4-final-observer']:
        files[str(p.relative_to(OUT))]=hashlib.sha256(p.read_bytes()).hexdigest()
for repeat in (1,2):
    p=OUT/'runs'/('c4-final-offer256-r'+str(repeat))/'commits.bin';files[str(p.relative_to(OUT))]=hashlib.sha256(p.read_bytes()).hexdigest()
files['c4-final-observer']=hashlib.sha256((OUT/'c4-final-observer').read_bytes()).hexdigest()
(OUT/'final-handoff-manifest.json').write_text(json.dumps({'status':'PASSED_FINAL_C4_2_QUIET','source_commit':summary['source_commit'],
    'product_implementation_commit':summary['product_implementation_commit'],'owned_fixture_pids_all_exited':pids,'messages':5120,'all_offered_targets':81920,'successful_targets':81920,
    'admission_failed':0,'provider_failed':0,'timeout':0,'unfinished':0,'dropped_invalid_write_errors':0,'sha256':files},indent=2)+'\n')
print('\n'.join(text))
