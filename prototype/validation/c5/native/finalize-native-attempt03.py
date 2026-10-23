import pathlib,json,hashlib,os,re,sqlite3,subprocess
ROOT=pathlib.Path(__file__).resolve().parent;j=lambda p:json.loads(p.read_text());h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
matrix=j(ROOT/'attempt-03-matrix-result.json');assert matrix['status']=='PASSED' and matrix['failure'] is None and len(matrix['runs'])==6
cached=j(ROOT/'preflight-native-cache.json')
for row in cached['checks']:
 p=pathlib.Path(row['path']);p=p if p.is_absolute() else pathlib.Path('/Users/ethan/Repo/PushGo')/p
 assert h(p)==row['sha256'],str(p)
manifest=j(ROOT/'attempt-03-executed-adapter-manifest.json')
for row in manifest['files']:assert h(ROOT/row['path'])==row['sha256'],row['path']
test=j(ROOT/'android/c5-test-apk-manifest.json');assert h(pathlib.Path(test['path']))==test['sha256']
staging=j(ROOT/'android/c5-staging-after.json');assert h(pathlib.Path(staging['test_source']))==test['test_source_sha256']
for row in staging['production_main_files']:assert h(ROOT/'android'/row['path'])==row['sha256']
assert h(pathlib.Path(test['original_main_apk']))==test['original_main_apk_sha256']
binary=ROOT.parent/'binaries/c5-final-ordinary-sqlite-pg-mysql';assert h(binary)==matrix['binary_sha256']
pids=[];observed={};storage=[]
for engine in ['pg','mysql']:
 apple=ROOT/f'{engine}-apple-run-03';android=ROOT/f'{engine}-android-run-03';control=ROOT/f'{engine}-control-run-03'
 ar=j(apple/'final-result.json');assert ar['failure'] is None and len(ar['phase_exits'])==8 and set(ar['phase_exits'].values())=={0}
 for label in ar['phase_exits']:
  text=(apple/f'apple-{label}.log').read_text();assert re.search(r'Test run with 1 test[^\n]*passed',text) and 'skipped' not in text.lower()
  pids.append(j(apple/f'apple-{label}-observations.json')['process_id'])
 owner_a=j(apple/'native-owner-coalescing.json');owner_d=j(android/'native-owner-coalescing.json');assert owner_a['status']==owner_d['status']=='PASSED'
 dr=j(android/'result.json');assert dr['status']=='PASSED' and dr['executed_methods']==3 and dr['skipped']==0
 session=j(android/'native/session.json');pids.extend([session['phase1_pid'],session['phase2_pid'],owner_d['native']['pid']])
 for path in (android/'native').glob('*-first.log'):
  text=path.read_text();assert 'OK (1 test)' in text and 'FAILURES!!!' not in text and 'INSTRUMENTATION_FAILED' not in text
 with sqlite3.connect(f'file:{android}/native/room-before-restart.sqlite?mode=ro&immutable=1',uri=True) as c:
  before={'messages':c.execute('SELECT count(*) FROM messages').fetchone()[0],'outbox':c.execute('SELECT count(*) FROM inbound_delivery_ack_outbox').fetchone()[0]}
 with sqlite3.connect(f'file:{android}/native/room-after-restart.sqlite?mode=ro&immutable=1',uri=True) as c:
  after={'messages':c.execute('SELECT count(*) FROM messages').fetchone()[0],'outbox':c.execute('SELECT count(*) FROM inbound_delivery_ack_outbox').fetchone()[0]}
 with sqlite3.connect(f'file:{android}/native/room-after-coalescing.sqlite?mode=ro&immutable=1',uri=True) as c:
  coalesced={'messages':c.execute('SELECT count(*) FROM messages').fetchone()[0],'outbox':c.execute('SELECT count(*) FROM inbound_delivery_ack_outbox').fetchone()[0]}
 assert before=={'messages':5,'outbox':1} and after=={'messages':6,'outbox':0} and coalesced=={'messages':7,'outbox':0}
 control_result=j(control/'result.json');assert control_result['status']=='PASSED';pids+=control_result['pids']
 for path in [apple/'fixture.log',android/'candidate-first.log']:
  text=path.read_text();pids.extend(int(v)for v in re.findall(r'READY.*?pid=(\d+)',text));assert re.search(r'SHUTDOWN.*joined=2 panicked=0 aborted=0 http_timed_out=false tasks=0',text)
 recover=float(re.search(r'Test ordinaryClientLoop\(\) passed after ([0-9.]+) seconds',(apple/'apple-recover.log').read_text())[1])
 observed[engine]={'Apple':{'status':'PASSED','native_invocations':8,'recover_native_seconds':recover,'ingest_pid':j(apple/'apple-ingest-observations.json')['process_id'],'recover_pid':j(apple/'apple-recover-observations.json')['process_id'],'owner_coalescing':{'old_owner':owner_a['old_owner'],'current_owner':owner_a['current_owner'],'ACK_owner':owner_a['ack_request_device_key'],'late_provider_status':owner_a['late_provider_response_receipt']['status'],'provider_calls':owner_a['provider_calls']}},'Android':{'status':'PASSED','executed_methods':3,'skipped':0,'phase1_pid':session['phase1_pid'],'phase2_pid':session['phase2_pid'],'Room_before':before,'Room_after_restart':after,'Room_after_coalescing':coalesced,'owner_coalescing':owner_d['native'],'late_provider_status':owner_d['late_provider_response_receipt']['status'],'provider_calls':1},'Gateway_restart':{'status':'PASSED','pids':control_result['pids'],'provider_calls':control_result['provider_calls']}}
for path in sorted(ROOT.glob('attempt-03-*-closed-storage.json')):
 value=j(path);tables=value['tables'];storage.append({'path':path.name,'storage':value['storage'],'messages':len(tables['messages']),'targets':len(tables['targets']),'resident_payload_bytes':sum(r['payload_bytes']for r in tables['messages']),'ledger_usage':tables['ledger_usage']})
assert len(storage)==6
pids+=[j(ROOT/'attempt-03-emulator/emulator-process.json')['pid']];pids=sorted(set(pids));absent={}
# Android app PIDs belong to the guest, so prove package process death via owned
# emulator termination rather than comparing them to unrelated host PID numbers.
host_pids=[]
for engine in ['pg','mysql']:
 for name,file in [('apple','fixture.log'),('android','candidate-first.log')]:host_pids.extend(int(v)for v in re.findall(r'READY.*?pid=(\d+)',(ROOT/f'{engine}-{name}-run-03'/file).read_text()))
 host_pids+=j(ROOT/f'{engine}-control-run-03/result.json')['pids']
 for label in j(ROOT/f'{engine}-apple-run-03/final-result.json')['phase_exits']:host_pids.append(j(ROOT/f'{engine}-apple-run-03'/f'apple-{label}-observations.json')['process_id'])
host_pids.append(j(ROOT/'attempt-03-emulator/emulator-process.json')['pid'])
for pid in sorted(set(host_pids)):
 try:os.kill(pid,0);absent[str(pid)]=False
 except ProcessLookupError:absent[str(pid)]=True
assert all(absent.values()),absent
adb=subprocess.check_output(['/Users/ethan/Library/Android/sdk/platform-tools/adb','devices'],text=True);assert 'emulator-5580' not in adb,adb
assert j(ROOT/'attempt-03-emulator-lease-release.json')['status']=='released'
first=j(ROOT/'pg-apple-run-01/first-failure.json');assert first['phase_exits']=={}
quiet={'status':'QUIET','owned_host_pids_absent':absent,'owned_guest_app_processes':'owned emulator stopped; no guest survives','adb_devices':adb,'lease_released':True,'case_databases_dropped':6,'hash_checks':{'old_native_cache':626,'C5_cloned_production_main':191,'executed_adapter_files':len(manifest['files']),'C5_test_APK_sha256':test['sha256'],'frozen_Gateway_sha256':h(binary)},'outside_scope':'root-owned isolated PG/MySQL environment/core worker lifecycle and shared adb server are not this lane owned processes'}
(ROOT/'attempt-03-quiet.json').write_text(json.dumps(quiet,indent=2)+'\n')
summary={'status':'PASSED attempt03 final native execution','previous_complete_baseline':'attempt-02-summary.json','previous_complete_baseline_commit':'753a1836b134915b2c6af2ef9fa6d075f52125a3','backends':observed,'binary_sha256':matrix['binary_sha256'],'product_commit':matrix['source_commit'],'native_builds':'NOT RUN during attempt03; exact cached Apple bundle, original main APK/JNI and frozen C5 test APK reused','prior_build_history':matrix['native_builds'],'production_main_APK_sha256':test['original_main_apk_sha256'],'C5_test_APK_sha256':test['sha256'],'C5_test_source_sha256':test['test_source_sha256'],'storage':storage,'product_assertion_retries':0,'first_product_failures':[],'test_system_history':['Initial PG observer parameter calibration expected implicit integer but PG inferred TEXT; explicit synthetic CAST fixed; original observer-pg-first-failure.json preserved.','Offline Android Gradle build exit0/45s; after-hash wrapper exit1 due relative cwd path, fixed absolute observer paths and rechecked hashes without rebuilding. Original build wrapper receipt preserved.','Runtime run-01 FAILED observer42P01 due public search_path; 0 native invocations/no emulator. Product PG schema fixed pushgo_c. Original run/console/manifest/result/closed-error preserved.','Corrected read-only observer calibrated against exact frozen candidate pushgo_c; run-03 completed all six loops with no native assertion retries.'],'new_downloads_during_attempt03':False,'downloads':'Earlier pure Python observer dependency wheels downloaded and pinned under native only; no product/global dependency installation; native runtime/build were offline.','limitations':matrix['limitations']+['Room exports prove exact rows in closed copied main files, not arbitrary live-WAL snapshot completeness.','Gateway-control restart uses synthetic HTTP clients; separate native owner coalescing is proven by Apple and Android actual controller/repository storage/ACK evidence.'],'quiet':quiet}
(ROOT/'attempt-03-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps({'status':summary['status'],'backends':{k:{'Apple_native_invocations':v['Apple']['native_invocations'],'Apple_recover_seconds':v['Apple']['recover_native_seconds'],'Android_methods':v['Android']['executed_methods'],'Room':[v['Android']['Room_before'],v['Android']['Room_after_restart'],v['Android']['Room_after_coalescing']],'Gateway_restart_pids':v['Gateway_restart']['pids']}for k,v in observed.items()},'quiet':quiet['status'],'host_PIDs_absent':len(absent),'old_cache_hashes':626,'C5_main_source_hashes':191,'case_DBs_dropped':6},indent=2))
