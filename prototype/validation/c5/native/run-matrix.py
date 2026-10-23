"""Root-dispatched runtime window only. No builds, downloads, product edits or retries."""
import argparse,pathlib,subprocess,os,sys,json,hashlib,time,signal,re
ROOT=pathlib.Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--binary',type=pathlib.Path,required=True);p.add_argument('--binary-sha256',required=True);p.add_argument('--source-commit',required=True);p.add_argument('--window-authorized',action='store_true');p.add_argument('--attempt',default='01');a=p.parse_args()
assert re.fullmatch(r'[0-9]{2}',a.attempt)
tag='attempt-'+a.attempt
assert a.window_authorized,'root runtime window required'
assert hashlib.sha256(a.binary.read_bytes()).hexdigest()==a.binary_sha256,'frozen Gateway mismatch'
helper=ROOT.parent/'env/isolated_db.py';lease_python='/Users/ethan/.local/bin/python3.13'
lease_helper=pathlib.Path('/Users/ethan/.codex/plugins/cache/dev-flow/dev-flow/2.0.3/skills/dev-flow/scripts/dev-flow.py')
emulator_env=os.environ.copy();emulator_env['C5_EMULATOR_EVIDENCE_DIR']=str(ROOT/(tag+'-emulator'))
lease=None;emulator_started=False;cases=[];runs=[];failure=None;count=None
# Freeze source/tool dependencies that determine this native lane. Product and native cache
# remain external and are checked before/after through preflight-native-cache.json.
paths=[p for p in ROOT.rglob('*') if p.is_file() and (p.suffix in ('.py','.sh') or p.name.endswith('.whl') or 'vendor' in p.parts or p.name=='CandidateOrdinaryC3DeviceTest.kt' or p.name=='app-debug-androidTest.apk') and '__pycache__' not in p.parts]
manifest=[{'path':str(p.relative_to(ROOT)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}for p in sorted(paths)]
(ROOT/(tag+'-executed-adapter-manifest.json')).write_text(json.dumps({'files':manifest,'binary_sha256':a.binary_sha256,'gateway_source_commit':a.source_commit},indent=2)+'\n')
def checkcache():
 value=json.loads((ROOT/'preflight-native-cache.json').read_text())
 for row in value['checks']:
  path=pathlib.Path(row['path']);path=path if path.is_absolute() else pathlib.Path('/Users/ethan/Repo/PushGo')/path
  assert hashlib.sha256(path.read_bytes()).hexdigest()==row['sha256'],row['path']
 test=json.loads((ROOT/'android/c5-test-apk-manifest.json').read_text());staging=json.loads((ROOT/'android/c5-staging-after.json').read_text())
 assert hashlib.sha256(pathlib.Path(test['path']).read_bytes()).hexdigest()==test['sha256']
 assert hashlib.sha256(pathlib.Path(staging['test_source']).read_bytes()).hexdigest()==test['test_source_sha256']
 assert hashlib.sha256(pathlib.Path(test['original_main_apk']).read_bytes()).hexdigest()==test['original_main_apk_sha256']
 for row in staging['production_main_files']:assert hashlib.sha256((ROOT/'android'/row['path']).read_bytes()).hexdigest()==row['sha256'],row['path']
 return value['count']
def dump(name,value):(ROOT/(tag+'-'+name)).write_text(json.dumps(value,indent=2,sort_keys=True,default=lambda v:{'hex':bytes(v).hex(),'bytes':len(v)} if isinstance(v,(bytes,memoryview)) else str(v))+'\n')
def run_command(cmd,log,env=None):
 with (ROOT/(tag+'-'+log)).open('x')as stream:
  value=subprocess.run(cmd,stdout=stream,stderr=subprocess.STDOUT,env=env)
 assert value.returncode==0,(str(log),value.returncode)
try:
 count=checkcache()
 for engine in ['pg','mysql']:
  for client in ['apple','android','control']:
   if client=='android' and not emulator_started:
    lease=json.loads(subprocess.check_output([lease_python,str(lease_helper),'resource-lease','acquire','--kind','emulator','--resource','emulator-5580','--ttl-seconds','1800'],text=True));dump('emulator-lease.json',lease)
    assert lease.get('token'),'emulator lease not acquired'
    emulator_started=True
    run_command([sys.executable,str(ROOT/'emulator_lifecycle.py'),'start'],'emulator-start-console-first.log',emulator_env)
   case=json.loads(subprocess.check_output([sys.executable,str(helper),'create',engine,'native_'+client],text=True));cases.append(case)
   env=os.environ.copy();env.update(C5_DB_URL_FILE=case['url_file'],C5_DB_BACKEND='postgres' if engine=='pg' else engine)
   out=ROOT/(engine+'-'+client+'-run-'+a.attempt)
   cmd=[sys.executable,str(ROOT/('harness/run_c3_control_restart.py' if client=='control' else client+'/run-loop.py')),'--binary',str(a.binary),'--out',str(out),'--source-commit',a.source_commit]
   if client=='control':cmd+=['--binary-sha256',a.binary_sha256]
   run_command(cmd,engine+'-'+client+'-console-first.log',env)
   runs.append({'engine':engine,'client':client,'out':str(out),'database':case['database'],'status':'PASSED'})
   dump('runtime-progress.json',{'runs':runs,'status':'RUNNING'})
except BaseException as error:
 failure=repr(error);dump('matrix-first-failure.json',{'error':failure,'completed':runs})
finally:
 if emulator_started:
  try:run_command([sys.executable,str(ROOT/'emulator_lifecycle.py'),'stop'],'emulator-stop-console-first.log',emulator_env)
  except BaseException as error:failure=failure or repr(error)
 if lease:
  try:
   released=subprocess.check_output([lease_python,str(lease_helper),'resource-lease','release','--kind','emulator','--resource','emulator-5580','--token',lease['token']],text=True);(ROOT/(tag+'-emulator-lease-release.json')).write_text(released)
  except BaseException as error:failure=failure or repr(error)
 # Native stores and Gateway SQL JSON snapshots retained; fresh Gateway DBs dropped after observations.
 sys.path.insert(0,str(ROOT/'harness'))
 from native_store_observer import NativeStoreObserver
 for case in cases:
  try:
   os.environ.update(C5_DB_URL_FILE=case['url_file'],C5_DB_BACKEND='postgres' if case['engine']=='pg' else case['engine'])
   obs=NativeStoreObserver();rows={name:obs.query(f'SELECT * FROM {name}') for name in ['messages','targets','devices','channels','channel_subscriptions','ledger_usage']}
   dump(case['engine']+'-'+case['database']+'-closed-storage.json',{'storage':obs.metadata(),'tables':rows})
  except BaseException as error:
   dump(case['engine']+'-'+case['database']+'-closed-storage-error.json',{'error':repr(error)})
   failure=failure or repr(error)
  try:subprocess.run([sys.executable,str(helper),'drop',case['engine'],case['database']],check=True,capture_output=True,text=True)
  except BaseException as error:failure=failure or repr(error)
 try:
  count=checkcache();assert hashlib.sha256(a.binary.read_bytes()).hexdigest()==a.binary_sha256
  for row in manifest:assert hashlib.sha256((ROOT/row['path']).read_bytes()).hexdigest()==row['sha256'],row['path']
 except BaseException as error:failure=failure or repr(error)
 dump('matrix-result.json',{'status':'PASSED'if failure is None else'FAILED','failure':failure,'runs':runs,'native_cache_hashes_rechecked':count,'binary_sha256':a.binary_sha256,'source_commit':a.source_commit,'owned_case_databases_drop_attempted':len(cases),'native_builds':'Apple NOT RUN cached bundle; Android isolated test APK offline build45s; production Kotlin dependency tasks recompiled due cloned path, cached installed main APK/JNI unchanged','test_apk_manifest':'android/c5-test-apk-manifest.json','first_build_wrapper_failure_retained':'android/c5-build-wrapper-first-failure.json','dependencies_downloaded':True,'first_connection_calibration_failure_retained':'observer-pg-first-failure.json','limitations':['Apple macOS host controllers/GRDB; no iOS/Watch/OS background/UI','Android API37 emulator, explicit ACK drain; no real FCM/WorkManager scheduling','cached JNI exact source revision UNVERIFIED; private channel journey unused','synthetic providers only; no release/deploy/production/physical acceptance']})
if failure:raise SystemExit(failure)
print('PASS six actual native/control loops across PostgreSQL and MySQL; owned emulator stopped and case DBs dropped')
