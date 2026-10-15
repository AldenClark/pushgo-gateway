#!/usr/bin/env python3
"""One first native Android run, actual candidate and exact synthetic provider capture.
The owned emulator must already run. No source build, product retry or emulator startup.
"""
import argparse,hashlib,json,os,pathlib,re,signal,socket,sqlite3,subprocess,sys,threading,time,urllib.request
HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'harness'))
from c3_mock import C3Mock
p=argparse.ArgumentParser()
p.add_argument('--binary',type=pathlib.Path,required=True)
p.add_argument('--out',type=pathlib.Path,required=True)
p.add_argument('--serial',required=True)
p.add_argument('--source-commit',help='Root-verified frozen binary source commit; defaults to live source HEAD')
p.add_argument('--source',type=pathlib.Path,required=True)
p.add_argument('--stage-root',type=pathlib.Path,required=True)
p.add_argument('--apk-manifest',type=pathlib.Path,required=True)
a=p.parse_args();run=a.out.resolve();run.mkdir(parents=True,exist_ok=False)
adb=str(pathlib.Path(os.environ['ANDROID_HOME'])/'platform-tools/adb')
env={k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','C1_','C2_','C3_')) and k.lower() not in ['http_proxy','https_proxy','all_proxy','no_proxy','rust_log']}
env['NO_PROXY']='127.0.0.1,localhost'
child=None;reader=None;lines=[];ready=threading.Event();reverses=[];failure=None;native_exit=None
binary=a.binary.resolve();db=run/'candidate.sqlite'
def dump(name,value): (run/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def command(args,**kw):return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,**kw).stdout
def hashfile(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def snapshot(label):
 if not db.exists():return
 with sqlite3.connect(f'file:{db}?mode=ro',uri=True) as c:
  c.row_factory=sqlite3.Row
  rows={name:[dict(v) for v in c.execute(f'SELECT * FROM {name}')] for name in ['messages','targets','devices','channels','channel_subscriptions']}
  # Blob bytes preserved in the raw SQLite backup; JSON uses hex rather than lossy decoding.
  for table in rows.values():
   for row in table:
    for key,val in list(row.items()):
     if isinstance(val,bytes):row[key]={'hex':val.hex(),'bytes':len(val)}
  dump(f'{label}-ledger.json',rows)
  with sqlite3.connect(run/f'{label}-raw.sqlite') as target:c.backup(target)
 with urllib.request.urlopen(public+'/__fixture/stats',timeout=5) as r:dump(f'{label}-http-stats.json',json.loads(r.read()))
def read_stdout():
 with (run/'candidate-first.log').open('x') as f:
  for line in child.stdout:
   lines.append(line);f.write(line);f.flush()
   if line.startswith('READY '):ready.set()
try:
 assert command([adb,'-s',a.serial,'shell','getprop','sys.boot_completed']).strip()=='1','owned emulator not booted'
 assert command([adb,'-s',a.serial,'shell','getprop','ro.build.version.sdk']).strip()=='37','expected API37'
 with C3Mock(run/'mock') as mock:
  with socket.socket() as choose:choose.bind(('127.0.0.1',0));port=choose.getsockname()[1]
  assert port not in (18335,18336)
  public=f'http://127.0.0.1:{port}'
  cmd=[str(binary),'--db-url',f'sqlite://{db}','--http-addr',f'127.0.0.1:{port}',
   '--mock-endpoint',mock.endpoint,'--mock-token-service-endpoint',mock.endpoint,
   '--provider-budget','32','--claim-quantum','32','--public-base-url',public]
  live_source_commit=command(['git','-C',str(a.source),'rev-parse','HEAD']).strip()
  source_commit=command(['git','-C',str(a.source),'rev-parse',a.source_commit or 'HEAD']).strip()
  source_diff=command(['git','-C',str(a.source),'diff','--','prototype/src'])
  (run/'candidate-source.diff').write_text(source_diff)
  dump('plan.json',{'command':cmd,'binary_sha256':hashfile(binary),'source_commit':source_commit,'live_source_head':live_source_commit,
   'source_diff_sha256':hashlib.sha256(source_diff.encode()).hexdigest(),'source_root':str(a.source.resolve()),
   'production_android_source_manifest_sha256':hashfile(HERE/'provenance/production-main-source-hashes.json'),
   'cached_jni_manifest_sha256':hashfile(HERE/'provenance/cached-jni-identity.json'),'native_apk_manifest':json.loads(a.apk_manifest.read_text()),
   'harness_source_manifest_sha256':hashfile(HERE/'provenance/executed-harness-source-identity.json'),'runner_sha256':hashfile(pathlib.Path(__file__)),
   'serial':a.serial,'scope':'unchanged native Android receiving repositories/Room/Keystore/HTTP/ACK with actual candidate; synthetic sender and provider peer; explicit drain, no OS WorkManager scheduling'})
  child=subprocess.Popen(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  reader=threading.Thread(target=read_stdout,daemon=True);reader.start()
  assert ready.wait(25),('candidate startup failed',lines[-8:])
  assert child.poll() is None,'candidate exited at readiness'
  for device_port,host_port in [(18335,port),(int(mock.endpoint.rsplit(':',1)[1]),int(mock.endpoint.rsplit(':',1)[1]))]:
   command([adb,'-s',a.serial,'reverse',f'tcp:{device_port}',f'tcp:{host_port}']);reverses.append(device_port)
  dump('reverse.json',{'mappings':reverses,'candidate_host_port':port,'advertised_port_not_reversed':port})
  snapshot('before-native')
  env.update(ANDROID_SERIAL=a.serial,C3_PUBLIC_URL=public,C3_GATEWAY_UPSTREAM_URL='http://127.0.0.1:18335',C3_MOCK_URL=mock.endpoint,
   C3_SKIP_BUILD='1',C3_RUN_OUT=str(run/'native'),C3_ANDROID_STAGE_ROOT=str(a.stage_root.resolve()),C3_ANDROID_APK_MANIFEST=str(a.apk_manifest.resolve()))
  with (run/'native-run-first.log').open('x') as log:
   result=subprocess.run([str(HERE/'run-native.sh')],env=env,stdout=log,stderr=subprocess.STDOUT)
  native_exit=result.returncode
  snapshot('after-native')
  assert native_exit==0,('native first run failed',native_exit)
  session=json.loads((run/'native/session.json').read_text())
  assert session['phase1_complete'] and session['phase2_complete']
  assert session['phase1_pid']!=session['phase2_pid'],'no genuine native process restart'
  native_rows={}
  for label in ['before','after']:
   with sqlite3.connect(f'file:{run}/native/room-{label}-restart.sqlite?mode=ro&immutable=1',uri=True) as c:
    c.row_factory=sqlite3.Row
    native_rows[label]={name:[dict(v) for v in c.execute(f'SELECT * FROM {name}')] for name in ['messages','inbound_delivery_ledger','inbound_delivery_ack_outbox','channel_subscriptions']}
  before=native_rows['before'];after=native_rows['after']
  assert len(before['messages'])==session['canonical_count']
  assert len(after['messages'])==session['canonical_count']+1
  assert len(before['inbound_delivery_ack_outbox'])==1 and before['inbound_delivery_ack_outbox'][0]['delivery_id']==session['unknown_delivery_id']
  assert not after['inbound_delivery_ack_outbox'],'native pending ACK survived successful recovery'
  assert next(v for v in before['inbound_delivery_ledger'] if v['delivery_id']==session['unknown_delivery_id'])['ack_state']=='pending'
  assert next(v for v in after['inbound_delivery_ledger'] if v['delivery_id']==session['unknown_delivery_id'])['ack_state']=='acked'
  dump('native-room-observations.json',native_rows)
  with sqlite3.connect(f'file:{db}?mode=ro',uri=True) as c:
   assert c.execute('SELECT provider_token FROM devices WHERE device_key=?',(session['device_key'],)).fetchone()==(None,),'real route logout not durable'
   assert c.execute('SELECT count(*) FROM channel_subscriptions WHERE device_key=?',(session['device_key'],)).fetchone()==(0,),'real unsubscribe not durable'
  # This checks exact IDs/title/full bodies against the real captures and explicitly
  # qualifies that copied closed main files are not arbitrary live-WAL snapshots.
  qualification=command([sys.executable,str(HERE/'verify-existing-room.py'),str(run)])
  (run/'native-copy-qualification.log').write_text(qualification)
  assert not (run/'mock/first-failure.json').exists(),'mock first failure exists'
  dump('result.json',{'status':'PASSED','native_exit':native_exit,'phase1_pid':session['phase1_pid'],'phase2_pid':session['phase2_pid'],
   'executed_methods':2,'skipped':0,'source_unchanged':True,'scope':'API37 emulator; actual candidate ordinary loop; explicit ACK drain and real process restart'})
except BaseException as e:
 failure=repr(e);dump('first-failure.json',{'failure':failure,'native_exit':native_exit})
finally:
 if child and child.poll() is None:
  child.send_signal(signal.SIGTERM)
  try:child.wait(timeout=25)
  except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5);failure=failure or 'forced candidate kill'
 if reader:reader.join(timeout=2)
 if child:
  shutdown=[s for s in lines if s.startswith('SHUTDOWN ')]
  if child.returncode!=0 or not shutdown or not re.search(r'joined=2 panicked=0 aborted=0 http_timed_out=false',shutdown[-1]):failure=failure or 'candidate shutdown incomplete'
 for device_port in reverses:
  try:command([adb,'-s',a.serial,'reverse','--remove',f'tcp:{device_port}'])
  except BaseException as e:failure=failure or repr(e)
 dump('final-result.json',{'failure':failure,'native_exit':native_exit,'candidate_exit':child.returncode if child else None,
  'candidate_shutdown':[s.strip() for s in lines if s.startswith('SHUTDOWN ')],
  'owned_emulator':'left running for root-coordinated shutdown','scope':'emulator only; no real FCM, physical device, WorkManager OS scheduling, release or production evidence'})
if failure:raise SystemExit(failure)
print('PASS: native Android ordinary candidate loop, durable ACK and full process restart')
