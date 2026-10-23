#!/usr/bin/env python3
"""One first native Android run, actual candidate and exact synthetic provider capture.
The owned emulator must already run. No source build, product retry or emulator startup.
"""
import argparse,base64,hashlib,json,os,pathlib,re,signal,socket,sqlite3,subprocess,sys,threading,time,urllib.request
HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'harness'))
from c3_mock import C3Mock
from native_store_observer import NativeStoreObserver
observer=NativeStoreObserver()
p=argparse.ArgumentParser()
p.add_argument('--binary',type=pathlib.Path,required=True)
p.add_argument('--out',type=pathlib.Path,required=True)
p.add_argument('--serial',default='emulator-5580')
p.add_argument('--source-commit',help='Root-verified frozen binary source commit; defaults to live source HEAD')
p.add_argument('--source',type=pathlib.Path,default='/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-single-ledger-contract-20261015/workspace-final')
a=p.parse_args();run=a.out.resolve();run.mkdir(parents=True,exist_ok=False)
adb='/Users/ethan/Library/Android/sdk/platform-tools/adb'
env={k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','C1_','C2_','C3_')) and k.lower() not in ['http_proxy','https_proxy','all_proxy','no_proxy','rust_log']}
env['NO_PROXY']='127.0.0.1,localhost'
child=None;reader=None;lines=[];ready=threading.Event();reverses=[];failure=None;native_exit=None
binary=a.binary.resolve()
apk_identity=json.loads((HERE/'c6-apk-identity.json').read_text())
test_apk={'path':apk_identity['test_apk'],'sha256':apk_identity['test_apk_sha256']}
assert hashlib.sha256(pathlib.Path(apk_identity['main_apk']).read_bytes()).hexdigest()==apk_identity['main_apk_sha256']
assert hashlib.sha256(pathlib.Path(test_apk['path']).read_bytes()).hexdigest()==test_apk['sha256']
def dump(name,value): (run/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def command(args,**kw):return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,**kw).stdout
def hashfile(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def snapshot(label):
 rows={name:observer.query(f'SELECT * FROM {name}') for name in ['messages','targets','devices','channels','channel_subscriptions']}
 for table in rows.values():
  for row in table:
   for key,val in list(row.items()):
    if isinstance(val,bytes):row[key]={'hex':val.hex(),'bytes':len(val)}
 dump(f'{label}-ledger.json',rows)
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
  cmd=[str(binary),'--db-url',observer.url,'--http-addr',f'127.0.0.1:{port}',
   '--mock-endpoint',mock.endpoint,'--mock-token-service-endpoint',mock.endpoint,
   '--private-enabled','--private-mqtt-addr','127.0.0.1:0','--provider-budget','32','--claim-quantum','32','--public-base-url',public]
  live_source_commit=command(['git','-C',str(a.source),'rev-parse','HEAD']).strip()
  source_commit=a.source_commit or 'UNVERIFIED final Gateway source commit'
  source_diff=command(['git','-C',str(a.source),'diff','--','prototype/src'])
  (run/'candidate-source.diff').write_text(source_diff)
  dump('plan.json',{'command':[v if v != observer.url else '<owned-db-url-file>' for v in cmd],'storage':observer.metadata(),'binary_sha256':hashfile(binary),'source_commit':source_commit,'live_source_head':live_source_commit,
   'source_diff_sha256':hashlib.sha256(source_diff.encode()).hexdigest(),'source_root':str(a.source.resolve()),
   'c6_shared_apk_identity':apk_identity,
   'installed_c6_test_apk_manifest':test_apk,'source_provenance_sha256':hashfile(HERE.parent/'source-provenance.json'),'runner_sha256':hashfile(pathlib.Path(__file__)),
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
   C3_SKIP_BUILD='1',C3_RUN_OUT=str(run/'native'),C6_MAIN_APK=apk_identity['main_apk'],C6_MAIN_APK_SHA256=apk_identity['main_apk_sha256'],C6_TEST_APK=test_apk['path'],C6_TEST_APK_SHA256=test_apk['sha256'])
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
  assert observer.query('SELECT provider_token FROM devices WHERE device_key=?',(session['device_key'],))==[{'provider_token':None}],'real route logout not durable'
  assert observer.query('SELECT count(*) AS n FROM channel_subscriptions WHERE device_key=?',(session['device_key'],))==[{'n':0}],'real unsubscribe not durable'
  # This checks exact IDs/title/full bodies against the real captures and explicitly
  # qualifies that copied closed main files are not arbitrary live-WAL snapshots.
  qualification=command([sys.executable,str(HERE/'verify-existing-room.py'),str(run)])
  (run/'native-copy-qualification.log').write_text(qualification)
  # Distinct old same-token owner accepted this delivery before the real native
  # repository reclaims the route. No successful Gateway response is manufactured.
  def call(path,body):
   request=urllib.request.Request(public+path,data=json.dumps(body).encode(),headers={'Content-Type':'application/json'},method='POST')
   with urllib.request.urlopen(request,timeout=10) as response:return json.load(response)['data']
  old=call('/device/register',{'platform':'android'})['device_key']
  assert old!=session['device_key']
  call('/channel/device',{'device_key':old,'platform':'android','channel_type':'fcm','provider_token':session['provider_token']})
  credential=os.urandom(16).hex();channel=call('/channel/subscribe',{'device_key':old,'channel_name':'C5 transferred native Android','password':credential})['channel_id']
  mergeop='c5-android-native-owner';mock.configure({'provider':'fcm','token':session['provider_token'],'op_id':mergeop,'hold':True,'max_hold_seconds':60,'count':1})
  merged=call('/message',{'channel_id':channel,'password':credential,'op_id':mergeop,'title':'C5 native owner transfer','body':'c5-coalesced-owner-'+'x'*7000,'ttl':int(time.time())+3600})
  deadline=time.monotonic()+15
  while True:
   captures=mock.captures(token=session['provider_token'],op_id=mergeop)
   if captures:break
   assert time.monotonic()<deadline,'old-owner real provider capture missing'
   time.sleep(.025)
  assert len(captures)==1 and captures[0]['held'] and captures[0]['data']['provider_device_key']==old
  original=observer.query('SELECT * FROM messages WHERE delivery_id=?',(merged['delivery_id'],))[0]
  original_target=observer.query('SELECT * FROM targets WHERE delivery_id=?',(merged['delivery_id'],))[0]
  assert original_target['device_key']==old and original_target['pull_owner']==old and original_target['state']=='running'
  snapshot('coalescing-old-accepted-held')
  command([adb,'-s',a.serial,'shell','am','force-stop','io.ethan.pushgo.c6evidence'])
  method='phase3CoalescedOwnerPersistsAndReceivesTransferredDelivery'
  encoded=base64.b64encode(json.dumps(captures[0]['data'],separators=(',',':')).encode()).decode()
  instrument=subprocess.run([adb,'-s',a.serial,'shell','am','instrument','-w','-r','-e','class','io.ethan.pushgo.CandidateOrdinaryC3DeviceTest#'+method,
   '-e','c3GatewayUrl','http://127.0.0.1:18335','-e','c3PublicUrl',public,'-e','c3MockUrl',mock.endpoint,
   '-e','c5OldOwner',old,'-e','c5MergeCaptureBase64',encoded,'io.ethan.pushgo.c6evidence.test/io.ethan.pushgo.test.PushGoAndroidJUnitRunner'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  output=instrument.stdout
  (run/'native'/f'{method}-first.log').write_text(output)
  assert instrument.returncode==0,('owner instrumentation command failed',instrument.returncode)
  assert 'OK (1 test)' in output and 'FAILURES!!!' not in output and 'INSTRUMENTATION_FAILED' not in output,output
  owner=json.loads(command([adb,'-s',a.serial,'exec-out','run-as','io.ethan.pushgo.c6evidence','cat','files/c5-owner-coalescing.json']))
  assert owner['old_owner']==old and owner['current_owner']==owner['persisted_owner']==session['device_key']
  assert owner['delivery_id']==merged['delivery_id'] and owner['ack_state']=='acked' and owner['outbox_count']==0
  assert owner['canonical_before']==6 and owner['canonical_after']==7 and owner['pid']!=session['phase2_pid']
  after_ack=observer.query('SELECT * FROM targets WHERE delivery_id=?',(merged['delivery_id'],))[0]
  assert after_ack['device_key']==old and after_ack['pull_owner']==owner['current_owner'] and after_ack['acked_at'] is not None and after_ack['receipt_at'] is None
  assert all(after_ack[k]==original_target[k] for k in ['attempt_id','route_generation','accepted_at'])
  assert observer.query('SELECT coalesced_to FROM devices WHERE device_key=?',(old,))==[{'coalesced_to':owner['current_owner']}]
  snapshot('coalescing-native-acked-before-frozen-receipt')
  released=mock.release(provider='fcm',token=session['provider_token'],op_id=mergeop);assert released['released']==1
  deadline=time.monotonic()+15
  while True:
   targets=observer.query('SELECT * FROM targets WHERE delivery_id=?',(merged['delivery_id'],))
   if not targets or targets[0]['receipt_at'] is not None:break
   assert time.monotonic()<deadline,'old frozen provider receipt missing'
   time.sleep(.025)
  while True:
   finished=[v for v in mock.requests(op_id=mergeop) if v['event']=='provider_finished']
   if finished:break
   assert time.monotonic()<deadline,'old provider response completion missing'
   time.sleep(.025)
  assert len(finished)==1 and finished[0]['status']==200 and finished[0]['response_error'] is None
  final=observer.query('SELECT * FROM messages WHERE delivery_id=?',(merged['delivery_id'],))[0]
  assert all(final[k]==original[k] for k in ['message_id','delivery_id','accepted_at','expires_at','dedupe_until'])
  assert final['payload_bytes']==0 and len(mock.captures(token=session['provider_token'],op_id=mergeop))==1
  command([adb,'-s',a.serial,'shell','am','force-stop','io.ethan.pushgo.c6evidence'])
  with (run/'native/room-after-coalescing.sqlite').open('wb') as stream:
   result=subprocess.run([adb,'-s',a.serial,'exec-out','run-as','io.ethan.pushgo.c6evidence','cat','databases/c3_candidate_ordinary.db'],stdout=stream,stderr=subprocess.PIPE);assert result.returncode==0
  with sqlite3.connect(f'file:{run}/native/room-after-coalescing.sqlite?mode=ro&immutable=1',uri=True) as conn:
   exact=conn.execute('SELECT m.message_id,m.title,m.body,l.device_key,l.ack_state FROM messages m JOIN inbound_delivery_ledger l ON l.entity_id=m.message_id WHERE l.delivery_id=?',(merged['delivery_id'],)).fetchall()
   assert exact==[(merged['message_id'],'C5 native owner transfer','c5-coalesced-owner-'+'x'*7000,owner['current_owner'],'acked')],exact
   assert conn.execute('SELECT count(*) FROM inbound_delivery_ack_outbox').fetchone()[0]==0
  dump('native-owner-coalescing.json',{'status':'PASSED','native':owner,'original_target':original_target,'after_native_ack_before_receipt':after_ack,'frozen_provider_capture':captures[0],'message_stable_fields':{k:final[k]for k in ['message_id','delivery_id','accepted_at','expires_at','dedupe_until']},'provider_calls':1,'late_provider_response_receipt':finished[0],'closed_room_exact_rows':exact,'closed_room_sha256':hashfile(run/'native/room-after-coalescing.sqlite')})
  snapshot('coalescing-after-frozen-receipt')
  assert not (run/'mock/first-failure.json').exists(),'mock first failure exists'
  dump('result.json',{'status':'PASSED','native_exit':native_exit,'phase1_pid':session['phase1_pid'],'phase2_pid':session['phase2_pid'],
   'executed_methods':3,'owner_coalescing':'PASSED real native repository/settings/Keystore/Room/ACK with old accepted delivery','skipped':0,'production_source_unchanged':True,'test_harness_extended':'unchanged C5 Provider methods packaged with C6 Private class; C6 shared test APK','scope':'API37 emulator; actual candidate ordinary loop; explicit ACK drain and real process restart'})
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
