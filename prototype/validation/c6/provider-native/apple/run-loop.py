#!/usr/bin/env python3
"""Actual native receiver controllers against candidate C; sender is explicit HTTP.
No real APNs, TokenService, app bundle, permission, or OS background evidence.
Every assertion failure is retained; there is no product-assertion retry.
"""
import argparse, base64, hashlib, http.server, json, os, pathlib, re, signal, sqlite3, subprocess, sys, threading, time, urllib.request, urllib.error
HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'harness'))
from c3_mock import C3Mock
from native_store_observer import NativeStoreObserver
observer=NativeStoreObserver()
p=argparse.ArgumentParser(); p.add_argument('--binary',type=pathlib.Path,required=True); p.add_argument('--out',type=pathlib.Path,required=True); p.add_argument('--source-commit',required=True)
a=p.parse_args(); run=a.out.resolve(); run.mkdir(parents=True,exist_ok=False)
accesses=[]; lock=threading.Lock(); expected={}; backend=None; child=None; pid=None; lines=[]; exits={}; failure=None; fail_ack=False
synthetic=os.urandom(32).hex(); ready=threading.Event()
env={k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','C1_','C2_','C3_')) and k.lower() not in ['http_proxy','https_proxy','all_proxy','no_proxy','rust_log']};env['NO_PROXY']='127.0.0.1,localhost'
def dump(path,value): path.write_text(json.dumps(value,indent=2,sort_keys=True,default=lambda v:{'bytes_base64':base64.b64encode(v).decode(),'sha256':hashlib.sha256(v).hexdigest()} if isinstance(v,bytes) else str(v))+'\n')
def query(sql,args=()):return observer.query(sql,args)
def snapshot(label):
 dump(run/f'{label}-ledger.json',{name:query(f'SELECT * FROM {name}') for name in ['messages','targets','devices','channels','channel_subscriptions']})
def durable(delivery):
 title,body=expected[delivery]; observed={}
 for name in ['pushgo.db','ingress.sqlite']:
  paths=list((run/'native-store').rglob(name)); assert len(paths)==1,(name,paths)
  with sqlite3.connect(f'file:{paths[0]}?mode=ro',uri=True) as c:
   if name=='pushgo.db':
    rows=c.execute('SELECT title,body FROM messages WHERE delivery_id=?',(delivery,)).fetchall(); assert rows==[(title,body)],('ACK before exact canonical durability',delivery,rows)
   else:
    rows=c.execute('SELECT delivery_id,base_url,device_key,state,attempts FROM ack_outbox WHERE delivery_id=?',(delivery,)).fetchall(); assert len(rows)==1 and rows[0][3]=='leased',('no leased durable ACK row',delivery,rows)
  observed[name]={'path':str(paths[0]),'rows':rows}
 return observed
class Server(http.server.ThreadingHTTPServer):
 daemon_threads=True
class Proxy(http.server.BaseHTTPRequestHandler):
 def log_message(self,*_):pass
 def do_GET(self):self.forward()
 def do_POST(self):self.forward()
 def forward(self):
  raw=self.rfile.read(int(self.headers.get('Content-Length',0))); data=json.loads(raw) if raw else None
  row={'method':self.command,'path':self.path,'request':data,'unix_ms':int(time.time()*1000)}
  try:
   ids=[]
   if self.path.endswith('/messages/ack'):
    ids=data.get('delivery_ids',[data.get('delivery_id')]); row['native_durable_at_ack']={v:durable(v) for v in ids}
    row['ledger_before_ack']=query('SELECT * FROM targets WHERE delivery_id IN ('+','.join('?'*len(ids))+')',ids)
   if fail_ack and ids:
    status=503; body=b'{"success":false,"error":"c3 deliberate durable ACK transport failure"}';row['injected_failure']=True
   else:
    request=urllib.request.Request(backend+self.path,data=raw if self.command=='POST' else None,headers={'Content-Type':'application/json'},method=self.command)
    try:
     with urllib.request.urlopen(request,timeout=25) as r:status,body=r.status,r.read()
    except urllib.error.HTTPError as e:status,body=e.code,e.read()
  except BaseException as e:row['oracle_error']=repr(e);status=500;body=b'{"success":false,"error":"native durability oracle failed"}'
  row.update(status=status,response=body.decode());
  with lock:accesses.append(row);dump(run/'http-access.json',accesses)
  self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
proxy=Server(('127.0.0.1',0),Proxy);threading.Thread(target=proxy.serve_forever,daemon=True).start();public=f'http://127.0.0.1:{proxy.server_port}/gateway'
env.update(C3_EVIDENCE_DIR=str(run),C3_GATEWAY_URL=public,C3_PROVIDER_TOKEN=synthetic)
def native(phase,delivery=None,capture=None,title=None,body=None,label=None):
 label=label or phase
 env['C3_PHASE']=phase
 if delivery:env.update(C3_DELIVERY_ID=delivery,C3_EXPECTED_TITLE=title,C3_EXPECTED_BODY=body)
 if capture:env['C3_CAPTURE_PATH']=str(capture)
 with (run/f'apple-{label}.log').open('w') as f:r=subprocess.run([str(HERE/'run-native.sh')],env=env,stdout=f,stderr=subprocess.STDOUT)
 exits[label]=r.returncode; assert r.returncode==0,('native failed',phase,r.returncode)
 if label!=phase:(run/f'apple-{phase}-observations.json').rename(run/f'apple-{label}-observations.json')
 text=(run/f'apple-{label}.log').read_text();assert re.search(r'Test run with 1 test[^\n]*passed',text),('no exact native test pass',phase);assert 'skipped' not in text.lower(),('native skipped',phase)
def call(path,body):
 req=urllib.request.Request(public+path,data=json.dumps(body).encode(),headers={'Content-Type':'application/json'},method='POST')
 with urllib.request.urlopen(req,timeout=25) as r:return json.loads(r.read())['data']
def wait_for(check,label,seconds=20):
 until=time.monotonic()+seconds
 while True:
  value=check()
  if value:return value
  assert time.monotonic()<until,label
  time.sleep(.05)
def send(channel,title,body,op):
 data=call('/message',{'channel_id':channel,'password':boot['credential'],'title':title,'body':body,'op_id':op,'ttl':int(time.time())+86400})
 rows=query('SELECT * FROM messages WHERE op_id=?',(op,));assert len(rows)==1
 row=rows[0];expected[row['delivery_id']]=(title,body);return row
try:
 with C3Mock(run/'mock') as mock:
  cmd=[str(a.binary.resolve()),'--db-url',observer.url,'--http-addr','127.0.0.1:0','--mock-endpoint',mock.endpoint,'--mock-token-service-endpoint',mock.endpoint,'--private-enabled','--private-mqtt-addr','127.0.0.1:0','--provider-budget','32','--public-base-url',public+'///','--claim-quantum','32']
  dump(run/'plan.json',{'command':[v if v != observer.url else '<owned-db-url-file>' for v in cmd],'storage':observer.metadata(),'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'gateway_source_commit':a.source_commit,'source_manifest_sha256':hashlib.sha256((HERE/'source-copy-manifest.json').read_bytes()).hexdigest(),'scope':f'native production receiver controllers; HTTP sender; synthetic provider capture; native {observer.backend} database'})
  child=subprocess.Popen(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  def reader():
   global backend,pid
   with (run/'fixture.log').open('w') as f:
    for line in child.stdout:
     f.write(line);f.flush();lines.append(line)
     if line.startswith('READY '):backend='http://'+re.search(r'http_addr=(\S+)',line)[1];pid=int(re.search(r'pid=(\d+)',line)[1]);ready.set()
  rt=threading.Thread(target=reader,daemon=True);rt.start();assert ready.wait(25),('candidate startup',lines[-8:])
  def capture(op,delivery):
   rows=wait_for(lambda: mock.captures(token=synthetic,op_id=op),'actual provider capture')
   row=rows[-1];payload=row['payload'];assert row['held'] is True,('provider response was not held',row);assert payload.get('delivery_id')==delivery,(payload,delivery)
   targets=query('SELECT state,receipt_at FROM targets WHERE delivery_id=?',(delivery,));assert targets==[{'state':'running','receipt_at':None}],('captured target not running',targets)
   path=run/f'capture-{op.replace(":","-")}.json';path.write_text(row['raw_utf8']);return payload,path
  def hold(op):mock.configure({'provider':'apns','token':synthetic,'op_id':op,'hold':True,'max_hold_seconds':60,'count':1})
  def release(op):
   released=mock.release(provider='apns',token=synthetic,op_id=op);assert released['released']==1,('provider hold lost',op,released)
  # Coalescing is initiated by the real cached native bootstrap controller. The
  # old accepted provider attempt remains frozen while new-owner Pull/GRDB/ACK runs.
  old=call('/device/register',{'platform':'macos'})['device_key']
  call('/channel/device',{'device_key':old,'platform':'macos','channel_type':'apns','provider_token':synthetic})
  credential=os.urandom(16).hex();oldchannel=call('/channel/subscribe',{'device_key':old,'channel_name':'C5 transferred native Apple','password':credential})['channel_id']
  mergeop='c5:apple:owner-transfer';hold(mergeop)
  merged=call('/message',{'channel_id':oldchannel,'password':credential,'title':'C5 native owner transfer','body':'c5-coalesced-owner-'+'x'*7000,'op_id':mergeop,'ttl':int(time.time())+3600})
  original=query('SELECT * FROM messages WHERE delivery_id=?',(merged['delivery_id'],))[0]
  expected[merged['delivery_id']]=('C5 native owner transfer','c5-coalesced-owner-'+'x'*7000)
  mergepayload,mergepath=capture(mergeop,merged['delivery_id'])
  assert str(mergepayload.get('provider_wakeup')).lower() in ['1','true'] and mergepayload['provider_device_key']==old
  original_target=query('SELECT * FROM targets WHERE delivery_id=?',(merged['delivery_id'],))[0]
  snapshot('coalescing-old-accepted-held')
  native('bootstrap');boot=json.loads((run/'bootstrap.json').read_text());device=boot['device_key'];snapshot('bootstrap')
  assert device!=old
  assert query('SELECT coalesced_to FROM devices WHERE device_key=?',(old,))==[{'coalesced_to':device}]
  transferred=query('SELECT * FROM targets WHERE delivery_id=?',(merged['delivery_id'],))[0]
  assert transferred['device_key']==old and transferred['pull_owner']==device and transferred['owner_generation']==-1
  # Negative old capability is a supporting direct Gateway request; it must not
  # enter the proxy's canonical-before-native-ACK oracle.
  def oldcall(path,body):
   request=urllib.request.Request(backend+'/gateway'+path,data=json.dumps(body).encode(),headers={'Content-Type':'application/json'},method='POST')
   with urllib.request.urlopen(request,timeout=10) as response:return json.load(response)['data']
  assert oldcall('/v2/messages/pull',{'device_key':old,'delivery_id':merged['delivery_id']})['items']==[]
  assert oldcall('/v2/messages/ack',{'device_key':old,'delivery_ids':[merged['delivery_id']]})['removed_count']==0
  native('direct',merged['delivery_id'],mergepath,*expected[merged['delivery_id']],label='coalesced-owner')
  owner_ack=[v for v in accesses if v['path'].endswith('/messages/ack') and merged['delivery_id'] in v['request'].get('delivery_ids',[v['request'].get('delivery_id')])]
  assert owner_ack and all(v['request']['device_key']==device for v in owner_ack)
  assert all(v['native_durable_at_ack'][merged['delivery_id']]['ingress.sqlite']['rows'][0][2]==device for v in owner_ack)
  after_ack=query('SELECT * FROM targets WHERE delivery_id=?',(merged['delivery_id'],))[0]
  assert after_ack['device_key']==old and after_ack['pull_owner']==device and after_ack['acked_at'] is not None and after_ack['receipt_at'] is None
  assert all(after_ack[k]==original_target[k] for k in ['attempt_id','route_generation','accepted_at'])
  snapshot('coalescing-native-acked-before-frozen-receipt');release(mergeop)
  finished=wait_for(lambda:[v for v in mock.requests(op_id=mergeop) if v['event']=='provider_finished'],'coalesced actual old provider response finished')
  assert len(finished)==1 and finished[0]['status']==200 and finished[0]['response_error'] is None
  wait_for(lambda:(lambda rows:not rows or rows[0]['receipt_at'] is not None)(query('SELECT * FROM targets WHERE delivery_id=?',(merged['delivery_id'],))),'coalesced Gateway consumed old frozen receipt')
  final=query('SELECT * FROM messages WHERE delivery_id=?',(merged['delivery_id'],))[0]
  assert all(final[k]==original[k] for k in ['message_id','delivery_id','accepted_at','expires_at','dedupe_until'])
  assert final['payload_bytes']==0 and len(mock.captures(token=synthetic,op_id=mergeop))==1
  snapshot('coalescing-after-frozen-receipt')
  dump(run/'native-owner-coalescing.json',{'status':'PASSED','old_owner':old,'current_owner':device,'native_bootstrap':json.loads((run/'apple-bootstrap-observations.json').read_text()),'native_ingress':json.loads((run/'apple-coalesced-owner-observations.json').read_text()),'ack_request_device_key':owner_ack[0]['request']['device_key'],'original_target':original_target,'after_native_ack_before_receipt':after_ack,'message_stable_fields':{k:final[k]for k in ['message_id','delivery_id','accepted_at','expires_at','dedupe_until']},'provider_calls':1,'late_provider_response_receipt':finished[0],'scope':'actual cached ProviderRouteController persistence and NotificationIngressController filtered Pull/GRDB/ACK under current owner; frozen provider attempt remained old owner'})
  directop='c3:apple:direct';hold(directop);direct=send(boot['channel_id'],'C3 direct ordinary','direct exact body',directop)
  payload,path=capture(directop,direct['delivery_id']);assert not payload.get('provider_wakeup'),payload
  snapshot('direct-running');native('direct',direct['delivery_id'],path,'C3 direct ordinary','direct exact body');snapshot('direct-acked-before-provider-receipt');release(directop)
  wait_for(lambda:(lambda rows:not rows or rows[0]['receipt_at'] is not None)(query('SELECT * FROM targets WHERE delivery_id=?',(direct['delivery_id'],))),'late direct Gateway receipt retained or terminal retirement')
  snapshot('direct-after-late-receipt')
  decoy=send(boot['survivor_channel_id'],'C3 unpulled survivor','filtered pull must leave survivor', 'c3:apple:decoy')
  wakeop='c3:apple:wakeup';hold(wakeop);title='C3 oversized ordinary';body='canonical oversized body '+('x'*8192);wake=send(boot['channel_id'],title,body,wakeop)
  payload,path=capture(wakeop,wake['delivery_id']);assert str(payload.get('provider_wakeup','')).lower() in ['1','true'];assert payload.get('base_url')==public
  snapshot('wakeup-running');native('sync');snapshot('sync-while-wakeup-running');fail_ack=True
  native('ingest',wake['delivery_id'],path,title,body);snapshot('wakeup-failed-ack-before-provider-receipt');release(wakeop);fail_ack=False
  native('recover',wake['delivery_id'],path,title,body);snapshot('wakeup-new-process-recovered')
  obs=[json.loads((run/f'apple-{v}-observations.json').read_text()) for v in ['ingest','recover']];assert obs[0]['process_id']!=obs[1]['process_id']
  pulls=[v for v in accesses if v['path'].endswith('/v2/messages/pull')];assert pulls and all(v['request'].get('delivery_id') in [wake['delivery_id'],merged['delivery_id']] for v in pulls),('unfiltered/wrong pull',pulls)
  with sqlite3.connect(f'file:{next((run/"native-store").rglob("pushgo.db"))}?mode=ro',uri=True) as c:assert c.execute('SELECT count(*) FROM messages WHERE delivery_id=?',(decoy['delivery_id'],)).fetchone()[0]==0
  assert query('SELECT payload_bytes FROM messages WHERE delivery_id=?',(decoy['delivery_id'],))[0]['payload_bytes']>0
  native('unsubscribe');snapshot('unsubscribed')
  logoutop='c3:apple:logout-running';hold(logoutop);logout=send(boot['survivor_channel_id'],'C3 logout in flight','retained after route logout',logoutop);capture(logoutop,logout['delivery_id']);before=query('SELECT * FROM devices WHERE device_key=?',(device,))[0]
  snapshot('logout-running');native('logout');after=query('SELECT * FROM devices WHERE device_key=?',(device,))[0]
  assert not after['provider_token'] and after['route_generation']>before['route_generation'],(before,after);snapshot('logout-before-provider-receipt');release(logoutop)
  wait_for(lambda:query('SELECT receipt_at FROM targets WHERE delivery_id=? AND receipt_at IS NOT NULL',(logout['delivery_id'],)),'logout late receipt missing');snapshot('logout-after-provider-receipt')
  final=query('SELECT * FROM messages WHERE delivery_id=?',(logout['delivery_id'],))[0]
  assert all(final[k]==logout[k] for k in ['message_id','delivery_id','accepted_at','expires_at']),('logout rewrote identity/time',logout,final)
  assert final['payload_bytes']>0,'logout erased retained Pull payload'
  final_target=query('SELECT * FROM targets WHERE delivery_id=?',(logout['delivery_id'],))[0];assert final_target['state']=='provider_accepted' and final_target['attempts']==1 and final_target['receipt_at'] is not None,('logout receipt state',final_target)
  assert len(mock.captures(token=synthetic,op_id=logoutop))==1,'logout duplicated provider network attempt'
  assert not (run/'mock/first-failure.json').exists(),'local provider hold/peer failure'
  assert not any('oracle_error' in v for v in accesses),'native durability oracle failed'
  assert any(v.get('injected_failure') for v in accesses),'ACK503 fault never exercised'
  dump(run/'result.json',{'failure':None,'phase_exits':exits,'scope':'native receiver controllers with actual candidate endpoints, direct/wakeup/filteredV2/durable503/newprocess/unsubscribe/logout, held local provider receipts'})
except BaseException as e:
 failure=repr(e);dump(run/'first-failure.json',{'failure':failure,'phase_exits':exits})
finally:
 if child and child.poll() is None:
  os.kill(pid or child.pid,signal.SIGTERM)
  try:child.wait(timeout=25)
  except subprocess.TimeoutExpired:os.kill(pid or child.pid,signal.SIGKILL);child.wait(timeout=5);failure=failure or 'forced candidate kill'
 if child:
  rt.join(timeout=2);shutdown=[v for v in lines if v.startswith('SHUTDOWN ')]
  if child.returncode!=0 or not shutdown or not re.search(r'joined=2 panicked=0 aborted=0 http_timed_out=false',shutdown[-1]):failure=failure or 'candidate shutdown incomplete'
 proxy.shutdown();proxy.server_close()
 dump(run/'final-result.json',{'failure':failure,'phase_exits':exits,'fixture_exit':child.returncode if child else None,'scope':'native macOS host controllers, GRDB and independent-process recovery; no physical device/APNs/OS lifecycle'})
if failure:raise SystemExit(failure)
print('PASS: actual native ordinary receiver closed loop with bounded local provider fault/receipt interleavings')
