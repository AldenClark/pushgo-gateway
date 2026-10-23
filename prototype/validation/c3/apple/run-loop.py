#!/usr/bin/env python3
"""Actual native receiver controllers against candidate C; sender is explicit HTTP.
No real APNs, TokenService, app bundle, permission, or OS background evidence.
Every assertion failure is retained; there is no product-assertion retry.
"""
import argparse, base64, hashlib, http.server, json, os, pathlib, re, signal, sqlite3, subprocess, sys, threading, time, urllib.request, urllib.error
HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'harness'))
from c3_mock import C3Mock
p=argparse.ArgumentParser(); p.add_argument('--binary',type=pathlib.Path,required=True); p.add_argument('--out',type=pathlib.Path,required=True)
p.add_argument('--apple-work-root',type=pathlib.Path,required=True); p.add_argument('--binary-sha256',required=True); p.add_argument('--source-commit',required=True)
a=p.parse_args(); work=a.apple_work_root.resolve()
assert (work/'stage-receipt.json').is_file(), 'Run explicit stage.py first'
assert hashlib.sha256(a.binary.read_bytes()).hexdigest()==a.binary_sha256, 'Frozen binary SHA mismatch'
assert re.fullmatch(r'[0-9a-f]{40}',a.source_commit), 'Explicit full source commit required'
run=a.out.resolve(); assert HERE not in run.parents and run!=HERE, 'Use external run output'
run.mkdir(parents=True,exist_ok=False)
db=run/'candidate.sqlite'; accesses=[]; lock=threading.Lock(); expected={}; backend=None; child=None; pid=None; lines=[]; exits={}; failure=None; fail_ack=False
synthetic=os.urandom(32).hex(); ready=threading.Event()
env={k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','C1_','C2_','C3_')) and k.lower() not in ['http_proxy','https_proxy','all_proxy','no_proxy','rust_log']};env['NO_PROXY']='127.0.0.1,localhost'
def dump(path,value): path.write_text(json.dumps(value,indent=2,sort_keys=True,default=lambda v:{'bytes_base64':base64.b64encode(v).decode(),'sha256':hashlib.sha256(v).hexdigest()} if isinstance(v,bytes) else str(v))+'\n')
def query(sql,args=()):
 with sqlite3.connect(f'file:{db}?mode=ro',uri=True) as c:
  c.row_factory=sqlite3.Row
  return [dict(v) for v in c.execute(sql,args)]
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
env.update(C3_EVIDENCE_DIR=str(run),C3_GATEWAY_URL=public,C3_PROVIDER_TOKEN=synthetic,C3_APPLE_WORK_ROOT=str(work))
def native(phase,delivery=None,capture=None,title=None,body=None):
 env['C3_PHASE']=phase
 if delivery:env.update(C3_DELIVERY_ID=delivery,C3_EXPECTED_TITLE=title,C3_EXPECTED_BODY=body)
 if capture:env['C3_CAPTURE_PATH']=str(capture)
 with (run/f'apple-{phase}.log').open('w') as f:r=subprocess.run([str(HERE/'run-native.sh')],env=env,stdout=f,stderr=subprocess.STDOUT)
 exits[phase]=r.returncode; assert r.returncode==0,('native failed',phase,r.returncode)
 text=(run/f'apple-{phase}.log').read_text();assert re.search(r'Test run with 1 test[^\n]*passed',text),('no exact native test pass',phase);assert 'skipped' not in text.lower(),('native skipped',phase)
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
  cmd=[str(a.binary.resolve()),'--db-url',f'sqlite://{db}','--http-addr','127.0.0.1:0','--mock-endpoint',mock.endpoint,'--mock-token-service-endpoint',mock.endpoint,'--provider-budget','32','--public-base-url',public+'///','--claim-quantum','32']
  dump(run/'plan.json',{'command':cmd,'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'declared_source_commit':a.source_commit,'portable_adapter_status':'NOT RUN by packaging validation','source_manifest_sha256':hashlib.sha256((work/'source-copy-manifest.json').read_bytes()).hexdigest(),'scope':'native production receiver controllers; HTTP sender; synthetic provider capture; local SQLite only'})
  child=subprocess.Popen(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  def reader():
   global backend,pid
   with (run/'fixture.log').open('w') as f:
    for line in child.stdout:
     f.write(line);f.flush();lines.append(line)
     if line.startswith('READY '):backend='http://'+re.search(r'http_addr=(\S+)',line)[1];pid=int(re.search(r'pid=(\d+)',line)[1]);ready.set()
  rt=threading.Thread(target=reader,daemon=True);rt.start();assert ready.wait(25),('candidate startup',lines[-8:])
  native('bootstrap');boot=json.loads((run/'bootstrap.json').read_text());device=boot['device_key'];snapshot('bootstrap')
  def capture(op,delivery):
   rows=wait_for(lambda: mock.captures(token=synthetic,op_id=op),'actual provider capture')
   row=rows[-1];payload=row['payload'];assert row['held'] is True,('provider response was not held',row);assert payload.get('delivery_id')==delivery,(payload,delivery)
   targets=query('SELECT state,receipt_at FROM targets WHERE delivery_id=?',(delivery,));assert targets==[{'state':'running','receipt_at':None}],('captured target not running',targets)
   path=run/f'capture-{op.replace(":","-")}.json';path.write_text(row['raw_utf8']);return payload,path
  def hold(op):mock.configure({'provider':'apns','token':synthetic,'op_id':op,'hold':True,'max_hold_seconds':60,'count':1})
  def release(op):
   released=mock.release(provider='apns',token=synthetic,op_id=op);assert released['released']==1,('provider hold lost',op,released)
  directop='c3:apple:direct';hold(directop);direct=send(boot['channel_id'],'C3 direct ordinary','direct exact body',directop)
  payload,path=capture(directop,direct['delivery_id']);assert not payload.get('provider_wakeup'),payload
  snapshot('direct-running');native('direct',direct['delivery_id'],path,'C3 direct ordinary','direct exact body');snapshot('direct-acked-before-provider-receipt');release(directop)
  wait_for(lambda:query('SELECT receipt_at FROM targets WHERE delivery_id=? AND receipt_at IS NOT NULL',(direct['delivery_id'],)) or query('SELECT delivery_id FROM messages WHERE delivery_id=? AND payload_bytes=0 AND pending_targets=0',(direct['delivery_id'],)),'late direct receipt retained or terminal retirement')
  snapshot('direct-after-late-receipt')
  decoy=send(boot['survivor_channel_id'],'C3 unpulled survivor','filtered pull must leave survivor', 'c3:apple:decoy')
  wakeop='c3:apple:wakeup';hold(wakeop);title='C3 oversized ordinary';body='canonical oversized body '+('x'*8192);wake=send(boot['channel_id'],title,body,wakeop)
  payload,path=capture(wakeop,wake['delivery_id']);assert str(payload.get('provider_wakeup','')).lower() in ['1','true'];assert payload.get('base_url')==public
  snapshot('wakeup-running');native('sync');snapshot('sync-while-wakeup-running');fail_ack=True
  native('ingest',wake['delivery_id'],path,title,body);snapshot('wakeup-failed-ack-before-provider-receipt');release(wakeop);fail_ack=False
  native('recover',wake['delivery_id'],path,title,body);snapshot('wakeup-new-process-recovered')
  obs=[json.loads((run/f'apple-{v}-observations.json').read_text()) for v in ['ingest','recover']];assert obs[0]['process_id']!=obs[1]['process_id']
  pulls=[v for v in accesses if v['path'].endswith('/v2/messages/pull')];assert pulls and all(v['request'].get('delivery_id')==wake['delivery_id'] for v in pulls),('unfiltered/wrong pull',pulls)
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
