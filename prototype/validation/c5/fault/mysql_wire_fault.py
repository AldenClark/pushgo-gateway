#!/usr/bin/env python3
"""Real synthetic MySQL packet faults; run only against root-frozen fixture.
Bounded 1 MiB packets, 8 connections, socket deadlines and task joins.
No SQL response fabrication. COMMIT failure cuts before server; unknown cuts real OK.
"""
import argparse, hashlib, http.server, json, os, pathlib, signal, socket, subprocess, threading, time, urllib.request, urllib.parse, urllib.error, uuid
P=argparse.ArgumentParser();P.add_argument('--binary',required=True);P.add_argument('--out',required=True);P.add_argument('--mode',choices=['before','after','process'],required=True);P.add_argument('--env-helper',required=True);P.add_argument('--workspace',required=True);P.add_argument('--commit',required=True);P.add_argument('--expected-sha256',required=True);A=P.parse_args()
O=pathlib.Path(A.out);O.mkdir(parents=True,exist_ok=False)
def product_hashes():
 paths=subprocess.check_output(['git','-C',A.workspace,'ls-files','-z']).decode().split('\0');wanted=[p for p in paths if p and (p.startswith('src/') or p.startswith('prototype/src/') or p in ['Cargo.toml','Cargo.lock','build.rs','prototype/Cargo.toml'])]
 return {p:hashlib.sha256((pathlib.Path(A.workspace)/p).read_bytes()).hexdigest() for p in sorted(wanted)}
assert subprocess.check_output(['git','-C',A.workspace,'rev-parse','HEAD'],text=True).strip()==A.commit
assert hashlib.sha256(pathlib.Path(A.binary).read_bytes()).hexdigest()==A.expected_sha256
initial_product_hashes=product_hashes()
(O/'product-hashes-before.json').write_text(json.dumps(initial_product_hashes,indent=2)+'\n')
R={'commit':A.commit,'binary':A.binary,'sha256':hashlib.sha256(pathlib.Path(A.binary).read_bytes()).hexdigest(),'mode':A.mode,'events':[],'scope':'real MySQL 8 ordinary native adapter; RAM-backed InnoDB; no powerloss claim'};mu=threading.Lock()
def note(kind,**kw):
 with mu:
  R['events'].append(dict(kind=kind,at=time.time(),**kw));(O/'receipt.json').write_text(json.dumps(R,indent=2)+'\n')
def helper(*args):
 p=subprocess.run(['python3',A.env_helper,*args],text=True,capture_output=True,timeout=20)
 if p.returncode:raise RuntimeError('guarded helper failed; output suppressed')
 return p.stdout.strip()
created=json.loads(helper('create','mysql','wire_'+A.mode));DB=created['database'];base=urllib.parse.urlsplit(pathlib.Path(created['url_file']).read_text().strip());assert base.hostname=='127.0.0.1'
url=urllib.parse.urlunsplit(base._replace(query='ssl-mode=DISABLED'));procs=[];logs=[]
def sql(q):
 f=O/'query.sql';f.write_text(q);return helper('sql','mysql',str(f),'--database',DB)
def snapshot():
 result={}
 for table,fields in [('messages','delivery_id,message_id,op_id,accepted_at,expires_at,dedupe_until,status,payload_bytes'),('targets','delivery_id,device_key,pull_owner,owner_generation,control_epoch,route_generation,state,attempts,attempt_id'),('ledger_usage','singleton,messages,targets,bytes,control_epoch'),('authority_metadata','singleton,dataset_uuid,schema_version')]:
  cols=fields.split(',');rows=sql('SELECT '+fields+' FROM '+table+';');result[table]=[dict(zip(cols,row.split('\t'))) for row in rows.splitlines()]
 return result
def port():
 s=socket.socket();s.bind(('127.0.0.1',0));v=s.getsockname()[1];s.close();return v
class Proxy:
 def __init__(self):
  self.stop=threading.Event();self.armed=threading.Event();self.hit=threading.Event();self.lock=threading.Lock();self.sockets=[];self.tasks=[];self.target=False;self.await_ok=False;self.count=0;self.authseen=False
  self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen(8);self.listener.settimeout(.2);self.port=self.listener.getsockname()[1];self.thread=threading.Thread(target=self.accept);self.thread.start()
 def accept(self):
  while not self.stop.is_set():
   try:c,_=self.listener.accept()
   except socket.timeout:continue
   except OSError:return
   self.count+=1
   if self.count>8:c.close();continue
   s=socket.create_connection((base.hostname,base.port),timeout=5);c.settimeout(.5);s.settimeout(.5);self.sockets += [c,s]
   for left,right,direction in [(c,s,'request'),(s,c,'response')]:
    t=threading.Thread(target=self.relay,args=(left,right,direction));self.tasks.append(t);t.start()
 def read(self,s,n):
  b=bytearray()
  while len(b)<n and not self.stop.is_set():
   try:d=s.recv(n-len(b))
   except socket.timeout:continue
   if not d:return None
   b.extend(d)
  return bytes(b) if len(b)==n else None
 def relay(self,left,right,direction):
  try:
   while not self.stop.is_set():
    h=self.read(left,4)
    if h is None:return
    n=int.from_bytes(h[:3],'little');assert n<=1048576,'packet exceeded fixed limit';b=self.read(left,n)
    if b is None:return
    if direction=='request' and not self.authseen and h[3]==1 and len(b)>=32:
     self.authseen=True;capabilities=int.from_bytes(b[:4],'little');assert capabilities&0x800==0,'client attempted TLS';note('plaintext-client-handshake-observed',client_ssl_flag=False)
    if direction=='request' and self.armed.is_set():
     if b[:1]==b'\x16' and b'INSERT INTO messages' in b[1:]:self.target=True;note('actual-message-statement-prepare-observed')
     if b[:1]==b'\x03' and b[1:].strip().upper()==b'COMMIT' and self.target:
      note('actual-com-query-commit-observed',packet_sequence=h[3],forwarded=A.mode=='after')
      if A.mode=='before':self.hit.set();return
      self.await_ok=True
    if direction=='response' and self.await_ok:
     assert b[:1]==b'\x00','actual COMMIT response was not server OK'
     note('actual-server-commit-ok-observed',packet_sequence=h[3],ok_payload_hex=b.hex());self.hit.set();return
    right.sendall(h+b)
  except (OSError,AssertionError) as e:
   note('proxy-relay-ended',direction=direction,error=type(e).__name__)
  finally:
   for s in [left,right]:
    try:s.shutdown(socket.SHUT_RDWR)
    except OSError:pass
    s.close()
 def close(self):
  self.stop.set();self.listener.close()
  for s in self.sockets:
   try:s.shutdown(socket.SHUT_RDWR)
   except OSError:pass
   s.close()
  self.thread.join(2)
  for t in self.tasks:t.join(2);assert not t.is_alive()
release=threading.Event();arrived=threading.Event();sends=[];provider_threads=[]
class Mock(http.server.BaseHTTPRequestHandler):
 def do_POST(self):
  provider_threads.append(threading.current_thread());self.connection.settimeout(5);length=int(self.headers['Content-Length']);assert 0<=length<=1048576
  data=json.loads(self.rfile.read(length));sends.append(data);note('synthetic-provider-request',number=len(sends));arrived.set();release.wait(15)
  b=b'{"name":"projects/fixture-project/messages/synthetic"}';self.send_response(200);self.send_header('Content-Length',str(len(b)));self.end_headers()
  try:self.wfile.write(b)
  except (BrokenPipeError,ConnectionResetError):pass
 def log_message(self,*a):pass
mock=http.server.ThreadingHTTPServer(('127.0.0.1',0),Mock);mock.daemon_threads=True;mock.block_on_close=False;mt=threading.Thread(target=mock.serve_forever);mt.start();hp=port();direct=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def launch(label,selected=None,reject=False):
 log=open(O/(label+'.log'),'w');logs.append(log);p=subprocess.Popen([A.binary,'--db-url',selected or url,'--http-addr',f'127.0.0.1:{port() if reject else hp}','--mock-endpoint',f'http://127.0.0.1:{mock.server_port}','--provider-budget','1','--claim-quantum','1'],stdout=log,stderr=subprocess.STDOUT);procs.append(p);deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  t=(O/(label+'.log')).read_text()
  if p.poll() is not None:
   if reject:assert p.returncode!=0 and 'owner' in t.lower();note(label,exit_code=p.returncode);return p
   raise AssertionError('startup exited; inspect captured log')
  if 'READY ' in t:assert not reject;note(label,pid=p.pid);return p
  time.sleep(.025)
 raise AssertionError('bounded startup deadline')
def req(path,data):
 try:
  r=direct.open(urllib.request.Request(f'http://127.0.0.1:{hp}'+path,data=json.dumps(data).encode(),headers={'Content-Type':'application/json'}),timeout=5);return {'status':r.status,'body':json.loads(r.read())}
 except urllib.error.HTTPError as e:return {'status':e.code,'body':e.read().decode()}
 except Exception as e:return {'error':type(e).__name__}
def ok(path,data):
 r=req(path,data);note('http'+path,response=r);assert r.get('status')==200,r;return r['body']['data']
def waitaccepted():
 deadline=time.monotonic()+8
 while time.monotonic()<deadline:
  s=snapshot()
  if s['targets'] and s['targets'][0]['state']=='provider_accepted':return s
  time.sleep(.05)
 raise AssertionError('bounded provider acceptance deadline')
proxy=None
try:
 if A.mode!='process':
  proxy=Proxy();proxyurl=urllib.parse.urlunsplit(base._replace(netloc=base.netloc.rsplit('@',1)[0]+'@127.0.0.1:'+str(proxy.port),query='ssl-mode=DISABLED'));p=launch('owner-proxied',proxyurl)
 else:p=launch('owner-direct')
 device=ok('/device/register',{'platform':'android'})['device_key'];ok('/channel/device',{'device_key':device,'channel_type':'FCM','provider_token':uuid.uuid4().hex});password=uuid.uuid4().hex;channel=ok('/channel/subscribe',{'device_key':device,'channel_name':'mysql-wire-'+A.mode,'password':password})['channel_id'];message={'channel_id':channel,'password':password,'title':'synthetic mysql wire','op_id':'mysql-wire-'+A.mode,'ttl':int(time.time()*1000)+180000}
 setup=snapshot();assert not setup['messages'];note('setup-complete-before-fault',snapshot=setup)
 if proxy:proxy.armed.set();response=req('/message',message);note('fault-http-response',response=response);assert response.get('status')!=200;assert proxy.hit.wait(5),'target COMMIT not intercepted';p.wait(timeout=8);assert p.returncode==70;note('gateway-failstop',exit_code=p.returncode,admission_probe=req('/message',message));before=snapshot();note('post-session-close',snapshot=before,provider_requests=len(sends));assert len(sends)==0
 else:
  accepted=ok('/message',message);assert arrived.wait(5);before=snapshot();note('provider-result-held',accepted=accepted,snapshot=before)
  alias=urllib.parse.urlunsplit(base._replace(netloc=base.netloc.replace('127.0.0.1','localhost'),query='ssl-mode=DISABLED&charset=utf8mb4'));launch('second-owner-same',reject=True);launch('second-owner-alias-params',alias,reject=True)
  os.kill(p.pid,signal.SIGSTOP);note('owner-stopped-but-live',pid=p.pid)
  session=sql("SELECT IS_USED_LOCK(CONCAT('pushgo-c-dataset-',dataset_uuid)) FROM authority_metadata WHERE singleton=1;");assert session.isdigit();sql('KILL CONNECTION '+session+';');note('owner-session-killed',connection_id=int(session));assert p.poll() is None;launch('second-owner-lost-session-os-fence',alias,reject=True);assert p.poll() is None
  os.kill(p.pid,signal.SIGKILL);p.wait(timeout=5);note('gateway-strongkill-provider-result-unknown',exit_code=p.returncode)
 if A.mode=='before':assert not before['messages'] and not before['targets'] and before['ledger_usage'][0]['messages']=='0'
 else:assert len(before['messages'])==1 and len(before['targets'])==1
 if proxy:proxy.close();proxy=None
 release.set();p=launch('restarted-direct');replay=ok('/message',message);after=waitaccepted();note('recovered-same-op',replay=replay,snapshot=after,provider_requests=sends.copy());assert len(after['messages'])==1
 if A.mode!='before':
  for k in ['delivery_id','message_id','op_id','accepted_at','expires_at','dedupe_until']:assert before['messages'][0][k]==after['messages'][0][k],k
  for k in ['owner_generation','control_epoch','route_generation','pull_owner']:assert before['targets'][0][k]==after['targets'][0][k],k
  assert before['authority_metadata']==after['authority_metadata'];assert replay['delivery_id']==before['messages'][0]['delivery_id']
 assert len(sends)==(2 if A.mode=='process' else 1)
 pull=ok('/v2/messages/pull',{'device_key':device});assert replay['delivery_id'] in json.dumps(pull);ok('/v2/messages/ack',{'device_key':device,'delivery_ids':[replay['delivery_id']]});end=snapshot();note('pull-ack-capacity',snapshot=end);assert end['ledger_usage'][0]['messages']=='0' and end['ledger_usage'][0]['targets']=='0' and end['ledger_usage'][0]['bytes']=='0'
 R['result']='PASS';note('completed')
except Exception as e:R['result']='FAIL';note('first-failure',error=repr(e));raise
finally:
 release.set()
 for p in procs:
  if p.poll() is None:
   p.send_signal(signal.SIGCONT);p.terminate()
   try:p.wait(timeout=10)
   except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
 if proxy:proxy.close()
 for log in logs:log.close()
 mock.shutdown();mock.server_close();mt.join(2);assert not mt.is_alive()
 for t in provider_threads:t.join(2);assert not t.is_alive()
 helper('drop','mysql',DB);note('owned-processes-closed-own-fresh-db-dropped')
 final_product_hashes=product_hashes();(O/'product-hashes-after.json').write_text(json.dumps(final_product_hashes,indent=2)+'\n');assert initial_product_hashes==final_product_hashes;assert hashlib.sha256(pathlib.Path(A.binary).read_bytes()).hexdigest()==A.expected_sha256;note('product-source-and-frozen-binary-hashes-unchanged',product_files=len(final_product_hashes))
