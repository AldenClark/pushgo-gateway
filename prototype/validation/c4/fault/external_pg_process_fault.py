#!/usr/bin/env python3
"""Owned real PG process test. Explicitly invoked only after binary freeze.
Creates one new DB in captured C4 container; retains it and all evidence.
No URL/credentials emitted; no container lifecycle action; not powerloss.
"""
import argparse, hashlib, http.server, json, os, pathlib, re, signal, socket, subprocess, threading, time, urllib.request, urllib.parse, urllib.error, uuid
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--out',required=True);p.add_argument('--pg-env',required=True);a=p.parse_args();out=pathlib.Path(a.out);out.mkdir(parents=True,exist_ok=False)
report={'binary':a.binary,'sha256':hashlib.sha256(pathlib.Path(a.binary).read_bytes()).hexdigest(),'events':[],'scope':'real PostgreSQL tmpfs; process/session failure; not powerloss'}
def save(): (out/'receipt.json').write_text(json.dumps(report,indent=2))
def note(kind,**kw):report['events'].append(dict(kind=kind,at=time.time(),**kw));save()
env=pathlib.Path(a.pg_env);owned=json.loads((env/'owned-container.json').read_text());ident=owned['id'];owner=owned['owner'];assert re.fullmatch('[a-f0-9]{64}',ident) and re.fullmatch('[a-f0-9]{32}',owner)
docker=['docker','--context','orbstack']
def call(args):
 r=subprocess.run(docker+args,text=True,capture_output=True)
 if r.returncode:raise RuntimeError('Owned docker command failed; suppressed potentially sensitive output')
 return r.stdout.strip()
ctx=json.loads(call(['context','inspect','orbstack']))[0];assert ctx['Endpoints']['docker']['Host']=='unix://'+str(pathlib.Path.home()/'.orbstack/run/docker.sock')
info=json.loads(call(['inspect',ident]))[0];assert info['Id']==ident and info['Config']['Labels']['io.pushgo.c4.synthetic.owner']==owner and info['Name']=='/pushgo-c4-pg-'+owner
base=urllib.parse.urlsplit((env/'synthetic-db-url.txt').read_text().strip());assert base.scheme in ['postgres','postgresql'] and base.hostname=='127.0.0.1' and base.path=='/'+owned['database'];assert call(['port',ident,'5432/tcp'])==base.hostname+':'+str(base.port)
database='c4_synthetic_'+uuid.uuid4().hex;assert re.fullmatch('c4_synthetic_[a-f0-9]{32}',database)
def sql(statement,db=None):return call(['exec',ident,'psql','-X','-q','-A','-t','-v','ON_ERROR_STOP=1','-U',owned['user'],'-d',db or database,'-c',statement])
# CREATE DATABASE is the only query directed to the base DB. No base table read/write.
sql('CREATE DATABASE '+database,owned['database']);note('new-owned-db',database=database,container_id=ident)
url=urllib.parse.urlunsplit(base._replace(path='/'+database));alias=urllib.parse.urlunsplit(base._replace(netloc=base.netloc.replace('127.0.0.1','localhost'),path='/'+database))
def port():
 s=socket.socket();s.bind(('127.0.0.1',0));v=s.getsockname()[1];s.close();return v
http_port=port();direct=urllib.request.build_opener(urllib.request.ProxyHandler({}));release=threading.Event();arrived=threading.Event();sends=[];logs=[];procs=[]
class Mock(http.server.BaseHTTPRequestHandler):
 def do_POST(self):
  data=json.loads(self.rfile.read(int(self.headers['Content-Length'])));sends.append(data);arrived.set();release.wait(30)
  data=b'{"name":"projects/fixture-project/messages/synthetic"}';self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers()
  try:self.wfile.write(data)
  except (BrokenPipeError,ConnectionResetError):pass
 def log_message(self,*args):pass
mock=http.server.ThreadingHTTPServer(('127.0.0.1',0),Mock);threading.Thread(target=mock.serve_forever,daemon=True).start()
def launch(label,selected_url=None,reject=False):
 log=open(out/(label+'.log'),'w');logs.append(log);proc=subprocess.Popen([a.binary,'--db-url',selected_url or url,'--http-addr',f'127.0.0.1:{port() if reject else http_port}','--mock-endpoint',f'http://127.0.0.1:{mock.server_port}','--provider-budget','1','--claim-quantum','1'],stdout=log,stderr=subprocess.STDOUT);procs.append(proc)
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  text=(out/(label+'.log')).read_text()
  if proc.poll() is not None:
   if reject:
    assert proc.returncode!=0 and ('owner' in text.lower()),'second owner rejected for unrelated reason';note(label,exit_code=proc.returncode);return proc
   raise AssertionError('startup exited; inspect captured fixture log')
  if 'READY ' in text:
   assert not reject,'second owner unexpectedly started';return proc
  time.sleep(.025)
 raise AssertionError('bounded startup deadline')
def req(path,data=None):
 try:
  r=direct.open(urllib.request.Request(f'http://127.0.0.1:{http_port}'+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'}),timeout=5);return {'status':r.status,'body':json.loads(r.read())}
 except urllib.error.HTTPError as e:return {'status':e.code,'body':e.read().decode()}
 except Exception as e:return {'error':type(e).__name__}
def ok(path,data):
 r=req(path,data);note('http'+path,response=r);assert r.get('status')==200,r;return r['body']['data']
def snapshot():
 return json.loads(sql("SELECT json_build_object('messages',(SELECT coalesce(json_agg(x),'[]') FROM (SELECT delivery_id,message_id,op_id,accepted_at,expires_at,dedupe_until,status,payload_bytes FROM pushgo_c.messages)x),'targets',(SELECT coalesce(json_agg(x),'[]') FROM (SELECT delivery_id,device_key,pull_owner,owner_generation,control_epoch,route_generation,state,attempts,attempt_id FROM pushgo_c.targets)x),'usage',(SELECT row_to_json(x) FROM pushgo_c.ledger_usage x),'metadata',(SELECT row_to_json(x) FROM pushgo_c.authority_metadata x))"))
try:
 proc=launch('owner-first');launch('second-owner-same',reject=True);launch('second-owner-host-alias',alias,reject=True)
 device=ok('/device/register',{'platform':'android'})['device_key'];ok('/channel/device',{'device_key':device,'channel_type':'FCM','provider_token':uuid.uuid4().hex});synthetic_value=uuid.uuid4().hex
 channel=ok('/channel/subscribe',{'device_key':device,'channel_name':'pg-process-fault','password':synthetic_value})['channel_id'];message={'channel_id':channel,'password':synthetic_value,'title':'pg external unknown','op_id':'pg-process-unknown','ttl':int(time.time()*1000)+180000}
 accepted=ok('/message',message);assert arrived.wait(5),'no synthetic provider attempt';before=snapshot();note('accepted-provider-held',accepted=accepted,snapshot=before)
 # Freeze the live process to make advisory loss versus OS-lock ownership deterministic.
 os.kill(proc.pid,signal.SIGSTOP);note('owner-process-stopped-but-alive',pid=proc.pid)
 session=json.loads(sql("SELECT coalesce(json_agg(pid),'[]') FROM pg_locks WHERE locktype='advisory' AND classid=1346852687 AND objid=1129271876 AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND granted"));assert len(session)==1,session
 assert sql('SELECT pg_terminate_backend('+str(int(session[0]))+')')=='t';note('exact-session-terminated',backend_pid=session[0])
 assert sql("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid=1346852687 AND objid=1129271876 AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND granted")=='0'
 assert proc.poll() is None;launch('second-owner-session-lost-os-lock',alias,reject=True);assert proc.poll() is None
 os.kill(proc.pid,signal.SIGKILL);proc.wait(timeout=5);note('gateway-killed-provider-result-unknown',exit_code=proc.returncode,snapshot=snapshot());release.set()
 proc=launch('recovered');deadline=time.monotonic()+8
 while time.monotonic()<deadline:
  after=snapshot()
  if after['targets'] and after['targets'][0]['state']=='provider_accepted':break
  time.sleep(.05)
 note('recovered',snapshot=after,provider_requests=sends.copy());assert after['targets'][0]['state']=='provider_accepted';assert len(after['messages'])==1 and len(sends)==2
 for k in ['delivery_id','message_id','op_id','accepted_at','expires_at','dedupe_until']:assert before['messages'][0][k]==after['messages'][0][k],k
 for k in ['owner_generation','control_epoch','route_generation','pull_owner']:assert before['targets'][0][k]==after['targets'][0][k],k
 assert before['metadata']==after['metadata'];assert after['targets'][0]['attempt_id']==before['targets'][0]['attempt_id']+1
 replay=ok('/message',message);assert replay['delivery_id']==accepted['delivery_id'];assert len(sends)==2
 pulled=ok('/v2/messages/pull',{'device_key':device});assert accepted['delivery_id'] in json.dumps(pulled)
 ok('/v2/messages/ack',{'device_key':device,'delivery_ids':[accepted['delivery_id']]});end=snapshot();note('after-pull-ack',snapshot=end)
 assert end['usage']['messages']==0 and end['usage']['targets']==0 and end['usage']['bytes']==0;assert end['messages'][0]['payload_bytes']==0;assert not end['targets']
 report['result']='PASS owned real PG second-owner/alias, lost-session OS fence, unknown-provider crash recovery, stable identity/TTL/epoch, Pull ACK capacity release';save()
except Exception as e:
 report['result']='FAIL';report['first_error']=repr(e);save();raise
finally:
 release.set()
 for proc in procs:
  if proc.poll() is None:
   proc.send_signal(signal.SIGCONT);proc.terminate()
   try:proc.wait(timeout=25)
   except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
 for log in logs:log.close()
 mock.shutdown()
