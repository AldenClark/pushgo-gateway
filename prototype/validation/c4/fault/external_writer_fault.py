#!/usr/bin/env python3
"""External synthetic contention; no product edits or build. Fresh OUT per run."""
import argparse, concurrent.futures, hashlib, http.server, json, pathlib, socket, sqlite3, subprocess, threading, time, urllib.request, urllib.error, uuid
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--out',required=True);a=p.parse_args();out=pathlib.Path(a.out);out.mkdir(parents=True,exist_ok=False)
report={'binary':a.binary,'sha256':hashlib.sha256(pathlib.Path(a.binary).read_bytes()).hexdigest(),'events':[]}
def save(): (out/'receipt.json').write_text(json.dumps(report,indent=2,default=lambda v:{'blob_hex':v.hex()} if isinstance(v,bytes) else str(v)))
def note(kind,**kw): report['events'].append(dict(kind=kind,at=time.time(),**kw));save()
def port():
 s=socket.socket();s.bind(('127.0.0.1',0));v=s.getsockname()[1];s.close();return v
http_port=port();release=threading.Event();arrived=threading.Event();sends=[]
direct=urllib.request.build_opener(urllib.request.ProxyHandler({}))
class Mock(http.server.BaseHTTPRequestHandler):
 def do_POST(self):
  body=json.loads(self.rfile.read(int(self.headers['Content-Length'])));sends.append(body);arrived.set();release.wait(15)
  data=b'{"name":"projects/fixture-project/messages/synthetic"}';self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers()
  try:self.wfile.write(data)
  except BrokenPipeError:pass
 def log_message(self,*args):pass
mock=http.server.ThreadingHTTPServer(('127.0.0.1',0),Mock);threading.Thread(target=mock.serve_forever,daemon=True).start()
db=out/'synthetic.sqlite';logs=[];procs=[]
def launch(label):
 log=open(out/(label+'.log'),'w');logs.append(log);proc=subprocess.Popen([a.binary,'--db-url','sqlite://'+str(db),'--http-addr',f'127.0.0.1:{http_port}','--mock-endpoint',f'http://127.0.0.1:{mock.server_port}','--provider-budget','1','--claim-quantum','1'],stdout=log,stderr=subprocess.STDOUT);procs.append(proc)
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  if proc.poll() is not None:raise AssertionError('startup exited '+str(proc.returncode))
  if 'READY ' in (out/(label+'.log')).read_text():return proc
  time.sleep(.025)
 raise AssertionError('startup missing READY')
def req(path,data=None):
 started=time.monotonic()
 try:
  r=direct.open(urllib.request.Request(f'http://127.0.0.1:{http_port}'+path,data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'}),timeout=8)
  return {'status':r.status,'body':json.loads(r.read()),'elapsed':time.monotonic()-started}
 except urllib.error.HTTPError as e:return {'status':e.code,'body':e.read().decode(),'elapsed':time.monotonic()-started}
 except Exception as e:return {'error':type(e).__name__+': '+str(e),'elapsed':time.monotonic()-started}
def ok(path,data):
 r=req(path,data);note('setup'+path,response=r);assert r['status']==200,r;return r['body']['data']
def rows():
 c=sqlite3.connect(db);c.row_factory=sqlite3.Row
 data={t:[dict(r) for r in c.execute('SELECT * FROM '+t)] for t in ['messages','targets']};c.close();return data
try:
 proc=launch('before');device=ok('/device/register',{'platform':'android'})['device_key'];ok('/channel/device',{'device_key':device,'channel_type':'FCM','provider_token':uuid.uuid4().hex});synthetic_value=uuid.uuid4().hex
 channel=ok('/channel/subscribe',{'device_key':device,'channel_name':'external-fault','password':synthetic_value})['channel_id']
 message={'channel_id':channel,'password':synthetic_value,'title':'synthetic held provider','op_id':'external-fault-held','ttl':int(time.time()*1000)+120000}
 accepted=ok('/message',message);assert arrived.wait(5),'provider never arrived';note('accepted-held',accepted=accepted,rows=rows())
 blocker=sqlite3.connect(db,timeout=1);blocker.execute('BEGIN IMMEDIATE');note('external-BEGIN-IMMEDIATE');release.set()
 with concurrent.futures.ThreadPoolExecutor(2) as pool:
  time.sleep(.1);concurrent=pool.submit(req,'/message',dict(message,op_id='external-fault-concurrent'))
  code=proc.wait(timeout=8);note('fixture-exit',code=code);note('concurrent-post',response=concurrent.result());note('post-after-exit',response=req('/message',dict(message,op_id='external-fault-after')))
 blocker.rollback();blocker.close();note('released-external-lock',rows=rows(),provider_requests=sends.copy());assert code==70,code
 before=rows();proc=launch('recovered');deadline=time.monotonic()+6
 while time.monotonic()<deadline:
  after=rows()
  if after['targets'] and after['targets'][0]['state']=='provider_accepted':break
  time.sleep(.025)
 note('manual-restart-recovery',before=before,after=after,provider_requests=sends.copy(),replay=req('/message',message))
 b=before['messages'][0];r=after['messages'][0]
 for key in ['delivery_id','message_id','op_id','accepted_at','expires_at','dedupe_until']:assert b[key]==r[key],key
 assert len(before['messages'])==1 and len(after['messages'])==1
 assert after['targets'][0]['state']=='provider_accepted',after
 assert after['targets'][0]['attempts']==before['targets'][0]['attempts']+1
 report['result']='PASS fixture exit70; manual restart stable IDs/time/TTL; library health separate';save()
except Exception as e:
 report['result']='FAIL';report['first_error']=repr(e);save();raise
finally:
 release.set()
 for proc in procs:
  if proc.poll() is None:proc.terminate();proc.wait(timeout=25)
 for log in logs:log.close()
 mock.shutdown()
