from pathlib import Path
import subprocess,socket,time,urllib.request,urllib.error,json,hashlib,signal,sqlite3,os
O=Path(__file__).resolve().parent/'http-oversize-second';O.mkdir(exist_ok=False)
B=O.parent.parent/'binaries/gateway-6d461fe-normal';s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close();db=O/'synthetic.sqlite';base='http://127.0.0.1:'+str(port)
args=[str(B),'--db-url','sqlite://'+str(db),'--http-addr','127.0.0.1:'+str(port),'--mock-endpoint','http://127.0.0.1:1','--private-enabled','--private-wss-enabled'];r={'binary_sha256':hashlib.sha256(B.read_bytes()).hexdigest(),'runtime_commit':'6d461fe8302ce0aace672217c9aca84ddbf4ba6e','scope':'credential-free oversized HTTP JSON, not business acceptance','cases':[]};p=None
try:
 with (O/'server.log').open('x') as f:
  p=subprocess.Popen(args,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
  for _ in range(100):
   try:
    with urllib.request.urlopen(base+'/gateway/profile',timeout=.2) as q:assert q.status==200
    break
   except (OSError,urllib.error.URLError):
    assert p.poll() is None;time.sleep(.05)
  else:raise AssertionError('startup bound elapsed')
  for size in (32769,1048576):
   data=b'{"pad":"'+b'x'*(size-10)+b'"}';assert len(data)==size
   req=urllib.request.Request(base+'/message',data=data,headers={'Content-Type':'application/json'})
   try:
    with urllib.request.urlopen(req,timeout=5) as q:code=q.status
   except urllib.error.HTTPError as e:code=e.code;e.read(4096)
   r['cases'].append({'http_bytes':size,'input_sha256':hashlib.sha256(data).hexdigest(),'status':code});assert code==413
  os.killpg(p.pid,signal.SIGTERM);r['clean_exit']=p.wait(timeout=7);assert r['clean_exit']==0
 with sqlite3.connect(db) as c:r['persisted_identity_count']=c.execute('SELECT count(*) FROM messages').fetchone()[0]
 assert r['persisted_identity_count']==0;r['status']='PASS'
finally:
 if p and p.poll() is None:
  os.killpg(p.pid,signal.SIGTERM);p.wait(timeout=7)
 (O/'receipt.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r))
