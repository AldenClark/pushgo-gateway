#!/usr/bin/env python3
"""Focused supplement: explicitly observe server lock absent before OS fence refusal."""
import argparse,hashlib,json,pathlib,signal,socket,subprocess,time,urllib.parse
P=argparse.ArgumentParser();P.add_argument('--binary',required=True);P.add_argument('--workspace',required=True);P.add_argument('--out',required=True);P.add_argument('--commit',required=True);P.add_argument('--expected-sha256',required=True);P.add_argument('--env-helper',required=True);P.add_argument('--baseline',required=True);A=P.parse_args()
O=pathlib.Path(A.out);O.mkdir(exist_ok=False)
B=pathlib.Path(A.binary);W=pathlib.Path(A.workspace);H=pathlib.Path(A.env_helper);SHA=A.expected_sha256;COMMIT=A.commit
assert hashlib.sha256(B.read_bytes()).hexdigest()==SHA;assert subprocess.check_output(['git','-C',str(W),'rev-parse','HEAD'],text=True).strip()==COMMIT
baseline=json.loads(pathlib.Path(A.baseline).read_text())
def hashes():return {p:hashlib.sha256((W/p).read_bytes()).hexdigest() for p in baseline}
assert hashes()==baseline
R={'commit':COMMIT,'sha256':SHA,'events':[]};procs=[];logs=[]
def note(kind,**v):R['events'].append(dict(kind=kind,at=time.time(),**v));(O/'receipt.json').write_text(json.dumps(R,indent=2)+'\n')
def helper(*a):
 p=subprocess.run(['python3',str(H),*a],capture_output=True,text=True,timeout=20);assert p.returncode==0,'guarded helper failed; sensitive output suppressed';return p.stdout.strip()
c=json.loads(helper('create','mysql','released_fence'));DB=c['database'];u=urllib.parse.urlsplit(pathlib.Path(c['url_file']).read_text().strip());url=urllib.parse.urlunsplit(u._replace(query='ssl-mode=DISABLED'));alias=urllib.parse.urlunsplit(u._replace(netloc=u.netloc.replace('127.0.0.1','localhost'),query='ssl-mode=DISABLED&charset=utf8mb4'))
def sql(q):p=O/'query.sql';p.write_text(q);return helper('sql','mysql',str(p),'--database',DB)
def port():
 s=socket.socket();s.bind(('127.0.0.1',0));p=s.getsockname()[1];s.close();return p
def launch(name,url,reject=False):
 log=open(O/(name+'.log'),'w');logs.append(log);p=subprocess.Popen([str(B),'--db-url',url,'--http-addr','127.0.0.1:'+str(port()),'--mock-endpoint','http://127.0.0.1:'+str(port()),'--provider-budget','1','--claim-quantum','1'],stdout=log,stderr=subprocess.STDOUT);procs.append(p);deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  text=(O/(name+'.log')).read_text()
  if p.poll() is not None:
   assert reject and p.returncode!=0 and text.strip()=='Error: OwnerContention';note(name,exit_code=p.returncode);return p
  if 'READY ' in text:assert not reject;note(name,pid=p.pid);return p
  time.sleep(.025)
 raise AssertionError('bounded startup deadline')
try:
 old=launch('old-owner-live',url);osignal=signal.SIGSTOP;old.send_signal(osignal);note('old-owner-sigstop-but-live',pid=old.pid)
 lock="CONCAT('pushgo-c-dataset-',dataset_uuid)";session=sql('SELECT IS_USED_LOCK('+lock+') FROM authority_metadata WHERE singleton=1;');assert session.isdigit();sql('KILL CONNECTION '+session+';');note('exact-owner-session-killed',connection_id=int(session))
 free=sql('SELECT IS_USED_LOCK('+lock+') IS NULL FROM authority_metadata WHERE singleton=1;');assert free=='1';assert old.poll() is None;note('server-dataset-lock-confirmed-unowned-old-process-live',is_used_lock_is_null=True)
 launch('alias-params-rejected-after-confirmed-server-lock-release',alias,True);assert old.poll() is None;assert sql('SELECT IS_USED_LOCK('+lock+') IS NULL FROM authority_metadata WHERE singleton=1;')=='1';note('server-lock-still-unowned-old-process-still-live')
 old.kill();old.wait(timeout=5);new=launch('restart-after-old-process-exit',url);note('restart-success-after-os-owner-exit',old_exit_code=old.returncode,new_pid=new.pid);R['result']='PASS';note('completed')
except Exception as e:R['result']='FAIL';note('first-failure',error=repr(e));raise
finally:
 for p in procs:
  if p.poll() is None:
   p.send_signal(signal.SIGCONT);p.terminate()
   try:p.wait(timeout=10)
   except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
 for l in logs:l.close()
 helper('drop','mysql',DB);assert hashes()==baseline;assert hashlib.sha256(B.read_bytes()).hexdigest()==SHA;note('owned-processes-closed-fresh-db-dropped-product-hashes-unchanged',product_files=len(baseline))
