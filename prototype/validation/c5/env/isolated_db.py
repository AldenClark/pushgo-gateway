#!/usr/bin/env python3
"""C5 new synthetic databases only; exact local images and guarded ownership."""
import argparse, fcntl, json, os, pathlib, re, secrets, subprocess, time, uuid
from urllib.parse import urlunsplit
R=pathlib.Path(__file__).resolve().parent
D=['docker','--context','orbstack']; KEY='io.pushgo.c5.synthetic.owner'
IMAGES={'pg':'postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777','mysql':'mysql@sha256:b3b90af2a6552ae30c266fdb7d5dd55f3afb72404bb78d37fe8a23eb857fd3fb'}
os.umask(0o077)
def run(args,stdin=None):
 p=subprocess.run(D+args,input=stdin,text=True,capture_output=True)
 if p.returncode: raise RuntimeError('Docker operation failed: '+p.stderr.strip())
 return p.stdout.strip()
def save(path,obj): path.write_text(json.dumps(obj,indent=2)+'\n')
def state(engine): return R/(engine+'-owned.json')
def check():
 c=json.loads(run(['context','inspect','orbstack']))[0]
 if c['Endpoints']['docker']['Host']!='unix://'+str(pathlib.Path.home()/'.orbstack/run/docker.sock'): raise RuntimeError('Unexpected Docker endpoint')
def owned(engine):
 s=json.loads(state(engine).read_text())
 if not re.fullmatch('[a-f0-9]{64}',s['id']) or not re.fullmatch('[a-f0-9]{32}',s['owner']): raise RuntimeError('Invalid ownership receipt')
 i=json.loads(run(['inspect',s['id']]))[0]
 if i['Id']!=s['id'] or i['Config']['Labels'].get(KEY)!=s['owner'] or i['Name']!='/pushgo-c5-'+engine+'-'+s['owner']: raise RuntimeError('Ownership mismatch')
 return s,i
def sql(engine,query,db=None):
 s,_=owned(engine)
 if engine=='pg': args=['psql','-X','-v','ON_ERROR_STOP=1','-At','-U',s['user'],'-d',db or s['database']]
 else: args=['mysql','--batch','--skip-column-names','-uroot']+(['--database='+db] if db else [])
 env=['-e','MYSQL_PWD='+s['root_password']] if engine=='mysql' else []
 return run(['exec','-i']+env+[s['id']]+args,query)
def writeurl(engine,s,db):
 authority=s['user']+(':'+s['password'] if engine=='mysql' else '')+'@'+s['endpoint']
 url=urlunsplit(('postgresql' if engine=='pg' else 'mysql',authority,'/'+db,'',''))
 p=R/(db+'-'+engine+'-url.txt'); p.write_text(url+'\n'); return p
def start(engine):
 if state(engine).exists(): raise RuntimeError('Receipt exists; never reuse')
 run(['image','inspect',IMAGES[engine]])
 token=uuid.uuid4().hex; db='c5_synthetic_'+token; user='c5_test_'+token[:16]
 s={'owner':token,'database':db,'user':user,'image':IMAGES[engine],'cases':{}}
 args=['run','--pull=never','--detach','--name','pushgo-c5-'+engine+'-'+token,'--label',KEY+'='+token,'--memory=1280m','--memory-swap=1280m','--cpus=2','--pids-limit=128','--network=bridge','--read-only','--tmpfs','/tmp:rw,size=32m','--shm-size=64m']
 if engine=='pg':
  args+=['--publish','127.0.0.1::5432','--tmpfs','/var/lib/postgresql/data:rw,size=768m','--tmpfs','/var/run/postgresql:rw,size=16m','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_DB='+db,'-e','POSTGRES_USER='+user,IMAGES[engine],'-c','shared_buffers=32MB','-c','max_connections=60','-c','max_wal_size=128MB','-c','min_wal_size=32MB','-c','log_statement=none']
 else:
  s['root_password']=secrets.token_hex(24); s['password']=secrets.token_hex(24)
  args+=['--publish','127.0.0.1::3306','--tmpfs','/var/lib/mysql:rw,size=768m','--tmpfs','/var/run/mysqld:rw,size=16m','-e','MYSQL_ROOT_PASSWORD='+s['root_password'],'-e','MYSQL_DATABASE='+db,'-e','MYSQL_USER='+user,'-e','MYSQL_PASSWORD='+s['password'],IMAGES[engine],'--innodb-buffer-pool-size=64M','--innodb-redo-log-capacity=64M','--max-connections=60','--performance-schema=OFF','--table-open-cache=128','--temptable-max-ram=16M','--temptable-max-mmap=0']
 s['id']=run(args)
 if not re.fullmatch('[a-f0-9]{64}',s['id']): raise RuntimeError('Unexpected container ID')
 save(state(engine),s)
 for n in range(120):
  try: sql(engine,'SELECT 1;'); break
  except RuntimeError as e:
   if n==0: (R/(engine+'-first-readiness-error.txt')).write_text(str(e)+'\n')
   if n==119: raise
   time.sleep(.5)
 port=run(['port',s['id'],'5432/tcp' if engine=='pg' else '3306/tcp'])
 if not re.fullmatch(r'127\.0\.0\.1:[0-9]+',port): raise RuntimeError('Unexpected endpoint')
 s['endpoint']=port; save(state(engine),s); p=writeurl(engine,s,db)
 print(json.dumps({'status':'READY','engine':engine,'database':db,'endpoint':port,'url_file':str(p)}))
def create(engine,label):
 if not re.fullmatch('[a-z][a-z0-9_]{0,24}',label): raise RuntimeError('Invalid case label')
 with (R/'cases.lock').open('a') as f:
  fcntl.flock(f,fcntl.LOCK_EX); s,_=owned(engine); db='c5_synthetic_'+label+'_'+uuid.uuid4().hex[:16]
  grant_db=db.replace('_','\\_')
  sql(engine,('CREATE DATABASE '+db+';') if engine=='pg' else ('CREATE DATABASE `'+db+'`; GRANT ALL PRIVILEGES ON `'+grant_db+'`.* TO '+repr(s['user'])+"@'%';"))
  p=writeurl(engine,s,db); s['cases'][db]={'url_file':str(p),'label':label}; save(state(engine),s)
 print(json.dumps({'engine':engine,'database':db,'user':s['user'],'url_file':str(p)}))
def drop(engine,db):
 with (R/'cases.lock').open('a') as f:
  fcntl.flock(f,fcntl.LOCK_EX); s,_=owned(engine)
  if db not in s['cases'] or not re.fullmatch('c5_synthetic_[a-z0-9_]+',db): raise RuntimeError('Not a captured fresh case')
  sql(engine,'DROP DATABASE '+db+';'); pathlib.Path(s['cases'].pop(db)['url_file']).unlink(missing_ok=True); save(state(engine),s)
def cleanup(engine):
 s,_=owned(engine); run(['rm','--force',s['id']]); state(engine).rename(R/(engine+'-removed-'+s['owner']+'.json'))
 for p in R.glob('c5_synthetic_*-'+engine+'-url.txt'): p.unlink()
 print('Removed captured '+engine+' container; tmpfs discarded')
if __name__=='__main__':
 p=argparse.ArgumentParser(); p.add_argument('action',choices=['start','status','create','drop','sql','cleanup']); p.add_argument('engine',choices=IMAGES); p.add_argument('value',nargs='?'); p.add_argument('--database'); a=p.parse_args(); check()
 if a.action=='start': start(a.engine)
 elif a.action=='status':
  s,i=owned(a.engine); print(json.dumps({'id':s['id'],'engine':a.engine,'status':i['State']['Status'],'endpoint':s.get('endpoint'),'image':i['Image'],'mount_types':[m['Type'] for m in i['Mounts']]}))
 elif a.action=='create': create(a.engine,a.value)
 elif a.action=='drop': drop(a.engine,a.value)
 elif a.action=='sql':
  s,_=owned(a.engine)
  if a.database and a.database not in s['cases']: raise RuntimeError('Unowned case database')
  print(sql(a.engine,pathlib.Path(a.value).read_text(),a.database))
 elif a.action=='cleanup': cleanup(a.engine)
