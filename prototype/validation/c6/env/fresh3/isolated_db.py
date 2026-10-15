#!/usr/bin/env python3
"""C6 disk3 DRAFT: explicit root launch approval required; source-only preparation."""
import argparse, fcntl, json, os, pathlib, re, secrets, subprocess, time, uuid
from urllib.parse import urlunsplit
R=pathlib.Path(__file__).resolve().parent
D=['docker','--context','orbstack']; KEY='io.pushgo.c6.disk3.synthetic.owner'
IMAGES={'pg':'postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777','mysql':'mysql@sha256:b3b90af2a6552ae30c266fdb7d5dd55f3afb72404bb78d37fe8a23eb857fd3fb'}
os.umask(0o077)
def run(args,stdin=None,environment=None):
 try:
  p=subprocess.run(D+args,input=stdin,text=True,capture_output=True,env=environment)
 except (subprocess.SubprocessError,OSError) as error:
  raise RuntimeError('Docker invocation failed ('+type(error).__name__+'); command arguments withheld') from None
 if p.returncode: raise RuntimeError('Docker operation failed: '+p.stderr.strip())
 return p.stdout.strip()
def save(path,obj): path.write_text(json.dumps(obj,indent=2)+'\n')
def state(engine):
 if engine=='mysql' and (R/'mysql-archived-stalled-only.json').exists(): raise RuntimeError('Original MySQL is archived-stalled-only; use env/fresh2/isolated_db.py, never old URLs')
 return R/(engine+'-owned.json')
def check():
 c=json.loads(run(['context','inspect','orbstack']))[0]
 if c['Endpoints']['docker']['Host']!='unix://'+str(pathlib.Path.home()/'.orbstack/run/docker.sock'): raise RuntimeError('Unexpected Docker endpoint')
def owned(engine):
 s=json.loads(state(engine).read_text())
 if not re.fullmatch('[a-f0-9]{64}',s['id']) or not re.fullmatch('[a-f0-9]{32}',s['owner']): raise RuntimeError('Invalid ownership receipt')
 i=json.loads(run(['inspect',s['id']]))[0]
 if i['Id']!=s['id'] or i['Config']['Labels'].get(KEY)!=s['owner'] or i['Name']!='/pushgo-c6-disk3-'+engine+'-'+s['owner']: raise RuntimeError('Ownership mismatch')

 if engine=='mysql':
  v=json.loads(run(['volume','inspect',s['volume_name']]))[0]
  if v['Name']!=s['volume_name'] or v['Driver']!='local' or v['Labels'].get(KEY)!=s['owner']: raise RuntimeError('Volume ownership mismatch')
  mounts=[x for x in i['Mounts'] if x['Destination']=='/var/lib/mysql']
  if len(mounts)!=1 or mounts[0]['Type']!='volume' or mounts[0]['Name']!=s['volume_name'] or mounts[0]['Source']!=v['Mountpoint']: raise RuntimeError('Datadir volume source identity mismatch')
 return s,i
def sql(engine,query,db=None):
 s,_=owned(engine)
 if engine=='pg': args=['psql','-X','-v','ON_ERROR_STOP=1','-At','-U',s.get('admin_user',s['user']),'-d',db or s['database']]
 else: args=['mysql','--batch','--skip-column-names','-uroot']+(['--database='+db] if db else [])
 env=['-e','MYSQL_PWD'] if engine=='mysql' else []
 environment=dict(os.environ,MYSQL_PWD=s['root_password']) if engine=='mysql' else None
 return run(['exec','-i']+env+[s['id']]+args,query,environment=environment)
def writeurl(engine,s,db):
 authority=s['user']+(':'+s['password'] if engine=='mysql' else '')+'@'+s['endpoint']
 url=urlunsplit(('postgresql' if engine=='pg' else 'mysql',authority,'/'+db,'',''))
 p=R/(db+'-'+engine+'-url.txt'); p.write_text(url+'\n'); return p
def start(engine):
 if os.environ.get('C6_DISK3_LAUNCH_APPROVED')!='YES_NEW_SYNTHETIC_DISK_ONLY': raise RuntimeError('DRAFT: root has not approved a fresh3 launch; no resource created')
 sv=os.statvfs(str(R))
 if sv.f_bavail*sv.f_frsize<4294967296: raise RuntimeError('Host available bytes below4GiB, refuse volume/container creation')
 if state(engine).exists(): raise RuntimeError('Receipt exists; never reuse')
 run(['image','inspect',IMAGES[engine]])
 token=uuid.uuid4().hex; db='c6_synthetic_'+token; user='c6_test_'+token[:16]
 launch_environment=None
 s={'owner':token,'database':db,'user':user,'image':IMAGES[engine],'cases':{}}
 if engine=='pg': s['admin_user']='c6_admin_'+token[:16]
 args=['run','--pull=never','--detach','--name','pushgo-c6-disk3-'+engine+'-'+token,'--label',KEY+'='+token,'--memory=1280m','--memory-swap=1280m','--cpus=2','--pids-limit=128','--network=bridge','--read-only','--tmpfs','/tmp:rw,size=32m','--shm-size=64m']
 if engine=='pg':
  args+=['--publish','127.0.0.1::5432','--tmpfs','/var/lib/postgresql/data:rw,size=768m','--tmpfs','/var/run/postgresql:rw,size=16m','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_DB='+db,'-e','POSTGRES_USER='+s['admin_user'],IMAGES[engine],'-c','shared_buffers=32MB','-c','max_connections=60','-c','max_wal_size=128MB','-c','min_wal_size=32MB','-c','log_statement=none','-c','shared_preload_libraries=pg_stat_statements','-c','pg_stat_statements.max=1000','-c','pg_stat_statements.track=all','-c','track_io_timing=on']
 else:
  s['root_password']=secrets.token_hex(24); s['password']=secrets.token_hex(24)
  s['volume_name']='pushgo-c6-disk3-data-'+token
  if run(['volume','ls','--filter','name='+s['volume_name'],'--format','{{.Name}}']): raise RuntimeError('Proposed volume name already exists; never reuse')
  volume=run(['volume','create','--driver','local','--label',KEY+'='+token,s['volume_name']])
  if volume!=s['volume_name']: raise RuntimeError('Unexpected created volume name')
  save(R/'owned-volume.json',{'name':volume,'owner':token,'label_key':KEY,'driver':'local','status':'CREATED_EMPTY_PENDING_CONTAINER'})
  launch_environment=dict(os.environ,MYSQL_ROOT_PASSWORD=s['root_password'],MYSQL_PASSWORD=s['password'])
  args+=['--publish','127.0.0.1::3306','--mount','type=volume,src='+s['volume_name']+',dst=/var/lib/mysql,volume-nocopy','--tmpfs','/var/run/mysqld:rw,size=16m','-e','MYSQL_ROOT_PASSWORD','-e','MYSQL_DATABASE='+db,'-e','MYSQL_USER='+user,'-e','MYSQL_PASSWORD',IMAGES[engine],'--innodb-buffer-pool-size=64M','--innodb-redo-log-capacity=64M','--max-connections=60','--performance-schema=ON','--performance-schema-digests-size=1000','--performance-schema-events-statements-history-size=10','--performance-schema-events-statements-history-long-size=1000','--performance-schema-max-sql-text-length=1024','--performance-schema-max-digest-length=1024','--table-open-cache=128','--temptable-max-ram=16M','--temptable-max-mmap=0']
 s['id']=run(args,environment=launch_environment)
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
 s['endpoint']=port; save(state(engine),s)
 if engine=='pg':
  sql(engine,'CREATE ROLE '+user+' LOGIN; GRANT pg_read_all_stats TO '+user+'; CREATE EXTENSION IF NOT EXISTS pg_stat_statements;')
 else:
  sql(engine,'SET GLOBAL log_bin_trust_function_creators=1;')
  sql(engine,'REVOKE ALL PRIVILEGES ON `'+db.replace('_','\\_')+'`.* FROM '+repr(user)+"@'%';")
  sql(engine,"GRANT PROCESS ON *.* TO "+repr(user)+"@'%'; GRANT SELECT ON performance_schema.* TO "+repr(user)+"@'%'; UPDATE performance_schema.setup_consumers SET ENABLED='YES' WHERE NAME IN ('events_statements_current','events_statements_history','events_statements_history_long','statements_digest'); UPDATE performance_schema.setup_instruments SET ENABLED='YES',TIMED='YES' WHERE NAME LIKE 'statement/%';")
 print(json.dumps({'status':'READY','engine':engine,'database':db,'endpoint':port,'business_url':'Assigned fresh cases only'}))
def create(engine,label,legacy_fixture_name=False):
 if not re.fullmatch('[a-z][a-z0-9_]{0,24}',label): raise RuntimeError('Invalid case label')
 with (R/'cases.lock').open('a') as f:
  fcntl.flock(f,fcntl.LOCK_EX); s,_=owned(engine)
  # Legacy observer names are permitted only inside this exact C6-owned instance.
  # Never load C5 state, reuse a database, or write any URL outside this C6 env.
  db=('c5_synthetic_'+uuid.uuid4().hex) if legacy_fixture_name else ('c6_synthetic_'+label+'_'+uuid.uuid4().hex[:16])
  grant_db=db.replace('_','\\_')
  sql(engine,('CREATE DATABASE '+db+' OWNER '+s['user']+';') if engine=='pg' else ('CREATE DATABASE `'+db+'`; GRANT ALL PRIVILEGES ON `'+grant_db+'`.* TO '+repr(s['user'])+"@'%';"))
  
  if engine=='pg': sql(engine,'CREATE EXTENSION IF NOT EXISTS pg_stat_statements;',db)
  p=writeurl(engine,s,db); s['cases'][db]={'url_file':str(p),'label':label,'legacy_fixture_name':legacy_fixture_name}; save(state(engine),s)
 print(json.dumps({'engine':engine,'database':db,'user':s['user'],'url_file':str(p)}))
def drop(engine,db):
 with (R/'cases.lock').open('a') as f:
  fcntl.flock(f,fcntl.LOCK_EX); s,_=owned(engine)
  if db not in s['cases'] or not re.fullmatch('c[56]_synthetic_[a-z0-9_]+',db): raise RuntimeError('Not a captured fresh case')
  if db.startswith('c5_') and not s['cases'][db].get('legacy_fixture_name'): raise RuntimeError('Legacy name lacks explicit C6 allocation receipt')
  sql(engine,'DROP DATABASE '+db+';'); pathlib.Path(s['cases'].pop(db)['url_file']).unlink(missing_ok=True); save(state(engine),s)
def cleanup(engine):
 s,_=owned(engine); run(['rm','--force',s['id']]); state(engine).rename(R/(engine+'-removed-'+s['owner']+'.json'))
 for p in R.glob('c[56]_synthetic_*-'+engine+'-url.txt'): p.unlink()
 print('Removed captured container only; owned disk volume retained pending separate explicit cleanup approval')
if __name__=='__main__':
 p=argparse.ArgumentParser(); p.add_argument('action',choices=['start','status','create','drop','sql','cleanup']); p.add_argument('engine',choices=['mysql']); p.add_argument('value',nargs='?'); p.add_argument('--database'); p.add_argument('--legacy-fixture-name',action='store_true'); a=p.parse_args(); check()
 if a.legacy_fixture_name and a.action!='create': raise RuntimeError('Legacy fixture naming is a create-only explicit option')
 if a.action=='start': start(a.engine)
 elif a.action=='status':
  s,i=owned(a.engine); print(json.dumps({'id':s['id'],'engine':a.engine,'status':i['State']['Status'],'endpoint':s.get('endpoint'),'image':i['Image'],'mount_types':[m['Type'] for m in i['Mounts']]}))
 elif a.action=='create': create(a.engine,a.value,a.legacy_fixture_name)
 elif a.action=='drop': drop(a.engine,a.value)
 elif a.action=='sql':
  s,_=owned(a.engine)
  if a.database and a.database not in s['cases']: raise RuntimeError('Unowned case database')
  print(sql(a.engine,pathlib.Path(a.value).read_text(),a.database))
 elif a.action=='cleanup': cleanup(a.engine)
