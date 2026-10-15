#!/usr/bin/env python3
"""C8 isolated DRAFT: explicit root launch approval required; source-only preparation."""
import argparse, fcntl, json, os, pathlib, re, secrets, subprocess, time, uuid
from urllib.parse import urlunsplit
R=pathlib.Path(__file__).resolve().parent
D=['docker','--context','orbstack']; KEY='io.pushgo.c7.isolated.synthetic.owner'
AUTH=pathlib.Path('/Users/ethan/Repo/PushGo/gateway/build/quality-results/c7-private-frame64-20261015/env')
EXPECTED={'pg':('2fc5f06ee05b5697694a79229ee0c0d261e347fea0e0cc44ba6e1f8cbb835dbd','2a42dd57da4c4bcba66e0509ad35c93c'),'mysql':('eaaf0b526c22bafb0a61a6e8e569008a246f677923e022f245c5a1264f577ed1','bd59112fdf0843f7962bf56cb7e44cb5')}
IMAGES={'pg': 'postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777', 'mysql': 'mysql@sha256:b3b90af2a6552ae30c266fdb7d5dd55f3afb72404bb78d37fe8a23eb857fd3fb'}
os.umask(0o077)
def run(args,stdin=None,environment=None):
 try:
  p=subprocess.run(D+args,input=stdin,text=True,capture_output=True,env=environment,timeout=7)
 except (subprocess.SubprocessError,OSError) as error:
  raise RuntimeError('Docker invocation failed ('+type(error).__name__+'); command arguments withheld') from None
 if p.returncode: raise RuntimeError('Docker operation failed: '+p.stderr.strip())
 return p.stdout.strip()
def save(path,obj):
 if path==state('mysql') and isinstance(obj,dict):obj={k:v for k,v in obj.items() if k!='root_password'}
 path.write_text(json.dumps(obj,indent=2)+'\n')
def state(engine):
 if engine=='mysql' and (R/'mysql-archived-stalled-only.json').exists(): raise RuntimeError('Original MySQL is archived-stalled-only; use env/fresh2/isolated_db.py, never old URLs')
 return R/(engine+'-owned.json')
def check():
 c=json.loads(run(['context','inspect','orbstack']))[0]
 if c['Endpoints']['docker']['Host']!='unix://'+str(pathlib.Path.home()/'.orbstack/run/docker.sock'): raise RuntimeError('Unexpected Docker endpoint')
def authority(engine):
 import hashlib
 p=AUTH/(engine+'-owned.json');parent=json.loads(p.read_text());ident,owner=EXPECTED[engine]
 if parent['id']!=ident or parent['owner']!=owner:raise RuntimeError('Captured parent engine authority changed')
 i=json.loads(run(['inspect',ident]))[0]
 if i['Id']!=ident or i['Name']!='/pushgo-c7-isolated-'+engine+'-'+owner or i['Config']['Labels'].get(KEY)!=owner or i['Image']!=IMAGES[engine].split('@')[1]:raise RuntimeError('Parent exact identity/image/label mismatch')
 if engine=='mysql':
  v=json.loads(run(['volume','inspect',parent['volume_name']]))[0];mounts=[x for x in i['Mounts'] if x['Destination']=='/var/lib/mysql']
  if v['Labels'].get(KEY)!=owner or v['Driver']!='local' or len(mounts)!=1 or mounts[0]['Name']!=v['Name'] or mounts[0]['Source']!=v['Mountpoint']:raise RuntimeError('Parent namedvolume ownership/mount mismatch')
 return parent,i,hashlib.sha256(p.read_bytes()).hexdigest()
def owned(engine):
 s=json.loads(state(engine).read_text());parent,i,digest=authority(engine)
 if (s['id'],s['owner'])!=EXPECTED[engine] or s['engine_authority_sha256']!=digest or s['engine_authority_source']!=str(AUTH/(engine+'-owned.json')):raise RuntimeError('C8 engine lease changed')
 # Root credential stays only in unchanged parent synthetic authority; never copy to C8 registry.
 if engine=='mysql':s['root_password']=parent['root_password']
 return s,i
def sql(engine,query,db=None):
 s,_=owned(engine)
 if engine=='pg':
  args=['exec','-i','-e','PGOPTIONS=-c statement_timeout=5000',s['id'],'timeout','-k','1','5','psql','-X','-v','ON_ERROR_STOP=1','-At','-U',s.get('admin_user',s['user']),'-d',db or s['database']];environment=None
 else:
  args=['exec','-i','-e','MYSQL_PWD',s['id'],'timeout','--kill-after=1s','5s','mysql','--batch','--skip-column-names','-uroot']+(['--database='+db] if db else []);environment=dict(os.environ,MYSQL_PWD=s['root_password'])
 # Preserve the harness injectable run seam for remaining190s/validation/optional deadlines.
 return run(args,query,environment=environment)
def writeurl(engine,s,db):
 authority=s['user']+(':'+s['password'] if engine=='mysql' else '')+'@'+s['endpoint']
 url=urlunsplit(('postgresql' if engine=='pg' else 'mysql',authority,'/'+db,'',''))
 p=R/(db+'-'+engine+'-url.txt'); p.write_text(url+'\n'); return p
def record_case(engine,s,db):
 p=R/'active-case-manifest.json'
 manifest=json.loads(p.read_text()) if p.exists() else {'status':'C8_OWNED_CASES_ALLOCATED_NO_WORKLOAD_AUTHORITY','cases':[]}
 assert not any(e['backend']==('postgres' if engine=='pg' else 'mysql') and e['database']==db for e in manifest['cases'])
 case=s['cases'][db];manifest['cases'].append({'backend':'postgres' if engine=='pg' else 'mysql','label':case['label'],'database':db,'url_file':case['url_file'],'role':case.get('role',s['user']),'container_id':s['id'],'owner_uuid':s['owner'],'case_registry_owner':s['case_registry_owner'],'engine_authority_source':s['engine_authority_source'],'image_reference':s['image'],'environment_helper':str(R/'isolated_db.py'),'captured_state':str(state(engine)),'environment_namespace':'C8/isolated','storage_medium':'bounded-tmpfs' if engine=='pg' else 'disk-backed-named-volume','volume_name':s.get('volume_name'),'legacy_fixture_name':case['legacy_fixture_name'],'native_factory':case.get('native_factory',False)})
 save(p,manifest)
def start(engine):
 if os.environ.get('C8_ENGINE_LEASE_APPROVED')!='YES_CAPTURED_ENGINES_FRESH_CASES_ONLY':raise RuntimeError('Root C8 engine reuse go required')
 if state(engine).exists():raise RuntimeError('C8 registry exists; refuse repeated lease setup')
 f=os.statvfs(str(R))
 if f.f_bavail*f.f_frsize<4294967296+536870912:raise RuntimeError('Host below4GiB+512MiB lease reserve')
 parent,i,digest=authority(engine)
 if not i['State']['Running']:raise RuntimeError('Captured engine not running; do not restart tmpfs or replace it')
 lease={'id':parent['id'],'owner':parent['owner'],'image':parent['image'],'endpoint':parent['endpoint'],'database':parent['database'],'admin_user':parent.get('admin_user'),'volume_name':parent.get('volume_name'),'cases':{},'user':'c8_test_'+uuid.uuid4().hex[:16],'password':secrets.token_hex(24),'case_registry_owner':uuid.uuid4().hex,'engine_authority_source':str(AUTH/(engine+'-owned.json')),'engine_authority_sha256':digest,'engine_lease_only':True}
 save(state(engine),lease)
 if i['State']['Paused']:run(['unpause',parent['id']])
 if engine=='pg':sql(engine,'CREATE ROLE '+lease['user']+' LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB; GRANT pg_read_all_stats TO '+lease['user']+';')
 else:sql(engine,"CREATE USER '"+lease['user']+"'@'%' IDENTIFIED BY '"+lease['password']+"'; GRANT PROCESS ON *.* TO '"+lease['user']+"'@'%'; GRANT SELECT ON performance_schema.* TO '"+lease['user']+"'@'%';")
 print(json.dumps({'status':'C8_LEASE_ACTIVE_NEW_ROLE_ONLY','engine':engine,'id':lease['id'],'owner':lease['owner'],'case_registry_owner':lease['case_registry_owner']}))
def create(engine,label,legacy_fixture_name=False):
 if os.environ.get('C8_CASE_PROVISION_APPROVED')!='YES_FRESH_OWNED_ONLY': raise RuntimeError('Root provisioning go required; no case mutation')
 if not re.fullmatch('[a-z][a-z0-9_]{0,24}',label): raise RuntimeError('Invalid case label')
 with (R/'cases.lock').open('a') as f:
  fcntl.flock(f,fcntl.LOCK_EX); s,_=owned(engine)
  if any(v['label']==label for v in s['cases'].values()): raise RuntimeError('Case label exists; refuse reuse')
  # Legacy observer names are permitted only inside this exact C8-owned instance.
  # Never load C5 state, reuse a database, or write any URL outside this C8 env.
  db=('c5_synthetic_'+uuid.uuid4().hex) if legacy_fixture_name else ('c8_synthetic_'+label+'_'+uuid.uuid4().hex[:16])
  grant_db=db.replace('_','\\_')
  sql(engine,('CREATE DATABASE '+db+' OWNER '+s['user']+';') if engine=='pg' else ('CREATE DATABASE `'+db+'`; GRANT ALL PRIVILEGES ON `'+grant_db+'`.* TO '+repr(s['user'])+"@'%';"))
  
  if engine=='pg': sql(engine,'CREATE EXTENSION IF NOT EXISTS pg_stat_statements;',db)
  p=writeurl(engine,s,db); s['cases'][db]={'url_file':str(p),'label':label,'legacy_fixture_name':legacy_fixture_name}; save(state(engine),s);record_case(engine,s,db)
 print(json.dumps({'engine':engine,'database':db,'user':s['user'],'url_file':str(p)}))
def factory(engine,label):
 if os.environ.get('C8_FACTORY_PROVISION_APPROVED')!='YES_SCOPED_NATIVE_FACTORY':raise RuntimeError('Separate root native factory go required')
 if not re.fullmatch('[a-z][a-z0-9_]{0,24}',label):raise RuntimeError('Invalid factory label')
 with (R/'cases.lock').open('a') as f:
  fcntl.flock(f,fcntl.LOCK_EX);s,_=owned(engine)
  if any(v['label']==label for v in s['cases'].values()):raise RuntimeError('Factory label exists; refuse reuse')
  token=uuid.uuid4().hex;db='c5_synthetic_'+token;role='c8_native_'+token[:16];password=secrets.token_hex(24)
  if engine=='pg':
   sql(engine,'CREATE ROLE '+role+' LOGIN CREATEDB NOCREATEROLE NOSUPERUSER; GRANT pg_read_all_stats TO '+role+'; CREATE DATABASE '+db+' OWNER '+role+';')
  else:
   assert sql(engine,'SELECT @@partial_revokes;')=='0', 'Prefix factory grants require partial_revokes OFF'
   exact=db.replace('_','\\_');prefix='c5\\_synthetic\\_case\\_%'
   sql(engine,"CREATE USER '"+role+"'@'%' IDENTIFIED BY '"+password+"'; CREATE DATABASE `"+db+"`; GRANT ALL PRIVILEGES ON `"+exact+"`.* TO '"+role+"'@'%'; GRANT ALL PRIVILEGES ON `"+prefix+"`.* TO '"+role+"'@'%'; GRANT PROCESS ON *.* TO '"+role+"'@'%'; GRANT SELECT ON performance_schema.* TO '"+role+"'@'%';")
  private=dict(s,user=role,password=password);url=writeurl(engine,private,db);s['cases'][db]={'label':label,'url_file':str(url),'role':role,'native_factory':True,'legacy_fixture_name':True,'scope':'PG CREATEDB only isolated instance; MySQL exactbase + escaped c5_synthetic_case_% only; no SUPER/globalDDL'};save(state(engine),s);record_case(engine,s,db)
 print(json.dumps({'engine':engine,'database':db,'user':role,'url_file':str(url),'factory':True}))
def drop(engine,db):
 with (R/'cases.lock').open('a') as f:
  fcntl.flock(f,fcntl.LOCK_EX); s,_=owned(engine)
  if db not in s['cases'] or not re.fullmatch('c[58]_synthetic_[a-z0-9_]+',db): raise RuntimeError('Not a captured fresh case')
  if db.startswith('c5_') and not s['cases'][db].get('legacy_fixture_name'): raise RuntimeError('Legacy name lacks explicit C8 allocation receipt')
  sql(engine,'DROP DATABASE '+db+';'); pathlib.Path(s['cases'].pop(db)['url_file']).unlink(missing_ok=True); save(state(engine),s)
def cleanup(engine):
 raise RuntimeError('Generic cleanup disabled. Final preservation + separate exact-resource deletion approval required.')
if __name__=='__main__':
 p=argparse.ArgumentParser(); p.add_argument('action',choices=['start','status','create','drop','sql','cleanup','factory']); p.add_argument('engine',choices=['pg','mysql']); p.add_argument('value',nargs='?'); p.add_argument('--database'); p.add_argument('--legacy-fixture-name',action='store_true'); a=p.parse_args(); check()
 if a.legacy_fixture_name and a.action!='create': raise RuntimeError('Legacy fixture naming is a create-only explicit option')
 if a.action=='start': start(a.engine)
 elif a.action=='status':
  s,i=owned(a.engine); print(json.dumps({'id':s['id'],'engine':a.engine,'status':i['State']['Status'],'endpoint':s.get('endpoint'),'image':i['Image'],'mount_types':[m['Type'] for m in i['Mounts']]}))
 elif a.action=='create': create(a.engine,a.value,a.legacy_fixture_name)
 elif a.action=='factory': factory(a.engine,a.value)
 elif a.action=='drop': drop(a.engine,a.value)
 elif a.action=='sql':
  s,_=owned(a.engine)
  if a.database and a.database not in s['cases']: raise RuntimeError('Unowned case database')
  print(sql(a.engine,pathlib.Path(a.value).read_text(),a.database))
 elif a.action=='cleanup': cleanup(a.engine)
