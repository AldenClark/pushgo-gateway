"""Narrow bounded/pre-reset guard wrapper; original prepare_pg_arm_disk3.py unchanged."""
import pathlib,importlib.util,subprocess,os,json,sys,hashlib,datetime
R=pathlib.Path(__file__).resolve().parent;os.umask(0o077)
assert sys.argv[1:]==['capacity_final_1','--prior-arm-quiet-approved'], 'Only explicitly authorized PG1 slot'
P=R/'pg1-bounded-preflight.json';assert not P.exists()
def load(p,n):
 sp=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
r={'status':'STARTED','source':str(pathlib.Path(__file__)),'source_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'base_script_sha256':hashlib.sha256((R/'prepare_pg_arm_disk3.py').read_bytes()).hexdigest(),'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
def save():P.write_text(json.dumps(r,indent=2)+'\n')
def bounded(m):
 def run(args,stdin=None,environment=None):
  try:p=subprocess.run(m.D+args,input=stdin,text=True,capture_output=True,timeout=7,env=environment)
  except subprocess.SubprocessError:raise RuntimeError('Bounded Docker operation timed out; argv withheld') from None
  if p.returncode:raise RuntimeError('Bounded operation failed: '+p.stderr.strip())
  return p.stdout.strip()
 m.run=run
 def sql(engine,query,db=None):
  s,_=m.owned(engine)
  if engine=='pg':
   args=['exec','-i','-e','PGOPTIONS=-c statement_timeout=5000',s['id'],'timeout','-k','1','5','psql','-X','-v','ON_ERROR_STOP=1','-At','-U',s.get('admin_user',s['user']),'-d',db or s['database']];env=None
  else:
   args=['exec','-i','-e','MYSQL_PWD',s['id'],'timeout','--kill-after=1s','5s','mysql','--batch','--skip-column-names','-uroot']+(['--database='+db] if db else []);env=dict(os.environ,MYSQL_PWD=s['root_password'])
  return run(args,query,env)
 m.sql=sql;return m
save()
try:
 pg=bounded(load(R/'isolated_db.py','pgcheck'));my=bounded(load(R/'fresh3/isolated_db.py','mycheck'));s,i=pg.owned('pg');ms,mi=my.owned('mysql');assert s['id']=='008ea1804e16ad16c691108dfa874f2f5300499397c9aa24d2b9f5cf8f4377be' and s['owner']=='621a4982d759466ca3428d7d14af1a15';assert ms['id']=='c24a4150e4f3f3e61af1445535b24a9ab1b7c16355b1f4162ae7d17152e67f81'
 db='c5_synthetic_1951de2265ad45fea8b3e6700fe9995f';assert s['cases'][db]['label']=='capacity_final_1'
 fs=os.statvfs(str(R));r['host_available_bytes']=fs.f_bavail*fs.f_frsize;r['pg_df']=pg.run(['exec',s['id'],'df','-k','/var/lib/postgresql/data']);r['pg_available_bytes']=int(r['pg_df'].splitlines()[-1].split()[3])*1024;r['pg_datadir_reservation_bytes']=768*1024*1024;r['minimum_pg_free_bytes']=256*1024*1024;r['pg_mounts']=i['HostConfig']['Tmpfs'];r['pg_cgroup_before']=pg.run(['exec',s['id'],'cat','/sys/fs/cgroup/memory.current','/sys/fs/cgroup/memory.max','/sys/fs/cgroup/memory.events']);r['budget_scope']='host>=4GiB; PG fixed768MiB tmpfs with >=256MiB free pre-arm; no disk/RAM changes';save();assert r['host_available_bytes']>=4294967296 and r['pg_available_bytes']>=r['minimum_pg_free_bytes']
 r['pg_business_tables']=pg.sql('pg',"SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE';",db);assert r['pg_business_tables']=='0';r['database']=db;r['url_file']=s['cases'][db]['url_file'];r['status']='PRE_RESET_GUARDS_PASS';save()
 orig=load(R/'prepare_pg_arm_disk3.py','original');base_load=orig.load
 orig.load=lambda p,n:bounded(base_load(p,n))
 orig.main()
 r['status']='ORIGINAL_PREP_COMPLETED_WITH_BOUNDED_WRAPPER';save();print(json.dumps({'preflight':str(P),'sha256':hashlib.sha256(P.read_bytes()).hexdigest(),'host_available_bytes':r['host_available_bytes'],'pg_available_bytes':r['pg_available_bytes']}))
except Exception as e:
 r['status']='STOPPED_FIRST_FAILURE_NO_RETRY';r['first_error_type']=type(e).__name__;r['first_error']='Subprocess arguments withheld' if isinstance(e,subprocess.SubprocessError) else str(e);save();raise RuntimeError(r['first_error']) from None
