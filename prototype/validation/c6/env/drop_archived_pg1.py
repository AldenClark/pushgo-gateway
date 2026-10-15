"""Root-authorized unique exact PG1 DROP after verified logical preservation."""
import pathlib,json,hashlib,importlib.util,subprocess,os,datetime
R=pathlib.Path(__file__).resolve().parent;os.umask(0o077);P=R/'pg1-exact-drop-receipt.json';assert not P.exists();DB='c5_synthetic_1951de2265ad45fea8b3e6700fe9995f'
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
sp=importlib.util.spec_from_file_location('pg',R/'isolated_db.py');pg=importlib.util.module_from_spec(sp);sp.loader.exec_module(pg)
r={'status':'STARTED','timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'database':DB,'source':str(pathlib.Path(__file__)),'source_sha256':sha(__file__),'scope':'Exact archived PG1 drop only; no forced disconnect/checkpoint/vacuum/reset/config/business/othercase mutation'}
def save():pg.save(P,r)
def run(args,stdin=None,environment=None):
 p=subprocess.run(pg.D+args,input=stdin,text=True,capture_output=True,timeout=7,env=environment)
 if p.returncode:raise RuntimeError('Bounded operation failed: '+p.stderr.strip())
 return p.stdout.strip()
pg.run=run
def sql(engine,query,db=None):
 s,_=pg.owned(engine)
 return run(['exec','-i','-e','PGOPTIONS=-c statement_timeout=5000 -c lock_timeout=5000',s['id'],'timeout','-k','1','5','psql','-X','-v','ON_ERROR_STOP=1','-At','-U',s['admin_user'],'-d',db or s['database']],query)
pg.sql=sql
def osstate(s):
 f=os.statvfs(str(R));return {'host_available_bytes':f.f_bavail*f.f_frsize,'pg_df':run(['exec',s['id'],'df','-k','/var/lib/postgresql/data']),'pg_inodes':run(['exec',s['id'],'df','-i','/var/lib/postgresql/data']),'pg_cgroup':run(['exec',s['id'],'cat','/sys/fs/cgroup/memory.current','/sys/fs/cgroup/memory.max','/sys/fs/cgroup/memory.events'])}
save()
try:
 a=R/'pg1-maintenance-archive-v2/manifest.json';assert sha(a)=='ac8ba1d436ea7d8093b7c2774859456f4b909638145f744dd9ad66c479a7f13b';arch=json.loads(a.read_text());assert arch['status']=='PG1_LOGICAL_EXPORT_COMPLETE_PENDING_ROOT_DROP_REVIEW' and arch['counts_stable'] and arch['logical_export']['crc_verified'];assert sha(arch['logical_export']['file'])==arch['logical_export']['compressed_sha256'];r['archive_manifest_sha256']=sha(a);r['host_dump_sha256']=sha(arch['logical_export']['file'])
 s,i=pg.owned('pg');assert s['id']=='008ea1804e16ad16c691108dfa874f2f5300499397c9aa24d2b9f5cf8f4377be' and s['owner']=='621a4982d759466ca3428d7d14af1a15';assert s['cases'][DB]['label']=='capacity_final_1';assert s['cases'][DB]['legacy_fixture_name'];r['container_id']=s['id'];r['owner']=s['owner'];r['os_before']=osstate(s);assert r['os_before']['host_available_bytes']>=4294967296;r['other_captured_cases_before']=sorted(set(s['cases'])-{DB});r['target_url_file']=s['cases'][DB]['url_file']
 r['clients']=sql('pg',"SELECT pid,datname,state FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid();");r['prepared']=sql('pg','SELECT transaction,gid,database FROM pg_prepared_xacts;');r['target_locks']=sql('pg',"SELECT pid,locktype,mode,granted FROM pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname='"+DB+"');");assert not any(r[k] for k in ['clients','prepared','target_locks'])
 r['statement']='DROP DATABASE '+DB;r['drop_attempted_once']=True;save();pg.drop('pg',DB);r['drop_succeeded']=True;save()
 r['absence']=sql('pg',"SELECT count(*) FROM pg_database WHERE datname='"+DB+"';");assert r['absence']=='0';post,_=pg.owned('pg');assert DB not in post['cases'] and sorted(post['cases'])==r['other_captured_cases_before'];assert not pathlib.Path(r['target_url_file']).exists();r['case_state_and_url_retired']=True;r['os_after']=osstate(post)
 mf=R/'active-case-manifest.json';prior=mf.read_bytes();backup=R/'active-case-manifest.before-pg1-drop.json';assert not backup.exists();backup.write_bytes(prior);d=json.loads(prior);entries=[e for e in d['cases'] if e.get('backend')=='postgres' and e.get('database')==DB];d['cases']=[e for e in d['cases'] if not(e.get('backend')=='postgres' and e.get('database')==DB)]
 for e in entries:e.update({'status':'RETIRED_DROPPED_AFTER_ARCHIVE','retirement_receipt':str(P),'archive_manifest':str(a)})
 d.setdefault('retired_cases',[]).extend(entries);pg.save(mf,d);r['manifest_before_sha256']=hashlib.sha256(prior).hexdigest();r['manifest_after_sha256']=sha(mf);r['status']='EXACT_PG1_DROP_COMPLETE_PENDING_ROOT_PG2_AUTHORIZATION';save();print(json.dumps({'receipt':str(P),'sha256':sha(P),'os_before':r['os_before'],'os_after':r['os_after'],'absence':r['absence']},indent=2))
except Exception as e:
 r['status']='STOPPED_FIRST_ERROR_NO_RETRY';r['first_error_type']=type(e).__name__;r['first_error']='Subprocess argv withheld' if isinstance(e,subprocess.SubprocessError) else str(e);save();raise RuntimeError(r['first_error']) from None
