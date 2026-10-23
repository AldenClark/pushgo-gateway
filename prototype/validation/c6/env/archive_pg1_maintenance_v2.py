"""Root-authorized PG1 maintenance preservation only. Never DROP/RESET/checkpoint/workload."""
import pathlib,importlib.util,os,subprocess,json,gzip,hashlib,time,datetime,re
R=pathlib.Path(__file__).resolve().parent;O=R/'pg1-maintenance-archive-v2';os.umask(0o077);O.mkdir(exist_ok=False);P=O/'manifest.json'
def load(path,name):
 sp=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
pg=load(R/'isolated_db.py','pg');my=load(R/'fresh3/isolated_db.py','my');DB='c5_synthetic_1951de2265ad45fea8b3e6700fe9995f'
r={'status':'STARTED','timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'database':DB,'source':str(pathlib.Path(__file__).resolve()),'source_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'scope':'PG1 export only under maintenance permission; no DROP/VACUUM/CHECKPOINT/parameter/reset/PG2/business operations','drop_executed':False}
def save():P.write_text(json.dumps(r,indent=2)+'\n')
def sha(p):
 h=hashlib.sha256()
 with pathlib.Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def hostguard():
 f=os.statvfs(str(O));n=f.f_bavail*f.f_frsize
 if n<4294967296:raise RuntimeError('Host4GiB preservation guard failed; stop')
 return n
def cmd(m,args,sql=None,env=None):
 p=subprocess.run(m.D+args,input=sql,text=True,capture_output=True,timeout=7,env=env)
 if p.returncode:raise RuntimeError('Bounded command failed: '+p.stderr.strip())
 return p.stdout.strip()
def q(sql,db=None):return cmd(pg,['exec','-i','-e','PGOPTIONS=-c statement_timeout=5000',s['id'],'timeout','-k','1','5','psql','-X','-v','ON_ERROR_STOP=1','-At','-U',s['admin_user'],'-d',db or s['database']],sql)
def mq(sql):return cmd(my,['exec','-i','-e','MYSQL_PWD',ms['id'],'timeout','--kill-after=1s','5s','mysql','--batch','--skip-column-names','-uroot'],sql,dict(os.environ,MYSQL_PWD=ms['root_password']))
def counts():
 raw=q("SELECT json_build_array(schemaname,tablename) FROM pg_tables WHERE schemaname <> 'information_schema' AND schemaname NOT LIKE 'pg\_%' ESCAPE '\\' ORDER BY schemaname,tablename;",DB)
 pairs=[json.loads(line) for line in raw.splitlines()];assert pairs and any(a=='pushgo_c' for a,b in pairs), 'Expected pushgo_c business schema absent'
 def ident(v):return '"'+v.replace('"','""')+'"'
 return {a+'.'+b:int(q('SELECT count(*) FROM '+ident(a)+'.'+ident(b)+';',DB)) for a,b in pairs}
def osstate():return {'host_available_bytes':hostguard(),'pg_df':cmd(pg,['exec',s['id'],'df','-k','/var/lib/postgresql/data']),'pg_inodes':cmd(pg,['exec',s['id'],'df','-i','/var/lib/postgresql/data']),'pg_wal_du_kib':cmd(pg,['exec',s['id'],'du','-sk','/var/lib/postgresql/data/pg_wal']),'pg_cgroup':cmd(pg,['exec',s['id'],'cat','/sys/fs/cgroup/memory.current','/sys/fs/cgroup/memory.max','/sys/fs/cgroup/memory.events'])}
save()
try:
 s,i=pg.owned('pg');ms,mi=my.owned('mysql');assert s['id']=='008ea1804e16ad16c691108dfa874f2f5300499397c9aa24d2b9f5cf8f4377be' and s['owner']=='621a4982d759466ca3428d7d14af1a15';assert ms['id']=='c24a4150e4f3f3e61af1445535b24a9ab1b7c16355b1f4162ae7d17152e67f81';assert s['cases'][DB]['label']=='capacity_final_1'
 r.update({'container_id':s['id'],'owner':s['owner'],'authority_state_sha256':sha(R/'pg-owned.json'),'mounts':i['HostConfig']['Tmpfs'],'os_before_sql':osstate()});save()
 quiet={'pg_clients':q("SELECT pid,datname,state FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid();"),'pg_prepared':q('SELECT transaction,gid FROM pg_prepared_xacts;'),'mysql_clients':mq("SELECT THREAD_ID,PROCESSLIST_ID,PROCESSLIST_COMMAND FROM performance_schema.threads WHERE TYPE='FOREGROUND' AND PROCESSLIST_ID<>CONNECTION_ID() AND PROCESSLIST_COMMAND<>'Daemon';"),'mysql_trx':mq('SELECT trx_id,trx_state FROM information_schema.innodb_trx;'),'mysql_locks':mq('SELECT COUNT(*) FROM performance_schema.data_locks;'),'mysql_userlocks':mq("SELECT OWNER_THREAD_ID FROM performance_schema.metadata_locks WHERE OBJECT_TYPE='USER LEVEL LOCK';")};assert all(not v for k,v in quiet.items() if k!='mysql_locks') and quiet['mysql_locks']=='0';r['crossquiet']=quiet;r['db_size_before']=q("SELECT pg_database_size('"+DB+"');");r['counts_before']=counts();r['stats_info_before']=q('SELECT dealloc,stats_reset FROM pg_stat_statements_info;')
 cols=json.loads((R/'formal-capacity_final_1-instrumentation/stats-before.json').read_text())['columns'];assert 'query' not in cols
 rows=[json.loads(l) for l in q('SELECT row_to_json(t) FROM (SELECT '+','.join(cols)+' FROM pg_stat_statements LIMIT 1000) t;').splitlines()];assert len(rows)<=1000
 stats=O/'stats-before-export.json';pg.save(stats,{'columns':cols,'rows':rows,'entries':len(rows),'info':r['stats_info_before'],'query_text_included':False});r['stats_file']=str(stats);r['stats_sha256']=sha(stats)
 raw=R.parent/'capacity/final-9fc812b/run-pg-final-1/result.json';r['raw_result_binding']={'file':str(raw),'sha256':sha(raw),'bytes':raw.stat().st_size};save()
 dest=O/'capacity_final_1.sql.gz';err=O/'pg_dump.stderr';start=time.monotonic();h=hashlib.sha256();n=0
 args=pg.D+['exec','-e','PGOPTIONS=-c statement_timeout=5000',s['id'],'timeout','-k','1','5','pg_dump','--no-password','--format=p','--no-owner','--no-acl','-U',s['admin_user'],'-d',DB]
 with err.open('xb') as e:
  proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=e)
  try:
   with dest.open('xb') as out:
    with gzip.GzipFile(fileobj=out,mode='wb',mtime=0,compresslevel=1) as g:
     while True:
      hostguard();b=proc.stdout.read(1048576)
      if not b:break
      if time.monotonic()-start>5:raise RuntimeError('5s dump limit exceeded; partial retained')
      g.write(b);h.update(b);n+=len(b);hostguard()
   code=proc.wait(timeout=1);assert code==0 and time.monotonic()-start<=5
  finally:
   proc.stdout.close()
   if proc.poll() is None:proc.terminate();proc.wait(timeout=2)
 r['logical_export']={'file':str(dest),'stderr_file':str(err),'elapsed_seconds':time.monotonic()-start,'compressed_bytes':dest.stat().st_size,'compressed_sha256':sha(dest),'stream_sha256':h.hexdigest(),'stream_bytes':n,'mode':oct(dest.stat().st_mode&0o777),'semantics':'Consistent pg_dump logical snapshot; no physical/crash/WAL replay completeness claim'};save()
 h2=hashlib.sha256();n2=0
 with gzip.open(dest,'rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h2.update(b);n2+=len(b)
 assert h2.hexdigest()==h.hexdigest() and n2==n;r['logical_export']['crc_verified']=True;r['logical_export']['decompressed_sha256']=h2.hexdigest();r['logical_export']['decompressed_bytes']=n2
 r['counts_after']=counts();assert r['counts_after']==r['counts_before'];r['counts_stable']=True;r['physical_vs_logical_semantics']='Actual pg_database_size and tmpfs/WAL observations are independent of logical row counts; ACK targets0 does not release table/index file space, and dumptext size is not physical footprint.';r['capacity_next_arm_plan']='Before PG2 require >= measured PG1 growth (~399MB) plus explicit margin, not merely prior256MiB threshold. Only exact PG1 DROP after root review may reclaim its physical database files; record actual df rather than predict reclaim as fact.';r['db_size_after']=q("SELECT pg_database_size('"+DB+"');");r['stats_info_after']=q('SELECT dealloc,stats_reset FROM pg_stat_statements_info;');r['os_after']=osstate();r['drop_plan_not_executed']={'exact_database':DB,'captured_container_id':s['id'],'label':'capacity_final_1','prerequisites':'Root must review logical export/counts/CRC/SHA and authorize exact DROP. Revalidate ownership, manifest hashes, no clients/prepared/locks on exactcase and host budget. Fail stop; no forced disconnect.','drop_statement':'DROP DATABASE "'+DB+'";','other_databases':'All retained, especially capacity_final_2/nativebase/baselines. No VACUUM FULL/CHECKPOINT/parameters.','post_drop':'Read-only absence+df/actual physical space and canonicalstate/URL retirement only after separate authority. Logical targets0 is not proof of file-space release.'};r['status']='PG1_LOGICAL_EXPORT_COMPLETE_PENDING_ROOT_DROP_REVIEW';save();print(json.dumps({'manifest':str(P),'sha256':sha(P),'counts':r['counts_after'],'db_bytes':r['db_size_after'],'export':r['logical_export'],'os_after':r['os_after']},indent=2))
except Exception as e:
 r['status']='STOPPED_FIRST_ERROR_NO_RETRY';r['first_error_type']=type(e).__name__;r['first_error']='Subprocess argv withheld' if isinstance(e,subprocess.SubprocessError) else str(e);save();raise RuntimeError(r['first_error']) from None
