"""SOURCE PREPARED ONLY. Explicit root final QUIET preservation authority required.
Preserves positively captured DBs only. Never removes, adopts by prefix, or resets.
"""
import argparse,pathlib,json,os,subprocess,importlib.util,datetime,hashlib,gzip,time
R=pathlib.Path(__file__).resolve().parent;D=['docker','--context','orbstack']
STATES=[('pg',R/'pg-owned.json','io.pushgo.c6.synthetic.owner'),('mysql-old',R/'archived-stalled-only/mysql-owned.json','io.pushgo.c6.synthetic.owner'),('mysql-fresh2',R/'fresh2/archived-stalled-only/mysql-owned.json','io.pushgo.c6.synthetic.owner'),('mysql',R/'fresh3/mysql-owned.json','io.pushgo.c6.disk3.synthetic.owner')]
IDS=['008ea1804e16ad16c691108dfa874f2f5300499397c9aa24d2b9f5cf8f4377be','d9f40918b1222b6de1a61baf22a7b3ca5dd0da08e5e3d3afe120431553d2e94b','5db64f385657c048a1878557b79a9942f04d448aea21c68fcecdd33e6e90c886','c24a4150e4f3f3e61af1445535b24a9ab1b7c16355b1f4162ae7d17152e67f81']
def sha(p):
 h=hashlib.sha256()
 with pathlib.Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h.update(b)
 return h.hexdigest()
def run(args,sql=None,env=None):
 p=subprocess.run(D+args,input=sql,text=True,capture_output=True,timeout=7,env=env)
 if p.returncode:raise RuntimeError('Bounded operation failed; argv withheld; '+p.stderr.strip())
 return p.stdout.strip()
def query(kind,s,sql,db=None):
 if kind=='pg':return run(['exec','-i','-e','PGOPTIONS=-c statement_timeout=5000',s['id'],'timeout','-k','1','5','psql','-X','-v','ON_ERROR_STOP=1','-At','-U',s['admin_user'],'-d',db or s['database']],sql)
 return run(['exec','-i','-e','MYSQL_PWD',s['id'],'timeout','--kill-after=1s','5s','mysql','--batch','--skip-column-names','-uroot']+(['--database='+db] if db else []),sql,dict(os.environ,MYSQL_PWD=s['root_password']))
def hostguard(path):
 f=os.statvfs(str(path));n=f.f_bavail*f.f_frsize
 if n<4294967296:raise RuntimeError('Host below4GiB; stop maintenance')
 return n
def stream(args,path,err,env=None):
 start=time.monotonic();h=hashlib.sha256();n=0
 with err.open('xb') as e:
  p=subprocess.Popen(D+args,stdout=subprocess.PIPE,stderr=e,env=env)
  try:
   with path.open('xb') as out:
    with gzip.GzipFile(fileobj=out,mode='wb',compresslevel=1,mtime=0) as g:
     for b in iter(lambda:p.stdout.read(1048576),b''):
      hostguard(path.parent)
      if time.monotonic()-start>5:raise RuntimeError('5s source stream deadline exceeded')
      g.write(b);h.update(b);n+=len(b);hostguard(path.parent)
   assert p.wait(timeout=1)==0 and time.monotonic()-start<=5
  finally:
   p.stdout.close()
   if p.poll() is None:p.terminate();p.wait(timeout=2)
 h2=hashlib.sha256();n2=0
 with gzip.open(path,'rb') as f:
  for b in iter(lambda:f.read(1048576),b''):h2.update(b);n2+=len(b)
 assert h.hexdigest()==h2.hexdigest() and n==n2
 return {'file':str(path),'compressed_sha256':sha(path),'compressed_bytes':path.stat().st_size,'decompressed_sha256':h2.hexdigest(),'decompressed_bytes':n2,'crc_verified':True,'mode':oct(path.stat().st_mode&0o777),'elapsed_seconds':time.monotonic()-start}
def counts(kind,s,db):
 if kind=='pg':
  rows=query(kind,s,"SELECT json_build_array(schemaname,tablename) FROM pg_tables WHERE schemaname<>'information_schema' AND left(schemaname,3)<>'pg_' ORDER BY schemaname,tablename;",db).splitlines();pairs=[json.loads(x) for x in rows]
  ident=lambda v:'"'+v.replace('"','""')+'"'
  return {a+'.'+b:int(query(kind,s,'SELECT count(*) FROM '+ident(a)+'.'+ident(b)+';',db)) for a,b in pairs}
 names=query(kind,s,"SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA='"+db+"' AND TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME;").splitlines()
 return {n:int(query(kind,s,'SELECT count(*) FROM `'+n.replace('`','``')+'`;',db)) for n in names}
def main():
 p=argparse.ArgumentParser();p.add_argument('--root-final-quiet-preservation-approved',action='store_true');p.add_argument('--factory-receipt',action='append',default=[]);a=p.parse_args()
 if not a.root_final_quiet_preservation_approved:raise SystemExit('No operations: explicit root final QUIET preservation approval required')
 os.umask(0o077);O=R/'final-owned-preservation';O.mkdir(exist_ok=False);P=O/'manifest.json';rec={'status':'STARTED','source':str(pathlib.Path(__file__)),'source_sha256':sha(__file__),'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'resources':[],'exports':[],'deletion_authorized':False,'prefix_adoption_forbidden':True}
 def save():P.write_text(json.dumps(rec,indent=2)+'\n')
 save()
 try:
  hostguard(O);active={}
  for (kind,state,key),expected in zip(STATES,IDS):
   s=json.loads(state.read_text());assert s['id']==expected;i=json.loads(run(['inspect',expected]))[0];assert i['Id']==expected and i['Config']['Labels'].get(key)==s['owner']
   entry={'backend':kind,'id':expected,'owner':s['owner'],'label_key':key,'name':i['Name'],'state_path':str(state),'state_sha256':sha(state),'state':i['State'],'mounts':i['Mounts'],'cases':s.get('cases',{}),'bootstrap_database':s['database'],'inspect_safe':{k:i[k] for k in ['Id','Name','Image','State','Mounts','HostConfig']},'volume_name':s.get('volume_name')};rec['resources'].append(entry);save()
   logs=O/(kind+'-container.log');lp=subprocess.run(D+['logs','--timestamps','--tail','2000',expected],capture_output=True,text=True,timeout=7);assert lp.returncode==0;logs.write_text(lp.stdout+'\n[stderr]\n'+lp.stderr);entry['container_log']={'file':str(logs),'sha256':sha(logs)}
   if i['State']['Running']:active[kind]=s
  assert set(active)=={'pg','mysql'}, 'Expected only captured PG+disk3 running'
  s=active['mysql'];v=json.loads(run(['volume','inspect',s['volume_name']]))[0];assert v['Name']==s['volume_name'] and v['Driver']=='local' and v['Labels'].get(STATES[-1][2])==s['owner'];mount=[x for x in rec['resources'][-1]['mounts'] if x['Destination']=='/var/lib/mysql'];assert len(mount)==1 and mount[0]['Type']=='volume' and mount[0]['Name']==v['Name'] and mount[0]['Source']==v['Mountpoint'];rec['volume']=v
  rec['quiet']={'pg_clients':query('pg',active['pg'],"SELECT pid,datname FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid();"),'pg_prepared':query('pg',active['pg'],'SELECT transaction,gid FROM pg_prepared_xacts;'),'mysql_clients':query('mysql',s,"SELECT THREAD_ID,PROCESSLIST_ID FROM performance_schema.threads WHERE TYPE='FOREGROUND' AND PROCESSLIST_ID<>CONNECTION_ID() AND PROCESSLIST_COMMAND<>'Daemon';"),'mysql_trx':query('mysql',s,'SELECT trx_id FROM information_schema.innodb_trx;'),'mysql_datalocks':query('mysql',s,'SELECT COUNT(*) FROM performance_schema.data_locks;'),'mysql_advisory':query('mysql',s,"SELECT OWNER_THREAD_ID FROM performance_schema.metadata_locks WHERE OBJECT_TYPE='USER LEVEL LOCK';")};assert all(not v for k,v in rec['quiet'].items() if k!='mysql_datalocks') and rec['quiet']['mysql_datalocks']=='0';save()
  # Positive ownership: canonical captured cases+captured bootstrap only. Any unexpected DB stops; no prefix adoption.
  for kind,s in active.items():
   known=set(s['cases'])|{s['database']}
   def named_databases(value):
    out=set()
    if isinstance(value,dict):
     for key,v in value.items():
      if key in ['database','database_name'] and isinstance(v,str):out.add(v)
      else:out.update(named_databases(v))
    elif isinstance(value,list):
     for v in value:out.update(named_databases(v))
    return out
   rec.setdefault('factory_receipt_bindings',[])
   for filename in a.factory_receipt:
    fp=pathlib.Path(filename).resolve();fp.relative_to(R.parent.resolve());text=fp.read_text();obj=json.loads(text)
    if s['id'] in text:
     names=named_databases(obj);assert all(n.replace('_','').isalnum() for n in names)
     known.update(names);rec['factory_receipt_bindings'].append({'path':str(fp),'sha256':sha(fp),'exact_container_id':s['id'],'positively_named_databases':sorted(names),'not_adopted_into_lifecycle_state':True})
   actual=set(query(kind,s,"SELECT datname FROM pg_database WHERE NOT datistemplate AND datname<>'postgres';" if kind=='pg' else "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('mysql','information_schema','performance_schema','sys');").splitlines());unknown=sorted(actual-known);rec[kind+'_unadopted_databases']=unknown;save();assert not unknown,'Uncaptured DBs require invocation-receipt review before preservation/deletion'
   for db in sorted(actual):
    assert db in known;item={'backend':kind,'database':db,'label':s['cases'].get(db,{}).get('label','captured_bootstrap'),'counts_before':counts(kind,s,db)};rec['exports'].append(item);save()
    if kind=='pg':args=['exec','-e','PGOPTIONS=-c statement_timeout=5000',s['id'],'timeout','-k','1','5','pg_dump','--no-password','--format=p','--no-owner','--no-acl','-U',s['admin_user'],'-d',db];env=None
    else:args=['exec','-e','MYSQL_PWD',s['id'],'timeout','--kill-after=1s','5s','mysqldump','-uroot','--skip-lock-tables','--no-tablespaces','--single-transaction','--quick','--hex-blob','--skip-add-locks','--set-gtid-purged=OFF',db];env=dict(os.environ,MYSQL_PWD=s['root_password'])
    item['export']=stream(args,O/(kind+'-'+db+'.sql.gz'),O/(kind+'-'+db+'.stderr'),env);item['counts_after']=counts(kind,s,db);assert item['counts_before']==item['counts_after'];item['stable']=True;save()
  pg=active['pg'];cols=json.loads((R/'formal-capacity_final_2-instrumentation/stats-before.json').read_text())['columns'];rec['pg_numeric']=[json.loads(x) for x in query('pg',pg,'SELECT row_to_json(t) FROM (SELECT '+','.join(cols)+' FROM pg_stat_statements LIMIT1000) t;'.replace('LIMIT1000','LIMIT 1000')).splitlines()];rec['pg_info']=query('pg',pg,'SELECT dealloc,stats_reset FROM pg_stat_statements_info;');rec['pg_config']=query('pg',pg,"SELECT version(),current_setting('fsync'),current_setting('full_page_writes'),current_setting('synchronous_commit');")
  cols=[]
  for row in query('mysql',s,'SHOW COLUMNS FROM performance_schema.events_statements_summary_by_digest;').splitlines():
   n,t=row.split('\t')[:2]
   if n in ['SCHEMA_NAME','DIGEST'] or t.lower().startswith(('bigint','int','decimal','double','float')):cols.append(n)
  rec['mysql_numeric']=[json.loads(x) for x in query('mysql',s,'SELECT JSON_OBJECT('+','.join("'"+c+"',`"+c+'`' for c in cols)+') FROM performance_schema.events_statements_summary_by_digest LIMIT 1000;').splitlines()];rec['mysql_lost_rowlocks']=query('mysql',s,"SHOW GLOBAL STATUS WHERE Variable_name='Performance_schema_digest_lost' OR Variable_name LIKE 'Innodb_row_lock%';");rec['mysql_config']=query('mysql',s,'SELECT @@server_uuid,@@log_bin,@@innodb_flush_log_at_trx_commit,@@sync_binlog,@@log_bin_trust_function_creators;');rec['mysql_current']=query('mysql',s,'SHOW BINARY LOG STATUS;');name=rec['mysql_current'].split('\t')[0];assert name.startswith('binlog.') and name.replace('.','').isalnum();rec['current_live_binlog_sha']=run(['exec',s['id'],'timeout','5s','sha256sum','/var/lib/mysql/'+name]);rec['current_live_binlog_archive']=stream(['exec',s['id'],'timeout','--kill-after=1s','5s','cat','/var/lib/mysql/'+name],O/(name+'-final-live.gz'),O/'current-binlog.stderr');rec['current_binlog_limit']='Live current under quiet; not closed/crash-consistent or unknown-COMMIT resolution; no FLUSH/PURGE.'
  rec['os_after']={'host_available_bytes':hostguard(O)}
  for kind,s in active.items():rec['os_after'][kind]={'df':run(['exec',s['id'],'df','-k','/var/lib/postgresql/data' if kind=='pg' else '/var/lib/mysql']),'cgroup':run(['exec',s['id'],'cat','/sys/fs/cgroup/memory.current','/sys/fs/cgroup/memory.max','/sys/fs/cgroup/memory.events'])}
  rec['status']='PRESERVATION_COMPLETE_PENDING_SEPARATE_ROOT_DELETE_AUTHORITY';save();print(json.dumps({'manifest':str(P),'sha256':sha(P),'status':rec['status']}))
 except Exception as e:
  rec['status']='STOPPED_FIRST_ERROR_NO_RETRY';rec['first_error_type']=type(e).__name__;rec['first_error']='Subprocess argv withheld' if isinstance(e,subprocess.SubprocessError) else str(e);save();raise RuntimeError(rec['first_error']) from None
if __name__=='__main__':main()
