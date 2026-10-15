"""Source-prepared only. Root's Provider-QUIET phase1 slot required. NEVER PURGE/DROP."""
import argparse,datetime,fcntl,gzip,hashlib,importlib.util,json,os,pathlib,re,subprocess,time
R=pathlib.Path(__file__).resolve().parent
MIN_HOST=4294967296
EXPECTED_ID='c24a4150e4f3f3e61af1445535b24a9ab1b7c16355b1f4162ae7d17152e67f81'
EXPECTED_OWNER='829bc0ad72204aff99718fc3073c1752'
FAILED={'capacity_sqlfix_final':'c5_synthetic_e85f72f8909f49ed850f889b92c115b8'}

def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  while True:
   block=f.read(1024*1024)
   if not block:return h.hexdigest()
   h.update(block)
def main():
 p=argparse.ArgumentParser();p.add_argument('--root-provider-quiet-approved',action='store_true');a=p.parse_args()
 if not a.root_provider_quiet_approved:raise RuntimeError('Root Provider-QUIET approval required; no database or Docker call performed')
 os.umask(0o077);O=R/'sqlfix-9fc-phase1-archive';O.mkdir(exist_ok=False);P=O/'manifest.json';record={'timestamp_utc':now(),'scope':'Root phase1 only: preserve 9fc exact failed-result DB tables via logical dumps, once native FLUSH, archive exact closed binlogs; no DROP/PURGE/RESET/config/resource/business changes','root_provider_quiet_approved':True,'failed_databases':FAILED,'logical_exports':[],'closed_binlog_archives':[],'purge_executed':False,'old_raw_failures_modified':False}
 def save():P.write_text(json.dumps(record,indent=2)+'\n')
 def host_guard():
  fs=os.statvfs(str(O));available=fs.f_bavail*fs.f_frsize
  if available<MIN_HOST:raise RuntimeError('Host available below4GiB; preserve partial evidence and stop without retry/purge')
  return available
 def call(args,stdin=None,env=None,deadline=10):
  try:result=subprocess.run(m.D+args,input=stdin,text=True,capture_output=True,env=env,timeout=deadline)
  except subprocess.SubprocessError:raise RuntimeError('Native operation timed out; command arguments withheld') from None
  if result.returncode:raise RuntimeError('Native operation failed exit'+str(result.returncode)+': '+result.stderr.strip())
  return result.stdout.strip()
 def sql(query):return call(['exec','-i','-e','MYSQL_PWD',s['id'],'timeout','--kill-after=1s','5s','mysql','--batch','--raw','--skip-column-names','-uroot'],query,dict(os.environ,MYSQL_PWD=s['root_password']),7)
 def os_snapshot(label):
  snapshot={'timestamp_utc':now(),'host_available_bytes':host_guard(),'df_bytes':call(['exec',s['id'],'df','-B1','-T','/var/lib/mysql']),'inodes_raw':call(['exec',s['id'],'df','-i','/var/lib/mysql']),'cgroup':call(['exec',s['id'],'cat','/sys/fs/cgroup/memory.current','/sys/fs/cgroup/memory.max','/sys/fs/cgroup/memory.events'])};record[label]=snapshot;save();return snapshot
 def quiet():
  checks={'clients':sql("SELECT THREAD_ID,PROCESSLIST_ID,PROCESSLIST_COMMAND,COALESCE(PROCESSLIST_STATE,'') FROM performance_schema.threads WHERE TYPE='FOREGROUND' AND PROCESSLIST_ID<>CONNECTION_ID() AND PROCESSLIST_COMMAND<>'Daemon';"),'transactions':sql('SELECT trx_id,trx_mysql_thread_id,trx_state FROM information_schema.innodb_trx;'),'data_locks':sql('SELECT COUNT(*) FROM performance_schema.data_locks;'),'user_locks':sql("SELECT OWNER_THREAD_ID,LOCK_STATUS FROM performance_schema.metadata_locks WHERE OBJECT_TYPE='USER LEVEL LOCK';"),'replica':sql('SHOW REPLICA STATUS;'),'replication_channels':sql('SELECT CHANNEL_NAME,SERVICE_STATE FROM performance_schema.replication_connection_status;'),'replication_appliers':sql('SELECT CHANNEL_NAME,SERVICE_STATE FROM performance_schema.replication_applier_status;')}
  if any(v for k,v in checks.items() if k!='data_locks') or checks['data_locks']!='0':raise RuntimeError('Quiet/replication gate failed; stop before heavy archive or rotation')
  return checks
 def stream_gzip(args,dest,stderr,environment=None,deadline_seconds=5):
  host_before=host_guard();start=time.monotonic();h=hashlib.sha256();count=0;process=None
  try:
   with stderr.open('xb') as err:
    process=subprocess.Popen(m.D+args,stdout=subprocess.PIPE,stderr=err,env=environment)
    with dest.open('xb') as output:
     with gzip.GzipFile(fileobj=output,mode='wb',compresslevel=1,mtime=0) as gz:
      while True:
       host_guard()
       if time.monotonic()-start>deadline_seconds:raise RuntimeError('Stream deadline reached; preserve partial artifact, no retry')
       chunk=process.stdout.read(1024*1024)
       if not chunk:break
       gz.write(chunk);h.update(chunk);count+=len(chunk);host_guard()
    code=process.wait(timeout=1)
   if code:raise RuntimeError('Stream source failed exit'+str(code)+'; preserve stderr and partial file')
   if time.monotonic()-start>deadline_seconds:raise RuntimeError('Stream completed beyond approved deadline; retain but do not accept')
   return {'file':str(dest),'stderr_file':str(stderr),'compressed_bytes':dest.stat().st_size,'compressed_sha256':digest(dest),'stream_uncompressed_bytes':count,'stream_uncompressed_sha256':h.hexdigest(),'mode':oct(dest.stat().st_mode&0o777),'elapsed_seconds':time.monotonic()-start,'host_available_before':host_before,'host_available_after':host_guard(),'source_exit_code':code}
  finally:
   if process:
    if process.stdout:process.stdout.close()
    try:process.wait(timeout=1)
    except subprocess.TimeoutExpired:
     process.terminate() # only local Docker CLI/OS stream producer; NEVER server SQL KILL
     try:process.wait(timeout=2)
     except subprocess.TimeoutExpired:process.kill();process.wait()
 def validate_gzip(path):
  h=hashlib.sha256();count=0
  with gzip.open(path,'rb') as inp:
   while True:
    block=inp.read(1024*1024)
    if not block:break
    h.update(block);count+=len(block)
  return {'crc_verified':True,'decompressed_sha256':h.hexdigest(),'decompressed_bytes':count}
 try:
  spec=importlib.util.spec_from_file_location('disk3',R/'isolated_db.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);s,i=m.owned('mysql');assert s['id']==EXPECTED_ID and s['owner']==EXPECTED_OWNER
  for label,db in FAILED.items():assert s['cases'][db]['label']==label
  record.update({'container_id':s['id'],'owner':s['owner'],'volume_name':s['volume_name'],'helper_state_sha256':digest(R/'mysql-owned.json'),'initial_inventory':{'container_name':i['Name'],'datadir_mount':[x for x in i['Mounts'] if x['Destination']=='/var/lib/mysql']}});save();os_snapshot('os_before_sql');df=record['os_before_sql']['df_bytes'].splitlines()[-1].split();assert int(df[4])>=MIN_HOST, 'Guest below4GiB before archive';record['quiet_before']=quiet();record['root_crossengine_quiet_authority']='Root explicit phase1 slot; PG hold/no calls';record['prior_crossengine_quiet_receipt_sha256']=digest(R/'sqlfix-final-postquiet-readonly.json');record['config_before']=sql('SELECT @@server_uuid,@@server_id,@@log_bin,@@innodb_flush_log_at_trx_commit,@@sync_binlog,@@log_bin_trust_function_creators,@@innodb_buffer_pool_size,@@innodb_redo_log_capacity,@@max_connections;');assert record['config_before']=='f6f8ca7a-c881-11f1-9b8f-727c29199193\t1\t1\t1\t1\t1\t67108864\t67108864\t60';save()
  for label,db in FAILED.items():
   tables=sql('SHOW TABLES FROM `'+db+'`;').splitlines()
   if not tables:raise RuntimeError('Expected retained failure schema missing; stop without replacing evidence')
   def counts():
    ans={}
    for table in tables:
     if not re.fullmatch('[a-z0-9_]+',table):raise RuntimeError('Unexpected table identifier')
     ans[table]=int(sql('SELECT COUNT(*) FROM `'+db+'`.`'+table+'`;'))
    return ans
   item={'label':label,'database':db,'counts_before':counts(),'logical_backup_limit':'Consistent logical single-transaction view while quiet, not physical crash backup; original failed results remain unchanged'};record['logical_exports'].append(item);save()
   args=['exec','-e','MYSQL_PWD',s['id'],'timeout','--kill-after=1s','5s','mysqldump','-uroot','--skip-lock-tables','--no-tablespaces','--single-transaction','--quick','--hex-blob','--skip-add-locks','--set-gtid-purged=OFF',db]
   exported=stream_gzip(args,O/(label+'.sql.gz'),O/(label+'-mysqldump-stderr.txt'),dict(os.environ,MYSQL_PWD=s['root_password']),5);item.update(exported);save();item['validation']=validate_gzip(pathlib.Path(exported['file']));assert item['validation']['decompressed_sha256']==exported['stream_uncompressed_sha256'] and item['validation']['decompressed_bytes']==exported['stream_uncompressed_bytes'];item['counts_after']=counts();assert item['counts_after']==item['counts_before'];item['counts_stable']=True;item['complete']=True;save()
  # Capture run/source/binary/raw binding hashes without copying or exposing content.
  base=R.parent.parent
  rels=['capacity/matched-disk3-pair/run-mysql-old/result.json','capacity/matched-disk3-pair/run-mysql-old/first-failure.json','capacity/matched-disk3-pair/run-mysql-final/result.json','capacity/matched-disk3-pair/run-mysql-final/first-failure.json']
  rels+=['capacity/final-9fc812b/run-mysql-final/result.json','capacity/final-9fc812b/run-mysql-final/first-failure.json']
  record['executed_source']={'path':str(pathlib.Path(__file__).resolve()),'sha256':digest(pathlib.Path(__file__).resolve())}
  record['raw_failure_bindings']={p:{'sha256':digest(base/p),'bytes':(base/p).stat().st_size} for p in rels if (base/p).exists()};record['quiet_before_rotation']=quiet();record['binlogs_before_rotation']=sql('SHOW BINARY LOGS;');record['status_before_rotation']=sql('SHOW BINARY LOG STATUS;');assert record['status_before_rotation'].split('\t')[0]=='binlog.000003';assert [x.split('\t')[0] for x in record['binlogs_before_rotation'].splitlines()]==['binlog.000003'];record['rotation_intent']={'statement':'FLUSH BINARY LOGS','max_invocations':1,'no_retry':True};save()
  sql('FLUSH BINARY LOGS;');record['rotation_succeeded']=True;record['rotation_completed_utc']=now();save();record['status_after_rotation']=sql('SHOW BINARY LOG STATUS;');record['logs_after_rotation']=sql('SHOW BINARY LOGS;');current=record['status_after_rotation'].split('\t')[0];assert re.fullmatch(r'binlog\.[0-9]{6,}',current);assert current!=record['status_before_rotation'].split('\t')[0]
  inventory=[{'file':line.split('\t')[0],'bytes':int(line.split('\t')[1])} for line in record['logs_after_rotation'].splitlines()];closed=[row for row in inventory if row['file']!=current];record['new_current_to_keep']=current;record['actual_closed_inventory']=closed;save()
  for row in closed:
   name=row['file'];assert re.fullmatch(r'binlog\.[0-9]{6,}',name);source='/var/lib/mysql/'+name;native_before=call(['exec',s['id'],'timeout','5s','sha256sum',source],deadline=7).split()[0];size_before=int(call(['exec',s['id'],'stat','-c','%s',source]));assert size_before==row['bytes']
   item={'native_file_name':name,'native_source_path':source,'native_before_sha256':native_before,'source_bytes_before':size_before};record['closed_binlog_archives'].append(item);save();compressed=stream_gzip(['exec',s['id'],'timeout','--kill-after=1s','5s','cat',source],O/(name+'.gz'),O/(name+'-stream-stderr.txt'),deadline_seconds=5);item.update(compressed);save();item['validation']=validate_gzip(pathlib.Path(compressed['file']));after_sha=call(['exec',s['id'],'timeout','5s','sha256sum',source],deadline=7).split()[0];after_size=int(call(['exec',s['id'],'stat','-c','%s',source]));assert native_before==compressed['stream_uncompressed_sha256']==item['validation']['decompressed_sha256']==after_sha;assert size_before==compressed['stream_uncompressed_bytes']==item['validation']['decompressed_bytes']==after_size;item['native_after_sha256']=after_sha;item['source_bytes_after']=after_size;item['stable_verified']=True;item['complete']=True;save()
  record['final_current']=sql('SHOW BINARY LOG STATUS;');assert record['final_current'].split('\t')[0]==current;record['quiet_after_archive']=quiet();record['config_after']=sql('SELECT @@server_uuid,@@server_id,@@log_bin,@@innodb_flush_log_at_trx_commit,@@sync_binlog,@@log_bin_trust_function_creators,@@innodb_buffer_pool_size,@@innodb_redo_log_capacity,@@max_connections;');assert record['config_after']==record['config_before'];os_snapshot('os_after_archive');record['purge_proposal_not_executed']={'exact_exclusive_to':current,'closed_files':[x['file'] for x in closed],'new_current_and_later_must_remain':True,'requires_root_read_complete_archive_then_separate_approval':True};record['failed_tables_dropped']=False;record['status']='PHASE1_COMPLETE_PENDING_ROOT_PURGE_REVIEW';save();print(json.dumps({'receipt':str(P),'status':record['status'],'current':current,'closed_archives':[{'file':x['native_file_name'],'source_bytes':x['source_bytes_before'],'compressed_bytes':x['compressed_bytes'],'sha256':x['native_before_sha256'],'complete':x['complete']} for x in record['closed_binlog_archives']],'after_budget':record['os_after_archive']},indent=2))
 except Exception as error:
  record['status']='STOPPED_PRESERVE_FIRST_ERROR_NO_PURGE';record['first_error_type']=type(error).__name__;record['first_error']='Subprocess command arguments withheld' if isinstance(error,subprocess.SubprocessError) else str(error);save();raise RuntimeError(record['first_error']) from None
if __name__=='__main__':main()
