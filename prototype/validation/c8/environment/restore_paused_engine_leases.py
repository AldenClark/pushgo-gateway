"""Root-authorized final C8 lease restoration: inspect/quiet then PAUSE only."""
import pathlib,importlib.util,os,json,hashlib,datetime
R=pathlib.Path(__file__).resolve().parent;os.umask(0o077);P=R/'final-paused-quiet-receipt.json';assert not P.exists();spec=importlib.util.spec_from_file_location('c8',R/'isolated_db.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def state(i):return {k:i['State'].get(k) for k in ['Status','Running','Paused','ExitCode']}
def hostfree():
 f=os.statvfs(str(R));return f.f_bavail*f.f_frsize
r={'status':'STARTED','timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':str(pathlib.Path(__file__).resolve()),'source_sha256':sha(__file__),'helper_sha256':sha(R/'isolated_db.py'),'scope':'Final root all-runtime-QUIET: restore exact two leased C7-owned engines to PAUSED, retain C7/C8 historical/new/failed cases and volume/tmpfs/refs; no STOP/DROP/reset/delete/SQLcleanup/unpause','resources':{},'minimum_host_bytes':4294967296,'host_available_before':hostfree(),'root_runtime_quiet_authority':'All C8 gateway/default/TLS/4aggregates/Android13/Windows20/capacity4lanes finished with captured PIDs quiet; no further DB workloads authorized'}
def save():m.save(P,r)
save()
try:
 captured={}
 for engine in ['pg','mysql']:
  s,i=m.owned(engine);expected_id,expected_owner=m.EXPECTED[engine];assert (s['id'],s['owner'])==(expected_id,expected_owner);assert i['Name']=='/pushgo-c7-isolated-'+engine+'-'+expected_owner
  refs=[]
  for db,c in s['cases'].items():
   ref=pathlib.Path(c['url_file']);refs.append({'database':db,'label':c['label'],'url_file':str(ref),'exists':ref.exists(),'mode':oct(ref.stat().st_mode&0o777) if ref.exists() else None,'URL_file_sha256':sha(ref) if ref.exists() else None})
   assert ref.exists() and ref.stat().st_mode&0o777==0o600
  r['resources'][engine]={'id':s['id'],'owner_uuid':s['owner'],'case_registry_owner':s['case_registry_owner'],'name':i['Name'],'label_key':m.KEY,'before':state(i),'case_inventory_current':refs,'canonical_state':str(m.state(engine)),'canonical_state_sha256':sha(m.state(engine)),'engine_authority_source':s['engine_authority_source'],'engine_authority_sha256':s['engine_authority_sha256'],'mounts':i['Mounts']};captured[engine]=(s,i);save()
  if engine=='mysql':
   v=json.loads(m.run(['volume','inspect',s['volume_name']]))[0];assert v['Labels'][m.KEY]==s['owner'];r['resources'][engine]['volume_identity']={'name':v['Name'],'owner_uuid':v['Labels'][m.KEY],'mountpoint':v['Mountpoint'],'driver':v['Driver']}
 # Inspect system connection catalogs only; no business-table queries or SQL mutation.
 checks={}
 for engine,(s,i) in captured.items():
  if i['State']['Running'] and not i['State']['Paused']:
   if engine=='pg':
    checks['pg_other_clients']=m.sql('pg',"SELECT pid,datname,usename,state FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid();");checks['pg_prepared']=m.sql('pg','SELECT transaction,gid,database FROM pg_prepared_xacts;')
   else:
    checks['mysql_other_clients']=m.sql('mysql',"SELECT THREAD_ID,PROCESSLIST_ID,COALESCE(PROCESSLIST_USER,''),COALESCE(PROCESSLIST_DB,''),PROCESSLIST_COMMAND FROM performance_schema.threads WHERE TYPE='FOREGROUND' AND PROCESSLIST_ID<>CONNECTION_ID() AND PROCESSLIST_COMMAND<>'Daemon';");checks['mysql_transactions']=m.sql('mysql','SELECT trx_id,trx_mysql_thread_id,trx_state FROM information_schema.innodb_trx;');checks['mysql_user_locks']=m.sql('mysql',"SELECT OWNER_THREAD_ID,LOCK_STATUS FROM performance_schema.metadata_locks WHERE OBJECT_TYPE='USER LEVEL LOCK';")
  else:checks[engine+'_not_queried']='Already paused or non-running; do not restart/unpause'
 r['connection_checks']=checks;save();assert all(not v for k,v in checks.items() if not k.endswith('_not_queried')),'Other application/transaction owner detected; stop without pause'
 # Persist pre-pause OS evidence while exec is still available; no subsequent exec into paused containers.
 for engine,(s,i) in captured.items():
  if i['State']['Running'] and not i['State']['Paused']:
   directory='/var/lib/postgresql/data' if engine=='pg' else '/var/lib/mysql';raw=m.run(['exec',s['id'],'df','-k',directory]);r['resources'][engine]['pre_pause_df']=raw;r['resources'][engine]['available_bytes']=int(raw.splitlines()[-1].split()[3])*1024
 save()
 for engine,(s,i) in captured.items():
  e=r['resources'][engine]
  if i['State']['Running'] and not i['State']['Paused']:m.run(['pause',s['id']]);e['pause_invoked_once']=True
  else:e['pause_invoked_once']=False
  after,ii=m.owned(engine);e['after']=state(ii)
  if i['State']['Running']:assert ii['State']['Running'] and ii['State']['Paused']
  assert sha(m.state(engine))==e['canonical_state_sha256'];assert sha(s['engine_authority_source'])==e['engine_authority_sha256'];save()
 r['manifest_sha256']=sha(R/'active-case-manifest.json');r['identity_sha256']=sha(R/'environment-identity.json');r['host_available_after']=hostfree();r['host4GiB_guard_pass_after']=r['host_available_after']>=r['minimum_host_bytes'];r['mysql4GiB_guard_pass_last_observation']=r['resources']['mysql'].get('available_bytes',0)>=4294967296;r['refs_and_state_modified']=False;r['restore_result']='Both exact original C7-owned engines restored to PAUSED; PostgreSQL tmpfs and MySQL named volume retained';r['future_authority']='No automatic unpause. User/root must explicitly approve maintenance or workload after identity and fresh budget review.';r['status']='FINAL_LEASES_PAUSED_ALL_CAPTURED_REFS_DATA_RETAINED_NO_FURTHER_IO';save();print(json.dumps({'receipt':str(P),'sha256':sha(P),'status':r['status'],'states':{k:v['after'] for k,v in r['resources'].items()},'host_available_after':r['host_available_after'],'mysql_available_last':r['resources']['mysql'].get('available_bytes')}))
except Exception as e:
 r['status']='STOPPED_FIRST_ERROR_RETAIN_PARTIAL_ACTUAL_STATE_NO_RETRY';r['first_error_type']=type(e).__name__;r['first_error']=str(e);save();raise RuntimeError(r['first_error']) from None
