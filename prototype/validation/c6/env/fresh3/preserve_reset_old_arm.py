import pathlib,importlib.util,json,datetime,os,hashlib,time,subprocess
R=pathlib.Path(__file__).resolve().parent;P=R.parent;os.umask(0o077)
sp=importlib.util.spec_from_file_location('my',R/'isolated_db.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);s,_=m.owned('mysql')
def query(q):
 return m.run(['exec','-i','-e','MYSQL_PWD',s['id'],'mysql','--batch','--raw','--skip-column-names','-uroot'],q,environment=dict(os.environ,MYSQL_PWD=s['root_password']))
def save(p,obj):m.save(p,obj)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
# Read server-native types, whitelisting numeric summary counters plus schema and digest hash.
cols=[];types={}
for line in query('SHOW COLUMNS FROM performance_schema.events_statements_summary_by_digest;').splitlines():
 pieces=line.split('\t');types[pieces[0]]=pieces[1]
for name,typ in types.items():
 if name in ['SCHEMA_NAME','DIGEST'] or any(typ.lower().startswith(prefix) for prefix in ['bigint','int','decimal','double','float']):cols.append(name)
assert 'DIGEST_TEXT' not in cols and 'QUERY_SAMPLE_TEXT' not in cols
assert len(cols)<100
business=query("SELECT THREAD_ID,PROCESSLIST_ID,COALESCE(PROCESSLIST_USER,''),COALESCE(PROCESSLIST_DB,''),PROCESSLIST_COMMAND FROM performance_schema.threads WHERE TYPE='FOREGROUND' AND PROCESSLIST_ID<>CONNECTION_ID() AND PROCESSLIST_COMMAND<>'Daemon';")
if business:raise RuntimeError('Business client detected; refuse reset')
# Cross-instance quiet gate is read-only; PG statistics are not reset.
spg=importlib.util.spec_from_file_location('pgquiet',R.parent/'isolated_db.py');pg=importlib.util.module_from_spec(spg);spg.loader.exec_module(pg)
quiet={'mysql_other_clients':business,'mysql_innodb_transactions':query('SELECT trx_id,trx_mysql_thread_id,trx_state FROM information_schema.innodb_trx;'),'mysql_data_locks':query('SELECT COUNT(*) FROM performance_schema.data_locks;'),'mysql_advisory_locks':query("SELECT OWNER_THREAD_ID,LOCK_STATUS FROM performance_schema.metadata_locks WHERE OBJECT_TYPE='USER LEVEL LOCK';"),'pg_other_clients':pg.sql('pg',"SELECT pid,datname,usename,COALESCE(state,'') FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid();"),'pg_prepared_transactions':pg.sql('pg','SELECT transaction,gid,prepared,owner,database FROM pg_prepared_xacts;')}
assert all(not v for k,v in quiet.items() if k!='mysql_data_locks') and quiet['mysql_data_locks']=='0'
quiet['docker_inventory']=m.run(['ps','-a','--no-trunc','--format','{{json .}}']).splitlines()
quiet['host_process_snapshot']=subprocess.run(['ps','-axo','pid=,ppid=,%cpu=,%mem=,comm='],capture_output=True,text=True).stdout
save(R/'disk3-before-old-quiet.json',{'timestamp_utc':utc(),'quiet':quiet,'scope':'Read-only cross-instance observation only; PG hold/no reset; no business workload'})
identity=json.loads(query("SELECT JSON_OBJECT('server_uuid',@@server_uuid,'server_id',@@server_id,'digest_limit',@@performance_schema_digests_size,'P_S',@@performance_schema,'trust',@@log_bin_trust_function_creators,'log_bin',@@log_bin,'flush',@@innodb_flush_log_at_trx_commit,'sync_binlog',@@sync_binlog);"))
args=','.join("'"+c+"',`"+c+'`' for c in cols)
raw=query('SELECT JSON_OBJECT('+args+') FROM performance_schema.events_statements_summary_by_digest;')
rows=[json.loads(line) for line in raw.splitlines() if line];assert len(rows)<=1000
before={'timestamp_utc':utc(),'container_id':s['id'],'owner_uuid':s['owner'],'server_identity':identity,'counter_columns':cols,'row_count':len(rows),'max_entries':1000,'null_digest_rows':sum(x['DIGEST'] is None for x in rows),'rows':rows,'digest_lost':query("SHOW GLOBAL STATUS LIKE 'Performance_schema_digest_lost';"),'global_row_lock_counters':query("SHOW GLOBAL STATUS LIKE 'Innodb_row_lock%';").splitlines(),'business_connections_except_observer':business,'excluded_fields':['DIGEST_TEXT','QUERY_SAMPLE_TEXT','SQL_TEXT','bound_parameters'],'historical_precheck':'Fresh3 new disk-backed instance startup/metadata counters before first old arm; no business result reclassification.'}
B=R/'disk3-mysql-old-digest-before-reset.json'
if B.exists():raise RuntimeError('Preservation receipt exists; refuse repeat reset')
save(B,before)
receipt={'timestamp_utc':utc(),'cross_instance_quiet_receipt':str(R/'disk3-before-old-quiet.json'),'storage_medium':'disk-backed-named-volume','environment_namespace':'C6/fresh3/disk3','authorization':'Root per-arm quiet→preserve→digest-only reset→preflight. Fresh3 disk-backed first formal old arm only; no workload start authorization.','before_snapshot':str(B),'before_sha256':sha(B),'reset_statement':'TRUNCATE TABLE performance_schema.events_statements_summary_by_digest','before_digest_rows':len(rows),'before_lost':before['digest_lost'],'server_identity':identity,'business_tables_or_configuration_or_log_changed':False,'business_failure_reclassification':False}
query(receipt['reset_statement']+';');receipt['reset_succeeded']=True;receipt['postreset_timestamp_utc']=utc();receipt['after_digest_entry_count_at_observation']=query('SELECT COUNT(*) FROM performance_schema.events_statements_summary_by_digest;');receipt['after_digest_lost_cumulative']=query("SHOW GLOBAL STATUS LIKE 'Performance_schema_digest_lost';");receipt['global_row_lock_counters_after']=query("SHOW GLOBAL STATUS LIKE 'Innodb_row_lock%';").splitlines();receipt['counter_semantics']='Digest counters reset only; lost and row-lock global counters are cumulative and are not assumed reset. Read-only preflight statements themselves may create digest rows after reset; preserve per-arm baseline then afterdelta/loss delta. Do not infer lost=0 from reset.'
receipt['postreset_nonnull_schema_digest_rows']=query('SELECT COUNT(*) FROM performance_schema.events_statements_summary_by_digest WHERE SCHEMA_NAME IS NOT NULL;')
receipt['global_row_lock_counters_unchanged_by_reset']=before['global_row_lock_counters']==receipt['global_row_lock_counters_after']
receipt['after_count_explanation']='Total observer/reset digests may be nonzero immediately; business-schema rows recorded independently. No instrumentation disabling or repeated reset to manufacture zero.'
save(R/'disk3-mysql-old-digest-reset-receipt.json',receipt)
print(json.dumps({k:v for k,v in receipt.items() if k not in ['server_identity','global_row_lock_counters_after']},indent=2))
