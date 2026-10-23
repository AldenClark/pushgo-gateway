"""Explicitly authorized post-final read-only bounded observation. No mutation."""
import pathlib,importlib.util,os,subprocess,json,datetime,hashlib
R=pathlib.Path(__file__).resolve().parent;os.umask(0o077)
P=R/'sqlfix-final-postquiet-readonly.json';assert not P.exists()
def module(n,p):
 sp=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
m=module('disk3',R/'isolated_db.py');s,i=m.owned('mysql')
assert s['id']=='c24a4150e4f3f3e61af1445535b24a9ab1b7c16355b1f4162ae7d17152e67f81' and s['owner']=='829bc0ad72204aff99718fc3073c1752'
d={'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'container_id':s['id'],'owner':s['owner'],'volume_name':s['volume_name'],'storage_mount':[v for v in i['Mounts'] if v['Destination']=='/var/lib/mysql'],'budget_receipt':str(R/'budget-sqlfix_after_quiet-acf4f120.json'),'status':'STARTED','scope':'Readonly no PG reset/workload/DDL/FLUSH/PURGE/export'}
def save():m.save(P,d)
def query(sql):
 p=subprocess.run(m.D+['exec','-i','-e','MYSQL_PWD',s['id'],'timeout','--kill-after=1s','5s','mysql','--batch','--raw','--skip-column-names','-uroot'],input=sql,text=True,capture_output=True,timeout=7,env=dict(os.environ,MYSQL_PWD=s['root_password']))
 if p.returncode:raise RuntimeError('Bounded SQL failed; no retries/argv recorded')
 return p.stdout.strip()
def counts(db):
 assert db in s['cases']
 names=query("SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA='"+db+"' AND TABLE_TYPE='BASE TABLE';").splitlines()
 assert all(n.replace('_','').isalnum() for n in names)
 return {n:int(query('SELECT COUNT(*) FROM `'+db+'`.`'+n+'`;')) for n in names}
save()
try:
 d['mysql_clients']=query("SELECT THREAD_ID,PROCESSLIST_ID,PROCESSLIST_COMMAND FROM performance_schema.threads WHERE TYPE='FOREGROUND' AND PROCESSLIST_ID<>CONNECTION_ID() AND PROCESSLIST_COMMAND<>'Daemon';")
 d['transactions']=query('SELECT trx_id,trx_mysql_thread_id,trx_state FROM information_schema.innodb_trx;');d['data_locks']=query('SELECT COUNT(*) FROM performance_schema.data_locks;');d['advisory_locks']=query("SELECT OWNER_THREAD_ID,LOCK_STATUS FROM performance_schema.metadata_locks WHERE OBJECT_TYPE='USER LEVEL LOCK';")
 pg=module('pg',R.parent/'isolated_db.py');ps,pi=pg.owned('pg');assert ps['id']=='008ea1804e16ad16c691108dfa874f2f5300499397c9aa24d2b9f5cf8f4377be'
 p=subprocess.run(pg.D+['exec','-i',ps['id'],'timeout','-k','1','5','psql','-X','-v','ON_ERROR_STOP=1','-At','-U',ps['admin_user'],'-d',ps['database']],input="SELECT pid,datname,state FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid();SELECT transaction,gid FROM pg_prepared_xacts;",text=True,capture_output=True,timeout=7)
 assert p.returncode==0;d['pg_other_clients_or_prepared']=p.stdout.strip()
 assert not any(d[k] for k in ['mysql_clients','transactions','advisory_locks','pg_other_clients_or_prepared']) and d['data_locks']=='0'
 d['config']=query('SELECT @@server_uuid,@@server_id,@@log_bin,@@innodb_flush_log_at_trx_commit,@@sync_binlog,@@log_bin_trust_function_creators,@@innodb_buffer_pool_size,@@innodb_redo_log_capacity,@@max_connections;')
 d['binary_logs']=query('SHOW BINARY LOGS;');d['binary_log_status']=query('SHOW BINARY LOG STATUS;');d['replicas']=query('SHOW REPLICAS;');d['replication_channels']=query('SELECT CHANNEL_NAME,SERVICE_STATE FROM performance_schema.replication_connection_status;')
 dbs=['c5_synthetic_905496a1afce4f41af24ef531a57228e','c5_synthetic_e7f57b4c7634411886a103112a8709a6','c5_synthetic_e85f72f8909f49ed850f889b92c115b8']
 d['counts_before']={db:counts(db) for db in dbs};d['counts_after']={db:counts(db) for db in dbs};assert d['counts_before']==d['counts_after'];d['stable_counts']=True
 d['status']='READONLY_COMPLETE_PENDING_ROOT_ARCHIVE_AUTHORIZATION';save();print(json.dumps({'receipt':str(P),'sha256':hashlib.sha256(P.read_bytes()).hexdigest(),'config':d['config'],'binary_logs':d['binary_logs'],'binary_log_status':d['binary_log_status'],'counts':d['counts_after'],'quiet':True}))
except Exception as e:
 d['status']='STOPPED_FIRST_ERROR';d['first_error_type']=type(e).__name__;save();raise RuntimeError('Readonly observation stopped; inspect receipt') from None
