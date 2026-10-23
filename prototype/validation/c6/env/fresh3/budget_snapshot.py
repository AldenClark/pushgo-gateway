"""DRAFT disk3 OS-first budget. No calls at import; requires approved actual owned state."""
import pathlib,importlib.util,json,datetime,sys,os,re,uuid,subprocess
R=pathlib.Path(__file__).resolve().parent

def main():
 label=sys.argv[1] if len(sys.argv)==2 else '';assert re.fullmatch('[a-z][a-z0-9_]{0,40}',label);os.umask(0o077)
 sp=importlib.util.spec_from_file_location('disk3',R/'isolated_db.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);s,i=m.owned('mysql');v=json.loads(m.run(['volume','inspect',s['volume_name']]))[0];sv=os.statvfs(str(R));path=R/('budget-'+label+'-'+uuid.uuid4().hex[:8]+'.json')
 r={'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'label':label,'container_id':s['id'],'owner_uuid':s['owner'],'storage_medium':'disk-backed-named-volume','volume_name':v['Name'],'volume_driver':v['Driver'],'volume_owner_label_key':m.KEY,'volume_owner_label_value':v['Labels'][m.KEY],'volume_mountpoint':v['Mountpoint'],'container_datadir_mount':[x for x in i['Mounts'] if x['Destination']=='/var/lib/mysql'],'minimum_available_bytes':4294967296,'host_available_bytes':sv.f_bavail*sv.f_frsize,'host_available_inodes':sv.f_favail,'host_backing_path':str(R),'case_allocation':s['cases'],'os_observations':{},'sql_inventory':{'status':'NOT_ATTEMPTED'},'scope':'Persist OS evidence before bounded SQL. No automatic purge/drop/reset/resize; no business load authorization.'}
 def save():m.save(path,r)
 save()
 try:
  for key,args in [('datadir_df_bytes',['df','-B1','-T','/var/lib/mysql']),('datadir_inodes',['df','-i','/var/lib/mysql']),('filesystem_type',['stat','-f','-c','%T','/var/lib/mysql']),('cgroup_memory',['cat','/sys/fs/cgroup/memory.current','/sys/fs/cgroup/memory.max','/sys/fs/cgroup/memory.events']),('pids',['cat','/sys/fs/cgroup/pids.current','/sys/fs/cgroup/pids.max'])]:
   p=subprocess.run(m.D+['exec',s['id']]+args,capture_output=True,text=True,timeout=5);r['os_observations'][key]={'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr};save()
   if p.returncode:raise RuntimeError('OS metadata observation failed: '+key)
  r['available_bytes']=int(r['os_observations']['datadir_df_bytes']['stdout'].splitlines()[-1].split()[4]);r['guard_effective_available_bytes']=min(r['available_bytes'],r['host_available_bytes']);r['guard_pass']=r['guard_effective_available_bytes']>=r['minimum_available_bytes'];r['os_snapshot_persisted_before_sql']=True;save()
  if not r['guard_pass']:r['status']='STOP_INSUFFICIENT4GIB';save();print(json.dumps({'receipt':str(path),'guard_pass':False,'effective_available_bytes':r['guard_effective_available_bytes']}));return
  args=m.D+['exec','-i','-e','MYSQL_PWD',s['id'],'timeout','--kill-after=1s','5s','mysql','--batch','--raw','--skip-column-names','-uroot'];p=subprocess.run(args,input='SHOW BINARY LOGS;SHOW BINARY LOG STATUS;SELECT @@server_uuid,@@server_id,@@log_bin,@@innodb_flush_log_at_trx_commit,@@sync_binlog,@@log_bin_trust_function_creators;',text=True,capture_output=True,timeout=7,env=dict(os.environ,MYSQL_PWD=s['root_password']));r['sql_inventory']={'status':'COMPLETE' if not p.returncode else 'FAILED_STOP_NO_RETRY','exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr};r['status']='BUDGET_READY' if p.returncode==0 else 'STOP_SQL_INVENTORY_FAILURE';save();print(json.dumps({'receipt':str(path),'storage_medium':r['storage_medium'],'volume_name':r['volume_name'],'available_bytes':r['available_bytes'],'host_available_bytes':r['host_available_bytes'],'guard_pass':r['guard_pass'],'status':r['status']}))
 except Exception as error:
  r['status']='STOPPED_PRESERVED_OS_FIRST';r['first_error_type']=type(error).__name__;r['first_error']='Subprocess arguments withheld' if isinstance(error,subprocess.SubprocessError) else str(error);save();raise RuntimeError(r['first_error']) from None
if __name__=='__main__':main()
