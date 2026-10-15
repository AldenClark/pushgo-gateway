"""C9 SOURCE ONLY: explicit runtime-window snapshot; no lifecycle/data mutation.
Host Gateway/harness CPU+RSS, mysqld RSS, cgroup CPU+memory are distinct metrics.
Cumulative deltas require matched before/after; do not add unlike CPU percentages.
"""
import argparse,pathlib,os,subprocess,datetime,json,hashlib,importlib.util,re,time
R=pathlib.Path(__file__).resolve().parent

def main():
 p=argparse.ArgumentParser();p.add_argument('--root-runtime-snapshot-approved',action='store_true');p.add_argument('--phase',required=True);p.add_argument('--case-db',required=True);p.add_argument('--gateway-pid',type=int);p.add_argument('--gateway-binary',type=pathlib.Path);p.add_argument('--gateway-binary-sha256');p.add_argument('--harness-pid',type=int);a=p.parse_args()
 if not a.root_runtime_snapshot_approved:raise SystemExit('No operations: explicit C9 runtime window required')
 assert re.fullmatch('[a-z][a-z0-9_]{0,40}',a.phase);os.umask(0o077);O=R/'snapshots';O.mkdir(exist_ok=True);P=O/(a.phase+'.json');assert not P.exists()
 spec=importlib.util.spec_from_file_location('c9',R/'isolated_db.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 rec={'status':'STARTED','timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'phase':a.phase,'source_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'case_db':a.case_db,'query_text_or_bindings_collected':False,'scope':'C9 newcase-scoped metadata + separate resource components; no DDL/reset/FLUSH/PURGE/cleanup; observer cost explicit'}
 def save():m.save(P,rec)
 def proc(pid):
  if pid is None:return {'provided':False,'meaning':'Not sampled; not an assertion of zero usage'}
  assert pid>1
  v=subprocess.run(['ps','-p',str(pid),'-o','pid=,ppid=,rss=,time=,%cpu=,comm='],capture_output=True,text=True,timeout=5);assert v.returncode==0 and v.stdout.strip();return {'provided':True,'pid':pid,'raw_ps_pid_ppid_rssKiB_cumulativeCPUtime_percentCPU_comm':v.stdout.strip(),'metrics':'RSS KiB; cumulative CPU time for before/after deltas; %CPU is host ps averaging, not synchronized with Docker CPU'}
 save();start=time.monotonic()
 try:
  s,i=m.owned('mysql');assert i['State']['Running'] and not i['State']['Paused'],'Paused engine: refuse exec/SQL; root must authorize unpause separately';assert a.case_db in s['cases'];assert s['cases'][a.case_db]['url_file'].startswith(str(R)+'/');rec['engine']={'id':s['id'],'owner_uuid':s['owner'],'case_registry_owner':s['case_registry_owner'],'volume_name':s['volume_name'],'authority_source':s['engine_authority_source'],'authority_sha256':s['engine_authority_sha256']}
  if a.gateway_pid:
   assert a.gateway_binary and a.gateway_binary_sha256 and hashlib.sha256(a.gateway_binary.read_bytes()).hexdigest()==a.gateway_binary_sha256
   rec['gateway_binary']={'file':str(a.gateway_binary),'sha256':a.gateway_binary_sha256,'binding_limit':'PID supplied by root-owned spawn receipt; ps comm captured, no arbitrary command argv/credentials collected'}
  rec['resources']={'gateway_host_process':proc(a.gateway_pid),'harness_host_process':proc(a.harness_pid),'snapshot_observer_host_process':proc(os.getpid())};rec['resources']['database_container']={'cpu_stat_cumulative_usec':m.run(['exec',s['id'],'cat','/sys/fs/cgroup/cpu.stat']),'memory_current_bytes':m.run(['exec',s['id'],'cat','/sys/fs/cgroup/memory.current']),'memory_stat_cache_breakdown':m.run(['exec',s['id'],'cat','/sys/fs/cgroup/memory.stat']),'memory_events':m.run(['exec',s['id'],'cat','/sys/fs/cgroup/memory.events']),'mysqld_pid1_status':m.run(['exec',s['id'],'cat','/proc/1/status']),'resource_limits':{k:i['HostConfig'][k] for k in ['NanoCpus','Memory','MemorySwap','PidsLimit']},'semantics':'mysqld VmRSS KiB differs from cgroup memory.current including cache; CPU usage_usec cumulative deltas include small exec observers. Do not attribute DB/cache memory to Gateway RSS.'};save()
  rec['configuration']=m.sql('mysql','SELECT VERSION(),@@server_uuid,@@log_bin,@@innodb_flush_log_at_trx_commit,@@sync_binlog,@@innodb_buffer_pool_size,@@innodb_redo_log_capacity,@@performance_schema,@@performance_schema_digests_size;');rec['engine_global_numeric_baseline_cumulative']=m.sql('mysql',"SHOW GLOBAL STATUS WHERE Variable_name IN ('Threads_connected','Threads_running','Com_commit','Com_rollback','Questions','Queries','Innodb_rows_read','Innodb_rows_inserted','Innodb_rows_updated','Innodb_rows_deleted','Innodb_buffer_pool_read_requests','Innodb_buffer_pool_reads','Innodb_data_reads','Innodb_data_writes','Innodb_os_log_written','Performance_schema_digest_lost');")
  cols=['SCHEMA_NAME','DIGEST','COUNT_STAR','SUM_TIMER_WAIT','SUM_LOCK_TIME','SUM_ROWS_AFFECTED','SUM_ROWS_SENT','SUM_ROWS_EXAMINED','SUM_CREATED_TMP_TABLES','SUM_CREATED_TMP_DISK_TABLES','SUM_SELECT_SCAN','SUM_NO_INDEX_USED'];rec['new_case_digest_numeric']=[json.loads(line) for line in m.sql('mysql','SELECT JSON_OBJECT('+','.join("'"+c+"',`"+c+'`' for c in cols)+") FROM performance_schema.events_statements_summary_by_digest WHERE SCHEMA_NAME='"+a.case_db+"' LIMIT 1000;").splitlines()];rec['digest_loss_note']='Cumulative digest lost is preserved, never reset here. Full/dropped instrumentation must be reported; missing digest rows do not prove no DB work.'
  f=os.statvfs(str(R));rec['host_available_bytes']=f.f_bavail*f.f_frsize;rec['observer_elapsed_seconds']=time.monotonic()-start;rec['status']='READONLY_COMPONENT_METADATA_CAPTURED_NO_WORKLOAD_RESULT';save();print(json.dumps({'receipt':str(P),'sha256':hashlib.sha256(P.read_bytes()).hexdigest(),'status':rec['status']}))
 except Exception as e:
  rec['status']='STOPPED_FIRST_ERROR_NO_RETRY';rec['first_error_type']=type(e).__name__;rec['first_error']='Subprocess args withheld' if isinstance(e,subprocess.SubprocessError) else str(e);save();raise RuntimeError(rec['first_error']) from None
if __name__=='__main__':main()
