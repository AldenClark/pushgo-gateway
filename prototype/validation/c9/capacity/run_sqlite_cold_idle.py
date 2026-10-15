#!/usr/bin/env python3
"""One authorized1260s SQLite fixture cold idle. No HTTP/SQL observation or build."""
import argparse,fcntl,hashlib,json,os,pathlib,resource,signal,stat,subprocess,threading,time,uuid
NORMAL_SHA='b771b79a93b24025a037ca61c7056ea5a743ba52627a417dbee7f90d9d9efe44'
SAMPLER_SHA='9c8beee62657c85a5dc9bad4b5da2c450d3a0eb7534aa99d949a254eb03f257c'
SECONDS=1260

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,row):
 with p.open('x') as f:json.dump(row,f,indent=2);f.write('\n')
def admission(free):return free>=4294967296+67108864

def main(a):
 assert a.authorized_window=='root-c9-sqlite-cold-idle'
 assert sha(a.binary)==NORMAL_SHA and sha(a.sampler)==SAMPLER_SHA
 out=a.out.resolve();assert not out.exists();out.mkdir(parents=True)
 lease=(out/'owned-resource.lock').open('x');fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
 sv=os.statvfs(out);free=sv.f_bavail*sv.f_frsize
 save(out/'resource-admission.json',{'available_bytes':free,'floor_bytes':4294967296,'expected_growth_bytes':67108864,'guard_pass':admission(free),'growth_basis':'emptySQLite+startup schema/WAL+1260natural1HzfixtureSTATS+OSmetadata; conservative64MiB estimate; noformalinput','no_cache_deletion':True})
 assert admission(free),'RESOURCE_STOP'
 (out/'executed-run_sqlite_cold_idle.py').write_bytes(pathlib.Path(__file__).read_bytes())
 db=out/'c9-owned-empty.sqlite';assert not db.exists();owner=uuid.uuid4().hex
 save(out/'resource-lease.json',{'owner_uuid':owner,'driver_pid':os.getpid(),'sqlite_path':str(db),'lock':'exclusiveflockhelduntilownedprocessshutdown','normal_sha256':NORMAL_SHA,'sampler_sha256':SAMPLER_SHA,'input_HTTP_requests':0,'sql_observation_queries':0,'seconds':SECONDS})
 env={k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','C4_COMMIT','C5_COMMIT')) and k.lower() not in ('http_proxy','https_proxy','all_proxy','no_proxy','rust_log')}
 env.update(NO_PROXY='127.0.0.1,localhost',DUAL_ROUTE_TEST_AUTH='c9-synthetic-no-HTTP',C2_MOCK_SHARED_TOKEN='c9-synthetic-no-HTTP')
 command=[str(a.binary.resolve()),'--db-url','sqlite://'+str(db),'--http-addr','127.0.0.1:0','--mock-endpoint','http://127.0.0.1:9','--mock-token-service-endpoint','http://127.0.0.1:9','--shared-token-env','C2_MOCK_SHARED_TOKEN','--provider-budget','32','--claim-quantum','32']
 ready=threading.Event();stop=threading.Event();reader_error=[];child=None;thread=None;failure=None;start=time.monotonic();observations=0;sampler_elapsed=0;pid_start={};u0=resource.getrusage(resource.RUSAGE_SELF)
 def first(error):
  p=out/'first-failure.json'
  if not p.exists():save(p,{'error_class':type(error).__name__,'error':str(error),'elapsed_seconds':time.monotonic()-start,'no_retry':True})
 try:
  child=subprocess.Popen(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  def reader():
   try:
    with (out/'gateway.log').open('x') as f:
     for line in child.stdout:
      f.write(line);f.flush()
      if line.startswith('READY '):ready.set()
   except BaseException as e:reader_error.append(type(e).__name__)
  thread=threading.Thread(target=reader,daemon=True);thread.start();assert ready.wait(30),'fixture startup deadline'
  begin=time.monotonic();save(out/'idle-start.json',{'driver_monotonic':begin,'owned_gateway_pid':child.pid,'driver_pid':os.getpid(),'seconds':SECONDS,'HTTP_SQL_observer_calls':0})
  with (out/'os-samples.jsonl').open('x') as samples:
   tick=begin
   while time.monotonic()<begin+SECONDS:
    assert child.poll() is None,'ownedfixtureexitedduringidle'
    for label,pid in [('gateway',child.pid),('harness',os.getpid())]:
     before=time.monotonic();p=subprocess.run([str(a.sampler.resolve()),'--owned-pid',str(pid)],capture_output=True,text=True,timeout=5);elapsed=time.monotonic()-before;sampler_elapsed+=elapsed;assert p.returncode==0,'ownedPIDsamplerfailure';metrics=json.loads(p.stdout);raw=json.loads(p.stderr);token=raw['proc_start_abstime'];assert pid_start.setdefault(label,token)==token,'PIDidentitychanged'
     samples.write(json.dumps({'label':label,'elapsed_seconds':time.monotonic()-begin,'metrics':metrics,'raw':raw,'sampler_elapsed_seconds':elapsed})+'\n');samples.flush();observations+=1
    tick+=1
    if tick<time.monotonic():tick=time.monotonic()+1
    stop.wait(max(0,min(tick,begin+SECONDS)-time.monotonic()))
  save(out/'idle-end.json',{'driver_monotonic':time.monotonic(),'idle_seconds':time.monotonic()-begin,'HTTP_SQL_observer_calls':0})
 except BaseException as e:failure=type(e).__name__+': '+str(e);first(e)
 finally:
  code=None
  if child is not None:
   if child.poll() is None:child.send_signal(signal.SIGTERM)
   try:code=child.wait(timeout=25)
   except subprocess.TimeoutExpired:failure=failure or 'shutdown deadline';first(RuntimeError('shutdown deadline'));child.kill();code=child.wait(timeout=5)
  if thread:thread.join(timeout=5)
  log=(out/'gateway.log').read_text() if (out/'gateway.log').exists() else ''
  clean=any(line.startswith('SHUTDOWN ') and 'panicked=0 aborted=0 http_timed_out=false' in line for line in log.splitlines())
  failure=failure or ('uncleanshutdown' if code!=0 or not clean or reader_error or (thread and thread.is_alive()) else None)
  u1=resource.getrusage(resource.RUSAGE_SELF);sv=os.statvfs(out)
  save(out/'result.json',{'failure':failure,'exit_code':code,'clean_shutdown':clean,'owned_gateway_pid':child.pid if child else None,'duration_seconds':time.monotonic()-start,'idle_requested_seconds':SECONDS,'HTTP_requests':0,'SQL_observation_queries':0,'sampler_invocations':observations,'sampler_wall_seconds_sum':sampler_elapsed,'harness_own_userCPU_seconds':u1.ru_utime-u0.ru_utime,'harness_own_systemCPU_seconds':u1.ru_stime-u0.ru_stime,'harness_children_CPU':'UNAVAILABLE; notattributedtoGateway','after_available_bytes':sv.f_bavail*sv.f_frsize,'after_guard_pass':admission(sv.f_bavail*sv.f_frsize),'quiet':child is None or child.poll() is not None,'fixture_1Hz_STATS_included':True,'timer_claim':'1260s covers2x600sreaperboundarywithmargin; min=max1, no shrink0 claim;1800smaxlifeNOTCOVERED','no_next_workload_authority':True})
  fcntl.flock(lease,fcntl.LOCK_UN);lease.close()
 if failure:raise SystemExit(failure)
 print('SQLITE_COLD_IDLE_COMPLETE '+str(out),flush=True)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('out','binary','sampler'):p.add_argument('--'+name,required=True,type=pathlib.Path)
 p.add_argument('--authorized-window',required=True);main(p.parse_args())
