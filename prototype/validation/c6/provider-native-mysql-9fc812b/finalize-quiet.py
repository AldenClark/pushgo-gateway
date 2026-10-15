"""Root-authorized finalization: evidence, C6 packages, exact owned AVD, lease.
Never drops DBs, purges binlogs, wipes AVDs or deletes runtime/images.
"""
import sys
sys.dont_write_bytecode=True
import pathlib,json,os,re,time,subprocess,hashlib
R=pathlib.Path(__file__).resolve().parent;B=R.parent;sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(name,v):(R/name).write_text(json.dumps(v,indent=2)+'\n')
rows=[]
for lane in ['apple','android']:
 run=R/f'runs/attempt-03-{lane}-mysql';e=json.loads((run/'execution.json').read_text());f=json.loads((run/'loop/final-result.json').read_text());assert e['status']=='PASSED' and f['failure'] is None
 log=(run/('loop/fixture.log' if lane=='apple' else 'loop/candidate-first.log')).read_text();ready=next(x for x in log.splitlines() if x.startswith('READY '));pid=int(re.search(r'pid=(\d+)',ready)[1])
 try:os.kill(pid,0)
 except ProcessLookupError:pass
 else:raise AssertionError('own Gateway PID remains')
 shutdown=[x for x in log.splitlines() if x.startswith('SHUTDOWN ')];assert shutdown and 'joined=2 panicked=0 aborted=0 http_timed_out=false tasks=0' in shutdown[-1]
 rows.append({'lane':lane,'status':e['status'],'run':str(run),'seconds':e['finished_unix']-e['started_unix'],'gateway_pid':pid,'gateway_pid_absent':True,'shutdown':shutdown[-1],'phase_results':f['phase_exits'] if lane=='apple' else {'methods':json.loads((run/'loop/result.json').read_text())['executed_methods'],'native_exit':f['native_exit']},'execution_receipt_sha256':sha(run/'execution.json')})
plan=json.loads((R/'attempt03-plan.json').read_text());assert sha(plan['gateway_binary'])==plan['gateway_binary_sha256'];apk=json.loads((R/'android/c6-apk-identity.json').read_text())
for field in ['main_apk','test_apk']:assert sha(apk[field])==apk[field+'_sha256']
os.environ['C6_OBSERVER_DEPENDENCIES']=json.loads((R/'observer-dependencies.json').read_text())['external_vendor'];sys.path.insert(0,str(R/'harness'));from native_store_observer import NativeStoreObserver
states=[]
for lane in ['apple','android']:
 g=json.loads((R/('preflight-'+lane+'.json')).read_text());os.environ.update(C6_DB_BACKEND='mysql',C6_DB_ENV_ROOT=g['environment_root'],C6_DB_URL_FILE=g['url_file']);observer=NativeStoreObserver()
 states.append({'lane':lane,'database':g['database'],'usage':observer.query('SELECT messages,targets,bytes,private_pending FROM ledger_usage WHERE singleton=1'),'target_states':observer.query('SELECT state,delivery_mode,COUNT(*) AS n FROM targets GROUP BY state,delivery_mode'),'message_count':observer.query('SELECT COUNT(*) AS n FROM messages'),'scope':'read-only final evidence; databases retained under environment owner'})
save('final-db-states.json',states)
adb='/Users/ethan/Library/Android/sdk/platform-tools/adb';pid=39703
process=json.loads((B/'native/attempt-05-mysql-receipt-fix/emulator/emulator-process.json').read_text());assert process['pid']==pid
command=subprocess.check_output(['ps','-p',str(pid),'-o','command='],text=True);uid=int(subprocess.check_output(['ps','-p',str(pid),'-o','uid='],text=True));assert uid==os.getuid() and '-avd pushgo_release_20260929' in command and '-port 5580' in command and '-read-only' in command
reverse=subprocess.check_output([adb,'-s','emulator-5580','reverse','--list'],text=True);assert not reverse.strip()
app=subprocess.run([adb,'-s','emulator-5580','shell','pidof','io.ethan.pushgo.c6evidence'],capture_output=True,text=True);assert not app.stdout.strip()
packages=['io.ethan.pushgo.c6evidence.test','io.ethan.pushgo.c6evidence'];removed=[]
for package in packages:
 result=subprocess.run([adb,'-s','emulator-5580','uninstall',package],capture_output=True,text=True);removed.append({'package':package,'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr});save('package-teardown.json',removed);assert result.returncode==0 and 'Success' in result.stdout
# Root explicitly authorized stopping only this captured process, after both users.
kill=subprocess.run([adb,'-s','emulator-5580','emu','kill'],capture_output=True,text=True);start=time.monotonic()
while time.monotonic()-start<30:
 try:os.kill(pid,0)
 except ProcessLookupError:break
 time.sleep(.2)
else:raise AssertionError('captured emulator PID did not stop; no fallback kill or unrelated cleanup')
save('emulator-teardown.json',{'captured_pid':pid,'pid_absent':True,'adb_emu_kill_exit':kill.returncode,'stdout':kill.stdout,'stderr':kill.stderr,'seconds':time.monotonic()-start,'adb_devices_after':subprocess.check_output([adb,'devices'],text=True),'AVD_runtime_images_removed':False})
lease_path=B/'native/attempt-05-mysql-receipt-fix/emulator-lease.json';lease=json.loads(lease_path.read_text());python='/Users/ethan/.local/bin/python3.13';helper='/Users/ethan/.codex/plugins/cache/dev-flow/dev-flow/2.0.3/skills/dev-flow/scripts/dev-flow.py'
# Never emit token or token-bearing argv. Exact cooperative API supplied by owner.
base=[python,helper,'resource-lease'];before=json.loads(subprocess.check_output(base+['inspect','--kind','emulator','--resource','emulator-5580'],text=True));save('lease-inspect-before-release.json',before);assert before['status']=='leased' and before['generation']==lease['generation'] and before['expires_at']==lease['expires_at']
released=json.loads(subprocess.check_output(base+['release','--kind','emulator','--resource','emulator-5580','--token',lease['token']],text=True));save('lease-release.json',released);assert released['status']=='released'
after=json.loads(subprocess.check_output(base+['inspect','--kind','emulator','--resource','emulator-5580'],text=True));save('lease-inspect-after-release.json',after);assert after['status']=='available'
budget=[]
for label in ['apple_before','apple_after','android_before','android_after']:
 ps=list((B/'env/fresh3').glob('budget-provider_sqlfix_'+label+'-*.json'));p=max(ps,key=lambda x:x.stat().st_mtime);v=json.loads(p.read_text());assert v['status']=='BUDGET_READY' and v['guard_pass'];budget.append({'phase':label,'receipt':str(p),'effective_available_bytes':v['guard_effective_available_bytes'],'minimum_bytes':v['minimum_available_bytes'],'status':v['status']})
quiet={'status':'QUIET; captured AVD stopped and same-owner lease released','lanes':rows,'all_owned_gateway_pids_absent':True,'all_adapters_returned_exit0':True,'proxy_mock_closed':'owned adapters exited after bounded cleanup','C6app_pid_empty_before_uninstall':True,'C6packages_uninstalled':packages,'reverse_empty':True,'captured_emulator_pid':pid,'emulator_pid_absent':True,'emulator_lease_status':after['status'],'lease_release_receipt':str(R/'lease-release.json'),'DB_binlog_cleanup':'NONE; exact cases retained','AVD_runtime_images_removed':False}
save('quiet.json',quiet)
summary={'status':'PASSED_BOTH_MYSQL_PROVIDER_LANES_AND_QUIET','gateway_source_commit':plan['gateway_source_commit'],'gateway_binary_sha256':plan['gateway_binary_sha256'],'lanes':rows,'mysql_budget':budget,'main_apk_sha256':apk['main_apk_sha256'],'test_apk_sha256':apk['test_apk_sha256'],'private_JNI_sha256':apk['packaged_so_sha256'],'original_source_manifest_sha256':sha(R/'source-provenance.json'),'first_preflight_STOP':'preflight-apple-first-failure.json retained; true4GiB stop and wrapper KeyError classified; root separately restored disk budget before new slot','scope':'original Provider controllers Apple8phases/Android3methods with Private ledger/control+idle MQTT listener; not Apple Private/WSSProvider/realProvider evidence','source_business_runners':'8 byte-identical to previously executed attempt02; original input/timeout/oracles unchanged','DB_state_receipt':str(R/'final-db-states.json'),'quiet_receipt':str(R/'quiet.json'),'no_build_or_product_edits':True,'no_PG_capacity_or_extra_business_runtime':True}
save('summary.json',summary)
print(json.dumps({'status':summary['status'],'summary':str(R/'summary.json'),'summary_sha256':sha(R/'summary.json'),'emulator_pid_absent':True,'lease_status':after['status'],'lane_seconds':[x['seconds'] for x in rows]},indent=2))
