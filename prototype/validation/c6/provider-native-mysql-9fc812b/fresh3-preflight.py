"""One explicit Provider lane guard. No provisioning/cleanup or product mutations."""
import sys
sys.dont_write_bytecode=True
import pathlib,json,importlib.util,fcntl,os,time,subprocess,hashlib,urllib.parse
R=pathlib.Path(__file__).resolve().parent;B=R.parent;E=B/'env/fresh3'
lane=sys.argv[1];assert lane in ('apple','android');label=lane+'_provider_sqlfix'
out=R/('preflight-'+lane+'.json');assert not out.exists()
sp=importlib.util.spec_from_file_location('c6_fresh3_owner',E/'isolated_db.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
assert m.KEY=='io.pushgo.c6.disk3.synthetic.owner';m.check();state,actual=m.owned('mysql')
assert state['id']=='c24a4150e4f3f3e61af1445535b24a9ab1b7c16355b1f4162ae7d17152e67f81'
assert state['owner']=='829bc0ad72204aff99718fc3073c1752'
manifest=json.loads((B/'env/active-case-manifest.json').read_text());cases=[x for x in manifest['cases'] if x['backend']=='mysql' and x['label']==label];assert len(cases)==1;case=cases[0]
assert case['container_id']==state['id'] and case['owner_uuid']==state['owner']
assert pathlib.Path(case['environment_helper']).resolve()==E/'isolated_db.py'
assert pathlib.Path(case['captured_state']).resolve()==E/'mysql-owned.json'
with (E/'cases.lock').open('r') as lock:
 fcntl.flock(lock,fcntl.LOCK_SH);capture=json.loads((E/'mysql-owned.json').read_text())
 path=pathlib.Path(case['url_file']).resolve();assert path.parent==E and path.stat().st_mode&0o077==0
 assert capture['cases'][case['database']]['url_file']==str(path) and capture['cases'][case['database']]['label']==label
 url=urllib.parse.urlsplit(path.read_text().strip());assert url.scheme=='mysql' and url.hostname=='127.0.0.1' and url.path=='/'+case['database'] and f'{url.hostname}:{url.port}'==capture['endpoint']
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
plan=json.loads((R/'attempt03-plan.json').read_text());assert sha(plan['gateway_binary'])==plan['gateway_binary_sha256']
apk=json.loads((R/'android/c6-apk-identity.json').read_text())
for field in ['main_apk','test_apk']:assert sha(apk[field])==apk[field+'_sha256']
lease_path=B/'native/attempt-05-mysql-receipt-fix/emulator-lease.json';lease=json.loads(lease_path.read_text());assert lease['status'] in ('acquired','renewed') and lease['kind']=='emulator' and lease['expires_at']>time.time()+180
proc=json.loads((B/'native/attempt-05-mysql-receipt-fix/emulator/emulator-process.json').read_text());assert proc['pid']==39703
os.kill(39703,0);cmd=subprocess.check_output(['ps','-p','39703','-o','command='],text=True);assert '-avd pushgo_release_20260929' in cmd and '-port 5580' in cmd and '-read-only' in cmd
adb='/Users/ethan/Library/Android/sdk/platform-tools/adb';assert subprocess.check_output([adb,'-s','emulator-5580','shell','getprop','sys.boot_completed'],text=True).strip()=='1'
assert not subprocess.check_output([adb,'-s','emulator-5580','reverse','--list'],text=True).strip()
app=subprocess.run([adb,'-s','emulator-5580','shell','pidof','io.ethan.pushgo.c6evidence'],capture_output=True,text=True);assert not app.stdout.strip()
# This helper writes OS-first evidence, then bounded SQL inventory; use the
# captured fresh3 owner's actual disk budget, never the old tmpfs reservation.
budget_result=subprocess.check_output([sys.executable,str(E/'budget_snapshot.py'),'provider_sqlfix_'+lane+'_before'],text=True)
# Persist exact stdout before any parsing/classification, including native STOP.
(R/('budget-'+lane+'-stdout.txt')).write_text(budget_result)
from budget_adapter import classify_budget
try:
 budget=json.loads(budget_result);budget_path=pathlib.Path(budget['receipt']).resolve()
 if budget_path.parent!=E or not budget_path.name.startswith('budget-provider_sqlfix_'+lane+'_before-') or budget_path.suffix!='.json':
  raise ValueError('budget receipt outside exact captured owner namespace')
 receipt=json.loads(budget_path.read_text())
 classification=classify_budget(budget,receipt,state['id'],state['owner'])
except (ValueError,KeyError,TypeError,OSError) as error:
 out.write_text(json.dumps({'status':'STOP_INVALID_BUDGET_EVIDENCE','exact_stdout_file':'budget-'+lane+'-stdout.txt','error':str(error),'native_or_Gateway_started':False},indent=2)+'\n')
 raise SystemExit('budget evidence invalid; saved; no Gateway/native started') from None
if classification['decision']!='READY':
 out.write_text(json.dumps({'status':classification['status'],'classification':classification,'budget':budget,'native_or_Gateway_started':False},indent=2)+'\n')
 raise SystemExit(classification['status']+'; original guard STOP saved; no Gateway/native started')
os.environ.update(C6_DB_BACKEND='mysql',C6_DB_ENV_ROOT=str(E),C6_DB_URL_FILE=str(path),C6_OBSERVER_DEPENDENCIES=json.loads((R/'observer-dependencies.json').read_text())['external_vendor'])
sys.path.insert(0,str(R/'harness'));from native_store_observer import NativeStoreObserver
observer=NativeStoreObserver();empty=observer.query('SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema=DATABASE()');assert empty==[{'n':0}],empty
result={'status':'GUARD_READY','lane':lane,'case_label':label,'database':case['database'],'url_file':str(path),'environment_root':str(E),'container_id':state['id'],'owner_uuid':state['owner'],'owner_key':m.KEY,'exact_case_and_URL_parent':True,'actual_tables':0,'gateway_sha256':plan['gateway_binary_sha256'],'main_apk_sha256':apk['main_apk_sha256'],'test_apk_sha256':apk['test_apk_sha256'],'emulator_pid':39703,'emulator_serial':'emulator-5580','lease_receipt':str(lease_path),'lease_generation':lease['generation'],'lease_seconds_remaining':int(lease['expires_at']-time.time()),'adb_reverse_empty':True,'app_PID_empty':True,'budget':budget,'scope':'captured fresh3 disk owner, OS-first4GiB guard; no provisioning/build/cleanup'}
out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':result['status'],'lane':lane,'receipt':str(out),'budget':budget},indent=2))
