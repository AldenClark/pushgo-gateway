"""Pure adapter checks from captured receipts; no subprocess/adb/SQL/network."""
import sys
sys.dont_write_bytecode=True
import pathlib,json,copy,hashlib
from budget_adapter import classify_budget
R=pathlib.Path(__file__).resolve().parent;B=R.parent
pass_stdout_path=B/'native/attempt-05-mysql-receipt-fix/private_sqlfix_preflight-mysql-budget.json'
pass_stdout=json.loads(pass_stdout_path.read_text());pass_path=pathlib.Path(pass_stdout['receipt']);passing=json.loads(pass_path.read_text())
stop_path=B/'env/fresh3/budget-provider_sqlfix_apple_before-c8028021.json';stopped=json.loads(stop_path.read_text())
# The failed old wrapper captured stdout only in memory then raised KeyError
# before writing it. This is its exact helper-defined STOP output shape, rebuilt
# from the actual preserved receipt; explicitly not a newly executed observation.
stop_stdout={'receipt':str(stop_path),'guard_pass':False,'effective_available_bytes':stopped['guard_effective_available_bytes']}
CID='c24a4150e4f3f3e61af1445535b24a9ab1b7c16355b1f4162ae7d17152e67f81';OWNER='829bc0ad72204aff99718fc3073c1752'
results=[]
def check(name,out,receipt,expected):
 try:actual=classify_budget(out,receipt,CID,OWNER)['decision']
 except ValueError:actual='REJECT'
 assert actual==expected,(name,expected,actual)
 results.append({'case':name,'expected':expected,'actual':actual})
check('actual-captured-PASS',pass_stdout,passing,'READY')
check('actual-STOP-receipt-with-helper-defined-missing-status-stdout',stop_stdout,stopped,'STOP')
for field in ['receipt','guard_pass','status','available_bytes','host_available_bytes','volume_name','storage_medium']:
 altered=copy.deepcopy(pass_stdout);altered.pop(field);check('PASS-stdout-missing-'+field,altered,passing,'REJECT')
for field in ['container_id','owner_uuid','volume_owner_label_key','volume_owner_label_value','minimum_available_bytes','guard_pass','guard_effective_available_bytes','sql_inventory','os_snapshot_persisted_before_sql','status']:
 altered=copy.deepcopy(passing);altered.pop(field);check('PASS-receipt-missing-'+field,pass_stdout,altered,'REJECT')
for field,value in [('container_id','wrong'),('owner_uuid','wrong'),('volume_owner_label_key','old-fresh2-key'),('volume_owner_label_value','wrong'),('volume_name','wrong'),('minimum_available_bytes',1),('os_snapshot_persisted_before_sql',False),('guard_effective_available_bytes',passing['guard_effective_available_bytes']+1)]:
 altered=copy.deepcopy(passing);altered[field]=value;check('reject-'+field,pass_stdout,altered,'REJECT')
for field in ['receipt','guard_pass','effective_available_bytes']:
 altered=copy.deepcopy(stop_stdout);altered.pop(field);check('STOP-stdout-missing-'+field,altered,stopped,'REJECT')
altered=copy.deepcopy(stop_stdout);altered['guard_pass']=True;check('STOP-cannot-become-PASS',altered,stopped,'REJECT')
altered=copy.deepcopy(stopped);altered['container_id']='wrong';check('STOP-bad-ownership-still-rejected',stop_stdout,altered,'REJECT')
altered=copy.deepcopy(passing);altered['sql_inventory']['status']='NOT_ATTEMPTED';check('PASS-incomplete-SQL-inventory',pass_stdout,altered,'REJECT')
altered=copy.deepcopy(pass_stdout);altered['guard_pass']=False;check('PASS-false-stdout-guard',altered,passing,'REJECT')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
record={'status':'PURE_ADAPTER_CHECKS_PASSED','count':len(results),'checks':results,'captured_pass_stdout':str(pass_stdout_path),'captured_pass_receipt':str(pass_path),'captured_stop_receipt':str(stop_path),'STOP_stdout_provenance':'Exact original helper STOP print schema reconstructed using actual preserved receipt. Raw first stdout was not persisted by old failing wrapper; no fresh budget run is claimed.','original_STOP_status':stopped['status'],'original_STOP_effective_available_bytes':stopped['guard_effective_available_bytes'],'runtime_started':False,'DB_adb_Gateway_native_calls':0,'hashes':{'budget_adapter.py':sha(R/'budget_adapter.py'),'fresh3-preflight.py':sha(R/'fresh3-preflight.py'),'PASS_stdout':sha(pass_stdout_path),'PASS_receipt':sha(pass_path),'STOP_receipt':sha(stop_path)}}
(R/'budget-adapter-pure-checks.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'status':record['status'],'checks':len(results),'runtime_calls':0}))
