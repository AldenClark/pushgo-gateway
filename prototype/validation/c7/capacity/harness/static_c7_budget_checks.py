#!/usr/bin/env python3
"""Actual source AST with stubs only; no environment state/native/DB/process calls."""
import ast,pathlib,types,collections,json,hashlib,subprocess
HERE=pathlib.Path(__file__).resolve().parent
helper_path=HERE.parent.parent/'env/isolated_db.py'
runner_path=HERE/'run_c7_capacity.py'
helper_text=helper_path.read_text();runner_text=runner_path.read_text()
def function(text,name):return next(n for n in ast.walk(ast.parse(text)) if isinstance(n,ast.FunctionDef) and n.name==name)
def install(node,scope):exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),'actual source AST','exec'),scope)
checks=[];calls=[]
class FakeSubprocess:
    TimeoutExpired=subprocess.TimeoutExpired
    SubprocessError=subprocess.SubprocessError
    def run(self,args,**kwargs):
        calls.append({'args':args,'timeout':kwargs.get('timeout')})
        return types.SimpleNamespace(returncode=0,stdout='ok\n',stderr='')
sp=FakeSubprocess();scope={'subprocess':sp,'D':['STUB_DOCKER'],'os':types.SimpleNamespace(environ={})}
install(function(helper_text,'run'),scope)
scope['owned']=lambda engine:(collections.defaultdict(lambda:'SYNTHETIC',id='STUB_ID',user='STUB_USER',database='STUB_DB'),{})
install(function(helper_text,'sql'),scope)
assert scope['sql']('mysql','STUB_QUERY','STUB_DB')=='ok'
assert calls[-1]['timeout']==7 and '5s' in calls[-1]['args'] and 'timeout' in calls[-1]['args'];checks.append('helper-default-outer7-native5')
clock=types.SimpleNamespace(monotonic=lambda:100)
runner_scope={'time':clock,'subprocess':sp,'helper':types.SimpleNamespace(D=['STUB_DOCKER']),'a':types.SimpleNamespace(engine='mysql')}
for name in ['safe_subprocess_timeout','scoped_db_arguments','bounded_db_run']:install(function(runner_text,name),runner_scope)
scope['run']=runner_scope['bounded_db_run']
for label,enforce,deadline,optional,wanted in [
    ('remaining190-cap7',True,290,None,7),
    ('remaining3-cap3',True,103,None,3),
    ('validation10-cap7',False,None,110,7),
    ('validation1.25-cap1.25',False,None,101.25,1.25),
    ('optional2-cap2',False,None,102,2),
    ('optional0.25-cap0.25',False,None,100.25,.25)]:
    runner_scope.update(enforce_deadline=enforce,deadline=deadline,post_completion_observation_deadline=optional)
    calls.clear();assert scope['sql']('mysql','STUB_QUERY','STUB_DB')=='ok'
    assert len(calls)==1 and calls[0]['timeout']==wanted and '5s' in calls[0]['args'];checks.append(label)
for label,enforce,deadline,optional in [('expired-lane',True,100,None),('expired-optional',False,None,99)]:
    runner_scope.update(enforce_deadline=enforce,deadline=deadline,post_completion_observation_deadline=optional);calls.clear()
    try:scope['sql']('mysql','STUB_QUERY','STUB_DB');raise AssertionError('expired must reject')
    except TimeoutError:pass
    assert not calls;checks.append(label+'-no-subprocess')
# The actual helper SQL must route to the injected run, not a direct subprocess call.
node=function(helper_text,'sql')
assert not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='subprocess' for n in ast.walk(node));checks.append('sql-calls-injectable-run-not-subprocess')
v6=(HERE.parent.parent.parent/'c6-private-capacity-20261015/capacity/frozen-harness-v6/harness/run_c6_capacity.py').read_text()
for name in ['wait_jobs','expected_target_rows','snapshot','drain','request','send']:
    assert ast.dump(function(v6,name))==ast.dump(function(runner_text,name));checks.append(name+'-unchanged-from-reviewed-v6')
receipt={'status':'PASS_SOURCE_ONLY','checks':checks,'passed':len(checks),'runner_sha256':hashlib.sha256(runner_path.read_bytes()).hexdigest(),'helper_sha256':hashlib.sha256(helper_path.read_bytes()).hexdigest(),'no_actual_subprocess_native_DB_environment_state':True,'runtime_ready':False}
print(json.dumps(receipt,indent=2))
