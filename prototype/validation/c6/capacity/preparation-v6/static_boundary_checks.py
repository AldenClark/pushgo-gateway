#!/usr/bin/env python3
"""Pure AST/function simulation only; no module import or native/DB calls."""
import ast, pathlib, textwrap, json, hashlib
HERE=pathlib.Path(__file__).resolve().parent
original=HERE.parent/'matched-disk3-pair/frozen-harness-v4/harness/run_c6_capacity.py'
prepared=HERE/'run_c6_capacity.py'
old=original.read_text();new=prepared.read_text();tree=ast.parse(new)
main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
wait=next(n for n in main.body if isinstance(n,ast.FunctionDef) and n.name=='wait_jobs')
factory='def factory():\n    sql_aggregate_complete_ticks=None\n    enforce_deadline=True\n    post_completion_observation_deadline=None\n'+textwrap.indent(ast.unparse(wait),'    ')+'\n    return wait_jobs,lambda:(sql_aggregate_complete_ticks,enforce_deadline,post_completion_observation_deadline)\n'
class Clock:
    def __init__(self):self.now=98.0
    def monotonic(self):return self.now
    def sleep(self,n):self.now+=n
class Mach:
    def __init__(self,c):self.c=c
    def mach_absolute_time(self):return round(self.c.now*1000)
def make(aggregate=1,identity=3,complete=True,identity_error=False):
    clock=Clock();calls=[];marks=[]
    def snapshot(label,raw=False):
        calls.append((label,raw));clock.now+=identity if raw else aggregate
        if raw:
            if identity_error:raise ValueError('mock identity observation failure')
            return {'dispatch_rows':[{'fixed':'unchanged identity witness'}]}
        return {'target_count':16,'states':{'provider_accepted':16} if complete else {'pending':16}}
    def mark(label):marks.append(label);clock.now+=2
    scope={'time':clock,'mach':Mach(clock),'snapshot':snapshot,'mark':mark}
    exec(compile(factory,'isolated actual wait_jobs AST','exec'),scope)
    wait,state=scope['factory']();return clock,calls,marks,wait,state
checks=[]
def check(name,condition):assert condition,name;checks.append(name)
c,calls,marks,w,state=make();rows=w(16,'drain',100,freeze_sqlaggregate=True)
check('aggregate-before100-freezes-before-identity-crosses100',state()==(99000,False,None) and c.now==104 and rows==[{'fixed':'unchanged identity witness'}])
check('marker-is-SQL-not-callback',marks==['SQLaggregate_complete_before_cutoff'])
c,calls,marks,w,state=make(aggregate=2)
try:w(16,'drain',100,freeze_sqlaggregate=True);raise RuntimeError('must fail')
except AssertionError:pass
check('aggregate-at-cutoff-fails-no-marker-no-identity',state()==(None,True,None) and not marks and calls==[('drain',False)])
c,calls,marks,w,state=make(aggregate=3)
try:w(16,'drain',100,freeze_sqlaggregate=True);raise RuntimeError('must fail')
except AssertionError:pass
check('aggregate-after-cutoff-fails',state()[0] is None)
c,calls,marks,w,state=make(complete=False)
try:w(16,'drain',100,freeze_sqlaggregate=True);raise RuntimeError('must fail')
except AssertionError:pass
check('partial-aggregate-never-enters-validation',not marks and all(not raw for _,raw in calls))
c,calls,marks,w,state=make(identity=11)
try:w(16,'drain',100,freeze_sqlaggregate=True);raise RuntimeError('must fail')
except AssertionError:pass
check('identity-total-ten-second-bound-fails-with-frozen-SQL-marker',state()==(99000,False,None))
c,calls,marks,w,state=make(identity=9)
try:w(16,'drain',100,freeze_sqlaggregate=True);raise RuntimeError('must fail')
except AssertionError:pass
check('marker-cost-is-included-in-ten-second-total',state()==(99000,False,None))
c,calls,marks,w,state=make(identity_error=True)
try:w(16,'drain',100,freeze_sqlaggregate=True);raise RuntimeError('must fail')
except ValueError:pass
check('identity-error-propagates-and-clears-budget',state()==(99000,False,None))
c,calls,marks,w,state=make()
try:w(16,'warmup',100);raise RuntimeError('must fail')
except AssertionError:pass
check('warmup-original-identity-deadline-unchanged',state()==(None,True,None) and not marks)
cutoff=next(n for n in ast.walk(main) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='cutoff' for t in n.targets))
expr=ast.Expression(body=cutoff.value);code=compile(ast.fix_missing_locations(expr),'actual cutoff expression','eval')
check('postcompletion-failure-does-not-shorten-original-cutoff',eval(code,{'sql_aggregate_complete_ticks':50,'deadline_ticks':100,'failure_ticks':80})==100)
check('precompletion-firstfailure-still-censors',eval(code,{'sql_aggregate_complete_ticks':None,'deadline_ticks':100,'failure_ticks':80})==80)
check('ownership-secret-identity-guards-unmodified',old[old.index('    mach='):old.index('    failure_ticks=None')]==new[new.index('    mach='):new.index('    failure_ticks=None')])
def pure_function(text,name):return ast.dump(next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name),include_attributes=False)
check('v4-full-denominator-timing-unknown-oracle-unchanged',pure_function(old,'expected_target_rows')==pure_function(new,'expected_target_rows'))
for function in ['snapshot','drain','request','send']:
    def nested(text):return next(n for n in ast.walk(ast.parse(text)) if isinstance(n,ast.FunctionDef) and n.name==function)
    check(function+'-unchanged',ast.dump(nested(old))==ast.dump(nested(new)))
check('original190-deadline-input-unchanged','deadline=load_start+10+180' in new and 'range(2560)' in new and 'load_start+i/256' in new)
check('zero-unfinished-callback-coverage-required',"callback_outcomes.get('accepted',0)!=len(rows['offers'])*len(keys)" in new)
check('original-SQL-ten-second-percall-budget-unchanged','budget=min(10,remaining)' in new)
receipt={'status':'PASS','checks':checks,'check_count':len(checks),'method':'isolated actual wait_jobs AST with fake clocks/snapshot/mark; no module imports/native/DB/build/runtime','v4_sha256':hashlib.sha256(original.read_bytes()).hexdigest(),'v6_sha256':hashlib.sha256(prepared.read_bytes()).hexdigest(),'strict_reducer_unchanged':True,'runtime_ready':False}
print(json.dumps(receipt,indent=2))
