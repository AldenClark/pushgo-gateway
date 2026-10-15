#!/usr/bin/env python3
"""Replay only the pure function AST. No runtime module import, DB or native APIs."""
import ast, pathlib
source=pathlib.Path(__file__).with_name('run_c6_capacity.py')
tree=ast.parse(source.read_text())
node=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=='expected_target_rows')
scope={};exec(compile(ast.Module(body=[node],type_ignores=[]),'isolated-expected-target-rows','exec'),scope)
f=scope['expected_target_rows'];base={'op_id':'op','device_key':'dev','delivery_id':'del','state':'provider_accepted'}
offers=[{'op_id':'op','offer_mach_ticks':1}];checks=[]
for label,ticks,want,late,unknown in [('unknown',{},'unfinished',False,True),('late',{('del','dev'):101},'unfinished',True,False),('at-cutoff',{('del','dev'):100},'accepted',False,False),('before-cutoff',{('del','dev'):99},'accepted',False,False)]:
    row=list(f(offers,['dev'],[base],[],ticks,100))[0]
    assert (row['final_outcome'],row['post_cutoff_success_censored'],row['callback_timing_unknown'])==(want,late,unknown)
    checks.append(label)
rows=list(f([{'op_id':str(i),'offer_mach_ticks':1} for i in range(2560)],[str(i) for i in range(16)],[],[],{},100))
assert len(rows)==40960 and all(r['final_outcome']=='unfinished' for r in rows)
checks.append('all-40960-unstarted-retained')
for label,error,want in [('http-timeout','timed out','timeout'),('http-error','synthetic','admission_failed')]:
    row=list(f(offers,['dev'],[],[{'path':'/message','label':'op','error':error}],{},100))[0]
    assert row['final_outcome']==want;checks.append(label)
print({'status':'PASS','checks':checks,'count':len(checks)})
