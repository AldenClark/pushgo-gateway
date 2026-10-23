#!/usr/bin/env python3
"""Execute the actual sampler AST against a fake6s clock; no OS/DB/HTTP calls."""
import ast,collections,hashlib,json,pathlib,threading,types
BASE=pathlib.Path(__file__).resolve().parent

def simulate(source):
 tree=ast.parse(source);main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main');sampler=next(n for n in ast.walk(main) if isinstance(n,ast.FunctionDef) and n.name=='sampler')
 clock=types.SimpleNamespace(value=0.0);events=[]
 class Stop:
  def is_set(self):return clock.value>=6
  def wait(self,seconds):clock.value+=seconds
 def run(command,**kw):return types.SimpleNamespace(returncode=0,stdout='100' if command[-1]=='rss=' else '2 100 00:00.01')
 ns={'time':types.SimpleNamespace(monotonic=lambda:clock.value),'stop':Stop(),'host_observer':types.SimpleNamespace(sample=lambda pid:{'fake':True}),'pid':42,'emit':lambda kind,row:events.append((clock.value,kind,row)),'resource':types.SimpleNamespace(RUSAGE_SELF=0,getrusage=lambda _:types.SimpleNamespace(ru_utime=clock.value/100,ru_stime=clock.value/200)),'subprocess':types.SimpleNamespace(run=run),'os':types.SimpleNamespace(getpid=lambda:11),'lock':threading.RLock(),'producer':dict(offered=0,started=0,finished=0),'pending_offers':{},'mach':types.SimpleNamespace(mach_absolute_time=lambda:int(clock.value*1000000)),'scale':.001}
 exec(compile(ast.Module(body=[sampler],type_ignores=[]),'actual_sampler_fakeclock','exec'),ns);ns['sampler']()
 return {'counts':dict(collections.Counter(kind for _,kind,_ in events)),'host_times':[t for t,k,_ in events if k=='host-load'],'harness_times':[t for t,k,_ in events if k=='harness'],'final_fake_seconds':clock.value}
def require_cadence(row):
 assert row['harness_times']==[0,1,2,3,4,5],'harnesssamplestarvationorwrongcadence'
 assert row['host_times']==[0,5],'hostnot5scadence'
 assert row['counts']['producer']==24
if __name__=='__main__':
 source=(BASE/'run_c9_mysql_cycles.py').read_text();row=simulate(source);require_cadence(row)
 receipt={'status':'PURE_ACTUAL_SAMPLER_AST_FAKECLOCK_PASS','scope':'6svirtualtime,no subprocess/OS/DB/HTTP','observed':row,'source_sha256':hashlib.sha256(source.encode()).hexdigest()};(BASE/'static-sampler-clock-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
