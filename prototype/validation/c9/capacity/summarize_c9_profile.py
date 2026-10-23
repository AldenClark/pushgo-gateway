#!/usr/bin/env python3
"""Offline C9 cumulative profile differences; no runtime or database access."""
import importlib.util,json,pathlib,sys,hashlib
BASE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('hist',BASE/'harness-v2/summarize_profile_window.py');hist=importlib.util.module_from_spec(spec);spec.loader.exec_module(hist)
def read(p):
 with p.open() as f:
  for line in f:
   if line.startswith('{'):yield json.loads(line)
def summarize(run):
 stats=[x for x in read(run/'gateway.log') if x.get('kind')=='stats']
 captures=list(read(run/'peer/captures.jsonl'));finishes=list(read(run/'peer/requests.jsonl'));offers=list(read(run/'offers.jsonl'))
 result={}
 for cycle in ('cycle0','cycle1','large'):
  ops={x['op_id'] for x in offers if x['cycle']==cycle}
  low=min(x['unix_ms'] for x in captures if x.get('event')=='received' and x.get('op_id') in ops)
  high=max(x['unix_ms'] for x in finishes if x.get('event')=='provider_finished' and x.get('op_id') in ops)
  interior=[x for x in stats if low<=x['unix_ms']<=high];assert len(interior)>1
  first,last=interior[0],interior[-1]
  paths={}
  for path in ('accept','fanout','claim','receipt'):
   a=first['profile']['paths'][path];b=last['profile']['paths'][path]
   paths[path]={kind:{name:hist.histogram(a[kind].get(name,{}),v) for name,v in b[kind].items()} for kind in ('phases','statements')}
  result[cycle]={'scope':'first/last 1Hz STATS strictly inside first Provider receive to last Provider finish for this cycle; misses boundary work including last receipt; not complete exact callback window','first_unix_ms':first['unix_ms'],'last_unix_ms':last['unix_ms'],'seconds':(last['unix_ms']-first['unix_ms'])/1000,'receipt_samples':last['receipt_commits']-first['receipt_commits'],'paths':paths,'timings':{k:hist.histogram(first['timings'][k],v) for k,v in last['timings'].items() if isinstance(v,dict)}}
 return {'semantics':'SQLx caller wall timers; Usage is 4-SQL bundle, not engine statement count. COMMIT includes worker scheduling. Nested phases overlap and must not sum. Histogram quantiles are bucket upper bounds, not exact. MySQL pool_acquire includes owner check.','cycles':result}
if __name__=='__main__':
 run=pathlib.Path(sys.argv[1]);out=pathlib.Path(sys.argv[2]);assert not out.exists();out.write_text(json.dumps(summarize(run),indent=2)+'\n')
