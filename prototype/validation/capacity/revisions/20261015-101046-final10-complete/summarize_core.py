#!/usr/bin/env python3
"""Read retained core69 receipts; does not execute any fixture or command."""
import hashlib,importlib.util,json,pathlib,datetime
HERE=pathlib.Path(__file__).resolve().parent;OUT=HERE.parent
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=module('matrix',HERE/'run_c2_matrix.py');a=module('analysis',HERE/'analyse_c2.py')
labels=[r['label'] for r in m.cases()]+[f'ceiling{h}-offer128-r2-c2' for h in [32,64]]
rows=[];status=[]
for label in labels:
    run=OUT/'runs'/label;r=a.reduce(run);rows.append(r)
    result=json.loads((run/'result.json').read_text());plan=json.loads((run/'plan.json').read_text())
    status.append({'run':label,'variant':plan['variant'],'status':'FAILED' if r['failure'] else 'PASSED',
      'failure':r['failure'],'performance_eligible':r['performance_eligible'],
      'messages_planned':r['messages_planned'],'unique_http_accepted':r['unique_message_operations_accepted_http'],
      'verified_actual_targets':r['actual_unique_targets_excluding_warmup'],'targets_per_message':r['targets_per_message'],
      'first_sql_all_targets_seconds':r['first_sql_all_receipts_visible_seconds'],
      'daemon_exited':result['daemon_exited'],'log_readers_joined':result['log_readers_joined'],
      'binary_sha256':plan['binary_sha256'],'runner_sha256':plan['runner_sha256']})
assert len(rows)==69 and sum(r['failure'] is not None for r in rows)==5
assert all(r['daemon_exited'] and r['log_readers_joined'] for r in status)
assert all(r['variant']=='CURRENT' and r['run'].startswith('offer') for r in status if r['status']=='FAILED')
(OUT/'core69-full-summary.json').write_text(json.dumps(rows,indent=2)+'\n')
(OUT/'core69-status.json').write_text(json.dumps({'cases':69,'passed':64,'failed':5,'states':status,'limit':'Five failed CURRENT capacity lanes cannot yield settled throughput. All successful receipt targets, wires, Pull/ACK and teardown were asserted by the runner. Local mock SQLite Release only.'},indent=2)+'\n')
known={}
for p in (HERE/'revisions').glob('*/run_compare.py'):
    known.setdefault(hashlib.sha256(p.read_bytes()).hexdigest(),[]).append(str(p))
known.setdefault(hashlib.sha256((HERE/'run_compare.py').read_bytes()).hexdigest(),[]).append(str(HERE/'run_compare.py'))
provenance=[]
for run in (OUT/'runs').iterdir():
    if not (run/'plan.json').exists():continue
    p=json.loads((run/'plan.json').read_text());h=p['runner_sha256']
    provenance.append({'run':run.name,'runner_sha256':h,'retained_exact_source_paths':known.get(h,[]),
      'source_status':'exact bytes retained' if h in known else 'historical hash only; exact source not archived; never reconstructed'})
(OUT/'runner-source-provenance-index.json').write_text(json.dumps(provenance,indent=2)+'\n')
print('Core69 reduced:64PASSED,5retainedCURRENT HTTP500 capacity failures; all daemons exited and readers joined.')
print('Exact source unavailable receipts:',[r['run'] for r in provenance if not r['retained_exact_source_paths']])
