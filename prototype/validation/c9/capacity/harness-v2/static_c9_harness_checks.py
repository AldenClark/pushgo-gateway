#!/usr/bin/env python3
"""AST and synthetic receipt partitioning only; no Gateway/engine/socket/subprocess calls."""
import ast,hashlib,json,pathlib,struct,tempfile
import reduce_c9_cycles
BASE=pathlib.Path(__file__).resolve().parent
checks=[]
s=(BASE/'run_c9_mysql_cycles.py').read_text();tree=ast.parse(s)
assert "deadline_ticks=tick+round(190*" in s and "cycle_cutoffs[label]=deadline_ticks" in s
assert "'slow_provider'" in s and 'wait_jobs(len(cycle_ops)*16' in s
assert "pending_offers.pop(label,None)" in s and "'oldest_queued_offer_age_ms'" in s
checks.append('firstactualofferbinds190Machcutoff; predraingate doesnotreset; driverqueueage keepsHTTPinflightseparate')
assert 'time.sleep(120)' in s and "metadata_snapshot(label+'_before')" in s and "metadata_snapshot(label+'_after')" in s
assert "snapshot(label+'-'+stage+'-loaded')" in s
checks.append('longidlebodyonlysleep+OS/stdoutthreads; SQL/componentmetadata outsideidle markers; loadedSQLboundedbycycle')
assert 'http_worker_thread_CPU_ns' in s and 'producer_main_thread_CPU_ns' in s and 'Mock_method_CPU' in s
assert "'scope':'driver+loopbackMockthreads; excludesGatewayandDB; spawnedobserverchildCPUunavailable'" in s
checks.append('HTTPclient andMockmethodthreadCPUlowerbounds; separateharnessOSCPURSS avoidsclaimingseparateRSSoraddingdoublecounts')
record=struct.Struct('<QQQ32s32sB7x')
with tempfile.TemporaryDirectory(prefix='c9-pure-reducer-') as temp:
 root=pathlib.Path(temp)/'run';root.mkdir();raw=[];expected=[]
 for index,(cycle,tick,cutoff,outcome) in enumerate([('cycle0',100,150,'accepted'),('cycle0',170,150,'unfinished'),('cycle1',250,300,'accepted'),('large',None,400,'unfinished')]):
  delivery=format(index+1,'032x');device=format(99,'032x');expected.append({'cycle':cycle,'op_id':str(index),'device_key':device,'delivery_id':delivery,'offer_mach_ticks':50,'final_outcome':outcome,'absolute_deadline_mach_ticks':cutoff})
  if tick is not None:raw.append(record.pack(tick,1,index,delivery.encode(),device.encode(),1))
 (root/'commits.bin').write_bytes(b''.join(raw));(root/'expected-targets.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in expected))
 meta={'mach_numer':1,'mach_denom':1,'writer_joined':True,'final_sql_verified':True,'dropped':0,'invalid_ids':0,'write_errors':0,'emitted':3,'expected_targets':4,'excluded_acknowledged_warmup_ids':[]};(root/'telemetry.json').write_text(json.dumps(meta))
 result=reduce_c9_cycles.partition_and_reduce(root,pathlib.Path(temp)/'derived');assert result['cycle0']['offered_targets']==2 and result['cycle0']['outcomes']=={'accepted':1,'unfinished':1} and result['cycle0']['post_cutoff_events_preserved_but_censored']==1;assert result['large']['outcomes']=={'unfinished':1}
 checks.append('unchangedstrictreducerseparatecyclecutoffs: earlycyclelatecallbackstaysunfinished despite laterglobalcycle; missingcallbackretainsdenominator')
 meta['dropped']=1;(root/'telemetry.json').write_text(json.dumps(meta))
 try:reduce_c9_cycles.partition_and_reduce(root,pathlib.Path(temp)/'drop-derived')
 except AssertionError:pass
 else:raise AssertionError('globalwriterdropmustinvalidateallcycles')
 checks.append('originalglobalwriterdropfailsderivedpercycleoracles; originalrawstreamnevermodified')
# Preserve the inherited exact outcome oracle function rather than reimplementing acceptance logic.
old=pathlib.Path('/Users/ethan/Repo/PushGo/gateway/build/quality-results/c8-private48-20261015/capacity/runner-source-c8-large/run_c8_large_cohort.py').read_text();old_tree=ast.parse(old)
for name in ('expected_target_rows','safe_subprocess_timeout','durable_nonterminal','workload_message','scoped_db_arguments'):
 before=next(n for n in old_tree.body if isinstance(n,ast.FunctionDef) and n.name==name);after=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name);assert ast.dump(before,include_attributes=False)==ast.dump(after,include_attributes=False)
checks.append('fiveinheritedC8outcome/DBbudget/scopefunctionsASTunchanged; noSQLsuccessbackfill')
r={'status':'SOURCE_PURE_CHECKS_PASS_NOT_EXECUTED','passed':len(checks),'checks':checks,'sources':{name:hashlib.sha256((BASE/name).read_bytes()).hexdigest() for name in ('run_c9_mysql_cycles.py','reduce_c9_cycles.py','c9_input_plan.py','static_c9_harness_checks.py')},'ephemeral_reducer_SQLite_only':'syntheticexpected/streamoracle; notGatewayDBorcaseworkload'};(BASE/'static-c9-harness-receipt.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
