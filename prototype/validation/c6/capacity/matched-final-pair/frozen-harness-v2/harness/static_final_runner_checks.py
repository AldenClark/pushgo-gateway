#!/usr/bin/env python3
"""Pure synthetic oracle checks. No subprocess, socket, Mach, Gateway, or DB calls."""
import ast, hashlib, importlib.util, json, pathlib, struct, tempfile
HERE=pathlib.Path(__file__).resolve().parent
def module(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    loaded=importlib.util.module_from_spec(spec);spec.loader.exec_module(loaded);return loaded

def main():
    runner=module('run_c5_capacity_final');reducer=module('reduce_commits');checks={}
    checks['pending_not_queued']=runner.durable_nonterminal({'pending':3,'running':2,'retry_wait':1,'provider_accepted':5})==6
    checks['warmup_not_formal']=not runner.workload_message('/message','c5:capacity:-1') and runner.workload_message('/message','c5:capacity:0')
    pg=['exec','-i','captured-id','psql','-X']
    checks['pgoptions_one_psql_process_only']=runner.scoped_db_arguments('pg',pg)==['exec','-i','-e','PGOPTIONS=-csearch_path=pushgo_c','captured-id','psql','-X'] and runner.scoped_db_arguments('mysql',pg)==pg and runner.scoped_db_arguments('pg',['inspect','captured-id'])==['inspect','captured-id']
    keys=[format(i,'032x') for i in range(16)]
    offers=[{'op_id':'c5:capacity:'+str(i),'offer_mach_ticks':100} for i in range(2560)]
    witness=[{'op_id':offer['op_id'],'device_key':key,'delivery_id':format(i+1,'032x'),'state':'provider_accepted'}
             for i,offer in enumerate(offers) for key in keys]
    events={(r['delivery_id'],r['device_key']):200 for r in witness}
    expected=list(runner.expected_target_rows(offers,keys,witness,[],events,300))
    checks['pre_ack_witness_40960']=len(expected)==40960 and all(r['delivery_id'] and r['final_outcome']=='accepted' for r in expected)
    # Negative control: the old overwritten empty witness loses every mapping.
    corrupted=list(runner.expected_target_rows(offers,keys,[],[],events,300))
    checks['ack_overwrite_detected']=len(corrupted)==40960 and all(r['delivery_id'] is None and r['final_outcome']=='unfinished' for r in corrupted)
    mixed_offers=offers[:5];mixed_witness=[dict(witness[0]),dict(witness[16],state='provider_accepted'),dict(witness[32],state='permanent_failed')]
    requests=[{'path':'/message','label':'c5:capacity:3','error':'TimeoutError: timed out'},
              {'path':'/message','label':'c5:capacity:4','error':'HTTPError: 503'}]
    # Only one intended key for the focused 5-outcome case.
    event_ticks={(r['delivery_id'],keys[0]):200 for r in mixed_witness};event_ticks[(mixed_witness[1]['delivery_id'],keys[0])]=400
    partial=list(runner.expected_target_rows(mixed_offers,keys[:1],mixed_witness,requests,event_ticks,300))
    checks['partial_denominator_and_cutoff']=[r['final_outcome'] for r in partial]==['accepted','unfinished','provider_failed','timeout','admission_failed']
    with tempfile.TemporaryDirectory(prefix='c5-pure-oracle-') as temp:
        temp=pathlib.Path(temp)
        (temp/'expected').write_text(''.join(json.dumps(r)+'\n' for r in partial))
        packed=b''
        for sequence,row in enumerate(mixed_witness):
            ticks=event_ticks[(row['delivery_id'],keys[0])]
            packed+=struct.pack('<QQQ32s32sB7x',ticks,1,sequence,row['delivery_id'].encode(),keys[0].encode(),2 if row['state']=='permanent_failed' else 1)
        (temp/'stream').write_bytes(packed)
        meta={'mach_numer':1,'mach_denom':1,'writer_joined':True,'final_sql_verified':True,
              'dropped':0,'invalid_ids':0,'write_errors':0,'emitted':3,'expected_targets':5,'measurement_cutoff_mach_ticks':300}
        (temp/'telemetry').write_text(json.dumps(meta))
        result=reducer.reduce(temp/'expected',temp/'stream',temp/'telemetry',temp/'scratch')
        checks['late_event_excluded_full_denominator']=result['offered_targets']==5 and result['success']['observed_targets']==1 and result['post_cutoff_events_preserved_but_censored']==1
        checks['failed_unfinished_quantiles_not_full_coverage']=result['success']['coverage']==.2 and not result['all_offered_success_quantiles_identified']
    source=(HERE/'run_c5_capacity_final.py').read_text();tree=ast.parse(source)
    # Inspect idle statement sequence and mark's body; no runtime functions invoked.
    checks['fixed_idle_no_http_no_sql']=all("mark('"+label+"-start');time.sleep(30);mark('"+label+"-end')" in source for label in ('cold-idle','post-ack-idle'))
    main_ast=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
    mark=next(n for n in main_ast.body if isinstance(n,ast.FunctionDef) and n.name=='mark')
    checks['mark_os_only']=not any(isinstance(n,ast.Name) and n.id in ('request','sql','connection_counts') for n in ast.walk(mark))
    checks['fixed_deadline_sql_budget_and_postcheck']='deadline=load_start+10+180' in source and 'timeout=min(10,remaining)' in source and 'fixed drain deadline exceeded during identity witness' in source
    checks['pre_ack_witness_preserved_in_finally']='ready.is_set() and not sql_verified' in source
    observer=module('db_os_observer')
    native='mysqld\nName:\tmysqld\nVmRSS:\t12345 kB\n'
    checks['native_kB_exact_bytes']=observer.parse_native_status('mysql',native)['rss_bytes']==12345*1024
    def rejects(fn):
        try:fn();return False
        except ValueError:return True
    checks['wrong_namespace_engine_rejected']=rejects(lambda:observer.parse_native_status('pg',native))
    checks['humanized_RSS_never_converted']=rejects(lambda:observer.parse_native_status('mysql','mysqld\nVmRSS: 309m\n'))
    checks['supported_coarse_TIME']=observer.parse_time('1:29')==89 and observer.parse_time('1:02:03')==3723
    checks['unknown_coarse_TIME_unavailable']=rejects(lambda:observer.parse_time('1h12'))
    top='PID PPID COMMAND TIME\n429 410 mysqld 1:29\n'
    process=observer.parse_top('mysql',top)[0]
    first={'container_id':'captured','container_started_at':'fixed','container_init_vm_host_pid':429,'engine_processes':[process]}
    second={**first,'engine_processes':[{**process,'cpu_seconds_coarse':93}]}
    delta=observer.cpu_delta(first,second,30)
    checks['CPU_cumulative_TIME_delta']=delta['available'] and delta['cpu_seconds_coarse_delta']==4 and delta['endpoint_quantization_error_seconds_bound']==2
    checks['PID_churn_CPU_unavailable']=not observer.cpu_delta(first,{**second,'engine_processes':second['engine_processes']+[{**process,'vm_host_pid':999}]},30)['available']
    checks['container_restart_CPU_unavailable']=not observer.cpu_delta(first,{**second,'container_started_at':'new'},30)['available']
    checks['counter_reset_CPU_unavailable']=not observer.cpu_delta(first,{**second,'engine_processes':[{**process,'cpu_seconds_coarse':1}]},30)['available']
    checks['no_pcCPU_or_human_RSS_runtime']='pcpu' not in source[source.index('    def db_sampler():'):source.index('    def request(')]
    checks['fixed_1Hz_OS_no_catchup']='next_tick+=1' in source and 'Missed slot; no catch-up burst' in source
    checks['observer_failure_preserved_UNAVAILABLE']="'first-db-observation-failure.json'" in source and "'observation_status':'UNAVAILABLE'" in source
    hashes={name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in ('run_c5_capacity_final.py','db_os_observer.py','summarize_resources_final.py','reduce_commits.py','prepare_observer.py','observer_fixture.rs','observer_library.rs')}
    receipt={'scope':'pure source/oracle checks only; no native build or Gateway/database runtime','checks':checks,'all_passed':all(checks.values()),'source_sha256':hashes}
    assert receipt['all_passed'],receipt
    print(json.dumps(receipt,indent=2))

if __name__=='__main__':main()
