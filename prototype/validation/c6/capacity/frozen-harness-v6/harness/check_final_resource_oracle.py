#!/usr/bin/env python3
"""Pure offline structured-DB sample integration; never queries a process or DB."""
import importlib.util,json,pathlib,tempfile
BASE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('final_resources',BASE/'summarize_resources_final.py')
resources=importlib.util.module_from_spec(spec);spec.loader.exec_module(resources)
def sample(t,pid=1,cpu=0,rss=100):
    return {'elapsed':t,'phase':'cold-idle-start','observation_status':'AVAILABLE',
        'container_id':'owned','container_started_at':'same','container_init_vm_host_pid':1,
        'native_pid1':{'rss_bytes':rss},
        'engine_processes':[{'vm_host_pid':pid,'vm_host_ppid':0,'comm':'mysqld','cpu_seconds_coarse':cpu}]}
def summarize(rows):
    with tempfile.TemporaryDirectory(prefix='pure-resource-',dir=BASE/'final-runner-preparation-v1') as temp:
        path=pathlib.Path(temp);(path/'db-process.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
        return resources.summarize(path)['db_engine_by_phase']['cold-idle-start']
checks={}
stable=summarize([sample(0,cpu=1,rss=100),sample(15,cpu=2,rss=200),sample(30,cpu=3,rss=150)])
checks['main_RSS_sample_peak_only']=stable['native_pid1_rss_peak_sampled_bytes']==200
checks['stable_coarse_CPU_span']=stable['cpu']['available'] and stable['cpu']['cpu_seconds_coarse_delta']==2
churn=summarize([sample(0),sample(15,pid=2,cpu=1),sample(30,cpu=2)])
checks['middle_PID_churn_not_hidden_by_equal_endpoints']=not churn['cpu']['available']
missing=summarize([sample(0),{'elapsed':15,'phase':'cold-idle-start','observation_status':'UNAVAILABLE'},sample(30,cpu=2)])
checks['one_missing_sample_CPU_unavailable']=not missing['cpu']['available'] and missing['unavailable_samples']==1
legacy=summarize([{'elapsed':0,'phase':'cold-idle-start','returncode':1,'raw':'','stderr':'unsupported pcpu'}])
checks['legacy_error_is_unavailable_not_zero_RAM']=legacy['available_samples']==0 and 'native_pid1_rss_peak_sampled_bytes' not in legacy
assert all(checks.values()),checks
print(json.dumps({'scope':'pure offline reducer integration only','checks':checks,'all_passed':True},indent=2))
