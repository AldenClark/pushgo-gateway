#!/usr/bin/env python3
"""One future root-authorized lane. Source preparation alone never starts this file."""
import argparse,hashlib,json,os,pathlib,signal,subprocess,sys,time
BASE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(BASE/'harness'))
import run_c6_capacity as runner
import db_statement_observer

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,r):
    with p.open('x') as f:json.dump(r,f,indent=2);f.write('\n')
def budget(config,label,before):
    command=[sys.executable,'-B',config['mysql_budget_script'],label]
    child=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
    try:stdout,stderr=child.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid,signal.SIGKILL);child.communicate();raise TimeoutError('Storage budget observer exceeded fixed 20s; no lane start or deadline extension') from None
    assert child.returncode==0,'storage budget observer failed; command output withheld'
    receipt=pathlib.Path(json.loads(stdout)['receipt']);r=json.loads(receipt.read_text())
    observed=validate_disk_budget(r,config,before)
    return {'path':str(receipt),'sha256':sha(receipt),**observed,'binlog_lifecycle':'raw SQL inventory retained; no reset/purge/drop by runner'}

def validate_disk_budget(r,config,before):
    assert r['container_id']==config['mysql_container_id'] and r['owner_uuid']==config['mysql_storage']['owner_uuid'],'budget container/owner mismatch'
    storage=config['mysql_storage'];assert r['storage_medium']==storage['medium']=='disk-backed-named-volume'
    assert r['volume_name']==storage['volume_name'] and r['volume_driver']=='local' and r['volume_mountpoint']==storage['volume_mountpoint']
    assert r['volume_owner_label_key']=='io.pushgo.c6.disk3.synthetic.owner' and r['volume_owner_label_value']==storage['owner_uuid']
    mounts=r['container_datadir_mount'];assert len(mounts)==1 and mounts[0]['Destination']=='/var/lib/mysql' and mounts[0]['Type']=='volume' and mounts[0]['Name']==storage['volume_name'] and mounts[0]['Source']==storage['volume_mountpoint']
    assert r['os_snapshot_persisted_before_sql'] and r['sql_inventory']['status']=='COMPLETE' and r['sql_inventory']['exit_code']==0 and r['status']=='BUDGET_READY'
    identity=r['sql_inventory']['stdout'].splitlines()[-1].split();assert len(identity)==6
    assert identity[:2]==[config['mysql_server_identity']['server_uuid'],str(config['mysql_server_identity']['server_id'])] and identity[2:]==['1','1','1','1'],'server identity/durability/trust mismatch'
    os_raw=r['os_observations'];assert all(v['exit_code']==0 for v in os_raw.values())
    filesystem=os_raw['filesystem_type']['stdout'].strip();assert filesystem==storage['filesystem_type'] and filesystem.lower() not in ('tmpfs','ramfs','devtmpfs','memory'),'non-disk or mismatched filesystem'
    guest=int(os_raw['datadir_df_bytes']['stdout'].splitlines()[-1].split()[4]);host=r['host_available_bytes'];assert guest==r['available_bytes'] and min(guest,host)==r['guard_effective_available_bytes']
    assert r['minimum_available_bytes']==4294967296
    fields=os_raw['datadir_inodes']['stdout'].splitlines()[-1].split();total,used,free=map(int,fields[1:4])
    inode={'available':False,'reason':'df reports total0/free0; capacity UNAVAILABLE, no fabricated free-inode count','raw':os_raw['datadir_inodes']['stdout']} if total==0 and free==0 else {'available':True,'total':total,'used':used,'free':free}
    if before:
        assert min(guest,host)>=4294967296 and r['guard_pass'],'less than4GiB host/guest free bytes; stop root, no resize/retry'
        if inode['available']:assert free>0,'known inode exhaustion; stop root'
    return {'storage_medium':r['storage_medium'],'available_bytes':guest,'host_available_bytes':host,'effective_available_bytes':min(guest,host),'minimum_available_bytes':4294967296,'space_guard_pass':min(guest,host)>=4294967296,'inodes':inode,'filesystem_type':filesystem,'volume_name':storage['volume_name']}

def main(a):
    config=json.loads(a.manifest.read_text());assert config['runtime_ready'] is True,'final source/binary and root exclusive window not yet bound'
    assert a.authorized_window=='root-exclusive-c6-disk3'
    assert config['authorized_lane']==a.lane,'only one root-authorized arm per finalized manifest'
    for path,expected in config['pinned_artifacts'].items():assert sha(pathlib.Path(path))==expected,('pinned artifact changed',path)
    assert config['instrumentation_reset']['approved_completed'] is True,'owner instrumentation reset receipt required'
    lane=config['lanes'][a.lane]
    out=pathlib.Path(lane['out']);out.parent.mkdir(parents=True,exist_ok=True);assert not out.exists()
    active=json.loads(pathlib.Path(config['active_case_manifest']).read_text())
    cases=[r for r in active['cases'] if r['label']==lane['case_label'] and r['backend']==('postgres' if lane['engine']=='pg' else 'mysql')];assert len(cases)==1;case=cases[0]
    assert case['container_id']==lane['container_id'];assert case['owner_uuid']==lane['owner_uuid']
    assert pathlib.Path(case['environment_helper']).resolve()==pathlib.Path(lane['db_helper']).resolve()
    binary=pathlib.Path(lane['binary']);assert sha(binary)==lane['binary_sha256']
    receipt=json.loads(pathlib.Path(lane['build_receipt']).read_text());assert receipt['source_commit']==lane['source_commit'] and receipt['binary_sha256']==lane['binary_sha256']
    audit=out.with_name(out.name+'-wrapper.json');record={'lane':a.lane,'started_unix':time.time(),'active_case_manifest_sha256':sha(pathlib.Path(config['active_case_manifest'])),'runner_sha256':sha(BASE/'harness/run_c6_capacity.py'),'configuration_manifest_sha256':sha(a.manifest),'case':case,'no_retry':True,'private_features':'default disabled; runner removes inherited PUSHGO_* settings; no feature enable flags'}
    if lane['engine']=='mysql':record['before_budget']=budget(config,a.lane.replace('-','_')+'_before',True)
    save(out.with_name(out.name+'-preflight.json'),record)
    helper=runner.load_helper(pathlib.Path(lane['db_helper']))
    def bounded(arguments,stdin=None,environment=None):
        try:r=subprocess.run(helper.D+runner.scoped_db_arguments(lane['engine'],arguments),input=stdin,text=True,capture_output=True,timeout=10,env=environment)
        except subprocess.TimeoutExpired:raise runner.safe_subprocess_timeout(10) from None
        if r.returncode:raise RuntimeError('owned boundary observation failed; command/output withheld')
        return r.stdout.strip()
    helper.run=bounded
    def statements(label):
        save(out.with_name(out.name+'-'+label+'-statement-counters.json'),db_statement_observer.capture(helper,lane['engine'],case['database']))
    statements('before')
    command=[sys.executable,'-B',str(BASE/'harness/run_c6_capacity.py'),'--out',str(out),'--engine',lane['engine'],'--binary',str(binary),'--db-url-file',case['url_file'],'--db-helper',lane['db_helper'],'--build-receipt',lane['build_receipt'],'--source-root',config['source_root'],'--source-identity',lane['source_identity'],'--source-commit',lane['source_commit'],'--kernel-sampler',config['kernel_sampler'],'--environment-identity',config['environment_identity'],'--comparison-arm',lane['comparison_arm'],'--authorized-window','root-exclusive-c6']
    try:
        with out.with_name(out.name+'-runner.log').open('x') as log:result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
        record['runner_returncode']=result.returncode
    finally:
        if lane['engine']=='mysql':
            try:record['after_budget']=budget(config,a.lane.replace('-','_')+'_after',False)
            except BaseException as error:record['after_budget_failure_class']=type(error).__name__;record['further_lane_allowed']=False
        try:
            statements('after')
            if lane['engine']=='mysql':
                before=json.loads(out.with_name(out.name+'-before-statement-counters.json').read_text())
                after=json.loads(out.with_name(out.name+'-after-statement-counters.json').read_text())
                save(out.with_name(out.name+'-server-row-lock-delta.json'),db_statement_observer.server_row_lock_delta(before,after))
        except BaseException as error:record['after_statements_failure_class']=type(error).__name__;record['further_lane_allowed']=False
        record['finished_unix']=time.time();record['next_lane_not_started']=True;record['instrumentation_reset']=config['instrumentation_reset'];record['pinned_artifacts']=config['pinned_artifacts'];save(audit,record)
    reductions={}
    if all((out/name).exists() for name in ('expected-targets.jsonl','commits.bin','telemetry.json')):
        with (out/'exact-commit-summary.json').open('x') as log:r=subprocess.run([sys.executable,'-B',str(BASE/'harness/reduce_commits.py'),'--expected',str(out/'expected-targets.jsonl'),'--stream',str(out/'commits.bin'),'--telemetry',str(out/'telemetry.json'),'--scratch',str(out/'commit-reduction.sqlite')],stdout=log,stderr=subprocess.STDOUT)
        reductions['commits_returncode']=r.returncode
    else:reductions['exact_commit_unavailable']='missing final observer accounting; preserve full expected denominator and raw events, never fabricate telemetry'
    if out.exists():
        with (out/'resource-summary.json').open('x') as log:r=subprocess.run([sys.executable,'-B',str(BASE/'harness/summarize_resources_final.py'),str(out)],stdout=log,stderr=subprocess.STDOUT)
        reductions['resources_returncode']=r.returncode
    save(out.with_name(out.name+'-reductions.json'),reductions)
    raise SystemExit(result.returncode or int(record.get('further_lane_allowed') is False) or int(any(v!=0 for k,v in reductions.items() if k.endswith('_returncode'))))
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',required=True,type=pathlib.Path);p.add_argument('--lane',required=True,choices=['mysql-old','mysql-final']);p.add_argument('--authorized-window',required=True);main(p.parse_args())
