#!/usr/bin/env python3
"""One root-authorized lane only; preserve every return code, never retry/advance."""
import argparse,hashlib,json,pathlib,subprocess,sys,time
BASE=pathlib.Path(__file__).resolve().parent;OUT=BASE/'final-651bf7'
COMMIT='651bf7e7e4691bd5a78b36625ff34b693be83590'
def save(path,row):
    with path.open('x') as f:json.dump(row,f,indent=2);f.write('\n')
def main(engine,attempt):
    assert (OUT/'build.json').exists()
    helper=BASE.parent/'env/isolated_db.py';label='final_'+engine+'_'+attempt
    creation=subprocess.run([sys.executable,'-B',str(helper),'create',engine,label],capture_output=True,text=True)
    assert creation.returncode==0,'fresh DB creation failed: '+creation.stderr
    case=json.loads(creation.stdout);lane=engine+'-'+attempt;save(OUT/(lane+'-case.json'),case)
    run=OUT/('run-'+lane)
    sampler=BASE.parents[1]/'c-client-loop-gate-20261015/binaries/c3_pid_rusage'
    command=[sys.executable,'-B',str(BASE/'run_c5_capacity_final.py'),'--out',str(run),
        '--binary',str(OUT/'c5-observer'),'--db-url-file',case['url_file'],'--db-helper',str(helper),
        '--build-receipt',str(OUT/'build.json'),'--source-root',str(OUT/'source-view'),
        '--source-identity',str(OUT/'source-identity.json'),'--source-commit',COMMIT,'--engine',engine,
        '--kernel-sampler',str(sampler),'--authorized-window','root-exclusive-c5']
    save(OUT/(lane+'-command.json'),{'command':command,'source_commit':COMMIT,
        'runner_sha256':hashlib.sha256((BASE/'run_c5_capacity_final.py').read_bytes()).hexdigest(),'started_unix':time.time()})
    with (OUT/(lane+'-runner.log')).open('x') as log:result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
    reductions={}
    if all((run/name).exists() for name in ('expected-targets.jsonl','commits.bin','telemetry.json')):
        reduction=[sys.executable,'-B',str(BASE/'reduce_commits.py'),'--expected',str(run/'expected-targets.jsonl'),
            '--stream',str(run/'commits.bin'),'--telemetry',str(run/'telemetry.json'),'--scratch',str(run/'commit-reduction.sqlite')]
        with (run/'exact-commit-summary.json').open('x') as log:r=subprocess.run(reduction,stdout=log,stderr=subprocess.STDOUT)
        reductions['commits_returncode']=r.returncode
    if run.exists():
        with (run/'resource-summary.json').open('x') as log:
            r=subprocess.run([sys.executable,'-B',str(BASE/'summarize_resources_final.py'),str(run)],stdout=log,stderr=subprocess.STDOUT)
        reductions['resources_returncode']=r.returncode
    save(OUT/(lane+'-execution.json'),{'runner_returncode':result.returncode,'reductions':reductions,
        'finished_unix':time.time(),'next_lane_not_started':True,'no_retry':True})
    print(json.dumps({'engine':engine,'runner_returncode':result.returncode,'reductions':reductions,'run':str(run)}),flush=True)
    raise SystemExit(result.returncode or int(any(v!=0 for v in reductions.values())))
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('engine',choices=('pg','mysql'));p.add_argument('--attempt',required=True,choices=('01','02'))
    arguments=p.parse_args();main(arguments.engine,arguments.attempt)
