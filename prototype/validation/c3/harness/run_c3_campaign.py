#!/usr/bin/env python3
"""Plan-only by default. No product build, fixture, or mock until --execute."""
import argparse,datetime,hashlib,json,pathlib,subprocess,sys
HERE=pathlib.Path(__file__).resolve().parent;OUT=HERE.parent;GATEWAY=HERE.parents[3]
def cases(mode='ab',diagnostics=False,run_prefix='',quiescence=False):
    rows=[]
    for repeat in [1,2]:
        variants=['BASELINE','CANDIDATE'] if mode=='ab' else ['BASELINE']
        if repeat==2:variants.reverse()
        for rate in [128,256]:
            for variant in variants:rows.append(dict(label=f'{variant.lower()}-offer{rate}-r{repeat}',variant=variant,scenario='sustained',rate=rate,seconds=10,repeat=repeat))
    if diagnostics:
        for scenario in ['db-block','fanout','cleanup']:
            for variant in (['BASELINE','CANDIDATE'] if mode=='ab' else ['BASELINE']):
                rows.append(dict(label=f'{variant.lower()}-{scenario}-r1',variant=variant,scenario=scenario,repeat=1))
    if quiescence:
        assert mode=='ab','quiescence candidate requires matched AB artifact set'
        for scenario in ['idle','falloff']:
            rows.append(dict(label=f'candidate-{scenario}-r1',variant='CANDIDATE',scenario=scenario,repeat=1))
    for row in rows:
        row['targets_per_message']=32 if row['scenario']=='fanout' else 16
        row['messages']=row['rate']*row['seconds'] if row.get('rate') else 2 if row['scenario']=='fanout' else 0 if row['scenario']=='idle' else 67 if row['scenario']=='falloff' else 16
        row['targets']=row['messages']*row['targets_per_message']
    if run_prefix:
        assert all(ch.isascii() and (ch.isalnum() or ch=='-') for ch in run_prefix),'invalid run prefix'
        prefix=run_prefix.rstrip('-')+'-'
        for row in rows:row['label']=prefix+row['label']
    return rows

def validate_artifact(name,a):
    assert hashlib.sha256(pathlib.Path(a['binary']).read_bytes()).hexdigest()==a['binary_sha256'],name+': binary changed'
    receipt=pathlib.Path(a['build_receipt']);assert hashlib.sha256(receipt.read_bytes()).hexdigest()==a['build_receipt_sha256'],name+': receipt changed'
    built=json.loads(receipt.read_text());root=pathlib.Path(a['source_root'])
    if a.get('source_archive'):
        identity_path=pathlib.Path(a['source_archive_identity'])
        assert hashlib.sha256(identity_path.read_bytes()).hexdigest()==a['source_archive_identity_sha256'],name+': archive identity changed'
        identity=json.loads(identity_path.read_text())
        assert identity['source_commit']==a['source_commit'] and identity['source_tree']==a['source_tree'],name+': archive commit/tree differs'
        assert identity['source_sha256']==a['source_sha256'],name+': archive source mapping differs'
        assert pathlib.Path(identity['source_root']).resolve()==root.resolve(),name+': archive path differs'
        actual_tree=subprocess.check_output(['git','show','-s','--format=%T',a['source_commit']],cwd=a['git_object_repository'],text=True).strip()
        assert actual_tree==a['source_tree'],name+': git object tree differs'
        files={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
        assert files==set(a['source_sha256']),name+': archive file set differs'
    else:
        assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==a['source_commit'],name+': commit changed'
    changed={}
    assert built['source_commit']==a['source_commit'],name+': receipt/source commit differs'
    assert built['binary_sha256']==a['binary_sha256'],name+': receipt/binary differs'
    source_hashes=built.get('source_sha256',a.get('source_sha256'))
    assert source_hashes,name+': no frozen source hash mapping'
    for p,old in source_hashes.items():
        now=hashlib.sha256((root/p).read_bytes()).hexdigest()
        if now!=old:changed[p]={'build':old,'observed':now}
    assert hashlib.sha256(pathlib.Path(a['profiling_source']).read_bytes()).hexdigest()==a['profiling_schema_sha256'],name+': profiling schema changed'
    allowed=set(a.get('documentation_drift_allowlist',[]))
    assert set(changed)<=allowed,name+': source changed since build'
    assert hashlib.sha256(pathlib.Path(a['kernel_sampler']).read_bytes()).hexdigest()==a['kernel_sampler_sha256'],name+': sampler changed'
    return {'documentation_drift':changed,'compiled_source_hashes_match':True}

def command(row,a):
    cmd=[sys.executable,'-B',str(HERE/'run_profile_capacity.py'),'--binary',a['binary'],'--fixture-source',a['fixture_source'],
      '--source-root',a['source_root'],'--build-receipt',a['build_receipt'],'--variant',row['variant'],
      '--out',str(OUT/'runs'/row['label']),'--scenario',row['scenario'],'--repeat',str(row['repeat']),
      '--engine','free','--provider-budget','32','--claim-quantum','32','--aggregate-observer',
      '--provider-delay-ms','20','--credential-mode','remote','--stats-path','/__fixture/stats','--kernel-sampler',a['kernel_sampler']]
    if a.get('source_archive'):cmd+=['--source-archive-identity',a['source_archive_identity']]
    if row['scenario']=='idle':cmd+=['--idle-seconds','60']
    if row['scenario']=='falloff':cmd+=['--falloff-idle-seconds','10','--vmmap']
    if row.get('rate'):cmd+=['--capacity-rates',str(row['rate']),'--stage-seconds',str(row['seconds'])]
    if row['scenario']=='fanout':cmd+=['--fanout-per-provider','16']
    return cmd

def main():
    global OUT,GATEWAY
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--mode',choices=['ab','baseline'],default='ab')
    parser.add_argument('--diagnostics',action='store_true');parser.add_argument('--select',help='Exact labels only; no implicit retries')
    parser.add_argument('--quiescence',action='store_true',help='Candidate only: idle60s and burst64/falloff10s once each')
    parser.add_argument('--run-prefix',default='',help='Separate immutable campaign labels, e.g. matched')
    parser.add_argument('--manifest',type=pathlib.Path);parser.add_argument('--execute',action='store_true')
    parser.add_argument('--out',type=pathlib.Path,help='Fresh external experiment directory required with --execute')
    parser.add_argument('--gateway-root',type=pathlib.Path,default=GATEWAY,help='Explicit checkout used only as child cwd')
    args=parser.parse_args();rows=cases(args.mode,args.diagnostics,args.run_prefix,args.quiescence)
    if args.select:
        labels=set(args.select.split(','));rows=[r for r in rows if r['label'] in labels]
        assert {r['label'] for r in rows}==labels,'unknown case'
    plan={'cases':rows,'run_prefix':args.run_prefix,'H_per_provider':32,'claim_quantum':32,'provider_delay_ms':20,
      'normal_targets_per_message':16,'public_max_fanout_targets_per_message':32,'rate_unit':'messages per second; rate128/256 does not mean recipients',
      'stats_path':'/__fixture/stats','credential_mode':'remote synthetic Token Service',
      'observation':'independent durable SQL target/receipt+wire+Pull/ACK+process exit; complete peerJSONL not ring',
      'quiescence_cases':2 if args.quiescence else 0,'maximum_primary_cases':8,'diagnostic_cases':6 if args.mode=='ab' else 3,
      'limits':'all current profiling overhead fixed on both sides; no new architecture ranking; first failure stops, no retry or adaptive timeout'}
    print(json.dumps(plan,indent=2),flush=True)
    if not args.execute:return
    assert args.out,'--out required for execution; never write runs into the source package'
    OUT=args.out.resolve();OUT.mkdir(parents=True,exist_ok=False)
    GATEWAY=args.gateway_root.resolve()
    assert args.manifest,'frozen manifest required'
    manifest=json.loads(args.manifest.read_text());variants={r['variant'] for r in rows}
    assert manifest['comparison_claim']=='instrumented-full-candidate-hotspot-ab','no architecture ranking manifest accepted'
    assert manifest['effective_profile']=={'opt_level':3,'lto':'fat','codegen_units':1,'panic':'abort','tokio_workers':4}
    if args.mode=='ab':
        assert manifest['artifacts']['BASELINE']['profiling_schema_sha256']==manifest['artifacts']['CANDIDATE']['profiling_schema_sha256'],'profiling overhead/schema must match'
    validation={v:validate_artifact(v,manifest['artifacts'][v]) for v in variants}
    assert rows,'empty campaign'
    receipt=OUT/('campaign-'+rows[0]['label']+'.json')
    with receipt.open('x') as f:json.dump({'plan':plan,'manifest':manifest,'source_validation':validation,
      'coordinator_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()},f,indent=2)
    # Archive actual bytes before any fixture/mock starts, including shared peer.
    archive=OUT/'executed-sources'/receipt.stem;archive.mkdir(parents=True,exist_ok=False)
    for name in ['run_c3_campaign.py','run_profile_capacity.py','c3_mock.py','reduce_profile_capacity.py','analyse_c2.py','analyse_c1_base.py','resource_monitor.py','resource-monitor-source-provenance.json','common.py']:
        (archive/name).write_bytes((HERE/name).read_bytes())
    for row in rows:
        print('START '+row['label'],flush=True);result=subprocess.run(command(row,manifest['artifacts'][row['variant']]),cwd=GATEWAY)
        print(f'END {row["label"]} exit={result.returncode}',flush=True)
        if result.returncode:raise SystemExit(result.returncode)
        # Reduce only after this lane's joined teardown, before another launch.
        run=OUT/'runs'/row['label']
        with (run/'profile-summary.json').open('x') as stream:
            subprocess.run([sys.executable,'-B',str(HERE/'reduce_profile_capacity.py'),str(run)],stdout=stream,check=True)
        reduced=json.loads((run/'profile-summary.json').read_text())[0]
        direct=reduced.get('direct_timing_phase_deltas',{}).get('first-all-targets-sql-visible',{})
        compact={'label':row['label'],'eligible':reduced['performance_eligible'],
            'elapsed_s':json.loads((run/'result.json').read_text())['elapsed_seconds'],
            'targets':reduced.get('actual_unique_targets_excluding_warmup'),
            'first_sql_s':reduced.get('first_sql_all_receipts_visible_seconds'),
            'completion_rate_including_drain':reduced.get('jobs_per_second_until_first_sql_all_receipts_visible'),
            'producer_backlog_peak':reduced.get('producer_backlog_peak'),
            'timing_mean_us':{name:h.get('mean_us') for name,h in direct.items()}}
        print('SUMMARY '+json.dumps(compact,sort_keys=True),flush=True)
if __name__=='__main__':main()
