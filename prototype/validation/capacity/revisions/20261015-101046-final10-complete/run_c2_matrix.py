#!/usr/bin/env python3
"""Decision-focused C2 matrix. Default only prints plan; execution must be explicit."""
import argparse, hashlib, json, pathlib, subprocess, sys
HERE=pathlib.Path(__file__).resolve().parent
OUT=HERE.parent
GATEWAY=OUT.parents[2]

def cases():
    rows=[]
    def common(label, scenario, repeats=1, **options):
        for repeat in range(1,repeats+1):
            # Rotate order to reduce a fixed warmed-host ordering bias.
            variants=['CURRENT','C32','C2']
            variants=variants[(repeat-1)%3:]+variants[:(repeat-1)%3]
            for variant in variants:
                rows.append(dict(label=f'{label}-r{repeat}-{variant.lower()}',variant=variant,
                                 scenario=scenario,repeat=repeat,budget=32,**options))
    common('cold-long-idle','idle',idle_seconds=60)
    common('short-idle','idle',2,idle_seconds=8)
    common('very-low','low',2,low_gap_seconds=5)
    common('burst64','burst',2)
    common('fanout32','fanout',2,fanout_per_provider=16)
    for rate in [128,256]:
        common(f'offer{rate}', 'sustained',2,capacity_rates=str(rate),stage_seconds=10)
    common('offer64-long','sustained',capacity_rates='64',stage_seconds=30)
    common('falloff','falloff',2,vmmap=True)
    common('slow-fcm200ms','slow',2)
    # Fault source is deterministic; second receipt only when reproduction is
    # required, selected with --fault-repeat. Preserve the original first.
    common('provider429503','failures')
    common('db-block','db-block')
    common('recovery','recovery')
    for ceiling in [8,32,64,128]:
        rows.append(dict(label=f'ceiling{ceiling}-offer128-r1-c2',variant='C2',
                         scenario='sustained',repeat=1,budget=ceiling,
                         capacity_rates='128',stage_seconds=10,vmmap=True))
    return rows

def final_cases():
    rows=[dict(label='final-short-idle-r1-c2',variant='C2',scenario='idle',repeat=1,budget=32,idle_seconds=8),
          dict(label='final-falloff-r1-c2',variant='C2',scenario='falloff',repeat=1,budget=32,vmmap=True)]
    for budget,repeat in [(32,1),(64,1),(32,2)]:
        for rate in [128,256]:
            rows.append(dict(label=f'final-h{budget}-offer{rate}-r{repeat}-c2',variant='C2',scenario='sustained',repeat=repeat,budget=budget,capacity_rates=str(rate),stage_seconds=10))
    return rows

def final_boundary_cases():
    return [dict(label='final-bound32x60',variant='C2',scenario='sustained',repeat=1,budget=32,capacity_rates='32',stage_seconds=60),
            dict(label='final-bound64x30',variant='C2',scenario='sustained',repeat=1,budget=32,capacity_rates='64',stage_seconds=30)]

def command(row, artifacts):
    a=artifacts[row['variant']]
    cmd=[sys.executable,str(HERE/'run_compare.py'),'--binary',a['binary'],
         '--build-receipt',a['build_receipt'],'--fixture-source',a['fixture_source'],'--source-root',a['source_root'],
         '--variant',row['variant'],'--out',str(OUT/'runs'/row['label']),
         '--scenario',row['scenario'],'--repeat',str(row['repeat']),
         '--engine','existing' if row['variant']=='CURRENT' else 'free',
         '--provider-budget',str(row['budget']),'--aggregate-observer']
    if row['variant']=='C2': cmd+=['--claim-quantum',str(min(32,row['budget']))]
    if a.get('kernel_sampler'): cmd+=['--kernel-sampler',a['kernel_sampler']]
    for key in ['idle_seconds','low_gap_seconds','fanout_per_provider','capacity_rates','stage_seconds']:
        if key in row: cmd+=['--'+key.replace('_','-'),str(row[key])]
    if row.get('vmmap'):cmd+=['--vmmap']
    return cmd

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts',type=pathlib.Path,help='JSON CURRENT/C32/C2 {binary, binary_sha256, fixture_source, source_root, build_receipt, kernel_sampler}')
    parser.add_argument('--continue-current-capacity-500',action='store_true',help='Preserve FAILED CURRENT capacity HTTP500 observations and continue independent remaining cases')
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--select',help='Exact comma-separated labels; no implicit retry')
    parser.add_argument('--label-suffix',help='Fresh receipt label after an explicitly diagnosed harness repair')
    parser.add_argument('--smoke',action='store_true',help='Three burst lanes, one per variant')
    parser.add_argument('--final-boundary-two',action='store_true',help='Exactly two approved final H32 finite boundary observations, equal1920messages')
    parser.add_argument('--final-eight',action='store_true',help='Only the eight final-source affected C2 cases, no controls')
    parser.add_argument('--fault-repeat',choices=['failures','db-block','recovery'])
    parser.add_argument('--adjacent-ceilings',help='Two comma-separated positive ceilings: explicit second decision receipt')
    args=parser.parse_args()
    rows=cases()
    if args.final_eight:rows=final_cases()
    if args.final_boundary_two:rows=final_boundary_cases()
    if args.smoke:rows=[dict(label=f'smoke-burst64-{v.lower()}',variant=v,scenario='burst',repeat=1,budget=32) for v in ['CURRENT','C32','C2']]
    if args.fault_repeat:rows=[dict(label=f'fault-repro-{args.fault_repeat}-r2-{v.lower()}',variant=v,scenario=args.fault_repeat,repeat=2,budget=32) for v in ['CURRENT','C32','C2']]
    if args.adjacent_ceilings:
        ceilings=[int(v) for v in args.adjacent_ceilings.split(',')]
        assert len(ceilings)==2 and len(set(ceilings))==2 and all(v in [8,32,64,128] for v in ceilings)
        rows=[dict(label=f'ceiling{v}-offer128-r2-c2',variant='C2',scenario='sustained',repeat=2,budget=v,capacity_rates='128',stage_seconds=10,vmmap=True) for v in ceilings]
    if args.select:
        labels=args.select.split(','); rows=[r for r in rows if r['label'] in labels]
        assert {r['label'] for r in rows}==set(labels),'unknown label'
    if args.label_suffix:
        assert all(c.isalnum() or c=='-' for c in args.label_suffix)
        rows=[{**r,'label':r['label']+'-'+args.label_suffix} for r in rows]
    print(json.dumps({'case_count':len(rows),'cases':rows,'healthy_duration_budget_minutes':30,
      'history_gc':'NOT RUN until dedicated ordinary-contract oracle is provided; not an ordinary receipt capacity claim',
      'sustained_rule':'Report offered/HTTP-start/accepted/receipt rates and producer+DB backlog slope. No sustainable claim if either grows, input missed, or post-input drain is needed.',
      'execution':'serial; fresh DB/output per row; first failing row stops without retry'},indent=2),flush=True)
    if not args.execute:return
    assert args.artifacts,'--artifacts required for execution'
    artifacts=json.loads(args.artifacts.read_text())
    source_validation={}
    for variant in {r['variant'] for r in rows}:
        a=artifacts[variant]
        assert hashlib.sha256(pathlib.Path(a['binary']).read_bytes()).hexdigest()==a['binary_sha256'],f'{variant}: binary identity changed'
        assert pathlib.Path(a['build_receipt']).is_file(),f'{variant}: build provenance required'
        assert hashlib.sha256(pathlib.Path(a['build_receipt']).read_bytes()).hexdigest()==a['build_receipt_sha256'],f'{variant}: build provenance changed'
        if a.get('source_commit'):
            assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=a['source_root'],text=True).strip()==a['source_commit'],f'{variant}: source commit changed'
            built=json.loads(pathlib.Path(a['build_receipt']).read_text())
            changed={}
            for source_path,built_sha in built['source_sha256'].items():
                observed_sha=hashlib.sha256((pathlib.Path(a['source_root'])/source_path).read_bytes()).hexdigest()
                if observed_sha!=built_sha:changed[source_path]={'build_sha256':built_sha,'observed_sha256':observed_sha}
            assert all(p=='prototype/README.md' for p in changed),f'{variant}: compiled source bytes changed since build'
            source_validation[variant]={'documentation_only_drift':changed,'compiled_input_hashes_match':True,
              'policy':'Only the exact README path explicitly updated by root after final8 may differ; every other receipt input remains byte-identical.'}
        assert a.get('kernel_sampler'),f'{variant}: corrected Mach CPU/interrupt sampler required'
        assert hashlib.sha256(pathlib.Path(a['kernel_sampler']).read_bytes()).hexdigest()==a['kernel_sampler_sha256'],f'{variant}: kernel sampler changed'
    receipt=OUT/('matrix-'+rows[0]['label']+'.json')
    with receipt.open('x') as f:json.dump({'cases':rows,'artifacts':artifacts,'continue_current_capacity_http500':args.continue_current_capacity_500,'source_validation':source_validation,'runner_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()},f,indent=2)
    for row in rows:
        cmd=command(row,artifacts)
        print('START '+row['label'],flush=True)
        result=subprocess.run(cmd,cwd=GATEWAY)
        print(f'END {row["label"]} exit={result.returncode}',flush=True)
        if result.returncode:
            run=OUT/'runs'/row['label']
            failed=json.loads((run/'result.json').read_text()) if (run/'result.json').exists() else {}
            first=json.loads((run/'first-failure.json').read_text()) if (run/'first-failure.json').exists() else {}
            known_control_boundary=(args.continue_current_capacity_500 and row['variant']=='CURRENT'
              and row['scenario'] in ['sustained','high'] and first.get('path')=='/message'
              and first.get('status')==500 and failed.get('exit_codes',[-1])[-1]==0
              and failed.get('daemon_exited') and failed.get('log_readers_joined'))
            if not known_control_boundary:raise SystemExit(result.returncode)
            (run/'retained-failed-control-continuation.json').write_text(json.dumps({
              'status':'FAILED','performance_eligible':False,'policy':'explicit CURRENT capacity HTTP500 continuation only; no retry; no accepted-target correctness claim',
              'first_receipt':str(run/'first-failure.json')},indent=2)+'\n')
            print('RETAIN FAILED CONTROL; CONTINUE INDEPENDENT CASES '+row['label'],flush=True)
if __name__=='__main__':main()
