#!/usr/bin/env python3
"""Plan-only unless --execute. Nine bounded regression lanes, not a matched A/B claim."""
import argparse,hashlib,json,pathlib,subprocess,sys
import run_c3_campaign as campaign
HERE=pathlib.Path(__file__).resolve().parent
DEFAULT_OUT=HERE.parent

def cases():
    spec=[('CANDIDATE','db-block',None),('BASELINE','fanout',None),('CANDIDATE','fanout',None),
          ('BASELINE','cleanup',None),('CANDIDATE','cleanup',None),('CANDIDATE','idle',None),
          ('CANDIDATE','falloff',None),('CANDIDATE','sustained',128),('CANDIDATE','sustained',256)]
    rows=[]
    for variant,scenario,rate in spec:
        count=rate*10 if rate else 2 if scenario=='fanout' else 0 if scenario=='idle' else 67 if scenario=='falloff' else 16
        recipients=32 if scenario=='fanout' else 16
        label=f'writerfix-{variant.lower()}-'+(f'offer{rate}' if rate else scenario)+'-r1'
        row={'label':label,'variant':variant,'scenario':scenario,'repeat':1,'messages':count,
             'targets_per_message':recipients,'targets':count*recipients}
        if rate:row.update(rate=rate,seconds=10)
        rows.append(row)
    return rows

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=pathlib.Path)
    p.add_argument('--out',type=pathlib.Path,help='Fresh external output directory required with --execute')
    p.add_argument('--select',help='Exact declared labels only; no implicit retry')
    p.add_argument('--execute',action='store_true')
    args=p.parse_args();rows=cases()
    if args.select:
        selected=set(args.select.split(','));rows=[r for r in rows if r['label'] in selected]
        assert {r['label'] for r in rows}==selected,'unknown case'
    assert rows,'empty plan'
    plan={'round':'writerfix-followup','cases':rows,'case_count':len(rows),
          'claim':'newcandidate functional/fault/quiescence/regression only; not an optimization matched A/B',
          'prior_primary8_identity':'10e59ec97230550216bc00aa3fe8c924b02510e1 candidate / cb0da19cfc1ca542e14a19e506a086a830103bcd control; never relabel as writerfix source',
          'preserved_failure':'matched-observerfix-baseline-db-block-r1 SQLite code5 owner-driver exit70; no retry of frozen control',
          'unchanged':{'H_per_provider':32,'claim_quantum':32,'provider_delay_ms':20,'normal_targets_per_message':16,
                       'public_max_fanout_targets_per_message':32,'body_bytes':1024,'db_block_seconds':2,
                       'sustained_input_seconds':10,'sustained_settle_timeout_seconds':180,
                       'idle_seconds':60,'falloff_idle_seconds':10,'stats_path':'/__fixture/stats'},
          'gate':'independent durable SQL target set + complete wire identity/content + Pull/ACK + joined shutdown; first failure stops, no timeout extension/retry'}
    print(json.dumps(plan,indent=2),flush=True)
    if not args.execute:return
    assert args.out,'--out required with --execute'
    assert args.manifest,'new frozen writerfix artifacts required'
    manifest=json.loads(args.manifest.read_text())
    assert manifest['comparison_claim']=='writer-fix-followup-regression-not-matched-ab'
    assert manifest['artifacts']['BASELINE']['source_commit']=='cb0da19cfc1ca542e14a19e506a086a830103bcd'
    assert manifest['artifacts']['CANDIDATE']['source_commit']!='10e59ec97230550216bc00aa3fe8c924b02510e1','writerfix needs new frozen candidate source'
    assert manifest['effective_profile']=={'opt_level':3,'lto':'fat','codegen_units':1,'panic':'abort','tokio_workers':4}
    assert manifest['artifacts']['BASELINE']['profiling_schema_sha256']==manifest['artifacts']['CANDIDATE']['profiling_schema_sha256']
    validation={v:campaign.validate_artifact(v,manifest['artifacts'][v]) for v in {r['variant'] for r in rows}}
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=False);campaign.OUT=out
    receipt=out/('campaign-'+rows[0]['label']+'.json')
    with receipt.open('x') as stream:json.dump({'plan':plan,'manifest':manifest,'source_validation':validation},stream,indent=2)
    archive=out/'executed-sources'/receipt.stem;archive.mkdir(parents=True,exist_ok=False)
    for name in ['run_writerfix_followup.py','run_c3_campaign.py','run_profile_capacity.py','c3_mock.py',
                 'reduce_profile_capacity.py','analyse_c2.py','analyse_c1_base.py','resource_monitor.py','common.py',
                 'resource-monitor-source-provenance.json','c3_pid_rusage.c']:
        (archive/name).write_bytes((HERE/name).read_bytes())
    for row in rows:
        print('START '+row['label'],flush=True)
        result=subprocess.run(campaign.command(row,manifest['artifacts'][row['variant']]),cwd=out)
        print(f'END {row["label"]} exit={result.returncode}',flush=True)
        if result.returncode:raise SystemExit(result.returncode)
        run=out/'runs'/row['label']
        with (run/'profile-summary.json').open('x') as stream:
            subprocess.run([sys.executable,'-B',str(HERE/'reduce_profile_capacity.py'),str(run)],stdout=stream,check=True)
        reduced=json.loads((run/'profile-summary.json').read_text())[0]
        print('SUMMARY '+json.dumps({'label':row['label'],'eligible':reduced['performance_eligible'],
              'targets':reduced.get('actual_unique_targets_excluding_warmup'),
              'first_sql_s':reduced.get('first_sql_all_receipts_visible_seconds'),
              'producer_backlog_peak':reduced.get('producer_backlog_peak')}),flush=True)
if __name__=='__main__':main()
