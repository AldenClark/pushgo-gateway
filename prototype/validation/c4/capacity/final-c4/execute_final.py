#!/usr/bin/env python3
"""Exact local final-C4 two-lane followup; intentionally not a portable packager."""
import difflib,hashlib,json,os,pathlib,shutil,subprocess,sys,tarfile,time
OUT=pathlib.Path(__file__).resolve().parent;BASE=OUT.parent;HERE=BASE/'harness'
REPO=BASE.parents[1]/'c-single-ledger-contract-20261015'/'workspace-final'
OLD=BASE.parents[1]/'c-client-loop-gate-20261015'
COMMIT='d925b97fe30068b66aefb66e33284831df6d8e4f'
TARGET=REPO/'prototype'/'target'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(path,value):
    with path.open('x') as f:json.dump(value,f,indent=2);f.write('\n')
phase='source-freeze'
try:
    save(OUT/'execution-start.json',{'source_commit':COMMIT,'approved_cases':2,'target':str(TARGET),
        'started_unix':time.time(),'python':sys.version,'coordinator_sha256':sha(pathlib.Path(__file__)),
        'normal_target_binary_before':sha(TARGET/'release'/'free_architecture_fixture'),
        'normal_binary_preservation':'root copied normal/test artifacts to outer OUT/binaries before authorizing this window'})
    archive=OUT/'source-original.tar'
    with archive.open('xb') as f:subprocess.run(['git','archive','--format=tar',COMMIT],cwd=REPO,stdout=f,check=True)
    source=OUT/'source';source.mkdir(exist_ok=False)
    with tarfile.open(archive) as f:f.extractall(source,filter='data')
    original={str(p.relative_to(source)):sha(p) for p in source.rglob('*') if p.is_file()}
    changes={}
    def edit(rel,old,new):
        p=source/rel;text=p.read_text();assert text.count(old)==1,(rel,'anchor count',text.count(old))
        updated=text.replace(old,new);p.write_text(updated)
        changes[rel]=''.join(difflib.unified_diff(text.splitlines(True),updated.splitlines(True),fromfile='a/'+rel,tofile='b/'+rel))
    edit('prototype/Cargo.toml','[dependencies]','[features]\ncommit-observer = []\n\n[dependencies]')
    edit('prototype/src/lib.rs','pub mod credentials;','#[cfg(feature = "commit-observer")]\npub mod commit_observer;\npub mod credentials;')
    anchor='''            .phase(Path::Receipt, Phase::Commit, tx.commit())
            .await?;
        drop(profile_connection);'''
    edit('prototype/src/store.rs',anchor,'''            .phase(Path::Receipt, Phase::Commit, tx.commit())
            .await?;
        #[cfg(feature = "commit-observer")]
        if changed > 0 { crate::commit_observer::committed(&ticket.delivery_id, &ticket.device_key, ticket.attempt_id, state); }
        drop(profile_connection);''')
    rel='prototype/src/bin/free_architecture_fixture.rs';p=source/rel;before=p.read_text();text=before
    for old,new in [('use clap::Parser;','#[cfg(feature = "commit-observer")]\n#[path = "support/commit_observer_fixture.rs"]\nmod commit_observer_fixture;\nuse clap::Parser;'),('    let cli = Cli::parse();','''    let cli = Cli::parse();
    #[cfg(feature = "commit-observer")]
    let commit_session = std::env::var_os("C4_COMMIT_STREAM").map(|path|
        commit_observer_fixture::Session::start(std::path::Path::new(&path))).transpose()?;'''),('    if report.panicked != 0 || report.aborted != 0 || report.failed != 0 {','''    #[cfg(feature = "commit-observer")]
    if let Some(session) = commit_session { session.finish()?; }
    if report.panicked != 0 || report.aborted != 0 || report.failed != 0 {''')]:
        assert text.count(old)==1;text=text.replace(old,new)
    p.write_text(text);changes[rel]=''.join(difflib.unified_diff(before.splitlines(True),text.splitlines(True),fromfile='a/'+rel,tofile='b/'+rel))
    for src,dst in [('observer_library.rs','prototype/src/commit_observer.rs'),('observer_fixture.rs','prototype/src/bin/support/commit_observer_fixture.rs')]:
        data=(HERE/src).read_text();(source/dst).parent.mkdir(exist_ok=True);(source/dst).write_text(data)
        changes[dst]=''.join(difflib.unified_diff([],data.splitlines(True),fromfile='/dev/null',tofile='b/'+dst))
    patch=''.join(changes.values());(OUT/'observer.patch').write_text(patch)
    normalize=lambda text:[line for line in text.splitlines() if line[:1] in ['+','-'] and not line.startswith(('+++','---'))]
    assert normalize(patch)==normalize((BASE/'19cc-observer.patch').read_text()),'measurement code differs'
    identity={'source_commit':COMMIT,'source_tree':subprocess.check_output(['git','show','-s','--format=%T',COMMIT],cwd=REPO,text=True).strip(),
        'source_root':str(source),'archive_sha256':sha(archive),'original_source_sha256':original,
        'source_sha256':{str(p.relative_to(source)):sha(p) for p in source.rglob('*') if p.is_file()},
        'instrumentation_patch_sha256':sha(OUT/'observer.patch'),'modified_files':list(changes),
        'observer_added_deleted_payload_identical_to19cc':True}
    identity_path=OUT/'source-identity.json';save(identity_path,identity)
    save(OUT/'static-review.json',{'status':'PREPARED_EXACT_FINAL_COMMIT','source_commit':COMMIT,'modified_files':list(changes),
        'observer_added_deleted_payload_identical':True,'source_files':len(identity['source_sha256']),
        'source_root_candidate_untouched':True,'runs_started':0})
    phase='build-final-c4'
    env=os.environ.copy();env['CARGO_TARGET_DIR']=str(TARGET)
    cmd=['cargo','+1.97.1','build','--locked','--offline','--release','--manifest-path',str(source/'prototype'/'Cargo.toml'),
        '--features','commit-observer','--bin','free_architecture_fixture']
    started=time.time()
    with (OUT/'build.log').open('x') as log:result=subprocess.run(cmd,cwd=source,env=env,stdout=log,stderr=subprocess.STDOUT)
    assert result.returncode==0,'finalC4 build failed; stop'
    binary=OUT/'c4-final-observer';shutil.copy2(TARGET/'release'/'free_architecture_fixture',binary)
    receipt={'source_commit':COMMIT,'source_tree':identity['source_tree'],'source_sha256':identity['source_sha256'],
        'binary':str(binary),'binary_sha256':sha(binary),'rustc':subprocess.check_output(['rustc','+1.97.1','-Vv'],text=True),
        'cargo':subprocess.check_output(['cargo','+1.97.1','-V'],text=True),'command':cmd,'elapsed_seconds':time.time()-started,
        'profile':{'name':'release','opt-level':3,'lto':'fat','codegen-units':1,'panic':'abort'},
        'lock_sha256':sha(source/'prototype'/'Cargo.lock'),'fixture_sha256':sha(source/'prototype'/'src'/'bin'/'free_architecture_fixture.rs'),
        'instrumentation_patch_sha256':identity['instrumentation_patch_sha256']}
    receipt_path=OUT/'build.json';save(receipt_path,receipt)
    print('BUILD PASSED finalC4 '+receipt['binary_sha256'],flush=True)
    (OUT/'runs').mkdir(exist_ok=False)
    for repeat in (1,2):
        phase='c4-final-offer256-r'+str(repeat);run=OUT/'runs'/phase
        command=[sys.executable,'-B',str(HERE/'run_profile_capacity.py'),'--binary',str(binary),
            '--fixture-source',str(source/'prototype'/'src'/'bin'/'free_architecture_fixture.rs'),
            '--source-root',str(source),'--source-archive-identity',str(identity_path),'--build-receipt',str(receipt_path),
            '--variant','CANDIDATE','--out',str(run),'--scenario','sustained','--repeat',str(repeat),'--engine','free',
            '--provider-budget','32','--claim-quantum','32','--aggregate-observer','--provider-delay-ms','20',
            '--credential-mode','remote','--stats-path','/__fixture/stats','--kernel-sampler',str(OLD/'binaries'/'c3_pid_rusage'),
            '--capacity-rates','256','--stage-seconds','10']
        print('START '+phase,flush=True)
        with (OUT/(phase+'-runner.log')).open('x') as log:result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
        assert result.returncode==0,phase+' failed; stop'
        with (run/'exact-commit-summary.json').open('x') as log:
            result=subprocess.run([sys.executable,'-B',str(HERE/'reduce_commits.py'),'--expected',str(run/'expected-targets.jsonl'),
                '--stream',str(run/'commits.bin'),'--telemetry',str(run/'telemetry.json'),'--scratch',str(run/'commit-reduction.sqlite')],stdout=log,stderr=subprocess.STDOUT)
        assert result.returncode==0,phase+' commit reduction failed; stop'
        with (run/'profile-summary.json').open('x') as log:
            result=subprocess.run([sys.executable,'-B',str(HERE/'reduce_profile_capacity.py'),str(run)],stdout=log,stderr=subprocess.STDOUT)
        assert result.returncode==0,phase+' profile reduction failed; stop'
        exact=json.loads((run/'exact-commit-summary.json').read_text())
        assert exact['offered_targets']==40960 and exact['outcomes']=={'accepted':40960}
        assert json.loads((run/'profile-summary.json').read_text())[0]['performance_eligible']
        print('PASSED '+phase+' '+json.dumps(exact['success']),flush=True)
    save(OUT/'execution-complete.json',{'status':'PASSED_FINAL_C4_2','source_commit':COMMIT,'finished_unix':time.time(),'quiet':True,
        'no_extra_lanes':True,'all_observer_threads_joined':True})
except BaseException as error:
    save(OUT/'first-failure.json',{'status':'FAILED_STOPPED','phase':phase,'error':repr(error),'unix':time.time(),
        'no_retry':True,'no_deadline_extension':True})
    raise
