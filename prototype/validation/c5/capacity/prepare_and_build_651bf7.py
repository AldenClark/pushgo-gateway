#!/usr/bin/env python3
"""Authorized final C5 observer build. One shared target, sparse linked source view."""
import hashlib,json,os,pathlib,shutil,subprocess,time
BASE=pathlib.Path(__file__).resolve().parent
ROOT=BASE.parents[1]/'c-single-ledger-contract-20261015/workspace-final'
OUT=BASE/'final-651bf7';VIEW=OUT/'source-view'
COMMIT='651bf7e7e4691bd5a78b36625ff34b693be83590'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):
    with path.open('x') as f:json.dump(value,f,indent=2);f.write('\n')
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()==COMMIT
assert not subprocess.check_output(['git','diff','HEAD','--binary'],cwd=ROOT)
tracked=[os.fsdecode(p) for p in subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).split(b'\0') if p]
original={name:sha(ROOT/name) for name in tracked if (ROOT/name).is_file()}
normal=BASE.parent/'binaries/c5-final-ordinary-sqlite-pg-mysql'
native=BASE.parent/'binaries/c5-final-shared-native-tests'
assert sha(normal)=='3204f8ac126282e74980eaffec386ab9ffc67f028f8bbcd15f47c9eb284f8298'
assert sha(native)=='173d98eab6eb7a9b4ba287471ef519219d5ee1fa2675d2e5693f09e527aae032'
save(OUT/'before-build-preservation.json',{'source_commit':COMMIT,'tracked_file_sha256':original,
    'normal_fixture_sha256':sha(normal),'native_test_sha256':sha(native),
    'target':str(ROOT/'prototype/target'),'only_target':True,'no_product_source_edits':True})
VIEW.mkdir(exist_ok=False)
overlay=OUT/'overlay'
overrides={str(p.relative_to(overlay)):p for p in overlay.rglob('*') if p.is_file()}
def populate(rel):
    dst=VIEW/rel;src=ROOT/rel
    if rel in overrides:
        dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(overrides[rel],dst);return
    prefix=(rel+'/') if rel else ''
    children={name[len(prefix):].split('/')[0] for name in set(original)|set(overrides) if name.startswith(prefix)}
    if not any(name==rel or name.startswith(prefix) for name in overrides):
        dst.parent.mkdir(parents=True,exist_ok=True);dst.symlink_to(src,target_is_directory=src.is_dir());return
    dst.mkdir(parents=True,exist_ok=True)
    for child in sorted(children):populate(prefix+child)
for top in sorted({p.split('/')[0] for p in set(original)|set(overrides)}):populate(top)
modified={name:sha(VIEW/name) for name in set(original)|set(overrides) if (VIEW/name).is_file()}
identity={'source_commit':COMMIT,'source_tree':subprocess.check_output(['git','show','-s','--format=%T',COMMIT],cwd=ROOT,text=True).strip(),
    'source_root':str(VIEW),'source_sha256':modified,'original_source_sha256':original,
    'instrumentation_patch_sha256':sha(OUT/'observer.patch'),
    'source_view':'sparse observer file overrides; all unchanged paths link to exact final candidate bytes; identity rechecked before workload'}
save(OUT/'source-identity.json',identity)
env=os.environ.copy();env['CARGO_TARGET_DIR']=str(ROOT/'prototype/target')
command=['cargo','+1.97.1','build','--locked','--offline','--release','--manifest-path',str(VIEW/'prototype/Cargo.toml'),
    '--features','commit-observer','--bin','free_architecture_fixture']
started=time.time()
with (OUT/'build.log').open('x') as log:result=subprocess.run(command,cwd=VIEW,env=env,stdout=log,stderr=subprocess.STDOUT)
if result.returncode:
    save(OUT/'first-failure.json',{'stage':'observer-build','returncode':result.returncode,'no_retry':True});raise SystemExit(result.returncode)
binary=OUT/'c5-observer';shutil.copy2(ROOT/'prototype/target/release/free_architecture_fixture',binary)
assert original=={name:sha(ROOT/name) for name in original},'candidate bytes changed during build'
assert sha(normal)=='3204f8ac126282e74980eaffec386ab9ffc67f028f8bbcd15f47c9eb284f8298'
assert sha(native)=='173d98eab6eb7a9b4ba287471ef519219d5ee1fa2675d2e5693f09e527aae032'
save(OUT/'build.json',{'source_commit':COMMIT,'source_tree':identity['source_tree'],'binary':str(binary),
    'binary_sha256':sha(binary),'source_identity_sha256':sha(OUT/'source-identity.json'),
    'rustc':subprocess.check_output(['rustc','+1.97.1','-Vv'],text=True),'command':command,
    'elapsed_seconds':time.time()-started,'profile':{'name':'release','opt-level':3,'lto':'fat','codegen-units':1,'panic':'abort'},
    'candidate_source_unchanged':True,'normal_test_frozen_preserved':True})
print(json.dumps({'status':'BUILD_PASS','binary_sha256':sha(binary),'elapsed_seconds':time.time()-started}),flush=True)
