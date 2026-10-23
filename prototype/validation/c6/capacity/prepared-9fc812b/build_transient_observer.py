#!/usr/bin/env python3
"""Future authorized slot only. Save/apply eight sparse files, build once, freeze, restore.
Never import this file for preparation. No mutable symlink source view is used.
"""
import argparse,hashlib,json,os,pathlib,shutil,signal,stat,subprocess,sys,time
BASE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(BASE/'harness'));import source_provenance
COMMIT='9fc812b40880e0ffd2375b4c83bb920292bdf880'
NORMAL_SHA='b7a0683dd46dd5d167c93b5e960adde4423323fd2bf96b81f89c9846b4572af3'
def sha(data):return hashlib.sha256(data).hexdigest()
def file_sha(p):return sha(p.read_bytes())
def save(path,row):
    with path.open('x') as f:json.dump(row,f,indent=2);f.write('\n')
def git(root,args,**kw):return subprocess.check_output(['git',*args],cwd=root,**kw)
def git_blobs(root):
    listing=git(root,['ls-tree','-r','-z',COMMIT]);objects={}
    for entry in listing.split(b'\0'):
        if not entry:continue
        header,name=entry.split(b'\t',1);mode,kind,oid=header.split();assert kind==b'blob','unexpected gitlink; stop'
        objects[os.fsdecode(name)]=oid.decode()
    names=sorted(objects);request=''.join(objects[n]+'\n' for n in names).encode();p=subprocess.run(['git','cat-file','--batch'],input=request,capture_output=True,cwd=root);assert p.returncode==0
    result={};at=0
    for name in names:
        end=p.stdout.index(b'\n',at);header=p.stdout[at:end].split();assert header[1]==b'blob';size=int(header[2]);at=end+1;result[name]=p.stdout[at:at+size];at+=size;assert p.stdout[at:at+1]==b'\n';at+=1
    assert at==len(p.stdout);return result

def main(a):
    assert a.authorized_slot=='root-exclusive-c6-observer-9fc','explicit root slot required'
    root=a.source_root.resolve();prepared=a.prepared_overlay.resolve();out=a.out.resolve();assert not out.exists()
    assert git(root,['rev-parse','HEAD'],text=True).strip()==COMMIT
    prep=json.loads((prepared/'preparation.json').read_text());assert prep['source_commit_at_preparation']==COMMIT
    assert file_sha(a.normal_binary)==NORMAL_SHA,'frozen normal mismatch'
    blobs=git_blobs(root);original={name:sha(content) for name,content in blobs.items()};tree=git(root,['show','-s','--format=%T',COMMIT],text=True).strip()
    documentation_differences={}
    for name,content in blobs.items():
        p=root/name
        if p.is_file() and file_sha(p)==original[name]:continue
        if name.endswith('.md') or name.startswith('prototype/docs/'):
            documentation_differences[name]=file_sha(p) if p.is_file() else None;continue
        raise AssertionError(('non-document source differs from9fc',name))
    overlays={name:(prepared/'overlay'/name) for name in prep['overlay_sha256']};assert len(overlays)==8
    snapshots={}
    for name,p in overlays.items():
        assert file_sha(p)==prep['overlay_sha256'][name];target=root/name
        if name in original:assert target.is_file() and not target.is_symlink() and file_sha(target)==original[name]
        else:assert not target.exists(),'new observer file already exists'
        snapshots[name]={'existed':target.exists(),'sha256':file_sha(target) if target.exists() else None,'mode':stat.S_IMODE(target.stat().st_mode) if target.exists() else None}
    out.mkdir(parents=True);backup=out/'recovery-original-bytes';frozen=out/'overlay'
    for name,row in snapshots.items():
        dst=frozen/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(overlays[name],dst)
        if row['existed']:
            dst=backup/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(root/name,dst);assert file_sha(dst)==row['sha256']
    shutil.copy2(prepared/'observer.patch',out/'observer.patch');assert file_sha(out/'observer.patch')==prep['patch_sha256']
    save(out/'before-apply.json',{'source_commit':COMMIT,'source_tree':tree,'paths':snapshots,'documentation_differences_preserved':documentation_differences,'normal_binary':str(a.normal_binary.resolve()),'normal_sha256':NORMAL_SHA,'only_target':str(root/'prototype/target'),'overlay_preparation_sha256':file_sha(prepared/'preparation.json'),'builds_authorized':1})
    modified={**original,**prep['overlay_sha256']};identity={'source_commit':COMMIT,'source_tree':tree,'source_root':str(root),'source_sha256':modified,'original_source_sha256':original,'instrumentation_patch_sha256':prep['patch_sha256'],'source_view':'immutable Git objects plus eight frozen observer overrides; documentation differences excluded from compile identity and never modified','documentation_differences_preserved':documentation_differences}
    save(out/'source-identity.json',identity)
    command=['cargo','+1.97.1','build','--locked','--offline','--release','--manifest-path',str(root/'prototype/Cargo.toml'),'--features','commit-observer','--bin','free_architecture_fixture'];env=os.environ.copy();env['CARGO_TARGET_DIR']=str(root/'prototype/target');started=time.time();success=False;stage='apply'
    def terminate(signum,frame):raise SystemExit(128+signum)
    previous_handlers={sig:signal.signal(sig,terminate) for sig in (signal.SIGTERM,signal.SIGINT)}
    try:
        for name in overlays:
            target=root/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(frozen/name,target);assert file_sha(target)==prep['overlay_sha256'][name]
        stage='build'
        with (out/'build.log').open('x') as log:r=subprocess.run(command,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
        assert r.returncode==0,('observer build failed, no retry',r.returncode)
        stage='freeze';binary=out/'c5-observer';shutil.copy2(root/'prototype/target/release/free_architecture_fixture',binary)
        receipt={'source_commit':COMMIT,'source_tree':tree,'binary':str(binary),'binary_sha256':file_sha(binary),'source_identity_sha256':file_sha(out/'source-identity.json'),'rustc':subprocess.check_output(['rustc','+1.97.1','-Vv'],text=True),'command':command,'elapsed_seconds':time.time()-started,'profile':{'name':'release','opt-level':3,'lto':'fat','codegen-units':1,'panic':'abort'},'source_application':'transient eight path overrides with durable per-path recovery bytes; restored before build handoff','normal_fixture_frozen_sha256':NORMAL_SHA}
        save(out/'build.json',receipt)
        replay={**identity,'verification_mode':'git-objects-and-frozen-overlay','upstream_source_identity_sha256':file_sha(out/'source-identity.json'),'frozen_overlay_root':str(frozen),'frozen_overlay_sha256':prep['overlay_sha256'],'binary_sha256':receipt['binary_sha256']};proof=source_provenance.verify(replay,root);save(out/'replay-source-identity.json',replay);save(out/'immutable-input-proof.json',proof);success=True
    except BaseException as error:
        save(out/'first-failure.json',{'stage':stage,'error_type':type(error).__name__,'detail':str(error),'no_retry':True});raise
    finally:
        for sig,handler in previous_handlers.items():signal.signal(sig,handler)
        restored={}
        for name,row in reversed(list(snapshots.items())):
            target=root/name
            if row['existed']:
                shutil.copy2(backup/name,target);os.chmod(target,row['mode']);restored[name]=file_sha(target)==row['sha256'] and stat.S_IMODE(target.stat().st_mode)==row['mode']
            else:
                if target.exists():target.unlink()
                restored[name]=not target.exists()
        docs_unchanged={name:((file_sha(root/name) if (root/name).is_file() else None)==expected) for name,expected in documentation_differences.items()}
        normal_unchanged=file_sha(a.normal_binary)==NORMAL_SHA;head_unchanged=git(root,['rev-parse','HEAD'],text=True).strip()==COMMIT
        save(out/'restoration.json',{'per_path_restored':restored,'documentation_differences_unchanged':docs_unchanged,'normal_binary_unchanged':normal_unchanged,'head_unchanged':head_unchanged,'build_succeeded':success,'time_unix':time.time()})
        assert all(restored.values()) and all(docs_unchanged.values()) and normal_unchanged and head_unchanged,'restoration identity failure; stop and preserve evidence'
    print(json.dumps({'status':'OBSERVER_FROZEN_AND_SOURCE_RESTORED','binary_sha256':receipt['binary_sha256'],'out':str(out)}))
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',required=True,type=pathlib.Path);p.add_argument('--prepared-overlay',required=True,type=pathlib.Path);p.add_argument('--out',required=True,type=pathlib.Path);p.add_argument('--normal-binary',required=True,type=pathlib.Path);p.add_argument('--authorized-slot',required=True);main(p.parse_args())
