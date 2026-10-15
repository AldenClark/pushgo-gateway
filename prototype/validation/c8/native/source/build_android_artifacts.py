"""Root-window-only C8 Android compiler; formal and QA inputs stay separate."""
import argparse,hashlib,json,os,shutil,signal,subprocess,time,tomllib,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
C7=ROOT.parent.parent/'c7-private-frame64-20261015'
REPO=C7/'worktrees/pushgo-android'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def free():return shutil.disk_usage(ROOT).free
def guard(growth):assert free()>=4*1024**3+growth,'freshgrowth+4GiB reserve unavailable'
def registry(p):return sorted((v['name'],v['version'],v.get('checksum')) for v in tomllib.loads(p.read_text())['package'] if v.get('source','').startswith('registry+'))
def run(command,cwd,env,logpath):
    started=time.time();minimum=free()
    with logpath.open('xb') as log:
        p=subprocess.Popen(command,cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        while p.poll() is None:
            minimum=min(minimum,free())
            if minimum<4*1024**3:
                os.killpg(p.pid,signal.SIGTERM);p.wait(timeout=15);raise RuntimeError('ownedbuildstopped:4GiB diskreserve')
            time.sleep(1)
    r={'command':list(map(str,command)),'pid':p.pid,'exit':p.returncode,'seconds':time.time()-started,'minimum_free':minimum,'free_after':free()}
    save(logpath.with_suffix('.receipt.json'),r)
    assert p.returncode==0,'firstcommandfailed: '+str(logpath)
    return r

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--phase',choices=['normal','qa'],required=True);parser.add_argument('--window-authorized',action='store_true');parser.add_argument('--expected-android-head',required=True);parser.add_argument('--attempt',choices=['01','02'],default='01');args=parser.parse_args();assert args.window_authorized
    lane=ROOT/(args.phase+'-build-attempt'+args.attempt);lane.mkdir();rec={'status':'RUNNING','phase':args.phase,'free_before':free(),'android_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO).decode().strip(),'warp_revision':'fded360134f2144876bb11b95e7431cb1d72aef3','steps':[]}
    normal_so=REPO/'app/build/generated/rustJniLibs/main/arm64-v8a/libpushgo_quinn_jni.so'
    rec['normal_SO_before']=sha(normal_so) if normal_so.exists() else None
    try:
        assert rec['android_head']==args.expected_android_head
        env={k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','ORG_GRADLE_PROJECT_PUSHGO_'))}
        rustc=subprocess.check_output(['rustup','which','--toolchain','1.97.1','rustc']).decode().strip();cargo=subprocess.check_output(['rustup','which','--toolchain','1.97.1','cargo']).decode().strip()
        rec['rustc_version']=subprocess.check_output([rustc,'--version']).decode().strip();rec['cargo_version']=subprocess.check_output([cargo,'--version']).decode().strip();assert '1.97.1' in rec['rustc_version'] and '1.97.1' in rec['cargo_version']
        env.update({'RUSTUP_TOOLCHAIN':'1.97.1','RUSTC':rustc,'CARGO':cargo,'CARGO_NET_OFFLINE':'true','CARGO_BUILD_JOBS':'2','CARGO_TARGET_DIR':str(ROOT/'android-target'),'ANDROID_SDK_ROOT':'/Users/ethan/Library/Android/sdk','ANDROID_NDK_HOME':'/Users/ethan/Library/Android/sdk/ndk/29.0.14206865','ANDROID_NDK_ROOT':'/Users/ethan/Library/Android/sdk/ndk/29.0.14206865','JAVA_HOME':'/Applications/Android Studio.app/Contents/jbr/Contents/Home','GRADLE_USER_HOME':str(ROOT/'gradle-user-home'),'ANDROID_USER_HOME':str(ROOT/'android-user-home')})
        if args.phase=='normal':
            guard(1024**3)
            pairs=[(C7/'native/jni-target',ROOT/'android-target'),(C7/'native/gradle-user-home/caches',ROOT/'gradle-user-home/caches'),(C7/'native/gradle-user-home/wrapper',ROOT/'gradle-user-home/wrapper')]
            for source,destination in pairs:
                assert source.is_dir() and not destination.exists();destination.parent.mkdir(parents=True,exist_ok=True)
                rec['steps'].append(run(['cp','-cR',str(source),str(destination)],REPO,env,lane/('clone-'+destination.name+'.log')))
        manifest=REPO/'native/quinn-jni/Cargo.toml' if args.phase=='normal' else ROOT/'jni-test-build/Cargo.toml'
        product_lock=REPO/'native/quinn-jni/Cargo.lock';product_sha=sha(product_lock)
        if args.phase=='qa':
            guard(1024**3);env['PUSHGO_C8_TEST_CA_DER']=str(ROOT/'synthetic-tls-public/ca.der')
            rec['QA_lock_seed_sha256']=sha(manifest.parent/'Cargo.lock');shutil.copy2(manifest.parent/'Cargo.lock',lane/'QA-seed-Cargo.lock')
            rec['steps'].append(run([cargo,'metadata','--offline','--format-version','1','--manifest-path',str(manifest)],REPO,env,lane/'metadata-calibration.log'))
            assert registry(product_lock)==registry(manifest.parent/'Cargo.lock'),'registry version/checksum drift'
            rec['QA_registry_tuples_equal']=True;rec['QA_lock_sha256']=sha(manifest.parent/'Cargo.lock')
        guard(2*1024**3)
        rec['steps'].append(run([cargo,'ndk','-t','arm64-v8a','-P','28','build','--manifest-path',str(manifest),'--release','--offline','--frozen'],REPO/'native/quinn-jni',env,lane/'jni.log'))
        library=ROOT/'android-target/aarch64-linux-android/release/libpushgo_quinn_jni.so';frozen=lane/'libpushgo_quinn_jni.so';shutil.copy2(library,frozen);rec['SO_sha256']=sha(frozen)
        der=(ROOT/'synthetic-tls-public/ca.der').read_bytes();has_ca=der in frozen.read_bytes();assert has_ca==(args.phase=='qa');rec['synthetic_CA_DER_embedded']=has_ca
        llvm=Path('/Users/ethan/Library/Android/sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/darwin-x86_64/bin')
        symbols=subprocess.check_output([str(llvm/'llvm-nm'),'-D','--defined-only',str(frozen)]).decode();(lane/'exports.txt').write_text(symbols)
        actual=sorted(line.split()[-1] for line in symbols.splitlines() if 'Java_io_ethan_pushgo_notifications_WarpLinkNativeBridge_' in line)
        expected=sorted('Java_io_ethan_pushgo_notifications_WarpLinkNativeBridge_'+line.split()[0] for line in (REPO/'native/quinn-jni/jni-contract.txt').read_text().splitlines() if line.startswith('native'));assert actual==expected and len(actual)==11
        headers=subprocess.check_output([str(llvm/'llvm-readelf'),'-lW',str(frozen)]).decode();(lane/'program-headers.txt').write_text(headers);loads=[line.split()[-1] for line in headers.splitlines() if line.strip().startswith('LOAD ')];assert loads and all(x=='0x4000' for x in loads)
        assert 'const JNI_ABI_VERSION: jint = 2;' in (REPO/'native/quinn-jni/src/lib.rs').read_text();rec.update({'ABI':2,'exports':11,'LOAD_alignment':loads})
        destination=normal_so if args.phase=='normal' else ROOT/'qa-jni-libs/arm64-v8a/libpushgo_quinn_jni.so';destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(frozen,destination);assert sha(destination)==rec['SO_sha256'];rec['packaging_SO_input']=str(destination)
        if args.phase=='qa':assert sha(normal_so)==rec['normal_SO_before'],'QA polluted normaloutput'
        guard(2*1024**3)
        command=['./gradlew','--offline','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx2g -Dfile.encoding=UTF-8','-Ppushgo.enableAbiSplits=false']
        if args.phase=='qa':command+=['-Ppushgo.c7IsolatedNativeQa=true','-Ppushgo.c8QaJniDir='+str(ROOT/'qa-jni-libs'),'-PPUSHGO_PRIVATE_CERT_PIN_SHA256=a0ae1d2a415960eedfa166e3b9073c60eb072132e13be94a18ac58887c913e22']
        command+=[':app:assembleDebug',':app:assembleDebugAndroidTest','-x',':app:buildRustJniLibs'];rec['steps'].append(run(command,REPO,env,lane/'apk.log'))
        for name,path in [('main_APK',REPO/'app/build/outputs/apk/debug/app-debug.apk'),('test_APK',REPO/'app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk')]:
            dest=lane/path.name;shutil.copy2(path,dest);rec[name]=str(dest);rec[name+'_sha256']=sha(dest)
        with zipfile.ZipFile(rec['main_APK']) as archive:rec['embedded_SO_sha256']=hashlib.sha256(archive.read('lib/arm64-v8a/libpushgo_quinn_jni.so')).hexdigest()
        if args.phase=='qa':
            assert rec['embedded_SO_sha256']==rec['SO_sha256']
        else:
            stripped=lane/'reproduced-normal-stripped.so'
            rec['steps'].append(run([str(llvm/'llvm-strip'),'--strip-unneeded','-o',str(stripped),str(frozen)],REPO,env,lane/'normal-strip.log'))
            assert rec['embedded_SO_sha256']==sha(stripped)
            rec['normal_default_strip_reproduced']=True
        assert sha(product_lock)==product_sha
        rec['normal_SO_after']=sha(normal_so)
        if args.phase=='qa':assert rec['normal_SO_after']==rec['normal_SO_before']
        rec['status']='PASSED'
    except Exception as error:rec['status']='FIRST_STOP';rec['first_error']=repr(error);raise
    finally:rec['free_after']=free();save(lane/'result.json',rec)
    print(json.dumps(rec))
if __name__=='__main__':main()
