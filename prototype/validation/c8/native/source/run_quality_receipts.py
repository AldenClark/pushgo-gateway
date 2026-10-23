from pathlib import Path
import os,subprocess,time,shutil,json,hashlib,signal
R=Path(__file__).resolve().parents[1]; W=R.parent.parent/'c7-private-frame64-20261015/worktrees/pushgo-android';O=R/'quality-final';O.mkdir();bindir=O/'bin';bindir.mkdir();(bindir/'python3').symlink_to('/Users/ethan/.local/bin/python3.13')
init=R/'gradle-user-home/init.d';init.mkdir(exist_ok=True);(init/'c8-offline.gradle').write_text('gradle.startParameter.offline = true\ngradle.startParameter.maxWorkerCount = 2\n')
env={k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','ORG_GRADLE_PROJECT_PUSHGO_'))};env.update(PATH=str(bindir)+':'+os.environ['PATH'],PYTHON_BIN=str(bindir/'python3'),JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home',GRADLE_USER_HOME=str(R/'gradle-user-home'),ANDROID_USER_HOME=str(R/'android-user-home'),ANDROID_SDK_ROOT='/Users/ethan/Library/Android/sdk',CARGO_NET_OFFLINE='true',RUSTUP_TOOLCHAIN='1.97.1',PYTHONDONTWRITEBYTECODE='1',GRADLE_OPTS='-Dorg.gradle.daemon=false -Dorg.gradle.workers.max=2 -Dorg.gradle.jvmargs=-Xmx2g')
frozen=[R/'qa-build-attempt02/app-debug.apk',R/'test-apk-transfer-fix/app-debug-androidTest.apk',R/'qa-jni-libs/arm64-v8a/libpushgo_quinn_jni.so',W/'app/build/generated/rustJniLibs/main/arm64-v8a/libpushgo_quinn_jni.so'];hashes={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in frozen}
rows=[]
for label,cmd in [('changed',['bash','scripts/quality_changed.sh','--base','9deaa11a9bc9e9824c798deddf7db976b45a1e75','--head','85bfe297684d5fddaf2ed42e26cf51bfa02164dd']),('pr',['bash','scripts/quality_test.sh','pr'])]:
 assert shutil.disk_usage(R).free>=7*1024**3
 env['QUALITY_RESULTS_ROOT']=str(O/label);start=time.time();minimum=shutil.disk_usage(R).free
 print('START '+label,flush=True)
 with (O/(label+'.log')).open('xb') as log:
  p=subprocess.Popen(cmd,cwd=W,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  while p.poll() is None:
   minimum=min(minimum,shutil.disk_usage(R).free)
   if minimum<4*1024**3:os.killpg(p.pid,signal.SIGTERM);p.wait(15);raise RuntimeError('4GiB guard')
   time.sleep(.5)
 row={'lane':label,'command':cmd,'exit':p.returncode,'seconds':time.time()-start,'minimum_free':minimum,'python':subprocess.check_output([str(bindir/'python3'),'--version']).decode().strip(),'python_executable':str((bindir/'python3').resolve()),'log':str(O/(label+'.log'))};rows.append(row);print(json.dumps(row),flush=True)
 (O/(label+'-receipt.json')).write_text(json.dumps(row,indent=2)+'\n')
after={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in frozen};assert after==hashes
(O/'artifact-preservation.json').write_text(json.dumps({'before':hashes,'after':after,'equal':after==hashes},indent=2)+'\n')
(O/'summary.json').write_text(json.dumps({'quality_commands':rows,'no_rule_changes':True,'frozen_artifacts_equal':True},indent=2)+'\n')
