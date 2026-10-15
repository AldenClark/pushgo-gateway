from pathlib import Path
import os,json,subprocess,shutil,hashlib,time,signal
R=Path(__file__).resolve().parents[1];W=R.parent.parent/'c7-private-frame64-20261015/worktrees/pushgo-android';O=R/'test-apk-transfer-fix';O.mkdir()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(v):(O/'result.json').write_text(json.dumps(v,indent=2)+'\n')
main=W/'app/build/outputs/apk/debug/app-debug.apk';so=W/'app/build/generated/rustJniLibs/main/arm64-v8a/libpushgo_quinn_jni.so';qa=R/'qa-jni-libs/arm64-v8a/libpushgo_quinn_jni.so'
before={str(p):sha(p) for p in (main,so,qa)};free=shutil.disk_usage(R).free;assert free>=7*1024**3
rec={'status':'FIRST_STOP','source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=W).decode().strip(),'before':before,'free_before':free};start=time.time()
env={k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','ORG_GRADLE_PROJECT_PUSHGO_'))};env.update(JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home',GRADLE_USER_HOME=str(R/'gradle-user-home'),ANDROID_USER_HOME=str(R/'android-user-home'),ANDROID_SDK_ROOT='/Users/ethan/Library/Android/sdk')
cmd=['./gradlew','--offline','--no-daemon','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx2g -Dfile.encoding=UTF-8','-Ppushgo.enableAbiSplits=false','-Ppushgo.c7IsolatedNativeQa=true','-Ppushgo.c8QaJniDir='+str(R/'qa-jni-libs'),'-PPUSHGO_PRIVATE_CERT_PIN_SHA256=a0ae1d2a415960eedfa166e3b9073c60eb072132e13be94a18ac58887c913e22',':app:assembleDebugAndroidTest','-x',':app:buildRustJniLibs']
try:
 with (O/'gradle.log').open('xb') as log:
  p=subprocess.Popen(cmd,cwd=W,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);rec['pid']=p.pid
  while p.poll() is None:
   if shutil.disk_usage(R).free<4*1024**3:os.killpg(p.pid,signal.SIGTERM);p.wait(15);raise RuntimeError('4GiB disk guard')
   time.sleep(.5)
 rec['exit']=p.returncode;assert p.returncode==0
 rec['after']={str(p):sha(p) for p in (main,so,qa)};assert rec['after']==before
 out=O/'app-debug-androidTest.apk';shutil.copyfile(W/'app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk',out)
 rec.update(status='PASSED',test_apk=str(out),test_apk_sha256=sha(out))
except BaseException as e:rec['first_error']=repr(e);raise
finally:rec['seconds']=time.time()-start;rec['free_after']=shutil.disk_usage(R).free;save(rec)
print(json.dumps(rec))
