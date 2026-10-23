from pathlib import Path
import os,subprocess,time,json,shutil
R=Path(__file__).resolve().parents[1];W=R.parent.parent/'c7-private-frame64-20261015/worktrees/pushgo-android';O=R/'quality-final/qa-config-negatives';O.mkdir()
env={k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','ORG_GRADLE_PROJECT_PUSHGO_'))};env.update(JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home',GRADLE_USER_HOME=str(R/'gradle-user-home'),ANDROID_USER_HOME=str(R/'android-user-home'),ANDROID_SDK_ROOT='/Users/ethan/Library/Android/sdk')
rows=[]
for label,args,expected in [('without-qa-flag',[], 'c8QaJniDir requires isolated QA mode'),('aggregate-release',['-Ppushgo.c7IsolatedNativeQa=true'],'QA JNI input must never enter a Release task graph')]:
 assert shutil.disk_usage(R).free>=7*1024**3
 cmd=['./gradlew','--offline','--no-daemon','--dry-run','--max-workers=2','-Dorg.gradle.jvmargs=-Xmx2g -Dfile.encoding=UTF-8','-Ppushgo.c8QaJniDir='+str(R/'qa-jni-libs'),*args,':app:assemble' if args else ':app:assembleDebug','-x',':app:buildRustJniLibs'];start=time.time()
 try:
  p=subprocess.run(cmd,cwd=W,env=env,capture_output=True,timeout=10);raw=p.stdout+p.stderr;(O/(label+'.log')).write_bytes(raw)
  row={'case':label,'exit':p.returncode,'seconds':time.time()-start,'command':cmd,'dry_run':True,'no_tasks_executed':True,'expected':expected,'diagnostic_found':expected.encode() in raw,'status':'PASSED' if p.returncode!=0 and expected.encode() in raw else 'FAILED'}
 except subprocess.TimeoutExpired as e:
  (O/(label+'.log')).write_bytes((e.stdout or b'')+(e.stderr or b''));row={'case':label,'status':'BLOCKED','first_error':'dry-run exceeded10s; no retry','seconds':time.time()-start}
 rows.append(row);(O/'result.json').write_text(json.dumps(rows,indent=2)+'\n');print(json.dumps(row),flush=True)
 if row['status']!='PASSED':break
