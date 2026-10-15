import pathlib,hashlib,json,sys
HERE=pathlib.Path(__file__).resolve().parent;ROOT=HERE.parent
OLD=pathlib.Path('/Users/ethan/Repo/PushGo/gateway/build/quality-results/c-client-loop-gate-20261015/android/staged-pushgo-android')
NEW=HERE/'c5-staged-pushgo-android';h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
rows=json.loads((ROOT/'preflight-native-cache.json').read_text())['checks'];checked=[]
for row in rows:
 p=pathlib.Path(row['path'])
 if not p.is_absolute():p=pathlib.Path('/Users/ethan/Repo/PushGo')/p
 assert h(p)==row['sha256'],str(p)
 if row['kind']=='android-staged':
  copied=NEW/p.relative_to(OLD);assert h(copied)==row['sha256'],str(copied)
  checked.append({'path':str(copied.relative_to(HERE)),'sha256':row['sha256']})
main=OLD/'app/build/outputs/apk/debug/app-universal-debug.apk';stagedmain=NEW/'app/build/outputs/apk/debug/app-universal-debug.apk'
assert h(main)==h(stagedmain),'C5 main APK changed; stop before native use'
source=NEW/'app/src/androidTest/java/io/ethan/pushgo/CandidateOrdinaryC3DeviceTest.kt'
value={'status':'PASSED','phase':sys.argv[1],'production_main_files':checked,'original_cached_main_apk_sha256':h(main),'cloned_main_apk_sha256':h(stagedmain),'source_test_sha256':h(source),'test_source':str(source),'production_source_unchanged':True,'cached_JNI_revision':'UNVERIFIED; unchanged cached JNI/private journey unused'}
(HERE/f'c5-staging-{sys.argv[1]}.json').write_text(json.dumps(value,indent=2)+'\n')
if sys.argv[1]=='after':
 apk=NEW/'app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk'
 value={'path':str(apk),'sha256':h(apk),'bytes':apk.stat().st_size,'test_source_sha256':h(source),'original_main_apk':str(main),'original_main_apk_sha256':h(main),'scope':'new isolated C5 instrumentation test APK; unchanged original cached production main APK/JNI'}
 (HERE/'c5-test-apk-manifest.json').write_text(json.dumps(value,indent=2)+'\n')
print(json.dumps({'status':'PASSED','phase':sys.argv[1],'production_main_hashes_checked':len(checked),'main_apk_unchanged':True}))
