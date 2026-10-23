#!/usr/bin/env python3
"""Run one explicitly scheduled C6 Provider lane. Does not provision DBs/emulators.
Source preparation did not execute this entrypoint. A root-authorized window is
an operational prerequisite; --window-label records that window, not permission.
"""
import argparse,hashlib,json,os,pathlib,re,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parent
C6=ROOT.parent
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def dump(p,v):p.write_text(json.dumps(v,indent=2,sort_keys=True)+'\n')
def check_cache():
 rows=json.loads((ROOT/'apple/cache-identity.json').read_text())['checks']
 for row in rows:assert sha(row['path'])==row['sha256'], 'frozen Apple cache/source changed: '+row['path']
 return {'checked_files':len(rows),'test_executable_sha256':next(r['sha256'] for r in rows if r['path'].endswith('/Contents/MacOS/PushGoAppleCoreTests'))}
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--lane',choices=['apple','android'],required=True)
 p.add_argument('--backend',choices=['sqlite','postgres','mysql'],required=True)
 p.add_argument('--binary',type=pathlib.Path,required=True)
 p.add_argument('--binary-sha256',required=True)
 p.add_argument('--source-commit',required=True)
 p.add_argument('--source',type=pathlib.Path,required=True)
 p.add_argument('--out',type=pathlib.Path,required=True)
 p.add_argument('--window-label',required=True)
 p.add_argument('--env-root',type=pathlib.Path)
 p.add_argument('--url-file',type=pathlib.Path)
 p.add_argument('--serial',help='required for Android; emulator is owned and started by native unit')
 a=p.parse_args()
 assert re.fullmatch(r'[0-9a-f]{64}',a.binary_sha256)
 assert re.fullmatch(r'[0-9a-f]{40}',a.source_commit), 'exact frozen Gateway commit required'
 assert sha(a.binary)==a.binary_sha256,'Gateway binary identity mismatch'
 out=a.out.resolve();assert out.is_relative_to(ROOT/'runs'),'run OUT must be inside C6 Provider runs'
 out.mkdir(parents=True,exist_ok=False)
 env=dict(os.environ);env['PYTHONDONTWRITEBYTECODE']='1'
 env['C6_DB_BACKEND']=a.backend
 dep=json.loads((ROOT/'observer-dependencies.json').read_text())
 env['C6_OBSERVER_DEPENDENCIES']=dep['external_vendor']
 if a.backend=='sqlite':
  db=out/'authority/gateway.sqlite';db.parent.mkdir();assert not db.exists();env['C6_SQLITE_PATH']=str(db)
 else:
  assert a.env_root and a.url_file,'fresh environment owner references required'
  env['C6_DB_ENV_ROOT']=str(a.env_root.resolve());env['C6_DB_URL_FILE']=str(a.url_file.resolve())
 if a.lane=='android':assert a.serial,'shared emulator serial and exclusive Android window required'
 # Verify prepared harness bytes before any owned process launch.
 manifest=json.loads((ROOT/'source-provenance.json').read_text())
 for row in manifest['files']:assert sha(ROOT/row['path'])==row['sha256'],row['path']
 before=check_cache() if a.lane=='apple' else json.loads((ROOT/'android/c6-apk-identity.json').read_text())
 if a.lane=='android':
  for field in ['main_apk','test_apk']:assert sha(before[field])==before[field+'_sha256'],field
 cmd=[sys.executable,str(ROOT/a.lane/'run-loop.py'),'--binary',str(a.binary.resolve()),'--source-commit',a.source_commit,'--out',str(out/'loop')]
 if a.lane=='android':cmd+=['--source',str(a.source.resolve()),'--serial',a.serial]
 record={'status':'RUNNING','lane':a.lane,'backend':a.backend,'window_label':a.window_label,'source_commit':a.source_commit,'binary_sha256':a.binary_sha256,'command':cmd,'artifact_identity':before,'started_unix':time.time(),'scope':'Provider clients with Private enabled; no Apple Private claim; no real Provider delivery'}
 dump(out/'execution.json',record)
 failure=None;code=None
 try:
  with (out/'adapter.log').open('x') as log:code=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT).returncode
  assert code==0,'first adapter invocation failed; retained without retry'
 finally:
  # A failure here must not overwrite/mask the adapter's original receipts.
  try:
   assert sha(a.binary)==a.binary_sha256,'Gateway binary changed during lane'
   if a.lane=='apple':check_cache()
   else:
    for field in ['main_apk','test_apk']:assert sha(before[field])==before[field+'_sha256'],field
  except BaseException as error:failure=repr(error)
  record.update(status='PASSED' if code==0 and not failure else 'FAILED',adapter_exit=code,identity_failure=failure,finished_unix=time.time())
  dump(out/'execution.json',record)
 if failure:raise SystemExit(failure)
 if code:raise SystemExit(code)
if __name__=='__main__':main()
