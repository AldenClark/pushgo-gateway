"""C8 owned emulator lifecycle. Lease token stays solely in this caller memory."""
from pathlib import Path
import os,sys,json,subprocess,time,hashlib,shutil,argparse
R=Path(__file__).resolve().parents[1]; C8=R.parent
P=Path('/Users/ethan/.local/bin/python3.13')
BUNDLED='/Users/ethan/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3'
LEASE=[str(P),'/Users/ethan/.codex/plugins/cache/dev-flow/dev-flow/2.0.3/skills/dev-flow/scripts/dev-flow.py','resource-lease']
ADB='/Users/ethan/Library/Android/sdk/platform-tools/adb'; SERIAL='emulator-5580'
parser=argparse.ArgumentParser();parser.add_argument('--attempt',choices=('01','02'),required=True);arguments=parser.parse_args()
O=R/('runtime-attempt'+arguments.attempt); O.mkdir(exist_ok=False)
def save(n,x): (O/n).write_text(json.dumps(x,indent=2)+'\n')
def call(cmd,**kw): return subprocess.run(cmd,check=True,capture_output=True,**kw)
def adb(*args): return call([ADB,'-s',SERIAL,*args],timeout=30).stdout.decode()
def lease(action,*args): return json.loads(call(LEASE+[action,'--kind','emulator','--resource',SERIAL,*args]).stdout)
def guard(): assert shutil.disk_usage(R).free >= 4*1024**3,'fresh disk below 4GiB stopguard'
token=None; em=None; child=None; result={'status':'FAILED','lanes':[]}; started=time.time()
try:
 guard(); assert shutil.disk_usage(R).free >= 6*1024**3
 inventory=call([ADB,'devices']).stdout.decode(); save('adb-before.json',{'inventory':inventory}); assert SERIAL not in inventory
 before=lease('inspect');save('lease-before.json',before); assert before['status']=='available'
 owned=lease('acquire','--ttl-seconds','1800'); assert owned['status']=='acquired'; token=owned.pop('token');owned['token_held_in_caller_context']=True;save('lease-acquire-redacted.json',owned)
 command=['/Users/ethan/Library/Android/sdk/emulator/emulator','-avd','pushgo_release_20260929','-port','5580','-read-only','-no-snapshot','-no-window','-no-audio','-gpu','swiftshader_indirect']
 with (O/'emulator.log').open('xb') as log: em=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 save('emulator-owned.json',{'pid':em.pid,'uid':os.getuid(),'command':command,'started':time.time()})
 boot=time.monotonic()
 while time.monotonic()-boot<180:
  guard(); assert em.poll() is None,'owned emulator startup exit'
  r=subprocess.run([ADB,'-s',SERIAL,'shell','getprop','sys.boot_completed'],capture_output=True,timeout=10)
  if r.returncode==0 and r.stdout.strip()==b'1':break
  time.sleep(2)
 else: raise RuntimeError('owned emulator boot deadline exceeded')
 save('boot.json',{'status':'PASSED','seconds':time.monotonic()-boot})
 sources={}
 frozen=O/'executed-source'; frozen.mkdir()
 for p in (R/'source').glob('*'):
  if p.is_file(): shutil.copyfile(p,frozen/p.name);sources[p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
 save('executed-source-manifest.json',sources)
 cases=[('sqlite','sqlite',[]),('pg','pg',[]),('mysql','mysql',[]),('sqlite-numeric48k','sqlite',['--numeric-metadata'])]+[(label,'sqlite',['--tls-negative',label]) for label in ('wrong-ca','wrong-host','wrong-pin')]
 for label,engine,extra in cases:
  guard(); assert owned['expires_at']>time.time()+180,'insufficient remaining owned lease'
  target=O/label
  cmd=[BUNDLED,str(R/'source/actual_case_driver.py'),'--binary',str(C8/'binaries/gateway-be3bc95-normal'),'--binary-sha256','b771b79a93b24025a037ca61c7056ea5a743ba52627a417dbee7f90d9d9efe44','--source-commit','be3bc95c58500ee9913dbc2d9b442d5eb6a74227','--engine',engine,'--serial',SERIAL,'--lease-receipt',str(O/'lease-acquire-redacted.json'),'--output',str(target),'--window-authorized',*extra]
  if engine!='sqlite':cmd+=['--case-receipt',str(C8/'env/active-case-manifest.json')]
  print('START '+label,flush=True)
  with (O/(label+'-console.log')).open('xb') as log:
   child=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
   minimum=shutil.disk_usage(R).free
   while child.poll() is None:
    free=shutil.disk_usage(R).free;minimum=min(minimum,free)
    if free<4*1024**3:
     child.terminate();child.wait(20);raise RuntimeError('4GiB live disk stopguard')
    time.sleep(.5)
  row={'lane':label,'exit':child.returncode,'minimum_free':minimum,'result':str(target/'result.json')};result['lanes'].append(row);save('matrix-progress.json',result)
  assert child.returncode==0,'first native lane failure: '+label
  print('PASS '+label,flush=True)
 result['status']='PASSED'
except BaseException as e:
 result['first_error']=repr(e);print('FIRST_STOP '+repr(e),flush=True)
finally:
 errors=[]
 if child and child.poll() is None:child.terminate();child.wait(20)
 if em:
  try:
   if em.poll() is None:
    for package in ('io.ethan.pushgo.c7evidence','io.ethan.pushgo.c7evidence.test'):
     adb('shell','am','force-stop',package)
     result[package+'_uninstall']=adb('uninstall',package).strip()
    result['reverse_before_emulator_stop']=adb('reverse','--list')
    captured=call(['ps','-p',str(em.pid),'-o','uid=,command=']).stdout.decode()
    assert str(os.getuid()) in captured and '-port 5580' in captured and '-read-only' in captured and 'pushgo_release_20260929' in captured
    adb('emu','kill');em.wait(30)
   result['emulator_pid']=em.pid;result['emulator_exit']=em.returncode;result['emulator_absent']=em.poll() is not None
  except BaseException as e: errors.append({'teardown':repr(e)})
 if token:
  try:
   assert not em or em.poll() is not None,'do not release live emulator'
   release=lease('release','--token',token);release.pop('token',None);save('lease-release.json',release);save('lease-after.json',lease('inspect'))
  except BaseException as e:errors.append({'release':repr(e)})
 token=None
 if errors:result['cleanup_errors']=errors;result['status']='FAILED'
 result['seconds']=time.time()-started;result['free_after']=shutil.disk_usage(R).free
 save('matrix-result.json',result);print('FINAL '+result['status'],flush=True)
sys.exit(0 if result['status']=='PASSED' else 1)
