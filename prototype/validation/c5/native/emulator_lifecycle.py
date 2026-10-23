import pathlib,subprocess,json,os,time,sys
out=pathlib.Path(os.environ.get('C5_EMULATOR_EVIDENCE_DIR',str(pathlib.Path(__file__).resolve().parent))).resolve();out.mkdir(parents=True,exist_ok=True);adb='/Users/ethan/Library/Android/sdk/platform-tools/adb'
if sys.argv[1]=='start':
 assert 'emulator-5580' not in subprocess.check_output([adb,'devices']).decode(),'owned serial already active'
 cmd=['/Users/ethan/Library/Android/sdk/emulator/emulator','-avd','pushgo_release_20260929','-port','5580','-read-only','-no-snapshot','-no-window','-no-audio','-gpu','swiftshader_indirect']
 with (out/'emulator-first.log').open('x') as f:p=subprocess.Popen(cmd,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
 (out/'emulator-process.json').write_text(json.dumps({'pid':p.pid,'command':cmd,'started_unix':time.time()},indent=2)+'\n')
 start=time.monotonic();rows=[]
 while time.monotonic()-start<180:
  r=subprocess.run([adb,'-s','emulator-5580','shell','getprop','sys.boot_completed'],capture_output=True,text=True);rows.append({'elapsed':time.monotonic()-start,'returncode':r.returncode,'boot_completed':r.stdout.strip()})
  if r.returncode==0 and r.stdout.strip()=='1':break
  time.sleep(2)
 else:raise SystemExit('owned emulator first boot timeout')
 (out/'emulator-boot.json').write_text(json.dumps({'status':'PASSED','polls':rows},indent=2)+'\n');print('booted owned emulator',p.pid)
else:
 pid=json.loads((out/'emulator-process.json').read_text())['pid']
 (out/'android-crash-log.txt').write_text(subprocess.run([adb,'-s','emulator-5580','logcat','-b','crash','-d'],capture_output=True,text=True).stdout)
 r=subprocess.run([adb,'-s','emulator-5580','emu','kill'],capture_output=True,text=True);start=time.monotonic()
 while time.monotonic()-start<30:
  try:os.kill(pid,0)
  except ProcessLookupError:break
  time.sleep(.2)
 else:raise SystemExit('owned emulator did not exit')
 (out/'emulator-teardown.json').write_text(json.dumps({'pid':pid,'absent':True,'kill_returncode':r.returncode,'adb_devices':subprocess.check_output([adb,'devices']).decode(),'seconds':time.monotonic()-start},indent=2)+'\n');print('emulator quiet')
