"""C8 explicit root authority: lease captured C7 engines, fresh C8 cases only."""
import pathlib,os,json,subprocess,hashlib,datetime,uuid
R=pathlib.Path(__file__).resolve().parent;os.umask(0o077);P=R/'lease-provision-receipt.json';assert not P.exists()
r={'status':'STARTED','timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':str(pathlib.Path(__file__)),'source_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'steps':[],'new_containers_or_volumes':False,'historical_cases_mutated':False,'workload_started':False}
def save():P.write_text(json.dumps(r,indent=2)+'\n')
def free():
 f=os.statvfs(str(R));return f.f_bavail*f.f_frsize
save()
try:
 r['fresh_host_available_bytes']=free();save();assert r['fresh_host_available_bytes']>=4294967296+536870912
 env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',C8_ENGINE_LEASE_APPROVED='YES_CAPTURED_ENGINES_FRESH_CASES_ONLY',C8_CASE_PROVISION_APPROVED='YES_FRESH_OWNED_ONLY',C8_FACTORY_PROVISION_APPROVED='YES_SCOPED_NATIVE_FACTORY')
 for action,engine,label,legacy in [('start','pg',None,False),('start','mysql',None,False),('create','pg','private_contract',False),('create','mysql','private_contract',False),('factory','pg','ordinary_contract',False),('factory','mysql','ordinary_contract',False),('create','pg','native_client',True),('create','mysql','native_client',True)]:
  step={'action':action,'engine':engine,'label':label,'legacy':legacy};r['steps'].append(step);save();assert free()>=4294967296
  args=['python3',str(R/'isolated_db.py'),action,engine]+([label] if label else [])+(['--legacy-fixture-name'] if legacy else []);p=subprocess.run(args,capture_output=True,text=True,timeout=30,env=env);step.update({'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr});save();assert p.returncode==0,'First lease/provision failure; no retry'
 # SQLite is a fresh zero-byte owned file; no schema/data prefill or old database reuse.
 sqlite=[];root=R/'sqlite';root.mkdir(exist_ok=False)
 for label in ['private_contract','ordinary_contract','native_client']:
  path=root/(label+'-'+uuid.uuid4().hex+'.sqlite');path.open('xb').close();path.chmod(0o600);ref=R/(path.stem+'-sqlite-url.txt');ref.write_text('sqlite://'+str(path)+'?mode=rwc\n');ref.chmod(0o600);sqlite.append({'backend':'sqlite','label':label,'database_file':str(path),'url_file':str(ref),'initial_bytes':0,'mode':'0o600','environment_namespace':'C8/isolated','case_owner':'C8 UUID filename','new_file_only':True})
 (R/'sqlite-case-manifest.json').write_text(json.dumps({'status':'FRESH_EMPTY_SQLITE_FILES_NO_WORKLOAD','cases':sqlite},indent=2)+'\n')
 for name,args in [('identity',['python3',str(R/'capture_environment_identity.py'),'--root-owned-environment-ready-approved']),('budget',['python3',str(R/'budget_snapshot.py'),'after_contract_provision'])]:
  step={'action':name};r['steps'].append(step);save();p=subprocess.run(args,capture_output=True,text=True,timeout=45,env=env);step.update({'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr});save();assert p.returncode==0,'First identity/budget failure; no retry'
  if name=='budget':assert json.loads(p.stdout)['guard_pass'],'Budget failed; no workload'
 r['host_available_after']=free();r['status']='C8_FRESH_CASES_ON_CAPTURED_ENGINES_READY_NO_WORKLOAD';save();print(json.dumps({'receipt':str(P),'sha256':hashlib.sha256(P.read_bytes()).hexdigest(),'status':r['status'],'host_available_bytes':r['host_available_after']}))
except Exception as e:
 r['status']='STOPPED_FIRST_ERROR_NO_RETRY';r['first_error_type']=type(e).__name__;r['first_error']='Subprocess argv withheld' if isinstance(e,subprocess.SubprocessError) else str(e);save();raise RuntimeError(r['first_error']) from None
