"""Source-only C8 exact aggregate driver. One approved aggregate per invocation.
No build/provision/reset/cleanup/retry. Each aggregate requires a distinct fresh case.
"""
import argparse,datetime,hashlib,importlib.util,json,os,pathlib,re,signal,subprocess,time
R=pathlib.Path(__file__).resolve().parent;OUT=R.parent
TESTS={
 'private-pg':('pg','postgres','private_contract','private_contract_tests::postgres_shared_private_ledger_contract','C8_PRIVATE_PG_URL_FILE','C8_PRIVATE_DISPOSABLE',False),
 'private-mysql':('mysql','mysql','private_contract','private_contract_tests::mysql_shared_private_ledger_contract','C8_PRIVATE_MYSQL_URL_FILE','C8_PRIVATE_DISPOSABLE',False),
 'ordinary-pg':('pg','postgres','ordinary_contract','backend_contract_tests::postgres_shared_ordinary_contract_and_native_failures','C8_TEST_URL_FILE','C8_NATIVE_DISPOSABLE',True),
 'ordinary-mysql':('mysql','mysql','ordinary_contract','backend_contract_tests::mysql_native_tests::mysql_shared_ordinary_contract_and_native_failures','C8_TEST_URL_FILE','C8_NATIVE_DISPOSABLE',True)}
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('aggregate',choices=TESTS);ap.add_argument('--root-exclusive-aggregate-approved',action='store_true');ap.add_argument('--test-binary',type=pathlib.Path,required=True);ap.add_argument('--test-binary-sha256',required=True);ap.add_argument('--case-manifest-sha256',required=True);ap.add_argument('--source-root',type=pathlib.Path,required=True);ap.add_argument('--expected-commit',required=True);ap.add_argument('--aggregate-timeout-seconds',type=int,default=120);a=ap.parse_args()
 if not a.root_exclusive_aggregate_approved:raise SystemExit('No calls: root exclusive aggregate slot required')
 assert 1<=a.aggregate_timeout_seconds<=120 and re.fullmatch('[a-f0-9]{64}',a.test_binary_sha256)
 os.umask(0o077);O=OUT/'tests/aggregate-runs'/a.aggregate;O.mkdir(parents=True,exist_ok=False);P=O/'receipt.json';record={'status':'STARTED','timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'aggregate':a.aggregate,'driver_sha256':sha(__file__),'no_retry':True,'scope':'One exact opt-in aggregate, no builds/provision/reset/cleanup; failure or timeout retains all DB state and first log'}
 def save():P.write_text(json.dumps(record,indent=2)+'\n')
 def commit():return subprocess.check_output(['git','rev-parse','HEAD'],cwd=a.source_root,text=True,timeout=7).strip()
 save();proc=None
 try:
  assert sha(a.test_binary)==a.test_binary_sha256 and commit()==a.expected_commit
  mf=R/'active-case-manifest.json';assert sha(mf)==a.case_manifest_sha256;manifest=json.loads(mf.read_text());engine,backend,label,test,var,optin,factory=TESTS[a.aggregate];entries=[e for e in manifest['cases'] if e['backend']==backend and e['label']==label];assert len(entries)==1;entry=entries[0];ref=pathlib.Path(entry['url_file']);assert ref.resolve().parent==R and not ref.is_symlink() and ref.stat().st_mode&0o777==0o600
  spec=importlib.util.spec_from_file_location('c7owned',R/'isolated_db.py');helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper);state,_=helper.owned(engine);db=entry['database'];case=state['cases'][db];assert case['label']==label and case['url_file']==str(ref) and entry['container_id']==state['id'] and entry['owner_uuid']==state['owner'];assert entry['captured_state']==str(R/(engine+'-owned.json')) and entry['environment_helper']==str(R/'isolated_db.py') and entry['environment_namespace']=='C8/isolated'
  assert state['engine_lease_only'] is True and entry['case_registry_owner']==state['case_registry_owner'] and entry['engine_authority_source']==state['engine_authority_source']
  if factory:assert case.get('native_factory') is True and case.get('legacy_fixture_name') is True and re.fullmatch('c5_synthetic_[a-f0-9]{32}',db)
  else:assert re.fullmatch('c8_synthetic_[a-z0-9_]+_[a-f0-9]{16}',db) and not case.get('native_factory',False)
  # Preflight queries never reveal URL values. Engine/role/endpoint ownership is also checked in the cfg(test) C8 guards.
  empty=helper.sql(engine,"SELECT count(*) FROM pg_tables WHERE schemaname<>'information_schema' AND left(schemaname,3)<>'pg_';" if engine=='pg' else 'SELECT count(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE=\'BASE TABLE\';',db);assert empty=='0','Exact assigned case must be unused and empty'
  urlhash=sha(ref);record.update({'test_name':test,'test_binary':str(a.test_binary),'test_binary_sha256':a.test_binary_sha256,'source_commit':a.expected_commit,'manifest_sha256':a.case_manifest_sha256,'case_entry':entry,'URL_file_sha256':urlhash,'actual_empty_business_table_count':0,'timeout_seconds':a.aggregate_timeout_seconds,'fresh_factory_or_case_required':True});save()
  environment={k:v for k,v in os.environ.items() if not k.startswith(('C4_','C5_','C6_','C7_','C8_','PUSHGO_','CARGO_PROFILE_')) and k not in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_TARGET_DIR']};environment[var]=str(ref);environment[optin]='YES_NEW_SYNTHETIC';args=[str(a.test_binary),'--ignored','--exact',test,'--nocapture','--test-threads=1'];log=O/'test.log';record['command']=args;record['log']=str(log);save();start=time.monotonic()
  with log.open('x') as f:
   proc=subprocess.Popen(args,cwd=a.source_root/'prototype',env=environment,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
   try:code=proc.wait(timeout=a.aggregate_timeout_seconds)
   except subprocess.TimeoutExpired:
    os.killpg(proc.pid,signal.SIGTERM)
    try:proc.wait(timeout=2)
    except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.wait(timeout=2)
    record['timed_out']=True;raise RuntimeError('Aggregate fixed timeout; only captured test process group stopped; DB state retained') from None
  record.update({'exit_code':code,'elapsed_seconds':time.monotonic()-start,'log_sha256':sha(log),'test_binary_unchanged_after':sha(a.test_binary)==a.test_binary_sha256,'source_commit_unchanged_after':commit()==a.expected_commit});text=log.read_text();record['one_exact_test_passed']=bool(re.search(r'test result: ok\. 1 passed; 0 failed;',text));assert code==0 and record['one_exact_test_passed'] and record['test_binary_unchanged_after'] and record['source_commit_unchanged_after'];record['status']='EXACT_AGGREGATE_PASS_NO_AUTO_NEXT';save();print(json.dumps({'receipt':str(P),'sha256':sha(P),'status':record['status']}))
 except Exception as e:
  record['status']='STOPPED_FIRST_ERROR_NO_RETRY';record['first_error_type']=type(e).__name__;record['first_error']='Subprocess arguments withheld' if isinstance(e,subprocess.SubprocessError) else str(e)
  if record.get('log') and pathlib.Path(record['log']).exists():record['log_sha256']=sha(record['log'])
  save();raise RuntimeError(record['first_error']) from None
if __name__=='__main__':main()
