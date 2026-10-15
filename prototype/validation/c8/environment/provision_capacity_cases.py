"""C8 root-authorized fresh capacity cases only; no benchmark or workload."""
import pathlib,importlib.util,os,json,hashlib,datetime,contextlib,io
R=pathlib.Path(__file__).resolve().parent;os.umask(0o077);P=R/'capacity-case-allocation.json';assert not P.exists();sp=importlib.util.spec_from_file_location('c8',R/'isolated_db.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
r={'status':'STARTED','timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':str(pathlib.Path(__file__)),'source_sha256':sha(__file__),'input_authority':'Root reviewed originalsmall40960/190 and boundedlarge4messages64targets near49152 JSON; provisioning only','allocated':[],'workload_started':False,'historical_cases_mutated':False}
def save():m.save(P,r)
save()
try:
 f=os.statvfs(str(R));r['host_available_before']=f.f_bavail*f.f_frsize;assert r['host_available_before']>=4294967296+1073741824;save();os.environ['C8_CASE_PROVISION_APPROVED']='YES_FRESH_OWNED_ONLY'
 for engine in ['pg','mysql']:
  for label in ['capacity_small','capacity_large']:
   with contextlib.redirect_stdout(io.StringIO()) as out:m.create(engine,label,True)
   assigned=json.loads(out.getvalue());db=assigned['database'];s,_=m.owned(engine);count=m.sql(engine,"SELECT count(*) FROM pg_tables WHERE schemaname<>'information_schema' AND left(schemaname,3)<>'pg_';" if engine=='pg' else "SELECT count(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE';",db);assert count=='0';r['allocated'].append({'engine':engine,'label':label,'database':db,'url_file':assigned['url_file'],'role':assigned['user'],'container_id':s['id'],'engine_owner_uuid':s['owner'],'case_registry_owner':s['case_registry_owner'],'legacy_fixture_name':True,'empty_business_tables':0});save()
 s,_=m.owned('mysql');r['mysql_app_grants']=m.sql('mysql',"SHOW GRANTS FOR '"+s['user']+"'@'%';").splitlines();r['active_case_manifest_sha256']=sha(R/'active-case-manifest.json')
 # Derive case references after allocation from actual state; retain prior measured identity untouched in a versioned copy.
 identity=R/'environment-identity.json';before=identity.read_bytes();backup=R/'environment-identity.before-capacity-allocation.json';assert not backup.exists();backup.write_bytes(before);d=json.loads(before)
 for engine in ['pg','mysql']:
  state=json.loads((R/(engine+'-owned.json')).read_text());e=d['engines'][engine];assert e['id']==state['id'] and e['owner_uuid']==state['owner'] and e['case_registry_owner']==state['case_registry_owner'];e['case_refs']={db:{**{k:v for k,v in c.items() if k in ['label','url_file','role','native_factory','legacy_fixture_name']},'case_registry_owner':state['case_registry_owner'],'engine_lease_only':True,'engine_authority_source':state['engine_authority_source']} for db,c in state['cases'].items()}
  for row in r['allocated']:
   if row['engine']==engine:e['empty_case_business_table_counts'][row['database']]='0'
 d['case_manifest_sha256']=r['active_case_manifest_sha256'];d['latest_case_allocation']={'receipt':str(P),'source_sha256':r['source_sha256'],'prior_identity_sha256':hashlib.sha256(before).hexdigest(),'prior_identity_preserved':str(backup),'scope':'Fresh owned case refs/actualempty counts and exactgrants only; existing measured configuration/versions/media unchanged'};m.save(identity,d);r['identity_sha256']=sha(identity);f=os.statvfs(str(R));r['host_available_after']=f.f_bavail*f.f_frsize;r['status']='CAPACITY_CASES_FRESH_EMPTY_NO_WORKLOAD_AUTHORITY';save();print(json.dumps({'receipt':str(P),'sha256':sha(P),'manifest_sha256':r['active_case_manifest_sha256'],'identity_sha256':r['identity_sha256'],'allocated':r['allocated'],'host_available_bytes':r['host_available_after']}))
except Exception as e:
 r['status']='STOPPED_FIRST_ERROR_NO_RETRY';r['first_error_type']=type(e).__name__;r['first_error']=str(e);save();raise RuntimeError(r['first_error']) from None
