"""Root-authorized exact C7 pause only. No SQL/stop/remove/export/unpause."""
import pathlib,importlib.util,json,hashlib,datetime,os
R=pathlib.Path(__file__).resolve().parent;os.umask(0o077);P=R/'paused-environment-receipt.json';assert not P.exists()
spec=importlib.util.spec_from_file_location('owned',R/'isolated_db.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
EXPECT={'pg':('2fc5f06ee05b5697694a79229ee0c0d261e347fea0e0cc44ba6e1f8cbb835dbd','2a42dd57da4c4bcba66e0509ad35c93c'),'mysql':('eaaf0b526c22bafb0a61a6e8e569008a246f677923e022f245c5a1264f577ed1','bd59112fdf0843f7962bf56cb7e44cb5')}
r={'status':'STARTED','timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':str(pathlib.Path(__file__).resolve()),'source_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'capacity_result':'NOTRUN_RESOURCE_GUARD','scope':'Exact two owned C7 containers pause; preserve tmpfs/namedvolume/credentials refs; no SQL/stop/rm/volume delete/export/unpause','resources':{},'references_modified':False}
def save():m.save(P,r)
def state(i):return {k:i['State'].get(k) for k in ['Status','Running','Paused','ExitCode']}
save()
try:
 checked={}
 # Verify both complete identities before the first pause; mysql helper also checks volume owner+mount Source.
 for engine,(ident,owner) in EXPECT.items():
  s,i=m.owned(engine);assert s['id']==ident and s['owner']==owner and i['Config']['Labels'][m.KEY]==owner;assert i['Name']=='/pushgo-c7-isolated-'+engine+'-'+owner
  entry={'id':ident,'owner_uuid':owner,'name':i['Name'],'label_key':m.KEY,'before':state(i),'canonical_state':str(R/(engine+'-owned.json')),'canonical_state_sha256':hashlib.sha256((R/(engine+'-owned.json')).read_bytes()).hexdigest(),'URL_refs_retained':[c['url_file'] for c in s['cases'].values()],'mounts':i['Mounts'],'volume_name':s.get('volume_name')}
  if engine=='mysql':
   assert s['volume_name']=='pushgo-c7-isolated-data-bd59112fdf0843f7962bf56cb7e44cb5';v=json.loads(m.run(['volume','inspect',s['volume_name']]))[0];assert v['Labels'][m.KEY]==owner;entry['volume_identity']={'name':v['Name'],'owner_label':v['Labels'][m.KEY],'mountpoint':v['Mountpoint'],'driver':v['Driver']}
  assert all(pathlib.Path(p).is_file() and pathlib.Path(p).stat().st_mode&0o777==0o600 for p in entry['URL_refs_retained']);r['resources'][engine]=entry;checked[engine]=(s,i);save()
 for engine,(s,i) in checked.items():
  entry=r['resources'][engine]
  if i['State']['Running'] and not i['State']['Paused']:m.run(['pause',s['id']]);entry['pause_invoked_once']=True
  else:entry['pause_invoked_once']=False;entry['skip_reason']='Already paused or not running; no repeated lifecycle operation'
  s2,i2=m.owned(engine);entry['after']=state(i2)
  if i['State']['Running']:assert i2['State']['Running'] and i2['State']['Paused']
  assert hashlib.sha256((R/(engine+'-owned.json')).read_bytes()).hexdigest()==entry['canonical_state_sha256'];save()
 r['resume_plan_not_executed']={'authority':'User/root explicit review required. Do not auto-unpause or start workload. Capacity remains NOTRUN.','prerequisites':'Review retained data/reference ownership and a maintenance resource recovery plan. Revalidate exact full IDs/UUID/volume/mount; guest below4GiB cannot authorize any business work. No forced stop/drop/purge to bypass guard.','explicit_commands_after_approval':['docker --context orbstack unpause '+EXPECT['pg'][0],'docker --context orbstack unpause '+EXPECT['mysql'][0]],'limits':'These commands would allow database background I/O. Separate approval and adequate resource guards are required before any workload; a pause is not durable backup or shutdown. No unpause has been executed.'};r['status']='EXACT_OWNED_C7_CONTAINERS_PAUSED_DATA_AND_REFS_RETAINED';save();print(json.dumps({'receipt':str(P),'sha256':hashlib.sha256(P.read_bytes()).hexdigest(),'status':r['status'],'states':{k:v['after'] for k,v in r['resources'].items()}}))
except Exception as e:
 r['status']='STOPPED_FIRST_ERROR_PARTIAL_STATE_PRESERVED';r['first_error_type']=type(e).__name__;r['first_error']=str(e);save();raise RuntimeError(r['first_error']) from None
