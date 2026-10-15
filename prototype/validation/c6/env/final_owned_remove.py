"""SOURCE PREPARED ONLY. Requires separately reviewed completed preservation hash.
No prune, force rm, other volume/images/projects. Conservative OrbStack stop gate.
"""
import argparse,pathlib,json,os,subprocess,hashlib,datetime
R=pathlib.Path(__file__).resolve().parent;D=['docker','--context','orbstack']
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def call(args,timeout=7):
 p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
 if p.returncode:raise RuntimeError('Bounded native operation failed; argv withheld')
 return p.stdout.strip()
def main():
 a=argparse.ArgumentParser();a.add_argument('--reviewed-manifest-sha256',required=True);a.add_argument('--root-owned-delete-approved',action='store_true');a.add_argument('--root-restore-initial-orbstack-approved',action='store_true');x=a.parse_args()
 if not x.root_owned_delete_approved:raise SystemExit('No operations: separate root exact owned-delete authority required')
 os.umask(0o077);M=R/'final-owned-preservation/manifest.json';assert sha(M)==x.reviewed_manifest_sha256;m=json.loads(M.read_text());assert m['status']=='PRESERVATION_COMPLETE_PENDING_SEPARATE_ROOT_DELETE_AUTHORITY';P=R/'final-owned-cleanup.json';assert not P.exists();r={'status':'STARTED','source':str(pathlib.Path(__file__)),'source_sha256':sha(__file__),'reviewed_manifest_sha256':sha(M),'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'removed_containers':[],'removed_volumes':[],'retired_urls':[],'images_modified':False,'other_project_resources_modified':False}
 def save():P.write_text(json.dumps(r,indent=2)+'\n')
 save()
 try:
  assert len(m['resources'])==4
  # Verify ALL identities and preserved artifacts before the first stop. Never partial-adopt ownership.
  ids={e['id'] for e in m['resources']};assert ids=={'008ea1804e16ad16c691108dfa874f2f5300499397c9aa24d2b9f5cf8f4377be','d9f40918b1222b6de1a61baf22a7b3ca5dd0da08e5e3d3afe120431553d2e94b','5db64f385657c048a1878557b79a9942f04d448aea21c68fcecdd33e6e90c886','c24a4150e4f3f3e61af1445535b24a9ab1b7c16355b1f4162ae7d17152e67f81'}
  for e in m['resources']:
   i=json.loads(call(D+['inspect',e['id']]))[0];assert i['Id']==e['id'] and i['Name']==e['name'] and i['Config']['Labels'].get(e['label_key'])==e['owner'];assert sha(e['state_path'])==e['state_sha256'];assert sha(e['container_log']['file'])==e['container_log']['sha256']
  for e in m['exports']:assert e['stable'] and e['export']['crc_verified'] and sha(e['export']['file'])==e['export']['compressed_sha256']
  assert sha(m['current_live_binlog_archive']['file'])==m['current_live_binlog_archive']['compressed_sha256']
  v=m['volume'];actual=json.loads(call(D+['volume','inspect',v['Name']]))[0];assert actual['Name']==v['Name'] and actual['Driver']==v['Driver'] and actual['Mountpoint']==v['Mountpoint'] and actual['Labels']==v['Labels'];attached=call(D+['ps','-a','--no-trunc','--filter','volume='+v['Name'],'--format','{{.ID}}']).splitlines();assert set(attached)=={m['resources'][-1]['id']}
  # Explicit root final quiet evidence remains a required external authority. No SQL kill or forced disconnect.
  for e in m['resources']:
   i=json.loads(call(D+['inspect',e['id']]))[0]
   if i['State']['Running']:call(D+['stop','--time','5',e['id']],timeout=12)
   assert not json.loads(call(D+['inspect',e['id']]))[0]['State']['Running'];call(D+['rm',e['id']]);r['removed_containers'].append(e['id']);save()
  assert not call(D+['ps','-a','--filter','volume='+v['Name'],'--format','{{.ID}}']);call(D+['volume','rm',v['Name']]);r['removed_volumes'].append(v['Name']);save()
  urlpaths=set()
  for e in m['resources']:
   s=json.loads(pathlib.Path(e['state_path']).read_text());urlpaths.update(c['url_file'] for c in s.get('cases',{}).values());root=pathlib.Path(e['state_path']).parent;urlpaths.update(str(p) for p in root.glob('*-url.txt'))
  manifest=R/'active-case-manifest.json';active=json.loads(manifest.read_text())
  for e in active.get('cases',[])+active.get('retired_cases',[]):
   if e.get('container_id') in ids:
    for k in ['url_file','canonical_url_file']:
     if e.get(k):urlpaths.add(e[k])
  projection=R/'mysql-owned.json'
  if projection.exists():
   pr=json.loads(projection.read_text());assert pr.get('test_guard_only') is True or pr.get('kind')=='test_guard_only_projection'
   for c in pr.get('cases',{}).values():
    if c.get('url_file'):urlpaths.add(c['url_file'])
  for name in sorted(urlpaths):
   p=pathlib.Path(name);assert not p.is_symlink();p.resolve().relative_to(R.resolve())
   if p.exists():p.unlink();r['retired_urls'].append(str(p))
  for e in m['resources']:
   p=pathlib.Path(e['state_path']);dest=p.with_name(p.stem+'-retired-final.json');assert not dest.exists();p.rename(dest)
  if projection.exists():projection.rename(R/'mysql-testguard-projection-retired-final.json')
  active['status']='ALL_C6_OWNED_ENVIRONMENTS_REMOVED';active['final_retirement_receipt']=str(P);active['retired_cases']=active.get('retired_cases',[])+[dict(e,status='RETIRED_FINAL_ENVIRONMENT_REMOVED') for e in active.get('cases',[])];active['cases']=[];manifest.write_text(json.dumps(active,indent=2)+'\n')
  r['remaining_container_inventory']=call(D+['ps','-a','--no-trunc','--format','{{json .}}']).splitlines();r['orbstack_restore']='NOT_ATTEMPTED'
  if x.root_restore_initial_orbstack_approved:
   vm=subprocess.run(['orb','list'],capture_output=True,text=True,timeout=7);proc=subprocess.run(['ps','-axo','pid=,comm='],capture_output=True,text=True,timeout=7);sock=subprocess.run(['lsof','-n','-a','-U',str(pathlib.Path.home()/'.orbstack/run/docker.sock')],capture_output=True,text=True,timeout=7)
   suspicious=[l for l in proc.stdout.splitlines() if any(w in l.lower() for w in ['cargo','rustc','xcodebuild','gradle','emulator','buildkit','containerd-shim'])];r['restore_guards']={'remaining_containers':r['remaining_container_inventory'],'orb_list':vm.stdout,'build_clients':suspicious,'docker_socket_clients':sock.stdout}
   # Any unexplained socket client is conservative STOP-RUNNING, never guess ownership.
   socketlines=[l for l in sock.stdout.splitlines()[1:] if l and not l.startswith('OrbStack')]
   if not r['remaining_container_inventory'] and vm.returncode==0 and not vm.stdout.strip() and not suspicious and not socketlines:
    call(['orb','stop']);status=subprocess.run(['orb','status'],capture_output=True,text=True,timeout=7);r['orbstack_restore']={'stdout':status.stdout,'stderr':status.stderr,'exit_code':status.returncode};assert 'Stopped' in status.stdout+status.stderr
   else:r['orbstack_restore']='LEFT_RUNNING_EXTERNAL_OR_UNCERTAIN_CLIENT_GUARD'
  r['status']='OWNED_CLEANUP_COMPLETE';save();print(json.dumps({'receipt':str(P),'sha256':sha(P),'status':r['status'],'orbstack_restore':r['orbstack_restore']}))
 except Exception as e:
  r['status']='STOPPED_FIRST_ERROR_PARTIAL_STATE_PRESERVED';r['first_error_type']=type(e).__name__;r['first_error']='Subprocess argv withheld' if isinstance(e,subprocess.SubprocessError) else str(e);save();raise RuntimeError(r['first_error']) from None
if __name__=='__main__':main()
