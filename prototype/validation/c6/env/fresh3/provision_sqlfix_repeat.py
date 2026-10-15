"""Root-authorized one fresh exact-scope synthetic allocation; never workload."""
import pathlib,importlib.util,json,os,hashlib,datetime,contextlib,io
R=pathlib.Path(__file__).resolve().parent;os.umask(0o077)
spec=importlib.util.spec_from_file_location('owned',R/'isolated_db.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
s,i=m.owned('mysql');assert s['id']=='c24a4150e4f3f3e61af1445535b24a9ab1b7c16355b1f4162ae7d17152e67f81' and s['owner']=='829bc0ad72204aff99718fc3073c1752'
assert not any(v['label']=='capacity_sqlfix_repeat' for v in s['cases'].values())
P=R/'allocation-capacity_sqlfix_repeat.json';assert not P.exists()
with contextlib.redirect_stdout(io.StringIO()) as output:m.create('mysql','capacity_sqlfix_repeat',True)
a=json.loads(output.getvalue());s,i=m.owned('mysql');db=a['database'];assert s['cases'][db]['label']=='capacity_sqlfix_repeat'
assert pathlib.Path(a['url_file']).stat().st_mode&0o777==0o600
rec={'backend':'mysql','label':'capacity_sqlfix_repeat','database':db,'url_file':a['url_file'],'container_id':s['id'],'owner_uuid':s['owner'],'image_reference':s['image'],'environment_helper':str(R/'isolated_db.py'),'captured_state':str(R/'mysql-owned.json'),'legacy_fixture_name':True,'environment_namespace':'C6/fresh3/disk3','storage_medium':'disk-backed-named-volume','volume_name':s['volume_name'],'role':s['user']}
manifest=R.parent/'active-case-manifest.json';old=manifest.read_bytes();backup=R.parent/'active-case-manifest.before-capacity-sqlfix-repeat.json';assert not backup.exists();backup.write_bytes(old);d=json.loads(old);d['cases'].append(rec);d['latest_allocation_labels']=['capacity_sqlfix_repeat'];d['timestamp_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();m.save(manifest,d)
m.save(P,{'status':'ALLOCATED_PENDING_EMPTY_QUIET_BUDGET_RESET_CHECK','allocation':rec,'source_path':str(pathlib.Path(__file__).resolve()),'source_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'manifest_before_sha256':hashlib.sha256(old).hexdigest(),'manifest_after_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),'scope':'New legacy case only; helper exact escaped case grant to existing synthetic role; no old DB mutation/privilege changes'})
print(json.dumps({'receipt':str(P),'database':db,'url_file':a['url_file']}))
