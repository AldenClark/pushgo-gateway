#!/usr/bin/env python3
"""Bounded normal-product C16 v1 marker -> C17 durable header acceptance."""
import argparse,copy,json,os,sqlite3,traceback,time
from pathlib import Path
import c17_cutover_acceptance as c
v=c.v
BASELINE=Path('/Users/ethan/Repo/PushGo/gateway/build/quality-results/c16-remote-history-20261017/binaries/pushgo-gateway-final-native')
BASELINE_SHA='8b523af0152c3d69d9a9a58474390b0ea163eff7b63844f58b9f40805c2566ee'
ROOT=v.ROOT/'legacy-marker-acceptance'
def hashes(root):return {str(p.relative_to(root)):c.legacy.sha(p) for p in sorted(root.rglob('*')) if p.is_file()}
def db_for(kind,root,name):
 if kind=='sqlite':return None
 db=c.pg.Pg(root,name) if kind=='pg' else c.my.Mysql(root,name)
 db.sequence=max([int(p.name.split('-')[1]) for p in root.glob('sql-*-*.json')]+[0])+1
 return db
def rows(kind,root,db):
 if kind=='sqlite':
  result={}
  for path in c.legacy.family(root):
   with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as con:
    con.row_factory=sqlite3.Row
    names=[r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for name in names:
     if name.startswith('ordinary_') or name in c.legacy.OBLIGATION_TABLES or name in ('semantic_id_registry','sender_submit_status'):
      result[path.name+':'+name]=sorted(repr(tuple(r)) for r in con.execute('SELECT * FROM "'+name+'"'))
  return result
 names=db.sql("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename" if kind=='pg' else "SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' ORDER BY BINARY TABLE_NAME").splitlines()
 return {n:sorted([json.dumps(r,sort_keys=True) for r in db.rows('"'+n+'"' if kind=='pg' else n)]) for n in names if n.startswith('ordinary_') or n in c.legacy.OBLIGATION_TABLES or n in ('semantic_id_registry','sender_submit_status')}
def marker(kind,root,db):
 value=json.loads((root/'gateway.sqlite.ordinary-cutover.json').read_text()) if kind=='sqlite' else db.rows('pushgo_ordinary_cutover')[0]
 if kind=='mysql':
  for key in ('phase','format','source_profile','sha256','dataset'):
   raw=value[key]
   if raw.startswith('\\x'):value[key]=bytes.fromhex(raw[2:]).decode()
 return value
def state(kind,root,db):
 if kind!='mysql':return c.state(kind,root,db)
 version=next(r['meta_value'] for r in db.rows('pushgo_schema_meta') if r['meta_key']=='schema_version')
 return version,marker(kind,root,db)['phase']
def normal(binary,kind,root,db,label,credential):
 product=c.normal_product(binary,kind,root,db,label,credential)
 try:
  product.ready()
 except BaseException:
  failure=traceback.format_exc();code=product.close();c.write(root/(label+'.failed-normal-receipt.json'),{'binary_sha256':c.legacy.sha(binary),'child_joined':product.child.poll() is not None,'exit_code':code,'startup_failure':failure});raise
 else:assert product.close()==0
 c.write(root/(label+'.normal-receipt.json'),{'binary_sha256':c.legacy.sha(binary),'child_joined':product.child.poll() is not None,'exit_code':product.child.returncode,'http_ready':True,'only_http_action':'GET /'})
def prepare():
 assert c.legacy.sha(BASELINE)==BASELINE_SHA
 ROOT.mkdir(mode=0o700,exist_ok=True);tools=ROOT/'native-tools';cases=json.loads((ROOT/'prepared-cases.json').read_text()) if (ROOT/'prepared-cases.json').exists() else []
 if not tools.exists():tools=c.make_tools(ROOT)
 for kind in ('sqlite','pg','mysql'):
  source=v.ROOT/(kind+'-source');credential=(source/'synthetic-credential').read_text()
  for phase in ('complete','activated'):
   case=ROOT/(kind+'-v1-'+phase)
   if any(x['case']==str(case) for x in cases):continue
   case.mkdir(mode=0o700,exist_ok=True);database=case/'database';backup=case/'v1-backup'
   if database.exists():
    assert kind=='mysql'
    db=db_for(kind,database,json.loads((database/'clone-restore.json').read_text())['argv'][-1])
   else:
    db=c.clone(kind,source,database);c.invoke(BASELINE,kind,database,db,'run',backup,'baseline-v1-run',tools)
   assert state(kind,database,db)==(c.OLDVERSION,'complete')
   m=marker(kind,database,db)
   if kind!='sqlite':assert m['format'].endswith('-v1')
   if phase=='activated':normal(BASELINE,kind,database,db,'baseline-v1-activation',credential)
   assert state(kind,database,db)==(c.OLDVERSION,phase)
   descriptor={'kind':kind,'phase':phase,'case':str(case),'database':str(database),'database_name':None if db is None else db.name,'backup':str(backup),'baseline_sha256':BASELINE_SHA,'baseline_state':state(kind,database,db),'marker_before':marker(kind,database,db),'backup_hashes':hashes(backup),'business_rows_before':rows(kind,database,db),'credential_source':str(source/'synthetic-credential')}
   c.write(case/'prepared.json',descriptor);cases.append(descriptor);c.write(ROOT/'prepared-cases.json',cases)
 c.write(ROOT/'prepare-result.json',{'status':'PASSED','cases':len(cases),'baseline_sha256':BASELINE_SHA,'scope':'real C16 CLI conversion, optional real C16 normal activation; no injected marker/header/checksum'})
def test(binary,sha):
 assert c.legacy.sha(binary)==sha
 tools=ROOT/'native-tools';cases=json.loads((ROOT/'prepared-cases.json').read_text());results=[];tag='-'+sha[:12]
 for case in cases:
  kind=case['kind'];root=Path(case['case']);database=Path(case['database']);backup=Path(case['backup']);db=db_for(kind,database,case['database_name']);credential=Path(case['credential_source']).read_text()
  assert hashes(backup)==case['backup_hashes']
  if (root/'result.json').exists():
   previous=json.loads((root/'result.json').read_text());previous['candidate_sha256']=json.loads((database/'candidate-v1-promotion.normal-receipt.json').read_text())['binary_sha256'];results.append(previous);continue
  started=(database/('candidate-v1-promotion'+tag+'.normal-receipt.json')).exists()
  assert state(kind,database,db)==((c.VERSION,'activated') if started else (c.OLDVERSION,case['phase']))
  if kind!='sqlite' and case['phase']=='complete' and not started:
   before=c.snap(kind,database,db,'v1-restore-before'+tag);c.invoke(binary,kind,database,db,'restore',backup,'v1-restore-safe-rejection'+tag,tools,False);assert c.snap(kind,database,db,'v1-restore-after'+tag)==before
  if not started:normal(binary,kind,database,db,'candidate-v1-promotion'+tag,credential)
  assert state(kind,database,db)==(c.VERSION,'activated')
  actual=rows(kind,database,db);c.write(root/'business-rows-after.json',actual);before=case['business_rows_before']
  assert all(actual.get(k)==value for k,value in before.items()),'PRODUCT FAILURE: promotion changed existing identity/body/responsibility rows'
  for key,value in actual.items():
   if key not in before:
    table=key.split(':')[-1]
    assert not value or table in ('ordinary_ledger_usage','ordinary_limits'),('PRODUCT FAILURE: unexpected new responsibility',key,value)
  m=marker(kind,database,db);prior=copy.deepcopy(case['marker_before']);prior['phase']='activated';assert m==prior,'PRODUCT FAILURE: promotion changed existing marker/backup binding'
  assert hashes(backup)==case['backup_hashes'],'PRODUCT FAILURE: v1 backup mutated'
  refusal=c.reject(c.OLD,kind,database,db,credential,'fixed-oldmain-promoted-v1-refused'+tag);receipt=json.loads((database/('fixed-oldmain-promoted-v1-refused'+tag+'-process/receipt.json')).read_text());assert receipt['exit_code']==1
  before=c.snap(kind,database,db,'activated-v1-restore-before'+tag);c.invoke(binary,kind,database,db,'restore',backup,'activated-v1-restore-rejection'+tag,tools,False);assert c.snap(kind,database,db,'activated-v1-restore-after'+tag)==before;assert hashes(backup)==case['backup_hashes']
  result={'candidate_sha256':sha,'kind':kind,'legacy_phase':case['phase'],'status':'PASSED','version_before':c.OLDVERSION,'version_after':c.VERSION,'normal_product_boot':True,'identity_body_responsibility_rows_unchanged':True,'backup_bytes_and_format_unchanged':True,'oldmain_exit':receipt['exit_code'],'oldmain_no_http_mqtt_unchanged':refusal,'activated_restore_rejected_unchanged':True,'v1_complete_remote_restore_rejected_unchanged':kind!='sqlite' and case['phase']=='complete'};results.append(result);c.write(root/'result.json',result);c.write(ROOT/'result.json',{'candidate':str(binary),'candidate_sha256':sha,'baseline_sha256':BASELINE_SHA,'results':results})
 for kind in ('sqlite','pg','mysql'):c.verify_frozen_source(kind,c.directory(ROOT/(kind+'-frozen-source-audit')))
 c.write(ROOT/'result.json',{'status':'PASSED','candidate':str(binary),'candidate_sha256':sha,'baseline_sha256':BASELINE_SHA,'results':results,'frozen_sources_unchanged':True})
def prepare_restore():
 assert c.legacy.sha(BASELINE)==BASELINE_SHA
 root=c.directory(ROOT/'sqlite-v1-complete-restore');source=v.ROOT/'sqlite-source';database=root/'database';backup=root/'v1-backup'
 c.clone('sqlite',source,database)
 before=c.snap('sqlite',database,None,'original-source')
 c.invoke(BASELINE,'sqlite',database,None,'run',backup,'baseline-v1-run',ROOT/'native-tools')
 assert state('sqlite',database,None)==(c.OLDVERSION,'complete')
 c.write(root/'prepared.json',{'database':str(database),'backup':str(backup),'backup_hashes':hashes(backup),'original_source':before,'baseline_sha256':BASELINE_SHA})
def test_restore(binary,sha):
 assert c.legacy.sha(binary)==sha
 root=ROOT/'sqlite-v1-complete-restore';case=json.loads((root/'prepared.json').read_text());database=Path(case['database']);backup=Path(case['backup']);source=v.ROOT/'sqlite-source'
 assert state('sqlite',database,None)==(c.OLDVERSION,'complete')
 c.invoke(binary,'sqlite',database,None,'restore',backup,'candidate-restore-'+sha[:12],ROOT/'native-tools')
 c.assert_version('sqlite',database,None,c.OLDVERSION)
 after=c.snap('sqlite',database,None,'restored-original-source');assert json.loads(json.dumps(after))==case['original_source']
 assert hashes(backup)==case['backup_hashes']
 history=json.loads((source/'source-history.json').read_text());expected=history['expected']
 for item in history['sends']:expected[item['op_id']]['old_status']=item['send_status']['data']
 c.ready_old('sqlite',database,None,(source/'synthetic-credential').read_text(),expected,'restored-fixed-oldmain')
 assert hashes(backup)==case['backup_hashes']
 c.write(root/'result.json',{'status':'PASSED','candidate_sha256':sha,'baseline_sha256':BASELINE_SHA,'original_source_full_snapshot_restored':True,'version_after':c.OLDVERSION,'fixed_oldmain_normal_boot_and_original_send_status':True,'backup_bytes_and_format_unchanged':True,'child_joined':True,'scope':'real C16 v1 complete12; C17 CLI restore before activation; fixed-oldmain normal boot'})
def main():
 p=argparse.ArgumentParser();p.add_argument('action',choices=('prepare','test','prepare-restore','test-restore'));p.add_argument('--candidate-binary',type=Path);p.add_argument('--candidate-sha256');a=p.parse_args();os.umask(0o077)
 try:
  if a.action=='prepare':prepare()
  elif a.action=='prepare-restore':prepare_restore()
  elif a.action=='test-restore':test_restore(a.candidate_binary.resolve(),a.candidate_sha256)
  else:test(a.candidate_binary.resolve(),a.candidate_sha256)
 except BaseException:
  failure=ROOT/'first-failure.txt'
  if not failure.exists():failure.write_text(traceback.format_exc())
  else:(ROOT/('failure-'+str(time.time_ns())+'.txt')).write_text(traceback.format_exc())
  raise
if __name__=='__main__':main()
