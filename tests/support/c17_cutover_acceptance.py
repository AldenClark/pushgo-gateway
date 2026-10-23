#!/usr/bin/env python3
"""Finite C17 native acceptance. Owned C17 sources only; no production mutations."""
import argparse,contextlib,copy,hashlib,inspect,json,os,secrets,shutil,signal,socket,sqlite3,subprocess,threading,time,traceback
from pathlib import Path
import c17_version_probe as v
sq,pg,my,legacy=v.sq,v.pg,v.my,v.legacy
SOURCE=v.ROOT
SQCAND=sq.CandidateProduct
SQINSPECT=sq.inspect_ordinary_live
VERSION=v.VERSION
OLD=v.OLD
OLDVERSION='2026-08-20-gateway-v12'
def write(p,x):v.write(p,x)
def directory(p):p.mkdir(mode=0o700);return p
def clone(kind,source,root):
 legacy.guard_disk(root.parent)
 if kind=='sqlite':legacy.backup_family(source,root);return None
 history=json.loads((source/'source-history.json').read_text())
 if kind=='pg':return pg.clone_database(history['database_name'],root)
 directory(root);db=my.Mysql(root);db.create();artifact=root/'clone.sql';v.cmd(['docker','exec',my.CONTAINER,'mysqldump','-uroot','--single-transaction','--hex-blob','--no-tablespaces','--set-gtid-purged=OFF',history['database_name']],artifact)
 argv=['docker','exec','-i',my.CONTAINER,'mysql','-uroot',db.name];p=subprocess.run(argv,input=artifact.read_bytes(),capture_output=True,timeout=60);write(root/'clone-restore.json',{'argv':argv,'exit_code':p.returncode});assert p.returncode==0
 return db
def url(kind,root,db):return f'sqlite://{root}/gateway.sqlite?mode=rwc' if kind=='sqlite' else db.url
def snap(kind,root,db,label):return v.sqlite_snap(root,label) if kind=='sqlite' else v.remote_snap(db,kind,label)
def business(s,kind):
 s=copy.deepcopy(s)
 if kind=='sqlite':return s
 s['rows'].pop('pushgo_product_owner',None);s['rows'].pop('pushgo_ordinary_cutover',None)
 # Catalog excludes only exact pre-existing coordination objects via native QA catalog.
 if kind=='mysql':s['schema']=[x for x in s['schema'] if x.split('\t',1)[0] not in ('pushgo_product_owner','pushgo_ordinary_cutover')]
 else:
  # pg_dump embeds multi-line metadata; table-local catalog avoids imprecise text deletion.
  s.pop('schema')
 return s
def canonical(kind,root,db):
 if kind=='sqlite':return legacy.logical_snapshot(root)
 mod=pg if kind=='pg' else my
 return mod.snapshot(db)
def state(kind,root,db):
 if kind=='sqlite':
  marker=json.loads((root/'gateway.sqlite.ordinary-cutover.json').read_text());c=sqlite3.connect(root/'gateway.sqlite');version=c.execute("SELECT meta_value FROM pushgo_schema_meta WHERE meta_key='schema_version'").fetchone()[0];c.close();return version,marker['phase']
 rows=db.rows('pushgo_schema_meta');version=next(x['meta_value'] for x in rows if x['meta_key']=='schema_version');phase=db.rows('pushgo_ordinary_cutover')[0]['phase']
 if kind=='mysql' and isinstance(phase,str) and phase.startswith('\\x'):phase=bytes.fromhex(phase[2:]).decode('ascii')
 return version,phase
def assert_version(kind,root,db,want):
 if kind=='sqlite':
  with sqlite3.connect(root/'gateway.sqlite') as c:actual=c.execute("SELECT meta_value FROM pushgo_schema_meta WHERE meta_key='schema_version'").fetchone()[0]
 else:actual=next(x['meta_value'] for x in db.rows('pushgo_schema_meta') if x['meta_key']=='schema_version')
 assert actual==want,(kind,actual,want)
def invoke(binary,kind,root,db,action,backup,label,tools,success=True):
 legacy.guard_disk(root);argv=[str(binary),'--db-url',url(kind,root,db),'--ordinary-cutover',action,'--ordinary-cutover-backup',str(backup),'--ordinary-source-profile','small'];env={k:x for k,x in os.environ.items() if not k.startswith(('PUSHGO_','MYSQL_'))};env['PATH']=str(tools)+os.pathsep+os.environ.get('PATH','')
 write(root/(label+'.command.json'),{'argv':argv,'PATH_override':str(tools),'binary_sha256':legacy.sha(binary)})
 with (root/(label+'.log')).open('xb') as out:p=subprocess.run(argv,env=env,stdout=out,stderr=out,timeout=100)
 write(root/(label+'.exit.json'),{'exit_code':p.returncode});assert (p.returncode==0)==success,(kind,label,p.returncode);return p.returncode
def external_markers(root):
 return {p.name:{'sha256':legacy.sha(p),'bytes':p.stat().st_size} for p in root.iterdir() if p.is_file() and ('.ordinary-cutover.' in p.name or p.name.endswith('.product-owner'))}
def reject(binary,kind,root,db,credential,label):
 before=snap(kind,root,db,label+'-before');external_before=external_markers(root);pdir=directory(root/(label+'-process'));http,mqtt=legacy.port(),legacy.port();argv=[str(binary),'--db-url',url(kind,root,db),'--http-addr',f'127.0.0.1:{http}','--runtime-profile','small','--token-service-url','http://127.0.0.1:1','--private-transports','mqtt','--mqtt-bind',f'127.0.0.1:{mqtt}','--mqtt-port',str(mqtt)];env={k:x for k,x in os.environ.items() if not k.startswith('PUSHGO_')};env['PUSHGO_TOKEN']=credential
 stop=threading.Event();accepts=[]
 def observe():
  while not stop.is_set():
   for port in (http,mqtt):
    with socket.socket() as s:
     s.settimeout(.002)
     if s.connect_ex(('127.0.0.1',port))==0:accepts.append(port)
   stop.wait(.001)
 thread=threading.Thread(target=observe);thread.start()
 try:
  with (pdir/'normal.log').open('xb') as out:
   child=subprocess.Popen(argv,env=env,stdout=out,stderr=out)
   try:code=child.wait(timeout=25)
   except subprocess.TimeoutExpired:child.terminate();child.wait(timeout=10);raise
 finally:stop.set();thread.join()
 log=(pdir/'normal.log').read_text();write(pdir/'receipt.json',{'argv':argv,'binary_sha256':legacy.sha(binary),'exit_code':code,'tcp_accepts':accepts,'ports':[http,mqtt],'poll_seconds':.001,'child_joined':child.poll() is not None})
 assert code!=0 and not accepts,(kind,label,code,accepts)
 if binary==OLD:assert 'schema_version_mismatch' in log and 'Schema version mismatch:' in log,log
 else:assert 'cutover' in log.lower() and ('incomplete' in log.lower() or 'restor' in log.lower()),log
 after=snap(kind,root,db,label+'-after');external_after=external_markers(root);write(pdir/'external-marker-snapshots.json',{'before':external_before,'after':external_after});assert external_before==external_after,'PRODUCT FAILURE: rejected normal startup changed external phase marker';assert before==after,'PRODUCT FAILURE: rejected normal startup mutated schema/rows/version'
 return {'exit_code':code,'tcp_accepts':0,'full_snapshot_unchanged':True}
def normal_product(binary,kind,root,db,label,credential):return SQCAND(binary,root,label,credential) if kind=='sqlite' else pg.Product(binary,root,label,credential,db.url)
def ready_old(kind,root,db,credential,expected,label):
 p=normal_product(OLD,kind,root,db,label,credential)
 try:
  p.ready()
  for op,fact in expected.items():
   value,status=p.request('/send_status/'+op);assert status==200
   for key in ('op_id','model','entity_id','status','accepted_at','expires_at'):assert value['data'][key]==fact['old_status'][key],(key,value,fact)
 finally:assert p.close()==0
 return True
def make_tools(root):
 tools=directory(root/'native-tools');old=Path('/Users/ethan/Repo/PushGo/gateway/build/quality-results/c16-remote-history-20261017/native-tools')
 for name in ('pg_dump','pg_restore','mysqldump','mysql'):
  text=(old/name).read_text().replace('pushgo-c16-','pushgo-c17-').replace('C16','C17');(tools/name).write_text(text);(tools/name).chmod(0o700)
 return tools
def prepare_oracles(root):
 pg.FROZEN_CATALOG_SQL=(Path(pg.__file__).parents[2]/'src/ordinary/pg_cutover/catalog.sql').read_text();my.FROZEN_CATALOG_SQL=(Path(my.__file__).parents[2]/'src/ordinary/mysql_cutover/catalog.sql').read_text()
 # Reuse the actual bounded MQTT oracle with explicit source/op-name adapters.
 text=inspect.getsource(pg.verify_normal_candidate).replace('C16-HISTORY-A','C17-HISTORY-A')
 needle='assert after_ack["payload_bytes"] == 0 and after_ack["payload_blob_length"] == 0, after_ack'
 text=text.replace(needle,needle+'\n        duplicate_acks = []\n        for _ in range(2):\n            duplicate, duplicate_http = p.request("/v2/messages/ack", {"device_key":device,"delivery_ids":[delivery_id]})\n            assert duplicate_http == 200 and duplicate["data"]["removed_count"] == 0\n            duplicate_acks.append(duplicate)\n        write_json(directory / "repeat-ack-after-puback.json", duplicate_acks)')
 (root/'adapted-normal-oracle.py').write_text(text);ns=dict(pg.__dict__);exec(compile(text,str(root/'adapted-normal-oracle.py'),'exec'),ns);return ns['verify_normal_candidate']
def journey(binary,kind,root,tools,verify,resume_mysql_complete=False):
 source=SOURCE/(kind+'-source');history=json.loads((source/'source-history.json').read_text());expected=history['expected'];credential=(source/'synthetic-credential').read_text()
 if kind=='sqlite':
  for item in history['sends']:expected[item['op_id']]['old_status']=item['send_status']['data']
 restore_root=root/'restore-before-activation';backup=root/'backup-before-activation'
 if resume_mysql_complete:
  assert kind=='mysql' and 'native-acceptance-first' in root.parts
  previous=json.loads((restore_root/'run.command.json').read_text());argv=previous['argv'];database_url=argv[argv.index('--db-url')+1];db=my.Mysql(restore_root,database_url.rsplit('/',1)[1]);db.sequence=10000
  before=json.loads((restore_root/'source-before/all-schema-rows-version.json').read_text());audit=directory(root/'resume-source-catalog');source_db=my.Mysql(audit,history['database_name']);catalog_before=canonical(kind,audit,source_db)
  assert state(kind,restore_root,db)==(VERSION,'complete');write(root/'resume-oracle-correction.json',{'first_failure':'../../first-failure.txt','known_ascii_phase_decoded':True,'reused_existing_plan_run':True,'new_product_operations_before_resume':0,'harness_sha256':legacy.sha(Path(__file__))})
 else:
  db=clone(kind,source,restore_root);before=snap(kind,restore_root,db,'source-before');catalog_before=canonical(kind,restore_root,db)
  invoke(binary,kind,restore_root,db,'plan',backup,'plan',tools);afterplan=snap(kind,restore_root,db,'after-plan');assert business(before,kind)==business(afterplan,kind);assert canonical(kind,restore_root,db)==catalog_before
  invoke(binary,kind,restore_root,db,'run',backup,'run',tools);assert state(kind,restore_root,db)==(VERSION,'complete')
 verify_migrated(kind,restore_root,db,expected,source)
 reject(OLD,kind,restore_root,db,credential,'oldmain-complete-refused')
 completed=snap(kind,restore_root,db,'complete');invoke(binary,kind,restore_root,db,'run',backup,'repeat-run',tools);assert snap(kind,restore_root,db,'after-repeat-run')==completed
 if kind=='mysql':
  m=json.loads((backup/'manifest.json').read_text());assert m['format'].endswith('-v2');assert (backup/'source.dump').exists() and (backup/'metadata.dump').exists();dump=(backup/'source.dump').read_text();metadata=(backup/'metadata.dump').read_text();assert 'DROP TABLE IF EXISTS `pushgo_schema_meta`' not in dump and 'DROP TABLE' not in metadata
 invoke(binary,kind,restore_root,db,'restore',backup,'restore',tools);assert_version(kind,restore_root,db,OLDVERSION);afterrestore=snap(kind,restore_root,db,'after-restore');assert business(before,kind)==business(afterrestore,kind);assert canonical(kind,restore_root,db)==catalog_before;ready_old(kind,restore_root,db,credential,expected,'restored-oldmain')
 active=root/'activated';adb=clone(kind,source,active);aback=root/'backup-activated';invoke(binary,kind,active,adb,'plan',aback,'plan',tools);invoke(binary,kind,active,adb,'run',aback,'run',tools);assert state(kind,active,adb)==(VERSION,'complete')
 sq.CandidateProduct=lambda b,d,l,c:normal_product(b,kind,d,adb,l,c)
 def inspect_live(d,op,delivery):
  if kind!='sqlite':return pg.inspect_live(adb,op,delivery) if kind=='pg' else my.inspect_live(adb,op,delivery)
  value=SQINSPECT(d,op,delivery);value['pending_targets']=sum(t['acked_at'] is None for t in value['targets']);return value
 sq.inspect_ordinary_live=inspect_live
 verify(binary,active,credential,{'expected':expected});assert state(kind,active,adb)==(VERSION,'activated');reject(OLD,kind,active,adb,credential,'oldmain-activated-refused');activated=snap(kind,active,adb,'before-denied-restore');invoke(binary,kind,active,adb,'restore',aback,'denied-activated-restore',tools,False);assert snap(kind,active,adb,'after-denied-restore')==activated
 result={'status':'PASSED','plan_business_catalog_readonly':True,'coordination_owner_table_excluded_from_source_equivalence':kind!='sqlite','restored_exact_source_business_catalog_and_v12':True,'restored_oldmain_status_verified':True,'oldmain_complete_and_activated_refused_without_any_schema_row_version_change':True,'mqtt_five_historical_conflicts_puback_body_clear_repeat_ack_restart':True,'activated_restore_denied_unchanged':True}
 write(root/'journey-result.json',result);return result

def remote_faults(binary,kind,root,tools):
 source=SOURCE/(kind+'-source');credential=(source/'synthetic-credential').read_text();db=clone(kind,source,root/'prepared');d=db.root;before=snap(kind,d,db,'source-before');catalog=canonical(kind,d,db);backup=d/'failed-backup';failtools=directory(root/'failing-dump-tools')
 for name in ('pg_dump','pg_restore','mysqldump','mysql'):
  (failtools/name).write_text('#!/bin/sh\nexit 97\n' if name==('pg_dump' if kind=='pg' else 'mysqldump') else (tools/name).read_text());(failtools/name).chmod(0o700)
 invoke(binary,kind,d,db,'run',backup,'native-dump-failed',failtools,False);assert state(kind,d,db)==(VERSION,'prepared');reject(OLD,kind,d,db,credential,'oldmain-prepared-refused');reject(binary,kind,d,db,credential,'candidate-prepared-refused');invoke(binary,kind,d,db,'restore',backup,'prepared-recovered',tools);assert_version(kind,d,db,OLDVERSION);assert business(snap(kind,d,db,'prepared-restored'),kind)==business(before,kind);assert canonical(kind,d,db)==catalog
 # Native restore executes the real archive completely, then reports a child failure.
 db=clone(kind,source,root/'restoring');d=db.root;before=snap(kind,d,db,'source-before');catalog=canonical(kind,d,db);backup=d/'valid-backup';invoke(binary,kind,d,db,'run',backup,'run',tools)
 shim=directory(root/'failing-restore-tools');native='pg_restore' if kind=='pg' else 'mysql'
 for name in ('pg_dump','pg_restore','mysqldump','mysql'):
  text=(tools/name).read_text()
  if name==native:text=text.replace('exec /usr/local/bin/docker','/usr/local/bin/docker')+'\nresult=$?\nif [ "$result" -ne 0 ]; then exit "$result"; fi\nexit 97\n'
  (shim/name).write_text(text);(shim/name).chmod(0o700)
 invoke(binary,kind,d,db,'restore',backup,'native-restore-applied-then-failed',shim,False);assert state(kind,d,db)==(VERSION,'restoring');reject(OLD,kind,d,db,credential,'oldmain-restoring-refused');reject(binary,kind,d,db,credential,'candidate-restoring-refused');invoke(binary,kind,d,db,'restore',backup,'restoring-recovered',tools);assert_version(kind,d,db,OLDVERSION);assert business(snap(kind,d,db,'restoring-restored'),kind)==business(before,kind);assert canonical(kind,d,db)==catalog
 result={'status':'PASSED','prepared_v13_dump_failure_old_and_new_refused':True,'restoring_v13_real_native_restore_child_failure_old_and_new_refused':True,'both_explicit_recoveries_source_v12':True,'fake_sql':False};write(root/'fault-result.json',result);return result

def verify_migrated(kind,root,db,expected,source):
 if kind!='sqlite':
  observed=json.loads((source/'source-observed-history.json').read_text());(pg if kind=='pg' else my).migrated_history(db,expected,observed);return
 with sqlite3.connect(root/'gateway.sqlite') as c:
  c.row_factory=sqlite3.Row;rows=[dict(r) for r in c.execute('SELECT * FROM ordinary_messages')];assert len(rows)==2
  for row in rows:
   fact=expected[row['op_id']];assert row['message_id']==fact['message_id'];assert row['accepted_at']==fact['old_status']['accepted_at'];assert row['channel_id']==fact['channel_id'] and row['thing_id'] is None;assert row['identity_state']=='legacy_unverifiable' and row['status']=='historical_unverifiable';assert all(row[k] is None for k in ('delivery_id','fingerprint','expires_at'));assert row['payload_bytes']==0 and row['payload_blob'] in (b'',None)
 write(root/'migrated-history.json',{'rows':len(rows),'api_ids_accepted_at_scope_preserved':True,'legacy_unverifiable':True,'no_payload_or_delivery_invention':True})

def sqlite_interruption(binary,root):
 import sqlite_cutover_faults as faults
 source=SOURCE/'sqlite-source';text=inspect.getsource(faults)
 text=text.replace('"c15-sqlite-history-20261017" in source.parts','"c17-downgrade-guard-20261017" in source.parts')
 needle='assert after_kill["phase"] == "prepared", "missed pre-completion fault window"'
 injection="\n    import c17_cutover_acceptance as c17\n    c17.assert_version('sqlite',database,None,c17.VERSION)\n    credential=(source/'synthetic-credential').read_text()\n    c17.reject(c17.OLD,'sqlite',database,None,credential,'c17-oldmain-prepared-refused')\n    c17.reject(binary,'sqlite',database,None,credential,'c17-candidate-prepared-refused')\n"
 text=text.replace(needle,needle+injection)
 text=text.replace('before = snapshot(database)', "before = snapshot(database)\n    import c17_cutover_acceptance as c17\n    c17.snap('sqlite',database,None,'c17-precutover-full-source')")
 generated=root.parent/'adapted-sqlite-process-fault.py';generated.write_text(text)
 # Run generated adapter in a joined child; preserve both the native SIGKILL receipt and first fault failure.
 env=dict(os.environ);env['PYTHONPATH']=str(Path(__file__).parent)+os.pathsep+env.get('PYTHONPATH','')
 argv=[str(Path(os.sys.executable)),str(generated),'--candidate-binary',str(binary),'--source-family',str(source),'--evidence-root',str(root)]
 with (root.parent/'sqlite-process-fault.log').open('xb') as log:p=subprocess.run(argv,env=env,stdout=log,stderr=log,timeout=120)
 write(root.parent/'sqlite-process-fault.command.json',{'argv':argv,'exit_code':p.returncode});assert p.returncode==0,'SQLite process interruption gate failed'
 result=json.loads((root/'result.json').read_text());result['actual_restoring_interruption']=sqlite_restoring_interruption(binary,root);write(root/'c17-extended-fault-result.json',result);return result

def sqlite_restoring_interruption(binary,root):
 database=root/'injected-source';backup=root/'backup-after-recovery';marker=database/'gateway.sqlite.ordinary-cutover.json';credential=(SOURCE/'sqlite-source/synthetic-credential').read_text();assert state('sqlite',database,None)==(VERSION,'complete')
 argv=[str(binary),'--db-url',url('sqlite',database,None),'--ordinary-cutover','restore','--ordinary-cutover-backup',str(backup),'--ordinary-source-profile','small'];env={k:x for k,x in os.environ.items() if not k.startswith('PUSHGO_')};observed=None
 write(root/'restoring-interruption.command.json',{'argv':argv,'single_attempt':True,'injection':'SIGKILL only after actual restoring phase observed'})
 with (root/'restoring-interruption.log').open('xb') as log:
  child=subprocess.Popen(argv,env=env,stdout=log,stderr=log);deadline=time.monotonic()+30
  try:
   while time.monotonic()<deadline and child.poll() is None:
    try:
     value=json.loads(marker.read_text())
     if value['phase']=='restoring':observed=value;child.send_signal(signal.SIGKILL);break
    except (FileNotFoundError,json.JSONDecodeError):pass
    time.sleep(.001)
  finally:
   if child.poll() is None and observed is None:child.kill()
   code=child.wait(timeout=10)
 if observed is None:
  receipt={'status':'NOT_INJECTED_WINDOW_MISSED','exit_code':code,'attempts':1,'child_joined':True};write(root/'restoring-interruption-result.json',receipt);return receipt
 try:phase=json.loads(marker.read_text()).get('phase')
 except FileNotFoundError:phase=None
 if code!=-signal.SIGKILL or phase!='restoring':
  receipt={'status':'NOT_INJECTED_WINDOW_MISSED','exit_code':code,'observed':observed,'after_join_phase':phase,'attempts':1,'child_joined':True};write(root/'restoring-interruption-result.json',receipt);return receipt
 assert state('sqlite',database,None)==(VERSION,'restoring')
 reject(OLD,'sqlite',database,None,credential,'oldmain-actual-restoring-refused');reject(binary,'sqlite',database,None,credential,'candidate-actual-restoring-refused')
 invoke(binary,'sqlite',database,None,'restore',backup,'recover-actual-restoring',root.parent.parent/'native-tools');assert_version('sqlite',database,None,OLDVERSION)
 before=json.loads((database/'c17-precutover-full-source.json').read_text());after=json.loads(json.dumps(snap('sqlite',database,None,'after-actual-restoring-recovery')));assert before==after,'PRODUCT FAILURE: real interrupted restore did not recover full source514 schema/rows/version'
 receipt={'status':'PASSED','actual_SIGKILL':True,'observed_phase':observed['phase'],'after_join_guard':VERSION,'after_join_phase':'restoring','old_new_normal_refused_full_snapshot_unchanged':True,'actual_native_recovery_exact_514_source_v12':True,'attempts':1,'child_joined':True};write(root/'restoring-interruption-result.json',receipt);return receipt

def fresh_normal(binary,kind,root):
 credential=secrets.token_urlsafe(32);db=None
 if kind!='sqlite':
  db=pg.Pg(root) if kind=='pg' else my.Mysql(root);db.create();artifact=root/'fresh-empty-database.dump'
  argv=['docker','exec',pg.CONTAINER,'pg_dump','-U','postgres','-d',db.name,'--format=custom'] if kind=='pg' else ['docker','exec',my.CONTAINER,'mysqldump','-uroot','--single-transaction','--routines','--events','--triggers','--hex-blob','--no-tablespaces','--set-gtid-purged=OFF',db.name]
  v.cmd(argv,artifact);write(root/'fresh-upgrade-backup-manifest.json',{'version':1,'driver':'postgres' if kind=='pg' else 'mysql','database_sha256':hashlib.sha256(db.url.encode()).hexdigest(),'artifact_uri':str(artifact),'artifact_sha256':legacy.sha(artifact),'artifact_bytes':artifact.stat().st_size,'completed_at_epoch_seconds':int(time.time())})
 for label in ('new-empty-first','new-empty-repeat'):
  product=normal_product(binary,kind,root,db,label,credential)
  try:product.ready()
  finally:assert product.close()==0
  assert_version(kind,root,db,VERSION)
 reject(OLD,kind,root,db,credential,'oldmain-new-empty-v13-refused')
 result={'status':'PASSED','fresh_normal_create_and_repeat_boot_v13':True,'oldmain_refused_unchanged':True};write(root/'fresh-normal-result.json',result);return result

def verify_frozen_source(kind,root):
 source=SOURCE/(kind+'-source')
 if kind=='sqlite':
  actual={}
  for path in legacy.family(source):
   with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as c:
    schema=c.execute('SELECT type,name,sql FROM sqlite_master ORDER BY type,name').fetchall();rows={n:sorted(repr(x) for x in c.execute('SELECT * FROM "'+n.replace('"','""')+'"')) for t,n,_ in schema if t=='table'};actual[path.name]={'schema':schema,'rows':rows}
  actual=json.loads(json.dumps(actual));frozen=json.loads((source/'frozen-source.json').read_text());write(root/'frozen-source-after.json',actual)
 else:
  history=json.loads((source/'source-history.json').read_text());audit=directory(root/'source-observation');db=pg.Pg(audit,history['database_name']) if kind=='pg' else my.Mysql(audit,history['database_name']);actual=v.remote_snap(db,kind,'full-source-after');frozen=json.loads((source/'frozen-source/all-schema-rows-version.json').read_text())
 assert actual==frozen,'PRODUCT FAILURE: frozen source changed'
 return True

def mysql_partial_ddl(binary,root,tools):
 source=SOURCE/'mysql-source';credential=(source/'synthetic-credential').read_text();db=clone('mysql',source,root/'database');d=db.root;before=snap('mysql',d,db,'source-before');catalog=canonical('mysql',d,db);backup=root/'backup';invoke(binary,'mysql',d,db,'run',backup,'run',tools);assert state('mysql',d,db)==(VERSION,'complete')
 manifest=json.loads((backup/'manifest.json').read_text());assert manifest['format'].endswith('-v2');assert (backup/'metadata.dump').exists()
 shim=directory(root/'partial-native-tools');native=tools/'mysql';script=shim/'mysql'
 body="import json,re,subprocess,sys\nfrom pathlib import Path\nroot=Path(ROOT)\ndata=sys.stdin.buffer.read(8*1024*1024+1)\nassert len(data)<=8*1024*1024\nmatch=re.search(rb'(?m)^DROP TABLE IF EXISTS `([a-zA-Z0-9_]+)`;[^\\n]*\\n',data)\nassert match\nname=match.group(1).decode()\nassert name not in ('pushgo_schema_meta','pushgo_ordinary_cutover','pushgo_product_owner')\nprefix=data[:match.end()]\n(root/'actual-native-prefix.sql').write_bytes(prefix)\nresult=subprocess.run([NATIVE]+sys.argv[1:],input=prefix,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)\n(root/'actual-native-prefix.stdout').write_bytes(result.stdout)\n(root/'actual-native-prefix.stderr').write_bytes(result.stderr)\n(root/'actual-native-prefix-result.json').write_text(json.dumps({'table':name,'prefix_bytes':len(prefix),'exit_code':result.returncode,'actual_native_DDL':True},indent=2))\nassert result.returncode==0\nsys.exit(97)\n"
 body=body.replace('ROOT',repr(str(root))).replace('NATIVE',repr(str(native)));script.write_text('#!'+os.sys.executable+'\n'+body);script.chmod(0o700)
 invoke(binary,'mysql',d,db,'restore',backup,'actual-first-native-drop-then-failure',shim,False)
 ddl=json.loads((root/'actual-native-prefix-result.json').read_text());assert ddl['exit_code']==0;assert state('mysql',d,db)==(VERSION,'restoring')
 count=db.sql("SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='"+ddl['table']+"'",label='independent-native-DROP-effect');assert count=='0',ddl
 reject(OLD,'mysql',d,db,credential,'oldmain-partial-native-DDL-refused');reject(binary,'mysql',d,db,credential,'candidate-partial-native-DDL-refused')
 invoke(binary,'mysql',d,db,'restore',backup,'retry-full-real-native-restore',tools);assert_version('mysql',d,db,OLDVERSION);after=snap('mysql',d,db,'after-full-recovery');assert business(before,'mysql')==business(after,'mysql');assert canonical('mysql',d,db)==catalog
 result={'status':'PASSED','actual_first_native_DROP_table':ddl['table'],'native_prefix_exit_code':0,'shim_exit_code':97,'metadata_header_table_not_dropped':True,'after_fault_version':VERSION,'after_fault_phase':'restoring','old_new_normal_refused_full_schema_rows_metadata_version_unchanged':True,'actual_full_native_restore_source12_exact_business_catalog':True,'single_case':True,'candidate_sha256':legacy.sha(binary)};write(root/'partial-ddl-result.json',result);return result

def main():
 p=argparse.ArgumentParser();p.add_argument('--candidate-binary',required=True,type=Path);p.add_argument('--candidate-sha256',required=True);p.add_argument('--evidence-root',required=True,type=Path);p.add_argument('--backend',choices=('sqlite','pg','mysql','all'),default='all');p.add_argument('--skip-faults',action='store_true');p.add_argument('--lane',choices=('all','journey','fresh','fault'),default='all');args=p.parse_args();os.umask(0o077);binary=args.candidate_binary.resolve();assert legacy.sha(binary)==args.candidate_sha256;root=args.evidence_root.resolve();directory(root);tools=make_tools(root);verify=prepare_oracles(root);write(root/'identities.json',{'candidate':str(binary),'candidate_sha256':args.candidate_sha256,'oldmain_sha256':legacy.sha(OLD),'harness_sha256':legacy.sha(Path(__file__)),'source_metadata':str(SOURCE/'native-preflight-result.json')})
 results={}
 try:
  for kind in (('sqlite','pg','mysql') if args.backend=='all' else (args.backend,)):
   legacy.guard_disk(root);backendroot=directory(root/kind);results[kind]={}
   if args.lane in ('all','journey'):results[kind]['journey']=journey(binary,kind,directory(backendroot/'journey'),tools,verify);write(root/'result.json',results)
   if args.lane in ('all','fresh'):results[kind]['fresh_normal']=fresh_normal(binary,kind,directory(backendroot/'fresh-normal'));write(root/'result.json',results)
   if not args.skip_faults and args.lane in ('all','fault'):
    results[kind]['faults']=sqlite_interruption(binary,backendroot/'sqlite-process-fault') if kind=='sqlite' else remote_faults(binary,kind,directory(backendroot/'faults'),tools)
    write(root/'result.json',results)
   results[kind]['frozen_source_unchanged']=verify_frozen_source(kind,backendroot);write(root/'result.json',results)
 except BaseException:
  (root/'first-failure.txt').write_text(traceback.format_exc());raise
if __name__=='__main__':main()
