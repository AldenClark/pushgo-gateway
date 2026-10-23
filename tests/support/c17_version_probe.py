#!/usr/bin/env python3
"""C17 native old-main version feasibility; only owned clones receive version injection."""
import hashlib,json,os,secrets,shutil,socket,sqlite3,subprocess,sys,threading,time,traceback
from pathlib import Path
import sqlite_cutover_journey as sq
import remote_cutover_journey as pg
import mysql_cutover_journey as my
import legacy_cutover_probe as legacy
ROOT=Path('/Users/ethan/Repo/PushGo/gateway/build/quality-results/c17-downgrade-guard-20261017')
OLD=Path('/Users/ethan/Repo/PushGo/gateway/build/quality-results/c12-final-bounded-20261016/binaries/M-main')
VERSION='2026-10-17-gateway-v13'
pg.CONTAINER='pushgo-c17-pg-20261017';pg.PREFIX='c17_synthetic_';pg.OP_IDS=('c17-history-a','c17-history-b')
my.CONTAINER='pushgo-c17-mysql-20261017';my.PREFIX='c17_synthetic_';my.OP_IDS=pg.OP_IDS
sq.OP_IDS=pg.OP_IDS
my.FROZEN_CATALOG_SQL=Path('/Users/ethan/Repo/PushGo/gateway/build/quality-results/c16-remote-history-20261017/mysql-source-catalog-01/source-schema.sql').read_text()
def write(p,v):
 p.write_text(json.dumps(v,indent=2,sort_keys=True,default=str)+'\n');p.chmod(0o600)
def folder(name):
 p=ROOT/name;p.mkdir(mode=0o700);return p
def cmd(argv,path):
 r=subprocess.run(argv,capture_output=True,timeout=60);path.write_bytes(r.stdout);path.with_suffix(path.suffix+'.stderr').write_bytes(r.stderr);write(path.with_suffix(path.suffix+'.command.json'),{'argv':argv,'exit_code':r.returncode});assert r.returncode==0;return r.stdout
def remote_snap(d,kind,label):
 r=d.root/label;r.mkdir(mode=0o700)
 if kind=='pg':
  names=d.sql("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename",label=label+'-tables').splitlines()
  schema=cmd(['docker','exec',pg.CONTAINER,'pg_dump','-U','postgres','-d',d.name,'--schema-only','--no-owner','--no-privileges'],r/'schema.sql').decode()
  schema='\n'.join(l for l in schema.splitlines() if not l.startswith(('\\restrict','\\unrestrict')))
 else:
  names=d.sql("SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' ORDER BY BINARY TABLE_NAME",label=label+'-tables').splitlines()
  schema=[d.sql('SHOW CREATE TABLE `'+n+'`',label=label+'-schema-'+n) for n in names]
 rows={n:d.rows(('"'+n+'"') if kind=='pg' else n) for n in names}
 for n in rows:rows[n]=sorted(rows[n],key=lambda x:json.dumps(x,sort_keys=True))
 out={'schema':schema,'rows':rows};write(r/'all-schema-rows-version.json',out);return out
def sqlite_snap(d,label):
 result={}
 for path in legacy.family(d):
  with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as c:
   schema=c.execute('SELECT type,name,sql FROM sqlite_master ORDER BY type,name').fetchall()
   rows={n:sorted([repr(r) for r in c.execute('SELECT * FROM "'+n.replace('"','""')+'"')]) for t,n,_ in schema if t=='table'}
   result[path.name]={'schema':schema,'rows':rows}
 write(d/(label+'.json'),result);return result
def probe(product_cls,d,credential,url,kind):
 http,mqtt=legacy.port(),legacy.port();ports=[http,mqtt];argv=[str(OLD),'--http-addr',f'127.0.0.1:{http}','--db-url',url,'--runtime-profile','small','--token-service-url','http://127.0.0.1:1','--private-transports','mqtt','--mqtt-bind',f'127.0.0.1:{mqtt}','--mqtt-port',str(mqtt),'--observability-log-level','info']
 env={k:v for k,v in os.environ.items() if not k.startswith('PUSHGO_')};env['PUSHGO_TOKEN']=credential
 write(d/'oldmain-version.command.json',{'argv':argv,'binary_sha256':legacy.sha(OLD),'synthetic_credential':'private omitted'})
 observed=[];stop=threading.Event()
 def monitor():
  while not stop.is_set():
   for port in ports:
    with socket.socket() as s:
     s.settimeout(.002)
     if s.connect_ex(('127.0.0.1',port))==0:observed.append({'port':port,'monotonic':time.monotonic()})
   stop.wait(.001)
 thread=threading.Thread(target=monitor);thread.start()
 started=time.monotonic()
 try:
  with (d/'oldmain-version.log').open('xb') as log:
   p=subprocess.Popen(argv,stdout=log,stderr=log,env=env)
   try:code=p.wait(timeout=25)
   except subprocess.TimeoutExpired:p.terminate();p.wait(timeout=10);raise
 finally:stop.set();thread.join()
 log=(d/'oldmain-version.log').read_text();receipt={'exit_code':code,'elapsed_seconds':time.monotonic()-started,'tcp_connect_observations':observed,'ports':ports,'poll_interval_seconds':.001,'child_joined':p.poll() is not None,'schema_version_mismatch':'schema_version_mismatch' in log and 'Schema version mismatch: expected ' in log,'api_or_worker_start_log':any(x in log for x in ['HTTP server listening','MQTT server listening'])};write(d/'oldmain-version.receipt.json',receipt)
 assert code!=0 and receipt['schema_version_mismatch'] and not observed,receipt
 return receipt
def run():
 assert legacy.sha(OLD)==sq.SOURCE_SHA
 write(ROOT/'audit/tool-identities.json',{str(Path(m.__file__).resolve()):legacy.sha(Path(m.__file__)) for m in (sq,pg,my,legacy)})
 results={}
 for kind,mod in [('sqlite',sq),('pg',pg),('mysql',my)]:
  legacy.guard_disk(ROOT)
  if kind=='sqlite' and (ROOT/'sqlite-version-clone/oldmain-version.receipt.json').exists():
   target=ROOT/'sqlite-version-clone';source=ROOT/'sqlite-source'
   receipt=json.loads((target/'oldmain-version.receipt.json').read_text());log=(target/'oldmain-version.log').read_text();assert 'schema_version_mismatch' in log and 'Schema version mismatch: expected ' in log and receipt['exit_code']!=0 and not receipt['tcp_connect_observations'];receipt['schema_version_mismatch']=True
   before=json.loads((target/'before-oldmain.json').read_text());after=sqlite_snap(target,'after-oldmain');assert before==json.loads(json.dumps(after)),'STOP: oldmain mutated clone'
   frozen=json.loads((source/'frozen-source.json').read_text());assert frozen==json.loads(json.dumps(sqlite_snap(source,'source-after')))
   write(target/'oracle-correction.json',{'first_failure_preserved':'first-failure.txt','reason':'fixed oldmain emits display error and structured reason, not variant name','verified_receipt':receipt})
   write(target/'injection.json',{'old_version':'2026-08-20-gateway-v12','new_version':VERSION,'only_write':'schema_version in owned clone','no_fake_checksum':True,'no_ddl_mutation':True})
   results[kind]={'status':'PASSED','source':str(source),'version_clone':str(target),'receipt':receipt,'snapshots_unchanged':True}
   continue
  source=folder(kind+'-source');credential=secrets.token_urlsafe(32)
  if kind=='sqlite':
   source.rmdir();expected,sends,_=sq.make_pristine(OLD,source,credential);(source/'synthetic-credential').write_text(credential);write(source/'source-history.json',{'source_sha256':sq.SOURCE_SHA,'source_runtime_profile':'small','expected':expected,'sends':sends,'database_url':f'sqlite://{source}/gateway.sqlite?mode=rwc','injected_business_rows':0})
   frozen=sqlite_snap(source,'frozen-source');target=ROOT/(kind+'-version-clone');legacy.backup_family(source,target);url=f'sqlite://{target}/gateway.sqlite?mode=rwc'
   original=sqlite_snap(target,'before-injection')
   with sqlite3.connect(target/'gateway.sqlite') as c:
    old=c.execute("SELECT meta_value FROM pushgo_schema_meta WHERE meta_key='schema_version'").fetchone()[0];assert old.endswith('-v12'),old;c.execute("UPDATE pushgo_schema_meta SET meta_value=? WHERE meta_key='schema_version'",(VERSION,))
   before=sqlite_snap(target,'before-oldmain');receipt=probe(None,target,credential,url,kind);after=sqlite_snap(target,'after-oldmain');assert before==after,'STOP: oldmain mutated version clone';assert frozen==sqlite_snap(source,'source-after'),'STOP: source changed'
  else:
   d,credential,expected=mod.source(OLD,source);frozen=remote_snap(d,kind,'frozen-source')
   if kind=='pg': clone=pg.clone_database(d.name,ROOT/(kind+'-version-clone'))
   else:
    target=folder(kind+'-version-clone');clone=my.Mysql(target);clone.create();artifact=target/'clone.sql';cmd(['docker','exec',my.CONTAINER,'mysqldump','-uroot','--single-transaction','--hex-blob','--no-tablespaces','--set-gtid-purged=OFF',d.name],artifact)
    argv=['docker','exec','-i',my.CONTAINER,'mysql','-uroot',clone.name];r=subprocess.run(argv,input=artifact.read_bytes(),capture_output=True,timeout=60);write(target/'restore.json',{'argv':argv,'exit':r.returncode});assert r.returncode==0
   target=clone.root;original=remote_snap(clone,kind,'before-injection');v=clone.rows('pushgo_schema_meta');old=next(r['meta_value'] for r in v if r['meta_key']=='schema_version');assert old.endswith('-v12'),old
   clone.sql("UPDATE pushgo_schema_meta SET meta_value='"+VERSION+"' WHERE meta_key='schema_version'",label='only-version-injection')
   before=remote_snap(clone,kind,'before-oldmain');receipt=probe(None,target,credential,clone.url,kind);after=remote_snap(clone,kind,'after-oldmain');assert before==after,'STOP: oldmain mutated version clone';assert frozen==remote_snap(d,kind,'source-after'),'STOP: source changed'
  write(target/'injection.json',{'old_version':old,'new_version':VERSION,'only_write':'UPDATE pushgo_schema_meta schema_version in owned clone','no_fake_checksum':True,'no_ddl_mutation':True})
  results[kind]={'status':'PASSED','source':str(source),'version_clone':str(target),'receipt':receipt,'snapshots_unchanged':True}
  write(ROOT/'native-preflight-result.json',{'proposed_version':VERSION,'results':results,'scope':'fixed oldmain native version feasibility only; candidate protection not implemented'})
 return results
if __name__=='__main__':
 try:run()
 except BaseException:
  (ROOT/'first-failure.txt').write_text(traceback.format_exc());raise
