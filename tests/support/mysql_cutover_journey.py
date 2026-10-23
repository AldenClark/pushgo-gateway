#!/usr/bin/env python3
"""Owned synthetic MySQL cutover journey using normal Gateway APIs.

No caller-selected existing database is accepted. All SQL observation is read-only;
creation/cloning is restricted to unique c16_synthetic_* databases in the QA container.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import traceback
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sqlite_cutover_journey as base
import legacy_cutover_probe as legacy

Mqtt5Peer = base.Mqtt5Peer

CONTAINER = 'pushgo-c16-mysql-20261017'
PREFIX = 'c16_synthetic_'
SOURCE_SHA = base.SOURCE_SHA
OP_IDS = ('c16-history-a', 'c16-history-b')
FROZEN_BINARIES = {}
RUNTIME_USER = 'c16_app'
FROZEN_CATALOG_SQL = None


def write_json(path, value):
    base.write_json(path, value)


class Mysql:
    def __init__(self, root, name=None):
        self.root = root
        self.name = name or PREFIX + secrets.token_hex(8)
        assert self.name.startswith(PREFIX) and self.name.replace('_', '').isalnum()
        self.url = 'mysql://root@127.0.0.1:42773/' + self.name
        self.sequence = 0

    def sql(self, sql, database=None, label='query'):
        self.sequence += 1
        stem = self.root / ('sql-%03d-%s' % (self.sequence, label))
        stem.with_suffix('.sql').write_text(sql + '\n', encoding='utf8')
        argv = ['docker','exec','-i',CONTAINER,'mysql','-uroot','--batch','--raw','--skip-column-names']
        if database is not False:
            argv += [database or self.name]
        result = subprocess.run(argv,input=sql,text=True,capture_output=True,timeout=30)
        stem.with_suffix('.stdout').write_text(result.stdout,encoding='utf8')
        stem.with_suffix('.stderr').write_text(result.stderr,encoding='utf8')
        write_json(stem.with_suffix('.json'),{'argv':argv,'exit_code':result.returncode})
        assert result.returncode==0,('SQL failed',str(stem))
        return result.stdout.strip()

    def create(self):
        self.sql('CREATE DATABASE `'+self.name+'` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci',database=False,label='create-owned-database')

    def rows(self, table, where='TRUE'):
        name = table.strip('`')
        assert name.replace('_','').isalnum()
        columns = self.sql("SELECT COLUMN_NAME,DATA_TYPE FROM information_schema.columns WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='"+name+"' ORDER BY ORDINAL_POSITION",label='table-columns')
        parts=[]
        for line in columns.splitlines():
            column,kind=line.split('\t')
            expression='`'+column+'`'
            if kind in ('binary','varbinary','tinyblob','blob','mediumblob','longblob'):
                if column in ('op_id','identity_state','historical_op'):
                    expression="CAST(`"+column+"` AS CHAR CHARACTER SET utf8mb4)"
                else:
                    expression="IF(`"+column+"` IS NULL,NULL,CAST(CONCAT(CHAR(92),'x',LOWER(HEX(`"+column+"`))) AS CHAR CHARACTER SET utf8mb4))"
            parts += ["'"+column+"'",expression]
        result=self.sql("SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT("+','.join(parts)+")),JSON_ARRAY()) FROM `"+name+'` WHERE '+where,label='table-rows')
        return json.loads(result)


class Product(base.ObservedProduct):
    def __init__(self, binary, directory, label, credential, database_url):
        legacy.guard_disk(directory)
        identity = legacy.sha(binary)
        assert str(binary) not in FROZEN_BINARIES or FROZEN_BINARIES[str(binary)] == identity
        if label in ('candidate-first','candidate-restarted','normal-http-v2-pull-ack'):
            database_url = database_url.replace('mysql://root@','mysql://'+RUNTIME_USER+'@',1)
        self.base = 'http://127.0.0.1:' + str(legacy.port())
        self.mqtt_port = legacy.port()
        self.credential = credential
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.events = []
        self.http_observed = False
        self.log_path = directory / (label + '.log')
        self.events_path = directory / (label + '.http.json')
        argv = [str(binary), '--http-addr', self.base.removeprefix('http://'),
                '--db-url', database_url, '--runtime-profile', 'small',
                '--token-service-url', 'http://127.0.0.1:1', '--private-transports', 'mqtt',
                '--mqtt-bind', '127.0.0.1:' + str(self.mqtt_port),
                '--mqtt-port', str(self.mqtt_port), '--observability-log-level', 'info']
        write_json(directory / (label + '.command.json'), {'argv': argv, 'binary_sha256': legacy.sha(binary),
                   'PUSHGO_TOKEN': 'synthetic environment; value omitted'})
        env = {k:v for k,v in os.environ.items() if not k.startswith('PUSHGO_')}
        env['PUSHGO_TOKEN'] = credential
        manifest = directory / 'fresh-upgrade-backup-manifest.json'
        if manifest.exists():
            env['PUSHGO_DB_UPGRADE_BACKUP_MANIFEST'] = str(manifest)
        with self.log_path.open('xb') as log:
            self.child = subprocess.Popen(argv, stdout=log, stderr=log, env=env)
        self.closed = False

    def close(self):
        if self.closed:
            return self.child.returncode
        result = super().close()
        self.closed = True
        write_json(self.log_path.with_suffix('.exit.json'), {'exit_code': result})
        return result


def capture_catalog(database, root):
    names=database.sql("SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' ORDER BY BINARY TABLE_NAME",label='catalog-tables').splitlines()
    catalog=[]
    for name in names:
        assert name.replace('_','').isalnum()
        output=database.sql('SHOW CREATE TABLE `'+name+'`',label='show-create-'+name)
        table,definition=output.split('\t',1)
        catalog.append([table,definition])
    write_json(root/'show-create-tables.json',catalog)
    sql=FROZEN_CATALOG_SQL.strip().rstrip(';')
    output=database.sql('SELECT JSON_ARRAY(kind,name,definition) FROM ('+sql+') canonical',label='canonical-source-catalog')
    canonical=[json.loads(line) for line in output.splitlines()]
    write_json(root/'source-schema.json',canonical)
    (root/'source-schema.sql').write_text(sql)
    return catalog


def source(binary, root, catalog_sql=None):
    assert legacy.sha(binary) == SOURCE_SHA, 'fixed oldmain SHA mismatch'
    legacy.guard_disk(root)
    pg = Mysql(root)
    pg.create()
    artifact = root / 'fresh-empty-database.dump'
    argv = ['docker','exec',CONTAINER,'mysqldump','-uroot','--single-transaction','--routines','--events','--triggers','--hex-blob','--no-tablespaces','--set-gtid-purged=OFF',pg.name]
    with artifact.open('xb') as stream:
        dumped = subprocess.run(argv,stdout=stream,stderr=subprocess.PIPE,timeout=30)
    (root / 'fresh-empty-backup.stderr').write_bytes(dumped.stderr)
    write_json(root / 'fresh-empty-backup.command.json', {'argv':argv,'exit_code':dumped.returncode})
    assert dumped.returncode == 0, 'fresh backup failed'
    write_json(root / 'fresh-upgrade-backup-manifest.json', {'version':1,'driver':'mysql',
        'database_sha256':hashlib.sha256(pg.url.encode()).hexdigest(),'artifact_uri':str(artifact),
        'artifact_sha256':legacy.sha(artifact),'artifact_bytes':artifact.stat().st_size,
        'completed_at_epoch_seconds':int(time.time())})
    credential = secrets.token_urlsafe(32)
    (root / 'synthetic-credential').write_text(credential, encoding='ascii')
    product = Product(binary, root, 'oldmain-source', credential, pg.url)
    expected, sends = {}, []
    try:
        product.ready()
        device = product.request('/device/register', {'platform':'mqtt'})[0]['data']['device_key']
        product.request('/channel/device', {'device_key':device,'platform':'mqtt','channel_type':'private'})
        channel = product.request('/channel/subscribe', {'device_key':device,'channel_name':'c16-empty-target','password':credential})[0]['data']['channel_id']
        product.request('/channel/unsubscribe', {'device_key':device,'channel_id':channel})
        expiry = int(time.time()*1000) + 3600000
        for i, op in enumerate(OP_IDS):
            fact = {'channel_id':channel,'title':'c16 title '+str(i),'body':'c16 synthetic original body '+str(i),'ttl':expiry+i}
            response = base.send(product, channel, credential, op, fact['title'],fact['body'],fact['ttl'])
            fact['message_id'] = response['response']['data']['message_id']
            status, http_status = product.request('/send_status/'+op)
            fact['old_status'] = status['data']
            expected[op] = fact
            sends.append({'op_id':op,'response':response,'send_status':status,'send_status_http':http_status})
    finally:
        assert product.close() == 0
    write_json(root / 'source-history.json', {'source_binary':str(binary),'source_sha256':SOURCE_SHA,
        'database_url':pg.url,'database_name':pg.name,'container':CONTAINER,'source_runtime_profile':'small',
        'normal_api_chain':['mqtt registration','Private route','subscribe','unsubscribe','two zero-target messages'],
        'expected':expected,'sends':sends,'injected_business_rows':0})
    # Stable row observations never include credential-bearing tables.
    observed = {table:pg.rows(table) for table in base.TABLES}
    write_json(root / 'source-observed-history.json', observed)
    assert len(observed['sender_submit_status']) == 2
    assert len(observed['semantic_id_registry']) == 2
    for table in legacy.OBLIGATION_TABLES:
        assert not observed[table], (table, observed[table])
    capture_catalog(pg, root)
    return pg, credential, expected


def provision_runtime_user(database):
    assert RUNTIME_USER=='c16_app'
    database.sql("CREATE USER IF NOT EXISTS 'c16_app'@'%' IDENTIFIED BY ''",database=False,label='create-owned-runtime-account')
    database.sql("GRANT ALL PRIVILEGES ON `"+database.name+"`.* TO 'c16_app'@'%'",database=False,label='grant-runtime-only-owned-database')
    grants=database.sql("SHOW GRANTS FOR 'c16_app'@'%'",database=False,label='verify-runtime-grants').splitlines()
    assert all(line.startswith('GRANT USAGE ON *.* TO ') or line.startswith('GRANT ALL PRIVILEGES ON `c16_synthetic_') for line in grants),grants
    global_process=int(database.sql("SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=CONCAT(CHAR(39),'c16_app',CHAR(39),'@',CHAR(39),'%',CHAR(39)) AND PRIVILEGE_TYPE='PROCESS'",database=False,label='verify-no-global-process'))
    assert global_process==0
    write_json(database.root/'runtime-privileges.json',{'user':RUNTIME_USER,'global_process':False,'grants':grants,'normal_runtime_global_privilege_added':False})


def clone_database(template, root):
    assert template.startswith(PREFIX) and template.replace('_', '').isalnum()
    root.mkdir(mode=0o700)
    database=Mysql(root)
    database.create()
    provision_runtime_user(database)
    artifact=root/'clone-native-source.sql'
    dump_argv=['docker','exec',CONTAINER,'mysqldump','-uroot','--single-transaction','--routines','--events','--triggers','--hex-blob','--no-tablespaces','--set-gtid-purged=OFF',template]
    with artifact.open('xb') as output:
        dumped=subprocess.run(dump_argv,stdout=output,stderr=subprocess.PIPE,timeout=30)
    write_json(root/'clone-native-dump.command.json',{'argv':dump_argv,'exit_code':dumped.returncode,'sha256':legacy.sha(artifact)})
    (root/'clone-native-dump.stderr').write_bytes(dumped.stderr)
    assert dumped.returncode==0
    restore_argv=['docker','exec','-i',CONTAINER,'mysql','-uroot',database.name]
    with artifact.open('rb') as stream:
        restored=subprocess.run(restore_argv,stdin=stream,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    write_json(root/'clone-native-restore.command.json',{'argv':restore_argv,'exit_code':restored.returncode})
    (root/'clone-native-restore.stderr').write_bytes(restored.stderr)
    assert restored.returncode==0
    return database


def invoke(binary, mode, pg, backup, label):
    legacy.guard_disk(pg.root)
    assert legacy.sha(binary) == FROZEN_BINARIES[str(binary)]
    argv = [str(binary),'--ordinary-cutover',mode,'--ordinary-cutover-backup',str(backup),
            '--ordinary-source-profile','small','--db-url',pg.url]
    log = pg.root / ('cutover-' + label + '.log')
    with log.open('xb') as stream:
        result = subprocess.run(argv,stdout=stream,stderr=subprocess.STDOUT,timeout=90)
    write_json(pg.root / ('cutover-' + label + '.json'),{'argv':argv,'exit_code':result.returncode,
               'binary_sha256':legacy.sha(binary),'stdout_stderr_path':str(log)})
    return result.returncode


def snapshot(database):
    names=database.sql("SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' AND TABLE_NAME NOT IN ('pushgo_product_owner','pushgo_ordinary_cutover') ORDER BY BINARY TABLE_NAME",label='snapshot-tables').splitlines()
    tables={}
    for name in names:
        rows=database.rows(name)
        assert len(rows)<=256
        tables[name]={'rows':len(rows),'sha256':hashlib.sha256(json.dumps(sorted(json.dumps(row,sort_keys=True) for row in rows)).encode()).hexdigest()}
    output=database.sql('SELECT JSON_ARRAY(kind,name,definition) FROM ('+FROZEN_CATALOG_SQL.strip().rstrip(';')+') canonical',label='snapshot-catalog')
    catalog=[json.loads(line) for line in output.splitlines()]
    return {'catalog':catalog,'tables':tables}


def migrated_history(pg, expected, observations):
    rows = pg.rows('ordinary_messages')
    assert len(rows) == 2
    for row in rows:
        fact = expected[row['op_id']]
        semantic = next(r for r in observations['semantic_id_registry'] if r['semantic_id']==fact['message_id'])
        assert row['message_id']==fact['message_id']
        assert row['accepted_at']==fact['old_status']['accepted_at']
        assert row['channel_id']==fact['channel_id'] and row.get('thing_id') is None
        assert row['identity_state']=='legacy_unverifiable' and row['status']=='historical_unverifiable'
        assert row['delivery_id'] is None and row['fingerprint'] is None and row['expires_at'] is None
        assert row['payload_bytes']==0 and row['payload_blob'] in ('\\x','',None)
        assert row['dedupe_until']==semantic['created_at'] + 7*86400000
    empty = {}
    for table in ('ordinary_targets',)+legacy.OBLIGATION_TABLES:
        present = int(pg.sql("SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='"+table+"'"))==1
        count = int(pg.sql('SELECT count(*) FROM '+table)) if present else 0
        assert count==0,(table,count)
        empty[table]=count
    result={'ordinary_messages':rows,'empty_responsibilities':empty}
    write_json(pg.root/'migrated-history.json',result)
    return result


def inspect_live(database, op, delivery):
    assert op.replace('-','').isalnum() and delivery.replace('-','').isalnum()
    result=inspect_http(database,op,delivery)
    return {'message_id':result['message_id'],'payload_bytes':result['payload_bytes'],
            'payload_blob_length':result['payload_blob_length'],
            'pending_targets':result['unacked_targets'],'target_rows':result['targets']}


def run_candidate(source_binary, candidate, root, source_root):
    assert legacy.sha(source_binary) == SOURCE_SHA
    for binary in (source_binary,candidate):
        FROZEN_BINARIES[str(binary)] = legacy.sha(binary)
    history=json.loads((source_root/'source-history.json').read_text())
    expected=history['expected']
    observations=json.loads((source_root/'source-observed-history.json').read_text())
    credential=(source_root/'synthetic-credential').read_text()
    write_json(root/'binary-identities.json',{'source_sha256':legacy.sha(source_binary),'candidate_sha256':legacy.sha(candidate)})
    restore_pg=clone_database(history['database_name'],root/'restore-before-start')
    before=snapshot(restore_pg)
    backup=root/'backup-before-start'
    assert invoke(candidate,'plan',restore_pg,backup,'plan')==0
    assert snapshot(restore_pg)==before
    assert invoke(candidate,'run',restore_pg,backup,'run')==0
    migrated_history(restore_pg,expected,observations)
    completed=snapshot(restore_pg)
    assert invoke(candidate,'run',restore_pg,backup,'repeat-run-noop')==0
    assert snapshot(restore_pg)==completed
    assert invoke(candidate,'restore',restore_pg,backup,'restore')==0
    assert snapshot(restore_pg)==before
    old=Product(source_binary,restore_pg.root,'restored-oldmain',credential,restore_pg.url)
    try:
        old.ready()
        for op,fact in expected.items():
            value,status=old.request('/send_status/'+op)
            for key in ('op_id','model','entity_id','status','accepted_at','expires_at'):
                assert value['data'][key]==fact['old_status'][key]
    finally:
        assert old.close()==0
    active=clone_database(history['database_name'],root/'normal-candidate')
    active_backup=root/'backup-after-start'
    assert invoke(candidate,'plan',active,active_backup,'plan')==0
    assert invoke(candidate,'run',active,active_backup,'run')==0
    migrated_history(active,expected,observations)
    # Reuse the already bounded MQTT/PUBACK/restart oracle with PostgreSQL observations.
    base.CandidateProduct=lambda binary,directory,label,token:Product(binary,directory,label,token,active.url)
    base.inspect_ordinary_live=lambda directory,op,delivery:inspect_live(active,op,delivery)
    base.OP_IDS=OP_IDS
    verify_normal_candidate(candidate,active.root,credential,{'expected':expected})
    verify_http_pull_ack(candidate,active,credential)
    activated=snapshot(active)
    assert invoke(candidate,'restore',active,active_backup,'restore-after-activation-refusal')!=0
    assert snapshot(active)==activated
    bypass=clone_database(active.name,root/'oldmain-direct-bypass-clone')
    old=Product(source_binary,bypass.root,'oldmain-status-only',credential,bypass.url)
    ready=False
    failure=None
    try:
        try:
            old.ready(); ready=True
            for op in OP_IDS:
                old.request('/send_status/'+op,allow_error=True)
        except BaseException as error:
            failure=type(error).__name__+': '+str(error)
    finally:
        exit_code=old.close()
    assert not any(e['path']=='/message' for e in old.events)
    write_json(root/'candidate-journey-result.json',{'status':'SYNTHETIC_MYSQL_CUTOVER_JOURNEY_PASSED',
        'restored_oldmain_verified':True,'same_changed_case_scope_409':True,'normal_http_v2_pull_ack':True,'actual_mqtt_puback_restart':True,
        'activated_restore_refused_unchanged':True,'direct_oldmain_clone':{'ready':ready,'failure':failure,'exit_code':exit_code,'message_posts':0},
        'source_database_untouched':history['database_name'],'normal_runtime_user':RUNTIME_USER,'normal_runtime_global_process':False,'injected_business_rows':0})

def inspect_http(database, op, delivery):
    messages=database.rows('ordinary_messages',"op_id='"+op+"'")
    assert len(messages)==1
    message=messages[0]
    targets=database.rows('ordinary_targets',"delivery_id='"+delivery+"'")
    blob=message.get('payload_blob')
    blob_bytes=0 if blob in ('\\x','',None) else len(bytes.fromhex(blob[2:]))
    return {'message_id':message['message_id'],'payload_bytes':message['payload_bytes'],
            'payload_blob_empty':blob in ('\\x','',None),'payload_blob_length':blob_bytes,'targets':len(targets),
            'unacked_targets':sum(row['acked_at'] is None for row in targets)}


def verify_http_pull_ack(binary,database,credential):
    product=Product(binary,database.root,'normal-http-v2-pull-ack',credential,database.url)
    try:
        product.ready()
        device=product.request('/device/register',{'platform':'android'})[0]['data']['device_key']
        product.request('/channel/device',{'device_key':device,'platform':'android','channel_type':'fcm',
                                           'provider_token':'c16-local-only-unresolvable-'+secrets.token_hex(8)})
        channel=product.request('/channel/subscribe',{'device_key':device,'channel_name':'c16-http-pull-ack','password':credential})[0]['data']['channel_id']
        op='c16-normal-http-pull-ack'
        body='c16 actual normal HTTP retained body'
        accepted,status=product.request('/message',{'channel_id':channel,'password':credential,'op_id':op,
            'title':'normal HTTP Pull ACK','body':body,'ttl':int(time.time()*1000)+3600000})
        assert status==200
        message=accepted['data']['message_id']
        pulled,pull_status=product.request('/v2/messages/pull',{'device_key':device})
        items=pulled['data']['items']
        item=next(row for row in items if row['payload']['message_id']==message)
        assert item['payload']['body']==body and item['payload']['op_id']==op
        delivery=item['delivery_id']
        before=inspect_http(database,op,delivery)
        assert before['payload_bytes']>0 and before['unacked_targets']==1
        view,view_http=product.request('/send_status/'+op)
        assert view_http==200 and view['data']['entity_id']==message
        assert 'body' not in view['data'] and 'title' not in view['data']
        ack_input={'device_key':device,'delivery_ids':[delivery]}
        ack,ack_status=product.request('/v2/messages/ack',ack_input)
        assert ack_status==200 and ack['data']['removed_count']==1
        duplicate,duplicate_status=product.request('/v2/messages/ack',ack_input)
        assert duplicate_status==200 and duplicate['data']['removed_count']==0
        empty,empty_status=product.request('/v2/messages/pull',{'device_key':device,'delivery_id':delivery})
        assert empty_status==200 and empty['data']['items']==[]
        deadline=time.monotonic()+20
        after=None
        while time.monotonic()<deadline:
            after=inspect_http(database,op,delivery)
            if after['payload_bytes']==0 and after['targets']==0:
                break
            time.sleep(.05)
        assert after['payload_bytes']==0 and after['payload_blob_empty'] and after['targets']==0,after
        write_json(database.root/'normal-http-v2-pull-ack.json',{'status':'NORMAL_HTTP_V2_PULL_ACK_PASSED',
            'accepted':accepted,'pull':pulled,'sender_status_body_free':view,'before_explicit_ack_sql':before,
            'ack':ack,'duplicate_ack':duplicate,'exact_pull_after_ack':empty,'after_ack_sql':after,
            'token_service':'deliberately unavailable local127.0.0.1:1','provider_accepted_claim':False,
            'actual_normal_binary':True,'injected_business_rows':0})
    finally:
        assert product.close()==0


def pg_http_supplement(binary,root,previous_root,credential_root):
    import remote_cutover_journey as pg_tool
    command=json.loads((previous_root/'normal-candidate/candidate-first.command.json').read_text())['argv']
    url=command[command.index('--db-url')+1]
    template=url.rsplit('/',1)[1]
    database=pg_tool.clone_database(template,root/'pg-normal-http')
    credential=(credential_root/'synthetic-credential').read_text()
    FROZEN_BINARIES[str(binary)]=legacy.sha(binary)
    verify_http_pull_ack(binary,database,credential)
    write_json(root/'pg-http-supplement-result.json',{'status':'NORMAL_PG_HTTP_V2_PULL_ACK_PASSED',
        'candidate_sha256':legacy.sha(binary),'template_database':template,'clone_database':database.name,
        'provider_accepted_claim':False})

def verify_normal_candidate(binary, directory, credential, history):
    p = base.CandidateProduct(binary, directory, "candidate-first", credential)
    mqtt = None
    try:
        p.ready()
        historical = history["expected"]
        channel = historical[OP_IDS[0]]["channel_id"]
        first = historical[OP_IDS[0]]
        second_channel_key = p.request("/device/register", {"platform": "mqtt"})[0]["data"]["device_key"]
        p.request("/channel/device", {"device_key": second_channel_key,
                                      "platform": "mqtt", "channel_type": "private"})
        second_channel = p.request("/channel/subscribe", {
            "device_key": second_channel_key, "channel_name": "c16-other-scope",
            "password": credential})[0]["data"]["channel_id"]
        conflicts = []
        for op, selected_channel, body, extra in (
            (OP_IDS[0], channel, first["body"], {}),
            (OP_IDS[0], channel, first["body"] + " changed after history", {}),
            ("C16-HISTORY-A", channel, first["body"], {}),
            (OP_IDS[0], second_channel, first["body"], {}),
            (OP_IDS[0], channel, first["body"], {
                "thing_id": "c16-different-thing", "occurred_at": str(int(time.time() * 1000))}),
        ):
            response, status = p.request("/message", {
                "channel_id": selected_channel, "password": credential,
                "op_id": op, "title": first["title"], "body": body, "ttl": first["ttl"], **extra},
                allow_error=True)
            assert status == 409, (status, response)
            error_codes = {
                "top_level": response.get("error_code"),
                "problem": (response.get("problem") or {}).get("code"),
            }
            assert error_codes == {
                "top_level": "historical_identity_unverifiable",
                "problem": "historical_identity_unverifiable",
            }, (error_codes, response)
            conflicts.append({"op_id": op, "channel_id": selected_channel,
                              "body": body, "http_status": status,
                              "error_codes": error_codes, "response": response})

        historical_statuses = []
        for historical_op, fact in historical.items():
            old_view, old_http = p.request('/send_status/' + historical_op)
            assert old_http == 200 and old_view['data']['entity_id'] == fact['message_id']
            assert old_view['data']['accepted_at'] == fact['old_status']['accepted_at']
            assert 'body' not in old_view['data'] and 'title' not in old_view['data']
            historical_statuses.append(old_view)

        device = p.request("/device/register", {"platform": "mqtt"})[0]["data"]["device_key"]
        p.request("/channel/device", {"device_key": device, "platform": "mqtt", "channel_type": "private"})
        p.request("/channel/subscribe", {"device_key": device, "channel_id": channel,
                                         "password": credential})
        mqtt = base.Mqtt5Peer(p.mqtt_port, device, credential)
        op = "c16-new-op-live"
        occurred_at = int(time.time() * 1000)
        input_body = {"channel_id": channel, "password": credential, "op_id": op,
                      "title": "new C16 live delivery", "body": "synthetic MQTT body",
                      "ttl": int(time.time() * 1000) + 3_600_000,
                      "occurred_at": str(occurred_at)}
        accepted, status = p.request("/message", input_body)
        assert status == 200 and accepted["success"] is True, accepted
        message_id = accepted["data"]["message_id"]
        received = mqtt.receive_publish()
        envelope = received["envelope"]
        assert envelope["data"]["message_id"] == message_id, envelope
        assert envelope["data"]["op_id"] == op, envelope
        assert int(envelope["data"]["occurred_at"]) == occurred_at, envelope
        delivery_id = envelope["delivery_id"]
        sender_status, sender_http = p.request('/send_status/' + op)
        assert sender_http == 200 and sender_status['data']['entity_id'] == message_id
        assert 'body' not in sender_status['data'] and 'title' not in sender_status['data']
        before_ack = base.inspect_ordinary_live(directory, op, delivery_id)
        mqtt.puback(received["packet_id"])
        deadline = time.monotonic() + 12
        after_ack = None
        while time.monotonic() < deadline:
            after_ack = base.inspect_ordinary_live(directory, op, delivery_id)
            if after_ack["target_rows"] == 0 and after_ack["pending_targets"] == 0:
                break
            time.sleep(.05)
        assert after_ack["target_rows"] == 0 and after_ack["pending_targets"] == 0, after_ack
        assert after_ack["payload_bytes"] == 0 and after_ack["payload_blob_length"] == 0, after_ack

        recovery_op = "c16-drop-restart-recovery"
        recovery_accept, recovery_status = p.request("/message", {
            "channel_id": channel, "password": credential, "op_id": recovery_op,
            "title": "C16 restart recovery", "body": "synthetic body held before PUBACK",
            "ttl": int(time.time() * 1000) + 3_600_000})
        assert recovery_status == 200 and recovery_accept["success"] is True
        held = mqtt.receive_publish()
        held_delivery = held["envelope"]["delivery_id"]
        assert held["envelope"]["data"]["op_id"] == recovery_op
        held_sql = base.inspect_ordinary_live(directory, recovery_op, held_delivery)
        assert held_sql["target_rows"] == 1 and held_sql["pending_targets"] == 1
        assert held_sql["payload_bytes"] > 0 and held_sql["payload_blob_length"] > 0
        mqtt.close()
        mqtt = None
        first_exit = p.close()
        assert first_exit == 0
        p = base.CandidateProduct(binary, directory, "candidate-restarted", credential)
        p.ready()
        mqtt = base.Mqtt5Peer(p.mqtt_port, device, credential)
        redelivery = mqtt.receive_publish()
        assert redelivery["envelope"]["delivery_id"] == held_delivery, (held, redelivery)
        assert redelivery["envelope"]["data"]["op_id"] == recovery_op
        mqtt.puback(redelivery["packet_id"])
        recovery_after = None
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            recovery_after = base.inspect_ordinary_live(directory, recovery_op, held_delivery)
            if recovery_after["target_rows"] == 0 and recovery_after["pending_targets"] == 0:
                break
            time.sleep(.05)
        assert recovery_after["target_rows"] == 0 and recovery_after["pending_targets"] == 0, recovery_after
        assert recovery_after["payload_bytes"] == 0 and recovery_after["payload_blob_length"] == 0, recovery_after
        write_json(directory / "candidate-live-journey.json", {
            "historical_conflicts": conflicts, "historical_statuses": historical_statuses, "new_op": op,
            "accepted_http": {"status": status, "response": accepted},
            "sender_status": sender_status, "mqtt_receive": received, "before_puback_sql": before_ack,
            "mqtt_puback_packet_id": received["packet_id"], "after_puback_sql": after_ack,
            "drop_restart_recovery": {"op_id": recovery_op,
                "first_unacked_mqtt_receive": held, "before_drop_sql": held_sql,
                "restart_exit": first_exit,
                "redelivered_same_delivery_id": redelivery,
                "mqtt_puback_packet_id": redelivery["packet_id"], "after_puback_sql": recovery_after},
            "actual_mqtt_peer": True})
    finally:
        if mqtt is not None:
            mqtt.close()
        if p is not None:
            assert p.close() == 0


def main():
    global FROZEN_CATALOG_SQL, RUNTIME_USER
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-only',action='store_true')
    parser.add_argument('--runtime-user',choices=('c16_app',),default='c16_app')
    parser.add_argument('--pg-pull-supplement',action='store_true')
    parser.add_argument('--credential-root',type=Path)
    parser.add_argument('--source-binary',required=True,type=Path)
    parser.add_argument('--candidate-binary',type=Path)
    parser.add_argument('--source-root',type=Path)
    parser.add_argument('--ordinary-source-profile',choices=('small',),default='small')
    parser.add_argument('--catalog-sql',type=Path)
    parser.add_argument('--evidence-root',required=True,type=Path)
    args = parser.parse_args()
    RUNTIME_USER = args.runtime_user
    os.umask(0o077)
    root = args.evidence_root.resolve()
    assert not root.exists(), 'refuse reused evidence root'
    root.mkdir(mode=0o700)
    tool = Path(__file__).resolve()
    (root / 'mysql_cutover_journey.py').write_bytes(tool.read_bytes())
    FROZEN_CATALOG_SQL = (tool.parents[2] / 'src/ordinary/mysql_cutover/catalog.sql').read_text()
    if args.catalog_sql:
        FROZEN_CATALOG_SQL = args.catalog_sql.read_text()
    (root / 'catalog-oracle.sql').write_text(FROZEN_CATALOG_SQL)
    write_json(root / 'tool-identity.json', {'path':str(tool),'sha256':legacy.sha(tool),
        'helper_hashes':{name:legacy.sha(tool.parent/name) for name in ('sqlite_cutover_journey.py','legacy_cutover_probe.py','remote_cutover_journey.py')},
        'argv':sys.argv,'catalog_oracle_sha256':hashlib.sha256(FROZEN_CATALOG_SQL.encode()).hexdigest()})
    try:
        if args.pg_pull_supplement:
            assert args.candidate_binary and args.source_root and args.credential_root
            pg_http_supplement(args.candidate_binary.resolve(),root,args.source_root.resolve(),args.credential_root.resolve())
            return
        if not args.source_only:
            assert args.candidate_binary and args.source_root
            run_candidate(args.source_binary.resolve(),args.candidate_binary.resolve(),root,args.source_root.resolve())
            return
        pg, credential, expected = source(args.source_binary.resolve(),root,args.catalog_sql)
        write_json(root / 'source-result.json', {'status':'OLDMAIN_SYNTHETIC_MYSQL_SOURCE_CREATED','database_url':pg.url,
                   'source_sha256':SOURCE_SHA,'source_runtime_profile':'small','injected_business_rows':0})
        assert args.source_only
    except BaseException as error:
        (root / 'probe-failure.txt').write_text(traceback.format_exc(),encoding='utf8')
        raise

if __name__ == '__main__':
    main()
