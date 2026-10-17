#!/usr/bin/env python3
"""Owned synthetic PostgreSQL cutover journey using normal Gateway APIs.

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

CONTAINER = 'pushgo-c16-pg-20261017'
PREFIX = 'c16_synthetic_'
SOURCE_SHA = base.SOURCE_SHA
OP_IDS = ('c16-history-a', 'c16-history-b')
FROZEN_BINARIES = {}
FROZEN_CATALOG_SQL = None


def write_json(path, value):
    base.write_json(path, value)


class Pg:
    def __init__(self, root, name=None):
        self.root = root
        self.name = name or PREFIX + secrets.token_hex(8)
        assert self.name.startswith(PREFIX) and self.name.replace('_', '').isalnum()
        self.url = 'postgres://postgres@127.0.0.1:42772/' + self.name
        self.sequence = 0

    def sql(self, sql, database=None, label='query'):
        self.sequence += 1
        stem = self.root / ('sql-%03d-%s' % (self.sequence, label))
        stem.with_suffix('.sql').write_text(sql + '\n', encoding='utf8')
        argv = ['docker', 'exec', '-i', CONTAINER, 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
                '-U', 'postgres', '-d', database or self.name, '-At']
        result = subprocess.run(argv, input=sql, text=True, capture_output=True, timeout=30)
        stem.with_suffix('.stdout').write_text(result.stdout, encoding='utf8')
        stem.with_suffix('.stderr').write_text(result.stderr, encoding='utf8')
        write_json(stem.with_suffix('.json'), {'argv': argv, 'exit_code': result.returncode})
        assert result.returncode == 0, ('SQL failed', str(stem))
        return result.stdout.strip()

    def create(self):
        self.sql('CREATE DATABASE "' + self.name + '"', database='postgres', label='create-owned-database')

    def rows(self, table, where='TRUE'):
        return json.loads(self.sql("SELECT COALESCE(json_agg(t),'[]'::json)::text FROM (SELECT * FROM " + table + ' WHERE ' + where + ') t;'))


class Product(base.ObservedProduct):
    def __init__(self, binary, directory, label, credential, database_url):
        legacy.guard_disk(directory)
        identity = legacy.sha(binary)
        assert str(binary) not in FROZEN_BINARIES or FROZEN_BINARIES[str(binary)] == identity
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


def source(binary, root, catalog_sql=None):
    assert legacy.sha(binary) == SOURCE_SHA, 'fixed oldmain SHA mismatch'
    legacy.guard_disk(root)
    pg = Pg(root)
    pg.create()
    artifact = root / 'fresh-empty-database.dump'
    argv = ['docker','exec',CONTAINER,'pg_dump','-U','postgres','-d',pg.name,'--format=custom']
    with artifact.open('xb') as stream:
        dumped = subprocess.run(argv,stdout=stream,stderr=subprocess.PIPE,timeout=30)
    write_json(root / 'fresh-empty-backup.command.json', {'argv':argv,'exit_code':dumped.returncode})
    assert dumped.returncode == 0, 'fresh backup failed'
    write_json(root / 'fresh-upgrade-backup-manifest.json', {'version':1,'driver':'postgres',
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
    if catalog_sql:
        sql = catalog_sql.read_text(encoding='utf8')
        value = json.loads(pg.sql("SELECT COALESCE(json_agg(json_build_array(kind,name,definition)), '[]'::json)::text FROM (" + sql.strip().rstrip(';') + ') canonical', label='canonical-source-catalog'))
        write_json(root / 'source-schema.json', value)
        (root / 'source-schema.sql').write_text(sql, encoding='utf8')
    return pg, credential, expected


def clone_database(template, root):
    assert template.startswith(PREFIX) and template.replace('_', '').isalnum()
    root.mkdir(mode=0o700)
    pg = Pg(root)
    pg.sql('CREATE DATABASE "' + pg.name + '" TEMPLATE "' + template + '"', database='postgres',label='clone-frozen-owned-template')
    return pg


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


def snapshot(pg):
    names = json.loads(pg.sql("SELECT COALESCE(json_agg(tablename ORDER BY tablename),'[]'::json)::text FROM pg_tables WHERE schemaname='public' AND tablename NOT IN ('pushgo_product_owner','pushgo_ordinary_cutover')"))
    result = {}
    for name in names:
        rows = pg.rows('"'+name+'"')
        assert len(rows) <= 256
        result[name] = {'rows':len(rows),'sha256':hashlib.sha256(json.dumps(sorted(json.dumps(r,sort_keys=True) for r in rows)).encode()).hexdigest()}
    catalog_sql = FROZEN_CATALOG_SQL
    catalog = json.loads(pg.sql("SELECT COALESCE(json_agg(json_build_array(kind,name,definition)), '[]'::json)::text FROM (" + catalog_sql.strip().rstrip(';') + ') canonical',label='snapshot-catalog'))
    return {'catalog':catalog,'tables':result}


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
        present = pg.sql("SELECT to_regclass('public."+table+"') IS NOT NULL")=='t'
        count = int(pg.sql('SELECT count(*) FROM '+table)) if present else 0
        assert count==0,(table,count)
        empty[table]=count
    result={'ordinary_messages':rows,'empty_responsibilities':empty}
    write_json(pg.root/'migrated-history.json',result)
    return result


def inspect_live(pg, op, delivery_id):
    assert op.replace('-','').isalnum() and delivery_id.replace('-','').isalnum()
    sql = "SELECT json_build_object('message_id',m.message_id,'payload_bytes',m.payload_bytes,'payload_blob_length',octet_length(m.payload_blob),'pending_targets',(SELECT count(*) FROM ordinary_targets WHERE delivery_id='"+delivery_id+"' AND acked_at IS NULL),'target_rows',(SELECT count(*) FROM ordinary_targets WHERE delivery_id='"+delivery_id+"'))::text FROM ordinary_messages m WHERE op_id='"+op+"'"
    return json.loads(pg.sql(sql,label='live-observation'))


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
    write_json(root/'candidate-journey-result.json',{'status':'SYNTHETIC_PG_CUTOVER_JOURNEY_PASSED',
        'restored_oldmain_verified':True,'same_changed_case_scope_409':True,'actual_mqtt_puback_restart':True,
        'activated_restore_refused_unchanged':True,'direct_oldmain_clone':{'ready':ready,'failure':failure,'exit_code':exit_code,'message_posts':0},
        'source_database_untouched':history['database_name'],'injected_business_rows':0})

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
    global FROZEN_CATALOG_SQL
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-only',action='store_true')
    parser.add_argument('--source-binary',required=True,type=Path)
    parser.add_argument('--candidate-binary',type=Path)
    parser.add_argument('--source-root',type=Path)
    parser.add_argument('--ordinary-source-profile',choices=('small',),default='small')
    parser.add_argument('--catalog-sql',type=Path)
    parser.add_argument('--evidence-root',required=True,type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.evidence_root.resolve()
    assert not root.exists(), 'refuse reused evidence root'
    root.mkdir(mode=0o700)
    tool = Path(__file__).resolve()
    (root / 'remote_cutover_journey.py').write_bytes(tool.read_bytes())
    catalog_path = args.catalog_sql or tool.parents[2] / 'src/ordinary/pg_cutover/catalog.sql'
    FROZEN_CATALOG_SQL = catalog_path.read_text()
    (root / 'catalog-oracle.sql').write_text(FROZEN_CATALOG_SQL)
    write_json(root / 'tool-identity.json', {'path':str(tool),'sha256':legacy.sha(tool),
        'helper_hashes':{name:legacy.sha(tool.parent/name) for name in ('sqlite_cutover_journey.py','legacy_cutover_probe.py')},
        'argv':sys.argv,'catalog_oracle_sha256':hashlib.sha256(FROZEN_CATALOG_SQL.encode()).hexdigest()})
    try:
        if not args.source_only:
            assert args.candidate_binary and args.source_root
            run_candidate(args.source_binary.resolve(),args.candidate_binary.resolve(),root,args.source_root.resolve())
            return
        pg, credential, expected = source(args.source_binary.resolve(),root,args.catalog_sql)
        write_json(root / 'source-result.json', {'status':'OLDMAIN_SYNTHETIC_PG_SOURCE_CREATED','database_url':pg.url,
                   'source_sha256':SOURCE_SHA,'source_runtime_profile':'small','injected_business_rows':0})
        assert args.source_only
    except BaseException as error:
        (root / 'probe-failure.txt').write_text(traceback.format_exc(),encoding='utf8')
        raise

if __name__ == '__main__':
    main()
