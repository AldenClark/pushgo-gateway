#!/usr/bin/env python3
"""PostgreSQL-only C16 synthetic SQL faults; never accepts an arbitrary URL.

Every attempt clones a joined, normal-old-main API fixture. No DROP DATABASE,
external HTTP, product hooks, runtime reconnect, or production inputs are used.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import struct
import threading
import subprocess
import time

import remote_cutover_journey as journey
import legacy_cutover_probe as legacy

EXCLUDED = ('pushgo_product_owner', 'pushgo_ordinary_cutover')


def ident(value):
    assert value.replace('_', '').isalnum(), value
    return '"' + value + '"'


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def snapshot(pg, filters=None):
    """Native canonical per-field and per-row SHA256; no credential plaintext."""
    filters = filters or {}
    tables = json.loads(pg.sql("SELECT coalesce(json_agg(tablename ORDER BY tablename),'[]') FROM pg_tables WHERE schemaname='public'", label='snapshot-tables'))
    result = {}
    for table in tables:
        if table in EXCLUDED:
            continue
        sql = """SELECT coalesce(json_agg(r ORDER BY r::text),'[]'::json)::text FROM (
          SELECT jsonb_build_object('fields', f, 'row_sha256',
          encode(sha256(convert_to(f::text,'UTF8')),'hex')) r FROM (
          SELECT (SELECT jsonb_object_agg(key, encode(sha256(convert_to(value::text,'UTF8')),'hex') ORDER BY key)
          FROM jsonb_each(to_jsonb(t))) f FROM public.%s t WHERE %s) x) y""" % (ident(table), filters.get(table, 'TRUE'))
        fields = json.loads(pg.sql(sql, label='field-hashes-'+table))
        schema_sql = "SELECT json_build_object('columns',(SELECT json_agg(json_build_array(column_name,data_type,is_nullable,column_default) ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name="+literal(table)+"),'indexes',(SELECT json_agg(indexdef ORDER BY indexname) FROM pg_indexes WHERE schemaname='public' AND tablename="+literal(table)+"),'constraints',(SELECT json_agg(pg_get_constraintdef(oid) ORDER BY conname) FROM pg_constraint WHERE conrelid="+literal('public.'+table)+"::regclass))"
        result[table] = {'rows':fields,'schema':json.loads(pg.sql(schema_sql,label='schema-'+table))}
    return result


def clone(root, template):
    legacy.guard_disk(root.parent)
    root.mkdir(mode=0o700)
    pg = journey.Pg(root)
    pg.sql('CREATE DATABASE ' + ident(pg.name) + ' TEMPLATE ' + ident(template), database='postgres', label='clone-frozen-api-source')
    return pg


def command(binary, pg, action, backup):
    return [str(binary), '--db-url', pg.url, '--ordinary-cutover', action,
            '--ordinary-cutover-backup', str(backup), '--ordinary-source-profile', 'small']


def run(root, label, argv, success=None, timeout=90, path_override=None):
    legacy.guard_disk(root)
    env = {k:v for k,v in os.environ.items() if not k.startswith('PUSHGO_')}
    if path_override is not None:
        env['PATH'] = path_override
    legacy.write_json(root / (label+'.command.json'), {'argv':argv,'PATH_override':path_override})
    with (root / (label+'.log')).open('xb') as log:
        result = subprocess.run(argv, env=env, stdout=log, stderr=log, timeout=timeout)
    legacy.write_json(root / (label+'.exit.json'), {'exit_code':result.returncode})
    if success is not None:
        assert (result.returncode == 0) == success, (label, result.returncode)
    return result.returncode


def minimal_row(pg, table, overrides):
    """Explicitly synthetic complete row; derive types, never infer business facts."""
    columns = json.loads(pg.sql("SELECT json_agg(json_build_object('name',column_name,'type',data_type,'nullable',is_nullable) ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name="+literal(table), label='injection-column-types'))
    values = {}
    for col in columns:
        if col['nullable'] == 'YES':
            continue
        kind = col['type']
        values[col['name']] = {'bytea':'\\x'+'01'*16,'boolean':False}.get(kind, 1 if kind in ('bigint','integer','smallint','numeric') else 'c16-explicit-sql-fault')
    values.update(overrides)
    return 'INSERT INTO '+ident(table)+' SELECT * FROM jsonb_populate_record(NULL::'+ident(table)+','+literal(json.dumps(values))+'::jsonb)'


def negative_cases(pg):
    cases = []
    # Each obligation table is rejected globally, even with terminal/ACK/orphan rows.
    for table in ('dispatch_submission','provider_dispatch_outbox','private_payloads','private_outbox','provider_pull_queue'):
        variants = ('pending','unknown','acked') if table == 'private_outbox' else ('pending','unknown') if table == 'provider_dispatch_outbox' else ('orphan',)
        for state in variants:
            override = {'delivery_id':'0'*31+'1'}
            if table == 'private_outbox':
                override.update(status=state, claimed_by='c16-sql-lease', claimed_at=1, acked_at=1 if state=='acked' else None)
            if table == 'provider_dispatch_outbox':
                override.update(state=state,lease_owner='c16-sql-lease',lease_until=9223372036854775807)
            cases.append((table+'-'+state, minimal_row(pg, table, override)))
    for status in ('sent','partial','pending'):
        cases.append(('sender-'+status, "UPDATE sender_submit_status SET status="+literal(status)+" WHERE model='message'"))
    cases.extend([
        ('wrong-version', "UPDATE pushgo_schema_meta SET meta_value='c16-unsupported' WHERE meta_key='schema_version'"),
        ('wrong-checksum', "UPDATE pushgo_schema_migrations SET checksum='c16-invalid'"),
        ('extra-schema-object', 'CREATE TABLE c16_injected_unknown_object(value TEXT)'),
        ('missing-status', "DELETE FROM sender_submit_status WHERE op_id=(SELECT min(op_id) FROM sender_submit_status WHERE model='message')"),
        ('ambiguous-status', "INSERT INTO sender_submit_status SELECT (jsonb_populate_record(NULL::sender_submit_status,to_jsonb(t)||'{\"op_id\":\"C16-ALIAS-FAULT\"}'::jsonb)).* FROM sender_submit_status t WHERE model='message' LIMIT 1"),
        ('malformed-semantic', "UPDATE semantic_id_registry SET dedupe_key='semantic:bad:message:-:c16-malformed' WHERE dedupe_key=(SELECT min(dedupe_key) FROM semantic_id_registry)"),
        ('semantic-collision', "INSERT INTO public.semantic_id_registry SELECT (jsonb_populate_record(NULL::public.semantic_id_registry,to_jsonb(t)||jsonb_build_object('dedupe_key',replace(dedupe_key,':message:-:',':message:thing:'),'semantic_id','dddddddddddddddddddddddddddddddd'))).* FROM public.semantic_id_registry t ORDER BY dedupe_key LIMIT 1; INSERT INTO public.sender_submit_status SELECT (jsonb_populate_record(NULL::public.sender_submit_status,to_jsonb(t)||jsonb_build_object('op_id',upper(op_id),'entity_id','dddddddddddddddddddddddddddddddd'))).* FROM public.sender_submit_status t WHERE model='message' ORDER BY op_id LIMIT 1"),
    ])
    for state, leased in (('pending',False),('unknown',False),('sent',True)):
        cases.append(('op-'+state+('-lease' if leased else ''), minimal_row(pg,'dispatch_op_dedupe',{'dedupe_key':'op:00000000000000000000000000:event:-:c16-fault','state':state,'provider_owner':'c16-lease' if leased else None,'provider_lease_until':9223372036854775807 if leased else None})))
    cases.append(('op-message-sent',minimal_row(pg,'dispatch_op_dedupe',{'dedupe_key':'op:00000000000000000000000000:message:-:c16-fault','state':'sent'})))
    cases.append(('malformed-delivery-collision',minimal_row(pg,'dispatch_delivery_dedupe',{'dedupe_key':'delivery:bad','delivery_id':'bad','state':'sent'})))
    cases.extend([
        ('empty-sender-op', "INSERT INTO public.sender_submit_status SELECT (jsonb_populate_record(NULL::public.sender_submit_status,to_jsonb(t)||jsonb_build_object('op_id','','entity_id','cccccccccccccccccccccccccccccccc'))).* FROM public.sender_submit_status t WHERE model='message' ORDER BY op_id LIMIT 1"),
        ('empty-semantic-key', "INSERT INTO public.semantic_id_registry SELECT (jsonb_populate_record(NULL::public.semantic_id_registry,to_jsonb(t)||jsonb_build_object('dedupe_key','','semantic_id','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'))).* FROM public.semantic_id_registry t ORDER BY dedupe_key LIMIT 1"),
        ('empty-op-key', minimal_row(pg,'dispatch_op_dedupe',{'dedupe_key':'','state':'pending'})),
        ('empty-delivery-key',minimal_row(pg,'dispatch_delivery_dedupe',{'dedupe_key':'','delivery_id':'bad','state':'pending'})),
    ])
    return cases


def rejection_suite(binary, root, template, selected=None):
    # Discover column types on a separate clone; all mutation scopes remain owned.
    discovery = clone(root / 'discovery', template)
    cases = negative_cases(discovery)
    if selected:
        assert set(selected).issubset({name for name, _ in cases}), 'unknown case selector'
        cases = [(name,sql) for name,sql in cases if name in selected]
    results = []
    for name, sql in cases:
        directory = root / name
        pg = clone(directory, template)
        legacy.write_json(directory / 'injection.json', {'origin':'EXPLICIT SQL FAULT INJECTION; not API history','sql':sql,'template':template,'database':pg.name})
        pg.sql(sql, label='EXPLICIT-SQL-FAULT-INJECTION')
        before = snapshot(pg)
        legacy.write_json(directory / 'before-field-hashes.json', before)
        for action in ('plan', 'run'):
            label = 'rejected-' + action
            run(directory,label,command(binary,pg,action,directory/(action+'-backup')),False)
            log = (directory/(label+'.log')).read_text()
            expected = ('target-bearing' if name.startswith(('dispatch_submission-', 'provider_dispatch_outbox-', 'private_payloads-', 'private_outbox-', 'provider_pull_queue-')) else
                        'empty' if name.startswith('empty-') else
                        'checksum' if name=='wrong-checksum' else
                        'schema' if name in ('wrong-version','extra-schema-object') else
                        'ordinary' if name.startswith('sender-') or name=='missing-status' else
                        'duplicate' if name in ('ambiguous-status','semantic-collision') else
                        'scope' if name=='malformed-semantic' else
                        'collision' if name in ('semantic-collision','malformed-delivery-collision') else
                        'responsibility')
            assert expected in log, (name, action, 'rejection not attributed to intended fault', expected)
        after = snapshot(pg)
        legacy.write_json(directory / 'after-field-hashes.json', after)
        assert before == after, name+' business field change on rejected cutover'
        results.append({'case':name,'status':'REJECTED_WITHOUT_BUSINESS_CHANGE','database':pg.name})
    return results


def inject_window(pg):
    # Exactly 512 marked SQL histories as in C15, using real API canonical scope.
    pg.sql("""INSERT INTO sender_submit_status
      SELECT (jsonb_populate_record(NULL::sender_submit_status,to_jsonb(t)||jsonb_build_object(
      'op_id','c16-fault-'||i,'entity_id','01'||lpad(to_hex(i),30,'0')))).*
      FROM (SELECT * FROM sender_submit_status WHERE model='message' LIMIT 1) t CROSS JOIN generate_series(1,512) i;
      INSERT INTO semantic_id_registry SELECT (jsonb_populate_record(NULL::semantic_id_registry,to_jsonb(t)||jsonb_build_object(
      'dedupe_key',split_part(dedupe_key,':',1)||':'||split_part(dedupe_key,':',2)||':message:-:c16-fault-'||i,
      'semantic_id','01'||lpad(to_hex(i),30,'0')))).*
      FROM (SELECT * FROM semantic_id_registry WHERE dedupe_key LIKE 'semantic:%:message:%' LIMIT 1) t CROSS JOIN generate_series(1,512) i;""",label='EXPLICIT-512-SQL-FAULT-WINDOW-HISTORIES')


def sessions(pg):
    # Observe from postgres, never add a target client during alone/admission.
    return json.loads(pg.sql("SELECT coalesce(json_agg(json_build_object('pid',a.pid,'query',a.query,'state',a.state,'owner',EXISTS(SELECT 1 FROM pg_locks l WHERE l.pid=a.pid AND l.locktype='advisory' AND l.classid=1346852687::bigint::oid AND l.objid=1330791756::bigint::oid AND l.objsubid=2 AND l.granted))),'[]') FROM pg_stat_activity a WHERE datname="+literal(pg.name)+" AND backend_type='client backend'",database='postgres',label='exact-target-session-observation'))


def interruption(binary, root, template, fault):
    pg = clone(root, template)
    inject_window(pg)
    before = snapshot(pg)
    legacy.write_json(root/'before-field-hashes.json',before)
    backup = root/'backup'
    argv = command(binary,pg,'run',backup)
    legacy.write_json(root/'injection.json',{'origin':'EXPLICIT 512 SQL fault-window histories; not API histories','fault':fault,'argv':argv})
    env = {k:v for k,v in os.environ.items() if not k.startswith('PUSHGO_')}
    observed = None
    with (root/'interrupted-run.log').open('xb') as log:
        child = subprocess.Popen(argv,env=env,stdout=log,stderr=log)
        try:
            deadline = time.monotonic()+60
            while child.poll() is None and time.monotonic()<deadline:
                current = sessions(pg)
                # A converting INSERT is a causal native observation AFTER prepared.
                converting = [s for s in current if s['state'] in ('active','idle in transaction') and 'INSERT INTO ordinary_messages' in s['query']]
                if converting:
                    owner = [s for s in current if s['owner']]
                    assert len(owner)==1 and len(converting)==1, current
                    observed = {'sessions':current,'migration_data_pid':converting[0]['pid'],'owner_pid':owner[0]['pid']}
                    if fault=='sigkill':
                        child.send_signal(signal.SIGKILL)
                    else:
                        target = owner[0]['pid'] if fault=='owner-session' else converting[0]['pid']
                        assert pg.sql('SELECT pg_terminate_backend('+str(target)+')',database='postgres',label='EXPLICIT-EXACT-MIGRATION-SESSION-TERMINATION')=='t'
                    break
            assert observed, 'native conversion fault window not observed; preserve failed attempt'
            exit_code = child.wait(timeout=30)
            assert exit_code != 0, 'interrupted migration unexpectedly succeeded'
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
    legacy.write_json(root/'fault-receipt.json',{'observed':observed,'exit_code':exit_code,'unknown_commit_injected':False})
    phase = pg.sql('SELECT phase FROM pushgo_ordinary_cutover',label='remaining-durable-phase')
    assert phase == 'prepared', ('missed precompletion fault window',phase)
    run(root,'repeat-incomplete',command(binary,pg,'run',root/'repeat-backup'),False)
    startup = [str(binary),'--db-url',pg.url,'--http-addr','127.0.0.1:'+str(legacy.port()),'--private-transports','false','--token-service-url','http://127.0.0.1:1']
    run(root,'incomplete-startup',startup,False,20)
    assert 'incomplete PostgreSQL cutover' in (root/'incomplete-startup.log').read_text() and 'restore' in (root/'incomplete-startup.log').read_text(), 'unattributed startup rejection'
    run(root,'native-restore',command(binary,pg,'restore',backup),True)
    after = snapshot(pg)
    legacy.write_json(root/'restored-field-hashes.json',after)
    assert before == after, 'full native business state restoration mismatch'
    run(root,'rerun-after-restore',command(binary,pg,'run',root/'backup-after-restore'),True)
    actual = json.loads(pg.sql("SELECT json_agg(json_build_object('op_id',op_id,'message_id',message_id) ORDER BY op_id) FROM ordinary_messages",label='recovered-message-identities'))
    source = json.loads(pg.sql("SELECT json_agg(json_build_object('op_id',op_id,'message_id',entity_id) ORDER BY op_id) FROM sender_submit_status WHERE model='message'",database=template,label='frozen-original-message-identities'))
    assert len(actual)==514
    assert all(item in actual for item in source), 'original API IDs changed'
    return {'fault':fault,'database':pg.name,'exit_code':exit_code,'full_native_restore':True,'histories':514,'original_api_ids_preserved':True,'unknown_commit_injected':False}



def positives(binary, root, template):
    """Supported explicit Thing scope plus unchanged shared-model records."""
    pg = clone(root, template)
    thing = '00112233445566778899aabbccddeeff'
    # No source row is deleted; one API identity receives a supported explicit
    # Thing scope. All added records are labeled SQL fixture data, not API data.
    sql = """UPDATE public.semantic_id_registry SET dedupe_key=
      split_part(dedupe_key,':',1)||':'||split_part(dedupe_key,':',2)||':message:THING:'||split_part(dedupe_key,':',5)
      WHERE dedupe_key=(SELECT min(dedupe_key) FROM public.semantic_id_registry);
      INSERT INTO public.semantic_id_registry
      SELECT (jsonb_populate_record(NULL::public.semantic_id_registry,to_jsonb(t)||jsonb_build_object(
      'dedupe_key','semantic:'||split_part(dedupe_key,':',2)||':'||m||':-:c16-shared-'||m,
      'semantic_id',CASE WHEN m='event' THEN 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' ELSE 'ffffffffffffffffffffffffffffffff' END))).*
      FROM (SELECT * FROM public.semantic_id_registry ORDER BY dedupe_key LIMIT 1) t CROSS JOIN (VALUES ('event'),('thing')) models(m);
      INSERT INTO public.sender_submit_status
      SELECT (jsonb_populate_record(NULL::public.sender_submit_status,to_jsonb(t)||jsonb_build_object(
      'op_id','c16-shared-'||m,'model',m,'status','sent','dispatch_status','sent',
      'entity_id',CASE WHEN m='event' THEN 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' ELSE 'ffffffffffffffffffffffffffffffff' END))).*
      FROM (SELECT * FROM public.sender_submit_status WHERE model='message' ORDER BY op_id LIMIT 1) t CROSS JOIN (VALUES ('event'),('thing')) models(m);
      INSERT INTO public.dispatch_op_dedupe(dedupe_key,delivery_id,state,created_at,updated_at,sent_at)
      SELECT 'op:'||split_part(dedupe_key,':',2)||':'||split_part(dedupe_key,':',3)||':-:'||split_part(dedupe_key,':',5),semantic_id,'sent',created_at,updated_at,updated_at
      FROM public.semantic_id_registry WHERE dedupe_key LIKE '%:c16-shared-%';
      INSERT INTO public.live_activity_tokens(activity_key,token,channel_id,platform,schema_version,created_at,updated_at,expires_at)
      SELECT 'c16-explicit-sql-activity','c16-explicit-sql-token',channel_id,'ios',1,accepted_at,updated_at,expires_at FROM public.sender_submit_status WHERE model='message' ORDER BY op_id LIMIT 1;
      INSERT INTO public.widget_push_subscriptions(device_key,platform,token,widget_kind,family,schema_version,created_at,updated_at)
      SELECT 'c16-explicit-sql-device','ios','c16-explicit-sql-widget-token','c16-widget','small',1,accepted_at,updated_at FROM public.sender_submit_status WHERE model='message' ORDER BY op_id LIMIT 1;
      """.replace('THING',thing)
    legacy.write_json(root/'injection.json',{'origin':'EXPLICIT SQL POSITIVE FIXTURE; shared rows are not normal API history','sql':sql,'template':template,'database':pg.name})
    pg.sql(sql,label='EXPLICIT-SQL-POSITIVE-SHARED-METADATA')
    filters = {'sender_submit_status': "model<>'message'", 'semantic_id_registry': "split_part(dedupe_key,':',3)<>'message'"}
    before = snapshot(pg,filters)
    legacy.write_json(root/'before-shared-field-hashes.json',before)
    original = json.loads(pg.sql("SELECT json_agg(json_build_object('message_id',entity_id,'op_id',op_id) ORDER BY op_id) FROM public.sender_submit_status WHERE model='message'",label='original-api-message-identities'))
    explicit_id = pg.sql("SELECT semantic_id FROM public.semantic_id_registry WHERE split_part(dedupe_key,':',4)="+literal(thing),label='explicit-thing-original-message-id')
    run(root,'supported-plan',command(binary,pg,'plan',root/'plan-backup'),True)
    assert snapshot(pg,filters)==before, 'plan changed shared business data'
    run(root,'supported-run',command(binary,pg,'run',root/'backup'),True)
    after = snapshot(pg,filters)
    legacy.write_json(root/'after-shared-field-hashes.json',after)
    # Product-owned ordinary tables are new; every preexisting shared relation,
    # row, field and schema must remain equal after ordinary extraction.
    assert all(after.get(table)==value for table,value in before.items()), 'shared source state changed'
    actual = json.loads(pg.sql("SELECT json_agg(json_build_object('message_id',message_id,'op_id',op_id) ORDER BY op_id) FROM public.ordinary_messages",label='converted-api-message-identities'))
    assert actual==original and len(actual)==2
    assert pg.sql("SELECT thing_id FROM public.ordinary_messages WHERE message_id="+literal(explicit_id),label='explicit-thing-preserved')==thing
    assert pg.sql("SELECT count(*) FROM public.sender_submit_status WHERE model='message'",label='ordinary-status-extracted')=='0'
    assert pg.sql("SELECT count(*) FROM public.semantic_id_registry WHERE split_part(dedupe_key,':',3)='message'",label='ordinary-semantic-extracted')=='0'
    return {'case':'supported-explicit-thing-shared-models','database':pg.name,'original_api_ids_preserved':True,'explicit_thing_preserved':True,'all_shared_business_fields_preserved':True,'sql_injected_shared_rows':8}



class CommitLossProxy:
    """Forward native PG bytes; drop exactly the third COMMIT acknowledgement.

    No backend response is synthesized. Every complete backend frame is parsed,
    preserving SSLRequest's initial unframed N. Per-session counts avoid mixing
    ProductOwner's separate physical connection with the migration connection.
    """
    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1',0))
        self.listener.listen()
        self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.connections = []
        self.events = []
        self.fault = None
        self.next_connection = 0
        self.thread = threading.Thread(target=self.accept,daemon=True)
        self.thread.start()

    def close_socket(self, stream):
        try:
            stream.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        stream.close()

    def accept(self):
        while not self.stop.is_set():
            try:
                client, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            server = socket.create_connection(('127.0.0.1',42772),timeout=5)
            client.settimeout(.2)
            server.settimeout(.2)
            with self.lock:
                self.next_connection += 1
                connection = self.next_connection
                self.connections.extend((client,server))
            threading.Thread(target=self.upstream,args=(client,server),daemon=True).start()
            threading.Thread(target=self.downstream,args=(server,client,connection),daemon=True).start()

    def upstream(self,client,server):
        try:
            while not self.stop.is_set():
                try:
                    data = client.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    break
                server.sendall(data)
        except OSError:
            pass
        finally:
            self.close_socket(client)
            self.close_socket(server)

    def downstream(self,server,client,connection):
        pending = b''
        initial = True
        commits = 0
        try:
            while not self.stop.is_set():
                try:
                    chunk = server.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                pending += chunk
                if initial and pending[:1] == b'N':
                    client.sendall(pending[:1])
                    pending = pending[1:]
                    initial = False
                while len(pending)>=5:
                    initial = False
                    length = struct.unpack('!I',pending[1:5])[0]
                    assert 4<=length<=128*1024*1024, ('invalid backend frame length',length)
                    size = length+1
                    if len(pending)<size:
                        break
                    frame,pending = pending[:size],pending[size:]
                    if frame == b'C'+struct.pack('!I',11)+b'COMMIT\0':
                        commits += 1
                        event = {'connection':connection,'commit_count':commits,'frame_hex':frame.hex(),'backend_endpoint':'127.0.0.1:42772','time_monotonic':time.monotonic()}
                        with self.lock:
                            self.events.append(event)
                            if commits==3 and self.fault is None:
                                self.fault = dict(event,action='native server COMMIT CommandComplete received; client closed before forwarding frame')
                                return
                    client.sendall(frame)
        except OSError:
            pass
        except AssertionError as error:
            with self.lock:
                self.events.append({'connection':connection,'proxy_error':type(error).__name__+': '+str(error)})
        finally:
            self.close_socket(client)
            self.close_socket(server)

    def close(self):
        self.stop.set()
        self.listener.close()
        with self.lock:
            connections = list(self.connections)
        for stream in connections:
            self.close_socket(stream)
        self.thread.join(timeout=2)


def commit_loss(binary,root,template):
    pg = clone(root,template)
    before = snapshot(pg)
    legacy.write_json(root/'before-field-hashes.json',before)
    original = json.loads(pg.sql("SELECT json_agg(json_build_object('message_id',entity_id,'op_id',op_id) ORDER BY op_id) FROM public.sender_submit_status WHERE model='message'",label='original-api-message-identities'))
    backup = root/'backup'
    proxy = CommitLossProxy()
    argv = command(binary,pg,'run',backup)
    argv[argv.index('--db-url')+1] = 'postgres://postgres@127.0.0.1:'+str(proxy.port)+'/'+pg.name
    legacy.write_json(root/'injection.json',{'origin':'TEST-ONLY TRANSPARENT TCP RESPONSE LOSS; native PostgreSQL, no forged responses','scope':pg.name,'target':'third native COMMIT CommandComplete on one physical connection','external_HTTP_requests':0})
    try:
        exit_code = run(root,'commit-response-lost',argv,None)
    finally:
        proxy.close()
        legacy.write_json(root/'proxy-receipt.json',{'fault':proxy.fault,'events':proxy.events,'exactly_one_response_dropped':proxy.fault is not None})
    assert proxy.fault, 'third COMMIT response-loss window NOT RUN; inspect retained protocol receipt'
    assert exit_code!=0, 'client did not report lost conversion COMMIT acknowledgement'
    assert not any('proxy_error' in event for event in proxy.events), 'protocol observation ambiguous'
    assert pg.sql('SELECT phase FROM public.pushgo_ordinary_cutover',label='independent-native-committed-phase')=='complete'
    actual = json.loads(pg.sql("SELECT json_agg(json_build_object('message_id',message_id,'op_id',op_id) ORDER BY op_id) FROM public.ordinary_messages",label='independent-native-committed-identities'))
    assert actual==original and len(actual)==2, 'native committed identities mismatch'
    committed = snapshot(pg)
    legacy.write_json(root/'independent-committed-field-hashes.json',committed)
    run(root,'direct-replay-after-lost-ack',command(binary,pg,'run',backup),True)
    assert snapshot(pg)==committed, 'replay changed committed business state'
    run(root,'native-restore-after-lost-ack',command(binary,pg,'restore',backup),True)
    restored = snapshot(pg)
    legacy.write_json(root/'restored-field-hashes.json',restored)
    assert restored==before, 'native restore after lost commit ack mismatched original business state'
    return {'case':'final-conversion-commit-response-loss','database':pg.name,'client_exit_code':exit_code,'server_commit_independently_verified':True,'same_backup_replay_without_duplicate':True,'full_native_restore':True,'original_api_ids_preserved':True,'unknown_commit_injected':True,'response_frame_hex':proxy.fault['frame_hex']}



def backup_failure(binary,root,template):
    pg = clone(root,template)
    before = snapshot(pg)
    legacy.write_json(root/'before-field-hashes.json',before)
    backup = root/'failed-backup'
    legacy.write_json(root/'injection.json',{'origin':'EXPLICIT TEST-ONLY pg_dump executable absence via child PATH','scope':pg.name,'PATH':'/c16-intentionally-nonexistent-native-tools'})
    run(root,'expected-native-dump-failure',command(binary,pg,'run',backup),False,path_override='/c16-intentionally-nonexistent-native-tools')
    state = json.loads(pg.sql("SELECT json_build_object('phase',phase,'sha256',sha256) FROM public.pushgo_ordinary_cutover",label='prepared-without-bound-archive'))
    assert state=={'phase':'prepared','sha256':''}, state
    after_failure = snapshot(pg)
    legacy.write_json(root/'after-failure-field-hashes.json',after_failure)
    assert after_failure==before, 'backup failure changed original business data'
    files = {str(p.relative_to(backup)):legacy.sha(p) for p in backup.rglob('*') if p.is_file()}
    legacy.write_json(root/'retained-failed-backup-files.json',files)
    run(root,'strict-pristine-source-abort',command(binary,pg,'restore',backup),True)
    assert 'pristine-source verification' in (root/'strict-pristine-source-abort.log').read_text()
    assert pg.sql("SELECT to_regclass('public.pushgo_ordinary_cutover') IS NULL",label='early-marker-cleared')=='t'
    assert snapshot(pg)==before
    assert {str(p.relative_to(backup)):legacy.sha(p) for p in backup.rglob('*') if p.is_file()}==files, 'failed backup files changed during abort'
    successful = root/'backup-after-abort'
    run(root,'rerun-after-pristine-abort',command(binary,pg,'run',successful),True)
    assert pg.sql('SELECT count(*) FROM public.ordinary_messages',label='rerun-original-history-count')=='2'
    run(root,'native-restore-after-rerun',command(binary,pg,'restore',successful),True)
    restored = snapshot(pg)
    legacy.write_json(root/'restored-field-hashes.json',restored)
    assert restored==before
    return {'case':'early-native-dump-failure-pristine-abort','database':pg.name,'expected_dump_failure':True,'prepared_sha256_empty':True,'strict_pristine_abort':True,'failed_backup_files_preserved':True,'rerun_and_full_restore':True,'all_business_fields_preserved':True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-binary',type=Path,required=True)
    parser.add_argument('--source-history',type=Path,required=True,help='source-history.json from joined remote_cutover_journey')
    parser.add_argument('--evidence-root',type=Path,required=True)
    parser.add_argument('--faults',help='comma-separated interruption fault names for only previously unrun cases')
    parser.add_argument('--cases',help='comma-separated rejection case names; keeps previously accepted cases out of a bounded rerun')
    parser.add_argument('--suite',choices=('rejections','interruptions','positives','commit-loss','backup-failure','all'),default='all')
    args = parser.parse_args()
    os.umask(0o077)
    info = json.loads(args.source_history.read_text())
    assert info['container']==journey.CONTAINER and info['injected_business_rows']==0 and info['source_sha256']==journey.SOURCE_SHA
    template = info['database_name']
    assert template.startswith(journey.PREFIX)
    ident(template)
    root = args.evidence_root.resolve()
    legacy.guard_disk(root.parent)
    root.mkdir(mode=0o700)
    results = []
    try:
        if args.suite in ('all','backup-failure'):
            results.append(backup_failure(args.candidate_binary.resolve(),root/'backup-failure',template))
        if args.suite in ('all','commit-loss'):
            results.append(commit_loss(args.candidate_binary.resolve(),root/'commit-loss',template))
        if args.suite in ('all','positives'):
            results.append(positives(args.candidate_binary.resolve(),root/'positives',template))
        if args.suite in ('all','rejections'):
            results.extend(rejection_suite(args.candidate_binary.resolve(),root,template,args.cases.split(',') if args.cases else None))
        if args.suite in ('all','interruptions'):
            faults = args.faults.split(',') if args.faults else ['sigkill','owner-session','data-session']
            assert set(faults).issubset({'sigkill','owner-session','data-session'})
            for fault in faults:
                results.append(interruption(args.candidate_binary.resolve(),root/fault,template,fault))
        legacy.write_json(root/'result.json',{'status':'PASSED','results':results,'binary_sha256':legacy.sha(args.candidate_binary),'harness_sha256':legacy.sha(Path(__file__)),'external_HTTP_requests':0,'unknown_commit_test':'PASSED' if any(r.get('unknown_commit_injected') for r in results) else 'NOT RUN','power_loss_test':'NOT RUN'})
    except BaseException as error:
        (root/'probe-failure.txt').write_text(type(error).__name__+': '+str(error)+'\n')
        raise


if __name__=='__main__':
    main()
