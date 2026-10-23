#!/usr/bin/env python3
"""C16 owned MySQL native contract faults. SQL fixture rows are NOT API history.

Only fresh c16_synthetic_* databases in the dedicated C16 MySQL container.
Original source databases are never changed. No runtime hooks or forged replies.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import secrets
import signal
import socket
import subprocess
import threading
import time

import mysql_cutover_journey as journey
import legacy_cutover_probe as legacy

EXCLUDED = ('pushgo_product_owner','pushgo_ordinary_cutover')


def qi(value):
    assert value.replace('_','').isalnum(), value
    return '`'+value+'`'


def lit(value):
    # Hex UTF8 literal is unaffected by MySQL NO_BACKSLASH_ESCAPES/sql_mode.
    return "CONVERT(X'"+str(value).encode().hex()+"' USING utf8mb4)"


def clone(root,template):
    legacy.guard_disk(root.parent)
    return journey.clone_database(template,root)


def columns(db,table):
    cache=getattr(db,'_fault_columns',{})
    if table in cache:return cache[table]
    rows=db.sql("SELECT COLUMN_NAME,DATA_TYPE,IS_NULLABLE FROM information_schema.columns WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME="+lit(table)+' ORDER BY ORDINAL_POSITION',label='column-types-'+table)
    cache[table]=[line.split('\t') for line in rows.splitlines()]
    db._fault_columns=cache
    return cache[table]


def snapshot(db,filters=None):
    """Native SHA256 per field, Python canonical SHA256 per row; no raw secrets."""
    filters=filters or {}
    names=db.sql("SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_TYPE='BASE TABLE' ORDER BY BINARY TABLE_NAME",label='snapshot-tables').splitlines()
    result={}
    for table in names:
        if table in EXCLUDED:
            continue
        cols=columns(db,table)
        hashes=[]
        for name,kind,nullable in cols:
            expr=qi(name)
            if kind in ('binary','varbinary','tinyblob','blob','mediumblob','longblob','bit'):
                expr='HEX('+expr+')'
            hashes.append('SHA2(CAST(JSON_ARRAY('+expr+') AS CHAR CHARACTER SET utf8mb4),256)')
        output=db.sql('SELECT JSON_ARRAY('+','.join(hashes)+') FROM '+qi(table)+' WHERE '+filters.get(table,'TRUE'),label='field-hashes-'+table)
        rows=[]
        for line in output.splitlines():
            fields=dict(zip([c[0] for c in cols],json.loads(line)))
            rows.append({'fields':fields,'row_sha256':hashlib.sha256(json.dumps(fields,sort_keys=True,separators=(',',':')).encode()).hexdigest()})
        rows.sort(key=lambda item:json.dumps(item,sort_keys=True))
        ddl=db.sql('SHOW CREATE TABLE '+qi(table),label='schema-'+table).split('\t',1)[1]
        result[table]={'rows':rows,'schema':ddl}
    return result


def copied(db,table,overrides,where='TRUE'):
    names=[row[0] for row in columns(db,table)]
    return 'INSERT INTO '+qi(table)+'('+','.join(map(qi,names))+') SELECT '+','.join(overrides.get(name,qi(name)) for name in names)+' FROM '+qi(table)+' WHERE '+where+' ORDER BY '+qi(names[0])+' LIMIT 1'


def minimal(db,table,overrides):
    values={}
    for name,kind,nullable in columns(db,table):
        if nullable=='YES':
            continue
        values[name] = "X'"+'01'*16+"'" if kind in ('binary','varbinary','tinyblob','blob','mediumblob','longblob') else '1' if kind in ('tinyint','smallint','mediumint','int','bigint','decimal','float','double') else lit('c16-explicit-sql-fixture')
    values.update(overrides)
    return 'INSERT INTO '+qi(table)+'('+','.join(map(qi,values))+') VALUES('+','.join(values.values())+')'


def command(binary,db,action,backup):
    return [str(binary),'--db-url',db.url,'--ordinary-cutover',action,'--ordinary-cutover-backup',str(backup),'--ordinary-source-profile','small']


def run(root,label,argv,success=None,path_override=None,timeout=90):
    legacy.guard_disk(root)
    env={k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','MYSQL_'))}
    if path_override is not None:
        env['PATH']=path_override
    legacy.write_json(root/(label+'.command.json'),{'argv':argv,'PATH_override':path_override})
    with (root/(label+'.log')).open('xb') as stream:
        process=subprocess.run(argv,env=env,stdout=stream,stderr=stream,timeout=timeout)
    legacy.write_json(root/(label+'.exit.json'),{'exit_code':process.returncode})
    if success is not None:
        assert (process.returncode==0)==success,(label,process.returncode)
    return process.returncode


def identities(db,ordinary=False):
    table='ordinary_messages' if ordinary else 'sender_submit_status'
    entity='message_id' if ordinary else 'entity_id'
    output=db.sql("SELECT JSON_OBJECT('op_id',CAST(op_id AS CHAR CHARACTER SET utf8mb4),'message_id',CAST("+entity+' AS CHAR CHARACTER SET utf8mb4)) FROM '+table+(" WHERE model='message'" if not ordinary else '')+' ORDER BY BINARY op_id',label='ordinary-identities' if ordinary else 'source-identities')
    return [json.loads(line) for line in output.splitlines()]


def negative_cases(db):
    result=[]
    for table in ('dispatch_submission','provider_dispatch_outbox','private_payloads','private_outbox','provider_pull_queue'):
        states=('pending','unknown','acked') if table=='private_outbox' else ('pending','unknown') if table=='provider_dispatch_outbox' else ('orphan',)
        for state in states:
            override={'delivery_id':lit('0'*31+'1')}
            if table=='private_outbox':
                override.update(status=lit(state),claimed_by=lit('c16-lease'),claimed_at='1',acked_at='1' if state=='acked' else 'NULL')
            if table=='provider_dispatch_outbox':
                override.update(state=lit(state),lease_owner=lit('c16-lease'),lease_until='9223372036854775807')
            result.append((table+'-'+state,minimal(db,table,override),'target-bearing'))
    for state in ('sent','partial','pending'):
        result.append(('sender-'+state,"UPDATE sender_submit_status SET status="+lit(state)+" WHERE model='message'",'ordinary'))
    result.extend([
        ('wrong-version',"UPDATE pushgo_schema_meta SET meta_value="+lit('c16-unsupported')+" WHERE meta_key='schema_version'",'schema'),
        ('wrong-checksum',"UPDATE pushgo_schema_migrations SET checksum="+lit('c16-invalid'),'checksum'),
        ('extra-schema-object','CREATE TABLE c16_injected_unknown(value TEXT) ENGINE=InnoDB','schema'),
        ('missing-status',"DELETE FROM sender_submit_status WHERE op_id='c16-history-a'",'ordinary'),
        ('ambiguous-status',copied(db,'sender_submit_status',{'op_id':lit('c16-alias-fault')},"model='message'"),'duplicate'),
        ('malformed-semantic',"UPDATE semantic_id_registry SET dedupe_key="+lit('semantic:bad:message:-:c16-malformed')+" WHERE dedupe_key LIKE '%:c16-history-a'",'scope'),
        # MySQL's native case-insensitive PK forbids case-alias sender inserts.
        # Distinct semantic ID across a competing Thing scope is schema-valid;
        # missing unique status relation must reject this collision attempt.
        ('semantic-collision',copied(db,'semantic_id_registry',{'dedupe_key':"REPLACE(dedupe_key,':message:-:',':message:thing:')",'semantic_id':lit('d'*32)}),'ordinary'),
    ])
    for state,lease in (('pending',False),('unknown',False),('sent',True)):
        result.append(('op-'+state+('-lease' if lease else ''),minimal(db,'dispatch_op_dedupe',{'dedupe_key':lit('op:00000000000000000000000000:event:-:c16-fault'),'state':lit(state),'provider_owner':lit('c16-lease') if lease else 'NULL','provider_lease_until':'9223372036854775807' if lease else 'NULL'}),'responsibility'))
    result.append(('op-message-sent',minimal(db,'dispatch_op_dedupe',{'dedupe_key':lit('op:00000000000000000000000000:message:-:c16-fault'),'state':lit('sent')}),'responsibility'))
    result.append(('malformed-delivery-collision',minimal(db,'dispatch_delivery_dedupe',{'dedupe_key':lit('delivery:bad'),'delivery_id':lit('bad'),'state':lit('sent')}),'collision'))
    result.extend([
        ('empty-sender-op',copied(db,'sender_submit_status',{'op_id':lit(''),'entity_id':lit('c'*32)},"model='message'"),'orphan'),
        ('empty-semantic-key',copied(db,'semantic_id_registry',{'dedupe_key':lit(''),'semantic_id':lit('b'*32)}),'empty'),
        ('empty-op-key',minimal(db,'dispatch_op_dedupe',{'dedupe_key':lit(''),'state':lit('pending')}),'empty'),
        ('empty-delivery-key',minimal(db,'dispatch_delivery_dedupe',{'dedupe_key':lit(''),'delivery_id':lit('bad'),'state':lit('pending')}),'empty'),
    ])
    return result


def rejections(binary,root,template,selected):
    discovery=clone(root/'discovery',template)
    cases=negative_cases(discovery)
    if selected:
        assert set(selected).issubset({case[0] for case in cases})
        cases=[case for case in cases if case[0] in selected]
    results=[]
    for name,sql,expected in cases:
        directory=root/name
        db=clone(directory,template)
        legacy.write_json(directory/'injection.json',{'origin':'EXPLICIT MYSQL SQL FAULT; not API history','sql':sql,'database':db.name,'native_constraints':'source schema retained'})
        db.sql(sql,label='EXPLICIT-SQL-FAULT-INJECTION')
        before=snapshot(db);legacy.write_json(directory/'before-field-hashes.json',before)
        for action in ('plan','run'):
            label='rejected-'+action
            run(directory,label,command(binary,db,action,directory/(action+'-backup')),False)
            log=(directory/(label+'.log')).read_text()
            assert expected in log,(name,action,expected,'fault attribution mismatch')
        after=snapshot(db);legacy.write_json(directory/'after-field-hashes.json',after)
        assert before==after,(name,'business schema/field changed')
        item={'case':name,'database':db.name,'status':'REJECTED_WITHOUT_BUSINESS_CHANGE'}
        legacy.write_json(directory/'result.json',item)
        results.append(item)
    return results


def positives(binary,root,template):
    db=clone(root,template)
    thing='00112233445566778899aabbccddeeff'
    statements=["UPDATE semantic_id_registry SET dedupe_key=REPLACE(dedupe_key,':message:-:',':message:"+thing+":') WHERE dedupe_key LIKE '%:c16-history-a'"]
    for model,entity in (('event','e'*32),('thing','f'*32)):
        statements.append(copied(db,'semantic_id_registry',{'dedupe_key':"CONCAT('semantic:',SUBSTRING_INDEX(SUBSTRING_INDEX(dedupe_key,':',2),':',-1),':"+model+":-:c16-shared-"+model+"')",'semantic_id':lit(entity)},"dedupe_key LIKE '%:message:%'"))
        statements.append(copied(db,'sender_submit_status',{'op_id':lit('c16-shared-'+model),'model':lit(model),'entity_id':lit(entity),'status':lit('sent'),'dispatch_status':lit('sent')},"model='message'"))
        statements.append("INSERT INTO dispatch_op_dedupe(dedupe_key,delivery_id,state,created_at,updated_at,sent_at) SELECT CONCAT('op:',SUBSTRING_INDEX(SUBSTRING_INDEX(dedupe_key,':',2),':',-1),':"+model+":-:c16-shared-"+model+"'),semantic_id,'sent',created_at,updated_at,updated_at FROM semantic_id_registry WHERE dedupe_key LIKE '%:c16-shared-"+model+"'")
    statements.append("INSERT INTO live_activity_tokens(activity_key,token,channel_id,platform,schema_version,created_at,updated_at,expires_at) SELECT 'c16-sql-activity','c16-sql-activity-token',channel_id,'ios',1,accepted_at,updated_at,expires_at FROM sender_submit_status WHERE model='message' ORDER BY op_id LIMIT 1")
    statements.append("INSERT INTO widget_push_subscriptions(device_key,platform,token,widget_kind,family,schema_version,created_at,updated_at) SELECT 'c16-sql-device','ios','c16-sql-widget-token','c16-widget','small',1,accepted_at,updated_at FROM sender_submit_status WHERE model='message' ORDER BY op_id LIMIT 1")
    sql=';\n'.join(statements)
    legacy.write_json(root/'injection.json',{'origin':'EXPLICIT SQL POSITIVE SHARED FIXTURE; not API histories','sql':sql,'injected_shared_rows':8})
    db.sql(sql,label='EXPLICIT-SQL-SHARED-POSITIVE')
    filters={'sender_submit_status':"model<>'message'",'semantic_id_registry':"SUBSTRING_INDEX(SUBSTRING_INDEX(dedupe_key,':',3),':',-1)<>'message'"}
    before=snapshot(db,filters);legacy.write_json(root/'before-shared-field-hashes.json',before)
    original=identities(db)
    explicit=db.sql("SELECT semantic_id FROM semantic_id_registry WHERE dedupe_key LIKE '%:message:"+thing+":%'",label='explicit-thing-source-id')
    run(root,'supported-plan',command(binary,db,'plan',root/'plan-backup'),True)
    assert snapshot(db,filters)==before
    run(root,'supported-run',command(binary,db,'run',root/'backup'),True)
    after=snapshot(db,filters);legacy.write_json(root/'after-shared-field-hashes.json',after)
    assert all(after.get(table)==value for table,value in before.items()),'shared business changed'
    assert identities(db,True)==original and len(original)==2
    assert db.sql('SELECT thing_id FROM ordinary_messages WHERE message_id='+lit(explicit),label='explicit-thing-preserved')==thing
    return {'case':'supported-thing-shared-metadata','database':db.name,'original_api_ids_preserved':True,'all_shared_fields_preserved':True,'sql_injected_shared_rows':8}


def inject_window(db):
    # Individual rows intentionally reproduce C15's 2^120+i marker identities.
    statements=[]
    for i in range(512):
        entity=f'{2**120+i:032x}'
        op='c16-fault-'+str(i)
        statements.append(copied(db,'sender_submit_status',{'op_id':lit(op),'entity_id':lit(entity)},"model='message' AND op_id='c16-history-a'"))
        statements.append(copied(db,'semantic_id_registry',{'dedupe_key':"CONCAT('semantic:',SUBSTRING_INDEX(SUBSTRING_INDEX(dedupe_key,':',2),':',-1),':message:-:"+op+"')",'semantic_id':lit(entity)},"dedupe_key LIKE '%:message:-:c16-history-a'"))
    db.sql(';\n'.join(statements),label='EXPLICIT-512-SQL-FAULT-WINDOW-HISTORIES')


def sessions(db):
    # Observe from mysql default DB; never add a target client during admission.
    output=db.sql("SELECT JSON_OBJECT('pid',ID,'state',STATE,'query',INFO,'owner',EXISTS(SELECT 1 FROM performance_schema.metadata_locks l JOIN performance_schema.threads t ON t.THREAD_ID=l.OWNER_THREAD_ID WHERE t.PROCESSLIST_ID=p.ID AND l.OBJECT_TYPE='USER LEVEL LOCK' AND l.LOCK_STATUS='GRANTED'),'post_ddl_message_write_lock',EXISTS(SELECT 1 FROM performance_schema.metadata_locks l JOIN performance_schema.threads t ON t.THREAD_ID=l.OWNER_THREAD_ID WHERE t.PROCESSLIST_ID=p.ID AND l.OBJECT_SCHEMA="+lit(db.name)+" AND l.OBJECT_NAME='ordinary_messages' AND l.LOCK_TYPE='SHARED_NO_READ_WRITE' AND l.LOCK_STATUS='GRANTED')) FROM performance_schema.processlist p WHERE DB="+lit(db.name),database='mysql',label='exact-target-sessions')
    return [json.loads(line) for line in output.splitlines()]


def restore_rerun(binary,root,db,backup,before,template):
    run(root,'native-full-restore',command(binary,db,'restore',backup),True)
    after=snapshot(db);legacy.write_json(root/'restored-field-hashes.json',after)
    assert before==after,'native full restore changed business fields/schema'
    run(root,'rerun-after-restore',command(binary,db,'run',root/'backup-after-restore'),True)
    actual=identities(db,True)
    source_root=root/'frozen-source-observation';source_root.mkdir(mode=0o700)
    original_db=journey.Mysql(source_root,template)
    original=identities(original_db)
    assert len(actual)==514 and all(item in actual for item in original)


def interruption(binary,root,template,fault):
    db=clone(root,template)
    inject_window(db)
    before=snapshot(db);legacy.write_json(root/'before-field-hashes.json',before)
    backup=root/'backup';argv=command(binary,db,'run',backup)
    legacy.write_json(root/'injection.json',{'origin':'EXPLICIT 512 SQL histories plus native process/session fault','fault':fault,'argv':argv,'DDL_boundary':'ordinary table DDL completed before observed conversion INSERT; no runtime hooks'})
    env={k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','MYSQL_'))}
    observed=None
    with (root/'interrupted-run.log').open('xb') as log:
        child=subprocess.Popen(argv,env=env,stdout=log,stderr=log)
        try:
            deadline=time.monotonic()+60
            while child.poll() is None and time.monotonic()<deadline:
                current=sessions(db)
                converting=[s for s in current if (fault=='data-session' and s['post_ddl_message_write_lock'] and not s['owner']) or (s['query'] and ('INSERT INTO ordinary_messages' in s['query'] or 'DELETE FROM semantic_id_registry WHERE dedupe_key' in s['query']))]
                if converting:
                    owner=[s for s in current if s['owner']]
                    assert len(converting)==1 and len(owner)==1,current
                    observed={'sessions':current,'data_pid':converting[0]['pid'],'owner_pid':owner[0]['pid']}
                    if fault=='sigkill':
                        child.send_signal(signal.SIGKILL)
                    else:
                        target=owner[0]['pid'] if fault=='owner-session' else converting[0]['pid']
                        db.sql('KILL CONNECTION '+str(target),database='mysql',label='EXPLICIT-EXACT-MIGRATION-SESSION-TERMINATION')
                    break
            assert observed,'native post-DDL/pre-data-COMMIT window NOT OBSERVED; first attempt preserved'
            rc=child.wait(timeout=30)
            assert rc!=0,'native interrupted migration succeeded'
        finally:
            if child.poll() is None:
                child.kill();child.wait(timeout=5)
    legacy.write_json(root/'fault-receipt.json',{'observed':observed,'exit_code':rc,'unknown_commit_injected':False})
    assert db.sql('SELECT CAST(phase AS CHAR) FROM pushgo_ordinary_cutover',label='durable-prepared-phase')=='prepared'
    run(root,'repeat-incomplete',command(binary,db,'run',root/'repeat-backup'),False)
    startup=[str(binary),'--db-url',db.url,'--http-addr','127.0.0.1:'+str(legacy.port()),'--private-transports','false','--token-service-url','http://127.0.0.1:1']
    run(root,'incomplete-startup',startup,False,timeout=20)
    log=(root/'incomplete-startup.log').read_text()
    assert 'incomplete MySQL cutover' in log and 'restore' in log,'unattributed startup rejection'
    restore_rerun(binary,root,db,backup,before,template)
    return {'fault':fault,'database':db.name,'full_native_restore':True,'histories':514,'original_api_ids_preserved':True,'actual_post_DDL_pre_COMMIT_interruption':True}


class CommitLossProxy:
    """Native MySQL packet forwarding; lose one real final COMMIT OK packet.

    Prepared statement IDs/parameter count come from actual server PREPARE_OK.
    The complete phase UPDATE must execute with actual 'complete' parameter and
    receive its real OK before the next COMMIT acknowledgement can be dropped.
    TLS is never disabled by mutating handshake bytes; caller's URL must disable
    TLS. No response is fabricated or modified.
    """
    def __init__(self):
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen();self.listener.settimeout(.2)
        self.port=self.listener.getsockname()[1]
        self.stop=threading.Event();self.lock=threading.Lock()
        self.sockets=[];self.events=[];self.fault=None;self.number=0
        self.thread=threading.Thread(target=self.accept,daemon=True);self.thread.start()

    @staticmethod
    def close_socket(stream):
        try:stream.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        stream.close()

    def record(self,event):
        with self.lock:self.events.append(event)

    def accept(self):
        while not self.stop.is_set():
            try:client,_=self.listener.accept()
            except socket.timeout:continue
            except OSError:break
            server=socket.create_connection(('127.0.0.1',42773),timeout=5)
            client.settimeout(.2);server.settimeout(.2)
            with self.lock:
                self.number+=1;number=self.number;self.sockets.extend((client,server))
            state={'number':number,'authenticated':False,'first_client':True,'prepared':{},'pending':None,'armed':False}
            threading.Thread(target=self.pipe,args=(client,server,state,False),daemon=True).start()
            threading.Thread(target=self.pipe,args=(server,client,state,True),daemon=True).start()

    @staticmethod
    def phase_parameter(payload,definition):
        if definition['params']!=1 or len(payload)<12:
            return None
        pos=10
        nulls=payload[pos];pos+=1
        rebound=payload[pos];pos+=1
        if nulls&1:return None
        if rebound:
            if len(payload)<pos+2:return None
            definition['type']=payload[pos];pos+=2
        if definition.get('type') not in (15,253,254):return None
        if len(payload)<=pos:return None
        size=payload[pos];pos+=1
        if size>=251:return None
        return payload[pos:pos+size].decode('utf8',errors='strict')

    def client_packet(self,payload,state):
        if not state['authenticated']:
            if state['first_client']:
                state['first_client']=False
                if len(payload)>=4 and int.from_bytes(payload[:4],'little')&0x800:
                    self.record({'connection':state['number'],'unsupported':'TLS requested; no packet mutation or injection permitted'})
            return
        if not payload:return
        command=payload[0]
        if command==0x16:
            sql=payload[1:].decode('utf8',errors='replace')
            state['pending']={'kind':'prepare','sql':sql}
        elif command==0x17 and len(payload)>=10:
            stmt=int.from_bytes(payload[1:5],'little');definition=state['prepared'].get(stmt)
            state['pending']=None
            if definition:
                sql=definition['sql'].strip().rstrip(';')
                if sql.upper()=='COMMIT':
                    state['pending']={'kind':'commit','sql':'COMMIT','statement_id':stmt}
                elif sql=='UPDATE pushgo_ordinary_cutover SET phase=? WHERE singleton=1':
                    value=self.phase_parameter(payload,definition)
                    state['pending']={'kind':'phase','value':value,'statement_id':stmt}
                    self.record({'connection':state['number'],'phase_parameter_observed':value,'statement_id':stmt})
        elif command==0x03:
            sql=payload[1:].decode('utf8',errors='replace').strip().rstrip(';')
            state['pending']={'kind':'commit','sql':'COMMIT'} if sql.upper()=='COMMIT' else None
        else:
            state['pending']=None

    def server_packet(self,payload,frame,state):
        if not payload:return False
        if not state['authenticated']:
            if payload[0]==0x00:state['authenticated']=True
            return False
        pending=state['pending']
        if not pending:return False
        if pending['kind']=='prepare':
            if payload[0]==0x00 and len(payload)>=12:
                stmt=int.from_bytes(payload[1:5],'little')
                state['prepared'][stmt]={'sql':pending['sql'],'params':int.from_bytes(payload[7:9],'little')}
            state['pending']=None
        elif pending['kind']=='phase':
            if payload[0]==0x00 and pending['value']=='complete':
                state['armed']=True
                self.record({'connection':state['number'],'complete_phase_real_OK_observed':True,'statement_id':pending['statement_id']})
            state['pending']=None
        elif pending['kind']=='commit':
            state['pending']=None
            event={'connection':state['number'],'real_commit_response_first_byte':payload[0],'phase_complete_armed':state['armed'],'packet_hex':frame.hex()}
            self.record(event)
            if payload[0]==0x00 and state['armed']:
                with self.lock:
                    if self.fault is None:
                        self.fault=dict(event,action='native MySQL server final COMMIT OK received; client closed before forwarding packet')
                        return True
        return False

    def pipe(self,source,destination,state,backend):
        pending=b''
        try:
            while not self.stop.is_set():
                try:data=source.recv(65536)
                except socket.timeout:continue
                if not data:break
                pending+=data
                while len(pending)>=4:
                    size=int.from_bytes(pending[:3],'little')+4
                    if len(pending)<size:break
                    frame,pending=pending[:size],pending[size:]
                    payload=frame[4:]
                    if backend:
                        if self.server_packet(payload,frame,state):return
                    else:self.client_packet(payload,state)
                    destination.sendall(frame)
        except OSError:pass
        except (AssertionError,UnicodeError,ValueError) as error:
            self.record({'connection':state['number'],'protocol_error':type(error).__name__+': '+str(error)})
        finally:
            self.close_socket(source);self.close_socket(destination)

    def close(self):
        self.stop.set();self.listener.close()
        with self.lock:streams=list(self.sockets)
        for stream in streams:self.close_socket(stream)
        self.thread.join(timeout=2)


def commit_loss(binary,root,template):
    db=clone(root,template)
    before=snapshot(db);legacy.write_json(root/'before-field-hashes.json',before)
    original=identities(db);backup=root/'backup'
    proxy=CommitLossProxy()
    argv=command(binary,db,'run',backup)
    argv[argv.index('--db-url')+1]='mysql://root@127.0.0.1:'+str(proxy.port)+'/'+db.name+'?ssl-mode=disabled'
    legacy.write_json(root/'injection.json',{'origin':'EXPLICIT TEST-ONLY NATIVE MYSQL COMMIT OK RESPONSE LOSS','scope':db.name,'arm':'actual prepared complete phase parameter + actual native phase OK, followed by COMMIT OK','forged_responses':0})
    try:rc=run(root,'commit-reply-lost',argv,None)
    finally:
        proxy.close();legacy.write_json(root/'proxy-receipt.json',{'fault':proxy.fault,'events':proxy.events})
    assert proxy.fault,'native final COMMIT reply-loss NOT RUN; missing/unsupported protocol window retained'
    assert rc!=0,'client did not report COMMIT acknowledgement loss'
    assert not any('protocol_error' in e or 'unsupported' in e for e in proxy.events),'protocol observation ambiguous'
    assert db.sql('SELECT CAST(phase AS CHAR) FROM pushgo_ordinary_cutover',label='independent-native-complete')=='complete'
    assert identities(db,True)==original and len(original)==2
    committed=snapshot(db);legacy.write_json(root/'committed-field-hashes.json',committed)
    run(root,'direct-noop-replay',command(binary,db,'run',backup),True)
    assert snapshot(db)==committed,'complete replay changed native business state'
    run(root,'full-native-restore',command(binary,db,'restore',backup),True)
    restored=snapshot(db);legacy.write_json(root/'restored-field-hashes.json',restored)
    assert restored==before,'native restore after COMMIT loss mismatched source'
    return {'case':'final-COMMIT-reply-loss','database':db.name,'client_exit_code':rc,'server_commit_independently_verified':True,'replay_without_duplicate':True,'full_native_restore':True,'unknown_commit_injected':True}


def backup_failure(binary,root,template):
    db=clone(root,template);before=snapshot(db);legacy.write_json(root/'before-field-hashes.json',before)
    backup=root/'failed-backup'
    legacy.write_json(root/'injection.json',{'origin':'EXPLICIT CHILD PATH NATIVE MYSQLDUMP ABSENCE','database':db.name})
    run(root,'expected-native-backup-failure',command(binary,db,'run',backup),False,path_override='/c16-intentionally-absent-native-tools')
    state=json.loads(db.sql("SELECT JSON_OBJECT('phase',CAST(phase AS CHAR),'sha256',CAST(sha256 AS CHAR)) FROM pushgo_ordinary_cutover",label='prepared-empty-sha256'))
    assert state=={'phase':'prepared','sha256':''},state
    after=snapshot(db);legacy.write_json(root/'after-backup-failure-field-hashes.json',after);assert after==before
    files={str(p.relative_to(backup)):legacy.sha(p) for p in backup.rglob('*') if p.is_file()}
    legacy.write_json(root/'failed-backup-files.json',files)
    run(root,'strict-pristine-abort',command(binary,db,'restore',backup),True)
    assert 'pristine-source verification' in (root/'strict-pristine-abort.log').read_text()
    assert db.sql("SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='pushgo_ordinary_cutover'",label='marker-cleared')=='0'
    assert snapshot(db)==before
    assert files=={str(p.relative_to(backup)):legacy.sha(p) for p in backup.rglob('*') if p.is_file()}
    valid=root/'backup-after-abort'
    run(root,'rerun-after-abort',command(binary,db,'run',valid),True)
    assert len(identities(db,True))==2
    run(root,'full-native-restore',command(binary,db,'restore',valid),True)
    restored=snapshot(db);legacy.write_json(root/'restored-field-hashes.json',restored);assert restored==before
    return {'case':'early-native-backup-failure','database':db.name,'pristine_source_abort':True,'failed_backup_files_unchanged':True,'rerun_and_full_restore':True}


def wrong_backup_hash(binary,root,template):
    db=clone(root,template);before=snapshot(db);legacy.write_json(root/'source-field-hashes.json',before)
    backup=root/'backup'
    run(root,'valid-conversion',command(binary,db,'run',backup),True)
    committed=snapshot(db);legacy.write_json(root/'committed-field-hashes.json',committed)
    artifact=backup/'source.dump'
    assert artifact.is_file()
    legacy.write_json(root/'injection.json',{'origin':'EXPLICIT BACKUP ARTIFACT CHECKSUM CORRUPTION; native business DB unchanged','artifact':str(artifact),'original_sha256':legacy.sha(artifact)})
    preserved=root/'uncorrupted-source.dump';shutil.copyfile(artifact,preserved)
    with artifact.open('ab') as stream:stream.write(b'\n-- c16 explicit backup checksum fault\n')
    run(root,'wrong-hash-restore-blocked',command(binary,db,'restore',backup),False)
    assert 'hash' in (root/'wrong-hash-restore-blocked.log').read_text()
    assert snapshot(db)==committed,'rejected bad-hash restore changed business DB'
    # Keep corrupted backup and its diagnostic intact. Recover native state with
    # an explicitly recorded byte restoration of only this owned backup artifact.
    corrupt=root/'corrupted-source.dump';shutil.copyfile(artifact,corrupt)
    shutil.copyfile(preserved,artifact)
    legacy.write_json(root/'artifact-recovery.json',{'original_copy':str(preserved),'corrupt_copy':str(corrupt),'restored_sha256':legacy.sha(artifact)})
    run(root,'restore-after-owned-artifact-repair',command(binary,db,'restore',backup),True)
    restored=snapshot(db);legacy.write_json(root/'restored-field-hashes.json',restored);assert restored==before
    return {'case':'wrong-backup-hash','database':db.name,'restore_rejected_without_business_change':True,'corrupt_bytes_preserved':True,'full_native_restore_after_artifact_repair':True}



def incomplete_start(binary,root,db,label):
    argv=[str(binary),'--db-url',db.url,'--http-addr','127.0.0.1:'+str(legacy.port()),'--private-transports','false','--token-service-url','http://127.0.0.1:1']
    run(root,label,argv,False,timeout=20)
    log=(root/(label+'.log')).read_text()
    assert ('incomplete MySQL cutover' in log or 'damaged MySQL cutover marker' in log) and ('restore' in log or 'marker' in log),'startup rejection not attributed to durable marker'


def privileges(binary,root,template):
    db=clone(root,template)
    before=snapshot(db);legacy.write_json(root/'before-field-hashes.json',before)
    username=journey.PREFIX+secrets.token_hex(7)
    account="'"+username+"'@'%'"
    # Empty-auth synthetic account, as on this dedicated disposable container.
    # No password assignment, secret or credential value is recorded.
    db.sql('CREATE USER '+account+'; GRANT ALL PRIVILEGES ON '+qi(db.name)+'.* TO '+account+'; GRANT SELECT ON performance_schema.* TO '+account,database='mysql',label='EXPLICIT-SYNTHETIC-LIMITED-ACCOUNT')
    legacy.write_json(root/'injection.json',{'origin':'EXPLICIT SYNTHETIC DB-ALL + performance_schema SELECT account WITHOUT global PROCESS; root sleeper metadata visibility fixture','account':username,'database':db.name,'password_assignment':'NONE'})
    metadata_before=db.sql("SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('pushgo_product_owner','pushgo_ordinary_cutover') ORDER BY TABLE_NAME",label='metadata-before-limited-plan')
    argv=['docker','exec','-i',journey.CONTAINER,'mysql','-uroot',db.name,'-e','SELECT /* c16-visibility-fixture */ SLEEP(60)']
    legacy.write_json(root/'root-sleeper.command.json',{'argv':argv,'origin':'explicit native metadata visibility fixture, not product traffic'})
    with (root/'root-sleeper.stdout').open('xb') as stream,(root/'root-sleeper.stderr').open('xb') as errors:
        sleeper=subprocess.Popen(argv,stdout=stream,stderr=errors)
        pid=None
        try:
            deadline=time.monotonic()+5
            while time.monotonic()<deadline and sleeper.poll() is None:
                output=db.sql("SELECT ID FROM performance_schema.processlist WHERE DB="+lit(db.name)+" AND INFO LIKE '%c16-visibility-fixture%'",database='mysql',label='exact-root-sleeper-pid')
                if output:
                    assert len(output.splitlines())==1
                    pid=int(output);break
            assert pid,'native root visibility fixture not observed'
            limited=command(binary,db,'plan',root/'limited-plan-backup')
            limited[limited.index('--db-url')+1]=db.url.replace('mysql://root@','mysql://'+username+'@')
            run(root,'limited-no-PROCESS-plan',limited,False)
            assert 'PROCESS' in (root/'limited-no-PROCESS-plan.log').read_text()
            assert db.sql("SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('pushgo_product_owner','pushgo_ordinary_cutover') ORDER BY TABLE_NAME",label='metadata-after-limited-plan')==metadata_before,'limited refusal occurred after metadata creation'
            assert not (root/'limited-plan-backup').exists()
            assert snapshot(db)==before
            run(root,'admin-with-live-client-plan',command(binary,db,'plan',root/'blocked-admin-backup'),False)
            assert 'stop and join' in (root/'admin-with-live-client-plan.log').read_text()
            assert snapshot(db)==before
        finally:
            if pid is not None and sleeper.poll() is None:
                db.sql('KILL CONNECTION '+str(pid),database='mysql',label='join-owned-root-visibility-fixture')
            if sleeper.poll() is None:
                try:sleeper.wait(timeout=5)
                except subprocess.TimeoutExpired:sleeper.kill();sleeper.wait(timeout=5)
            legacy.write_json(root/'root-sleeper.exit.json',{'exit_code':sleeper.returncode})
    run(root,'admin-after-all-clients-joined-plan',command(binary,db,'plan',root/'accepted-admin-backup'),True)
    after=snapshot(db);legacy.write_json(root/'after-field-hashes.json',after);assert after==before
    return {'case':'global-PROCESS-visibility','database':db.name,'limited_refused_before_metadata_and_backup':True,'admin_live_client_refused':True,'joined_admin_plan_passed':True,'all_business_fields_unchanged':True}


def empty_marker(binary,root,template):
    db=clone(root,template);before=snapshot(db);legacy.write_json(root/'before-field-hashes.json',before)
    sql="CREATE TABLE pushgo_ordinary_cutover(singleton TINYINT PRIMARY KEY CHECK(singleton=1),format VARBINARY(64) NOT NULL,phase VARBINARY(16) NOT NULL,backup TEXT NOT NULL,source_profile VARBINARY(16) NOT NULL,sha256 VARBINARY(64) NOT NULL,dataset VARBINARY(32) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin"
    legacy.write_json(root/'injection.json',{'origin':'EXPLICIT SOURCE-PRISTINE MYSQL EMPTY VALID MARKER DDL FAULT; simulates implicit CREATE commit before singleton INSERT','sql':sql})
    db.sql(sql,label='EXPLICIT-EMPTY-VALID-MARKER-DDL')
    assert snapshot(db)==before
    run(root,'empty-marker-repeat-run',command(binary,db,'run',root/'blocked-backup'),False)
    incomplete_start(binary,root,db,'empty-marker-startup')
    restore=command(binary,db,'restore',root/'uncreated-backup')
    no_profile=restore[:-2]
    run(root,'empty-marker-no-profile-restore',no_profile,False)
    assert 'explicit fixed-main source profile' in (root/'empty-marker-no-profile-restore.log').read_text()
    run(root,'empty-marker-explicit-pristine-abort',restore,True)
    assert 'empty prepared marker aborted' in (root/'empty-marker-explicit-pristine-abort.log').read_text()
    assert db.sql("SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='pushgo_ordinary_cutover'",label='empty-marker-cleared')=='0'
    after=snapshot(db);legacy.write_json(root/'after-field-hashes.json',after);assert after==before
    return {'case':'empty-valid-marker-implicit-DDL','database':db.name,'repeat_startup_and_profileless_restore_refused':True,'explicit_profile_pristine_abort':True,'business_fields_unchanged':True}


def partial_restore(binary,root,template):
    db=clone(root,template);before=snapshot(db);legacy.write_json(root/'source-field-hashes.json',before)
    backup=root/'backup';run(root,'valid-conversion',command(binary,db,'run',backup),True)
    shim=root/'partial-native-tools';shim.mkdir(mode=0o700)
    native=shutil.which('mysql');assert native,'native QA mysql wrapper missing'
    native=Path(native).resolve()
    assert 'c16-remote-history-20261017' in native.parts,'only this round owned native wrapper accepted'
    script=shim/'mysql'
    body="""#!/usr/bin/python3
import json,re,subprocess,sys
from pathlib import Path
root=Path(ROOT)
data=sys.stdin.buffer.read(8*1024*1024+1)
assert len(data)<=8*1024*1024, 'bounded synthetic restore dump required'
match=re.search(rb'(?m)^DROP TABLE IF EXISTS `([a-zA-Z0-9_]+)`;[^\\n]*\\n',data)
assert match, 'first native dump DROP TABLE DDL not found'
prefix=data[:match.end()]
(root/'partial-native-prefix.sql').write_bytes(prefix)
(root/'partial-native-DDL.json').write_text(json.dumps({'table':match.group(1).decode(),'prefix_bytes':len(prefix),'origin':'EXPLICIT native first-DDL-only restore failure shim'},indent=2))
result=subprocess.run([NATIVE]+sys.argv[1:],input=prefix,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
(root/'partial-native-prefix.stdout').write_bytes(result.stdout)
(root/'partial-native-prefix.stderr').write_bytes(result.stderr)
(root/'partial-native-prefix.exit.json').write_text(json.dumps({'argv':[NATIVE]+sys.argv[1:],'exit_code':result.returncode}))
assert result.returncode==0, 'native first DDL did not apply'
sys.exit(97)
""".replace('ROOT',repr(str(root))).replace('NATIVE',repr(str(native)))
    script.write_text(body);script.chmod(0o700)
    legacy.write_json(root/'injection.json',{'origin':'EXPLICIT TEST-ONLY NATIVE RESTORE SHIM applies actual first dump DROP DDL then exits97; no all-DDL-atomic claim','shim':str(script),'shim_sha256':legacy.sha(script),'native_forwarder':str(native),'native_forwarder_sha256':legacy.sha(native)})
    run(root,'expected-partial-native-restore-failure',command(binary,db,'restore',backup),False,path_override=str(shim)+os.pathsep+os.environ.get('PATH',''))
    assert 'native MySQL restore failed' in (root/'expected-partial-native-restore-failure.log').read_text()
    assert db.sql('SELECT CAST(phase AS CHAR) FROM pushgo_ordinary_cutover',label='persistent-restoring-phase')=='restoring'
    ddl=json.loads((root/'partial-native-DDL.json').read_text())
    assert json.loads((root/'partial-native-prefix.exit.json').read_text())['exit_code']==0
    assert db.sql('SELECT COUNT(*) FROM information_schema.tables WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='+lit(ddl['table']),label='native-DDL-partial-effect')=='0'
    incomplete_start(binary,root,db,'partial-native-restore-startup-refused')
    run(root,'partial-native-restore-run-refused',command(binary,db,'run',root/'blocked-backup'),False)
    run(root,'native-complete-restore-retry',command(binary,db,'restore',backup),True)
    restored=snapshot(db);legacy.write_json(root/'restored-field-hashes.json',restored);assert restored==before
    return {'case':'partial-native-implicit-DDL-restore-failure','database':db.name,'actual_first_DDL_applied':ddl['table'],'restoring_marker_persisted':True,'startup_and_repeat_run_refused':True,'complete_native_restore_retry_equal':True,'all_DDL_atomic_claim':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-binary',required=True,type=Path)
    parser.add_argument('--source-history',required=True,type=Path)
    parser.add_argument('--catalog-sql',required=True,type=Path)
    parser.add_argument('--evidence-root',required=True,type=Path)
    parser.add_argument('--suite',choices=('rejections','positives','interruptions','commit-loss','backup-failure','wrong-hash','privileges','empty-marker','partial-restore','all'),default='all')
    parser.add_argument('--lanes',help='comma-separated finite suite lanes; resume only previously unrun lanes')
    parser.add_argument('--cases',help='only comma-separated previously unrun rejection cases')
    parser.add_argument('--faults',help='only comma-separated previously unrun interruption cases')
    args=parser.parse_args();os.umask(0o077)
    info=json.loads(args.source_history.read_text())
    assert info['container']==journey.CONTAINER and info['source_sha256']==journey.SOURCE_SHA and info['injected_business_rows']==0
    template=info['database_name'];assert template.startswith(journey.PREFIX);qi(template)
    root=args.evidence_root.resolve();legacy.guard_disk(root.parent);root.mkdir(mode=0o700)
    binary=args.candidate_binary.resolve()
    sealed={}
    for source in (Path(__file__).resolve(),Path(journey.__file__).resolve(),args.catalog_sql.resolve()):
        target=root/('sealed-'+source.name);shutil.copyfile(source,target);sealed[str(source)]={'copy':str(target),'sha256':legacy.sha(target)}
    legacy.write_json(root/'seal.json',{'files':sealed,'candidate_binary':str(binary),'candidate_sha256':legacy.sha(binary),'source_history_sha256':legacy.sha(args.source_history)})
    results=[]
    try:
        all_lanes=('privileges','empty-marker','partial-restore','backup-failure','wrong-hash','commit-loss','positives','rejections','interruptions')
        lanes=args.lanes.split(',') if args.lanes else all_lanes if args.suite=='all' else (args.suite,)
        assert set(lanes).issubset(set(all_lanes)), 'unknown suite lane'
        for lane in lanes:
            if lane=='rejections':results.extend(rejections(binary,root,template,args.cases.split(',') if args.cases else None))
            elif lane=='interruptions':
                faults=args.faults.split(',') if args.faults else ['sigkill','owner-session','data-session']
                assert set(faults).issubset({'sigkill','owner-session','data-session'})
                for fault in faults:
                    item=interruption(binary,root/fault,template,fault);legacy.write_json(root/fault/'result.json',item);results.append(item)
            else:
                function={'positives':positives,'commit-loss':commit_loss,'backup-failure':backup_failure,'wrong-hash':wrong_backup_hash,'privileges':privileges,'empty-marker':empty_marker,'partial-restore':partial_restore}[lane]
                item=function(binary,root/lane,template);legacy.write_json(root/lane/'result.json',item);results.append(item)
        legacy.write_json(root/'result.json',{'status':'PASSED','results':results,'candidate_sha256':legacy.sha(binary),'external_HTTP_requests':0,'power_loss_test':'NOT RUN','unknown_commit_test':'PASSED' if any(r.get('unknown_commit_injected') for r in results) else 'NOT RUN'})
    except BaseException as error:
        (root/'probe-failure.txt').write_text(type(error).__name__+': '+str(error)+'\n');raise


if __name__=='__main__':main()
