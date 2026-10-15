#!/usr/bin/env python3
"""One bounded synthetic control lifecycle across a real Gateway SIGKILL/restart.
Requires root runtime clearance. Never builds, edits product, or uses real providers.
Fresh --out is mandatory; first failure and raw process/SQLite/peer receipts persist.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import signal
import socket
import sqlite3
import subprocess
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
from c3_mock import C3Mock


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=pathlib.Path,required=True)
    parser.add_argument('--binary-sha256',required=True)
    parser.add_argument('--source-commit',required=True)
    parser.add_argument('--out',type=pathlib.Path,required=True)
    args=parser.parse_args()
    run=args.out.resolve();run.mkdir(parents=True,exist_ok=False)
    binary=args.binary.resolve();db=run/'candidate.sqlite'
    process=None;readers=[];logs=[];events=[];failure=None;phase='identity';pids=[]
    accepted={};requests={};snapshots={};expected_disconnected=[]
    def dump(name,value):
        (run/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
    def event(kind,**data):
        row={'event':kind,'unix_ms':int(time.time()*1000),'phase':phase,**data};events.append(row)
        with (run/'events.jsonl').open('a') as stream:stream.write(json.dumps(row,sort_keys=True)+'\n')
    def require(value,message):
        if not value:
            # Freeze the oracle boundary before context teardown releases held
            # peers and could change provider receipts in the live Gateway.
            dump('first-oracle-receipt.json',{'phase':phase,'error':message,'unix_ms':int(time.time()*1000)})
            if db.exists():
                try:snapshot('first-oracle-failure')
                except BaseException as error:dump('first-oracle-snapshot-error.json',{'error':repr(error)})
            raise AssertionError(message)
        return value
    def poll(predicate,label,seconds=8):
        deadline=time.monotonic()+seconds
        while True:
            result=predicate()
            if result:return result
            if process is not None:require(process.poll() is None,f'Gateway exited during {label}: {process.returncode}')
            require(time.monotonic()<deadline,f'bounded wait failed: {label}')
            time.sleep(.02)
    def http(path,body=None,method=None):
        data=json.dumps(body).encode() if body is not None else None
        req=urllib.request.Request(public+path,data=data,headers={'Content-Type':'application/json'},method=method)
        started=time.monotonic()
        try:
            with urllib.request.urlopen(req,timeout=5) as response:status,value=response.status,json.load(response)
        except urllib.error.HTTPError as error:status,value=error.code,json.load(error)
        event('http',path=path,method=req.get_method(),status=status,body=body,response=value,elapsed_ms=(time.monotonic()-started)*1000)
        require(status==200 and value.get('success') is True,f'HTTP failure {path}: {status} {value}')
        return value['data']
    def rows(table):
        with sqlite3.connect(f'file:{db}?mode=ro',uri=True,timeout=2) as conn:
            conn.row_factory=sqlite3.Row
            return [dict(row) for row in conn.execute(f'SELECT * FROM {table}')]
    def snapshot(label):
        tables=['messages','targets','devices','channels','channel_subscriptions','ledger_usage','retired_provider_tokens']
        with sqlite3.connect(f'file:{db}?mode=ro',uri=True,timeout=2) as conn:
            conn.row_factory=sqlite3.Row
            value={table:[dict(row) for row in conn.execute(f'SELECT * FROM {table}')] for table in tables}
            snapshots[label]=value
            with sqlite3.connect(run/f'{label}.sqlite') as target:conn.backup(target)
        def encoded(value):
            if isinstance(value,bytes):return {'hex':value.hex(),'bytes':len(value)}
            raise TypeError(type(value).__name__)
        (run/f'{label}.json').write_text(json.dumps(value,default=encoded,indent=2,sort_keys=True)+'\n')
        event('sqlite_snapshot',label=label)
        return value
    def launch(index,mock):
        nonlocal process
        ready=threading.Event();found=[]
        command=[str(binary),'--db-url',f'sqlite://{db}','--http-addr',f'127.0.0.1:{port}',
            '--mock-endpoint',mock.endpoint,'--mock-token-service-endpoint',mock.endpoint,
            '--provider-budget','4','--claim-quantum','4','--public-base-url',public]
        environment={k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','C1_','C2_','C3_'))
            and k.lower() not in ('http_proxy','https_proxy','all_proxy','no_proxy','rust_log')}
        environment['NO_PROXY']='127.0.0.1,localhost'
        child=subprocess.Popen(command,env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        process=child;pids.append(child.pid)
        def read():
            with (run/f'gateway-{index}.log').open('x') as stream:
                for line in child.stdout:
                    stream.write(line);stream.flush()
                    if line.startswith('READY '):found.append(line.rstrip());ready.set()
        thread=threading.Thread(target=read,name=f'gateway-{index}-stdout',daemon=True);thread.start();readers.append(thread)
        event('process_launch',pid=child.pid,command=command)
        require(ready.wait(20),f'Gateway {index} readiness missing')
        require(child.poll() is None,f'Gateway {index} exited at readiness')
        require(re.search(rf'\bpid={child.pid}\b',found[0]) is not None,'READY process PID mismatch')
        logs.append({'index':index,'pid':child.pid,'ready':found[0],'command':command})
    def capture(mock,op,count=1):
        return poll(lambda:mock.captures(provider='fcm',op_id=op,limit=20) if len(mock.captures(provider='fcm',op_id=op,limit=20))>=count else None,f'{op} provider capture {count}')
    def held_submit(mock,name,key,channel,password):
        op=f'control-restart-{name}-{uuid.uuid4().hex}'
        payload={'channel_id':channel,'password':password,'op_id':op,'title':f'restart {name}',
            'body':'synthetic stable canonical content','occurred_at':int(time.time()*1000)-1000,'ttl':int(time.time()*1000)+120000}
        mock.configure({'provider':'fcm','op_id':op,'hold':True,'max_hold_seconds':60,'count':1})
        requests[name]=payload;accepted[name]=http('/message',payload)
        records=capture(mock,op)
        require(len(records)==1 and records[0]['held'],'submission did not overlap held real provider request')
        require(records[0]['delivery_id']==accepted[name]['delivery_id'],'capture delivery identity mismatch')
        poll(lambda:any(row['op_id']==op and row['status']=='provider_queued' for row in rows('messages')),f'{name} durable queued')
        return records[0]
    try:
        actual_hash=hashlib.sha256(binary.read_bytes()).hexdigest()
        require(actual_hash==args.binary_sha256,'frozen binary hash mismatch')
        with socket.socket() as choose:choose.bind(('127.0.0.1',0));port=choose.getsockname()[1]
        public=f'http://127.0.0.1:{port}'
        dump('plan.json',{'binary':str(binary),'binary_sha256':actual_hash,'source_commit':args.source_commit,
            'harness_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
            'mock_sha256':hashlib.sha256(pathlib.Path(__file__).with_name('c3_mock.py').read_bytes()).hexdigest(),
            'scope':'one real Gateway SIGKILL/new PID, synthetic loopback Remote owner/provider, same DB; no native client or real provider acceptance',
            'hold_seconds':60,'recovery_observation_seconds':8,'external_unknown_op3_max_provider_calls':2,
            'expected_peer_response_errors':'BrokenPipeError/ConnectionResetError permitted only for pre-kill held capture sequences after old PID is confirmed dead'})
        with C3Mock(run/'mock') as mock:
            phase='first_process';launch(1,mock)
            key=http('/device/register',{'platform':'android'})['device_key']
            synthetic_route=uuid.uuid4().hex
            http('/channel/device',{'device_key':key,'platform':'android','channel_type':'fcm','provider_token':synthetic_route})
            password=uuid.uuid4().hex
            channel=http('/channel/subscribe',{'device_key':key,'channel_name':'restart controls','password':password})['channel_id']
            first=held_submit(mock,'acked',key,channel,password)
            ack=http('/v2/messages/ack',{'device_key':key,'delivery_ids':[accepted['acked']['delivery_id']]})
            require(ack['removed_count']==1,'ACK before held receipt did not release obligation')
            second=held_submit(mock,'retired',key,channel,password)
            winner=http('/device/register',{'platform':'android'})['device_key']
            http('/channel/device',{'device_key':winner,'platform':'android','channel_type':'fcm','provider_token':synthetic_route})
            require(not http('/v2/messages/pull',{'device_key':key})['items'],'old coalesced capability can still Pull')
            require(http('/v2/messages/ack',{'device_key':key,'delivery_ids':[accepted['retired']['delivery_id']]})['removed_count']==0,'old capability can ACK transferred obligation')
            require(http('/v2/messages/pull',{'device_key':winner})['items'][0]['delivery_id']==accepted['retired']['delivery_id'],'winning key lacks transferred Pull')
            http('/channel/device/provider-token/retire',{'platform':'android','provider_token':synthetic_route})
            require(not http('/v2/messages/pull',{'device_key':winner})['items'],'retired epoch remains Pull-visible')
            http('/channel/device',{'device_key':winner,'platform':'android','channel_type':'fcm','provider_token':synthetic_route})
            third=held_submit(mock,'future',winner,channel,password)
            before=snapshot('before-kill')
            require(all(any(t['delivery_id']==accepted[name]['delivery_id'] and t['state']=='running' for t in before['targets']) for name in accepted),'kill did not overlap every held attempt')
            phase='sigkill';expected_disconnected=[first['sequence'],second['sequence'],third['sequence']]
            old_pid=process.pid;process.kill();require(process.wait(timeout=5)==-signal.SIGKILL,'Gateway did not die by SIGKILL')
            event('process_killed',pid=old_pid,exit_code=process.returncode)
            process=None
            phase='restart';launch(2,mock);require(process.pid!=old_pid,'restart reused old PID')
            future_captures=capture(mock,requests['future']['op_id'],2)
            require(len(future_captures)==2,'unexpected external-unknown replay count')
            require(future_captures[0]['data']==future_captures[1]['data'],'recovered provider body/identity/first time/TTL changed')
            require(future_captures[0]['wire_sha256']==future_captures[1]['wire_sha256'],'recovered exact provider wire body changed')
            poll(lambda:any(row['op_id']==requests['future']['op_id'] and row['status']=='sent' for row in rows('messages')),'future recovered provider acceptance')
            after=snapshot('after-restart-before-release')
            for name in ('acked','retired'):
                require(len(mock.captures(op_id=requests[name]['op_id'],limit=20))==1,f'{name} was resent after restart')
            for name in accepted:
                original=next(row for row in before['messages'] if row['op_id']==requests[name]['op_id'])
                current=next(row for row in after['messages'] if row['op_id']==requests[name]['op_id'])
                for field in ('message_id','delivery_id','accepted_at','expires_at','dedupe_until'):
                    require(current[field]==original[field],f'{name} changed {field} across restart')
                require(current['dedupe_until']-current['accepted_at']==30*86400000,'selected 30-day identity retention changed')
                duplicate=http('/message',requests[name])
                require(duplicate['acceptance']=='duplicate_completed' and duplicate['delivery_id']==accepted[name]['delivery_id'] and duplicate['message_id']==accepted[name]['message_id'],'operation identity did not survive restart')
            phase='release_old_dead_connections';mock.release()
            poll(lambda:len([r for r in mock.requests(limit=100) if r['event']=='provider_finished'])==4,'all old holds explicitly released')
            finished=[r for r in mock.requests(limit=100) if r['event']=='provider_finished']
            for row in finished:
                error=row.get('response_error')
                require(error is None or (row['capture_sequence'] in expected_disconnected and error in ('BrokenPipeError','ConnectionResetError')),f'unexpected peer response error {row}')
            dump('released-peer-receipts.json',{'old_dead_pid':old_pid,'expected_disconnected_capture_sequences':expected_disconnected,'finished':finished})
            phase='final_ack';require(http('/v2/messages/ack',{'device_key':winner,'delivery_ids':[accepted['future']['delivery_id']]})['removed_count']==1,'future ACK failed')
            require(not http('/v2/messages/pull',{'device_key':winner})['items'],'ACKed future resurrected in Pull')
            final=snapshot('final')
            require(not final['targets'],'settled/ACKed/retired targets remain after restart')
            require(all(row['payload_bytes']==0 for row in final['messages']),'released body remains resident in ledger')
            require(len(mock.captures(op_id=requests['future']['op_id'],limit=20))==2,'future duplicated beyond one crash replay')
            token_requests=[row for row in mock.requests(limit=100) if row['event']=='token_request']
            require(token_requests,'actual Remote credential owner was not exercised')
            require(not (run/'mock/first-failure.json').exists(),'mock preserved a first failure')
            phase='graceful_finish';process.send_signal(signal.SIGTERM);require(process.wait(timeout=25)==0,'restarted Gateway failed orderly shutdown');process=None
            dump('result.json',{'status':'PASSED','pids':pids,'source_commit':args.source_commit,'binary_sha256':actual_hash,
                'accepted':accepted,'provider_calls':{'acked':1,'retired':1,'future':2},'token_requests':token_requests,
                'expected_disconnected_captures':expected_disconnected,'scope':'real OS Gateway restart only; bounded single synthetic control lifecycle'})
    except BaseException as error:
        failure={'phase':phase,'classification':'observation_or_harness' if phase in ('identity','first_process') and not accepted else 'unclassified_first_failure',
            'error':repr(error),'traceback':traceback.format_exc(),'pids':pids,'accepted':accepted}
        dump('first-failure.json',failure)
        if db.exists():
            try:snapshot('first-failure')
            except BaseException as snapshot_error:dump('snapshot-error.json',{'error':repr(snapshot_error)})
    finally:
        if process is not None and process.poll() is None:
            process.kill();process.wait(timeout=5)
        for reader in readers:reader.join(timeout=3)
        dump('processes.json',logs)
    if failure:raise SystemExit(json.dumps(failure))
    print('PASS: actual Gateway SIGKILL/new PID; ACK/retirement fences and stable bounded external-unknown replay')


if __name__=='__main__':main()
