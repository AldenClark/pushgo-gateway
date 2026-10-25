#!/usr/bin/env python3
"""Populate one real normal Gateway scope for client-side conflict/recovery tests.

All records enter through /message. Only the client fixture chooses which of the
actual first identities to seed as a local historical conflict; this tool never
changes the Gateway's payload, target, ACK, or configuration tables.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid
import urllib.request
import urllib.error
from urllib.parse import urlsplit


def message_bytes(context, namespace, index, target_bytes=None, severity=None):
    item = {'op_id':str(uuid.uuid4()), 'title':f'Deep fixture {namespace[:8]} #{index:04}',
        'body':f'Synthetic durable content {namespace} #{index:04}'}
    request = {'channel_id':context['channel_id'], 'password':context['channel_password'], **item}
    if severity is not None:
        assert severity in ('normal','low')
        item['severity'] = severity
        request['severity'] = severity
    if target_bytes is not None:
        request['body'] = ''
        overhead = len(json.dumps(request,separators=(',',':'),ensure_ascii=False).encode())
        assert target_bytes > overhead
        request['body'] = 'x'*(target_bytes-overhead)
        item['body'] = request['body']
    encoded = json.dumps(request,separators=(',',':'),ensure_ascii=False).encode()
    if target_bytes is not None:
        assert len(encoded) == target_bytes
    item['request_bytes'] = len(encoded)
    return item,encoded


def post_message_bytes(context, encoded):
    request = urllib.request.Request(context['base_url']+'/message', method='POST', data=encoded,
        headers={'Authorization':'Bearer '+context['token'],'Content-Type':'application/json'})
    try:
        response = urllib.request.urlopen(request,timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status = response.status
        value = json.load(response)
    return status,value


def next_acceptance_millisecond(after):
    # Source and caller are the same host. This is an observed-clock phase
    # condition, not a fixed sleep or retry of business actions. Native ordering
    # is still verified afterwards; a clock rollback fails setup rather than
    # publishing a large message in the rejected prefix.
    started = time.monotonic()
    deadline = started+2
    while time.time_ns()//1_000_000 <= after:
        assert time.monotonic() < deadline, 'owned normal Gateway clock phase did not advance'
        time.sleep(.001)
    return (time.monotonic()-started)*1000


def choose_rows(rows, expected, rejected_count, device):
    """Validate real frozen ownership and preserve the database's native order."""
    assert len(rows) == len(expected), 'each accepted message needs exactly one frozen target'
    assert 0 <= rejected_count < len(rows)
    message_ids = set()
    delivery_ids = set()
    result = []
    for row in rows:
        message_id = row['message_id']
        assert message_id in expected and message_id not in message_ids
        assert row['delivery_id'] not in delivery_ids
        assert row['pull_owner'] == device and row['delivery_mode'] == 'provider'
        assert row['acked_at'] is None, 'fixture must not pre-ACK a delivery'
        payload = json.loads(row['payload_blob'])
        item = expected[message_id]
        assert row['op_id'] == item['op_id']
        assert payload['entity_type'] == 'message'
        assert payload['body'] == item['body'] and payload['title'] == item['title']
        if 'severity' in item:
            assert payload['severity'] == item['severity']
        assert payload.get('delivery_id', row['delivery_id']) == row['delivery_id']
        assert payload.get('message_id', message_id) == message_id
        result.append({'delivery_id':row['delivery_id'], 'message_id':message_id,
            'op_id':row['op_id'], 'body':item['body'], 'title':item['title'],
            'body_sha256':hashlib.sha256(item['body'].encode()).hexdigest(),
            'severity':payload.get('severity'),
            'accepted_at':row['accepted_at'], 'request_bytes':item.get('request_bytes')})
        message_ids.add(message_id)
        delivery_ids.add(row['delivery_id'])
    assert message_ids == set(expected)
    return result[:rejected_count], result[rejected_count:]


def verify_initial_head(head, ordered_rows):
    complete = len(ordered_rows) <= 200
    assert head['scan_complete'] is complete and head['has_more'] is not complete
    if complete:
        assert head['next_page_token'] is None
    else:
        assert isinstance(head['next_page_token'],str) and head['next_page_token']
    assert [item['delivery_id'] for item in head['items']] == [
        item['delivery_id'] for item in ordered_rows[:200]]


def attach_actual_pull_payloads(head, ordered_rows, post_page, stored_payloads):
    """Copy wire maps, never reconstruct them from selected business fields."""
    expected = {item['delivery_id']:item for item in ordered_rows}
    assert len(expected) == len(ordered_rows)
    seen = set()
    tokens = set()
    # The owned fixture is finite, unfiltered, and at most2000 small records
    # with one49KiB record. Keep a separate bound if the server contract changes.
    for _ in range(20):
        assert type(head.get('scan_complete')) is bool and type(head.get('has_more')) is bool
        complete = head['scan_complete']
        token = head['next_page_token']
        assert head['has_more'] is not complete
        assert (token is None) if complete else (isinstance(token,str) and bool(token))
        for item in head['items']:
            delivery = item['delivery_id']
            assert delivery in expected and delivery not in seen
            payload = item['payload']
            assert isinstance(payload,dict) and all(isinstance(k,str) and isinstance(v,str)
                                                    for k,v in payload.items())
            canonical = dict(stored_payloads[delivery])
            canonical.pop('delivery_id',None) # The normal V2 encoder removes this inner key.
            assert payload == canonical, 'actual Pull wire must match its saved canonical payload'
            expected[delivery]['payload'] = dict(payload)
            seen.add(delivery)
        if complete:
            assert seen == set(expected), 'actual traversal cannot omit fixture rows'
            return len(tokens)+1
        assert token not in tokens, 'continuation must advance'
        tokens.add(token)
        head = post_page(token)
    raise AssertionError('owned fixture traversal exceeded20pages')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rejected', type=int, required=True)
    parser.add_argument('--healthy', type=int, required=True)
    parser.add_argument('--concurrency', type=int, default=8)
    parser.add_argument('--severity', choices=('normal','low'))
    parser.add_argument('--include-pull-payloads', action='store_true')
    args = parser.parse_args()
    assert (args.rejected == 0 or 200 <= args.rejected <= 1800) and 1 <= args.healthy <= 1800
    assert 2 <= args.rejected + args.healthy <= 2000 and 1 <= args.concurrency <= 8
    assert args.context.is_absolute() and args.context.is_file() and not args.context.is_symlink()
    assert args.context.stat().st_mode & 0o077 == 0
    owner = args.context.parent.resolve()
    assert args.context.parent == owner and owner.stat().st_mode & 0o077 == 0
    assert args.output.is_absolute() and not args.output.exists() and args.output.parent == owner
    context = json.loads(args.context.read_text())
    assert context['synthetic_only'] is True and context['normal_product'] is True
    origin = urlsplit(context['base_url'])
    assert origin.scheme=='http' and origin.hostname=='127.0.0.1' and origin.port is not None
    assert origin.username is None and origin.password is None
    assert origin.path=='' and not origin.query and not origin.fragment
    assert context['consumer'] in ('android','windows','apple')
    assert Path(context['database']).is_file() and Path(context['database']).resolve()==owner/'gateway.sqlite'
    ready = json.loads((owner/'ready.json').read_text())
    assert ready['normal_qa_feature'] is False and ready['external_provider'] is False
    assert ready['base_url']==context['base_url'] and ready['sqlite']==context['database']
    driver_path = Path(__file__).with_name('normal_product_serve.py')
    spec = importlib.util.spec_from_file_location('normal_product_serve', driver_path)
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    started = time.time()
    observations = []
    namespace = uuid.uuid4().hex

    def submit(index, target_bytes=None):
        item,encoded = message_bytes(context,namespace,index,target_bytes,args.severity)
        before = time.monotonic()
        status,value = post_message_bytes(context,encoded)
        assert status==200 and value['success'] is True, (status,value.get('error_code'))
        message_id = value['data']['message_id']
        assert isinstance(message_id,str) and message_id
        return message_id,item,{'index':index,'message_id':message_id,
            'request_bytes':len(encoded),'elapsed_seconds':time.monotonic()-before}

    # Only one legal large message; the remaining setup cohort stays small.
    with ThreadPoolExecutor(max_workers=args.concurrency) as workers:
        submitted = list(workers.map(submit, range(args.rejected+args.healthy-1)))
    phase = sqlite3.connect('file:'+context['database']+'?mode=ro',uri=True)
    max_accepted = phase.execute('SELECT MAX(t.accepted_at) FROM ordinary_targets t '
        'JOIN ordinary_messages m ON m.delivery_id=t.delivery_id '
        'WHERE m.channel_id=? AND t.pull_owner=?',
        (context['channel_id'],context['device_key'])).fetchone()[0]
    phase.close()
    assert max_accepted is not None
    clock_fence_ms = next_acceptance_millisecond(max_accepted)
    large = submit(args.rejected+args.healthy-1,49152)
    submitted.append(large)
    too_large,too_large_bytes = message_bytes(context,namespace,args.rejected+args.healthy,49153,args.severity)
    rejected_status,rejected_response = post_message_bytes(context,too_large_bytes)
    assert rejected_status==400 and rejected_response.get('error_code')=='invalid_request_body'
    expected = {}
    for message_id,item,observation in submitted:
        assert message_id not in expected
        expected[message_id] = item
        observations.append(observation)
    connection = sqlite3.connect('file:'+context['database']+'?mode=ro', uri=True)
    connection.row_factory = sqlite3.Row
    rows = connection.execute('SELECT m.message_id,m.delivery_id,m.op_id,m.payload_blob, '
        't.accepted_at,t.pull_owner,t.delivery_mode,t.acked_at FROM ordinary_messages m '
        'JOIN ordinary_targets t ON t.delivery_id=m.delivery_id '
        'WHERE m.channel_id=? AND t.pull_owner=? ORDER BY t.accepted_at,t.delivery_id',
        (context['channel_id'],context['device_key'])).fetchall()
    rejected,healthy = choose_rows(rows, expected, args.rejected, context['device_key'])
    large_row = next(item for item in healthy if item['message_id']==large[0])
    assert large_row['request_bytes']==49152 and len(large_row['body'].encode())<49152
    absent = connection.execute('SELECT COUNT(*),(SELECT COUNT(*) FROM ordinary_targets t '
        'JOIN ordinary_messages m2 ON m2.delivery_id=t.delivery_id WHERE m2.op_id=?) '
        'FROM ordinary_messages WHERE op_id=?',
        (too_large['op_id'],too_large['op_id'])).fetchone()
    assert tuple(absent)==(0,0), 'oversized rejection cannot leave an identity or target'
    connection.close()
    boundary={'accepted_request_bytes':49152,'large_delivery_id':large_row['delivery_id'],
        'large_message_id':large_row['message_id'],'large_op_id':large_row['op_id'],
        'large_body_sha256':large_row['body_sha256'],'large_body_bytes':len(large_row['body'].encode()),
        'rejected_request_bytes':49153,'rejected_op_id':too_large['op_id'],
        'status':rejected_status,'error_code':rejected_response['error_code'],
        'identity_rows':0,'target_rows':0,'clock_fence_wait_ms':clock_fence_ms}

    # This read never ACKs and does not create a server cursor. It proves actual
    # native API ordering rather than guessing from producer call order or sleep.
    head = driver.post(context['base_url'],context['token'],'/v2/messages/pull',
        {'device_key':context['device_key']})
    verify_initial_head(head,rejected+healthy)
    payload_pages = 0
    if args.include_pull_payloads:
        payload_pages = attach_actual_pull_payloads(head,rejected+healthy,
            lambda token: driver.post(context['base_url'],context['token'],'/v2/messages/pull',
                {'device_key':context['device_key'],'page_token':token}),
            {row['delivery_id']:json.loads(row['payload_blob']) for row in rows})
    value = dict(context)
    value.update({'rejected':rejected,'healthy':healthy,
        'rejected_delivery_ids':[item['delivery_id'] for item in rejected],
        'fixture_kind':('normal API valid records; historical/foreign-owner conflicts injected ONLY in client local test store'
                        if args.rejected else 'normal API valid records; no historical-conflict role'),
        'population_concurrency':args.concurrency,'boundary':boundary,
        'requested_severity':args.severity,
        'ordering':'actual ordinary_targets(accepted_at,delivery_id); roles chosen after all durable acceptance',
        'server_fault_injection':False,'expected_total_messages':len(rows),
        'actual_pull_payload_pages':payload_pages,
        'generated_epoch':time.time()})
    driver.private_json(args.output,value)
    receipt = {'status':'PASS','context':str(args.output),'consumer':context['consumer'],
        'normal_product_binary_sha256':json.loads((Path(context['database']).parent/'ready.json').read_text())['binary_sha256'],
        'rejected':len(rejected),'healthy':len(healthy),'actual_head_count':len(head['items']),
        'population_seconds':time.time()-started,'http_setup_concurrency':args.concurrency,
        'requested_severity':args.severity,
        'population_is_not_a_load_or_capacity_measurement':True,'direct_server_sql_writes':0,
        'server_ack_calls':0,'boundary':boundary,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'actual_pull_payload_pages':payload_pages,
        'observations':observations}
    driver.private_json(args.output.with_suffix('.receipt.json'),receipt)
    print(json.dumps({'ready':True,'context':str(args.output),'rejected':len(rejected),'healthy':len(healthy)}))


if __name__ == '__main__':
    main()
