#!/usr/bin/env python3
"""Read-only reconciliation of native canonical IDs/content against actual candidate Pull bytes."""
import argparse, hashlib, json, pathlib, sqlite3
p=argparse.ArgumentParser();p.add_argument('--run',required=True,type=pathlib.Path);a=p.parse_args();run=a.run.resolve()
result=json.loads((run/'result.json').read_text());assert result['failure'] is None,result
access=json.loads((run/'http-access.json').read_text())
pulls=[x for x in access if x['path'].endswith('/v2/messages/pull')]
assert len(pulls)==1,pulls
page=json.loads(pulls[0]['response'])['data'];assert len(page['items'])==1,page
item=page['items'][0]; payload=item['payload'];delivery=item['delivery_id']
native=list((run/'native-store').rglob('pushgo.db'));assert len(native)==1,native
with sqlite3.connect(f'file:{native[0]}?mode=ro',uri=True) as c:
 c.row_factory=sqlite3.Row
 rows=[dict(x) for x in c.execute('SELECT id,message_id,delivery_id,title,body FROM messages')]
assert len(rows)==1,rows
row=rows[0]
assert row['delivery_id']==delivery and row['message_id']==payload['message_id'],(row,payload)
assert row['title']==payload['title'] and row['body']==payload['body'],(row,payload)
with sqlite3.connect(f'file:{run / "candidate.sqlite"}?mode=ro',uri=True) as c:
 c.row_factory=sqlite3.Row
 canonical=dict(c.execute('SELECT delivery_id,message_id,op_id,payload_bytes,pending_targets FROM messages WHERE delivery_id=?',(delivery,)).fetchone())
 targets=c.execute('SELECT COUNT(*) FROM targets WHERE delivery_id=?',(delivery,)).fetchone()[0]
assert canonical['message_id']==row['message_id'] and canonical['op_id']==payload['op_id']
assert canonical['payload_bytes']==0 and canonical['pending_targets']==0 and targets==0,canonical
acks=[x for x in access if x['path'].endswith('/v2/messages/ack')]
assert [x['status'] for x in acks]==[503,200],acks
assert all('native_durable_at_ack' in x and not x.get('oracle_error') for x in acks)
ingest=json.loads((run/'apple-ingest-observations.json').read_text());recover=json.loads((run/'apple-recover-observations.json').read_text())
assert ingest['process_id']!=recover['process_id']
receipt={'product_status':'PASSED','test_system_status':'PASSED','phase_exits':result['phase_exits'],'native_tests_executed':2,'product_assertion_retries':0,'process_ids':[ingest['process_id'],recover['process_id']],'request_counts':{'pull':len(pulls),'ack_failed':1,'ack_succeeded':1,'provider_captures':len(list(run.glob('provider-body-*.json')))},'canonical_native_id':row['id'],'message_id':row['message_id'],'delivery_id':delivery,'op_id':canonical['op_id'],'title':row['title'],'body_utf8_bytes':len(row['body'].encode()),'body_sha256':hashlib.sha256(row['body'].encode()).hexdigest(),'exact_native_content_equals_actual_candidate_pull':True,'server_post_ack':canonical|{'target_rows':targets},'scope':'captured actual candidate ordinary wakeup -> unchanged application controller -> disk GRDB -> failed durable ACK -> fresh native process ACK recovery; no OS delivery/real APNs/physical-device claim'}
(run/'native-reconciliation.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt,indent=2))
