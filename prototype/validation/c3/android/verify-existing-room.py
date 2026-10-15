#!/usr/bin/env python3
"""Read already-exported standalone closed Room main files; never rerun native work."""
import argparse,hashlib,json,pathlib,sqlite3
p=argparse.ArgumentParser();p.add_argument('run',type=pathlib.Path);a=p.parse_args();run=a.run.resolve()
session=json.loads((run/'native/session.json').read_text())
captures=[json.loads(v)for v in (run/'mock/captures.jsonl').read_text().splitlines()]
expected={'c3-during-sync':'c3-during-sync-content','c3-direct':'c3-direct-content','c3-oversized':'c3-oversized-'+'x'*7000,'c3-unavailable':'c3-unavailable-content','c3-unknown':'c3-unknown-ack-content','c3-before-logout':'c3-before-logout-content'}
observed={}
for label,expected_count in [('before',5),('after',6)]:
 path=run/f'native/room-{label}-restart.sqlite'
 with sqlite3.connect(f'file:{path}?mode=ro&immutable=1',uri=True)as c:
  c.row_factory=sqlite3.Row
  assert c.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
  rows=[dict(v)for v in c.execute('SELECT * FROM messages')]
  assert len(rows)==expected_count
  summary=[]
  for row in rows:
   raw=json.loads(row['raw_payload_json']);delivery=raw['delivery_id'];title=row['title']
   assert row['body']==expected[title]
   capture=next(v for v in captures if v['delivery_id']==delivery)
   assert capture['token']==session['provider_token']
   if title!='c3-oversized':
    assert capture['data']['body']==row['body'] and capture['data']['title']==title
    assert capture['data']['message_id']==row['message_id']
   else:assert capture['data']['provider_wakeup']=='1'
   assert raw['message_id']==row['message_id'] and raw['channel_id']==session['channel_id']
   ledger=c.execute('SELECT * FROM inbound_delivery_ledger WHERE delivery_id=?',(delivery,)).fetchone();assert ledger
   assert ledger['device_key']==session['device_key'] and ledger['entity_id']==row['message_id']
   state='pending'if label=='before'and delivery==session['unknown_delivery_id']else'acked'
   assert ledger['ack_state']==state
   summary.append({'delivery_id':delivery,'message_id':row['message_id'],'title':title,'body_sha256':hashlib.sha256(row['body'].encode()).hexdigest(),'body_length':len(row['body']),'ack_state':state,'exact_capture_sequence':capture['sequence']})
  outbox=[dict(v)for v in c.execute('SELECT * FROM inbound_delivery_ack_outbox')]
  assert len(outbox)==(1 if label=='before' else 0)
  if outbox:assert outbox[0]['delivery_id']==session['unknown_delivery_id']and outbox[0]['last_attempt_uncertain']==1
  observed[label]={'main_file_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'canonical_count':len(rows),'outbox':outbox,'exact_rows':summary}
result={'status':'PASSED for exact observed copied-main rows','native_reexecuted':False,'primary_recovery_evidence':'phase2 actually opens the original Android Room database in a distinct PID before recovery calls','copy_boundary':'run-native copies main DB after successful instrumentation completion and @After network.close();db.close(); then explicit package force-stop before before-copy. after-copy also follows completed @After db.close().','explicit_checkpoint_or_sqlite_backup':False,'native_WAL_or_SHM_exported':False,'limitation':'This does not establish arbitrary live WAL snapshot completeness. immutable=1 reads only each closed copied main file. Exact latest canonical rows, immutable delivery/message identities, titles, full bodies, ledger pending/acked states and outbox 1->0 are independently present in those main files and match real captures/native assertions.','observations':observed}
(run/'native-main-copy-qualification.json').write_text(json.dumps(result,indent=2)+'\n')
print('exact copied-main delivery/title/body/ledger/outbox qualification PASS')
