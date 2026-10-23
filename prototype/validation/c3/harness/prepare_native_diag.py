import ast, hashlib, json, pathlib, re, sqlite3
import argparse
p=argparse.ArgumentParser();p.add_argument('--out',required=True,type=pathlib.Path);p.add_argument('--store-source',required=True,type=pathlib.Path);a=p.parse_args();root=a.out.resolve()
root.mkdir(parents=True,exist_ok=False)
source=a.store_source.read_bytes()
(root/'store-source.rs').write_bytes(source)
s=source.decode(); schema=re.search(r'const SCHEMA:&str="(.*?)";',s,re.S).group(1)
(root/'schema.sql').write_text(schema)
def fn_sql(fn):
    start=s.index('async fn '+fn+'('); end=s.find('\n    ',s.index('\n    }',start)+6)
    # function body is delimited by the next method declaration
    nxt=re.search(r'\n    (?:pub(?:\([^)]*\))? )?async fn ',s[start+9:])
    body=s[start:start+9+nxt.start()] if nxt else s[start:]
    return [ast.literal_eval(x) for x in re.findall(r'sqlx::(?:query|query_scalar)\(("(?:[^"\\]|\\.)*")',body)]
ret=fn_sql('retire_token_targets_tx')[0]
rew=ret.replace('FROM targets t JOIN retired_provider_tokens r','FROM retired_provider_tokens r CROSS JOIN targets t')
coalesce="SELECT device_key FROM devices WHERE platform=? AND provider_token=? AND device_key<>? AND retired_at IS NULL"
maint=fn_sql('maintain_tx')
# Remove loop-body statements whose execution needs retired rows, keeping only actually executed empty-maintenance SQL.
maint=[q for q in maint if not q.startswith(('DELETE FROM channel_subscriptions','DELETE FROM devices WHERE device_key=?'))]
retgc=fn_sql('retire_token_targets_tx')[-1]
queries=[('retire_join',ret,[]),('retire_cross',rew,[]),('coalesce_lookup',coalesce,['android','none','winner']),('retire_gc',retgc,[])]+[(f'empty_maintenance_{i}',q,[1000]*q.count('?')) for i,q in enumerate(maint)]
for n in [10000,20000]:
    db=root/f'synthetic-{n}.sqlite'; con=sqlite3.connect(db)
    con.executescript(schema)
    con.execute('PRAGMA journal_mode=WAL');con.execute('PRAGMA synchronous=FULL');con.execute('PRAGMA foreign_keys=ON')
    with con:
        con.executemany('INSERT INTO devices(device_key,platform,provider,provider_token) VALUES(?,?,?,?)',[(f'd{i:06}','android','FCM',f't{i:06}') for i in range(n)])
        con.executemany('INSERT INTO messages(delivery_id,message_id,op_id,channel_id,fingerprint,payload_blob,payload_bytes,accepted_at,expires_at,dedupe_until,status,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',[(f'm{i:06}',f'msg{i}',f'op{i}','channel','fp',b'{}',2,1000,1000000,2000000,'provider_queued',1000) for i in range((n+31)//32)])
        con.executemany('INSERT INTO targets(delivery_id,device_key,platform,provider,provider_token,accepted_at,state,next_attempt_at) VALUES(?,?,?,?,?,?,?,?)',[(f'm{i//32:06}',f'd{i:06}','android','FCM',f't{i:06}',1000,'pending',1000) for i in range(n)])
    con.close()
    steps=[]
    for label,q,binds in queries:
        steps.append(dict(path='plan',label=label,sql='EXPLAIN QUERY PLAN '+q,binds=binds,capture_rows=True))
    for repeat in range(3):
        steps.extend([dict(path='measure',label=label,sql=q,binds=binds) for label,q,binds in queries])
    # An index control for the devices lookup; changes only disposable diagnostic DB.
    steps.append(dict(path='control',label='create_devices_index',sql='CREATE INDEX diagnostic_devices_token ON devices(platform,provider_token,device_key) WHERE retired_at IS NULL'))
    steps.append(dict(path='plan',label='coalesce_lookup_indexed',sql='EXPLAIN QUERY PLAN '+coalesce,binds=['android','none','winner'],capture_rows=True))
    for repeat in range(3): steps.append(dict(path='measure',label='coalesce_lookup_indexed',sql=coalesce,binds=['android','none','winner']))
    # Positive semantic oracle: one retired token selects one existing target; compare full rows.
    steps.append(dict(path='control',label='seed_one_retired',sql="INSERT INTO retired_provider_tokens VALUES('android','t000001',1)"))
    for label,q in [('retire_join_one',ret),('retire_cross_one',rew)]:
        steps.append(dict(path='plan',label=label,sql='EXPLAIN QUERY PLAN '+q,capture_rows=True))
        steps.append(dict(path='measure',label=label,sql=q,capture_rows=True))
    (root/f'steps-{n}.json').write_text(json.dumps(steps,indent=2))
(root/'provenance.json').write_text(json.dumps(dict(source_sha256=hashlib.sha256(source).hexdigest(),schema_sha256=hashlib.sha256(schema.encode()).hexdigest(),python_sqlite=sqlite3.sqlite_version,targets=[10000,20000],repeats=3,retired_initial=0,clock_at=1000,all_messages_unexpired=True,all_devices_active=True,claims='independent SQLite engine; not SQLx runtime evidence'),indent=2))
print(json.dumps(dict(source_sha256=hashlib.sha256(source).hexdigest(),queries=len(queries),root=str(root))))
