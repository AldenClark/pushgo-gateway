import ast,json,pathlib,re,sqlite3
import argparse
p=argparse.ArgumentParser();p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args();root=a.out.resolve();s=(root/'store-source.rs').read_text()
def sqls(fn):
 start=s.index('async fn '+fn+'(');nxt=re.search(r'\n    (?:pub(?:\([^)]*\))? )?async fn ',s[start+9:]);body=s[start:start+9+nxt.start()]
 return [ast.literal_eval(x) for x in re.findall(r'sqlx::(?:query|query_scalar)\(("(?:[^"\\]|\\.)*")',body)]
ret=sqls('retire_token_targets_tx')[0];cross=ret.replace('FROM targets t JOIN retired_provider_tokens r','FROM retired_provider_tokens r CROSS JOIN targets t')
clean=[q for q in sqls('maintain_tx') if q.startswith('DELETE FROM devices WHERE device_key IN')][0]
co=sqls('coalesce_owners_tx');winner='d005000';binds=[[winner,'android','shared',winner],[winner,winner,'android','shared',winner],['android','shared',winner],[1000,winner,'android','shared',winner]]
con=sqlite3.connect(root/'synthetic-10000.sqlite');dest=sqlite3.connect(root/'semantics.sqlite');con.backup(dest);con.close()
with dest:
 dest.execute('DROP INDEX diagnostic_devices_token');dest.execute('DROP INDEX diagnostic_devices_coalesced');dest.execute('DELETE FROM retired_provider_tokens')
 dest.execute("UPDATE targets SET provider_token='bulk' WHERE device_key<'d005000'")
dest.close()
steps=[]
def add(path,label,sql,binds=None,capture=False):steps.append(dict(path=path,label=label,sql=sql,binds=binds or [],capture_rows=capture))
def pair(name,setup):
 add('control',name+'_save','SAVEPOINT compare')
 for i,q in enumerate(setup):add('control',name+'_seed'+str(i),q)
 add('semantics',name+'_original',ret,capture=True);add('semantics',name+'_cross',cross,capture=True)
 add('control',name+'_rollback','ROLLBACK TO compare');add('control',name+'_release','RELEASE compare')
pair('empty',[])
pair('all_targets_future_epoch',["UPDATE targets SET control_epoch=2", "INSERT INTO retired_provider_tokens VALUES('android','bulk',1)"])
pair('one_marker_many_old_and_future',["UPDATE targets SET control_epoch=2 WHERE device_key>='d002500' AND device_key<'d005000'", "INSERT INTO retired_provider_tokens VALUES('android','bulk',1)"])
pair('multiple_markers',["UPDATE targets SET control_epoch=2 WHERE device_key<'d004900'", "INSERT INTO retired_provider_tokens VALUES('android','bulk',1),('android','t005001',1),('android','t005002',0),('android','missing',99)"])
# Source cleanup predicate is preserved exactly. Include an inconsistent retired_at=NULL/coalesced_to!=NULL orphan to disprove adding retired_at condition as an equivalent SQL rewrite.
for indexed in [False,True]:
 name='cleanup_indexed' if indexed else 'cleanup_original';add('control',name+'_save','SAVEPOINT compare')
 if indexed:add('control',name+'_index','CREATE INDEX diagnostic_devices_coalesced_key ON devices(device_key) WHERE coalesced_to IS NOT NULL')
 for i,q in enumerate(["INSERT INTO devices(device_key,platform,retired_at,coalesced_to) VALUES('orphan','android',1000,'winner'),('orphan_null_retired','android',NULL,'winner')", "UPDATE devices SET retired_at=1000,coalesced_to='winner' WHERE device_key IN ('d000000','d000001')", "DELETE FROM targets WHERE device_key='d000001'", "UPDATE targets SET pull_owner='d000001' WHERE device_key='d000002'", "UPDATE targets SET pull_owner='winner' WHERE device_key='d000000'"]):add('control',name+'_seed'+str(i),q)
 add('plan',name,'EXPLAIN QUERY PLAN '+clean,capture=True)
 add('semantics',name,clean+' RETURNING device_key',capture=True)
 add('semantics',name+'_retained',"SELECT device_key FROM devices WHERE coalesced_to IS NOT NULL ORDER BY device_key",capture=True)
 add('control',name+'_rollback','ROLLBACK TO compare');add('control',name+'_release','RELEASE compare')
# Full source four-statement coalesce in a savepoint: overlap subscription + old target transfer + retired-owner changes.
for indexed in [False,True]:
 name='union_indexed' if indexed else 'union_original';add('control',name+'_save','SAVEPOINT compare')
 if indexed:add('control',name+'_index','CREATE INDEX diagnostic_devices_token ON devices(platform,provider_token,device_key) WHERE retired_at IS NULL')
 for i,q in enumerate(["INSERT INTO channels VALUES('c0','c0','synthetic'),('c1','c1','synthetic'),('c2','c2','synthetic')", "UPDATE devices SET provider_token='shared' WHERE device_key IN ('d000000','d000001','d005000')", "INSERT INTO channel_subscriptions VALUES('c0','d005000'),('c0','d000000'),('c1','d000000'),('c2','d000001')"]):add('control',name+'_seed'+str(i),q)
 for i,(q,b) in enumerate(zip(co,binds)):add('semantics',name+'_source'+str(i),q,b)
 add('semantics',name+'_subscriptions',"SELECT channel_id,device_key FROM channel_subscriptions ORDER BY channel_id,device_key",capture=True)
 add('semantics',name+'_owners',"SELECT device_key,pull_owner,owner_generation FROM targets WHERE device_key IN ('d000000','d000001') ORDER BY device_key",capture=True)
 add('semantics',name+'_devices',"SELECT device_key,retired_at,coalesced_to FROM devices WHERE device_key IN ('d000000','d000001','d005000') ORDER BY device_key",capture=True)
 add('control',name+'_rollback','ROLLBACK TO compare');add('control',name+'_release','RELEASE compare')
(root/'steps-semantics.json').write_text(json.dumps(steps,indent=2))
