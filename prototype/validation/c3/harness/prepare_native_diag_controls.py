import ast,json,pathlib,re
import argparse
p=argparse.ArgumentParser();p.add_argument('--out',required=True,type=pathlib.Path);a=p.parse_args();root=a.out.resolve();s=(root/'store-source.rs').read_text()
def fn_sql(fn):
 start=s.index('async fn '+fn+'(');nxt=re.search(r'\n    (?:pub(?:\([^)]*\))? )?async fn ',s[start+9:]);body=s[start:start+9+nxt.start()]
 return [ast.literal_eval(x) for x in re.findall(r'sqlx::(?:query|query_scalar)\(("(?:[^"\\]|\\.)*")',body)]
co=fn_sql('coalesce_owners_tx');binds=[['winner','android','none','winner'],['winner','winner','android','none','winner'],['android','none','winner'],[1000,'winner','android','none','winner']]
cleanup=[q for q in fn_sql('maintain_tx') if q.startswith('DELETE FROM devices WHERE device_key IN')][0]
ret=fn_sql('retire_token_targets_tx')[0];cross=ret.replace('FROM targets t JOIN retired_provider_tokens r','FROM retired_provider_tokens r CROSS JOIN targets t')
steps=[dict(path='control',label='drop_diag_index',sql='DROP INDEX diagnostic_devices_token')]
queries=[(f'coalesce_actual_{i}',q,b) for i,(q,b) in enumerate(zip(co,binds))]+[('coalesced_cleanup',cleanup,[])]
for label,q,b in queries:steps.append(dict(path='plan',label=label,sql='EXPLAIN QUERY PLAN '+q,binds=b,capture_rows=True))
for repeat in range(3):steps.extend(dict(path='measure',label=label,sql=q,binds=b) for label,q,b in queries)
steps.extend([dict(path='control',label='devices_token_index',sql='CREATE INDEX diagnostic_devices_token ON devices(platform,provider_token,device_key) WHERE retired_at IS NULL'),dict(path='control',label='devices_coalesced_index',sql='CREATE INDEX diagnostic_devices_coalesced ON devices(coalesced_to,device_key) WHERE coalesced_to IS NOT NULL')])
for label,q,b in queries:steps.append(dict(path='plan',label=label+'_indexed',sql='EXPLAIN QUERY PLAN '+q,binds=b,capture_rows=True))
for repeat in range(3):steps.extend(dict(path='measure',label=label+'_indexed',sql=q,binds=b) for label,q,b in queries)
steps.append(dict(path='control',label='seed_512_retired',sql="INSERT OR REPLACE INTO retired_provider_tokens SELECT platform,provider_token,1 FROM targets WHERE device_key<'d000512'"))
steps.extend([dict(path='positive',label='retire_join_limit256',sql=ret,capture_rows=True),dict(path='positive',label='retire_cross_limit256',sql=cross,capture_rows=True)])
(root/'steps-controls.json').write_text(json.dumps(steps,indent=2))
