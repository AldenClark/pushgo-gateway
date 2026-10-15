#!/usr/bin/env python3
"""Offline conversion of owned metadata boundary receipts; no queries."""
import json,pathlib,sys
run=pathlib.Path(sys.argv[1]);items=[]
def numeric(text):
 result={}
 for l in text.splitlines():
  p=l.split()
  if len(p)==2:
   try:result[p[0]]=int(p[1])
   except ValueError:pass
 return result
for l in (run/'harness.jsonl').open():
 r=json.loads(l)
 if r['kind']!='component_metadata_boundary':continue
 ref=json.loads(r['receipt_stdout']);p=pathlib.Path(ref['receipt']);m=json.loads(p.read_text());d=m['resources']['database_container'];cpu=numeric(d['cpu_stat_cumulative_usec']);mem=numeric(d['memory_stat_cache_breakdown']);global_=numeric(m['engine_global_numeric_baseline_cumulative'])
 items.append({'label':r['label'],'receipt':str(p),'receipt_sha256':ref['sha256'],'observer_seconds':m['observer_elapsed_seconds'],'DB_cgroup_CPU_cumulative_usec':cpu,'DB_cgroup_memory_current_bytes':int(d['memory_current_bytes']),'DB_cgroup_anon_bytes':mem.get('anon'),'DB_cgroup_filecache_bytes':mem.get('file'),'DB_global_numeric_cumulative':global_,'case_digest_rows':len(m['new_case_digest_numeric']),'case_digests':m['new_case_digest_numeric'],'coverage':m['digest_loss_note']})
a,b=items[0],items[-1];out={'scope':'OS/container and database metadata capture boundaries, outside idle bodies; whole existing server/cache, not perconnection or Gateway memory; CPU cgroup includes exec observers; numerical digests no statement-name mapping and prepared coverage not established','boundaries':items,'DB_cgroup_CPU_seconds_boundary_delta':(b['DB_cgroup_CPU_cumulative_usec']['usage_usec']-a['DB_cgroup_CPU_cumulative_usec']['usage_usec'])/1e6,'DB_global_numeric_boundary_delta':{k:b['DB_global_numeric_cumulative'][k]-v for k,v in a['DB_global_numeric_cumulative'].items() if k in b['DB_global_numeric_cumulative'] and k not in ('Threads_connected','Threads_running')},'observer_boundary_seconds_sum':sum(x['observer_seconds'] for x in items),'engine_statement_total_from_digests':'NOT_IDENTIFIED: no evidence of complete prepared/digest cache coverage; unknown/eviction not zero'}
p=run/'component-metadata-summary.json';assert not p.exists();p.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({k:v for k,v in out.items() if k!='boundaries'},indent=2))
