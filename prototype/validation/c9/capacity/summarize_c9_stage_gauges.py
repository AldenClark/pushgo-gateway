#!/usr/bin/env python3
"""Offline phase alignment, observed gauge peaks and exact activity counts; no probes."""
import json,pathlib,statistics,struct,sys
p=pathlib.Path(sys.argv[1])
def read(name):
 with (p/name).open() as f:
  for l in f:
   if l.startswith('{'):yield json.loads(l)
phases=list(read('phases.jsonl'));offers=list(read('offers.jsonl'));req=list(read('requests.jsonl'));prod=list(read('producer.jsonl'));snap=list(read('snapshots.jsonl'));conn=list(read('db-connections.jsonl'));db=list(read('db-process.jsonl'));stats=[x for x in read('gateway.log') if x.get('kind')=='stats'];m=json.loads((p/'telemetry.json').read_text());scale=m['mach_numer']/m['mach_denom']/1e9;offset=statistics.median(x['unix_ns']/1e6-x['elapsed']*1000 for x in db if 'unix_ns'in x)
for s in stats:s['elapsed']=(s['unix_ms']-offset)/1000
expected={(x['delivery_id'],x['device_key']):x for x in read('expected-targets.jsonl')};commits=[];R=struct.Struct('<QQQ32s32sB7x')
with (p/'commits.bin').open('rb') as f:
 while raw:=f.read(96):
  t,_,_,d,k,state=R.unpack(raw)
  if (d.decode(),k.decode()) in expected:commits.append((t,state))
def peak(values):return max(values) if values else None
def gauge(s,key):
 v=s.get(key);return sum(v) if isinstance(v,list) else v
out=[]
for i,a in enumerate(phases):
 if not a['label'].endswith('-start'):continue
 stem=a['label'][:-6];end=next((b for b in phases[i+1:] if b['label']==stem+'-end'),None)
 if end is None:continue
 lo,hi=a['elapsed'],end['elapsed'];ss=[x for x in stats if lo<=x['elapsed']<=hi];pp=[x for x in prod if lo<=x['elapsed']<=hi];qq=[x for x in snap if lo<=x['elapsed']<=hi];cc=[x for x in conn if lo<=x['elapsed']<=hi];cpu_a=a['kernel']['metrics'];cpu_b=end['kernel']['metrics'];clocklo,clockhi=a['mach_ticks'],end['mach_ticks']
 row={'phase':stem,'elapsed_start':lo,'elapsed_end':hi,'seconds':hi-lo,'actual_offered_messages':sum(clocklo<=x['offer_mach_ticks']<clockhi for x in offers),'HTTP_success_responses':sum(x['path']=='/message' and x['label']!='c5:capacity:-1' and x['status']==200 and not x['error'] and clocklo<=x['http_end_mach_ticks']<clockhi for x in req),'target_in_window_COMMIT_events':sum(clocklo<=t<clockhi and state==1 for t,state in commits),'Gateway_CPU_seconds':(cpu_b['userCPU_ns']+cpu_b['systemCPU_ns']-cpu_a['userCPU_ns']-cpu_a['systemCPU_ns'])/1e9,'Gateway_RSS_start_end_bytes':[cpu_a['RSSbytes'],cpu_b['RSSbytes']],'producer_main_thread_CPU_seconds':(end['producer_main_thread_CPU_ns']-a['producer_main_thread_CPU_ns'])/1e9,'sampled_gauge_peaks':{key:peak([gauge(s,key) for s in ss if gauge(s,key)is not None]) for key in ('provider_owned','owned_attempts','network_inflight','receipts_owned','claim_reservations','provider_targets','tasks','num_alive','http_connections')},'Gateway_gauge_samples':len(ss),'producer_queue_peak_excludes_inflight':peak([x['queued'] for x in pp]),'producer_inflight_peak':peak([x['inflight'] for x in pp]),'oldest_queued_offer_age_ms_peak':peak([x['oldest_queued_offer_age_ms'] for x in pp if x['oldest_queued_offer_age_ms'] is not None]),'durable_backlog_peak_sampled':peak([x['durable_nonterminal'] for x in qq]),'oldest_durable_age_ms_peak_wall_observed':peak([x['oldest_durable_age_ms_wall_observed'] for x in qq if x.get('oldest_durable_age_ms_wall_observed')is not None]),'physical_connections_boundary_samples':cc,'missing_semantics':'null means no applicable sample, not zero; 1Hz Gateway gauges can miss subsecond peaks. Connection samples are explicit boundaries, not continuous stage maxima.'}
 out.append(row)
last=stats[-1];result={'scope':'Activity counts use exact Mach phase markers; async target events during stage may belong to prior offered cohort. Per-cohort latency in baseline-offline-summary.json. Gauge STATS aligned via median recorded OS observer wall/elapsed offset, finite1Hz; not exact concurrency trace.','phases':out,'global_cumulative_peak_gauges':{k:last.get(k) for k in ('peak_claim_reservations','peak_owned_attempts','peak_network_inflight','peak_receipts_owned','peak_http_connections')},'all_connection_boundary_receipts':conn,'definitions':{'provider_targets':'budget32 per activeProvider, not actualrequest/worker count','owned_attempts':'actual attempt ownership, distinct from receipts_owned andclaimreservation','num_alive':'two pump lifetime gauge, not worker count','task':'allTokio tasks, not active heapobjects','HTTP_success_responses':'client read/JSON parse completion; not DB-admission COMMIT timestamp','database_accept_COMMIT_per_message':'NOT_MEASURED as exact Mach points; admission timings and1Hz aggregate counts only','backlog':'durable SQL nonterminal excludes externaloffer queue; offered-minus-COMMIT rates include all formaloffers','oldest':'SQL persistedaccepted_at to observerwall includes query/staleness anddifferentclock; not exact offerlatency'}}
q=p/'stage-gauges-and-activity.json';assert not q.exists();q.write_text(json.dumps(result,indent=2)+'\n');print(q)
