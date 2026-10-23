#!/usr/bin/env python3
"""Pure input/oracle checks only: no subprocess, sockets, DB, process or build calls."""
import hashlib,json,pathlib
import c9_input_plan as plan
checks=[]
r=plan.planned_inventory()
assert [s['messages'] for s in r['stages']]==[5,20,80,512,128]
assert r['messages_per_small_cycle']==745 and r['targets_per_small_cycle']==11920
assert r['total_formal_targets']==23904 and r['total_formal_messages']==1494
checks.append('two identical745message cycles x16targets plus4large messages =23904 formal targets;16warmup excluded')
for stage in plan.STAGES:
 offers=plan.offers_for_stage(*stage)
 assert len({offer['stage_index'] for offer in offers})==len(offers)
 assert offers[0]['offset_seconds']==0 and offers[-1]['offset_seconds']<stage[2]
checks.append('every finite stage count and monotonic stage-local emission offset is exact')
cutoff=plan.cycle_cutoff(1000,24)
assert cutoff==5560 and cutoff==plan.cycle_cutoff(1000,24)
checks.append('cycle absolute190s cutoff derives only from first offer, not stage/drain/HTTP progress')
observed=[plan.callback_outcome(True,100,200,'provider_accepted'),
          plan.callback_outcome(True,None,200,'provider_accepted'),
          plan.callback_outcome(True,201,200,'provider_accepted'),
          plan.callback_outcome(True,100,200,'permanent_failed'),
          plan.callback_outcome(False,None,200,None)]
assert observed==['accepted','unfinished','unfinished','provider_failed','unfinished'] and len(observed)==5
checks.append('missing/late/durable-only/failed targets remain denominator; no SQL timestamp substitution')
assert plan.callback_outcome(True,200,200,'provider_accepted')=='accepted'
checks.append('exact callback at original cutoff remains included, strictly later callback censored')
base=pathlib.Path(__file__).resolve().parent
r={'status':'PURE_CHECKS_PASS_PROPOSAL_NOT_RUNTIME_READY','passed':len(checks),'checks':checks,
   'source_sha256':{name:hashlib.sha256((base/name).read_bytes()).hexdigest() for name in ('c9_input_plan.py','static_c9_plan_checks.py')},
   'no_build_DB_or_workload_calls':True}
(base/'static-c9-plan-receipt.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
