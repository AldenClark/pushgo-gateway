#!/usr/bin/env python3
"""Pure C9 proposal, not a runtime authorization or DB/HTTP driver."""
from fractions import Fraction

FANOUT=16
CYCLES=2
CYCLE_DEADLINE_SECONDS=190
IDLE_SECONDS=120
# Offset is local to a stage. The pre-slow drain barrier never resets the cycle cutoff.
STAGES=(
    ('low',Fraction(1,4),20,20),
    ('ramp_4',Fraction(4),5,20),
    ('ramp_16',Fraction(16),30,20),
    ('burst_256',Fraction(256),2,20),
    ('slow_provider',Fraction(16),8,500),
)

def offers_for_stage(name,rate,seconds,provider_delay_ms):
    count=rate*seconds
    assert count.denominator==1
    return [{'stage':name,'stage_index':index,'offset_seconds':float(Fraction(index,1)/rate),
             'provider_delay_ms':provider_delay_ms} for index in range(count.numerator)]

def planned_inventory():
    stages=[{'name':name,'rate_messages_s':float(rate),'seconds':seconds,
             'messages':len(offers_for_stage(name,rate,seconds,delay)),
             'provider_delay_ms':delay} for name,rate,seconds,delay in STAGES]
    messages=sum(stage['messages'] for stage in stages)
    return {'small_cycles':CYCLES,'stages':stages,'messages_per_small_cycle':messages,
            'targets_per_small_cycle':messages*FANOUT,'large_messages':4,'large_complete_JSON_bytes':49152,
            'large_targets':4*FANOUT,'total_formal_messages':messages*CYCLES+4,
            'total_formal_targets':messages*CYCLES*FANOUT+4*FANOUT,
            'warmup_targets_excluded':16,'cycle_absolute_cutoff_seconds':CYCLE_DEADLINE_SECONDS}

def callback_outcome(http_ok,callback_ticks,cutoff_ticks,durable_state):
    # SQL-visible provider_accepted cannot substitute for a missing/late callback timestamp.
    if callback_ticks is None or callback_ticks>cutoff_ticks:
        return 'unfinished'
    if durable_state=='provider_accepted':return 'accepted'
    if durable_state in ('permanent_failed','expired','cancelled'):return 'provider_failed'
    return 'unfinished'

def cycle_cutoff(first_offer_ticks,ticks_per_second):
    return first_offer_ticks+CYCLE_DEADLINE_SECONDS*ticks_per_second
