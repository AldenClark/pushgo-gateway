#!/usr/bin/env python3
"""Offline OS/resource summary of one C5 lane. No build, process, or DB operations."""
import argparse, collections, json, pathlib

def read(root,name):
    path=root/(name+'.jsonl')
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
def cpu_seconds(value):
    days,_,tail=value.partition('-')
    if not tail:tail=days;days='0'
    pieces=tail.split(':')
    return int(days)*86400+sum(float(v)*60**i for i,v in enumerate(reversed(pieces)))
def summarize(root):
    phases=read(root,'phases');rss=read(root,'rss');producer=read(root,'producer');snaps=read(root,'snapshots')
    markers={r['label']:r for r in phases};groups=collections.defaultdict(list)
    for row in rss:groups[row['phase']].append(row)
    gateway={phase:{'samples':len(values),'rss_min_bytes':min(v['proc_rss_bytes'] for v in values),
        'rss_peak_bytes':max(v['proc_rss_bytes'] for v in values),'rss_last_bytes':values[-1]['proc_rss_bytes'],
        'ps_lifetime_cpu_percent_peak':max(v['proc_cpu_percent'] for v in values)} for phase,values in groups.items()}
    def period(begin,end):
        if begin not in markers or end not in markers:return {'available':False}
        start,finish=markers[begin],markers[end];seconds=finish['elapsed']-start['elapsed']
        result={'available':True,'seconds':seconds,'http_observer_calls_in_idle':0}
        first=start.get('kernel');last=finish.get('kernel')
        if first and last:
            first=first['metrics'];last=last['metrics']
            for name in ('userCPU_ns','systemCPU_ns','interrupt_wakes','pkgIdle_wakes'):
                if first.get(name) is not None and last.get(name) is not None:result[name+'_delta']=last[name]-first[name]
            if all(name+'_delta' in result for name in ('userCPU_ns','systemCPU_ns')):
                result['average_cpu_percent_one_core']=100*(result['userCPU_ns_delta']+result['systemCPU_ns_delta'])/1e9/seconds
        return result
    import db_os_observer
    db_groups=collections.defaultdict(list)
    for row in read(root,'db-process'):db_groups[row['phase']].append(row)
    db_summary={}
    for phase,all_values in db_groups.items():
        values=[row for row in all_values if row.get('observation_status')=='AVAILABLE']
        item={'samples':len(all_values),'available_samples':len(values),
              'unavailable_samples':len(all_values)-len(values),
              'rss_scope':'namespace PID1 main engine process only; not cluster physical RAM',
              'cpu_scope':'coarse cumulative process TIME; only same captured container/start/init PID and observed PID/PPID/comm set; no undetected child PID reuse assumed'}
        if values:
            item.update(native_pid1_rss_first_bytes=values[0]['native_pid1']['rss_bytes'],
                native_pid1_rss_peak_sampled_bytes=max(row['native_pid1']['rss_bytes'] for row in values),
                native_pid1_rss_last_bytes=values[-1]['native_pid1']['rss_bytes'],
                first_elapsed=values[0]['elapsed'],last_elapsed=values[-1]['elapsed'])
        if len(values)>=2 and len(values)==len(all_values):
            transitions=[db_os_observer.cpu_delta(old,new,new['elapsed']-old['elapsed'])
                         for old,new in zip(values,values[1:])]
            if all(delta['available'] for delta in transitions):
                item['cpu']=db_os_observer.cpu_delta(values[0],values[-1],values[-1]['elapsed']-values[0]['elapsed'])
            else:item['cpu']={'available':False,'reason':'PID/counter/owner identity changed within phase',
                              'unavailable_transitions':[r for r in transitions if not r['available']]}
        else:item['cpu']={'available':False,'reason':'missing/failed OS samples or no two-point interval'}
        db_summary[phase]=item
    return {'scope':'owned Gateway OS metrics and distinct pinned database engine process metrics; synthetic local lane',
        'gateway_by_phase':gateway,
        'cold_idle':period('cold-idle-start','cold-idle-end'),
        'post_ack_idle':period('post-ack-idle-start','post-ack-idle-end'),
        'burst_to_provider_commit':period('offer-start','provider-commit-complete'),
        'tail_drain_seconds':markers['provider-commit-complete']['elapsed']-markers['offer-end']['elapsed'] if all(k in markers for k in ('offer-end','provider-commit-complete')) else None,
        'producer_queue_peak':max((r['queued'] for r in producer),default=None),
        'http_inflight_peak':max((r['inflight'] for r in producer),default=None),
        'durable_nonterminal_peak':max((r['durable_nonterminal'] for r in snaps),default=None),
        'db_engine_by_phase':db_summary,'db_connection_snapshots':read(root,'db-connections'),
        'limitations':['Gateway fixture owns unchanged once-per-second stats heartbeat; included in idle cost',
            'Only native namespace PID1 RSS is reported; it omits PG backend mappings and is not whole-cluster physical RAM; humanized top RSS is never parsed',
            'Database connection samples are labeled boundary snapshots, not a peak connection assertion',
            'Gateway ps percent CPU is a lifetime estimate; DB CPU uses supported per-process cumulative TIME with whole-second precision and PID churn guards',
            'Interrupt/package-idle wake counters are specific kernel counters, not all process wakeups',
            'Counters.sql is nominal charging, not an engine SQL/trigger operation total',
            'MySQL acquire may include owner RPC whereas PostgreSQL acquire includes its mutex; phases are not equivalent work']}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('run',type=pathlib.Path)
    print(json.dumps(summarize(parser.parse_args().run),indent=2))
