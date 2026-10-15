#!/usr/bin/env python3
"""OS-only database observer. No SQL, Gateway HTTP, or container lifecycle calls."""
import re,subprocess,time

def parse_native_status(engine,text):
    lines=text.splitlines();expected={'pg':'postgres','mysql':'mysqld'}[engine]
    if not lines or lines[0]!=expected:raise ValueError('namespace PID1 is not expected database engine')
    match=re.search(r'^VmRSS:\s+(\d+)\s+kB\s*$',text,re.M)
    if not match:raise ValueError('native VmRSS kB unavailable')
    # Linux /proc status uses 1024-byte kB. No humanized top RSS conversion.
    return {'namespace_pid':1,'comm':expected,'VmRSS_kB':int(match[1]),
            'rss_bytes':int(match[1])*1024,'scope':'namespace PID1 main engine process RSS; not cluster physical RAM'}

def parse_time(text):
    # BusyBox supported cumulative CPU TIME. Unrecognized humanized values fail closed.
    if not re.fullmatch(r'(?:\d+-)?\d+:\d\d(?::\d\d)?',text):
        raise ValueError('unsupported coarse process time: '+text)
    days,separator,clock=text.partition('-')
    if not separator:clock=days;days='0'
    return int(days)*86400+sum(int(value)*60**power for power,value in enumerate(reversed(clock.split(':'))))

def parse_top(engine,text):
    expected={'pg':'postgres','mysql':'mysqld'}[engine];rows=[]
    for line in text.splitlines()[1:]:
        fields=line.split()
        if len(fields)!=4:raise ValueError('unexpected supported Docker top shape')
        pid,ppid,comm,cpu=fields
        if comm!=expected:continue
        rows.append({'vm_host_pid':int(pid),'vm_host_ppid':int(ppid),'comm':comm,
                     'cpu_seconds_coarse':parse_time(cpu)})
    if not rows:raise ValueError('database engine process unavailable in top')
    return rows

def observe(helper,engine):
    state,inspect=helper.owned(engine)  # Full captured ID + label + name guard each sample.
    native=subprocess.run(helper.D+['exec',state['id'],'cat','/proc/1/comm','/proc/1/status'],
                          capture_output=True,text=True,timeout=5)
    if native.returncode:raise RuntimeError('native /proc observer failed: '+native.stderr)
    top=subprocess.run(helper.D+['top',state['id'],'-eo','pid,ppid,comm,time'],
                       capture_output=True,text=True,timeout=5)
    if top.returncode:raise RuntimeError('supported top observer failed: '+top.stderr)
    return {'unix_ns':time.time_ns(),'container_id':state['id'],
            'container_started_at':inspect['State']['StartedAt'],'container_init_vm_host_pid':inspect['State']['Pid'],
            'native_pid1':parse_native_status(engine,native.stdout),'engine_processes':parse_top(engine,top.stdout),
            'raw_native_status':native.stdout,'raw_top':top.stdout,
            'cpu_resolution':'whole seconds; process TIME delta, not ps pcpu or per-connection CPU',
            'rss_resolution':'Linux /proc VmRSS kB * 1024; main process only; do not sum PostgreSQL shared RSS'}

def cpu_delta(first,last,wall_seconds):
    if any(first[k]!=last[k] for k in ('container_id','container_started_at','container_init_vm_host_pid')):
        return {'available':False,'reason':'container restart/init PID changed'}
    a={r['vm_host_pid']:r for r in first['engine_processes']};b={r['vm_host_pid']:r for r in last['engine_processes']}
    if set(a)!=set(b):return {'available':False,'reason':'PID churn; total engine CPU not identified'}
    total=0
    for pid,old in a.items():
        new=b[pid]
        if (old['vm_host_ppid'],old['comm'])!=(new['vm_host_ppid'],new['comm']):
            return {'available':False,'reason':'process identity changed'}
        delta=new['cpu_seconds_coarse']-old['cpu_seconds_coarse']
        if delta<0:return {'available':False,'reason':'CPU counter reset'}
        total+=delta
    return {'available':True,'cpu_seconds_coarse_delta':total,
            'average_one_core_percent_coarse':100*total/wall_seconds if wall_seconds>0 else None,
            'processes':len(a),'endpoint_quantization_error_seconds_bound':2*len(a),
            'scope':'same captured container/start/init PID and identical observed PID/PPID/comm set; assumes no undetected child PID reuse; disappeared processes not reconstructed'}
