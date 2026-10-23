#!/usr/bin/env python3
"""Sanitized host load observation. Never requests args, command lines or env."""
import os,pathlib,subprocess
TOOLS={'cargo','rustc','swift-frontend','swiftc','clang','ld','java','gradle','emulator','qemu-system-aarch64','c5-observer','c6-observer','free_architecture_fixture'}
def parse(text,owned):
    rows=[]
    for line in text.splitlines():
        fields=line.split(None,5)
        if len(fields)!=6:continue
        pid,ppid,cpu,rss,cpu_time,comm=fields;pid=int(pid);ppid=int(ppid);cpu=float(cpu)
        name=pathlib.Path(comm).name
        if name not in TOOLS and cpu<5:continue
        rows.append({'pid':pid,'ppid':ppid,'comm':name,'cpu_percent_ps_estimate':cpu,
            'rss_bytes':int(rss)*1024,'cpu_time':cpu_time,
            'known_capacity_process':pid in owned or ppid in owned})
    return rows
def sample(gateway_pid=None):
    process=subprocess.run(['/bin/ps','-axo','pid=,ppid=,%cpu=,rss=,time=,comm='],capture_output=True,text=True,timeout=3)
    if process.returncode:raise RuntimeError('sanitized ps observation failed')
    return {'scope':'selected executable basenames and process counters only; no args/env; ps CPU is an estimate',
        'load_average':os.getloadavg(),'processes':parse(process.stdout,{os.getpid(),gateway_pid}),
        'no_whole_host_quiet_claim':True}
