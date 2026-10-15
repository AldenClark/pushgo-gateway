#!/usr/bin/env python3
"""C3 profiled full-candidate local comparison. One fresh DB/run; preserve first failure.
SQL counts come from the identical fixture; ps_metrics is OS-only. All data synthetic.
"""
import argparse, collections, concurrent.futures, contextlib, hashlib, http.server, importlib, json, os
import pathlib, re, signal, socket, sqlite3, subprocess, sys, threading, time, urllib.request
import ctypes
mach = ctypes.CDLL('/usr/lib/libSystem.B.dylib')
mach.mach_absolute_time.restype = ctypes.c_uint64
class MachTimebase(ctypes.Structure):
    _fields_ = [('numer',ctypes.c_uint32),('denom',ctypes.c_uint32)]
mach_timebase = MachTimebase()
assert mach.mach_timebase_info(ctypes.byref(mach_timebase)) == 0


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--stats-path', default='/__fixture/stats')
parser.add_argument('--provider-delay-ms',type=float,default=20)
parser.add_argument('--credential-mode',choices=['remote','fixture'],default='remote')
parser.add_argument('--binary', required=True, type=pathlib.Path)
parser.add_argument('--out', required=True, type=pathlib.Path)
parser.add_argument('--scenario', required=True, choices=['idle','burst','sustained','fanout','db-block','cleanup','falloff'])
parser.add_argument('--repeat', default='1', help='Receipt name only; runs exactly once')
parser.add_argument('--engine', choices=['free'], default='free')
parser.add_argument('--provider-budget', type=int, choices=[8,32,64,128], default=32)
parser.add_argument('--fixture-source', required=True, type=pathlib.Path)
parser.add_argument('--fanout-per-provider', type=int, default=16)
parser.add_argument('--aggregate-observer', action='store_true')
parser.add_argument('--claim-quantum', type=int, choices=[8,32,64,128])
parser.add_argument('--kernel-sampler', type=pathlib.Path)
parser.add_argument('--stage-seconds', type=int, default=4)
parser.add_argument('--capacity-rates', help='Comma-separated preregistered message rates')
parser.add_argument('--idle-seconds', type=float, default=60)
parser.add_argument('--falloff-idle-seconds',type=float,default=10)
parser.add_argument('--cold-seconds', type=float, default=2)
parser.add_argument('--low-gap-seconds', type=float, default=5)
parser.add_argument('--build-receipt', type=pathlib.Path, required=True)
parser.add_argument('--source-root', type=pathlib.Path, required=True)
parser.add_argument('--source-archive-identity',type=pathlib.Path)
parser.add_argument('--vmmap', action='store_true', help='Owned PID summary at rate-end and falloff; creates observer cost')
parser.add_argument('--variant', required=True, choices=['BASELINE','CANDIDATE'])
args = parser.parse_args()
assert args.provider_delay_ms >= 0
assert args.falloff_idle_seconds >= 10
assert args.idle_seconds >= 0 and args.cold_seconds >= 0 and args.low_gap_seconds > 0
assert 1 <= args.stage_seconds <= 60
capacity_rates = [int(s) for s in args.capacity_rates.split(',')] if args.capacity_rates else [128,256] if args.scenario=='high' else [1,4,16,32,64]
assert all(1 <= rate <= 256 for rate in capacity_rates)
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
monitor = importlib.import_module('resource_monitor')
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=False)  # Do not overwrite a first receipt.
(out/'executed-runner.py').write_bytes(pathlib.Path(__file__).read_bytes())
(out/'executed-c3-mock.py').write_bytes(pathlib.Path(__file__).with_name('c3_mock.py').read_bytes())
(out/'executed-resource-monitor.py').write_bytes(pathlib.Path(monitor.__file__).read_bytes())
(out/'executed-common.py').write_bytes(pathlib.Path(__file__).with_name('common.py').read_bytes())
(out/'resource-monitor-source-provenance.json').write_bytes(pathlib.Path(__file__).with_name('resource-monitor-source-provenance.json').read_bytes())
db = out / 'gateway.sqlite'
lock = threading.RLock()
started = time.monotonic()
phase = 'startup'
records = {'mock': [], 'requests': [], 'phases': [], 'rss': [], 'snapshots': [], 'producer': [], 'offers': []}
files = {name: (out / (name + '.jsonl')).open('w') for name in records}
mock_counts = {'fcm': 0, 'apns': 0}
mock_live = {'fcm': 0, 'apns': 0}
mock_peak = {'fcm': 0, 'apns': 0}
mock_mode = 'normal'
pid = None
addr = None
child = None
fixture_bind_addr = '127.0.0.1:0'
if args.scenario == 'recovery':
    with socket.socket() as port_selection:
        port_selection.bind(('127.0.0.1',0))
        fixture_bind_addr = '127.0.0.1:'+str(port_selection.getsockname()[1])
children = []
reader_threads = []
fixture_pids = []
op_ttls = {}
excluded_acknowledged_warmup_ids = set()
stop = threading.Event()
ready = threading.Event()
recovery_hold = threading.Event()
lines = []
producer = dict(scheduled=0, submitted=0, started=0, finished=0, accepted=0)
SECRET = hashlib.sha256(b'c3-capacity-seed-20261015').hexdigest()[:32]

def emit(kind, row):
    with lock:
        row = {'elapsed': time.monotonic()-started, 'unix_ms': int(time.time()*1000), **row}
        records[kind].append(row)
        files[kind].write(json.dumps(row, sort_keys=True)+'\n'); files[kind].flush()
    return row

def mark(name):
    global phase
    phase = name
    stats = None; cpu_time = None
    if pid and addr and child is not None and child.poll() is None:
        with urllib.request.urlopen(urllib.request.Request('http://'+addr+args.stats_path,headers={'Authorization':'Bearer '+env['DUAL_ROUTE_TEST_AUTH']}),timeout=5) as r:
            stats = json.loads(r.read())
        cpu_time = subprocess.check_output(['/bin/ps','-p',str(pid),'-o','time='],text=True).strip()
    kernel = None
    if args.kernel_sampler and pid and child.poll() is None:
        observed = subprocess.run([str(args.kernel_sampler.resolve()),'--owned-pid',str(pid)],capture_output=True,text=True)
        kernel = {'exit_code':observed.returncode,'metrics':json.loads(observed.stdout),
                  'helperRaw':json.loads(observed.stderr),'monotonic_ns':time.monotonic_ns()}
    if args.vmmap and pid and (name.startswith('rate-end-') or name in ['falloff-idle-start','falloff-idle-end']):
        observed = subprocess.run(['/usr/bin/vmmap','-summary',str(pid)],capture_output=True,text=True,timeout=20)
        (out/('vmmap-'+name+'.txt')).write_text(observed.stdout+observed.stderr)
        (out/('vmmap-'+name+'.json')).write_text(json.dumps({'pid':pid,'exit_code':observed.returncode,'observer_cost_excluded_from_rate_window':True})+'\n')
    emit('phases', {'phase': name, 'fixture_stats':stats, 'kernel':kernel,
                    'process_cpu_time':cpu_time,
                    'mock_counts': dict(mock_counts), 'mock_live': dict(mock_live)})

# Reuse the exact shared C3 peer. Capacity changes only fixed provider delay;
# Remote Token Service and test control routes are not delayed.
import c3_mock
class CapacityHandler(c3_mock.Handler):
    def reply(self,status,data):
        if self.path.startswith('/v1/projects/') or self.path.startswith('/3/device/'):
            time.sleep(args.provider_delay_ms/1000)
        return super().reply(status,data)

class CapacityState(c3_mock.State):
    def __init__(self,path):
        super().__init__(path)
        self.active_metrics = {}
    def emit(self,kind,row):
        row=super().emit(kind,row)
        if kind=='captures' and row.get('event')=='received':
            data=row['data'];provider=row['provider']
            with lock:
                mock_counts[provider]+=1;mock_live[provider]+=1
                mock_peak[provider]=max(mock_peak[provider],mock_live[provider])
                metric={'provider':provider,'call':mock_counts[provider],'phase':phase,
                  'token':row['token'],'title':data.get('title'),'delivery_id':row['delivery_id'],
                  'message_id':data.get('message_id'),'op_id':row['op_id'],
                  'body_matches':data.get('body')=='x'*1024,'bytes':row['bytes'],
                  'start_ms':row['unix_ms'],'valid':True,'sent_at':data.get('sent_at'),
                  'ttl':data.get('ttl'),'base_url':data.get('base_url'),
                  'canonical_wire_sha256':hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                  'shared_capture_sequence':row['sequence']}
                self.active_metrics[row['sequence']]=metric
            emit('mock',{**metric,'event':'started','planned_status':row['planned_status']})
        elif kind=='requests' and row.get('event')=='provider_finished':
            with lock:
                metric=self.active_metrics.pop(row['capture_sequence'])
                mock_live[row['provider']]-=1
            emit('mock',{**metric,'event':'finished','status':row['status'],
                         'response_error':row['response_error'],'finish_ms':row['unix_ms']})
        return row

class CapacityMock(c3_mock.C3Mock):
    def __init__(self,path):
        self.state=CapacityState(path)
        self.server=c3_mock.Server(self.state,0)
        self.server.RequestHandlerClass=CapacityHandler
        self.endpoint=f'http://127.0.0.1:{self.server.server_port}'
        self.thread=None
peer=CapacityMock(out/'peer')
server=peer.server
env = {k:v for k,v in os.environ.items() if not k.startswith('PUSHGO_') and
       k.lower() not in ['http_proxy','https_proxy','all_proxy','no_proxy','rust_log']}
env['NO_PROXY'] = '127.0.0.1,localhost'
env['DUAL_ROUTE_TEST_AUTH'] = SECRET
env['C2_MOCK_SHARED_TOKEN'] = SECRET
env['C4_COMMIT_STREAM'] = str(out/'commits.bin')
binary = args.binary.resolve()
plan = {'scenario': args.scenario, 'repeat': args.repeat, 'binary': str(binary),
        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'runner_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
        'resource_monitor_sha256':hashlib.sha256(pathlib.Path(monitor.__file__).read_bytes()).hexdigest(),
        'resource_monitor_common_sha256':hashlib.sha256(pathlib.Path(__file__).with_name('common.py').read_bytes()).hexdigest(),
        'build_receipt':str(args.build_receipt.resolve()),'build_receipt_sha256':hashlib.sha256(args.build_receipt.read_bytes()).hexdigest(),
        'variant':args.variant, 'source_root':str(args.source_root.resolve()),
        'fixture_sha256':hashlib.sha256(args.fixture_source.read_bytes()).hexdigest(),
        'engine':args.engine, 'provider_budget':args.provider_budget,
        'restart_delay_seconds':0,'mock_listen_backlog':128,
        'devices': {'fcm':args.fanout_per_provider if args.scenario == 'fanout' else 1 if args.scenario == 'low' else 8,'apns':args.fanout_per_provider if args.scenario == 'fanout' else 1 if args.scenario == 'low' else 8}, 'seed':20261015, 'body_bytes':1024, 'vus':8,
        'capacity_stages': [{'messages_per_second': rate,'duration_seconds':args.stage_seconds} for rate in capacity_rates] if args.scenario in ['sustained','high'] else None,
        'aggregate_observer':args.aggregate_observer,'claim_quantum':args.claim_quantum,
        'kernel_sampler_sha256':hashlib.sha256(args.kernel_sampler.read_bytes()).hexdigest() if args.kernel_sampler else None,
        'steady_messages':16, 'steady_rate_per_second':4, 'burst_messages':64,
        'worker_threads':4, 'profile':'instrumented-full-candidate', 'settle_timeout_seconds':180 if args.scenario in ['sustained','high'] else 120 if args.scenario == 'failures' else 90 if args.scenario == 'recovery' else 45, 'sampler':'resource_monitor.ps_metrics every 250ms',
        'sql_oracle':'sqlx::query completion/drop events; statement verbs only; not successful transactions'}
if args.source_archive_identity:
    identity=json.loads(args.source_archive_identity.read_text())
    assert pathlib.Path(identity['source_root']).resolve()==args.source_root.resolve(),'source archive root mismatch'
    observed={p:hashlib.sha256((args.source_root/p).read_bytes()).hexdigest() for p in identity['source_sha256']}
    assert observed==identity['source_sha256'],'source archive bytes changed'
    actual_files={str(p.relative_to(args.source_root)) for p in args.source_root.rglob('*') if p.is_file()}
    assert actual_files==set(observed),'source archive file set differs'
    plan['source_identity']={'commit':identity['source_commit'],'tree':identity['source_tree'],
        'archive_sha256':identity['archive_sha256'],'tracked_file_sha256':observed,
        'archive_identity_sha256':hashlib.sha256(args.source_archive_identity.read_bytes()).hexdigest(),
        'mode':'immutable git archive, commit object and all tracked bytes; active HEAD irrelevant'}
else:
    source_files = subprocess.check_output(['git','ls-files','-z'], cwd=args.source_root).split(b'\0')
    plan['source_identity'] = {
        'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=args.source_root,text=True).strip(),
        'dirty_diff_sha256':hashlib.sha256(subprocess.check_output(['git','diff','HEAD','--binary'],cwd=args.source_root)).hexdigest(),
        'tracked_file_sha256': {os.fsdecode(f):hashlib.sha256((args.source_root/os.fsdecode(f)).read_bytes()).hexdigest()
                                for f in source_files if f and (args.source_root/os.fsdecode(f)).is_file()},
    }
plan['provider_delays_ms']={'fcm':args.provider_delay_ms,'apns':args.provider_delay_ms}
plan['ttl_mapping']={'logical_duration_seconds':86400,'input':'absolute_epoch_milliseconds','wire':'absolute_epoch_milliseconds','fixture_only_adapter':False}
plan['stats_path']=args.stats_path
plan['provider_delay_ms']=args.provider_delay_ms
plan['credential_mode']=args.credential_mode
plan['shared_mock_sha256']=hashlib.sha256(pathlib.Path(c3_mock.__file__).read_bytes()).hexdigest()
plan['profile_semantics']='per-path caller-wall log2 buckets; errors/cancel included; nested gate_hold/fanout/maintenance overlap; statement SQL includes trigger+SQLx dispatch/results; never sum nested or treat cancel as worker completion'
plan['idle_seconds'] = args.idle_seconds
plan['falloff_idle_seconds']=args.falloff_idle_seconds
plan['observation_cost']='fixture emits full stats heartbeat1Hz; harness RSS ps250ms and phase stats/Mach calls; same matched sides; idle resources include heartbeat cost'
plan['low_gap_seconds'] = args.low_gap_seconds
plan['target_count_per_message'] = sum(plan['devices'].values())
plan['backlog_definition'] = {'producer':'submitted minus HTTP-started; scheduled-minus-submitted is injection lag',
 'accepted_db':'nonterminal durable target rows, includes queued/running; excludes unsent producer backlog'}
plan['cpu_definition'] = 'kernel sampler raw Mach ticks * timebase_numer / timebase_denom; interrupt_wakes is ri_interrupt_wkups, never total wakes'
process_context = subprocess.run(['ps','-axo','pid,ppid,%cpu,%mem,etime,comm'],capture_output=True,text=True)
thermal_context = subprocess.run(['pmset','-g','therm'],capture_output=True,text=True)
(out/'host-context-before.json').write_text(json.dumps({'load_average':os.getloadavg(),'cpu_count':os.cpu_count(),
 'ps_exit':process_context.returncode,'processes':process_context.stdout,'thermal_exit':thermal_context.returncode,
 'thermal':thermal_context.stdout,'observed_only':True},indent=2)+'\n')
(out/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')

def launch():
    global child, pid, addr
    pid = None; addr = None; ready.clear()
    index = len(children)
    cmd = ['/usr/bin/time','-l','-o',str(out/f'rusage-{index}.log'),str(binary),
           '--db-url',f'sqlite://{db}?mode=rwc','--http-addr',fixture_bind_addr,
           '--mock-endpoint',f'http://127.0.0.1:{server.server_port}']
    cmd += ['--shared-token-env','C2_MOCK_SHARED_TOKEN']
    if args.credential_mode=='remote':cmd += ['--mock-token-service-endpoint',peer.endpoint]
    if args.engine == 'free': cmd += ['--provider-budget',str(args.provider_budget)]
    if args.claim_quantum: cmd += ['--claim-quantum',str(args.claim_quantum)]
    child = subprocess.Popen(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    children.append(child)
    def reader(process):
        global pid, addr
        with (out/f'gateway-{index}.log').open('w') as f:
            for line in process.stdout:
                f.write(line); f.flush()
                with lock: lines.append(line)
                if line.startswith('READY '):
                    pid = int(re.search(r'pid=(\d+)',line)[1]); addr = re.search(r'http_addr=(\S+)',line)[1]
                    fixture_pids.append(pid)
                    ready.set()
    reader_thread = threading.Thread(target=reader,args=(child,),daemon=True)
    reader_threads.append(reader_thread); reader_thread.start()
    assert ready.wait(25), ('fixture did not become ready', lines[-10:])
    mark('ready' if index == 0 else 'restarted')

def sampler():
    while not stop.is_set():
        if pid: emit('rss', {'phase':phase,'pid':pid,**monitor.ps_metrics(pid)})
        with lock:
            emit('producer', {'phase':phase, **producer,
                  'producer_waiting':producer['submitted']-producer['started'],
                  'http_inflight':producer['started']-producer['finished'],
                  'schedule_injection_lag':producer['scheduled']-producer['submitted']})
        stop.wait(.25)
sampler_thread = threading.Thread(target=sampler,daemon=True)
sampler_thread.start()

def request(path, data, label, allow_preaccept_failure=False):
    http_start_mach_ticks=mach.mach_absolute_time()
    start_ms = int(time.time()*1000); t = time.monotonic()
    if path == '/message':
        with lock: producer['started'] += 1
    status = None; response = None; error = None
    try:
        req = urllib.request.Request('http://'+addr+path,data=json.dumps(data).encode(),
                                     headers={'Content-Type':'application/json',
                                              'Authorization':'Bearer '+env['DUAL_ROUTE_TEST_AUTH']},method='POST')
        with urllib.request.urlopen(req,timeout=20) as r:
            status = r.status; response = json.loads(r.read())
        assert status == 200, (path,status,response)
        return response['data']
    except BaseException as e:
        status = getattr(e,'code',status)
        if hasattr(e,'read'): response = e.read().decode(errors='replace')
        error = repr(e)
        with lock:
            receipt = out/'first-failure.json'
            if not receipt.exists(): receipt.write_text(json.dumps({'failure':error,'path':path,'label':label,'status':status,'response':response},indent=2)+'\n')
        if allow_preaccept_failure and status in (500,503):
            return {'injected_preaccept_failure':status}
        raise
    finally:
        http_end_mach_ticks=mach.mach_absolute_time()
        if path == '/message':
            with lock:
                producer['finished'] += 1
                if status == 200: producer['accepted'] += 1
        emit('requests', {'phase':phase,'label':label,'path':path,'start_ms':start_ms,
                          'status':status,'latency_ms':(time.monotonic()-t)*1000,
                          'response':response,'error':error,'http_start_mach_ticks':http_start_mach_ticks,'http_end_mach_ticks':http_end_mach_ticks})

@contextlib.contextmanager
def connection(path):
    conn = sqlite3.connect(f'file:{path}?mode=ro',uri=True,timeout=5)
    conn.row_factory = sqlite3.Row
    try: yield conn
    finally: conn.close()

def side(suffix): return db.with_name(db.stem+suffix+db.suffix)

def snapshot(label, raw=True):
    # High-load observation uses only aggregate counts while running; full
    # independent identity rows are loaded once at the successful drain gate.
    if args.aggregate_observer and not raw:
        authority = db if args.engine == 'free' else side('.dispatch')
        table = 'targets' if args.engine == 'free' else 'provider_dispatch_outbox'
        with connection(authority) as conn:
            excluded = tuple(sorted(excluded_acknowledged_warmup_ids))
            predicate = ' WHERE delivery_id NOT IN ('+','.join('?' for _ in excluded)+')' if excluded else ''
            states = dict(conn.execute(f'SELECT state,count(*) FROM {table}'+predicate+' GROUP BY state',excluded))
            leased = 0 if args.engine=='free' else conn.execute('SELECT count(*) FROM provider_dispatch_outbox WHERE lease_owner IS NOT NULL').fetchone()[0]
            if args.engine=='free':
                pull_rows = conn.execute('SELECT count(*) FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id WHERE t.acked_at IS NULL AND m.expires_at>?',(int(time.time()*1000),)).fetchone()[0]
            else: pull_rows = None
        if args.engine!='free':
            with connection(side('.delivery')) as conn: pull_rows=conn.execute('SELECT count(*) FROM provider_pull_queue').fetchone()[0]
        summary={'label':label,'states':states,'target_count':sum(states.values()),'pull_rows':pull_rows,'leased_rows':leased,'core_table_counts':{},'dispatch_table_counts':{table:sum(states.values())}}
        emit('snapshots',summary);return summary
    if args.engine == 'free':
        with connection(db) as conn:
            rows = [dict(r) for r in conn.execute("""SELECT
                upper(t.provider)||':'||t.delivery_id||':'||t.device_key AS job_id,
                upper(t.provider) AS provider,t.delivery_id,m.op_id,t.device_key,t.state,
                t.attempts AS attempt_count,t.next_attempt_at,
                NULL AS lease_owner,NULL AS lease_until,t.attempt_id AS lease_generation,
                t.provider_status,m.accepted_at,t.receipt_at AS completed_at,
                coalesce(t.receipt_at,m.accepted_at) AS updated_at
                FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id
                ORDER BY t.provider,m.op_id,t.device_key""")]
            retained_bytes = conn.execute('SELECT coalesce(sum(payload_bytes),0) FROM messages').fetchone()[0]
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            counts = {table:conn.execute('SELECT count(*) FROM "'+table.replace('"','""')+'"').fetchone()[0] for table in tables}
            pull_rows = conn.execute('SELECT count(*) FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id WHERE t.acked_at IS NULL AND m.payload_blob IS NOT NULL AND m.expires_at>?',(int(time.time()*1000),)).fetchone()[0]
        rows = [r for r in rows if r['delivery_id'] not in excluded_acknowledged_warmup_ids]
        states = {}
        for row in rows: states[row['state']] = states.get(row['state'],0)+1
        summary={'label':label,'states':states,'dispatch_table_counts':counts,'pull_rows':pull_rows,
                 'leased_rows':0,'running_rows':sum(r['state']=='running' for r in rows),'core_table_counts':counts if raw else {},
                 'retained_payload_bytes':retained_bytes}
        emit('snapshots',{**summary,**({'dispatch_rows':rows} if raw else {})})
        return {**summary,'dispatch_rows':rows}
    with connection(side('.dispatch')) as conn:
        rows = [dict(r) for r in conn.execute('SELECT job_id,provider,delivery_id,op_id,device_key,state,attempt_count,next_attempt_at,lease_owner,lease_until,lease_generation,provider_status,accepted_at,completed_at,updated_at FROM provider_dispatch_outbox ORDER BY provider,op_id,device_key')]
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        counts = {table:conn.execute('SELECT count(*) FROM "'+table.replace('"','""')+'"').fetchone()[0] for table in tables}
    with connection(side('.delivery')) as conn:
        pull_rows = conn.execute('SELECT count(*) FROM provider_pull_queue').fetchone()[0]
    core_counts = {}
    if raw:
        with connection(db) as conn:
            for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
                core_counts[table] = conn.execute('SELECT count(*) FROM "'+table.replace('"','""')+'"').fetchone()[0]
    rows = [r for r in rows if r['delivery_id'] not in excluded_acknowledged_warmup_ids]
    states = {}
    for row in rows: states[row['state']] = states.get(row['state'],0)+1
    summary = {'label':label,'states':states,'dispatch_table_counts':counts,'pull_rows':pull_rows,
               'leased_rows':sum(r['lease_owner'] is not None for r in rows), 'core_table_counts':core_counts}
    emit('snapshots', {**summary, **({'dispatch_rows':rows} if raw else {})})
    return {**summary,'dispatch_rows':rows}

def wait_jobs(expected, label):
    deadline = time.monotonic()+plan['settle_timeout_seconds']
    while True:
        snap = snapshot(label, raw=False)
        if snap.get('target_count',len(snap.get('dispatch_rows',[]))) == expected and snap['states'] == {'provider_accepted':expected}:
            return snapshot(label,raw=True) if args.aggregate_observer else snap
        assert not any(k in snap['states'] for k in ['permanent_failed','expired','terminal_failed']), snap['states']
        assert time.monotonic() < deadline, ('jobs did not settle',snap['states'],expected)
        time.sleep(.25)

def drain(expected, warmup=False):
    all_acknowledged_ids = set()
    for key in keys:
        seen = set(); seen_ops = set()
        while True:
            result = request('/v2/messages/pull', {'device_key':key}, 'pull')
            ids = [item['delivery_id'] for item in result['items']]
            assert len(ids) == len(set(ids)) and not seen.intersection(ids), ('duplicate Pull id',key,ids)
            seen.update(ids)
            for item in result['items']:
                payload = item['payload']; seen_ops.add(payload['op_id'])
                assert payload['title'] == payload['op_id'] and payload['body'] == 'x'*1024, 'Pull content changed'
                assert item['delivery_id'] and payload.get('delivery_id', item['delivery_id']) == item['delivery_id'], 'v2 Pull identity mismatch'
            if ids:
                retained = request('/v2/messages/pull', {'device_key':key}, 'pull-before-ack')
                assert retained == result, 'Pull content was removed before ACK'
                ack = request('/v2/messages/ack', {'device_key':key,'delivery_ids':ids},'ack')
                assert ack['removed_count'] == len(ids), ack
                all_acknowledged_ids.update(ids)
            if not result['has_more']: break
            assert ids, ('empty has_more', key)
        assert len(seen) == expected, (key,len(seen),expected)
        wanted = {f'dual:{args.scenario}:{i:03d}' for i in ([-1] if warmup else range(expected))}
        assert seen_ops == wanted, ('unexpected Pull operation identity',seen_ops,wanted)
    assert snapshot('after-ack')['pull_rows'] == 0
    return all_acknowledged_ids

def submit(pool, i, allow_preaccept_failure=False, scheduled_at=None):
    with lock:
        producer['scheduled'] += 1
        producer['submitted'] += 1
    emit('offers', {'op_id':f'dual:{args.scenario}:{i:03d}',
          'scheduled_monotonic':scheduled_at if scheduled_at is not None else time.monotonic(),
          'submitted_monotonic':time.monotonic(), 'offer_mach_ticks':mach.mach_absolute_time()})
    return pool.submit(send,i,allow_preaccept_failure)

def send(i, allow_preaccept_failure=False):
    name = f'dual:{args.scenario}:{i:03d}'
    # Both C3 sources use the same ordinary absolute-millisecond TTL contract.
    with lock:
        ttl = op_ttls.setdefault(i,int(time.time()*1000)+86400*1000)
    return request('/message', {'ttl':ttl,'channel_id':channel,'password':SECRET,'title':name,
                               'op_id':name,'body':'x'*1024}, name, allow_preaccept_failure)

def write_expected(rows):
    by_identity = {(r['op_id'],r['device_key']):r for r in rows}
    admission = {r['label']:r for r in records['requests'] if r['path']=='/message'}
    with (out/'expected-targets.jsonl').open('x') as f:
        for offer in records['offers']:
            op=offer['op_id']
            for key in keys:
                row=by_identity.get((op,key));request_row=admission.get(op,{})
                state=row.get('state') if row else None
                if state=='provider_accepted':outcome='accepted'
                elif state in ('permanent_failed','expired','cancelled'):outcome='provider_failed'
                elif row:outcome='unfinished'
                elif 'timed out' in str(request_row.get('error','')):outcome='timeout'
                elif request_row.get('error'):outcome='admission_failed'
                else:outcome='unfinished'
                f.write(json.dumps({'op_id':op,'device_key':key,
                    'delivery_id':row['delivery_id'] if row else None,
                    'offer_mach_ticks':offer['offer_mach_ticks'],'final_outcome':outcome})+'\n')

failure = None; exit_codes = []; keys = []; channel = None; device_tokens = {}; device_providers = {}
try:
    peer.__enter__()
    launch(); mark('cold'); time.sleep(args.cold_seconds); snapshot('cold')
    mark('setup')
    per_provider = plan['devices']['fcm']; total_devices = 2 * per_provider
    for i in range(total_devices):
        platform, provider = ('android','fcm') if i < per_provider else ('ios','apns')
        key = request('/device/register',{'platform':platform},f'register-{i}')['device_key']
        request('/channel/device',{'device_key':key,'platform':platform,'channel_type':provider,
                                  'provider_token':format(i+20261015,'064x')},f'route-{i}')
        binding = {'channel_name':'dual-route-synthetic'} if i == 0 else {'channel_id':channel}
        result = request('/channel/subscribe',{'device_key':key,'password':SECRET,**binding},f'subscribe-{i}')
        assert result['subscribed'] and result['created'] == (i == 0), result
        if i == 0: channel = result['channel_id']
        else: assert result['channel_id'] == channel
        keys.append(key)
        device_tokens[key] = format(i+20261015,'064x')
        device_providers[key] = provider
    with connection(db) as conn:
        assert conn.execute('SELECT count(*) FROM channels').fetchone()[0] == 1
        assert conn.execute('SELECT count(*) FROM channel_subscriptions').fetchone()[0] == total_devices
    snapshot('setup')
    if args.scenario == 'idle':
        mark('idle'); time.sleep(args.idle_seconds); mark('idle-complete'); snapshot('idle-final')
    else:
        mark('warmup'); send(-1); warm = wait_jobs(total_devices,'warmup')
        assert all(r['attempt_count'] == 1 for r in warm['dispatch_rows']), 'unexpected warmup retry'
        warm_wire = [r for r in records['mock'] if r['event'] == 'started']
        assert len(warm_wire) == total_devices and len({(r['provider'],r['op_id'],r['delivery_id'],r['token']) for r in warm_wire}) == total_devices, 'unexpected warmup external duplicate'
        warmup_delivery_ids = {r['delivery_id'] for r in warm['dispatch_rows']}
        assert warmup_delivery_ids and all(r['op_id']==f'dual:{args.scenario}:-01' for r in warm['dispatch_rows'])
        acknowledged_warmup_ids = drain(1, warmup=True)
        assert acknowledged_warmup_ids == warmup_delivery_ids, 'warmup ACK identities differ from durable provider targets'
        # Exclude exactly the independently identified and fully ACK-verified
        # warmup deliveries for both sources; physical reclamation is permitted.
        excluded_acknowledged_warmup_ids.update(acknowledged_warmup_ids)
        (out/'acknowledged-warmup-identities.json').write_text(json.dumps(sorted(warmup_delivery_ids))+'\n')
        with lock:
            mock_counts.update(fcm=0,apns=0)
            producer.update(scheduled=0,submitted=0,started=0,finished=0,accepted=0)
        mark('load'); mock_mode = args.scenario
        count = 64 if args.scenario in ['burst','falloff'] else 8 if args.scenario == 'recovery' else 2 if args.scenario == 'fanout' else 4 if args.scenario == 'low' else 16
        if args.scenario in ['sustained','high']: count = sum(stage['messages_per_second']*stage['duration_seconds'] for stage in plan['capacity_stages'])
        blocker = None
        if args.scenario == 'db-block':
            blocker = sqlite3.connect(db if args.engine == 'free' else side('.dispatch'),timeout=5)
            blocker.execute('BEGIN IMMEDIATE'); mark('db-lock-acquired')
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = []
            if args.scenario in ['sustained','high']:
                next_id = 0
                for stage in plan['capacity_stages']:
                    rate = stage['messages_per_second']; duration = stage['duration_seconds']; mark('rate-'+str(rate)); snapshot('rate-'+str(rate)+'-start', raw=False)
                    stage_start = time.monotonic()
                    for j in range(rate*duration):
                        time.sleep(max(0,stage_start+j/rate-time.monotonic()))
                        futures.append(submit(pool,next_id,scheduled_at=stage_start+j/rate)); next_id += 1
                        if j % rate == rate-1:
                            snapshot('rate-'+str(rate)+'-second-'+str(j//rate+1), raw=False)
                    time.sleep(max(0,stage_start+duration-time.monotonic()))
                    snapshot('rate-'+str(rate)+'-end', raw=False); mark('rate-end-'+str(rate))
                mark('sustained-input-stop')
            else:
                for i in range(count):
                    if args.scenario in ['steady','low']:
                        gap = args.low_gap_seconds if args.scenario == 'low' else .25
                        deadline = started_load+gap*i if i else time.monotonic()
                        if i == 0: started_load = deadline
                        time.sleep(max(0,deadline-time.monotonic()))
                    futures.append(submit(pool,i,args.scenario == 'db-block'))
            if blocker:
                time.sleep(2); blocker.rollback(); blocker.close(); mark('db-lock-released')
            for f in futures: f.result()
        if args.scenario == 'db-block':
            # Fixed same-identity second wave for every variant. Preserve first
            # responses; these are injected precommit admission failures, not
            # a throughput shortcut or new/replaced operations.
            snapshot('after-block-first-wave'); mark('same-identity-second-wave')
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                [f.result() for f in [submit(pool,i) for i in range(count)]]
        if args.scenario == 'recovery':
            deadline = time.monotonic()+5
            snapshot('pre-kill')
            while sum(mock_live.values()) == 0:
                assert time.monotonic() < deadline, 'no real provider attempt before crash'
                time.sleep(.005)
            mark('kill')
            with lock:
                assert sum(mock_live.values()) > 0, 'kill fault did not overlap an HTTP attempt'
                os.kill(pid,signal.SIGKILL)
            recovery_hold.set()
            exit_codes.append(child.wait(timeout=5)); pid = None
            mark('restart-immediate')
            mock_mode = 'normal'; launch()
        mark('settle'); final = wait_jobs(count*total_devices,'settle')
        # This marker precedes independent identity/wire verification. Timing
        # reduction still uses the first successful SQL snapshot itself.
        mark('first-all-targets-sql-visible')
        if args.scenario == 'falloff':
            mark('falloff-sparse')
            for i in range(count,count+3):
                send(i); time.sleep(1)
            count += 3
            final = wait_jobs(count*total_devices,'falloff-sparse-settle')
        identities = {(r['op_id'],r['device_key']) for r in final['dispatch_rows']}
        wanted = {(f'dual:{args.scenario}:{i:03d}',key) for i in range(count) for key in keys}
        assert identities == wanted, 'missing or duplicate durable identity'
        wire_expected = {(device_providers[r['device_key']], r['op_id'], r['delivery_id'], device_tokens[r['device_key']])
                         for r in final['dispatch_rows']}
        wire_started = [r for r in records['mock'] if r['event'] == 'started' and r['delivery_id'] not in excluded_acknowledged_warmup_ids]
        wire_observed = {(r['provider'],r['op_id'],r['delivery_id'],r['token']) for r in wire_started}
        assert wire_observed == wire_expected, 'provider receipt identity/recipient differs from durable intent'
        hashes_by_identity = collections.defaultdict(set)
        for row in wire_started:
            hashes_by_identity[(row['provider'],row['op_id'],row['delivery_id'],row['token'])].add(row['canonical_wire_sha256'])
        assert all(len(hashes)==1 for hashes in hashes_by_identity.values()), 'retry/recovery changed canonical identity/content/time/expiry/authority'
        assert all(r['body_matches'] and r['title'] == r['op_id'] for r in wire_started), 'provider content changed'
        if args.scenario not in ['failures','recovery']:
            assert all(r['attempt_count'] == 1 for r in final['dispatch_rows']), 'unexpected normal retry'
            assert len(wire_started) == len(wire_expected), 'unexpected duplicate external normal attempt'
        assert all(r.get('valid',True) for r in records['mock']), 'invalid mock request'
        if args.credential_mode=='remote':
            token_providers={r['provider'] for r in map(json.loads,(out/'peer'/'requests.jsonl').read_text().splitlines()) if r.get('event')=='token_request'}
            assert token_providers=={'fcm','apns'},('Remote credentials not observed in persistent stream',token_providers)
        mark('provider-complete'); snapshot('provider-complete')
        cleanup_key=None
        if args.scenario=='cleanup':
            cleanup_key=keys[0];mark('cleanup-start')
            response=request('/channel/device/provider-token/retire',{'platform':'android','provider_token':device_tokens[cleanup_key]},'retire-provider-token')
            assert response['retired'] is True,response
            deadline=time.monotonic()+15
            while True:
                with connection(db) as conn:
                    left=conn.execute('SELECT count(*) FROM targets WHERE device_key=? AND acked_at IS NULL',(cleanup_key,)).fetchone()[0]
                if left==0:break
                assert time.monotonic()<deadline,('cleanup did not physically finish',left)
                time.sleep(.05)
            empty=request('/v2/messages/pull',{'device_key':cleanup_key},'pull-retired-token')
            assert empty['items']==[] and not empty['has_more'],empty
            keys.remove(cleanup_key);mark('cleanup-complete')
        write_expected(final['dispatch_rows'])
        mark('ack-start');drain(count);mark('ack-complete')
        snapshot('final'); mark('complete')
        if args.scenario == 'falloff':
            mark('falloff-idle-start'); time.sleep(args.falloff_idle_seconds); mark('falloff-idle-end'); snapshot('falloff-idle')
except BaseException as e:
    failure = repr(e)
    if not (out/'first-failure.json').exists():
        (out/'first-failure.json').write_text(json.dumps({'failure':failure,'phase':phase,'last_gateway_lines':lines[-15:]},indent=2)+'\n')
finally:
    recovery_hold.set()
    if child is not None and child.poll() is None:
        if pid: os.kill(pid,signal.SIGTERM)
        try: exit_codes.append(child.wait(timeout=25))
        except subprocess.TimeoutExpired:
            if pid: os.kill(pid,signal.SIGKILL)
            exit_codes.append(child.wait(timeout=5))
    stop.set(); sampler_thread.join(timeout=5); peer.__exit__(None,None,None)
    for reader_thread in reader_threads: reader_thread.join(timeout=5)
    daemon_exited = True
    for fixture_pid in fixture_pids:
        try: os.kill(fixture_pid,0); daemon_exited = False
        except ProcessLookupError: pass
    if failure is None and (not daemon_exited or any(t.is_alive() for t in reader_threads)):
        failure = 'daemon exit or log reader join not proven'
        if not (out/'first-failure.json').exists():
            (out/'first-failure.json').write_text(json.dumps({'failure':failure})+'\n')
    shutdown_lines = [line for line in lines if line.startswith('SHUTDOWN ')]
    if failure is None and (not shutdown_lines or not re.search(r'joined=[1-9][0-9]* panicked=0 aborted=0 http_timed_out=false tasks=[0-9]+', shutdown_lines[-1])):
        failure = 'final gateway did not shut down cleanly: '+repr(shutdown_lines[-1:])
        if not (out/'first-failure.json').exists():
            (out/'first-failure.json').write_text(json.dumps({'failure':failure},indent=2)+'\n')
    if failure is None and (not exit_codes or exit_codes[-1] != 0):
        failure = 'final fixture exit was not successful: '+repr(exit_codes)
        if not (out/'first-failure.json').exists():
            (out/'first-failure.json').write_text(json.dumps({'failure':failure},indent=2)+'\n')
    if not (out/'expected-targets.jsonl').exists():
        try:
            with connection(db) as conn:
                remaining=[dict(r) for r in conn.execute('SELECT m.op_id,t.device_key,t.delivery_id,t.state FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id')]
            write_expected(remaining)
        except BaseException as telemetry_error:
            (out/'expected-targets-failure.json').write_text(json.dumps({'error':repr(telemetry_error)})+'\n')
    observer_path=out/'commits.observer.json'
    if observer_path.exists():
        telemetry=json.loads(observer_path.read_text())
        telemetry.update(mach_numer=mach_timebase.numer,mach_denom=mach_timebase.denom,
            expected_targets=len(records['offers'])*len(keys),planned_targets=40960,
            final_sql_verified=failure is None,
            excluded_acknowledged_warmup_ids=sorted(excluded_acknowledged_warmup_ids),
            driver_memory_scope='original finite C3 Python records; excluded from Gateway RSS')
        (out/'telemetry.json').write_text(json.dumps(telemetry,indent=2)+'\n')
    for f in files.values(): f.close()
    database_bytes = {p.name:p.stat().st_size for p in out.glob('gateway*') if p.is_file() and (p.suffix == '.sqlite' or p.name.endswith(('-wal','-shm')))}
    (out/'result.json').write_text(json.dumps({'failure':failure,'exit_codes':exit_codes,'database_file_bytes_after_shutdown':database_bytes,
        'daemon_exited':daemon_exited,'log_readers_joined':all(not t.is_alive() for t in reader_threads),'producer_final':producer,'sampler_joined':not sampler_thread.is_alive(),'shared_mock_server_joined':peer.thread is not None and not peer.thread.is_alive(),
        'elapsed_seconds':time.monotonic()-started,'mock_counts':mock_counts,'mock_peak_attempts':mock_peak},indent=2)+'\n')
if failure is not None: raise SystemExit(failure)
assert exit_codes[-1] == 0, exit_codes
print('COMPLETE',flush=True)
