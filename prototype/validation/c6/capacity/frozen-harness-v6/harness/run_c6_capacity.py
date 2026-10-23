#!/usr/bin/env python3
"""One explicitly authorized C6 paired PG/MySQL capacity lane; never builds or creates DBs.

Fixed: H32/Q32, real candidate Provider+Remote Token owner, Mock20ms,
16 targets, 8 HTTP callers, 256 msg/s x10s, 180s maximum after planned input end,
30s cold and post-ACK idle. No retries; output directory must not exist.
"""
import argparse, concurrent.futures, ctypes, hashlib, importlib.util, json, math
import os, pathlib, re, signal, stat, struct, subprocess, sys, threading, time, urllib.request
from urllib.parse import urlsplit
import c3_mock
import db_os_observer
import source_provenance
import host_observer
import prepared_completion_observer

HERE=pathlib.Path(__file__).resolve().parent
def safe_subprocess_timeout(timeout):
    # Never serialize command arguments from a DB observation subprocess.
    return TimeoutError(f'DB observer subprocess exceeded unchanged remaining-time budget ({timeout} seconds)')

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def quantiles(samples):
    samples=sorted(samples); n=len(samples)
    return {'n':n, **{f'p{q}_ms':samples[math.ceil(n*q/100)-1] if n else None for q in (50,95,99)}}
def load_helper(path):
    spec=importlib.util.spec_from_file_location('c5_isolated_db',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def durable_nonterminal(states):
    return sum(n for state,n in states.items() if state in ('pending','running','retry_wait'))

def workload_message(path,label):
    return path=='/message' and label!='c5:capacity:-1'

def scoped_db_arguments(engine,arguments):
    # One explicitly owned observer psql process only. No container/global setting.
    if engine=='pg' and arguments[:2]==['exec','-i'] and 'psql' in arguments:
        return arguments[:2]+['-e','PGOPTIONS=-csearch_path=pushgo_c']+arguments[2:]
    return arguments

def expected_target_rows(offers,keys,witness,requests,accepted_ticks,cutoff):
    by_identity={(r['op_id'],r['device_key']):r for r in witness}
    requests={r['label']:r for r in requests if r['path']=='/message'}
    for offer in offers:
        for key in keys:
            row=by_identity.get((offer['op_id'],key));req=requests.get(offer['op_id'],{});state=row['state'] if row else None
            ticks=accepted_ticks.get((row['delivery_id'],key)) if row else None
            if state in ('provider_accepted','permanent_failed','expired','cancelled') and ticks is not None and cutoff is not None and ticks>cutoff:outcome='unfinished'
            elif state=='provider_accepted' and ticks is None:outcome='unfinished'
            elif state=='provider_accepted':outcome='accepted'
            elif state in ('permanent_failed','expired','cancelled'):outcome='provider_failed'
            elif row:outcome='unfinished'
            elif 'timed out' in str(req.get('error','')).lower():outcome='timeout'
            elif req.get('error'):outcome='admission_failed'
            else:outcome='unfinished'
            yield {'op_id':offer['op_id'],'device_key':key,'delivery_id':row['delivery_id'] if row else None,
                'offer_mach_ticks':offer['offer_mach_ticks'],'final_outcome':outcome,
                'durable_state_at_final_witness':state,'post_cutoff_success_censored':state=='provider_accepted' and ticks is not None and cutoff is not None and ticks>cutoff,
                'callback_timing_unknown':state=='provider_accepted' and ticks is None}

def main(a):
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    for name in (pathlib.Path(__file__).name,'db_os_observer.py','source_provenance.py','host_observer.py','c3_mock.py','observer_fixture.rs','observer_library.rs','reduce_commits.py','prepared_completion_observer.py','prepared-query-hash-map.json'):
        (out/('executed-'+name)).write_bytes((HERE/name).read_bytes())
    # Shared monotonic source with the fixture. Import does not call these APIs.
    mach=ctypes.CDLL('/usr/lib/libSystem.B.dylib');mach.mach_absolute_time.restype=ctypes.c_uint64
    class Timebase(ctypes.Structure): _fields_=[('numer',ctypes.c_uint32),('denom',ctypes.c_uint32)]
    base=Timebase();assert mach.mach_timebase_info(ctypes.byref(base))==0
    scale=base.numer/base.denom/1_000_000
    helper=load_helper(a.db_helper.resolve())
    assert a.engine=='mysql' and helper.KEY=='io.pushgo.c6.disk3.synthetic.owner','exact disk3 MySQL helper required'
    assert a.db_url_file.resolve().parent==a.db_helper.resolve().parent,'URL must belong to this C6 env directory'
    helper.check(); owned,container_inspect=helper.owned(a.engine)
    environment=json.loads(a.environment_identity.read_text())['engines'][a.engine]
    assert owned['id']==environment['id'] and container_inspect['Image']==environment['image_id'],'environment identity mismatch'
    storage=environment['storage'];assert storage['medium']=='disk-backed-named-volume'
    mounts=[m for m in container_inspect['Mounts'] if m['Destination']=='/var/lib/mysql']
    assert len(mounts)==1 and mounts[0]['Type']=='volume' and mounts[0]['Name']==storage['volume_name'] and mounts[0]['Source']==storage['volume_mountpoint'],'exact disk3 volume mount mismatch'
    assert owned['volume_name']==storage['volume_name'] and owned['owner']==storage['owner_uuid']
    assert a.db_url_file.is_file() and not a.db_url_file.is_symlink() and stat.S_IMODE(a.db_url_file.stat().st_mode)==0o600,'private regular URL file mode0600 required'
    url=a.db_url_file.read_text().strip();parsed=urlsplit(url);database=parsed.path.lstrip('/')
    assert database in owned['cases'],'fresh captured C6 case required'
    assert database.startswith('c5_synthetic_'),'legacy fixture compatibility name in new C6 container required'
    assert pathlib.Path(owned['cases'][database]['url_file']).resolve()==a.db_url_file.resolve()
    assert parsed.netloc.endswith('@'+owned['endpoint']) and parsed.hostname in ('127.0.0.1','localhost')
    assert parsed.scheme in (('postgres','postgresql') if a.engine=='pg' else ('mysql',))
    # No URL/password is emitted to plans, logs, or subprocess receipts.
    lock=threading.RLock(); files={}; rows={}; phase='startup'; beginning=time.monotonic()
    for name in ('phases','rss','db-process','db-connections','snapshots','requests','offers','producer','host-load'):
        files[name]=(out/(name+'.jsonl')).open('x');rows[name]=[]
    def emit(kind,row):
        with lock:
            record={'elapsed':time.monotonic()-beginning,'monotonic_ns':time.monotonic_ns(),'phase':phase,**row}
            rows[kind].append(record);files[kind].write(json.dumps(record,sort_keys=True)+'\n');files[kind].flush()
        return record
    failure_ticks=None
    def first(error, **context):
        nonlocal failure_ticks
        with lock:
            try:
                with (out/'first-failure.json').open('x') as f:
                    failure_ticks=mach.mach_absolute_time()
                    json.dump({'error':str(error),'phase':phase,'elapsed':time.monotonic()-beginning,'mach_ticks':failure_ticks,**context},f,indent=2);f.write('\n')
            except FileExistsError: pass
    producer=dict(offered=0,started=0,finished=0,accepted=0,skipped_after_first_failure=0)
    ready=threading.Event(); stop=threading.Event(); failed=threading.Event()
    child=None;pid=None;addr=None;gateway_lines=[];keys=[];channel=None;tokens={};providers={}
    side_observation_status={'applicable':False}
    exclusion=set();deadline=None;deadline_ticks=None;enforce_deadline=False;failure=None;final_rows=[];sql_verified=False
    reader_thread=None;sampler_thread=None;db_sampler_thread=None;peer=None;sql_aggregate_complete_ticks=None
    secret=hashlib.sha256(b'c5-capacity-synthetic-20261015').hexdigest()[:32]
    env={k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','C4_COMMIT','C5_COMMIT'))
         and k.lower() not in ('http_proxy','https_proxy','all_proxy','no_proxy','rust_log')}
    env.update(NO_PROXY='127.0.0.1,localhost',DUAL_ROUTE_TEST_AUTH=secret,C2_MOCK_SHARED_TOKEN=secret,
               C5_COMMIT_STREAM=str(out/'commits.bin'))
    plan={'status':'AUTHORIZED_RUNTIME_INPUT','engine':a.engine,'database':database,
          'comparison_arm':a.comparison_arm,'environment_identity_sha256':digest(a.environment_identity),
          'source_commit':a.source_commit,'source_root':str(a.source_root.resolve()),
          'binary':str(a.binary.resolve()),'binary_sha256':digest(a.binary),
          'build_receipt_sha256':digest(a.build_receipt),'build_receipt':str(a.build_receipt.resolve()),
          'source_identity_sha256':digest(a.source_identity),'source_identity':str(a.source_identity.resolve()),
          'runner_sha256':digest(pathlib.Path(__file__)),'peer_sha256':digest(HERE/'c3_mock.py'),
          'provider_budget':32,'claim_quantum':32,'provider_delay_ms':20,'http_callers':8,
          'devices':{'fcm':8,'apns':8},'message_body_bytes':1024,'offer_rate_messages_s':256,
          'offer_seconds':10,'planned_messages':2560,'planned_targets':40960,
          'cold_idle_seconds':30,'cold_idle_position':'after setup + acknowledged warmup, directly before offered burst; startup OS marker also retained','post_ack_idle_seconds':30,'settle_deadline_seconds':180,
          'deadline_anchor':'planned ten-second input end; no reset after HTTP waits or SQL polls',
          'idle_observation':'OS-only ps and owned PID Mach sampler; no Gateway HTTP and no SQL during idle',
          'fixture_baseline':'unchanged fixture emits its own stats heartbeat once/second; included in idle cost',
          'db_observation':'1Hz owned-container native PID1 /proc VmRSS kB; supported Docker top per-process cumulative TIME; no pcpu or humanized RSS conversion; SQL connection snapshots only at non-idle boundaries',
          'quantiles':'exact nearest-rank observed completions; all offered targets retained in denominator',
          'toolchain_required':'Rust 1.97.1 release; no build in runner','retries':0,'host_load_observer':'sanitized pid/ppid/comm/CPU/TIME at start and5s; no args/env, no quiet assumption',
          'environment_comparison':'C6 owned containers with P_S ON / pg_stat_statements ON; pair only, no absolute C5 OFF timing comparison',
          'storage_scope':'MySQL8.4.11 exact owned disk-backed named volume in OrbStack VM; VM filesystem/fsync boundary, no host power-loss durability claim','storage_identity':storage}
    receipt=json.loads(a.build_receipt.read_text())
    assert receipt.get('binary_sha256')==plan['binary_sha256'],'build/binary identity mismatch'
    assert receipt.get('source_commit')==a.source_commit,'build/source commit mismatch'
    assert '1.97.1' in receipt.get('rustc',''),'wrong toolchain receipt'
    assert receipt.get('profile',{}).get('name')=='release','release receipt required'
    identity=json.loads(a.source_identity.read_text());assert identity['source_commit']==a.source_commit
    plan['source_verification']=source_provenance.verify(identity,a.source_root.resolve())
    if identity.get('verification_mode')=='git-objects-and-frozen-overlay':
        assert receipt.get('source_identity_sha256')==identity['upstream_source_identity_sha256']
        assert plan['binary_sha256']==identity['binary_sha256']
    if a.comparison_arm=='baseline-c5':
        assert a.source_commit=='651bf7e7e4691bd5a78b36625ff34b693be83590'
        assert plan['binary_sha256']=='52731d4a4599a379984e16734c9b9f304593aefe64b86563c6e7032e2a16e4af'
    (out/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    post_completion_observation_deadline=None
    def bounded_db_run(arguments,stdin=None,environment=None):
        remaining=deadline-time.monotonic() if enforce_deadline else 10
        if post_completion_observation_deadline is not None:remaining=min(remaining,post_completion_observation_deadline-time.monotonic())
        if remaining<=0:raise TimeoutError('fixed lane deadline before DB observation')
        budget=min(10,remaining)
        try:
            process=subprocess.run(helper.D+scoped_db_arguments(a.engine,arguments),input=stdin,text=True,capture_output=True,timeout=budget,env=environment)
        except subprocess.TimeoutExpired:
            raise safe_subprocess_timeout(budget) from None
        if process.returncode:raise RuntimeError('Docker observation failed: '+process.stderr.strip())
        return process.stdout.strip()
    helper.run=bounded_db_run
    def sql(query): return helper.sql(a.engine,query,database)
    def connection_counts(label):
        if a.engine=='pg':
            query="SELECT json_build_object('case_connections',count(*) FILTER(WHERE datname=current_database()),'case_active_excluding_observer',count(*) FILTER(WHERE datname=current_database() AND state='active' AND pid<>pg_backend_pid()),'server_connections',count(*),'observer_connections',count(*) FILTER(WHERE pid=pg_backend_pid())) FROM pg_stat_activity;"
        else:
            query="SELECT JSON_OBJECT('case_connections',SUM(DB=DATABASE()),'case_active_excluding_observer',SUM(DB=DATABASE() AND COMMAND<>'Sleep' AND ID<>CONNECTION_ID()),'server_connections',COUNT(*),'observer_connections',SUM(ID=CONNECTION_ID())) FROM information_schema.PROCESSLIST;"
        raw=sql(query);emit('db-connections',{'label':label,'metrics':json.loads(raw),'scope':'server/case connections; observer query explicit'})
    def kernel():
        if not a.kernel_sampler or not pid:return None
        p=subprocess.run([str(a.kernel_sampler.resolve()),'--owned-pid',str(pid)],text=True,capture_output=True,timeout=5)
        if p.returncode: raise RuntimeError('owned PID kernel sampler failed: '+p.stderr)
        return {'metrics':json.loads(p.stdout),'raw':json.loads(p.stderr)}
    def mark(name):
        nonlocal phase
        phase=name;emit('phases',{'label':name,'kernel':kernel()})
    def sampler():
        next_host=time.monotonic()
        while not stop.is_set():
            if time.monotonic()>=next_host:
                try:emit('host-load',host_observer.sample(pid))
                except BaseException as error:emit('host-load',{'observation_status':'UNAVAILABLE','error':repr(error)})
                next_host=time.monotonic()+5
            if pid:
                p=subprocess.run(['/bin/ps','-p',str(pid),'-o','%cpu=,rss=,time='],text=True,capture_output=True,timeout=2)
                values=p.stdout.split()
                if len(values)>=3: emit('rss',{'pid':pid,'proc_cpu_percent':float(values[0]),'proc_rss_bytes':int(values[1])*1024,'cpu_time':values[2]})
            with lock:emit('producer',{**producer,'queued':producer['offered']-producer['started'],'inflight':producer['started']-producer['finished']})
            stop.wait(.25)
    def db_sampler():
        next_tick=time.monotonic()
        while not stop.is_set():
            # OS views only. Main engine RSS is not PostgreSQL cluster physical RAM.
            try:
                observed=db_os_observer.observe(helper,a.engine)
                emit('db-process',{'observation_status':'AVAILABLE',**observed})
            except BaseException as error:
                emit('db-process',{'observation_status':'UNAVAILABLE','error':repr(error)})
                try:
                    with (out/'first-db-observation-failure.json').open('x') as receipt:
                        json.dump({'scope':'DB OS observer only; business outcome remains independently measured',
                                   'error':repr(error),'phase':phase},receipt,indent=2);receipt.write('\n')
                except FileExistsError:pass
                return  # Stop this observer; never read an unverified owner or invent metrics.
            next_tick+=1
            if next_tick<time.monotonic():next_tick=time.monotonic()+1  # Missed slot; no catch-up burst.
            stop.wait(max(0,next_tick-time.monotonic()))
    def request(path,data,label,offer=None):
        begin=mach.mach_absolute_time();status=None;response=None;error=None
        measured=workload_message(path,label)
        if measured:
            with lock:producer['started']+=1
        try:
            remaining=deadline-time.monotonic() if deadline and path=='/message' else 20
            if remaining<=0:raise TimeoutError('fixed lane deadline before HTTP start')
            req=urllib.request.Request('http://'+addr+path,data=json.dumps(data).encode(),method='POST',
                headers={'Content-Type':'application/json','Authorization':'Bearer '+secret})
            with urllib.request.urlopen(req,timeout=min(20,remaining)) as result:
                status=result.status;response=json.loads(result.read())
            assert status==200,(label,status,response)
            return response['data']
        except BaseException as e:
            error=repr(e);status=getattr(e,'code',status);first(error,path=path,label=label,status=status)
            failed.set();raise
        finally:
            end=mach.mach_absolute_time()
            if measured:
                with lock:producer['finished']+=1;producer['accepted']+=int(status==200 and error is None)
            emit('requests',{'path':path,'label':label,'status':status,'response':response,'error':error,
                'http_start_mach_ticks':begin,'http_end_mach_ticks':end,'latency_ms':(end-begin)*scale,
                'offer_to_http_start_ms':(begin-offer)*scale if offer is not None else None})
    def snapshot(label,raw=False):
        # One aggregate result while loaded; no full-window Gateway-side cache.
        excluded=','.join("'"+x+"'" for x in sorted(exclusion)) or "''"
        assert all(re.fullmatch('[a-f0-9]{32}',x) for x in exclusion)
        predicate='t.delivery_id NOT IN ('+excluded+')'
        states=sql('SELECT '+("json_build_object('state',state,'n',count(*))" if a.engine=='pg' else "JSON_OBJECT('state',state,'n',count(*))")+' FROM targets t WHERE '+predicate+' GROUP BY state;')
        states={r['state']:int(r['n']) for r in map(json.loads,states.splitlines())}
        result={'label':label,'states':states,'target_count':sum(states.values()),
                'durable_nonterminal':durable_nonterminal(states)}
        if raw:
            fields="'delivery_id',t.delivery_id,'device_key',t.device_key,'op_id',m.op_id,'state',t.state,'attempt_count',t.attempts,'provider',t.provider,'receipt_at',t.receipt_at"
            query='SELECT '+('json_build_object' if a.engine=='pg' else 'JSON_OBJECT')+'('+fields+') FROM targets t JOIN messages m ON m.delivery_id=t.delivery_id WHERE '+predicate+' ORDER BY m.op_id,t.device_key;'
            result['dispatch_rows']=[json.loads(line) for line in sql(query).splitlines()]
        emit('snapshots',result);return result
    def drain(expected,warm=False):
        acknowledged=set()
        for key in keys:
            seen=set();ops=set()
            while True:
                result=request('/v2/messages/pull',{'device_key':key},'pull')
                items=result['items'];ids=[r['delivery_id'] for r in items]
                assert len(ids)==len(set(ids)) and not seen.intersection(ids),('duplicate pull',key)
                seen.update(ids)
                for item in items:
                    payload=item['payload'];ops.add(payload['op_id'])
                    assert payload['body']=='x'*1024 and payload['title']==payload['op_id']
                if ids:
                    assert request('/v2/messages/pull',{'device_key':key},'pull-before-ack')==result
                    ack=request('/v2/messages/ack',{'device_key':key,'delivery_ids':ids},'ack')
                    assert ack['removed_count']==len(ids);acknowledged.update(ids)
                if not result['has_more']:break
                assert ids
            assert len(seen)==expected,(key,len(seen),expected)
            wanted={'c5:capacity:-1'} if warm else {'c5:capacity:'+str(i) for i in range(expected)}
            assert ops==wanted,('pull operation identity',key)
        return acknowledged
    def send(i,offer=None):
        if offer is not None and failed.is_set():
            with lock:producer['skipped_after_first_failure']+=1
            return None
        op='c5:capacity:'+str(i)
        return request('/message',{'ttl':int(time.time()*1000)+86400000,'channel_id':channel,
            'password':secret,'op_id':op,'title':op,'body':'x'*1024},op,offer)
    def wait_jobs(expected,label,limit,freeze_sqlaggregate=False):
        nonlocal sql_aggregate_complete_ticks,enforce_deadline,post_completion_observation_deadline
        while True:
            assert time.monotonic()<limit,('fixed drain deadline exceeded',label)
            snap=snapshot(label)
            assert time.monotonic()<limit,('fixed drain deadline exceeded during SQL snapshot',label)
            assert not any(snap['states'].get(k) for k in ('permanent_failed','expired','cancelled')),('terminal target failure',snap)
            if snap['target_count']==expected and snap['states']=={'provider_accepted':expected}:
                if freeze_sqlaggregate:
                    tick=mach.mach_absolute_time()
                    assert time.monotonic()<limit,('fixed drain deadline exceeded before SQL aggregate marker',label)
                    sql_aggregate_complete_ticks=tick
                    enforce_deadline=False
                    validation_limit=time.monotonic()+10
                    post_completion_observation_deadline=validation_limit
                    try:
                        mark('SQLaggregate_complete_before_cutoff')
                        result=snapshot(label+'-verified',True)['dispatch_rows']
                        assert time.monotonic()<validation_limit,('identity witness validation exceeded10s',label)
                    finally:post_completion_observation_deadline=None
                    return result
                result=snapshot(label+'-verified',True)['dispatch_rows']
                assert time.monotonic()<limit,('fixed drain deadline exceeded during identity witness',label)
                return result
            time.sleep(min(1,max(0,limit-time.monotonic())))
    class Delayed(c3_mock.Handler):
        def reply(self,status,data):
            if self.path.startswith(('/v1/projects/','/3/device/')):time.sleep(.020)
            return super().reply(status,data)
    try:
        emit('host-load',host_observer.sample())
        peer=c3_mock.C3Mock(out/'peer');peer.server.RequestHandlerClass=Delayed;peer.__enter__()
        cmd=[str(a.binary.resolve()),'--db-url',url,'--http-addr','127.0.0.1:0','--mock-endpoint',peer.endpoint,
            '--mock-token-service-endpoint',peer.endpoint,'--shared-token-env','C2_MOCK_SHARED_TOKEN',
            '--provider-budget','32','--claim-quantum','32']
        child=subprocess.Popen(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        def reader():
            nonlocal pid,addr
            with (out/'gateway.log').open('x') as f:
                for line in child.stdout:
                    f.write(line);f.flush();gateway_lines.append(line)
                    if line.startswith('READY '):
                        pid=int(re.search(r'pid=(\d+)',line)[1]);addr=re.search(r'http_addr=(\S+)',line)[1];ready.set()
        reader_thread=threading.Thread(target=reader,daemon=True);reader_thread.start()
        assert ready.wait(30),('fixture readiness failed',gateway_lines[-8:])
        sampler_thread=threading.Thread(target=sampler,daemon=True);sampler_thread.start()
        db_sampler_thread=threading.Thread(target=db_sampler,daemon=True);db_sampler_thread.start()
        connection_counts('ready');mark('ready');mark('setup')
        for i in range(16):
            platform,provider=('android','fcm') if i<8 else ('ios','apns')
            key=request('/device/register',{'platform':platform},'register-'+str(i))['device_key']
            token=format(i+20261015,'064x')
            request('/channel/device',{'device_key':key,'platform':platform,'channel_type':provider,'provider_token':token},'route-'+str(i))
            binding={'channel_name':'c5-capacity-synthetic'} if channel is None else {'channel_id':channel}
            result=request('/channel/subscribe',{'device_key':key,'password':secret,**binding},'subscribe-'+str(i))
            assert result['subscribed'];channel=result['channel_id'];keys.append(key);tokens[key]=token;providers[key]=provider
        mark('warmup');send(-1);warm=wait_jobs(16,'warmup',time.monotonic()+180)
        acknowledged=drain(1,True);assert acknowledged=={r['delivery_id'] for r in warm}
        exclusion.update(acknowledged);(out/'excluded-warmup.json').write_text(json.dumps(sorted(exclusion))+'\n')
        connection_counts('before-cold-idle');mark('cold-idle-start');time.sleep(30);mark('cold-idle-end')
        mark('offer-start');load_start=time.monotonic();deadline=load_start+10+180
        deadline_ticks=mach.mach_absolute_time()+round(190*1_000_000_000*base.denom/base.numer)
        enforce_deadline=True
        futures=[];pool=concurrent.futures.ThreadPoolExecutor(max_workers=8)
        try:
            for i in range(2560):
                if failed.is_set():raise RuntimeError('first HTTP failure stopped further offers')
                delay=load_start+i/256-time.monotonic()
                if delay>0:time.sleep(delay)
                ticks=mach.mach_absolute_time()
                emit('offers',{'op_id':'c5:capacity:'+str(i),'offer_mach_ticks':ticks,'scheduled_monotonic':load_start+i/256})
                with lock:producer['offered']+=1
                futures.append(pool.submit(send,i,ticks))
                if i%256==255:snapshot('burst-second-'+str(i//256+1))
            time.sleep(max(0,load_start+10-time.monotonic()));mark('offer-end');snapshot('offer-end')
            for future in concurrent.futures.as_completed(futures,timeout=max(.001,deadline-time.monotonic())):
                future.result()
        finally:
            pool.shutdown(wait=True,cancel_futures=True)
        mark('drain-start');final_rows=wait_jobs(len(rows['offers'])*16,'drain',deadline,freeze_sqlaggregate=True);sql_verified=True
        enforce_deadline=False
        mark('provider-commit-complete');connection_counts('after-provider-commit')
        assert all(r['attempt_count']==1 for r in final_rows),'unexpected retry'
        expected={(r['delivery_id'],r['device_key']) for r in final_rows}
        assert len(expected)==len(rows['offers'])*16
        captures=[json.loads(line) for line in (out/'peer/captures.jsonl').read_text().splitlines()]
        captures=[r for r in captures if r.get('event')=='received' and r['delivery_id'] not in exclusion]
        wire={(r['delivery_id'],r['token'],r['op_id'],r['provider']) for r in captures}
        wanted={(r['delivery_id'],tokens[r['device_key']],r['op_id'],providers[r['device_key']]) for r in final_rows}
        assert wire==wanted and len(captures)==len(wanted),'provider identity/count mismatch'
        assert all(r['data']['body']=='x'*1024 and r['data']['title']==r['op_id'] for r in captures)
        peer_requests=[json.loads(line) for line in (out/'peer/requests.jsonl').read_text().splitlines()]
        assert {r['provider'] for r in peer_requests if r.get('event')=='token_request'}=={'fcm','apns'}
        if a.engine=='mysql' and a.comparison_arm=='final-mysql':
            # Side diagnostic only, after durable/identity/wire success, before ACK.
            observation_wait_started=time.monotonic();observation_wait_until=min(deadline,observation_wait_started+1.2)
            try:
                observed_receipts=None;wanted_receipts=len(rows['offers'])*len(keys)+len(exclusion)*len(keys)
                while time.monotonic()<observation_wait_until:
                    for line in reversed(gateway_lines):
                        if line.startswith('{'):
                            data=json.loads(line)
                            if data.get('kind')=='stats':observed_receipts=data.get('receipt_commits');break
                    if observed_receipts==wanted_receipts:break
                    time.sleep(min(.02,max(0,observation_wait_until-time.monotonic())))
                if time.monotonic()>=deadline:observed_receipts=None
                waited=time.monotonic()-observation_wait_started
                query_names=json.loads((HERE/'prepared-query-hash-map.json').read_text())['query_names']
                post_completion_observation_deadline=time.monotonic()+2
                prepared=prepared_completion_observer.observe(sql,witness_targets=len(expected),offered_targets=len(rows['offers'])*len(keys),receipt_commits=observed_receipts,warmup_targets=len(exclusion)*len(keys),gateway_alive=child.poll() is None,query_names=query_names)
                prepared.update(observation_wait_seconds=waited,wait_not_target_latency=True,observation_start_after_marker='provider-commit-complete and identity/wire validation; before ack-start',observation_finished_mach_ticks=mach.mach_absolute_time(),business_deadline_mach_ticks=deadline_ticks)
            except Exception as observation_error:
                prepared={'available':False,'scope':'optional post-completion prepared-instance diagnostic','error_class':type(observation_error).__name__,'capacity_result_unchanged':True,'no_retry':True}
            finally:post_completion_observation_deadline=None
            side_observation_status={'applicable':True,'available':prepared.get('available',False),'artifact':'post-completion-prepared.json','persisted':True}
            try:(out/'post-completion-prepared.json').write_text(json.dumps(prepared,indent=2)+'\n')
            except OSError as persistence_error:
                side_observation_status.update(available=False,persisted=False,error_class=type(persistence_error).__name__)
                print(json.dumps({'kind':'side_observation_persistence_failure','phase':'post-completion-prepared','error_class':type(persistence_error).__name__}),flush=True)
        mark('ack-start');drain(len(rows['offers']));mark('ack-complete')
        remaining=int(sql('SELECT count(*) FROM targets WHERE acked_at IS NULL;'));assert remaining==0
        connection_counts('before-post-ack-idle');mark('post-ack-idle-start');time.sleep(30);mark('post-ack-idle-end')
        connection_counts('after-post-ack-idle')
    except BaseException as e:
        failure=repr(e);failed.set();first(failure)
    finally:
        enforce_deadline=False
        exit_code=None
        if child is not None:
            if child.poll() is None:os.kill(pid or child.pid,signal.SIGTERM)
            try:exit_code=child.wait(timeout=25)
            except subprocess.TimeoutExpired:
                first('shutdown deadline exceeded');child.kill();exit_code=child.wait(timeout=5);failure=failure or 'shutdown timeout'
        # After stopping the owner, preserve a stable SQL witness for partial lanes.
        # Successful pre-ACK rows remain authoritative even if ACK reclaimed them.
        if child is not None and ready.is_set() and not sql_verified:
            try:final_rows=snapshot('final-partial' if failure else 'final',True)['dispatch_rows'];sql_verified=True
            except BaseException as e:
                (out/'final-sql-failure.json').write_text(json.dumps({'error':repr(e)})+'\n')
        # Every offered operation expands across all intended device targets, even if no row exists.
        cutoff=deadline_ticks if sql_aggregate_complete_ticks is not None else (min(x for x in (deadline_ticks,failure_ticks) if x is not None) if deadline_ticks or failure_ticks else None)
        accepted_ticks={};event_record=struct.Struct('<QQQ32s32sB7x')
        if (out/'commits.bin').exists():
            with (out/'commits.bin').open('rb') as stream:
                while raw:=stream.read(event_record.size):
                    if len(raw)!=event_record.size:break  # Offline reducer rejects partial records.
                    ticks,attempt,sequence,delivery,device,state=event_record.unpack(raw)
                    if state in (1,2,3,4):
                        identity_key=(delivery.decode('ascii'),device.decode('ascii'))
                        accepted_ticks[identity_key]=min(ticks,accepted_ticks.get(identity_key,ticks))
        callback_outcomes={}
        with (out/'expected-targets.jsonl').open('x') as f:
            for row in expected_target_rows(rows['offers'],keys,final_rows,rows['requests'],accepted_ticks,cutoff):
                callback_outcomes[row['final_outcome']]=callback_outcomes.get(row['final_outcome'],0)+1
                f.write(json.dumps(row)+'\n')
        if sql_aggregate_complete_ticks is not None and callback_outcomes.get('accepted',0)!=len(rows['offers'])*len(keys):
            failure=failure or 'in-window successful callback coverage incomplete';first(failure)
        stop.set()
        for thread in (sampler_thread,db_sampler_thread,reader_thread):
            if thread:thread.join(timeout=5)
        if peer:peer.__exit__(None,None,None)
        observer=out/'commits.observer.json'
        if observer.exists():
            telemetry=json.loads(observer.read_text());telemetry.update(mach_numer=base.numer,mach_denom=base.denom,
                expected_targets=len(rows['offers'])*len(keys),planned_targets=40960,final_sql_verified=sql_verified,
                excluded_acknowledged_warmup_ids=sorted(exclusion),workload_passed=failure is None,
                measurement_cutoff_mach_ticks=cutoff,absolute_deadline_mach_ticks=deadline_ticks,
                first_failure_mach_ticks=failure_ticks,SQLaggregate_complete_before_cutoff_mach_ticks=sql_aggregate_complete_ticks)
            (out/'telemetry.json').write_text(json.dumps(telemetry,indent=2)+'\n')
        clean=bool(gateway_lines and any(re.search(r'^SHUTDOWN .*joined=[1-9][0-9]* panicked=0 aborted=0 http_timed_out=false',line) for line in gateway_lines))
        if exit_code!=0 or not clean:
            failure=failure or 'fixture exit/SHUTDOWN not clean';first(failure,exit_code=exit_code)
        if any(thread and thread.is_alive() for thread in (sampler_thread,db_sampler_thread,reader_thread)):
            failure=failure or 'observer thread not joined';first(failure)
        result={'failure':failure,'SQLaggregate_complete_before_cutoff_mach_ticks':sql_aggregate_complete_ticks,'callback_outcomes':callback_outcomes,'side_observation':side_observation_status,'exit_code':exit_code,'offered_messages':len(rows['offers']),
            'planned_messages':2560,'offered_targets':len(rows['offers'])*len(keys),'planned_targets':40960,
            'producer_final':producer,'final_sql_verified':sql_verified,'clean_shutdown':clean,
            'admission_queue_wait':quantiles([r['offer_to_http_start_ms'] for r in rows['requests'] if r['offer_to_http_start_ms'] is not None]),
            'message_http_latency':quantiles([r['latency_ms'] for r in rows['requests'] if r['path']=='/message' and r['label']!='c5:capacity:-1']),
            'request_failures':sum(bool(r['error']) for r in rows['requests'] if r['path']=='/message'),
            'elapsed_seconds':time.monotonic()-beginning,'no_retry':True,'deadline_extended':False,
            'quiet':True,'next_lane_allowed':failure is None}
        for f in files.values():f.close()
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    if failure:raise SystemExit(failure)
    print('COMPLETE '+str(out),flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('out','binary','db-url-file','db-helper','build-receipt','source-root','source-identity'):
        p.add_argument('--'+name,type=pathlib.Path,required=True)
    p.add_argument('--source-commit',required=True);p.add_argument('--engine',choices=('pg','mysql'),required=True)
    p.add_argument('--kernel-sampler',type=pathlib.Path,required=True)
    p.add_argument('--environment-identity',type=pathlib.Path,required=True)
    p.add_argument('--comparison-arm',choices=('baseline-c5','early-claim-fix','final-mysql','final-pg'),required=True)
    p.add_argument('--authorized-window',required=True,choices=('root-exclusive-c6',),help='Root must explicitly authorize runtime before use')
    arguments=p.parse_args()
    try:main(arguments)
    except BaseException as error:
        if arguments.out.exists() and not (arguments.out/'first-failure.json').exists():
            with (arguments.out/'first-failure.json').open('x') as receipt:
                json.dump({'scope':'runner preflight or uncaught harness failure','error':repr(error)},receipt);receipt.write('\n')
        raise
