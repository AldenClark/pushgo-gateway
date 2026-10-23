#!/usr/bin/env python3
"""Fresh candidate + captured provider wakeup + unchanged application-controller, two processes.
Deliberate proxy ACK failure is one-time durability calibration, never an assertion retry.
"""
import argparse, hashlib, http.server, json, os, pathlib, re, signal, sqlite3
import subprocess, threading, time, urllib.request, urllib.error
p = argparse.ArgumentParser()
p.add_argument('--binary', required=True, type=pathlib.Path)
p.add_argument('--out', required=True, type=pathlib.Path)
a = p.parse_args()
OUT = pathlib.Path(__file__).resolve().parents[1]
run = a.out.resolve(); run.mkdir(parents=True, exist_ok=False)
db = run/'candidate.sqlite'; captures=[]; accesses=[]; lock=threading.Lock()
backend=None; child=None; pid=None; failure=None; fail_ack=True; lines=[]; exits={}
EXPECTED_TITLE='ordinary native wakeup'
EXPECTED_BODY='canonical wakeup body '+('x'*8192)
class Server(http.server.ThreadingHTTPServer):
    request_queue_size=128
    daemon_threads=True
class Provider(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_): pass
    def do_POST(self):
        raw=self.rfile.read(int(self.headers.get('Content-Length',0)))
        with lock:
            i=len(captures); captures.append(json.loads(raw)); (run/f'provider-body-{i}.json').write_bytes(raw)
        self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'{}')
def storage_at_ack(delivery):
    observed={}
    for name in ['pushgo.db','ingress.sqlite']:
        paths=list((run/'native-store').rglob(name))
        assert len(paths)==1, ('expected one isolated database',name,paths)
        with sqlite3.connect(f'file:{paths[0]}?mode=ro',uri=True) as c:
            if name=='pushgo.db':
                rows=c.execute('SELECT title,body FROM messages WHERE delivery_id=?',(delivery,)).fetchall()
                assert rows==[(EXPECTED_TITLE,EXPECTED_BODY)], ('ACK before correct canonical durability',rows)
            else:
                rows=c.execute('SELECT delivery_id,base_url,device_key,state,attempts FROM ack_outbox WHERE delivery_id=?',(delivery,)).fetchall()
                assert len(rows)==1 and rows[0][3]=='leased', ('ACK has no durable owned marker',rows)
        observed[name]={'path':str(paths[0]),'rows':rows}
    return observed
class Proxy(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_): pass
    def do_POST(self):
        raw=self.rfile.read(int(self.headers.get('Content-Length',0))); data=json.loads(raw)
        row={'path':self.path,'request':data,'unix_ms':int(time.time()*1000)}
        try:
            if self.path.endswith('/v2/messages/ack'):
                assert data['device_key']==device and data['delivery_ids']==[delivery]
                row['native_durable_at_ack']=storage_at_ack(delivery)
            if fail_ack and self.path.endswith('/v2/messages/ack'):
                status=503; body=b'{"success":false,"error":"c2 deliberate ACK transport failure"}'
                row['injected_failure']=True
            else:
                req=urllib.request.Request(backend+self.path,data=raw,headers={'Content-Type':'application/json'},method='POST')
                try:
                    with urllib.request.urlopen(req,timeout=20) as r: status,body=r.status,r.read()
                except urllib.error.HTTPError as e: status,body=e.code,e.read()
        except BaseException as e:
            row['oracle_error']=repr(e); status=500; body=b'{"success":false,"error":"native ACK oracle failed"}'
        row.update(status=status,response=body.decode())
        with lock:
            accesses.append(row); (run/'http-access.json').write_text(json.dumps(accesses,indent=2)+'\n')
        self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
provider=Server(('127.0.0.1',0),Provider); proxy=Server(('127.0.0.1',0),Proxy)
for server in [provider,proxy]: threading.Thread(target=server.serve_forever,daemon=True).start()
public=f'http://127.0.0.1:{proxy.server_port}/gateway'
env={k:v for k,v in os.environ.items() if not k.startswith(('PUSHGO_','C1_','C2_')) and k.lower() not in ['http_proxy','https_proxy','all_proxy','no_proxy','rust_log']}
env['NO_PROXY']='127.0.0.1,localhost'; ready=threading.Event()
def call(path,body):
    req=urllib.request.Request(public+path,data=json.dumps(body).encode(),headers={'Content-Type':'application/json'},method='POST')
    with urllib.request.urlopen(req,timeout=20) as r: return json.loads(r.read())['data']
def server_acked():
    with sqlite3.connect(f'file:{db}?mode=ro',uri=True) as c:
        row=c.execute('SELECT acked_at FROM targets WHERE delivery_id=? AND device_key=?',(delivery,device)).fetchone()
        if row is not None: return row[0] is not None
        retained=c.execute('SELECT payload_bytes,pending_targets FROM messages WHERE delivery_id=?',(delivery,)).fetchone()
        return retained==(0,0)
try:
    cmd=[str(a.binary.resolve()),'--db-url',f'sqlite://{db}','--http-addr','127.0.0.1:0','--mock-endpoint',f'http://127.0.0.1:{provider.server_port}','--provider-budget','32','--public-base-url',public+'///','--claim-quantum','32']
    (run/'plan.json').write_text(json.dumps({'command':cmd,'binary_sha256':hashlib.sha256(a.binary.read_bytes()).hexdigest(),'scope':'synthetic ordinary-message candidate fixture + captured APNs JSON, macOS application-controller + GRDB + two independent test processes'},indent=2)+'\n')
    child=subprocess.Popen(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    def reader():
        global backend,pid
        with (run/'fixture.log').open('w') as f:
            for line in child.stdout:
                f.write(line); f.flush(); lines.append(line)
                if line.startswith('READY '):
                    backend='http://'+re.search(r'http_addr=(\S+)',line)[1]; pid=int(re.search(r'pid=(\d+)',line)[1]); ready.set()
    rt=threading.Thread(target=reader,daemon=True); rt.start()
    assert ready.wait(25), ('fixture startup',lines[-8:])
    device=call('/device/register',{'platform':'ios'})['device_key']
    call('/channel/device',{'device_key':device,'platform':'ios','channel_type':'apns','provider_token':format(20261015,'064x')})
    password=os.urandom(16).hex()
    channel=call('/channel/subscribe',{'device_key':device,'channel_name':'C2 native ordinary wakeup','password':password})['channel_id']
    accepted=call('/message',{'channel_id':channel,'password':password,'title':EXPECTED_TITLE,'body':EXPECTED_BODY,'op_id':'c2:native:wakeup','ttl':int(time.time())+86400})
    with sqlite3.connect(f'file:{db}?mode=ro',uri=True) as c:
        delivery=c.execute('SELECT delivery_id FROM messages WHERE op_id=?',('c2:native:wakeup',)).fetchone()[0]
    until=time.monotonic()+15
    while True:
        with lock: index=next((i for i,v in enumerate(captures) if v.get('delivery_id')==delivery),None)
        if index is not None: break
        assert time.monotonic()<until, 'actual provider capture absent'
        time.sleep(.05)
    payload=captures[index]
    assert str(payload.get('provider_wakeup','')).lower() in ['1','true'], ('actual candidate emitted no wakeup; cannot synthesize one',payload)
    assert payload.get('base_url')==public, ('actual authoritative route mismatch',payload.get('base_url'),public)
    env.update(C2_EVIDENCE_DIR=str(run),C2_GATEWAY_URL=public,C2_DEVICE_KEY=device,C2_DELIVERY_ID=delivery,C2_CAPTURED_WAKEUP_PATH=str(run/f'provider-body-{index}.json'),C2_EXPECTED_TITLE=EXPECTED_TITLE,C2_EXPECTED_BODY=EXPECTED_BODY)
    for phase in ['ingest','recover']:
        env['C2_PHASE']=phase
        if phase=='recover':
            assert not server_acked(), 'failed ACK incorrectly settled server row'
            fail_ack=False
        log=run/f'apple-{phase}.log'
        with log.open('w') as f: result=subprocess.run([str(OUT/'client-evidence/run-apple-native-oracle.sh')],env=env,stdout=f,stderr=subprocess.STDOUT)
        exits[phase]=result.returncode
        assert result.returncode==0, ('native phase failed',phase,result.returncode)
        assert re.search(r'Test run with 1 test[^\n]*passed',log.read_text()), ('must execute exactly one passing test',phase)
        assert 'skipped' not in log.read_text().lower(), ('skipped native test',phase)
    obs=[json.loads((run/f'apple-{phase}-observations.json').read_text()) for phase in ['ingest','recover']]
    assert obs[0]['process_id']!=obs[1]['process_id'], 'restart must be a new test process'
    assert server_acked(), 'production successful ACK did not settle candidate target'
    assert not any('oracle_error' in row for row in accesses), 'ACK durability oracle failed'
    assert any(row.get('injected_failure') for row in accesses) and any(row['path'].endswith('/v2/messages/ack') and row['status']==200 for row in accesses)
    assert not any('/messages/ack' in row['path'] and '/v2/' not in row['path'] for row in accesses), 'legacy ACK escaped wakeup route'
except BaseException as e:
    failure=repr(e); (run/'first-failure.json').write_text(json.dumps({'failure':failure,'phase_exits':exits},indent=2)+'\n')
finally:
    if child is not None and child.poll() is None:
        os.kill(pid or child.pid,signal.SIGTERM)
        try: child.wait(timeout=25)
        except subprocess.TimeoutExpired:
            os.kill(pid or child.pid,signal.SIGKILL); child.wait(timeout=5); failure=failure or 'forced fixture kill'
    if child is not None:
        rt.join(timeout=2)
        shutdown=[line for line in lines if line.startswith('SHUTDOWN ')]
        if child.returncode!=0 or not shutdown or not re.search(r'joined=2 panicked=0 aborted=0 http_timed_out=false',shutdown[-1]): failure=failure or 'fixture shutdown incomplete'
    for server in [provider,proxy]: server.shutdown(); server.server_close()
    (run/'result.json').write_text(json.dumps({'failure':failure,'phase_exits':exits,'fixture_exit':child.returncode if child else None,'scope':'application-controller host entry + disk GRDB + durable ACK + two-process recovery; synthetic provider, no real APNs/OS background'},indent=2)+'\n')
if failure: raise SystemExit(failure)
print('PASS: captured actual wakeup -> app controller -> canonical durability -> failed ACK -> new-process recovery',flush=True)
