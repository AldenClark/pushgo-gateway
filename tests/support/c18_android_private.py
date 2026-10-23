"""C18 normal Gateway + existing Android production repositories/JNI, SQLite only.

Only explicit newly-owned paths, emulator-5580 and isolated c7evidence package.
TLS inspection/drop relay is test infrastructure, never a Gateway protocol stub.
No production DB discovery, dependency fetch, system trust or persistent key write.
"""
import argparse
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
import zipfile

from c18_tls_relay import FramedTlsRelay

ROOT = Path('/Users/ethan/Repo/PushGo/gateway/build/quality-results/c18-client128-20261018')
C8 = ROOT.parent / 'c8-private48-20261015/native'
sys.path.insert(0, str(C8 / 'source'))
from device_phase_runner import Device
from synthetic_tls_material import leaf_pem_for_anonymous_pipe

ADB = '/Users/ethan/Library/Android/sdk/platform-tools/adb'
GATEWAY_SHA = '619a9ecf1630c55c72226137f8899af4e6daeb2d544e8eb3fa78ab6507fbe9a2'
PIN = 'a0ae1d2a415960eedfa166e3b9073c60eb072132e13be94a18ac58887c913e22'
PACKAGE = 'io.ethan.pushgo.c7evidence'


def sha(data): return hashlib.sha256(data).hexdigest()
def save(path, value): path.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str) + '\n')
def guard(): assert shutil.disk_usage(ROOT).free >= (4 * 1024**3 + 512 * 1024**2), 'disk reserve: STOP'
def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]


def wait(f, reason, seconds=20):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        guard()
        value = f()
        if value: return value
        time.sleep(.025)
    raise AssertionError('deadline: ' + reason)


class Product:
    def __init__(self, output):
        self.output = output
        self.db = output / 'gateway.sqlite'
        assert not self.db.exists()
        self.binary = ROOT / 'binaries/pushgo-gateway-frozen'
        assert sha(self.binary.read_bytes()) == GATEWAY_SHA
        self.http_port, self.tcp_port = port(), port()
        self.base = 'http://127.0.0.1:' + str(self.http_port)
        self.auth = secrets.token_urlsafe(24)
        self.child = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def start(self, advertised):
        fd, writer = os.pipe()
        args = [str(self.binary), '--db-url', f'sqlite://{self.db}?mode=rwc',
                '--http-addr', f'127.0.0.1:{self.http_port}', '--public-base-url', self.base,
                '--runtime-profile', 'small', '--token-service-url', 'http://127.0.0.1:1',
                '--private-transports', 'tcp', '--private-tcp-bind', f'127.0.0.1:{self.tcp_port}',
                '--private-tcp-port', str(advertised), '--private-tcp-tls-enabled',
                '--private-tls-cert', str(C8 / 'synthetic-tls-public/leaf.pem'),
                '--private-tls-key', f'/dev/fd/{fd}', '--observability-log-level', 'info']
        save(self.output / 'gateway.command.json', {'argv': args, 'sha256': GATEWAY_SHA,
             'synthetic_auth': 'process environment only', 'private_key': 'public test identity, anonymous pipe only'})
        env = {k: v for k, v in os.environ.items() if not k.startswith('PUSHGO_')}
        env['PUSHGO_TOKEN'] = self.auth
        try:
            with (self.output / 'gateway.log').open('xb') as log:
                self.child = subprocess.Popen(args, stdout=log, stderr=log, env=env, pass_fds=(fd,))
        finally: os.close(fd)
        try: os.write(writer, leaf_pem_for_anonymous_pipe())
        finally: os.close(writer)
        def ready():
            assert self.child.poll() is None, 'normal Gateway exited: inspect gateway.log'
            try: return self.request('/', None)[0] == 200
            except OSError: return False
        wait(ready, 'normal product HTTP startup')
        status, profile = self.request('/gateway/profile', None)
        assert status == 200 and profile['success']
        save(self.output / 'gateway-profile.json', profile)

    def request(self, path, raw):
        r = urllib.request.Request(self.base + path, data=raw, headers={
            'Authorization': 'Bearer ' + self.auth, 'Content-Type': 'application/json'})
        try: response = self.opener.open(r, timeout=10)
        except urllib.error.HTTPError as e: response = e
        with response:
            status, body = response.status, response.read(256 * 1024 + 1)
        assert len(body) <= 256 * 1024
        if path == '/': return status, {'ready': status == 200}
        try: value = json.loads(body)
        except json.JSONDecodeError: value = {'raw': body.decode(errors='replace')}
        return status, value

    def rows(self, sql, params=()):
        assert sql.startswith('SELECT ')
        with sqlite3.connect(self.db.as_uri() + '?mode=ro', uri=True) as c:
            c.row_factory = sqlite3.Row
            return [dict(r) for r in c.execute(sql, params)]

    def message(self, delivery):
        return self.rows('SELECT delivery_id,message_id,op_id,status,payload_bytes,length(payload_blob) AS blob_bytes,pending_targets,identity_state,expires_at,private_enqueued_count,private_rejected_count FROM ordinary_messages WHERE delivery_id=?', (delivery,))

    def targets(self, delivery):
        return self.rows('SELECT * FROM ordinary_targets WHERE delivery_id=?', (delivery,))

    def close(self):
        if self.child is None: return
        if self.child.poll() is None: self.child.send_signal(signal.SIGINT)
        code = self.child.wait(timeout=20)
        save(self.output / 'gateway.exit.json', {'pid': self.child.pid, 'exit_code': code, 'joined': True})
        assert code == 0


def decode_frame(frame):
    """Observer only: decode real postcard envelopes; never produce product frames."""
    assert 2 <= len(frame) <= 131072 and frame[1] == 0x12
    i = 2
    def integer():
        nonlocal i
        n = 0
        for shift in range(0, 70, 7):
            assert i < len(frame); b = frame[i]; i += 1; n |= (b & 127) << shift
            if not b & 128: return n
        raise AssertionError('bad observed varint')
    def string():
        nonlocal i
        n = integer(); assert n <= len(frame) - i
        s = frame[i:i+n].decode(); i += n; return s
    if frame[0] == 4:
        string(); string()
        for _ in range(4): integer()
        option = integer(); assert option in (0, 1)
        if option: integer()
        integer(); limit = integer(); wire = integer(); payload = integer()
        assert i == len(frame)
        return {'type': 'welcome', 'max_frame_bytes': limit, 'wire': wire, 'payload': payload}
    if frame[0] == 8:
        seq = integer(); delivery = string(); length = integer()
        assert length == len(frame) - i
        version = integer(); assert version == 1
        fields = {}
        for _ in range(integer()):
            key = string(); value = string(); assert key not in fields; fields[key] = value
        assert i == len(frame)
        return {'type': 'deliver', 'seq': seq, 'delivery_id': delivery, 'data': fields}
    if frame[0] == 9:
        option = integer(); assert option in (0, 1)
        if option: integer()
        delivery = string(); status = string(); assert i == len(frame)
        return {'type': 'ack', 'delivery_id': delivery, 'status': status}
    return {'type': frame[0]}


class Coordinator:
    def __init__(self, product, relay, output):
        self.p, self.relay, self.output = product, relay, output
        self.seq, self.first_error, self.cut_count = 0, None, 0
        self.accepted, self.expected = [], {}

    def frames(self):
        path = self.relay._output / 'frames.jsonl'
        result = []
        # Capture under the relay journal lock: no partial JSONL tail can be
        # mistaken for a decoder/product failure while another pump appends.
        with self.relay._lock:
            lines = path.read_text().splitlines()
        for line in lines:
            row = json.loads(line)
            if row['raw_file']:
                raw = (self.relay._output / row['raw_file']).read_bytes()
                assert sha(raw) == row['sha256'] and len(raw) == row['full_frame_bytes']
                row['decoded'] = decode_frame(raw)
            result.append(row)
        return result

    def settled(self, delivery):
        def check():
            messages = self.p.message(delivery); targets = self.p.targets(delivery)
            if len(messages) != 1: return None
            m = messages[0]
            # Normal ACK transaction removes the completed target (store.rs),
            # releases the body and retains only the original message identity.
            # Require an unexpired, unrejected delivery and an actual positive
            # client ACK; absence by expiry or a route change is not success.
            committed = (not targets and m['pending_targets'] == 0 and
                         m['payload_bytes'] == 0 and m['blob_bytes'] == 0 and
                         m['expires_at'] > time.time() * 1000 and
                         m['private_enqueued_count'] == 1 and m['private_rejected_count'] == 0)
            positive = any(f.get('decoded', {}).get('type') == 'ack' and
                           f['decoded']['delivery_id'] == delivery and
                           f['decoded']['status'] == 'ok' and not f['dropped'] for f in self.frames())
            return {'message': m, 'targets': targets, 'ack_commit_evidence': 'real positive ACK + committed target removal/body release before TTL'} if committed and positive else None
        return wait(check, 'target ACK COMMIT and body release')

    def checkpoint(self, request):
        assert self.first_error is None
        action, data = request['action'], request['data']
        if action == 'submit':
            raw = data['raw_request'].encode(); assert 0 < len(raw) <= 49152
            assert sha(raw) == data['request_sha256']; value = json.loads(raw)
            for k in ('channel_id', 'password', 'title', 'body'): assert value[k] == data[k]
            status, response = self.p.request('/message', raw)
            receipt = self.output / ('http-accept-' + value['op_id'] + '.json')
            # Freeze even failed/unexpected responses before decoding product fields.
            save(receipt, {'http_status': status, 'raw_request': raw.decode(), 'response': response})
            assert status == 200 and response['success'], response
            accepted = response['data']
            # Normal product exposes message_id, not the prototype delivery_id.
            identities = self.p.rows('SELECT delivery_id,message_id FROM ordinary_messages WHERE op_id=?', (value['op_id'],))
            assert len(identities) == 1 and identities[0]['message_id'] == accepted['message_id'], (response, identities)
            delivery = identities[0]['delivery_id']
            m = self.p.message(delivery); t = self.p.targets(delivery)
            assert len(m) == 1 and len(t) == 1 and t[0]['delivery_mode'] == 'private', (m, t)
            result = {'delivery_id': delivery, 'message_id': m[0]['message_id'], 'title': data['title'],
                      'body': data['body'], 'request_sha256': sha(raw), 'request_utf8_bytes': len(raw)}
            self.accepted.append(delivery); self.expected[delivery] = value
            save(self.output / ('http-accept-' + value['op_id'] + '.json'), {'http_status': status,
                'raw_request': raw.decode(), 'response': response, 'result': result})
        elif action == 'arm-wire-ack-loss':
            self.relay.arm_ack_drop(); result = {'armed': True, 'fault': 'drop real C->S type9 only'}
        elif action == 'wire-ack-dropped':
            delivery = data['delivery']['delivery_id']
            def dropped():
                frames = self.frames()
                found = [f for f in frames if f.get('decoded', {}).get('type') == 'ack' and f['decoded']['delivery_id'] == delivery and f['dropped']]
                return found or None
            acks = wait(dropped, 'actual ACK frame lost on wire')
            m, t = self.p.message(delivery), self.p.targets(delivery)
            assert len(t) == 1 and t[0]['acked_at'] is None and m[0]['pending_targets'] == 1 and m[0]['payload_bytes'] > 0
            result = {'dropped_actual_ack_frames': acks, 'message': m, 'targets': t, 'android_before_ack_loss': data}
        elif action in ('ack-committed', 'replay-ack-committed'):
            delivery = data.get('delivery', data)['delivery_id']; result = self.settled(delivery)
            records = self.frames()
            actual = [f for f in records if f.get('decoded', {}).get('type') == 'deliver' and f['decoded']['delivery_id'] == delivery]
            assert actual
            if action == 'replay-ack-committed':
                assert len({f['connection_seq'] for f in actual}) >= 2, 'must actually redeliver after process restart'
                assert any(f.get('decoded', {}).get('delivery_id') == delivery and f.get('decoded', {}).get('type') == 'ack' and not f['dropped'] for f in records)
            for frame in actual:
                fields = frame['decoded']['data']; original = self.expected[delivery]
                assert fields['message_id'] == result['message']['message_id']
                assert fields['body'] == original['body'] and fields['title'] == original['title']
                if 'metadata' in original: assert json.loads(fields['metadata']) == original['metadata']
            result['actual_network_deliveries'] = actual
        elif action == 'old-private-offline':
            result = wait(lambda: self.relay.snapshot() if self.relay.snapshot()['active'] == 0 else None, 'actual socket closed')
        elif action in ('connected', 'reconnected'):
            result = wait(lambda: self.relay.snapshot() if self.relay.snapshot()['active'] and self.relay.snapshot()['accepted'] > self.cut_count and self.relay.snapshot()['welcome_count'] else None, 'real TLS session with WELCOME')
        elif action == 'cut-owned-tcp-relay':
            self.cut_count = self.relay.snapshot()['accepted']; self.relay.cut(); result = {'accepted_before': self.cut_count}
        elif action == 'reject-overlimit':
            op = 'c18-over-' + uuid.uuid4().hex
            value = {'channel_id': data['channel_id'], 'password': data['password'], 'title': 'C18 over', 'body': '', 'op_id': op}
            raw = json.dumps(value, separators=(',', ':')).encode()
            value['body'] = 'x' * (49153 - len(raw)); raw = json.dumps(value, separators=(',', ':')).encode()
            assert len(raw) == 49153; before = len(self.frames())
            counts_before = [self.p.rows('SELECT count(*) AS n FROM ' + table)[0]['n']
                             for table in ('ordinary_messages', 'ordinary_targets')]
            status, response = self.p.request('/message', raw)
            save(self.output / 'http-overlimit-response.json', {'http_status': status,
                 'request_utf8_bytes': len(raw), 'request_sha256': sha(raw), 'response': response})
            assert status == 400 and response.get('success') is False
            assert response['error_code'] == 'invalid_request_body'
            assert 'length limit exceeded' in response['error']
            identities = self.p.rows('SELECT message_id FROM ordinary_messages WHERE op_id=?', (op,)); assert identities == []
            assert counts_before == [self.p.rows('SELECT count(*) AS n FROM ' + table)[0]['n']
                                     for table in ('ordinary_messages', 'ordinary_targets')]
            assert not any(f.get('decoded', {}).get('type') == 'deliver' for f in self.frames()[before:])
            result = {'status': status, 'error_code': response['error_code'], 'identity_established': False, 'target_count': 0, 'raw_request_bytes': len(raw), 'request_sha256': sha(raw), 'response': response}
        else: raise AssertionError('unimplemented checkpoint ' + action)
        self.seq += 1
        save(self.output / f'checkpoint-{self.seq:03d}-{action}.json', {'request': request, 'result': result})
        return result

    def server(self):
        owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                try:
                    assert self.path == '/checkpoint'
                    n = int(self.headers.get('Content-Length', '0')); assert 0 < n <= 256 * 1024
                    value = owner.checkpoint(json.loads(self.rfile.read(n)))
                    code, answer = 200, {'verified': True, 'data': value}
                except Exception:
                    owner.first_error = traceback.format_exc()
                    save(owner.output / 'first-checkpoint-failure.json', {'error': owner.first_error})
                    code, answer = 500, {'verified': False, 'error': owner.first_error}
                raw = json.dumps(answer, default=str).encode()
                self.send_response(code); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)
            def log_message(self, *_): pass
        return http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)


def export_room(device, output):
    output.mkdir()
    for suffix in ('', '-wal', '-shm'):
        try: data = device.call('exec-out', 'run-as', PACKAGE, 'cat', 'databases/c7_private.db' + suffix)
        except subprocess.CalledProcessError:
            assert suffix; continue
        (output / ('c7_private.db' + suffix)).write_bytes(data)
    with sqlite3.connect(output / 'c7_private.db') as source, sqlite3.connect(output / 'coherent.sqlite') as copy:
        source.backup(copy); copy.row_factory = sqlite3.Row
        result = {t: [dict(r) for r in copy.execute('SELECT * FROM ' + t)] for t in ('messages', 'inbound_delivery_ledger', 'inbound_delivery_ack_outbox')}
    save(output / 'snapshot.json', result)
    return result


def run(args):
    guard(); output = args.output.resolve(); assert output.is_relative_to(ROOT / 'runtime')
    lease = json.loads(args.lease_receipt.read_text())
    assert args.lease_receipt.resolve().is_relative_to(ROOT / 'native')
    assert lease['status'] == 'acquired' and lease['kind'] == 'emulator'
    assert lease['expires_at'] > time.time() and lease['token_held_in_caller_context']
    output.mkdir(mode=0o700); product = Product(output)
    device = Device(Path(ADB), 'emulator-5580', PACKAGE, output / 'instrumentation')
    assert device.call('shell', 'getprop', 'ro.kernel.qemu').strip() == b'1'
    identity = json.loads(args.artifact_identity.read_text())
    for key in ('main_apk', 'test_apk'):
        assert sha(Path(identity[key]).read_bytes()) == identity[key + '_sha256']
        device.call('install', '-r', '-t', identity[key], timeout=90)
    installed = device.call('shell', 'pm', 'path', PACKAGE).decode().strip().removeprefix('package:')
    raw = device.call('exec-out', 'cat', installed); assert sha(raw) == identity['main_apk_sha256']
    installed_test = device.call('shell', 'pm', 'path', PACKAGE + '.test').decode().strip().removeprefix('package:')
    assert sha(device.call('exec-out', 'cat', installed_test)) == identity['test_apk_sha256']
    with zipfile.ZipFile(io.BytesIO(raw)) as z: installed_so = sha(z.read('lib/arm64-v8a/libpushgo_quinn_jni.so'))
    assert installed_so == identity['compiler_so_sha256']
    save(output / 'installed-artifacts.json', {**identity, 'installed_so_sha256': installed_so})
    relay = FramedTlsRelay(('127.0.0.1', product.tcp_port), C8 / 'synthetic-tls-public/leaf.pem', C8 / 'synthetic-tls-public/ca.pem', leaf_pem_for_anonymous_pipe(), PIN, output / 'relay')
    server = worker = None; reverses = []; outcome = {'status': 'FAILED', 'gateway_sha256': GATEWAY_SHA}
    try:
        relay.start(); product.start(relay.port)
        checkpoints = output / 'checkpoints'; checkpoints.mkdir()
        coordinator = Coordinator(product, relay, checkpoints); server = coordinator.server()
        worker = threading.Thread(target=server.serve_forever); worker.start()
        reverses = [product.http_port, relay.port, server.server_port]
        for p in reverses: device.call('reverse', f'tcp:{p}', f'tcp:{p}')
        values = {'c7GatewayUrl': product.base, 'c7ControlUrl': f'http://127.0.0.1:{server.server_port}', 'c7GatewayToken': product.auth}
        device.call('shell', 'pm', 'clear', PACKAGE)
        device.method('c18SmallAndLargePersistBeforeWireAckLoss', values)
        device.stop(); first = export_room(device, output / 'phase1-room')
        assert len(first['messages']) == 2 and len(first['inbound_delivery_ledger']) == 2
        held = [d for d in coordinator.accepted if product.message(d)[0]['pending_targets'] == 1]
        assert len(held) == 1
        relay.allow_ack()
        device.method('c18NewProcessDeduplicatesRedeliveryAndReconnects', values)
        device.stop(); second = export_room(device, output / 'phase2-room')
        assert len(second['messages']) == 3 and len(second['inbound_delivery_ledger']) == 3
        assert all(r['ack_state'] == 'acked' for r in second['inbound_delivery_ledger'])
        for d in coordinator.accepted: coordinator.settled(d)
        frames = coordinator.frames(); welcomes = [f['decoded'] for f in frames if f.get('decoded', {}).get('type') == 'welcome']
        assert welcomes and all(w['max_frame_bytes'] == 131072 for w in welcomes)
        assert not coordinator.first_error and not relay.snapshot()['errors']
        save(output / 'decoded-actual-frames.json', frames)
        save(output / 'final-ledger.json', {d: {'message': product.message(d), 'targets': product.targets(d)} for d in coordinator.accepted})
        outcome.update(status='PASSED', actual_instrumented_methods=2, skipped=0, room_messages=3, delivery_targets=3, wire_ACK_loss_and_replay=True, client_process_restart=True, exact_large_request_bytes=49152, overlimit_request_bytes=49153, welcome_max_bytes=131072, actual_DELIVER_frame_bytes=[f['full_frame_bytes'] for f in frames if f['type'] == 8], scope='normal frozen Gateway with actual Android production client/JNI/Room/Keystore; isolated TLS inspection relay and QA CA; not OS/Provider/release acceptance')
    except BaseException:
        outcome['first_error'] = traceback.format_exc(); raise
    finally:
        errors = []
        def clean(name, f):
            try: f()
            except Exception as e: errors.append({name: repr(e)})
        clean('stop isolated app', device.stop)
        for p in reverses: clean('remove owned reverse', lambda p=p: device.call('reverse', '--remove', f'tcp:{p}'))
        if server: server.shutdown(); server.server_close()
        if worker: worker.join(5)
        clean('relay', relay.close); clean('Gateway', product.close)
        outcome['relay'] = relay.snapshot(); outcome['cleanup_errors'] = errors
        if errors: outcome['status'] = 'FAILED_CLEANUP'
        save(output / 'result.json', outcome)
    assert outcome['status'] == 'PASSED', outcome


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True); parser.add_argument('--artifact-identity', type=Path, required=True); parser.add_argument('--lease-receipt', type=Path, required=True)
    run(parser.parse_args())
