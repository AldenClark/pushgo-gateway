"""Bounded C8 Windows production host TCP/TLS adapter; no runtime on import.

Fresh SQLite only. Existing native fixture supplies exact Gateway, bounded mock,
public certificates and synthetic key memory->anonymouspipe. No Android/PG/MySQL
runtime, system trust, cert regeneration, alternate parser/store/ACK decision.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request

C8 = Path(__file__).resolve().parents[2]
WINDOWS = C8 / "windows"
WORKTREE = C8.parent / "c7-private-frame64-20261015/worktrees/pushgo-windows"
NATIVE = C8 / "native/source"
sys.path.insert(0, str(NATIVE))
from actual_case_driver import ActualCandidate, ActualStore, C3Mock, encode
from private_native_coordination import OpaqueTlsRelay, trigger_statements, wait_fact


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    with path.open("x") as f:
        json.dump(value, f, indent=2, default=encode)
        f.write("\n")


def raw_request(candidate, raw):
    request = urllib.request.Request(candidate.base + "/message", data=raw,
              headers={"Content-Type": "application/json", "Authorization": "Bearer " + candidate.auth})
    with urllib.request.urlopen(request, timeout=10) as response:
        value = json.loads(response.read())
    assert value["success"] is True
    return value["data"]


def legal_input(channel, password, kind):
    # Same boundary shape as Gateway legal_http_input_at_size, not a larger API.
    value = {"channel_id": channel, "password": password, "title": "x", "body": "", "op_id": "private-wire-boundary"}
    if kind == "numeric-metadata":
        value["metadata"] = None
    base = json.dumps(value, separators=(",", ":"), sort_keys=True)
    if kind == "numeric-metadata":
        entries = []
        while True:
            entries.append('"%x":1e15' % len(entries))
            raw = base.replace('"metadata":null', '"metadata":{' + ','.join(entries) + '}')
            if len(raw) > 49152:
                entries.pop()
                break
        base = base.replace('"metadata":null', '"metadata":{' + ','.join(entries) + '}')
    raw = base.replace('"body":""', '"body":"' + 'x' * (49152 - len(base)) + '"').encode()
    assert len(raw) == 49152
    return raw


def client_rows(root):
    path = root / "private.sqlite"
    if not path.is_file():
        return []
    db = sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True, timeout=5)
    try:
        db.row_factory = sqlite3.Row
        return [dict(row) for row in db.execute("SELECT * FROM messages ORDER BY id")]
    finally:
        db.close()


def target(store, delivery):
    rows = store.rows("SELECT * FROM targets WHERE delivery_id=?", (delivery,))
    assert len(rows) == 1
    return rows[0]


def message(store, delivery):
    rows = store.rows("SELECT * FROM messages WHERE delivery_id=?", (delivery,))
    assert len(rows) == 1
    return rows[0]


def remote_ack(store, delivery, expected_message_id):
    # Real ACK COMMIT may reclaim the nonrunning target in the same transaction.
    # Absence alone is insufficient: retained immutable message identity, sent
    # status and released shared counters/payload must agree, with no unACK row.
    rows = store.rows("SELECT * FROM targets WHERE delivery_id=?", (delivery,))
    msg = message(store, delivery)
    committed = (msg['message_id'] == expected_message_id and msg['status'] == 'sent'
                 and msg['pending_targets'] == 0 and msg['payload_bytes'] == 0
                 and all(row['acked_at'] is not None for row in rows))
    return {"delivery_id": delivery, "remote_ack_committed": True, "targets": rows, "message": msg} if committed else None


class Client:
    def __init__(self, binary, root, cfg, phase, gate=None):
        self.root, self.phase = root, phase
        root.mkdir(exist_ok=True)
        (root / "C7_SYNTHETIC_PRIVATE_HOST").touch()
        cfg = dict(cfg, owned_directory=str(root), phase=phase, deadline_seconds=60)
        if gate is not None:
            cfg['before_ack_gate_seconds'] = gate
        path = root / (phase + '-config.json')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            json.dump(cfg, f)
        self.log_path = root / (phase + '-client.log')
        self.log = self.log_path.open('xb')
        self.process = subprocess.Popen([str(binary), str(path)], stdout=self.log, stderr=subprocess.STDOUT)

    def fact(self, suffix):
        path = self.root / (self.phase + suffix)
        def check():
            if path.is_file():
                return json.loads(path.read_text())
            assert self.process.poll() is None, 'client exited before witness; see owned log'
            return None
        return wait_fact(check, suffix, 15)

    def kill_at_gate(self):
        witness = self.fact('-before-ack.json')
        assert witness['pid'] == self.process.pid and witness['actual_production_decision'] == 'AckOk'
        assert not (self.root / (self.phase + '-gate-invalid.txt')).exists()
        self.process.kill()
        assert self.process.wait(10) == -signal.SIGKILL
        self.log.close()
        return witness

    def stop(self, expect_success=True):
        if self.process.poll() is None:
            (self.root / (self.phase + '-stop')).touch()
            try:
                self.process.wait(15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(10)
                raise AssertionError('owned client failed joined shutdown')
        self.log.close()
        receipt = json.loads((self.root / (self.phase + '-result.json')).read_text())
        if expect_success:
            assert self.process.returncode == 0 and receipt['welcome_received'] and receipt['message_persisted'] and not receipt['test_gate_failed']
        return receipt


def setup(candidate, store, output, kind):
    # Exact production Windows registration. No Android/MQTT alias or preseed.
    try:
        registered = candidate.request('POST', '/device/register', {'platform': 'windows'})
    except urllib.error.HTTPError as error:
        save(output / 'windows-register-first-http.json', {'request': {'platform': 'windows'}, 'status': error.code, 'response': error.read().decode()})
        raise AssertionError(f'production Windows registration rejected HTTP {error.code}') from error
    save(output / 'windows-register-first-http.json', {'status': 200, 'response': registered})
    device = registered['device_key']
    route = candidate.request('POST', '/channel/device', {'device_key': device, 'platform': 'windows', 'channel_type': 'private'})
    password = os.urandom(16).hex()
    channel = candidate.request('POST', '/channel/subscribe', {'device_key': device, 'channel_name': 'C8 Windows isolated Private', 'password': password})['channel_id']
    raw = legal_input(channel, password, kind)
    original = output / 'original-http.json'
    original.write_bytes(raw)
    accepted = raw_request(candidate, raw)
    save(output / 'http-accepted.json', {'raw_bytes': len(raw), 'raw_sha256': sha(raw), 'response': accepted, 'route': route})
    duplicate = raw_request(candidate, raw)
    assert (duplicate['message_id'], duplicate['delivery_id']) == (accepted['message_id'], accepted['delivery_id'])
    save(output / 'http-duplicate.json', duplicate)
    return device, channel, password, raw, original, accepted


def run(args):
    output = args.output.resolve()
    assert output.is_relative_to(WINDOWS)
    assert args.gateway.resolve().is_relative_to(C8 / 'binaries')
    assert sha(args.gateway.read_bytes()) == args.gateway_sha256
    output.mkdir(parents=True, exist_ok=False)
    result = {'status': 'FAILED', 'mode': args.mode, 'kind': args.kind, 'gateway_sha256': args.gateway_sha256, 'scope': 'actual Windows production Rust host TCP TLS + SQLite; Windows OS NOTRUN'}
    candidate = relay = None
    clients = []
    store = ActualStore('sqlite', None, output)
    fault = False
    try:
        with C3Mock(output / 'bounded-provider') as peer:
            label = args.mode if args.mode in ('wrong-ca', 'wrong-host') else 'leaf'
            candidate = ActualCandidate(args.gateway, args.gateway_sha256, store, peer, output, label)
            candidate.start()
            if args.mode == 'bootstrap':
                try:
                    registered = candidate.request('POST', '/device/register', {'platform': 'windows'})
                except urllib.error.HTTPError as error:
                    save(output / 'windows-register-first-http.json', {'status': error.code, 'response': error.read().decode()})
                    raise
                save(output / 'windows-register-first-http.json', registered)
                result['status'] = 'PASSED'
                return result
            device, channel, password, raw, original, accepted = setup(candidate, store, output, args.kind)
            relay = OpaqueTlsRelay(('127.0.0.1', candidate.tcp_port))
            relay.start()
            certs = json.loads((C8 / 'native/synthetic-tls-public/public-identities.json').read_text())['identities']
            pin = certs[label]['der_sha256'] if args.mode != 'wrong-pin' else '0' * 64
            cfg = {'synthetic_private_host': True, 'base_url': candidate.base, 'device_key': device, 'token': candidate.auth, 'tcp_port': relay.port, 'tls_host': 'localhost', 'cert_pin_sha256': pin, 'expected_message_id': accepted['message_id'], 'expected_delivery_id': accepted['delivery_id'], 'expected_body_sha256': sha(json.loads(raw)['body'].encode()), 'expected_http_request_path': str(original)}
            binary = WINDOWS / 'binaries' / ('c8-windows-host-normal-fded360' if args.mode == 'normal-reject' else 'c8-windows-host-qa-fded360')
            result['client_sha256'] = sha(binary.read_bytes())
            freeze_label = 'normal' if args.mode == 'normal-reject' else 'qa'
            freeze = json.loads((WINDOWS / (freeze_label + '-binary-freeze.json')).read_text())
            assert result['client_sha256'] == freeze['sha256']
            root = output / 'client'
            delivery = accepted['delivery_id']
            if args.mode in ('normal-reject', 'wrong-ca', 'wrong-host', 'wrong-pin'):
                # Fixed six-second observation, no retry of an expected failure.
                client = Client(binary, root, cfg, 'tls-negative'); clients.append(client)
                time.sleep(6)
                receipt = client.stop(expect_success=False)
                logs = client.log_path.read_text()
                save(output / 'negative-client-result.json', receipt)
                assert not receipt['welcome_received'] and not receipt['message_persisted'] and receipt['message_count'] == 0
                assert client.process.returncode != 0
                assert target(store, delivery)['acked_at'] is None
                assert message(store, delivery)['payload_bytes'] > 0
                expected = {'normal-reject': ('UnknownIssuer', 'unknown issuer'), 'wrong-ca': ('UnknownIssuer', 'unknown issuer'), 'wrong-host': ('NotValidForName', 'not valid for name'), 'wrong-pin': ('pin',)}[args.mode]
                if args.mode == 'normal-reject':
                    # Keep the first normal control's strict oracle unchanged;
                    # root expressly prohibits rerunning it to find a diagnostic.
                    assert any(word in logs for word in expected), 'actual TLS diagnostic missing; preserve first log'
                else:
                    # Distinct first controls: behavior qualification, never a
                    # claim to have independently observed the TLS failure stage.
                    assert client_rows(root) == []
                    assert relay.snapshot()['accepted'] > 0
                    retained = target(store, delivery)
                    assert retained['private_claim'] is None and retained['private_group'] is None
                    stats = candidate.stats()
                    assert stats['private_resources']['authenticated_connections'] == 0
                    assert stats['private_resources']['reserved_or_owned_work'] == 0
                    save(output / 'negative-independent-state.json', {'target': retained, 'message': message(store, delivery), 'private_resources': stats['private_resources'], 'client_rows': [], 'relay': relay.snapshot()})
                result['negative_control'] = {'receipt': receipt, 'relay': relay.snapshot(), 'failure_stage': 'UNKNOWN', 'exact_certificate_cause_independently_observed': False, 'client_diagnostic': logs, 'qualification': 'behavior rejection only; production connect budget may mask underlying TLS cause'}
            elif args.mode == 'ack-db-failure':
                store.execute_owned_fault(trigger_statements('sqlite', True)); fault = True
                client = Client(binary, root, cfg, 'db-failure'); clients.append(client)
                persisted = client.fact('-persisted.json')
                failure = candidate.wait_expected_exit(70, 'Private ACK COMMIT failed', 15)
                pending = target(store, delivery)
                assert pending['acked_at'] is None and message(store, delivery)['payload_bytes'] > 0
                save(output / 'actual-server-ack-commit-failure.json', {'gateway': failure, 'persisted': persisted, 'retained_target': pending, 'retained_message': message(store, delivery)})
                store.execute_owned_fault(trigger_statements('sqlite', False)); fault = False
                candidate.start()
                ack = wait_fact(lambda: remote_ack(store, delivery, accepted['message_id']), 'real ACK after server DB recovery', 15)
                save(output / 'actual-server-recovery-ack.json', ack)
                receipt = client.stop()
                assert receipt['message_count'] == 1
                result['client'] = receipt
            else:
                first = Client(binary, root, cfg, 'before-wire-ack', gate=30); clients.append(first)
                witness = first.fact('-before-ack.json')
                retained = target(store, delivery)
                assert retained['acked_at'] is None and message(store, delivery)['payload_bytes'] > 0
                save(output / 'pre-writer-remote-retained.json', {'target': retained, 'message': message(store, delivery), 'checkpoint': witness})
                result['kill_checkpoint'] = first.kill_at_gate()
                pull = candidate.request('POST', '/v2/messages/pull', {'device_key': device, 'delivery_id': delivery})
                ack_http = candidate.request('POST', '/v2/messages/ack', {'device_key': device, 'delivery_ids': [delivery]})
                assert pull['items'] == [] and ack_http['removed_count'] == 0
                save(output / 'private-http-capability-denied.json', {'pull': pull, 'ack': ack_http})
                second = Client(binary, root, cfg, 'restarted-process'); clients.append(second)
                ack = wait_fact(lambda: remote_ack(store, delivery, accepted['message_id']), 'real replay ACK after owned SIGKILL', 15)
                save(output / 'actual-replay-ack-committed.json', ack)
                assert len(client_rows(root)) == 1
                # Same live client survives Gateway connection loss/restart.
                physical_before = relay.snapshot()
                candidate.close()
                candidate.start()
                extra_raw = json.dumps({'channel_id': channel, 'password': password, 'op_id': 'same-process-reconnect', 'title': 'reconnect', 'body': 'same live production client after Gateway restart'}, separators=(',', ':')).encode()
                extra = raw_request(candidate, extra_raw)
                extra_ack = wait_fact(lambda: remote_ack(store, extra['delivery_id'], extra['message_id']), 'same-process reconnect and ACK', 15)
                assert second.process.poll() is None
                rows = client_rows(root)
                assert len(rows) == 2 and any(row['message_id'] == extra['message_id'] and row['body'] == json.loads(extra_raw)['body'] for row in rows)
                assert relay.snapshot()['accepted'] > physical_before['accepted']
                save(output / 'actual-same-process-reconnect.json', {'same_pid': second.process.pid, 'before': physical_before, 'after': relay.snapshot(), 'extra_accepted': extra, 'ack': extra_ack})
                receipt = second.stop()
                assert receipt['sqlite_reopened_with_message'] and receipt['message_count'] == 2
                assert receipt['body_sha256'] == cfg['expected_body_sha256']
                if args.kind == 'numeric-metadata':
                    assert receipt['metadata']['whole_value_equal']
                result['client'] = receipt
            result['status'] = 'BEHAVIOR_QUALIFIED' if args.mode in ('wrong-ca', 'wrong-host', 'wrong-pin') else 'PASSED'
    except Exception as error:
        result['first_failure'] = repr(error)
    finally:
        # Bounded cleanup of only objects created in this invocation.
        cleanup_errors = []
        for client in clients:
            if client.process.poll() is None:
                try:
                    client.stop(expect_success=False)
                except Exception as error:
                    cleanup_errors.append(repr(error))
        for label, action in [
            ('remove-owned-fault', lambda: store.execute_owned_fault(trigger_statements('sqlite', False)) if fault else None),
            ('snapshot', lambda: save(output / 'db-final-snapshot.json', store.snapshot())),
            ('client-snapshot', lambda: save(output / 'client-final-snapshot.json', client_rows(output / 'client'))),
            ('gateway-resource-stats', lambda: save(output / 'gateway-resource-stats.json', candidate.stats()) if candidate and candidate.process and candidate.process.poll() is None else None),
            ('relay-close', lambda: relay.close() if relay else None),
            ('gateway-close', lambda: candidate.close() if candidate else None),
        ]:
            try:
                value = action()
                if label == 'gateway-close':
                    result['gateway_quiet'] = value
            except Exception as error:
                cleanup_errors.append({'operation': label, 'error': repr(error)})
        if relay:
            result['relay'] = relay.snapshot()
        result['client_pids'] = [{'pid': c.process.pid, 'exit': c.process.returncode} for c in clients]
        result['cleanup_errors'] = cleanup_errors
        if cleanup_errors:
            result['status'] = 'FAILED'
        save(output / 'result.json', result)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--gateway', type=Path, required=True)
    ap.add_argument('--gateway-sha256', required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--mode', choices=['bootstrap', 'positive', 'ack-db-failure', 'normal-reject', 'wrong-ca', 'wrong-host', 'wrong-pin'], required=True)
    ap.add_argument('--kind', choices=['text', 'numeric-metadata'], default='text')
    args = ap.parse_args()
    result = run(args)
    print(json.dumps(result, default=encode))
    raise SystemExit(0 if result['status'] in ('PASSED', 'BEHAVIOR_QUALIFIED') else 1)


if __name__ == '__main__':
    main()
