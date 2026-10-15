#!/usr/bin/env python3
"""Synthetic loopback Token Service + FCM/APNs peer; never a gateway protocol stub."""
import argparse
import collections
import hashlib
import http.server
import json
import pathlib
import signal
import threading
import time
import urllib.parse

PROJECT = 'synthetic-c3-project'
MAX_BODY = 65536
MAX_ROWS = 256


class State:
    def __init__(self, out):
        self.out = pathlib.Path(out)
        self.out.mkdir(parents=True, exist_ok=False)
        self.lock = threading.RLock()
        self.rows = {k: collections.deque(maxlen=MAX_ROWS) for k in ('captures', 'requests')}
        self.files = {k: (self.out / (k + '.jsonl')).open('x') for k in self.rows}
        self.rules = []
        self.active = {}
        self.sequence = 0
        self.generation = 0
        self.closing = False

    def emit(self, kind, row):
        with self.lock:
            self.sequence += 1
            if row.get('event')=='received':
                data=row.get('data',{})
                row={k:v for k,v in row.items() if k not in ('payload','data','raw_utf8','headers')}
                row['provider_data_flags']={key:data.get(key) for key in ('provider_mode','provider_wakeup','_skip_persist')}
                row['field_sha256']={key:hashlib.sha256(str(value).encode()).hexdigest() for key,value in data.items() if key in ('title','body','metadata')}
            row = dict(row, sequence=self.sequence, unix_ms=int(time.time() * 1000))
            self.rows[kind].append(row)
            self.files[kind].write(json.dumps(row, sort_keys=True) + '\n')
            self.files[kind].flush()
            return row

    def failure(self, error):
        with self.lock:
            try:
                with (self.out / 'first-failure.json').open('x') as stream:
                    json.dump({'error': error, 'unix_ms': int(time.time() * 1000)}, stream)
            except FileExistsError:
                pass

    @staticmethod
    def matches(selector, row):
        return all(selector.get(k) is None or selector[k] == row.get(k)
                   for k in ('provider', 'token', 'op_id', 'delivery_id'))

    def query(self, kind, **selector):
        limit = int(selector.pop('limit', 100))
        if not 1 <= limit <= MAX_ROWS:
            raise ValueError('limit must be 1..256')
        after = int(selector.pop('after', 0))
        if set(selector) - {'provider', 'token', 'op_id', 'delivery_id'}:
            raise ValueError('unknown query selector')
        with self.lock:
            return [dict(r) for r in self.rows[kind]
                    if r['sequence'] > after and self.matches(selector, r)][-limit:]

    def configure(self, rule):
        allowed = {'provider', 'token', 'op_id', 'delivery_id', 'hold', 'max_hold_seconds', 'next_status', 'count'}
        if set(rule) - allowed or rule.get('provider') not in ('fcm', 'apns'):
            raise ValueError('provider fcm/apns and known rule fields required')
        if rule.get('next_status', 200) not in (200, 401, 403, 429, 503):
            raise ValueError('next_status must be 200/401/403/429/503')
        if not 0 < float(rule.get('max_hold_seconds', 10)) <= 60:
            raise ValueError('max_hold_seconds must be >0 and <=60')
        if type(rule.get('count', 1)) is not int or not 1 <= rule.get('count', 1) <= 256:
            raise ValueError('count must be 1..256')
        for key in ('token', 'op_id', 'delivery_id'):
            if key in rule and (not isinstance(rule[key], str) or len(rule[key]) > 512):
                raise ValueError('selectors must be strings <=512 characters')
        with self.lock:
            if len(self.rules) >= 32:
                raise ValueError('at most 32 pending rules')
            self.rules.append(dict(rule, count=rule.get('count', 1)))
        self.emit('requests', {'event': 'configure', 'rule': rule})
        return {'ok': True}

    def release(self, **selector):
        if set(selector) - {'provider', 'token', 'op_id', 'delivery_id'}:
            raise ValueError('unknown release selector')
        with self.lock:
            released = 0
            for row, event in self.active.values():
                if self.matches(selector, row):
                    event.set()
                    released += 1
        self.emit('requests', {'event': 'release', 'selector': selector, 'released': released})
        return {'ok': True, 'released': released}

    def begin_provider(self, path, payload, raw, headers):
        fcm = path.startswith('/v1/projects/') and path.endswith('/messages:send')
        apns = path.startswith('/3/device/')
        if not fcm and not apns:
            raise ValueError('unknown provider path')
        if not isinstance(payload, dict):
            raise ValueError('payload must be an object')
        data = payload.get('message', {}).get('data', {}) if fcm else payload
        if not isinstance(data, dict):
            raise ValueError('provider data must be an object')
        row = {'event': 'received', 'provider': 'fcm' if fcm else 'apns', 'path': path,
               'payload': payload, 'data': data, 'token': payload.get('message', {}).get('token') if fcm else path.rsplit('/', 1)[-1],
               'op_id': data.get('op_id'), 'delivery_id': data.get('delivery_id'),
               'raw_utf8': raw.decode(), 'wire_sha256': hashlib.sha256(raw).hexdigest(),
               'bytes': len(raw), 'headers': {k.lower(): v for k, v in headers.items()
                                            if k.lower() in ('authorization', 'apns-topic', 'apns-push-type', 'apns-priority', 'apns-expiration')}}
        with self.lock:
            rule = next((r for r in self.rules if self.matches(r, row)), {})
            status, hold = rule.get('next_status', 200), rule.get('hold', False)
            deadline = float(rule.get('max_hold_seconds', 10))
            if rule:
                rule['count'] -= 1
                if rule['count'] == 0:
                    self.rules.remove(rule)
            row = self.emit('captures', dict(row, planned_status=status, held=bool(hold)))
            event = threading.Event()
            if not hold or self.closing:
                event.set()
            self.active[row['sequence']] = (row, event)
        return row, status, event, deadline

    def end_provider(self, row, status, response_error=None):
        with self.lock:
            self.active.pop(row['sequence'], None)
            # Link to exact received capture without duplicating large bodies.
            self.emit('requests', {'event': 'provider_finished', 'capture_sequence': row['sequence'],
                                  'provider': row['provider'], 'token': row['token'], 'op_id': row['op_id'],
                                  'delivery_id': row['delivery_id'], 'status': status, 'response_error': response_error})

    def close(self):
        with self.lock:
            for stream in self.files.values():
                stream.close()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def reply(self, status, data):
        body = json.dumps(data, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        if status == 429:
            self.send_header('Retry-After', '1')
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def do_GET(self):
        state = self.server.state
        url = urllib.parse.urlsplit(self.path)
        try:
            query = urllib.parse.parse_qs(url.query, strict_parsing=True)
            if len(self.path) > 2048 or any(len(v) != 1 for v in query.values()):
                raise ValueError('query too large or repeated')
            query = {k: v[0] for k, v in query.items()}
            if url.path in ('/provider/token', '/provider/token/production'):
                provider = query.get('provider')
                if provider not in ('fcm', 'apns'):
                    raise ValueError('unknown token provider')
                with state.lock:
                    state.generation += 1
                    generation = state.generation
                state.emit('requests', {'event': 'token_request', 'path': self.path, 'provider': provider,
                                        'force_refresh': query.get('force_refresh'), 'generation': generation})
                self.reply(200, {'success': True, 'data': {'token': f'synthetic-c3-{provider}-{generation}',
                                                        'expires_in': 3600, 'project_id': PROJECT}})
            elif url.path in ('/__test/captures', '/__test/requests'):
                kind = url.path.rsplit('/', 1)[-1]
                self.reply(200, {kind: state.query(kind, **query), 'retention_limit': MAX_ROWS})
            else:
                self.reply(404, {'error': 'unknown test-peer route'})
        except (ValueError, TypeError) as error:
            self.reply(400, {'error': str(error)})

    def do_POST(self):
        state = self.server.state
        try:
            length = int(self.headers.get('Content-Length', '-1'))
            if not 0 <= length <= MAX_BODY:
                self.close_connection = True
                self.reply(413, {'error': 'body must be bounded at 65536 bytes'})
                return
            raw = self.rfile.read(length)
            payload = json.loads(raw)
            if self.path == '/__test/configure':
                self.reply(200, state.configure(payload))
                return
            if self.path == '/__test/release':
                self.reply(200, state.release(**payload))
                return
            row, status, event, deadline = state.begin_provider(self.path, payload, raw, self.headers)
        except (ValueError, TypeError, AttributeError) as error:
            self.reply(400, {'error': str(error)})
            return
        response_error = None
        try:
            if not event.wait(deadline):
                status = 503
                state.failure(f'provider hold timed out capture={row["sequence"]}')
                state.emit('requests', {'event': 'hold_timeout', 'capture_sequence': row['sequence']})
            if status in (401, 403):
                response = {'reason': 'ExpiredProviderToken', 'error': {'status': 'UNAUTHENTICATED'}}
            elif status in (429, 503):
                response = {'error': {'status': 'RESOURCE_EXHAUSTED' if status == 429 else 'UNAVAILABLE', 'message': 'synthetic C3 failure'}}
            else:
                response = {'name': f'projects/{PROJECT}/messages/synthetic'} if row['provider'] == 'fcm' else {}
            self.reply(status, response)
        except OSError as error:
            response_error = type(error).__name__
        finally:
            state.end_provider(row, status, response_error)


class Server(http.server.ThreadingHTTPServer):
    request_queue_size = 128
    daemon_threads = False
    block_on_close = True

    def __init__(self, state, port):
        self.state = state
        self.slots = threading.BoundedSemaphore(128)
        super().__init__(('127.0.0.1', port), Handler)

    def get_request(self):
        conn, address = super().get_request()
        conn.settimeout(5)
        return conn, address

    def process_request(self, request, address):
        if not self.slots.acquire(timeout=.1):
            self.shutdown_request(request)
            self.state.failure('test peer exceeded 128 concurrent connections')
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class C3Mock:
    def __init__(self, out_dir, port=0):
        self.state = State(out_dir)
        try:
            self.server = Server(self.state, port)
        except BaseException:
            self.state.close()
            raise
        self.endpoint = f'http://127.0.0.1:{self.server.server_port}'
        self.thread = None

    def __enter__(self):
        self.thread = threading.Thread(target=self.server.serve_forever, name='c3-mock-server')
        self.thread.start()
        return self

    def configure(self, rule):
        return self.state.configure(rule)

    def release(self, **selector):
        return self.state.release(**selector)

    def captures(self, **selector):
        return self.state.query('captures', **selector)

    def requests(self, **selector):
        return self.state.query('requests', **selector)

    def __exit__(self, *_):
        with self.state.lock:
            self.state.closing = True
        self.release()
        if self.thread:
            self.server.shutdown()
            self.thread.join(timeout=5)
        self.server.server_close()
        self.state.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=pathlib.Path)
    parser.add_argument('--port', type=int, default=0)
    args = parser.parse_args()
    done = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: done.set())
    with C3Mock(args.out, args.port) as mock:
        print(json.dumps({'endpoint': mock.endpoint, 'project_id': PROJECT}), flush=True)
        done.wait()


if __name__ == '__main__':
    main()
