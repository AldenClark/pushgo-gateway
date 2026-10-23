#!/usr/bin/env python3
"""Tiny synthetic loopback smoke; no candidate or real network."""
import argparse
import concurrent.futures
import hashlib
import json
import pathlib
import time
import urllib.error
import urllib.request

from c3_mock import C3Mock, PROJECT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=pathlib.Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    rows = []
    failure = None
    try:
        with C3Mock(args.out / 'peer') as mock:
            def request(path, body=None):
                raw = json.dumps(body).encode() if body is not None else None
                req = urllib.request.Request(mock.endpoint + path, data=raw,
                                             headers={'Content-Type': 'application/json'})
                try:
                    with urllib.request.urlopen(req, timeout=5) as response:
                        status, payload = response.status, json.load(response)
                except urllib.error.HTTPError as error:
                    status, payload = error.code, json.load(error)
                return status, payload

            for path in ['/provider/token?provider=fcm', '/provider/token?provider=fcm&force_refresh=true',
                         '/provider/token/production?provider=apns']:
                status, data = request(path)
                assert status == 200 and data['success'] and data['data']['project_id'] == PROJECT
                rows.append({'token_path': path, 'token': data['data']['token']})
            assert len({r['token'] for r in rows}) == 3
            data = {'op_id': 'synthetic-smoke-op', 'delivery_id': 'synthetic-smoke-delivery',
                    'title': 'synthetic', 'body': 'actual-wire'}
            fcm = {'message': {'token': 'synthetic-smoke-token', 'data': data}}
            fcm_path = f'/v1/projects/{PROJECT}/messages:send'
            for planned_status in [401, 429, 503]:
                assert request('/__test/configure', {'provider': 'fcm', 'next_status': planned_status})[0] == 200
                status, response = request(fcm_path, fcm)
                assert status == planned_status
                rows.append({'planned_status': planned_status, 'status': status})
            assert request(fcm_path, fcm)[0] == 200
            assert request('/__test/configure', {'provider': 'apns', 'hold': True,
                                                'token': 'synthetic-apns', 'op_id': data['op_id'],
                                                'max_hold_seconds': 5})[0] == 200
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(request, '/3/device/synthetic-apns', data)
                deadline = time.monotonic() + 2
                while not mock.captures(provider='apns', token='synthetic-apns', op_id=data['op_id']):
                    assert time.monotonic() < deadline, 'held capture missing'
                    time.sleep(.01)
                assert not pending.done(), 'hold did not suspend provider response'
                code, captured = request('/__test/captures?provider=apns&token=synthetic-apns&op_id=synthetic-smoke-op&limit=1')
                assert code == 200 and captured['captures'][0]['payload'] == data
                assert request('/__test/release', {'provider': 'apns', 'token': 'wrong'})[1]['released'] == 0
                assert not pending.done()
                assert request('/__test/release', {'provider': 'apns', 'token': 'synthetic-apns'})[1]['released'] == 1
                assert pending.result(timeout=3)[0] == 200
            requests = request('/__test/requests?limit=100')[1]['requests']
            finished = [r for r in requests if r['event'] == 'provider_finished']
            assert [r['status'] for r in finished] == [401, 429, 503, 200, 200]
            assert not any(r['response_error'] for r in finished)
            assert not (mock.state.out / 'first-failure.json').exists()
            rows.append({'provider_finished_statuses': [r['status'] for r in finished],
                         'capture_count': len(mock.captures(limit=256))})
    except BaseException as error:
        failure = repr(error)
        with (args.out / 'first-failure.json').open('x') as stream:
            json.dump({'failure': failure}, stream)
    source = pathlib.Path(__file__).with_name('c3_mock.py')
    (args.out / 'result.json').write_text(json.dumps({'failure': failure, 'observations': rows,
        'peer_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'scope': 'tiny synthetic loopback HTTP only; no candidate or native runtime'}, indent=2) + '\n')
    if failure:
        raise SystemExit(failure)
    print('PASS: synthetic token protocol, exact capture, bounded hold/release and 401/429/503 wire responses')


if __name__ == '__main__':
    main()
