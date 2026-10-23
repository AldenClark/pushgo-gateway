# C3 synthetic loopback peer

`c3_mock.py` is a standard-library-only test peer. It serves the existing Remote
Token Service wire protocol and captures actual candidate FCM/APNs requests. It
does not implement register, sync, ACK, route, or any gateway protocol. Native
network fault proxies forward those calls to the actual candidate.

```python
from c3_mock import C3Mock
with C3Mock(run / 'mock') as mock:  # new directory required, never overwrite
    # Candidate CLI: --mock-endpoint mock.endpoint
    #                --mock-token-service-endpoint mock.endpoint
    mock.configure({'provider': 'apns', 'token': token, 'op_id': op,
                    'hold': True, 'max_hold_seconds': 60})
    # Submit through actual candidate. Poll exact receipt within scenario bound.
    capture = mock.captures(token=token, op_id=op)[0]
    actual_apns_payload = capture['payload']
    mock.release(provider='apns', token=token, op_id=op)
```

Python `.captures(**selector)` and `.requests(**selector)` return lists. A selector
can contain `provider`, `token`, `op_id`, `delivery_id`, `after` (exclusive sequence),
and `limit` (default 100, max 256). Missing selector values are wildcards; provided
values match exactly. Returned rows are in chronological order.

The test-only HTTP control surface exists on this peer's loopback endpoint:

| Method | Path | Body or result |
| --- | --- | --- |
| GET | `/__test/captures?token=...&op_id=...&limit=100` | `{"captures":[...],"retention_limit":256}` |
| GET | `/__test/requests?provider=fcm&after=0` | `{"requests":[...],"retention_limit":256}` |
| POST | `/__test/configure` | Same rule dictionary as Python `.configure(rule)` |
| POST | `/__test/release` | Exact selector dictionary; empty object releases every active hold |

Configure queues at most 32 rules. The first matching pending rule is consumed
once per provider request, `count` defaults to 1 (max 256). `next_status` defaults
to 200 and supports 200, 401, 403, 429, 503. 401/403 send
`ExpiredProviderToken` plus `UNAUTHENTICATED`; 429 supplies `Retry-After: 1`.
`hold` defaults false. Held requests wait at most `max_hold_seconds` (default 10,
max 60), then return 503 and preserve the first hold-timeout failure. Configure
before submission and release only after observing the exact held capture.
Release affects active holds, not future requests or unconsumed rules.

Captured rows have `event: received`, provider, path, token, op_id, delivery_id,
`payload` (exact parsed JSON), `data` (FCM inner data or APNs payload), `raw_utf8`
(exact HTTP body), `wire_sha256`, bytes, selected synthetic provider headers,
sequence, unix_ms, held, and planned_status. A capture means request received;
it does not mean provider accepted. Corresponding `requests` row
`event: provider_finished` links `capture_sequence`, actual status and
response_error. A null response_error means the local HTTP write completed,
not proof the remote application consumed it.

Token requests are GET `/provider/token?provider=fcm[&force_refresh=true]` or
`/provider/token/production?provider=apns`. Responses are
`{"success":true,"data":{"token":"synthetic-c3-<provider>-<generation>","expires_in":3600,"project_id":"synthetic-c3-project"}}`.
Each actual refresh generates a new synthetic credential; token_request rows
preserve provider, path, generation and force_refresh. This exercises the
candidate's existing Remote credential owner without production credentials.

Storage is two append-only JSONL streams plus 256-row rings, per fresh scenario
directory. Request bodies are limited to 64 KiB, queries to 256 results, and
concurrent peer connections to 128. Reads have a 5-second socket timeout.
Context exit releases holds, stops and joins the server thread, joins request
threads, and closes evidence streams. Use short, bounded individual scenarios.

Standalone CLI after root runtime clearance:
`python3 -B c3_mock.py --out /absolute/new/scenario/mock [--port 0]`.
It prints endpoint/project JSON, and exits cleanly on SIGINT/SIGTERM.

Preparation validation: `python3 -B -m unittest -v test_c3_mock.py` performs only
five pure state tests, no sockets, native builds, or candidate processes. Actual
network integration remains separately gated. All data is synthetic; this is
not evidence of real FCM/APNs delivery, OS background delivery, or release readiness.
