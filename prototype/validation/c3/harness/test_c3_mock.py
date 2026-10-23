"""Pure bounded state tests only: no sockets, binaries, or native builds."""
import json
import pathlib
import tempfile
import unittest

from c3_mock import MAX_ROWS, State


class MockStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = State(pathlib.Path(self.tmp.name) / 'peer')

    def tearDown(self):
        self.state.close()
        self.tmp.cleanup()

    def begin(self, token='synthetic-device', op='synthetic-op'):
        data = {'op_id': op, 'delivery_id': 'synthetic-delivery', 'body': 'unchanged'}
        payload = {'message': {'token': token, 'data': data}}
        raw = json.dumps(payload, separators=(',', ':')).encode()
        return self.state.begin_provider('/v1/projects/synthetic-c3-project/messages:send', payload, raw, {})

    def test_exact_capture_and_receipt_link(self):
        row, status, event, _ = self.begin()
        self.assertEqual(row['payload'], json.loads(row['raw_utf8']))
        self.assertEqual(row['data']['body'], 'unchanged')
        self.assertTrue(event.is_set())
        self.state.end_provider(row, status)
        self.assertEqual(self.state.query('requests')[0]['capture_sequence'], row['sequence'])
        self.assertEqual(len(self.state.query('captures', token='wrong')), 0)

    def test_exact_one_shot_hold_release_and_failure(self):
        self.state.configure({'provider': 'fcm', 'token': 'target', 'op_id': 'op',
                              'hold': True, 'max_hold_seconds': 60, 'next_status': 429})
        _, status, event, _ = self.begin('other', 'op')
        self.assertEqual(status, 200)
        self.assertTrue(event.is_set())
        row, status, event, deadline = self.begin('target', 'op')
        self.assertEqual((status, deadline), (429, 60))
        self.assertFalse(event.is_set())
        self.assertEqual(self.state.release(provider='apns')['released'], 0)
        self.assertFalse(event.is_set())
        self.assertEqual(self.state.release(token='target')['released'], 1)
        self.assertTrue(event.is_set())
        self.state.end_provider(row, status)
        self.assertEqual(self.begin('target', 'op')[1], 200)

    def test_apns_oversized_wakeup_preserves_actual_wire(self):
        payload = {'provider_wakeup': '1', 'delivery_id': 'delivery', 'op_id': 'op', 'base_url': 'http://127.0.0.1:1'}
        raw = json.dumps(payload).encode()
        row, _, _, _ = self.state.begin_provider('/3/device/abc', payload, raw, {'apns-topic': 'synthetic'})
        self.assertEqual(row['token'], 'abc')
        self.assertEqual(row['payload'], payload)
        self.assertEqual(row['raw_utf8'].encode(), raw)

    def test_bounded_ring_and_first_failure_preserved(self):
        for i in range(MAX_ROWS + 9):
            self.state.emit('requests', {'event': 'synthetic', 'number': i})
        self.assertEqual(len(self.state.rows['requests']), MAX_ROWS)
        self.assertEqual(len(self.state.query('requests', limit=MAX_ROWS)), MAX_ROWS)
        self.state.failure('original')
        self.state.failure('later')
        self.assertEqual(json.loads((self.state.out / 'first-failure.json').read_text())['error'], 'original')
        with self.assertRaises(ValueError):
            self.state.query('requests', limit=MAX_ROWS + 1)
        with self.assertRaises(FileExistsError):
            State(self.state.out)

    def test_reject_unbounded_or_unknown_control(self):
        for rule in ({'provider': 'fcm', 'count': 257}, {'provider': 'fcm', 'max_hold_seconds': 61},
                     {'provider': 'huawei'}, {'provider': 'fcm', 'other': 1}):
            with self.assertRaises(ValueError):
                self.state.configure(rule)


if __name__ == '__main__':
    unittest.main()
