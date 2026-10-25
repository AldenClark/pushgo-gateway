import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

p = Path(__file__).with_name('normal_product_deep_pull.py')
spec = importlib.util.spec_from_file_location('normal_product_deep_pull', p)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class FrozenScopeFixtureTests(unittest.TestCase):
    def setUp(self):
        self.expected = {
            'message-z': {'op_id':'op-z','title':'title-z','body':'body-z'},
            'message-a': {'op_id':'op-a','title':'title-a','body':'body-a'},
        }
        self.rows = [dict(message_id=mid, delivery_id='delivery-'+mid[-1],
            op_id=item['op_id'], accepted_at=1, pull_owner='synthetic-device',
            delivery_mode='provider', acked_at=None,
            payload_blob=json.dumps({'entity_type':'message','title':item['title'],'body':item['body']}))
            for mid,item in self.expected.items()]

    def choose(self, rows=None):
        return fixture.choose_rows(self.rows if rows is None else rows,
            self.expected, 1, 'synthetic-device')

    def test_roles_follow_actual_native_order_without_python_tie_sort(self):
        rejected, healthy = self.choose()
        self.assertEqual([x['message_id'] for x in rejected], ['message-z'])
        self.assertEqual([x['message_id'] for x in healthy], ['message-a'])
        self.assertEqual(rejected[0]['body'], 'body-z')
        self.assertEqual(len(rejected[0]['body_sha256']), 64)

    def test_tiny_normal_fixture_has_no_rejected_role_and_completes_its_head(self):
        rejected,healthy = fixture.choose_rows(self.rows,self.expected,0,'synthetic-device')
        self.assertEqual(rejected,[])
        head={'items':[{'delivery_id':r['delivery_id']}for r in healthy],
              'has_more':False,'scan_complete':True,'next_page_token':None}
        fixture.verify_initial_head(head,healthy)
        for changed in [dict(head,items=head['items'][:1]),
                        dict(head,scan_complete=False),dict(head,next_page_token='unexpected')]:
            with self.assertRaises(AssertionError):
                fixture.verify_initial_head(changed,healthy)

    def test_missing_frozen_target_is_not_a_successful_fixture(self):
        with self.assertRaises(AssertionError):
            self.choose(self.rows[:1])

    def test_other_owner_cannot_be_claimed_as_this_scope(self):
        rows = copy.deepcopy(self.rows)
        rows[0]['pull_owner'] = 'another-device'
        with self.assertRaises(AssertionError):
            self.choose(rows)

    def test_already_acked_row_cannot_stand_for_a_rejected_obligation(self):
        rows = copy.deepcopy(self.rows)
        rows[0]['acked_at'] = 1
        with self.assertRaises(AssertionError):
            self.choose(rows)

    def test_changed_body_cannot_be_reported_as_an_exact_content_match(self):
        rows = copy.deepcopy(self.rows)
        payload = json.loads(rows[0]['payload_blob'])
        payload['body'] = 'unexpected replacement'
        rows[0]['payload_blob'] = json.dumps(payload)
        with self.assertRaises(AssertionError):
            self.choose(rows)

    def test_duplicate_delivery_cannot_inflate_the_head_count(self):
        rows = copy.deepcopy(self.rows)
        rows[1]['delivery_id'] = rows[0]['delivery_id']
        with self.assertRaises(AssertionError):
            self.choose(rows)

    def test_explicit_low_severity_must_match_the_actual_saved_payload(self):
        rows = copy.deepcopy(self.rows)
        for row in rows:
            self.expected[row['message_id']]['severity'] = 'low'
            payload = json.loads(row['payload_blob'])
            payload['severity'] = 'low'
            row['payload_blob'] = json.dumps(payload)
        rejected,healthy = self.choose(rows)
        self.assertEqual(rejected[0]['severity'],'low')
        self.assertEqual(healthy[0]['severity'],'low')
        payload['severity'] = 'normal'
        rows[-1]['payload_blob'] = json.dumps(payload)
        with self.assertRaises(AssertionError):
            self.choose(rows)


class ExactRequestBoundaryTests(unittest.TestCase):
    def test_counted_bytes_are_the_bytes_transmitted(self):
        # Empty placeholder only: this unit tests encoding, not authentication.
        # Real requests obtain their context from the existing0600 file.
        context = {'channel_id':'synthetic-channel','channel_password':''}
        for size in [49152,49153]:
            item,encoded = fixture.message_bytes(context,'synthetic-namespace',7,size)
            self.assertEqual(len(encoded),size)
            self.assertEqual(item['request_bytes'],size)
            self.assertEqual(json.loads(encoded)['body'],item['body'])
            self.assertLess(len(item['body'].encode()),49152)
            item,encoded = fixture.message_bytes(context,'synthetic-namespace',7,size,'low')
            self.assertEqual(len(encoded),size)
            self.assertEqual(json.loads(encoded)['severity'],'low')
            self.assertEqual(item['severity'],'low')

    def test_elapsed_clock_phase_has_no_fixed_wait(self):
        with patch.object(fixture.time,'time_ns',return_value=2_000_000), \
             patch.object(fixture.time,'monotonic',side_effect=[0.0,.001]), \
             patch.object(fixture.time,'sleep') as sleeping:
            fixture.next_acceptance_millisecond(1)
            sleeping.assert_not_called()

    def test_clock_rollback_or_stall_fails_instead_of_retrying_a_submission(self):
        with patch.object(fixture.time,'time_ns',return_value=1_000_000), \
             patch.object(fixture.time,'monotonic',side_effect=[0.0,3.0]), \
             patch.object(fixture.time,'sleep') as sleeping:
            with self.assertRaises(AssertionError):
                fixture.next_acceptance_millisecond(1)
            sleeping.assert_not_called()


if __name__ == '__main__':
    unittest.main()
