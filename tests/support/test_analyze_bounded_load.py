"""Small deterministic oracles for the bounded-load evidence analyzer."""
import unittest

from analyze_bounded_load import backlog_sample_at_or_after, quantiles


class BoundedLoadAnalyzerTests(unittest.TestCase):
    def test_after_drain_uses_actual_sample_and_reports_its_lag(self):
        rows = [
            {"elapsed_us": 90, "data": {"pending_targets": 8}},
            {"elapsed_us": 110, "data": {"pending_targets": 0}},
        ]
        observed = backlog_sample_at_or_after(rows, 100)
        self.assertEqual(observed["pending_targets"], 0)
        self.assertEqual(observed["sample_elapsed_us"], 110)
        self.assertEqual(observed["sample_lag_us"], 10)
        self.assertEqual(backlog_sample_at_or_after(rows, 90)["pending_targets"], 8)

    def test_no_after_sample_or_no_drain_stays_unknown(self):
        rows = [{"elapsed_us": 90, "data": {"pending_targets": 8}}]
        self.assertIsNone(backlog_sample_at_or_after(rows, 100))
        self.assertIsNone(backlog_sample_at_or_after(rows, None))
        self.assertIsNone(backlog_sample_at_or_after([], 100))

    def test_quantiles_keep_the_full_planned_denominator(self):
        complete = quantiles(list(range(100)), 100)
        self.assertEqual((complete["p50_ms"], complete["p95_ms"], complete["p99_ms"]), (49, 94, 98))
        partial = quantiles(list(range(94)), 100)
        self.assertEqual((partial["samples"], partial["missing"]), (94, 6))
        self.assertEqual(partial["p50_ms"], 49)
        self.assertIsNone(partial["p95_ms"])
        self.assertIsNone(partial["p99_ms"])
        one_missing = quantiles(list(range(99)), 100)
        self.assertEqual(one_missing["p99_ms"], 98)
        mostly_missing = quantiles(list(range(40)), 100)
        self.assertIsNone(mostly_missing["p50_ms"])
        with self.assertRaises(ValueError):
            quantiles(list(range(101)), 100)


if __name__ == "__main__":
    unittest.main()
