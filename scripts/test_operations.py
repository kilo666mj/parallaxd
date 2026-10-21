import copy
import datetime as dt
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("operations", Path(__file__).with_name("check-operations.py"))
ops = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ops)


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime.now(dt.timezone.utc)
        self.d = {
            "generated_at": self.now.isoformat(),
            "ha": {"role": "primary", "active": True, "promoted": False},
            "result_queue": {"depth": 0},
            "notifications": {"pending": 0},
            "history": {}, "rejected_results": {"bad_signature": 2},
            "assignments": [{"effective_owner": "a"}],
        }
        self.mesh = {"Reporting": ["a", "b"], "Isolated": [], "Partitioned": False}
        self.cfg = {"probers": [{"name": "a"}, {"name": "b"}]}

    def check(self, previous=None):
        docs = {"/v1/diagnostics": self.d, "/v1/mesh": self.mesh, "/v1/status": []}
        return ops.inspect_coordinator(docs.__getitem__, self.cfg, self.now, previous)[0]

    def test_fleet_requires_every_configured_prober(self):
        self.assertEqual(self.check(), [])
        self.mesh["Reporting"] = ["a"]
        self.assertTrue(self.check())

    @patch.object(ops.time, "sleep")
    def test_result_processing_can_drain_without_alerting(self, sleep):
        busy = copy.deepcopy(self.d)
        busy["result_queue"] = {"depth": 1, "capacity": 128}
        samples = iter([busy, self.d])

        def get(path):
            if path == "/v1/diagnostics":
                return next(samples)
            return {"/v1/mesh": self.mesh, "/v1/status": []}[path]

        failures, _ = ops.inspect_coordinator(get, self.cfg, self.now, None)
        self.assertEqual(failures, [])
        sleep.assert_called_once_with(1)

        # A draining queue must not clear unrelated errors in the first snapshot.
        busy["history"]["last_error"] = "private failure detail"
        samples = iter([busy, self.d])
        failures, _ = ops.inspect_coordinator(get, self.cfg, self.now, None)
        self.assertEqual(failures, ["history persistence reports an error"])

    @patch.object(ops.time, "sleep")
    def test_persistent_result_backlog_still_fails(self, sleep):
        self.d["result_queue"] = {"depth": 1, "capacity": 128}
        self.assertEqual(self.check(), [
            "result queue did not drain after 45 one-second rechecks (depth=1, capacity=128)"
        ])
        self.assertEqual(sleep.call_count, 45)

    @patch.object(ops.time, "sleep")
    def test_queue_can_drain_on_final_recheck(self, sleep):
        busy = copy.deepcopy(self.d)
        busy["result_queue"]["depth"] = 1
        samples = iter([busy] * 44 + [self.d])
        self.assertIsNone(ops.result_queue_failure(lambda _: next(samples), busy, self.now))
        self.assertEqual(sleep.call_count, 45)

    @patch.object(ops.time, "sleep")
    def test_queue_confirmation_requires_fresh_reachable_diagnostics(self, sleep):
        self.d["result_queue"]["depth"] = 1
        stale = copy.deepcopy(self.d)
        stale["result_queue"]["depth"] = 0
        stale["generated_at"] = "2000-01-01T00:00:00Z"
        self.assertEqual(ops.result_queue_failure(lambda _: stale, self.d, self.now),
                         "stale diagnostics while checking result queue")
        def unavailable(_):
            raise OSError("unreachable")
        with self.assertRaises(OSError):
            ops.result_queue_failure(unavailable, self.d, self.now)

    @patch.object(ops.time, "sleep")
    def test_empty_queue_needs_no_rechecks(self, sleep):
        self.assertEqual(self.check(), [])
        sleep.assert_not_called()

    def test_errors_and_rejection_increases_fail(self):
        self.assertTrue(self.check({"bad_signature": 1}))
        self.assertTrue(self.check({}))  # first occurrence of a rejection reason
        self.assertFalse(self.check({"bad_signature": 3}))  # process restarted
        self.d["notifications"]["destinations"] = {"sink": {"last_error": "secret"}}
        errors = self.check()
        self.assertTrue(errors)
        self.assertNotIn("secret", str(errors))

    def test_standby_requires_fresh_unpromoted_replica(self):
        self.cfg["ha"] = {"role": "standby"}
        self.d["ha"] = {"role": "standby", "active": False, "promoted": False,
                        "last_replica_sync": self.now.isoformat()}
        self.assertFalse(self.check())
        original = copy.deepcopy(self.d["ha"])
        for changes in ({"active": True}, {"promoted": True},
                        {"replication_lag_ms": 120001},
                        {"last_replica_sync": "2000-01-01T00:00:00Z"}):
            self.d["ha"] = dict(original, **changes)
            self.assertTrue(self.check())

    def test_watcher_startup_without_heartbeat_is_not_healthy(self):
        with self.assertRaises(KeyError):
            ops.inspect_watcher(lambda _: {"alive": True}, self.now, 120)
        state = {"alive": True, "last": {"at": self.now.isoformat()}}
        self.assertFalse(ops.inspect_watcher(lambda _: state, self.now, 120))
        state["last"]["at"] = "2000-01-01T00:00:00Z"
        self.assertTrue(ops.inspect_watcher(lambda _: state, self.now, 120))


if __name__ == "__main__":
    unittest.main()
