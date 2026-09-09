import copy
import datetime as dt
import importlib.util
from pathlib import Path
import unittest

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
