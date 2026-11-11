"""The real drivers against HTTP stand-ins for Orchestrator and Prime."""
import unittest

from chaoslab.drivers import DriverError
from chaoslab.drivers.autopod import AutopodDriver
from chaoslab.drivers.orchestrator import OrchestratorDriver

from .fakes import FakeOrchestrator, FakePrime

NOW = lambda seconds: False        # noqa: E731  a "sleep" that never waits and never reports a stop


class OrchestratorTest(unittest.TestCase):
    def setUp(self):
        self.orch = FakeOrchestrator()
        self.addCleanup(self.orch.close)
        self.driver = OrchestratorDriver(self.orch.url, token="key")
        self.driver.VERIFY_EVERY = 0

    def test_wrong_key_is_a_clear_error(self):
        with self.assertRaises(DriverError) as ctx:
            OrchestratorDriver(self.orch.url, token="wrong").probe()
        self.assertIn("401", str(ctx.exception))

    def test_discovery(self):
        self.assertIn("2 appliances", self.driver.probe())
        targets = {t.key: t for t in self.driver.discover()}
        self.assertEqual(sorted(targets), ["orch:vrrp:1.NE:10", "orch:wan:1.NE:wan0", "orch:wan:1.NE:wan1.20",
                                           "orch:wan:2.NE:wan0", "orch:wan:2.NE:wan1.20"])     # link-local skipped,
        self.assertEqual(targets["orch:wan:1.NE:wan1.20"].name, "wan1.20 (MPLS)")              # only the master listed

    def test_wan_fault_is_a_full_state_write_of_one_flag(self):
        target = next(t for t in self.driver.discover() if t.key == "orch:wan:1.NE:wan0")
        fault = self.driver.faults(target)[0]
        self.assertEqual(self.driver.precheck(target, fault), (True, ""))
        self.driver.inject(target, fault, 60)
        nepk, body = self.orch.posts[-1]
        self.assertEqual(nepk, "1.NE")
        self.assertEqual({r["ifname"]: r["admin"] for r in body["ifInfo"]}, {"wan0": False, "wan1": True, "wan1.20": True, "lan0": True})
        self.assertTrue(all("mac" in r for r in body["ifInfo"]))          # untouched fields are written back
        self.assertEqual(len(self.driver.held()), 1)
        ok, why = self.driver.precheck(target, fault)
        self.assertFalse(ok)
        self.driver.restore(target, fault)
        ok, facts = self.driver.verify(target, fault, NOW)
        self.assertTrue(ok and facts["interface_recovered"])
        self.assertEqual(self.driver.held(), [])

    def test_vrrp_failover_and_stabilisation(self):
        target = next(t for t in self.driver.discover() if t.kind == "vrrp")
        fault = self.driver.faults(target)[0]
        self.assertTrue(self.driver.precheck(target, fault)[0])
        self.driver.inject(target, fault, 60)
        facts = self.driver.after_inject(target, fault, NOW)
        self.assertTrue(facts["failover_detected"])
        self.assertEqual(facts["new_master"], "edge-2")
        self.driver.restore(target, fault)
        ok, facts = self.driver.verify(target, fault, NOW)
        self.assertTrue(ok, facts)
        self.assertTrue(facts["vrrp_stabilized"] and facts["original_master_restored"])      # preempt

    def test_restore_all(self):
        targets = [t for t in self.driver.discover() if t.kind == "wan"][:2]
        for t in targets:
            self.driver.inject(t, self.driver.faults(t)[0], 60)
        self.assertEqual(self.driver.restore_all(), [])
        self.assertTrue(all(i["admin"] for n in self.orch.ifaces.values() for i in n.values()))


class AutopodSpanTest(unittest.TestCase):
    def setUp(self):
        self.prime = FakePrime()
        self.addCleanup(self.prime.close)
        self.driver = AutopodDriver(self.prime.url, "lab1", username="eng", password="pw")

    def test_bad_password(self):
        with self.assertRaises(DriverError) as ctx:
            AutopodDriver(self.prime.url, "lab1", username="eng", password="no").probe()
        self.assertIn("login failed", str(ctx.exception))

    def test_every_span_is_a_target(self):
        self.assertIn("span API available", self.driver.probe())
        targets = self.driver.discover()
        self.assertEqual(len(targets), 8)
        self.assertIn("autopod:lab1:aus:wan-a", {t.key for t in targets})        # a branch: not possible before
        menu = self.driver.faults(targets[0])
        self.assertEqual({f.direction for f in menu}, {"", "down", "up", "both"})

    def test_impair_one_direction_then_clear(self):
        target = next(t for t in self.driver.discover() if t.key == "autopod:lab1:aus:wan-a")
        fault = next(f for f in self.driver.faults(target) if f.id == "loss-10" and f.direction == "up")
        self.driver.inject(target, fault, 240)
        method, path, body = self.prime.calls[-1]
        self.assertEqual((method, path), ("POST", "/api/v1/labs/lab1/spans/aus:wan-a/impair"))
        self.assertEqual(body, {"ttl_s": 240, "owner": "chaoslab", "up": {"loss_pct": 10}})
        self.assertEqual(self.prime.state["aus:wan-a"]["up"], {"loss_pct": 10})
        ok, facts = self.driver.verify(target, fault, NOW)
        self.assertFalse(ok)                                               # still impaired: verify must say so
        self.driver.restore(target, fault)
        ok, facts = self.driver.verify(target, fault, NOW)
        self.assertTrue(ok and facts["read_back"])
        self.assertEqual(self.driver.held(), [])

    def test_both_directions_and_link_down(self):
        target = next(t for t in self.driver.discover() if t.key == "autopod:lab1:dal:xc")
        both = next(f for f in self.driver.faults(target) if f.id == "delay-100" and f.direction == "both")
        self.driver.inject(target, both, 100)
        self.assertEqual(self.prime.state["dal:xc"]["down"], self.prime.state["dal:xc"]["up"])
        down = next(f for f in self.driver.faults(target) if f.id == "link-down")
        self.driver.inject(target, down, 99999)                             # ttl is clamped to Prime's maximum
        self.assertEqual(self.prime.calls[-1][2], {"state": "down", "ttl_s": 3600, "owner": "chaoslab"})
        self.assertEqual(self.driver.restore_all(), [])
        self.assertEqual(self.prime.state["dal:xc"]["link"], "up")

    def test_unknown_state_fails_verification(self):
        target = next(t for t in self.driver.discover() if t.key == "autopod:lab1:dal:wan-a")
        self.prime.state["dal:wan-a"]["unknown"] = ["link"]
        ok, facts = self.driver.verify(target, self.driver.faults(target)[0], NOW)
        self.assertFalse(ok)
        self.assertIn("cannot confirm", facts["reason"])

    def test_expired_session_logs_in_again_once(self):
        self.driver.probe()
        self.prime.tokens.clear()                                           # Prime restarted: sessions are gone
        self.driver.discover()
        self.assertEqual(self.prime.logins, 2)

    def test_structured_error_is_readable(self):
        target = self.driver.discover()[0]
        target.meta["span"] = "nowhere:wan-a"
        with self.assertRaises(DriverError) as ctx:
            self.driver.inject(target, self.driver.faults(target)[0], 60)
        self.assertIn("nowhere:wan-a is not a span", str(ctx.exception))


class AutopodLegacyTest(unittest.TestCase):
    def test_old_prime_is_limited_to_its_allowlist_and_one_direction(self):
        prime = FakePrime(spans=False)
        self.addCleanup(prime.close)
        driver = AutopodDriver(prime.url, "lab1", username="eng", password="pw")
        self.assertIn("no span API", driver.probe())
        targets = driver.discover()
        self.assertEqual({t.group for t in targets}, {"dal"})               # the branch and the remote site are out
        menu = driver.faults(targets[0])
        self.assertEqual({f.direction for f in menu}, {"down"})
        self.assertNotIn("link-down", {f.id for f in menu})
        fault = next(f for f in menu if f.id == "blackhole")
        driver.inject(targets[0], fault, 60)
        self.assertEqual(prime.legacy[-1], {"scope": "dal", "spec": {"isp-a": {"loss_pct": 100}}})
        driver.restore(targets[0], fault)
        self.assertEqual(prime.legacy[-1], {"scope": "dal", "profile": "clear"})


if __name__ == "__main__":
    unittest.main()
