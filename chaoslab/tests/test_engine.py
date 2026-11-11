"""The chaos engine, driven against the simulated lab with time compressed."""
import tempfile
import time
import unittest

import chaoslab.engine as engine_mod
from chaoslab.drivers import Driver, DriverError, Fault, Target
from chaoslab.drivers.sim import SimLab, run_sim_fleet
from chaoslab.engine import Engine, EngineError
from chaoslab.fleet import Fleet
from chaoslab.store import Store

FAST = {"cycles": 1, "wait": 0, "holdMin": 3, "baseline": 3, "settle": 3}


def wait_idle(engine, timeout=60):
    deadline = time.time() + timeout
    while not engine.idle():
        if time.time() > deadline:
            raise AssertionError("engine did not go idle")
        time.sleep(0.1)


class BrokenRestore(Driver):
    """A driver whose restore fails for the trial (first try and the engine's immediate retry), to
    prove the engine says so loudly and the run's cleanup still puts the target back."""
    name, label = "broken", "Broken"

    def __init__(self):
        self.down, self.fail = False, 2

    def configured(self):
        return True

    def status(self):
        return {"driver": self.name, "label": self.label}

    def discover(self):
        return [Target("b:1", self.name, "wan", "edge", "wan0")]

    def faults(self, target):
        return [Fault("admin-down", "Admin down", "down")]

    def inject(self, target, fault, ttl_s):
        self.down = True

    def restore(self, target, fault):
        if self.fail:
            self.fail -= 1
            raise DriverError("orchestrator stopped answering")
        self.down = False

    def held(self):
        return [{"driver": self.name, "what": "wan0", "how": "down"}] if self.down else []

    def restore_all(self):
        self.down = False
        return []


class EngineTest(unittest.TestCase):
    def setUp(self):
        self._grace, engine_mod.COLLECT_GRACE = engine_mod.COLLECT_GRACE, 3.5
        self.store = Store(tempfile.mkdtemp())
        self.fleet = Fleet(self.store)
        self.engine = Engine(self.store, self.fleet)

    def tearDown(self):
        engine_mod.COLLECT_GRACE = self._grace

    def sim(self):
        lab = SimLab(seed=1)
        self.engine.set_driver("sim", lab)
        run_sim_fleet(lab, self.fleet)
        time.sleep(3.5)          # let the simulated flows produce a baseline
        return lab

    def test_nothing_connected(self):
        with self.assertRaises(EngineError):
            self.engine.start(FAST)

    def test_parameter_bounds(self):
        self.engine.set_driver("sim", SimLab())
        for bad in ({"holdMin": 0}, {"holdMin": 10, "holdMax": 5}, {"selection": "alphabetical"}, {"kinds": []},
                    {"cycles": "many"}, {"wait": -1}):
            with self.assertRaises(EngineError, msg=str(bad)):
                self.engine.start(dict(FAST, **bad))
        self.assertTrue(self.engine.idle())

    def test_link_down_on_the_active_transport_is_measured(self):
        self.sim()
        self.engine.discover()
        wait_idle(self.engine)
        self.engine.start(FAST, only="sim:span:par:wan-a", fault_id="link-down")
        wait_idle(self.engine)
        trial = self.engine.trials(1)[0]
        self.assertTrue(trial["success"], trial["reason"])
        impact = trial["impact"]
        hit = [l for l in impact["legs"] if l["affected"]]
        self.assertEqual([l["dst"] for l in hit], ["par-host"])          # only the leg through that site
        self.assertGreaterEqual(impact["worstMs"], 250)                   # the simulated edge takes 0.3-0.9 s
        self.assertLessEqual(impact["worstMs"], 1100)
        self.assertEqual(self.engine.held(), [])
        actions = [r["action"] for r in self.store.rows("SELECT action FROM audit ORDER BY id")]
        for needed in ("RUN_START", "FAULT_INJECT", "FAULT_RESTORE", "TRIAL_VERDICT", "RUN_END"):
            self.assertIn(needed, actions)

    def test_one_way_delay_counts_as_impact_and_shows_its_direction(self):
        self.sim()
        self.engine.discover()
        wait_idle(self.engine)
        # +100 ms toward chi: below the simulated edge's steering threshold, so it stays for the hold.
        self.engine.start(dict(FAST, holdMin=5), only="sim:span:chi:wan-a", fault_id="delay-100", direction="down")
        wait_idle(self.engine)
        impact = self.engine.trials(1)[0]["impact"]
        leg = next(l for l in impact["legs"] if l["dst"] == "chi-host")
        self.assertTrue(leg["affected"])
        self.assertEqual(impact["worstMs"], 0)
        self.assertGreater(leg["rttShiftMs"], 60)
        self.assertGreater(leg["fault"]["fwd"] - leg["base"]["fwd"], 60)       # dal -> chi is "toward chi"
        self.assertLess(abs(leg["fault"]["rev"] - leg["base"]["rev"]), 15)

    def test_scope_is_enforced(self):
        self.engine.set_driver("sim", SimLab(seed=2))
        self.engine.discover()
        wait_idle(self.engine)
        keep = "sim:span:lon:wan-b"
        self.engine.set_scope([t.key for t in self.engine.targets if t.key != keep])
        self.engine.start(dict(FAST, cycles=3, holdMin=1, baseline=0, settle=0))
        wait_idle(self.engine)
        self.assertEqual({t["target"]["key"] for t in self.engine.trials()}, {keep})
        with self.assertRaises(EngineError):
            self.engine.set_scope(["no-such-target"])

    def test_stop_restores(self):
        lab = SimLab(seed=3)
        self.engine.set_driver("sim", lab)
        self.engine.start(dict(FAST, holdMin=120, baseline=0), )
        deadline = time.time() + 20
        while not self.engine.held() and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(len(self.engine.held()), 1)
        self.engine.stop()
        wait_idle(self.engine)
        self.assertEqual(self.engine.held(), [])
        self.assertIn("cut short", self.engine.trials(1)[0]["reason"])

    def test_failed_restore_is_loud_and_retried_at_cleanup(self):
        driver = BrokenRestore()
        self.engine.set_driver("broken", driver)
        self.engine.start(dict(FAST, holdMin=1, baseline=0, settle=0))
        wait_idle(self.engine)
        trial = self.engine.trials(1)[0]
        self.assertFalse(trial["success"])
        self.assertIn("RESTORE FAILED", trial["reason"])
        self.assertFalse(driver.down)                                     # the run's cleanup put it back
        self.assertTrue(self.store.one("SELECT 1 FROM audit WHERE action='FAULT_RESTORE' AND result='FAILED'"))

    def test_connection_cannot_change_while_holding(self):
        driver = BrokenRestore()
        self.engine.set_driver("broken", driver)
        driver.down = True
        with self.assertRaises(EngineError):
            self.engine.set_driver("broken", None)


if __name__ == "__main__":
    unittest.main()
