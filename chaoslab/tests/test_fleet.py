"""Endpoints, flows and the numbers derived from what agents report."""
import tempfile
import unittest

from chaoslab.fleet import Fleet, FleetError, summarise
from chaoslab.store import Store


def make():
    store = Store(tempfile.mkdtemp())
    return store, Fleet(store)


def enrol(fleet, name, addr):
    return fleet.enroll({"token": fleet.join_token, "instance": f"inst-{name}-0001", "name": name, "hostname": name,
                         "os": "linux", "arch": "amd64", "version": "1.0.0", "addrs": [addr]}, addr)["agent_id"]


def tx(leg, ts, sent=50, rcv=50, rtt=1000):
    return {"leg": leg, "ts": ts, "sent": sent, "rcv": rcv, "rtt": [rtt, rtt, rtt, rtt, rtt, rtt], "bytes": sent * 200}


class EnrolmentTest(unittest.TestCase):
    def test_wrong_token_is_refused(self):
        _, fleet = make()
        with self.assertRaises(PermissionError):
            fleet.enroll({"token": "nope", "instance": "abcdefgh"}, "10.0.0.1")

    def test_reinstall_keeps_identity_and_names_are_unique(self):
        _, fleet = make()
        a = enrol(fleet, "host", "10.0.0.1")
        self.assertEqual(a, enrol(fleet, "host", "10.0.0.1"))            # same instance id
        other = fleet.enroll({"token": fleet.join_token, "instance": "different-0001", "name": "host",
                              "addrs": ["10.0.0.2"]}, "10.0.0.2")
        self.assertEqual(other["name"], "host-2")

    def test_rotating_the_token_keeps_enrolled_agents(self):
        _, fleet = make()
        a = enrol(fleet, "a", "10.0.0.1")
        key = fleet.store.one("SELECT key FROM agents WHERE id=?", (a,))["key"]
        old = fleet.join_token
        self.assertNotEqual(old, fleet.rotate_token())
        self.assertFalse(fleet.token_ok(old))
        self.assertIsNotNone(fleet.authenticate(a, key))
        self.assertIsNone(fleet.authenticate(a, "wrong"))


class FlowTest(unittest.TestCase):
    def setUp(self):
        self.store, self.fleet = make()
        self.a, self.b, self.c = (enrol(self.fleet, n, f"10.0.0.{i}") for i, n in enumerate("abc", 1))

    def flow(self, **over):
        spec = {"name": "f", "topology": "ptp", "proto": "udp", "src": self.a, "dsts": [self.b]}
        spec.update(over)
        return self.fleet.create_flow(spec)

    def test_shapes_expand_to_legs(self):
        self.flow()
        self.flow(name="fan", topology="ptmp", dsts=[self.b, self.c])
        self.flow(name="mesh", topology="mesh", dsts=[self.b, self.c])
        self.assertEqual([len(f["legs"]) for f in self.fleet.flows()], [1, 2, 6])

    def test_validation(self):
        for bad in ({"dsts": [self.a]}, {"dsts": []}, {"proto": "sctp"}, {"size": 20}, {"pps": 0}, {"dscp": 64},
                    {"port": 70000}, {"name": ""}, {"topology": "ptp", "dsts": [self.b, self.c]}, {"size": 1500}):
            with self.assertRaises(FleetError, msg=str(bad)):
                self.flow(**bad)
        self.flow(size=8000, allowFragments=True)

    def test_config_pairs_sender_and_reflector(self):
        self.flow(proto="tcp", port=5001, dscp=46)
        send, reflect = self.fleet.config_for(self.a), self.fleet.config_for(self.b)
        self.assertEqual(len(send["send"]), 1)
        self.assertEqual(send["send"][0]["dst"], "10.0.0.2")
        self.assertEqual(send["reflect"], [])
        self.assertEqual(reflect["reflect"], [{"leg": send["send"][0]["leg"], "proto": "tcp", "port": 5001, "dscp": 46}])
        self.fleet.set_flow_enabled(self.fleet.flows()[0]["id"], False)
        self.assertEqual(self.fleet.config_for(self.a)["send"], [])

    def test_agent_in_use_cannot_be_removed(self):
        self.flow()
        with self.assertRaises(FleetError):
            self.fleet.remove_agent(self.b)
        self.fleet.remove_agent(self.c)

    def test_direction_split_comes_from_joining_both_ends(self):
        self.flow()
        leg = self.fleet.flows()[0]["legs"][0]["id"]
        # 50 sent, the reflector saw 40 (10 lost forward), 36 answers came back (4 lost on return).
        self.fleet.ingest(self.a, [tx(leg, 1000, 50, 36)], [], [])
        before = self.fleet.window(0, 10 ** 13)[leg]
        self.assertEqual((before["loss"], before["fwdLoss"]), (28.0, None))      # direction unknown yet
        self.fleet.ingest(self.b, [], [{"leg": leg, "ts": 1000, "rx": 40}], [])
        after = self.fleet.window(0, 10 ** 13)[leg]
        self.assertEqual((after["loss"], after["fwdLoss"], after["revLoss"]), (28.0, 20.0, 8.0))

    def test_records_from_the_wrong_agent_are_dropped(self):
        self.flow()
        leg = self.fleet.flows()[0]["legs"][0]["id"]
        self.fleet.ingest(self.c, [tx(leg, 1000)], [{"leg": leg, "ts": 1000, "rx": 1}], [])
        self.fleet.ingest(self.b, [tx(leg, 1000)], [], [])       # b reflects this leg, it does not send it
        self.assertEqual(self.fleet.window(0, 10 ** 13), {})

    def test_upload_retry_does_not_double_count(self):
        self.flow()
        leg = self.fleet.flows()[0]["legs"][0]["id"]
        for _ in range(3):
            self.fleet.ingest(self.a, [tx(leg, 1000)], [], [])
        self.assertEqual(self.fleet.window(0, 10 ** 13)[leg]["sent"], 50)

    def test_outage_open_then_closed_is_one_event(self):
        self.flow()
        leg = self.fleet.flows()[0]["legs"][0]["id"]
        self.fleet.ingest(self.a, [], [], [{"leg": leg, "start": 5_000_000_000, "end": 0, "lost": 3, "open": True}])
        self.assertTrue(self.fleet.outages(0, 9000)[leg][0]["open"])
        self.fleet.ingest(self.a, [], [], [{"leg": leg, "start": 5_000_000_000, "end": 5_730_000_000, "lost": 36}])
        got = self.fleet.outages(0, 9000)[leg]
        self.assertEqual(len(got), 1)
        self.assertEqual((got[0]["ms"], got[0]["lost"], got[0]["open"]), (730, 36, False))

    def test_agent_clock_offset_moves_records_onto_controller_time(self):
        self.flow()
        leg = self.fleet.flows()[0]["legs"][0]["id"]
        agent = self.store.one("SELECT * FROM agents WHERE id=?", (self.a,))
        self.fleet.sync(agent, {"ctl_offset_ns": 7_000_000_000, "tx": [tx(leg, 1000)]}, "10.0.0.1")
        self.assertEqual(self.store.one("SELECT ts_ms FROM samples")["ts_ms"], 1_007_000)


class SummariseTest(unittest.TestCase):
    def test_empty_seconds_do_not_poison_means(self):
        rows = [dict(tx(1, 1, 50, 50, 2000), rtt_avg=2000, rtt_min=2000, rtt_max=2000, rtt_p99=2000, rx=50),
                dict(tx(1, 2, 50, 0, 0), rtt_avg=0, rtt_min=0, rtt_max=0, rtt_p99=0, rx=0)]
        out = summarise(rows)
        self.assertEqual((out["loss"], out["fwdLoss"], out["revLoss"]), (50.0, 50.0, 0.0))
        self.assertEqual((out["rtt"], out["rttMin"]), (2.0, 2.0))


if __name__ == "__main__":
    unittest.main()
