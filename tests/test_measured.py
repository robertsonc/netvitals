"""Tests for the 1.9.0 measured-WAN tranche: the --wan-counters spec parser,
the stdlib SNMPv2c encoder/decoder round trip, the REST JSON path helper,
the simulator source's integration math, the slice-boundary detector, the
slice-loss-ratio evidence rule, and the scenario parser. No network, no
display - the SNMP test decodes bytes we build ourselves."""
import argparse
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netquality as nq  # noqa: E402


class TestWanSpec(unittest.TestCase):
    def test_sim_forms(self):
        self.assertEqual(nq._wan_spec("sim"), {"kind": "sim", "noise_pps": 0.0})
        self.assertEqual(nq._wan_spec("sim:250")["noise_pps"], 250.0)

    def test_snmp_form(self):
        spec = nq._wan_spec("snmp:10.0.0.5,public,3")
        self.assertEqual(spec, {"kind": "snmp", "host": "10.0.0.5",
                                "community": "public", "ifindex": 3,
                                "port": 161})
        self.assertEqual(nq._wan_spec("snmp:h,c,1,1161")["port"], 1161)

    def test_rest_form_with_pipes(self):
        spec = nq._wan_spec("rest:https://orch/api/if|tok123|data.tx|data.rx")
        self.assertEqual(spec["url"], "https://orch/api/if")
        self.assertEqual(spec["token"], "tok123")
        self.assertEqual(spec["tx_key"], "data.tx")
        # Defaults when only the URL is given.
        spec = nq._wan_spec("rest:http://x/y")
        self.assertIsNone(spec["token"])
        self.assertEqual(spec["rx_key"], "rx_pkts")

    def test_bad_specs_rejected(self):
        for bad in ("", "magic", "snmp:host,comm", "snmp:h,c,zero",
                    "rest:ftp://x", "sim:banana"):
            with self.assertRaises(argparse.ArgumentTypeError):
                nq._wan_spec(bad)


class TestSnmpCodec(unittest.TestCase):
    def test_get_request_encodes_and_response_decodes(self):
        oids = [f"{nq.IFHC_BASE}.11.3", f"{nq.IFHC_BASE}.7.3"]
        req = nq.snmp_build_get("public", oids, req_id=42)
        self.assertEqual(req[0], 0x30)          # outer SEQUENCE
        self.assertIn(b"public", req)
        # Build a GetResponse carrying Counter64 values using the same BER
        # primitives, then decode it.
        vb = b"".join(
            nq._ber(0x30, nq._ber_oid(o)
                    + nq._ber(0x46, v.to_bytes(8, "big")))
            for o, v in ((oids[0], 123456789012), (oids[1], 987654321)))
        pdu = nq._ber(0xA2, nq._ber_int(42) + nq._ber_int(0) + nq._ber_int(0)
                      + nq._ber(0x30, vb))
        resp = nq._ber(0x30, nq._ber_int(1)
                       + nq._ber(0x04, b"public") + pdu)
        values = nq.snmp_parse_response(resp)
        self.assertEqual(values[oids[0]], 123456789012)
        self.assertEqual(values[oids[1]], 987654321)

    def test_garbage_returns_empty(self):
        self.assertEqual(nq.snmp_parse_response(b"\xde\xad\xbe\xef"), {})
        self.assertEqual(nq.snmp_parse_response(b""), {})

    def test_oid_encoding_multibyte_arcs(self):
        # 2.1.1 header + an arc > 127 must use the continuation bit.
        oid = "1.3.6.1.2.1.31.1.1.1.11.300"
        body = nq._ber_oid(oid)
        self.assertEqual(body[0], 0x06)
        # Round-trip through the response parser's decoder.
        vb = nq._ber(0x30, body + nq._ber(0x41, b"\x01"))
        pdu = nq._ber(0xA2, nq._ber_int(1) + nq._ber_int(0) + nq._ber_int(0)
                      + nq._ber(0x30, vb))
        resp = nq._ber(0x30, nq._ber_int(1) + nq._ber(0x04, b"c") + pdu)
        self.assertIn(oid, nq.snmp_parse_response(resp))


class TestJsonPath(unittest.TestCase):
    def test_dotted_paths_and_lists(self):
        doc = {"data": {"ifaces": [{"tx": 5}, {"tx": 9}]}}
        self.assertEqual(nq._json_path(doc, "data.ifaces.1.tx"), 9)
        with self.assertRaises((KeyError, IndexError)):
            nq._json_path(doc, "data.nope")


class TestSimSource(unittest.TestCase):
    def test_integrates_rates_through_slices(self):
        # Two streams: 50 pps x 1 slice and 10 pps x 3 slices; x2 for the
        # reflected echoes -> 160 WAN pps.
        src = nq.SimWanSource(lambda: [(50.0, 1), (10.0, 3)], noise_pps=0.0)
        src.poll()
        time.sleep(0.25)
        a = src.poll()
        time.sleep(0.25)
        b = src.poll()
        rate = (b["tx_pkts"] - a["tx_pkts"]) / 0.25
        self.assertAlmostEqual(rate, 160.0, delta=32.0)  # ±2% jitter + timing


class TestSliceBoundaryDetector(unittest.TestCase):
    @staticmethod
    def staircase(budget, step_ms, noise=0.0):
        """Synthetic scan: RTT jumps step_ms at each budget multiple."""
        samples = []
        for inner in range(900, budget * 3 + 300, 32):
            slices = 1 + max(0, (inner - 1) // budget)
            rtt = 2.0 + slices * step_ms + noise * ((inner // 32) % 3 - 1)
            samples.append((inner, rtt, 0.0))
        return samples

    def test_clean_staircase_measures_the_budget(self):
        # Sizes 900..4380 cross the 1360 budget at 1360/2720/4080.
        samples = self.staircase(1360, step_ms=0.6)
        boundaries, est = nq.detect_slice_boundaries(samples)
        self.assertEqual(len(boundaries), 3)
        self.assertAlmostEqual(est, 1360, delta=48)

    def test_different_budget_is_measured_not_assumed(self):
        samples = self.staircase(1100, step_ms=0.5)
        boundaries, est = nq.detect_slice_boundaries(samples)
        self.assertGreaterEqual(len(boundaries), 2)
        self.assertAlmostEqual(est, 1100, delta=48)

    def test_flat_curve_finds_nothing(self):
        samples = [(s, 2.0 + 0.02 * ((s // 32) % 3), 0.0)
                   for s in range(900, 4300, 32)]
        boundaries, est = nq.detect_slice_boundaries(samples)
        self.assertEqual(boundaries, [])
        self.assertIsNone(est)


class TestSliceLossEvidence(unittest.TestCase):
    @staticmethod
    def row(sid, loss, tx=1000, proto="UDP", connected=True):
        return {"sid": sid, "name": f"UDP-{30201 + sid}", "proto": proto,
                "connected": connected, "loss": loss, "late": 0.0,
                "cum_tx": tx}

    def test_matching_ratio_names_the_amplification(self):
        rows = [self.row(0, 1.0), self.row(1, 2.9)]
        out = nq.slice_loss_evidence(rows, {0: 1, 1: 3}, deadband=0.5)
        self.assertIsNotNone(out)
        self.assertIn("3-slice/1-slice", out)

    def test_mismatched_ratio_stays_silent(self):
        rows = [self.row(0, 1.0), self.row(1, 1.1)]
        self.assertIsNone(nq.slice_loss_evidence(rows, {0: 1, 1: 3},
                                                 deadband=0.5))

    def test_below_deadband_or_thin_data_stays_silent(self):
        rows = [self.row(0, 0.1), self.row(1, 0.3)]
        self.assertIsNone(nq.slice_loss_evidence(rows, {0: 1, 1: 3},
                                                 deadband=0.5))
        rows = [self.row(0, 1.0, tx=50), self.row(1, 3.0, tx=50)]
        self.assertIsNone(nq.slice_loss_evidence(rows, {0: 1, 1: 3},
                                                 deadband=0.5))

    def test_equal_slice_counts_prove_nothing(self):
        rows = [self.row(0, 1.0), self.row(1, 3.0)]
        self.assertIsNone(nq.slice_loss_evidence(rows, {0: 1, 1: 1},
                                                 deadband=0.5))


class TestWanInnerBytes(unittest.TestCase):
    def test_native_and_vxlan_framings(self):
        self.assertEqual(nq.wan_inner_bytes(200, "UDP", False), 228)
        self.assertEqual(nq.wan_inner_bytes(200, "TCP", False), 240)
        self.assertEqual(nq.wan_inner_bytes(200, "UDP", True),
                         200 + nq.VXLAN_OVERHEAD_UDP + 28)


class TestScenarioParser(unittest.TestCase):
    GOOD = ('{"name": "demo", "repeat": 2, "stages": ['
            '{"name": "base", "secs": 10},'
            '{"name": "load", "secs": 5, "load_mbps": 10},'
            '{"name": "cal", "secs": 20, "load_mbps": 8, '
            '"square_on_s": 5, "square_off_s": 5},'
            '{"name": "wipe", "secs": 1, "reset": true}]}')

    def test_valid_document(self):
        name, stages, repeat = nq.parse_scenario(self.GOOD)
        self.assertEqual((name, repeat, len(stages)), ("demo", 2, 4))
        self.assertEqual(stages[1]["load_mbps"], 10.0)
        self.assertEqual(stages[2]["square_on_s"], 5.0)
        self.assertTrue(stages[3]["reset"])
        self.assertEqual(stages[0]["load_mbps"], 0.0)

    def test_bad_documents_report_the_stage(self):
        bads = [
            ("[1,2]", "object"),
            ('{"stages": []}', "non-empty"),
            ('{"stages": [{"name": "x"}]}', "secs"),
            ('{"stages": [{"secs": 5, "load_mbps": 2000}]}', "load_mbps"),
            ('{"stages": [{"secs": 5, "square_on_s": 5}]}', "together"),
            ('{"stages": [{"secs": 5, "square_on_s": 5, '
             '"square_off_s": 5}]}', "load_mbps > 0"),
            ('{"repeat": -1, "stages": [{"secs": 5}]}', "repeat"),
            ("not json", "JSON"),
        ]
        for doc, needle in bads:
            with self.assertRaises(ValueError) as cm:
                nq.parse_scenario(doc)
            self.assertIn(needle, str(cm.exception))

    def test_repeat_zero_means_loop(self):
        _, _, repeat = nq.parse_scenario(
            '{"repeat": 0, "stages": [{"secs": 1}]}')
        self.assertEqual(repeat, 0)


if __name__ == "__main__":
    unittest.main()
