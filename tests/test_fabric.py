"""Tests for the 2.0.0 fabric-proof tranche: the FEC verdict rules, the
IPv4-fragment classifier and ICMP error-queue parser behind the sniffer and
the sweep's PMTUD detection, and the demo-report builder/renderer. Pure
logic - the report tests run against a stub engine, no sockets."""
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netquality as nq  # noqa: E402


class TestFecVerdict(unittest.TestCase):
    @staticmethod
    def wan(tx=1000.0, drops=None, ok=True):
        return {"ok": ok, "kind": "snmp", "tx_pps": tx, "rx_pps": tx,
                "drop_pps": drops}

    def test_wan_drops_with_clean_probes_reads_fec(self):
        out = nq.fec_verdict(self.wan(drops=20.0), probe_loss_pct=0.0,
                             slices=3)
        self.assertIsNotNone(out)
        self.assertIn("FEC repairing", out)

    def test_amplified_probe_loss_reads_no_fec(self):
        # WAN slice loss ~1%, probes losing ~3% on a 3-slice stream.
        out = nq.fec_verdict(self.wan(drops=10.0), probe_loss_pct=3.0,
                             slices=3)
        self.assertIsNotNone(out)
        self.assertIn("no FEC", out)

    def test_all_clean_or_no_data_is_silent(self):
        self.assertIsNone(nq.fec_verdict(self.wan(drops=0.0), 0.0, 3))
        self.assertIsNone(nq.fec_verdict(self.wan(drops=None), 5.0, 3))
        self.assertIsNone(nq.fec_verdict(self.wan(drops=20.0, ok=False),
                                         0.0, 3))
        self.assertIsNone(nq.fec_verdict(None, 0.0, 3))

    def test_ambiguous_middle_ground_is_silent(self):
        # Probe loss comparable to WAN loss on a single-slice stream:
        # neither repair nor amplification proven.
        self.assertIsNone(nq.fec_verdict(self.wan(drops=10.0),
                                         probe_loss_pct=1.0, slices=1))


class TestFragmentClassifier(unittest.TestCase):
    @staticmethod
    def ipv4(flags_frag, proto=17, src="10.0.0.1", dst="10.0.0.2"):
        import socket as s
        return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, flags_frag,
                           64, proto, 0, s.inet_aton(src), s.inet_aton(dst))

    def test_first_fragment_and_continuation(self):
        first = nq.parse_ipv4_fragment(self.ipv4(0x2000))     # MF, offset 0
        self.assertEqual(first[:2], (True, True))
        cont = nq.parse_ipv4_fragment(self.ipv4(0x2000 | 100))
        self.assertEqual(cont[:2], (True, False))
        last = nq.parse_ipv4_fragment(self.ipv4(185))         # offset only
        self.assertEqual(last[:2], (True, False))

    def test_unfragmented_and_garbage(self):
        whole = nq.parse_ipv4_fragment(self.ipv4(0x4000))     # DF
        self.assertEqual(whole[0], False)
        self.assertEqual(whole[3:], ("10.0.0.1", "10.0.0.2"))
        self.assertIsNone(nq.parse_ipv4_fragment(b"\x60" + b"\x00" * 30))
        self.assertIsNone(nq.parse_ipv4_fragment(b"\x45\x00"))

    def test_l2_offset_skips_ethernet(self):
        pkt = b"\x00" * 14 + self.ipv4(0x2000)
        self.assertEqual(nq.parse_ipv4_fragment(pkt, 14)[:2], (True, True))


class TestIcmpErrParser(unittest.TestCase):
    @staticmethod
    def cmsg(origin=2, typ=3, code=4, info=1500):
        ee = struct.pack("=IBBBBI", 90, origin, typ, code, 0, info)
        ip_recverr = getattr(__import__("socket"), "IP_RECVERR", 11)
        return [(0, ip_recverr, ee)]  # level 0 == socket.IPPROTO_IP

    def test_frag_needed_carries_the_mtu(self):
        self.assertEqual(nq.parse_icmp_err(self.cmsg()), (3, 4, 1500))

    def test_non_icmp_origin_ignored(self):
        self.assertIsNone(nq.parse_icmp_err(self.cmsg(origin=1)))
        self.assertIsNone(nq.parse_icmp_err([]))
        self.assertIsNone(nq.parse_icmp_err(None))


class _StubEngine:
    """Just enough engine for build_report: a canned snapshot()."""

    def __init__(self):
        row = {"name": "UDP-30201", "proto": "UDP", "port": 30201,
               "connected": True, "rtt_avg": 1.2, "latency": 0.6,
               "jitter": 0.3, "loss": 0.5, "late": 0.1, "score": 92.0,
               "mos": 4.4, "label": "Excellent", "cum_tx": 1000,
               "cum_recv": 994, "cum_lost": 5, "cum_late": 1,
               "fwd_lost": 3, "rtn_lost": 2, "peer_rx_max": 200,
               "rx_echo_max": 200, "expect_size": 200, "dscp_req": 46,
               "fwd_tos": 46 << 2, "rtn_tos": 46 << 2, "tx_pps": 50.0}
        self._snap = {
            "peer": "10.0.0.2", "rows": [row], "udp_silent": False,
            "loss_pattern": None, "overall": 92.0, "udp_mos": 4.4,
            "udp_score": 92.0, "tcp_pqi": None, "worst": 92.0,
            "overall_label": "Excellent", "uptime": 61.0,
            "since_reset": 61.0, "links_up": 1,
            "totals": {"tx": 1000, "recv": 994, "lost": 5, "late": 1,
                       "loss_pct": 0.5, "late_pct": 0.1, "fwd_lost": 3,
                       "rtn_lost": 2, "fwd_pct": 0.3, "rtn_pct": 0.2,
                       "life_tx": 1000, "life_recv": 994, "life_lost": 5,
                       "life_late": 1, "life_loss_pct": 0.5,
                       "life_late_pct": 0.1},
            "frame_size": 200, "dont_fragment": False, "vxlan": None,
            "size_status": "verified", "offered_mbps": 0.75,
            "target_mbps": None, "profiles_active": False,
            "wan": {"kind": "sim", "ok": True, "detail": "", "tx_pps": 100.0,
                    "rx_pps": 100.0, "tx_mbps": None, "rx_mbps": None,
                    "drop_pps": 1.0, "age": 0.5},
            "scenario": None,
            "slice_evidence": None,
            "predicted_wan_pps": 100.0,
            "frags": None,
            "fec": "FEC repairing: WAN dropping 1.00% while probes run "
                   "0.50% clean",
        }

    def snapshot(self):
        return self._snap


class _StubArgs:
    _argv = ["--peer", "10.0.0.2", "--dscp", "EF"]


class TestReport(unittest.TestCase):
    def test_build_report_carries_the_story(self):
        data = nq.build_report(_StubEngine(), _StubArgs())
        self.assertEqual(data["peer"], "10.0.0.2")
        self.assertEqual(data["overall"]["label"], "Excellent")
        self.assertEqual(len(data["streams"]), 1)
        self.assertEqual(data["streams"][0]["dscp_req"], 46)
        self.assertIn("FEC repairing", data["diagnostics"]["fec"])
        self.assertEqual(data["command_line"], "--peer 10.0.0.2 --dscp EF")

    def test_html_is_self_contained_and_escaped(self):
        data = nq.build_report(_StubEngine(), _StubArgs())
        data["peer"] = "<script>alert(1)</script>"
        html = nq.render_report_html(data)
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("UDP-30201", html)
        self.assertIn("EF→EF/EF", html)
        self.assertIn("FEC repairing", html)
        self.assertNotIn("http://", html)     # no external fetches
        self.assertNotIn("https://", html)

    def test_write_report_produces_the_pair(self):
        with tempfile.TemporaryDirectory(prefix="nv-report-") as tmp:
            base = os.path.join(tmp, "demo")
            jp, hp = nq.write_report(_StubEngine(), _StubArgs(), base=base)
            self.assertTrue(os.path.exists(jp))
            self.assertTrue(os.path.exists(hp))
            import json
            with open(jp, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["peer"], "10.0.0.2")
            with open(hp, encoding="utf-8") as fh:
                self.assertIn("<!DOCTYPE html>", fh.read())


if __name__ == "__main__":
    unittest.main()
