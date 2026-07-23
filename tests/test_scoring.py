"""Tests for the pure logic the UI renders: the quality/PQI scores, the
label/colour bands the dashboard paints from them, the loss-pattern and
loss-direction diagnostics shown in the console/GUI, and the wire packet
build/parse round-trip and small display formatters. No sockets, no threads,
no display — just the deterministic functions behind what the user sees."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netquality as nq  # noqa: E402


class TestQualityScore(unittest.TestCase):
    def test_perfect_path_is_excellent(self):
        r, mos, label = nq.quality_score(latency_ms=1.0, loss_pct=0.0, jitter_ms=0.0)
        self.assertGreaterEqual(r, 80)
        self.assertEqual(label, "Excellent")
        self.assertLessEqual(mos, 4.5)
        self.assertGreaterEqual(mos, 4.0)

    def test_score_monotonic_in_loss(self):
        good, _, _ = nq.quality_score(20.0, 0.0, 2.0)
        bad, _, _ = nq.quality_score(20.0, 10.0, 2.0)
        self.assertGreater(good, bad)

    def test_score_and_mos_are_clamped(self):
        r, mos, _ = nq.quality_score(latency_ms=5000.0, loss_pct=100.0, jitter_ms=500.0)
        self.assertGreaterEqual(r, 0.0)
        self.assertGreaterEqual(mos, 1.0)

    def test_label_bands(self):
        self.assertEqual(nq.score_label(85), "Excellent")
        self.assertEqual(nq.score_label(70), "Good")
        self.assertEqual(nq.score_label(60), "Fair")
        self.assertEqual(nq.score_label(50), "Poor")
        self.assertEqual(nq.score_label(10), "Bad")

    def test_color_bands_track_labels(self):
        # Every band returns a distinct hex colour; boundaries align with labels.
        colors = {nq.score_color(v) for v in (85, 75, 65, 55, 10)}
        self.assertEqual(len(colors), 5)
        for c in colors:
            self.assertRegex(c, r"^#[0-9a-fA-F]{6}$")


class TestPqiScore(unittest.TestCase):
    def test_clean_tcp_path_scores_high(self):
        pqi, label = nq.pqi_score(latency_ms=5.0, rtt_std_ms=1.0, retrans_pct=0.0,
                                  tput_ratio=1.0, connect_ms=6.0, rtt_ms=5.0)
        self.assertGreaterEqual(pqi, 80)
        self.assertEqual(label, "Excellent")

    def test_retransmissions_and_backpressure_hurt(self):
        clean, _ = nq.pqi_score(5.0, 1.0, 0.0, 1.0, 6.0, 5.0)
        lossy, _ = nq.pqi_score(5.0, 1.0, 5.0, 0.6, 6.0, 5.0)
        self.assertGreater(clean, lossy)

    def test_none_connect_time_is_tolerated(self):
        pqi, _ = nq.pqi_score(5.0, 1.0, 0.0, 1.0, None, 5.0)
        self.assertGreaterEqual(pqi, 0.0)
        self.assertLessEqual(pqi, 100.0)


class TestLossVerdict(unittest.TestCase):
    def test_clean_when_below_inflight_allowance(self):
        self.assertEqual(nq.loss_verdict(3, 2), ("clean", "ok"))

    def test_forward_only(self):
        label, sev = nq.loss_verdict(50, 0)
        self.assertEqual(label, "→ forward")
        self.assertEqual(sev, "warn")

    def test_return_only(self):
        label, _ = nq.loss_verdict(0, 50)
        self.assertEqual(label, "← return")

    def test_return_dominant(self):
        label, _ = nq.loss_verdict(10, 100)
        self.assertEqual(label, "← return")

    def test_both_directions(self):
        label, _ = nq.loss_verdict(50, 60)
        self.assertEqual(label, "both dirs")


class TestLossPattern(unittest.TestCase):
    def test_too_little_loss_returns_none(self):
        self.assertIsNone(nq.classify_loss_pattern({"UDP-1": [1.0, 2.0]}, min_events=5))

    def test_single_port_is_flagged_port_specific(self):
        events = {"UDP-30201": [i * 0.5 for i in range(20)],
                  "UDP-30202": [], "TCP-30101": [], "TCP-30102": []}
        out = nq.classify_loss_pattern(events)
        self.assertIsNotNone(out)
        self.assertIn("port-specific", out)

    def test_path_wide_when_all_streams_lose_together(self):
        # Every stream loses in the same instants -> correlated / path-wide.
        instants = [t * 0.5 for t in range(10)]
        events = {n: list(instants) for n in
                  ("UDP-30201", "UDP-30202", "TCP-30101", "TCP-30102")}
        out = nq.classify_loss_pattern(events)
        self.assertIn("path-wide", out)

    def test_protocol_selective_udp_only(self):
        events = {"UDP-30201": [t * 0.3 for t in range(15)],
                  "UDP-30202": [t * 0.3 + 0.1 for t in range(15)],
                  "TCP-30101": [], "TCP-30102": []}
        out = nq.classify_loss_pattern(events)
        self.assertIn("protocol-selective", out)


class TestWireProtocol(unittest.TestCase):
    def test_build_parse_round_trip(self):
        pkt = nq.build_packet(nq.TYPE_PROBE, sid=2, seq=12345, ts_ns=987654321,
                              size=200, rxsize=64, rxcount=7, peer_ns=111)
        self.assertEqual(len(pkt), 200)
        fields = nq.parse_header(pkt)
        ptype, sid, seq, ts_ns, psize, rxsize, rxcount, peer_ns = fields
        self.assertEqual(ptype, nq.TYPE_PROBE)
        self.assertEqual(sid, 2)
        self.assertEqual(seq, 12345)
        self.assertEqual(ts_ns, 987654321)
        self.assertEqual(psize, 200)
        self.assertEqual(rxsize, 64)
        self.assertEqual(rxcount, 7)
        self.assertEqual(peer_ns, 111)

    def test_size_clamped_to_header_minimum(self):
        pkt = nq.build_packet(nq.TYPE_ECHO, 0, 1, 0, size=1)
        self.assertEqual(len(pkt), nq.HEADER_LEN)

    def test_parse_rejects_short_and_bad_magic(self):
        self.assertIsNone(nq.parse_header(b"\x00" * (nq.HEADER_LEN - 1)))
        junk = b"\xde\xad\xbe\xef" + b"\x00" * (nq.HEADER_LEN - 4)
        self.assertIsNone(nq.parse_header(junk))

    def test_seq_wraps_at_uint32(self):
        pkt = nq.build_packet(nq.TYPE_PROBE, 0, nq.MAX_COUNT + 5, 0, size=200)
        _, _, seq, *_ = nq.parse_header(pkt)
        self.assertEqual(seq, 4)  # (MAX_COUNT + 5) & 0xFFFFFFFF


class TestFormatters(unittest.TestCase):
    def test_hms(self):
        self.assertEqual(nq._hms(0), "00:00:00")
        self.assertEqual(nq._hms(3661), "01:01:01")
        self.assertEqual(nq._hms(59), "00:00:59")

    def test_ports_summary_reflects_streams(self):
        summary = nq.ports_summary()
        self.assertIn("UDP", summary)
        self.assertIn("TCP", summary)
        self.assertIn(str(nq.DEFAULT_UDP_PORTS[0]), summary)

    def test_build_streams(self):
        streams = nq.build_streams((100, 200), (300, 400))
        self.assertEqual([s[2] for s in streams], [100, 200, 300, 400])
        self.assertEqual(streams[0][1], "UDP")
        self.assertEqual(streams[2][1], "TCP")


if __name__ == "__main__":
    unittest.main()
