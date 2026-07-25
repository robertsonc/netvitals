"""Tests for the known-quantity rate logic added in 1.7.0: the --mbps →
per-stream pps derivation, the sustained-load square-wave schedule, and the
burst test's verdict shapes (factored into a pure function so the
loss-vs-late semantics stay testable without a peer). No sockets, no
threads, no display."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netquality as nq  # noqa: E402


class TestPpsFromMbps(unittest.TestCase):
    def test_round_trips_to_the_requested_load(self):
        # 2 UDP + 2 TCP streams at the derived rates must re-total the ask
        # (IP level, probes only) - that is the whole "known quantity" deal.
        for mbps, size in ((1.0, 200), (8.0, 1000), (100.0, 8972)):
            udp_pps, tcp_pps = nq.pps_from_mbps(mbps, size)
            total = (2 * udp_pps * (size + nq.IPV4_UDP_OVERHEAD) * 8
                     + 2 * tcp_pps * (size + nq.IPV4_TCP_OVERHEAD) * 8)
            self.assertAlmostEqual(total / 1e6, mbps, places=6)

    def test_split_is_even_per_stream_not_per_packet(self):
        # Equal bandwidth per stream: TCP probes cost 12 B more on the wire,
        # so the TCP rate must be slightly LOWER, not equal.
        udp_pps, tcp_pps = nq.pps_from_mbps(4.0, 1000)
        self.assertGreater(udp_pps, tcp_pps)
        self.assertAlmostEqual(udp_pps * (1000 + 28), tcp_pps * (1000 + 40),
                               places=4)

    def test_fractional_rates_are_preserved(self):
        udp_pps, tcp_pps = nq.pps_from_mbps(1.0, 8972)
        self.assertIsInstance(udp_pps, float)
        self.assertLess(udp_pps, 4.0)   # ~3.5 pps: fractional, not rounded
        self.assertGreater(udp_pps, 3.0)

    def test_tiny_target_is_floored_not_zero(self):
        udp_pps, tcp_pps = nq.pps_from_mbps(0.0001, 60000)
        self.assertEqual(udp_pps, 0.1)
        self.assertEqual(tcp_pps, 0.1)


class TestSquarePhase(unittest.TestCase):
    def test_no_off_half_means_always_on(self):
        for off in (0, 0.0, None):
            self.assertTrue(nq.square_phase(0.0, 10.0, off))
            self.assertTrue(nq.square_phase(1234.5, 10.0, off))

    def test_wave_starts_on_and_alternates(self):
        on, off = 10.0, 5.0
        self.assertTrue(nq.square_phase(0.0, on, off))
        self.assertTrue(nq.square_phase(9.99, on, off))
        self.assertFalse(nq.square_phase(10.0, on, off))
        self.assertFalse(nq.square_phase(14.99, on, off))
        self.assertTrue(nq.square_phase(15.0, on, off))   # next period

    def test_wave_repeats(self):
        on, off = 3.0, 7.0
        for k in range(5):
            base = k * (on + off)
            self.assertTrue(nq.square_phase(base + 1.0, on, off))
            self.assertFalse(nq.square_phase(base + on + 1.0, on, off))

    def test_degenerate_on_half_is_off(self):
        self.assertFalse(nq.square_phase(0.0, 0.0, 5.0))


class TestBurstVerdicts(unittest.TestCase):
    # results rows: (mbps, loss_pct, late_pct, rtt_med_ms, rtt_p95_ms)
    BASE_MED, BASE_P95 = 5.0, 6.0

    def verdicts(self, results):
        return nq.burst_verdicts(results, self.BASE_MED, self.BASE_P95)

    def test_clean_ladder_names_the_highest_clean_stage(self):
        lines = self.verdicts([(1, 0.0, 0.0, 5.0, 6.5),
                               (5, 0.2, 0.3, 5.5, 7.0)])
        self.assertEqual(len(lines), 1)
        self.assertIn("Clean up to 5 Mbps", lines[0])

    def test_p95_blowup_without_loss_reads_bufferbloat(self):
        lines = self.verdicts([(10, 0.5, 1.0, 80.0, 200.0)])
        self.assertTrue(any("Deep queue" in ln for ln in lines))

    def test_hard_loss_with_flat_rtt_reads_policer(self):
        lines = self.verdicts([(10, 20.0, 0.0, 6.0, 8.0)])
        self.assertTrue(any("Policer-like" in ln for ln in lines))

    def test_hard_loss_after_rtt_growth_reads_shaper(self):
        lines = self.verdicts([(10, 12.0, 3.0, 90.0, 150.0)])
        self.assertTrue(any("Shaper-like" in ln for ln in lines))

    def test_late_echoes_do_not_trigger_the_rate_cap_verdicts(self):
        # 30% late but zero hard loss: a policer's drops never arrive, so
        # this must NOT read as a rate cap (and it isn't clean either).
        lines = self.verdicts([(10, 0.0, 30.0, 50.0, 120.0)])
        self.assertFalse(any("Policer" in ln or "Shaper" in ln
                             for ln in lines))
        self.assertFalse(any("Clean" in ln for ln in lines))

    def test_late_disqualifies_clean(self):
        # loss 0.5 + late 0.8 = 1.3% impairment: not a clean stage.
        lines = self.verdicts([(5, 0.5, 0.8, 5.5, 7.0)])
        self.assertFalse(any("Clean" in ln for ln in lines))

    def test_ambiguous_response_falls_back_to_the_table(self):
        lines = self.verdicts([(1, 3.0, 0.0, 10.0, 20.0)])
        self.assertEqual(len(lines), 1)
        self.assertIn("see the table", lines[0])


if __name__ == "__main__":
    unittest.main()
