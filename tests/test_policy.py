"""Tests for the 1.8.0 policy-classification surface: N-stream port lists,
per-stream traffic profiles (incl. IMIX patterns), the --mbps generalization
over profiles, DSCP parsing/naming, the qWAVE traffic-type mapping, and the
wire-compatible TOS-report stamping. Pure logic - no sockets, no display."""
import argparse
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netquality as nq  # noqa: E402


class TestPortLists(unittest.TestCase):
    def test_default_pair_still_parses(self):
        self.assertEqual(nq._udp_port_list("30201,30202"), (30201, 30202))
        self.assertEqual(nq._tcp_port_list("30101,30102"), (30101, 30102))

    def test_one_to_eight_ports(self):
        self.assertEqual(nq._udp_port_list("5060"), (5060,))
        eight = ",".join(str(40000 + i) for i in range(8))
        self.assertEqual(len(nq._udp_port_list(eight)), 8)
        nine = ",".join(str(40000 + i) for i in range(9))
        with self.assertRaises(argparse.ArgumentTypeError):
            nq._udp_port_list(nine)

    def test_tcp_none_runs_udp_only(self):
        for raw in ("none", "NONE", "off", "0", ""):
            self.assertEqual(nq._tcp_port_list(raw), ())

    def test_udp_streams_are_required(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            nq._udp_port_list("")
        with self.assertRaises(argparse.ArgumentTypeError):
            nq._udp_port_list("none")

    def test_duplicates_and_ranges_rejected(self):
        for bad in ("30201,30201", "0,1", "1,70000", "a,b"):
            with self.assertRaises(argparse.ArgumentTypeError):
                nq._udp_port_list(bad)

    def test_build_streams_scales_and_colors_cycle(self):
        streams = nq.build_streams((1, 2, 3), (4,))
        self.assertEqual(len(streams), 4)
        self.assertEqual([s[1] for s in streams], ["UDP"] * 3 + ["TCP"])
        # sids stay sequential; colors defined for any sid.
        self.assertEqual([s[0] for s in streams], [0, 1, 2, 3])
        for sid in range(20):
            self.assertRegex(nq.stream_color(sid), r"^#[0-9a-fA-F]{6}$")


class TestProfiles(unittest.TestCase):
    def test_named_and_custom_entries(self):
        entries = nq._profile_list("voice,imix,1200x90,548")
        self.assertEqual(entries[0], "voice")
        self.assertEqual(entries[1], "imix")
        self.assertEqual(entries[2], (1200, 90.0))
        self.assertEqual(entries[3], (548, None))

    def test_bad_entries_rejected(self):
        for bad in ("gaming", "10x", "33", "70000", "1200x0", ""):
            with self.assertRaises(argparse.ArgumentTypeError):
                nq._profile_list(bad)

    def test_resolve_fills_defaults_and_expands_imix(self):
        resolved = nq.resolve_profiles(["voice", "imix"], 4, base_size=200)
        self.assertEqual(len(resolved), 4)
        self.assertEqual(resolved[0], ((200,), 50))
        imix_sizes, imix_pps = resolved[1]
        self.assertEqual(len(imix_sizes), 12)          # 7 + 4 + 1
        self.assertEqual(max(imix_sizes), 1472)        # 1500 B IP packet
        self.assertEqual(min(imix_sizes), 36)          # 64 B IP packet
        self.assertIsNone(imix_pps)
        # Unlisted streams keep --size at the base rate.
        self.assertEqual(resolved[2], ((200,), None))
        self.assertEqual(resolved[3], ((200,), None))

    def test_imix_mean_matches_the_classic_mix(self):
        sizes, _ = nq.TRAFFIC_PROFILES["imix"]
        # 7:4:1 of 64/576/1500-byte IP packets -> mean ~354.3 B IP.
        mean_ip = nq.mean_wire_size(sizes, "UDP")
        self.assertAlmostEqual(mean_ip, (7 * 64 + 4 * 576 + 1500) / 12.0,
                               places=1)

    def test_pps_for_streams_splits_bandwidth_evenly(self):
        profiles = nq.resolve_profiles(["voice", "imix"], 2, base_size=200)
        rates = nq.pps_for_streams(8.0, profiles, ["UDP", "UDP"])
        total = sum(r * nq.mean_wire_size(p[0], "UDP") * 8
                    for r, p in zip(rates, profiles))
        self.assertAlmostEqual(total / 1e6, 8.0, places=6)
        # The IMIX stream's mean packet is bigger, so its pps is lower.
        self.assertGreater(rates[0], rates[1])


class TestDscp(unittest.TestCase):
    def test_names_values_and_skips(self):
        self.assertEqual(nq._dscp_list("EF,af41,-,17"), [46, 34, None, 17])
        self.assertEqual(nq._dscp_list("be"), [0])

    def test_bad_entries_rejected(self):
        for bad in ("banana", "64", "-1"):
            with self.assertRaises(argparse.ArgumentTypeError):
                nq._dscp_list(bad)

    def test_dscp_name_round_trip(self):
        self.assertEqual(nq.dscp_name(46), "EF")
        self.assertEqual(nq.dscp_name(34), "AF41")
        self.assertEqual(nq.dscp_name(0), "BE")
        self.assertEqual(nq.dscp_name(17), "17")
        self.assertEqual(nq.dscp_name(None), "-")

    def test_qwave_mapping_is_monotone_and_honest(self):
        # Requested -> (traffic type, applied). The applied value must be
        # what the Windows stack really uses for that type.
        self.assertEqual(nq.qwave_traffic_type(0), (0, 0))
        self.assertEqual(nq.qwave_traffic_type(8), (1, 8))
        self.assertEqual(nq.qwave_traffic_type(26), (2, 28))
        self.assertEqual(nq.qwave_traffic_type(34), (3, 40))
        self.assertEqual(nq.qwave_traffic_type(46), (4, 56))
        last_type = -1
        for d in range(64):
            t, applied = nq.qwave_traffic_type(d)
            self.assertGreaterEqual(t, last_type)
            self.assertTrue(0 <= applied <= 63)
            last_type = t


class TestTosReport(unittest.TestCase):
    def test_stamp_and_parse_round_trip(self):
        echo = nq.build_packet(nq.TYPE_ECHO, 0, 1, 0, size=64)
        stamped = nq.stamp_tos_report(echo, 0xB8)   # EF << 2
        self.assertEqual(len(stamped), len(echo))
        self.assertEqual(nq.parse_tos_report(stamped), 0xB8)
        # The header itself is untouched.
        self.assertEqual(nq.parse_header(stamped)[:3],
                         nq.parse_header(echo)[:3])

    def test_old_peer_zero_padding_reads_as_no_report(self):
        echo = nq.build_packet(nq.TYPE_ECHO, 0, 1, 0, size=64)
        self.assertIsNone(nq.parse_tos_report(echo))

    def test_minimal_echo_has_no_room(self):
        echo = nq.build_packet(nq.TYPE_ECHO, 0, 1, 0, size=nq.HEADER_LEN)
        self.assertEqual(nq.stamp_tos_report(echo, 0xB8), echo)
        self.assertIsNone(nq.parse_tos_report(echo))

    def test_none_tos_is_a_no_op(self):
        echo = nq.build_packet(nq.TYPE_ECHO, 0, 1, 0, size=64)
        self.assertEqual(nq.stamp_tos_report(echo, None), echo)


class TestLauncherNewFields(unittest.TestCase):
    def vals(self, **over):
        from test_launcher import launcher_defaults
        v = launcher_defaults()
        v.update({"profiles": "", "dscp": ""})
        v.update(over)
        return v

    def test_profiles_and_dscp_emitted_and_round_trip(self):
        argv = nq._launcher_argv(self.vals(profiles="voice,imix",
                                           dscp="EF,AF41"))
        args = nq.parse_args(argv)
        self.assertEqual(args.profiles, ["voice", "imix"])
        self.assertEqual(args.dscp, [46, 34])
        # Blank fields stay off the command line.
        argv = nq._launcher_argv(self.vals())
        self.assertNotIn("--profiles", argv)
        self.assertNotIn("--dscp", argv)

    def test_invalid_profile_reports_field_name(self):
        with self.assertRaises(ValueError) as cm:
            nq._launcher_argv(self.vals(profiles="gaming"))
        self.assertIn("Profiles", str(cm.exception))

    def test_port_lists_emit_n_ports(self):
        argv = nq._launcher_argv(self.vals(udp_ports="5060,5061,5062",
                                           tcp_ports="none"))
        self.assertEqual(argv[argv.index("--udp-ports") + 1], "5060,5061,5062")
        self.assertEqual(argv[argv.index("--tcp-ports") + 1], "none")
        args = nq.parse_args(argv)
        self.assertEqual(args.udp_ports, (5060, 5061, 5062))
        self.assertEqual(args.tcp_ports, ())


if __name__ == "__main__":
    unittest.main()
