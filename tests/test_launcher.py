"""Tests for the graphical launcher's form logic — the code path that turns the
launch-window field values into the CLI argv, plus the field parsers/validators
and settings persistence behind it. The real Tkinter widgets need a display and
a human, so these exercise the pure glue the widgets sit on: `_launcher_argv`
(what pressing "Start" produces), `_peer_list`/`_port_pair`/`_mbps_list` (the
field type-converters), `_fmt_num`, and `load_settings`/`save_settings`."""
import argparse
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netquality as nq  # noqa: E402


def launcher_defaults(**overrides):
    """The `vals` dict the launcher's collect() hands to `_launcher_argv` when
    every field is left at its default (mirrors run_launcher's default vars).
    Pass overrides to model a user editing a field."""
    vals = {
        "peer": "10.0.0.2",
        "size": "200", "pps": "50", "dont_fragment": False,
        "bind": "0.0.0.0", "udp_ports": "", "tcp_ports": "",
        "window": "10", "timeout": "2", "loss_deadband": "0.5",
        "history": "300", "refresh_ms": "500",
        "vxlan": False, "vxlan_vni": str(nq.VXLAN_DEFAULT_VNI),
        "vxlan_port": str(nq.VXLAN_DEFAULT_PORT), "no_gui": False,
    }
    vals.update(overrides)
    return vals


class TestLauncherArgv(unittest.TestCase):
    def test_defaults_emit_only_peer(self):
        # Only options that differ from the CLI defaults should be emitted, so
        # a default form yields the shortest possible command line.
        self.assertEqual(nq._launcher_argv(launcher_defaults()), ["--peer", "10.0.0.2"])

    def test_argv_round_trips_through_parse_args(self):
        # Whatever the launcher builds must parse back cleanly (no bad flags).
        argv = nq._launcher_argv(launcher_defaults(
            size="8972", pps="100", window="30", timeout="1.5",
            dont_fragment=True, no_gui=True))
        args = nq.parse_args(argv)
        self.assertEqual(args.peer, "10.0.0.2")
        self.assertEqual(args.size, 8972)
        self.assertEqual(args.pps, 100)
        self.assertEqual(args.window, 30.0)
        self.assertEqual(args.timeout, 1.5)
        self.assertTrue(args.dont_fragment)
        self.assertTrue(args.no_gui)

    def test_missing_peer_is_rejected(self):
        with self.assertRaises(ValueError):
            nq._launcher_argv(launcher_defaults(peer="  "))

    def test_non_default_ports_emitted_defaults_suppressed(self):
        # Typing the default ports explicitly must NOT add flags.
        vals = launcher_defaults(udp_ports="30201,30202", tcp_ports="30101,30102")
        self.assertEqual(nq._launcher_argv(vals), ["--peer", "10.0.0.2"])
        # ...but a real change is emitted.
        vals = launcher_defaults(udp_ports="40001,40002")
        argv = nq._launcher_argv(vals)
        self.assertIn("--udp-ports", argv)
        self.assertEqual(argv[argv.index("--udp-ports") + 1], "40001,40002")

    def test_out_of_range_number_reports_field_name(self):
        with self.assertRaises(ValueError) as cm:
            nq._launcher_argv(launcher_defaults(pps="0"))
        self.assertIn("Probes/sec", str(cm.exception))

    def test_non_numeric_field_reports_field_name(self):
        with self.assertRaises(ValueError) as cm:
            nq._launcher_argv(launcher_defaults(size="big"))
        self.assertIn("Probe size", str(cm.exception))

    def test_size_below_header_len_is_rejected(self):
        with self.assertRaises(ValueError):
            nq._launcher_argv(launcher_defaults(size=str(nq.HEADER_LEN - 1)))

    def test_mesh_peers_switch_to_peers_flag(self):
        argv = nq._launcher_argv(launcher_defaults(peer="10.0.0.2, 10.0.0.3"))
        self.assertEqual(argv[:2], ["--peers", "10.0.0.2,10.0.0.3"])
        self.assertNotIn("--peer", argv)

    def test_mesh_with_vxlan_is_rejected(self):
        with self.assertRaises(ValueError) as cm:
            nq._launcher_argv(launcher_defaults(peer="10.0.0.2,10.0.0.3", vxlan=True))
        self.assertIn("VXLAN", str(cm.exception))

    def test_vxlan_flags_and_non_default_vni(self):
        argv = nq._launcher_argv(launcher_defaults(vxlan=True, vxlan_vni="1234"))
        self.assertIn("--vxlan", argv)
        self.assertEqual(argv[argv.index("--vxlan-vni") + 1], "1234")
        # Default VNI stays implicit.
        argv = nq._launcher_argv(launcher_defaults(vxlan=True))
        self.assertNotIn("--vxlan-vni", argv)

    def test_bind_non_default_emitted(self):
        argv = nq._launcher_argv(launcher_defaults(bind="192.168.1.10"))
        self.assertEqual(argv[argv.index("--bind") + 1], "192.168.1.10")


class TestFieldParsers(unittest.TestCase):
    def test_peer_list_trims_and_dedups(self):
        self.assertEqual(nq._peer_list(" a , b ,c "), ["a", "b", "c"])
        with self.assertRaises(argparse.ArgumentTypeError):
            nq._peer_list("a,a")
        with self.assertRaises(argparse.ArgumentTypeError):
            nq._peer_list("  ,  ")

    def test_port_pair(self):
        self.assertEqual(nq._port_pair("30201, 30202"), (30201, 30202))
        for bad in ("30201", "1,2,3", "a,b", "0,65535", "1,70000"):
            with self.assertRaises(argparse.ArgumentTypeError):
                nq._port_pair(bad)

    def test_mbps_list(self):
        self.assertEqual(nq._mbps_list("1,2.5,10"), [1.0, 2.5, 10.0])
        for bad in ("", "0", "-1", "501", "x"):
            with self.assertRaises(argparse.ArgumentTypeError):
                nq._mbps_list(bad)

    def test_fmt_num_keeps_human_friendly(self):
        self.assertEqual(nq._fmt_num(10.0), "10")
        self.assertEqual(nq._fmt_num(0.5), "0.5")
        self.assertEqual(nq._fmt_num(16777215), "16777215")


class TestSettingsPersistence(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="nv-settings-")
        # Redirect config_dir() at both the Windows and XDG env it reads.
        self._saved = {k: os.environ.get(k) for k in ("APPDATA", "XDG_CONFIG_HOME")}
        os.environ["APPDATA"] = self._tmp
        os.environ["XDG_CONFIG_HOME"] = self._tmp

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_missing_settings_returns_empty_dict(self):
        self.assertEqual(nq.load_settings(), {})

    def test_save_then_load_round_trip(self):
        nq.save_settings({"peer": "10.0.0.2", "pps": 50})
        self.assertEqual(nq.load_settings(), {"peer": "10.0.0.2", "pps": 50})

    def test_corrupt_settings_reads_as_empty(self):
        os.makedirs(nq.config_dir(), exist_ok=True)
        with open(nq.settings_path(), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual(nq.load_settings(), {})


if __name__ == "__main__":
    unittest.main()
