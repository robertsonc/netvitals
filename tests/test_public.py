"""Tests for the public-endpoint tranche (3.2.0): the egress (source)
report carried in echo padding, the --allow parser and --public/--responder
argument rules, the Engine's private/public roles, the responder's reflect
path over real loopback sockets (127.0.0.1 only, so it runs on every CI
platform), and the web/report/console surfaces that show the public path.
One end-to-end case needs a second loopback address and skips without it."""
import json
import os
import socket
import sys
import threading
import time
import unittest
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netquality as nq  # noqa: E402
import nv_webui  # noqa: E402


def free_ports(n, kind=socket.SOCK_DGRAM):
    """n distinct currently-free loopback ports of one socket type."""
    socks, ports = [], []
    try:
        while len(ports) < n:
            s = socket.socket(socket.AF_INET, kind)
            s.bind(("127.0.0.1", 0))
            socks.append(s)
            ports.append(s.getsockname()[1])
    finally:
        for s in socks:
            s.close()
    return ports


def wait_for(pred, timeout=5.0, step=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(step)
    return pred()


class TestSrcReport(unittest.TestCase):
    def echo(self, size=200):
        return nq.build_packet(nq.TYPE_ECHO, 0, 7, 123, size)

    def test_round_trip(self):
        out = nq.stamp_src_report(self.echo(), ("203.0.113.7", 51234))
        self.assertEqual(nq.parse_src_report(out), ("203.0.113.7", 51234))
        self.assertEqual(len(out), 200)          # never grows the echo
        # The header is untouched: the originator still parses the echo.
        self.assertEqual(nq.parse_header(out)[2], 7)

    def test_coexists_with_tos_report(self):
        out = nq.stamp_tos_report(self.echo(), 0xB8)
        out = nq.stamp_src_report(out, ("198.51.100.9", 30201))
        self.assertEqual(nq.parse_tos_report(out), 0xB8)
        self.assertEqual(nq.parse_src_report(out), ("198.51.100.9", 30201))

    def test_old_peer_zero_padding_reads_as_no_report(self):
        self.assertIsNone(nq.parse_src_report(self.echo()))

    def test_too_small_to_carry_it(self):
        small = self.echo(nq.SRC_REPORT_OFF + nq.SRC_REPORT_LEN - 1)
        self.assertEqual(nq.stamp_src_report(small, ("10.0.0.1", 1)), small)
        self.assertIsNone(nq.parse_src_report(small))
        just = self.echo(nq.SRC_REPORT_OFF + nq.SRC_REPORT_LEN)
        self.assertIsNotNone(nq.parse_src_report(
            nq.stamp_src_report(just, ("10.0.0.1", 1))))

    def test_unparseable_address_leaves_echo_alone(self):
        e = self.echo()
        self.assertEqual(nq.stamp_src_report(e, ("not-an-ip", 1)), e)

    def test_stats_keep_and_reset_seen_as(self):
        st = nq.StreamStats()
        st.on_send(1, 100)
        st.on_echo(1, 100, 200, peer_src=("203.0.113.7", 4000))
        self.assertEqual(st.snapshot()["seen_as"], ("203.0.113.7", 4000))
        st.reset()
        self.assertIsNone(st.snapshot()["seen_as"])


class TestAllowList(unittest.TestCase):
    def test_hosts_and_cidrs(self):
        nets = nq._allow_list("203.0.113.7, 198.51.100.0/24")
        self.assertTrue(nq._ip_allowed("203.0.113.7", nets))
        self.assertTrue(nq._ip_allowed("198.51.100.200", nets))
        self.assertFalse(nq._ip_allowed("203.0.113.8", nets))
        self.assertFalse(nq.allow_is_open(nets))

    def test_any_is_open(self):
        nets = nq._allow_list("any")
        self.assertTrue(nq.allow_is_open(nets))
        self.assertTrue(nq._ip_allowed("8.8.8.8", nets))
        self.assertTrue(nq.allow_is_open(nq._allow_list("0.0.0.0/0")))

    def test_rejects_garbage(self):
        import argparse
        for bad in ("", " , ", "10.0.0.0/33", "example.com", "::1"):
            with self.assertRaises(argparse.ArgumentTypeError, msg=bad):
                nq._allow_list(bad)

    def test_non_ip_source_is_refused(self):
        self.assertFalse(nq._ip_allowed("bogus", nq._allow_list("any")))


class TestPublicArgs(unittest.TestCase):
    def normalized(self, argv):
        args = nq.parse_args(argv)
        with mock.patch.object(nq, "_alert_gui_error"):
            ok = nq._normalize_peer_args(args)
        return ok, args

    def test_public_alongside_peer(self):
        ok, args = self.normalized(["--peer", "10.0.0.2",
                                    "--public", " 203.0.113.10 "])
        self.assertTrue(ok)
        self.assertEqual(args.public, "203.0.113.10")
        self.assertEqual(args.peer, "10.0.0.2")

    def test_public_must_be_distinct_and_single(self):
        for argv in (["--peer", "10.0.0.2", "--public", "10.0.0.2"],
                     ["--peers", "10.0.0.2,10.0.0.3", "--public", "10.0.0.3"],
                     ["--peer", "10.0.0.2", "--public", "1.1.1.1,2.2.2.2"]):
            with mock.patch("sys.stderr"):
                ok, _args = self.normalized(argv)
            self.assertFalse(ok, argv)

    def test_responder_rules(self):
        def conflict(argv):
            return nq._responder_conflicts(nq.parse_args(argv))
        self.assertIsNone(conflict(["--responder", "--allow", "10.0.0.0/8"]))
        self.assertIsNone(conflict(["--peer", "10.0.0.2"]))
        self.assertIn("--allow", conflict(["--responder"]))
        self.assertIn("--responder", conflict(["--peer", "10.0.0.2",
                                               "--allow", "any"]))
        for extra in (["--peer", "10.0.0.2"], ["--public", "1.2.3.4"],
                      ["--vxlan"], ["--burst-test"], ["--mtu-sweep"]):
            self.assertIn("only reflects",
                          conflict(["--responder", "--allow", "any"] + extra),
                          extra)

    def test_main_rejects_public_with_vxlan(self):
        with mock.patch("sys.stderr"):
            rc = nq.main(["--peer", "10.0.0.2", "--public", "1.2.3.4",
                          "--vxlan", "--no-gui"])
        self.assertEqual(rc, 2)

    def test_main_rejects_public_with_mesh_or_jumbo(self):
        for argv in (["--peers", "10.0.0.2,10.0.0.3", "--public", "1.2.3.4"],
                     ["--peer", "10.0.0.2", "--public", "1.2.3.4",
                      "--size", "8972"],
                     ["--peer", "10.0.0.2", "--public", "1.2.3.4",
                      "--profiles", "9000"]):
            with mock.patch("sys.stderr"), \
                    mock.patch.object(nq, "_alert_gui_error"):
                self.assertEqual(nq.main(argv + ["--no-gui"]), 2, argv)


class TestLauncherPublic(unittest.TestCase):
    def vals(self, **kw):
        v = {"peer": "10.0.0.2", "size": "200", "pps": "50", "mbps": "",
             "dont_fragment": False, "bind": "0.0.0.0", "udp_ports": "",
             "tcp_ports": "", "window": "10", "timeout": "2",
             "loss_deadband": "0.5", "history": "300", "refresh_ms": "500",
             "vxlan": False, "vxlan_vni": str(nq.VXLAN_DEFAULT_VNI),
             "vxlan_port": str(nq.VXLAN_DEFAULT_PORT), "no_gui": False}
        v.update(kw)
        return v

    def test_emits_public_and_round_trips(self):
        argv = nq._launcher_argv(self.vals(public=" 203.0.113.10 "))
        self.assertEqual(argv, ["--peer", "10.0.0.2",
                                "--public", "203.0.113.10"])
        self.assertEqual(nq.parse_args(argv).public, "203.0.113.10")

    def test_blank_public_emits_nothing(self):
        self.assertEqual(nq._launcher_argv(self.vals(public="")),
                         ["--peer", "10.0.0.2"])

    def test_rejects_bad_public(self):
        for kw in ({"public": "10.0.0.2"},
                   {"public": "1.1.1.1,2.2.2.2"},
                   {"public": "1.1.1.1", "vxlan": True},
                   {"peer": "10.0.0.2,10.0.0.3", "public": "1.1.1.1"},
                   {"public": "1.1.1.1", "size": "8972"},
                   {"public": "1.1.1.1", "profiles": "voice,9000"}):
            with self.assertRaises(ValueError, msg=kw):
                nq._launcher_argv(self.vals(**kw))


class TestEngineRoles(unittest.TestCase):
    def test_public_is_one_more_pair_with_a_role(self):
        e = nq.Engine("10.0.0.2", public="203.0.113.10", history_seconds=10)
        self.assertEqual(e.peer, "10.0.0.2")
        self.assertEqual(e.peers, ["10.0.0.2", "203.0.113.10"])
        self.assertEqual(e.private_peers, ["10.0.0.2"])
        self.assertEqual(e.roles["203.0.113.10"], "public")
        snap = e.snapshot("203.0.113.10")
        self.assertEqual(snap["role"], "public")
        self.assertEqual(snap["egress"], [])
        self.assertEqual(e.snapshot()["role"], "private")
        ps = e.path_summary("203.0.113.10")
        self.assertFalse(ps["up"])
        self.assertIsNone(ps["score"])
        self.assertEqual(ps["stream_count"], len(nq.STREAMS))

    def test_public_is_single_peer_only(self):
        # A second destination for ONE private peer - not a mesh extra.
        with self.assertRaises(ValueError):
            nq.Engine(peers=["10.0.0.2", "10.0.0.3"], public="1.2.3.4")
        e = nq.Engine("10.0.0.2", public="1.2.3.4")
        self.assertEqual(nq.peer_label(e, "1.2.3.4"), "1.2.3.4  (public)")
        self.assertEqual(nq.peer_label(e, "10.0.0.2"), "10.0.0.2")

    def test_public_refuses_jumbo_probes(self):
        # Internet paths are 1500 B MTU: 1472 fits, 1473 and jumbo don't.
        nq.Engine("10.0.0.2", size=nq.PUBLIC_MAX_PROBE, public="1.2.3.4")
        for size in (nq.PUBLIC_MAX_PROBE + 1, 8972):
            with self.assertRaises(ValueError) as cm:
                nq.Engine("10.0.0.2", size=size, public="1.2.3.4")
            self.assertIn("1500 B MTU", str(cm.exception))
        # ...including a jumbo size hidden in a per-stream profile.
        prof = nq.resolve_profiles([(9000, None)], len(nq.STREAMS), 200)
        with self.assertRaises(ValueError):
            nq.Engine("10.0.0.2", profiles=prof, public="1.2.3.4")
        # Jumbo stays fine for the private peer alone.
        nq.Engine("10.0.0.2", size=8972)

    def test_rejects_same_endpoint_and_vxlan(self):
        with self.assertRaises(ValueError):
            nq.Engine("10.0.0.2", public="10.0.0.2")
        with self.assertRaises(ValueError):
            nq.Engine("10.0.0.2", public="1.2.3.4",
                      vxlan={"vni": 1, "port": 4789})

    def test_no_public_keeps_the_classic_shape(self):
        e = nq.Engine("10.0.0.2")
        self.assertIsNone(e.public)
        self.assertEqual(e.peers, e.private_peers)


class TestResponderLoopback(unittest.TestCase):
    """The responder's reflect path over real 127.0.0.1 sockets."""

    def setUp(self):
        udp, = free_ports(1)
        tcp, = free_ports(1, socket.SOCK_STREAM)
        patch = mock.patch.object(nq, "STREAMS",
                                  nq.build_streams((udp,), (tcp,)))
        patch.start()
        self.addCleanup(patch.stop)
        self.udp_port, self.tcp_port = udp, tcp
        self.lines = []
        self.stop = threading.Event()
        self.resp = None

    def start(self, allow="127.0.0.0/8"):
        self.resp = nq.Responder("127.0.0.1", nq._allow_list(allow),
                                 self.stop, out=self.lines.append)
        self.resp.start()
        self.addCleanup(self.resp.close)

    def client(self):
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        c.bind(("127.0.0.1", 0))
        c.settimeout(2.0)
        self.addCleanup(c.close)
        return c

    def test_udp_probe_is_echoed_with_egress_report(self):
        self.start()
        c = self.client()
        for seq in (1, 2, 4):   # seq 3 "lost" in the forward direction
            c.sendto(nq.build_packet(nq.TYPE_PROBE, 0, seq, 99, 200),
                     ("127.0.0.1", self.udp_port))
            data, _addr = c.recvfrom(65535)
        p = nq.parse_header(data)
        self.assertEqual(p[0], nq.TYPE_ECHO)
        self.assertEqual(p[2], 4)              # seq
        self.assertEqual(p[3], 99)             # originator timestamp intact
        self.assertEqual(p[5], 200)            # rxsize
        self.assertEqual(p[6], 1)              # one forward gap (seq 3)
        self.assertNotEqual(p[7], 0)           # responder clock
        self.assertEqual(nq.parse_src_report(data), c.getsockname())
        flows = self.resp.snapshot()["flows"]
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["rx"], 3)
        self.assertTrue(any("source 127.0.0.1 up" in ln for ln in self.lines))

    def test_test_probes_echo_without_gap_tracking(self):
        self.start()
        c = self.client()
        c.sendto(nq.build_packet(nq.TYPE_TEST, 0, 50, 1, 1200),
                 ("127.0.0.1", self.udp_port))
        data, _addr = c.recvfrom(65535)
        p = nq.parse_header(data)
        self.assertEqual((p[0], p[2], p[6]), (nq.TYPE_ECHO, 50, 0))

    def test_echoes_and_strangers_get_nothing(self):
        self.start(allow="10.0.0.0/8")   # loopback is NOT allowed
        c = self.client()
        c.settimeout(0.4)
        c.sendto(nq.build_packet(nq.TYPE_PROBE, 0, 1, 1, 200),
                 ("127.0.0.1", self.udp_port))
        with self.assertRaises(socket.timeout):
            c.recvfrom(65535)
        self.assertTrue(wait_for(lambda: self.resp.snapshot()["refused"] == 1))
        self.assertTrue(any("refused 127.0.0.1" in ln for ln in self.lines))

    def test_allowed_echo_packets_are_never_reflected(self):
        self.start()
        c = self.client()
        c.settimeout(0.4)
        c.sendto(nq.build_packet(nq.TYPE_ECHO, 0, 1, 1, 200),
                 ("127.0.0.1", self.udp_port))
        with self.assertRaises(socket.timeout):
            c.recvfrom(65535)

    def test_full_flow_table_drops_new_flows_not_live_ones(self):
        with mock.patch.object(nq, "RESPONDER_MAX_FLOWS", 1):
            self.start()
            a, b = self.client(), self.client()
            a.sendto(nq.build_packet(nq.TYPE_PROBE, 0, 1, 1, 200),
                     ("127.0.0.1", self.udp_port))
            a.recvfrom(65535)
            b.settimeout(0.4)
            b.sendto(nq.build_packet(nq.TYPE_PROBE, 0, 1, 1, 200),
                     ("127.0.0.1", self.udp_port))
            with self.assertRaises(socket.timeout):
                b.recvfrom(65535)
            self.assertEqual(self.resp.snapshot()["dropped_full"], 1)
            a.sendto(nq.build_packet(nq.TYPE_PROBE, 0, 2, 1, 200),
                     ("127.0.0.1", self.udp_port))
            a.recvfrom(65535)   # the live flow keeps being answered

    def test_tcp_probe_is_echoed_and_flow_ends_with_connection(self):
        self.start()
        conn = socket.create_connection(("127.0.0.1", self.tcp_port),
                                        timeout=2.0)
        with conn:
            conn.sendall(nq.build_packet(nq.TYPE_PROBE, 1, 1, 5, 120))
            msg = nq._recv_msg(conn)
            self.assertIsNotNone(msg)
            self.assertEqual(nq.parse_header(msg)[2], 1)
            self.assertEqual(nq.parse_src_report(msg), conn.getsockname())
            self.assertTrue(wait_for(
                lambda: len(self.resp.snapshot()["flows"]) == 1))
        self.assertTrue(wait_for(
            lambda: self.resp.snapshot()["flows"] == []
            and self.resp.snapshot()["conns"] == 0))

    def test_tcp_handshake_alone_is_not_a_flow(self):
        # The originator's 15 s connect-time sampler opens empty conns.
        self.start()
        socket.create_connection(("127.0.0.1", self.tcp_port),
                                 timeout=2.0).close()
        time.sleep(0.3)
        self.assertEqual(self.resp.snapshot()["flows"], [])

    def test_idle_udp_flows_expire(self):
        self.start()
        c = self.client()
        c.sendto(nq.build_packet(nq.TYPE_PROBE, 0, 1, 1, 200),
                 ("127.0.0.1", self.udp_port))
        c.recvfrom(65535)
        later = time.monotonic() + nq.RESPONDER_IDLE_S + 1
        with self.resp.lock:
            gone = self.resp._expire_locked(later)
        self.assertEqual(gone, ["127.0.0.1"])
        self.assertEqual(self.resp.snapshot()["flows"], [])


def _second_loopback():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.2", 0))
        return True
    except OSError:
        return False
    finally:
        s.close()


@unittest.skipUnless(_second_loopback(), "needs 127.0.0.2 (Linux loopback)")
class TestPublicPathEndToEnd(unittest.TestCase):
    """Branch engine on 127.0.0.2 probing a responder on 127.0.0.1 as its
    --public endpoint, with an unanswered private peer beside it."""

    def test_public_path_scores_and_names_its_egress(self):
        udp = free_ports(2)
        tcp = free_ports(2, socket.SOCK_STREAM)
        with mock.patch.object(nq, "STREAMS",
                               nq.build_streams(tuple(udp), tuple(tcp))):
            stop = threading.Event()
            resp = nq.Responder("127.0.0.1", nq._allow_list("127.0.0.2"),
                                stop, out=lambda _line: None)
            resp.start()
            eng = nq.Engine("127.0.0.3", bind="127.0.0.2", pps=20,
                            history_seconds=10, public="127.0.0.1")
            eng.start()
            try:
                self.assertTrue(wait_for(
                    lambda: eng.path_summary("127.0.0.1")["links_up"] == 4,
                    timeout=8.0))
                ps = eng.path_summary("127.0.0.1")
                self.assertEqual(ps["role"], "public")
                self.assertEqual(ps["egress"], ["127.0.0.2"])
                self.assertIsNotNone(ps["udp_mos"])
                self.assertIsNotNone(ps["tcp_pqi"])
                # The private peer never answers; the paths stay separate.
                self.assertFalse(eng.path_summary("127.0.0.3")["up"])
            finally:
                eng.shutdown()
                resp.close()


class TestPublicSurfaces(unittest.TestCase):
    def engine(self):
        e = nq.Engine("10.0.0.2", public="203.0.113.10", history_seconds=10)
        self.addCleanup(e.shutdown)
        return e

    def test_dashboard_payload_paths_and_selection(self):
        e = self.engine()
        args = nq.parse_args(["--peer", "10.0.0.2", "--public",
                              "203.0.113.10"])
        payload = nv_webui.build_dashboard_payload(nq, e, args)
        self.assertEqual([p["role"] for p in payload["paths"]],
                         ["private", "public"])
        self.assertEqual(payload["snap"]["role"], "private")
        pub = nv_webui.build_dashboard_payload(nq, e, args,
                                               peer="203.0.113.10")
        self.assertEqual(pub["snap"]["peer"], "203.0.113.10")
        self.assertIn("Public path", pub["snap"]["anatomy"]["note"])
        json.dumps(pub)   # serializable end to end

    def test_no_public_no_path_strip(self):
        e = nq.Engine("10.0.0.2")
        self.addCleanup(e.shutdown)
        args = nq.parse_args(["--peer", "10.0.0.2"])
        self.assertIsNone(
            nv_webui.build_dashboard_payload(nq, e, args)["paths"])

    def test_silent_public_path_is_explained_after_grace(self):
        e = self.engine()
        snap = e.snapshot("203.0.113.10")
        self.assertEqual(nv_webui._warning_from_snap(nq, snap), ("", ""))
        e.start_time -= nq.PUBLIC_SILENT_GRACE_S + 1
        msg, level = nv_webui._warning_from_snap(
            nq, e.snapshot("203.0.113.10"))
        self.assertEqual(level, "bad")
        self.assertIn("--responder", msg)
        self.assertIn("--allow", msg)

    def test_public_udp_silent_names_the_breakout_policy(self):
        snap = self.engine().snapshot("203.0.113.10")
        snap.update(udp_silent=True, links_up=2)
        msg, level = nv_webui._warning_from_snap(nq, snap)
        self.assertIn("public path", msg)
        self.assertEqual(level, "bad")

    def test_console_line(self):
        down = {"peer": "203.0.113.10", "up": False}
        self.assertIn("waiting", nq.public_path_line(down, 1.0))
        self.assertIn("--responder", nq.public_path_line(down, 60.0))
        up = {"peer": "203.0.113.10", "up": True, "score": 88.4,
              "label": "Excellent", "links_up": 4, "stream_count": 4,
              "rtt": 23.14, "loss_pct": 0.0, "udp_mos": 4.31,
              "tcp_pqi": 91.0, "egress": ["198.51.100.7"]}
        line = nq.public_path_line(up, 60.0)
        for part in ("88/100", "RTT 23.1 ms", "MOS 4.31", "PQI 91",
                     "egress 198.51.100.7"):
            self.assertIn(part, line)

    def test_report_carries_the_public_path(self):
        e = self.engine()
        args = nq.parse_args(["--peer", "10.0.0.2", "--public",
                              "203.0.113.10"])
        data = nq.build_report(e, args)
        self.assertEqual(data["public"]["endpoint"], "203.0.113.10")
        self.assertFalse(data["public"]["up"])
        html = nq.render_report_html(data)
        self.assertIn("Public path (local breakout / SSE)", html)
        self.assertIsNone(nq.build_report(nq.Engine("10.0.0.2"), args)
                          ["public"])

    def test_snapshot_route_selects_public_path(self):
        e = self.engine()
        args = nq.parse_args(["--peer", "10.0.0.2", "--public",
                              "203.0.113.10"])
        ctx = nv_webui._UiContext("dashboard", nq, engine=e, args=args)
        port = nv_webui._pick_port()
        httpd = nv_webui.ThreadingHTTPServer(("127.0.0.1", port),
                                             nv_webui.make_handler(ctx))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            for q, role in (("", "private"), ("?path=public", "public"),
                            ("?path=bogus", "private")):
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/api/snapshot{q}",
                        timeout=3) as resp:
                    self.assertEqual(
                        json.loads(resp.read())["snap"]["role"], role, q)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_load_generator_retargets(self):
        port, = free_ports(1)
        # Built against the private peer (TEST-NET: never actually sent
        # to), then started at the public endpoint.
        lg = nq.LoadGenerator("192.0.2.1", port, bind="127.0.0.1")
        err = lg.start(0.01, peer="127.0.0.1")
        self.assertIsNone(err)
        try:
            self.assertEqual(lg.status()["peer"], "127.0.0.1")
        finally:
            lg.stop()
            lg.thread.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
