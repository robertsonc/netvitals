"""Tests for the route view and source reporting (3.2.0): hop statistics,
the tracer's round folding (destination discovery, path changes, latency
attribution, the ICMP rate-limit hint), address classes, the NAT verdict,
the ICMP offender parser, the report/console/web surfaces, and the admin-
free probe backends against real loopback sockets on the platforms that
have one (Linux: UDP + IP_RECVERR; Windows: IcmpSendEcho)."""
import json
import os
import socket
import struct
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import netquality as nq  # noqa: E402
import nv_webui  # noqa: E402


def wait_for(pred, timeout=5.0, step=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(step)
    return pred()


class FakeBackend:
    """A scripted network: `paths` maps round number -> {ttl: reply}; the
    last entry repeats. Replies are (kind, addr, rtt_ms, flag)."""

    name = "fake"

    def __init__(self, *paths):
        self.paths = paths
        self.calls = []
        self.closed = False

    def describe(self):
        return "fake network"

    def round(self, ip, ttls, timeout, seq):
        ttls = list(ttls)
        self.calls.append(ttls)
        script = self.paths[min(len(self.calls) - 1, len(self.paths) - 1)]
        return {t: r for t, r in script.items() if t in ttls}

    def close(self):
        self.closed = True


THREE_HOPS = {1: ("hop", "10.1.1.1", 0.5, None),
              2: ("hop", "81.2.3.2", 4.0, None),
              3: ("dest", "91.4.5.2", 22.0, None)}


class TestAddressClassAndNat(unittest.TestCase):
    def test_ip_class(self):
        cases = {"10.1.1.1": "private", "172.20.0.1": "private",
                 "192.168.1.1": "private", "100.64.12.1": "cgnat",
                 "8.8.8.8": "public", "127.0.0.1": "loopback",
                 "169.254.1.1": "link-local", "not-an-ip": "other",
                 # documentation ranges are NOT RFC 1918, despite
                 # ipaddress.is_private saying True for them
                 "192.0.2.1": "other", "203.0.113.7": "other"}
        for ip, want in cases.items():
            self.assertEqual(nq.ip_class(ip), want, ip)

    def test_nat_verdict(self):
        v = nq.nat_verdict
        self.assertEqual(v("10.1.1.20", [(30201, ("10.1.1.20", 30201))]),
                         "none")
        self.assertEqual(v("10.1.1.20", [(30201, ("81.2.3.1", 30201))]),
                         "nat")
        self.assertEqual(v("10.1.1.20", [(30201, ("81.2.3.1", 40211))]),
                         "napt")
        self.assertEqual(v("10.1.1.20", [(30201, ("10.1.1.20", 40211))]),
                         "pat")
        # one translated stream is enough to call it
        self.assertEqual(v("10.1.1.20", [(30201, ("81.2.3.1", 30201)),
                                         (30202, ("81.2.3.1", 51000))]),
                         "napt")
        self.assertIsNone(v("10.1.1.20", [(30201, None)]))
        self.assertIsNone(v("0.0.0.0", [(30201, ("81.2.3.1", 30201))]))
        self.assertEqual(set(nq.NAT_LABELS), {"none", "nat", "napt", "pat"})


class TestIcmpOffender(unittest.TestCase):
    @staticmethod
    def cmsg(origin=2, typ=11, code=0, ip="81.2.3.2"):
        ee = struct.pack("=IBBBBII", 113, origin, typ, code, 0, 0, 0)
        sin = (struct.pack("=H", socket.AF_INET) + struct.pack("!H", 0)
               + socket.inet_aton(ip) + b"\0" * 8)
        return [(socket.IPPROTO_IP, nq.IP_RECVERR or 11, ee + sin)]

    def test_time_exceeded_names_the_hop(self):
        self.assertEqual(nq.parse_icmp_offender(self.cmsg()),
                         (11, 0, "81.2.3.2"))
        self.assertEqual(nq.parse_icmp_offender(self.cmsg(typ=3, code=13)),
                         (3, 13, "81.2.3.2"))

    def test_non_icmp_or_short_is_none(self):
        self.assertIsNone(nq.parse_icmp_offender(self.cmsg(origin=1)))
        self.assertIsNone(nq.parse_icmp_offender(
            [(socket.IPPROTO_IP, nq.IP_RECVERR or 11, b"\0" * 12)]))
        self.assertIsNone(nq.parse_icmp_offender([]))

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux ABI")
    def test_ip_recverr_is_usable_on_linux(self):
        # Regression: CPython doesn't export IP_RECVERR, so 2.0.0's
        # hasattr() gate never enabled the error queue (the MTU sweep's
        # PMTUD verdict and now the route view depend on it).
        self.assertEqual(nq.IP_RECVERR, 11)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.assertTrue(nq.enable_icmp_err(s))
        finally:
            s.close()


class TestHopStats(unittest.TestCase):
    def test_mtr_style_stats(self):
        h = nq.HopStats(3)
        for rtt in (10.0, 12.0, 11.0):
            h.on_reply("hop", "81.2.3.2", rtt)
        h.on_timeout()
        s = h.summary()
        self.assertEqual((s["sent"], s["recv"]), (4, 3))
        self.assertAlmostEqual(s["loss_pct"], 25.0)
        self.assertEqual((s["best"], s["worst"], s["last"]),
                         (10.0, 12.0, 11.0))
        self.assertAlmostEqual(s["avg"], 11.0)
        self.assertEqual(s["history"], [10.0, 12.0, 11.0, None])
        self.assertGreater(s["jitter"], 0)
        self.assertEqual(s["addr"], "81.2.3.2")

    def test_route_change_needs_a_margin(self):
        h = nq.HopStats(2)
        for _ in range(6):
            h.on_reply("hop", "81.2.3.2", 4.0)
        h.on_reply("hop", "91.9.9.9", 4.0)          # one stray: no change
        self.assertEqual(h.summary()["changes"], [])
        for _ in range(8):
            h.on_reply("hop", "91.9.9.9", 4.0)      # sustained: a change
        s = h.summary()
        self.assertEqual(s["addr"], "91.9.9.9")
        self.assertEqual(len(s["changes"]), 1)
        self.assertEqual(s["changes"][0][1:], ("81.2.3.2", "91.9.9.9"))

    def test_alternating_responders_are_ecmp_not_flaps(self):
        h = nq.HopStats(4)
        for i in range(12):
            h.on_reply("hop", "10.9.0.1" if i % 2 else "10.9.0.2", 5.0)
        s = h.summary()
        self.assertTrue(s["ecmp"])
        self.assertEqual(s["changes"], [])
        tags = dict((t, k) for k, t in nq.hop_tags(dict(
            s, **{"class": "private", "rate_limited": False})))
        self.assertIn("ECMP ×2", tags)


class TestTracerFolding(unittest.TestCase):
    def tracer(self):
        return nq.RouteTracer("91.4.5.2", 30201, backend=FakeBackend(),
                              rdns=False)

    def test_destination_found_trims_the_tail(self):
        tr = self.tracer()
        replies = dict(THREE_HOPS)
        replies.update({t: ("dest", "91.4.5.2", 22.0, None)
                        for t in range(4, 31)})   # every TTL >= 3 arrives
        tr.fold(replies, 30)
        self.assertEqual(tr.dest_ttl, 3)
        self.assertEqual(sorted(tr.hops), [1, 2, 3])
        self.assertEqual(tr._limit(), 3)
        snap = tr.snapshot()
        self.assertTrue(snap["reached"])
        self.assertEqual([h["kind"] for h in snap["hops"]],
                         ["hop", "hop", "dest"])

    def test_latency_is_attributed_by_best_rtt(self):
        tr = self.tracer()
        tr.fold(THREE_HOPS, 3)
        tr.fold({1: ("hop", "10.1.1.1", 0.4, None),
                 2: ("hop", "81.2.3.2", 3.0, None),     # new best at hop 2
                 3: ("dest", "91.4.5.2", 21.0, None)}, 3)
        hops = tr.snapshot()["hops"]
        self.assertEqual([h["best"] for h in hops], [0.4, 3.0, 21.0])
        self.assertEqual([round(h["delta"], 1) for h in hops],
                         [0.4, 2.6, 18.0])
        self.assertEqual(tr.snapshot()["total_ms"], 21.0)

    def test_attribution_never_goes_negative(self):
        # A slow-path router can answer SLOWER than the hop after it.
        tr = self.tracer()
        tr.fold({1: ("hop", "10.1.1.1", 9.0, None),
                 2: ("dest", "91.4.5.2", 5.0, None)}, 2)
        self.assertEqual([h["delta"] for h in tr.snapshot()["hops"]],
                         [9.0, 0.0])

    def test_path_getting_longer_reopens_the_search(self):
        tr = self.tracer()
        tr.fold(THREE_HOPS, 3)
        self.assertEqual(tr.dest_ttl, 3)
        tr.fold({1: THREE_HOPS[1], 2: THREE_HOPS[2],
                 3: ("hop", "81.9.9.9", 9.0, None)}, 3)
        self.assertIsNone(tr.dest_ttl)
        self.assertGreater(tr._limit(), 3)

    def test_unreachable_is_terminal_and_tagged(self):
        tr = self.tracer()
        tr.fold({1: THREE_HOPS[1],
                 2: ("unreach", "81.2.3.2", 4.0,
                     "administratively prohibited")}, 30)
        snap = tr.snapshot()
        self.assertEqual(tr.dest_ttl, 2)
        self.assertIn(("bad", "administratively prohibited"),
                      nq.hop_tags(snap["hops"][-1]))

    def test_silent_tail_collapses_and_limit_backs_off(self):
        tr = self.tracer()
        for _ in range(3):
            tr.fold({1: THREE_HOPS[1], 2: THREE_HOPS[2]}, 30)
        snap = tr.snapshot()
        self.assertEqual([h["ttl"] for h in snap["hops"]], [1, 2])
        self.assertEqual(snap["silent_tail"], 28)
        self.assertFalse(snap["reached"])
        self.assertEqual(tr._limit(), 2 + nq.ROUTE_MAX_UNKNOWN)

    def test_rate_limit_hint_only_when_loss_does_not_carry(self):
        tr = self.tracer()
        for i in range(10):
            got = dict(THREE_HOPS)
            if i % 2:
                del got[2]              # hop 2 drops half its ICMP...
            tr.fold(got, 3)             # ...but hop 3 answers every time
        hops = tr.snapshot()["hops"]
        self.assertTrue(hops[1]["rate_limited"])
        self.assertFalse(hops[2]["rate_limited"])
        tr2 = self.tracer()
        for i in range(10):
            tr2.fold({1: THREE_HOPS[1]} if i % 2 else THREE_HOPS, 3)
        # Loss that carries on to the destination is real, not a hint.
        self.assertFalse(tr2.snapshot()["hops"][1]["rate_limited"])

    def test_live_loop_with_a_fake_network(self):
        fake = FakeBackend(THREE_HOPS)
        tr = nq.RouteTracer("127.0.0.1", 30201, backend=fake, interval=0.02,
                            rdns=False)
        tr.start()
        try:
            self.assertTrue(wait_for(lambda: tr.rounds >= 5))
        finally:
            tr.stop()
        self.assertTrue(wait_for(lambda: not tr.running))
        self.assertTrue(fake.closed)
        self.assertEqual(len(fake.calls[0]), nq.ROUTE_MAX_HOPS)
        self.assertEqual(fake.calls[-1], [1, 2, 3])   # stopped at the dest
        self.assertEqual(tr.snapshot()["method"], "fake network")

    def test_idle_tracer_stops_itself(self):
        tr = nq.RouteTracer("127.0.0.1", 30201,
                            backend=FakeBackend(THREE_HOPS), interval=0.02,
                            idle_stop=0.2, rdns=False)
        tr.start()
        self.assertTrue(wait_for(lambda: not tr.running, timeout=3.0))

    def test_unavailable_platform_reports_why(self):
        with mock.patch.object(nq.sys, "platform", "darwin"):
            with self.assertRaises(nq.RouteUnavailable):
                nq.make_route_backend("0.0.0.0", 30201)


class TestEngineRoutes(unittest.TestCase):
    def test_one_path_traced_at_a_time(self):
        e = nq.Engine("10.0.0.2", public="203.0.113.10")
        self.addCleanup(e.shutdown)
        a = e.route("10.0.0.2", backend=FakeBackend(THREE_HOPS))
        self.assertIs(e.route("10.0.0.2"), a)      # reused while running
        b = e.route("203.0.113.10", backend=FakeBackend(THREE_HOPS))
        self.assertTrue(wait_for(lambda: not a.running))
        self.assertTrue(b.running)
        e.shutdown()
        self.assertTrue(wait_for(lambda: not b.running))

    def test_route_payload_marks_the_nat_boundary(self):
        e = nq.Engine("10.0.0.2", public="203.0.113.10")
        self.addCleanup(e.shutdown)
        e.local_src["203.0.113.10"] = "10.1.1.20"
        for sid, proto, port, _n in nq.STREAMS:
            if proto == "UDP":
                e.stats[("203.0.113.10", sid)].seen_as = ("81.2.3.1", port)
        tr = nq.RouteTracer("203.0.113.10", 30201, backend=FakeBackend(),
                            rdns=False)
        tr.fold({1: ("hop", "10.1.1.1", 0.5, None),
                 2: ("hop", "100.64.0.1", 3.0, None),
                 3: ("hop", "81.2.3.2", 4.0, None),
                 4: ("dest", "203.0.113.10", 22.0, None)}, 4)
        with mock.patch.object(nq.Engine, "route", lambda self, p: tr):
            r = nv_webui.build_route_payload(nq, e, "203.0.113.10")
        self.assertEqual(r["role"], "public")
        self.assertEqual(r["identity"]["nat"], "nat")
        self.assertEqual(r["identity"]["source"], "10.1.1.20")
        self.assertEqual(r["nat_after"], 2)        # after the CGNAT hop
        self.assertEqual(r["route"]["hops"][0]["tags"][0],
                         {"k": "gateway", "t": "gateway"})
        json.dumps(r)

    def test_report_and_console_carry_the_route(self):
        e = nq.Engine("10.0.0.2", public="203.0.113.10")
        self.addCleanup(e.shutdown)
        tr = nq.RouteTracer("203.0.113.10", 30201, backend=FakeBackend(),
                            rdns=False)
        tr.fold(THREE_HOPS, 3)
        e.routes["203.0.113.10"] = tr
        args = nq.parse_args(["--peer", "10.0.0.2", "--public",
                              "203.0.113.10"])
        data = nq.build_report(e, args)
        self.assertEqual(len(data["routes"]["public"]["hops"]), 3)
        self.assertIn("gateway", data["routes"]["public"]["hops"][0]["tags"])
        html = nq.render_report_html(data)
        self.assertIn("Route — public path", html)
        lines = nq.format_route("public", tr.snapshot())
        text = "\n".join(lines)
        self.assertIn("81.2.3.2", text)
        self.assertIn("destination", text)


class TestSymmetricReflectorReportsSource(unittest.TestCase):
    """Regular peers stamp the source they saw too (not only responders),
    so the private path gets a NAT verdict as well."""

    def test_udp_reflector_stamps_source(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        stop = threading.Event()
        cfg = (0, "UDP", port, f"UDP-{port}")
        st = nq.StreamStats()
        us = nq.UDPStream(cfg, ["127.0.0.1"], "127.0.0.1", (200,), 3600.0,
                          {"127.0.0.1": st}, stop)
        us.start()
        self.addCleanup(stop.set)
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        c.bind(("127.0.0.1", 0))
        c.settimeout(2.0)
        self.addCleanup(c.close)
        c.sendto(nq.build_packet(nq.TYPE_PROBE, 0, 1, 7, 200),
                 ("127.0.0.1", port))
        while True:
            data, _addr = c.recvfrom(65535)
            if nq.parse_header(data)[0] == nq.TYPE_ECHO:
                break
        self.assertEqual(nq.parse_src_report(data), c.getsockname())


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux backend")
class TestUdpBackendLoopback(unittest.TestCase):
    def test_trace_to_a_local_responder(self):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 0))
        port = udp.getsockname()[1]
        udp.close()
        stop = threading.Event()
        with mock.patch.object(nq, "STREAMS", nq.build_streams((port,), ())):
            resp = nq.Responder("127.0.0.1", nq._allow_list("127.0.0.0/8"),
                                stop, out=lambda _l: None)
            resp.start()
        self.addCleanup(resp.close)
        backend = nq._UdpTtlBackend("127.0.0.1", port)
        try:
            got = backend.round("127.0.0.1", range(1, 3), 1.0, seq=1)
        finally:
            backend.close()
        self.assertEqual(got[1][:2], ("dest", "127.0.0.1"))

    def test_trace_to_a_closed_port_ends_at_port_unreachable(self):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 0))
        port = udp.getsockname()[1]
        udp.close()     # nothing listens: the host answers ICMP 3/3
        backend = nq._UdpTtlBackend("127.0.0.1", port)
        try:
            got = backend.round("127.0.0.1", [1], 1.0, seq=1)
        finally:
            backend.close()
        self.assertEqual(got[1][:2], ("dest", "127.0.0.1"))


@unittest.skipUnless(sys.platform == "win32", "Windows backend")
class TestIcmpBackendLoopback(unittest.TestCase):
    def test_icmp_echo_to_loopback(self):
        backend = nq._IcmpEchoBackend()
        got = backend.round("127.0.0.1", [1, 2], 1.0, seq=1)
        self.assertIn(1, got)
        self.assertEqual(got[1][:2], ("dest", "127.0.0.1"))


if __name__ == "__main__":
    unittest.main()
