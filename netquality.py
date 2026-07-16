#!/usr/bin/env python3
"""
Network Vitals (netquality.py) - bidirectional network quality probe between
two workstations.

A single, self-contained, dependency-free Python app. Run the SAME program on
both workstations. Each instance continuously sends AND receives:

    * 2 UDP probe streams  (default ports 30201 and 30202)
    * 2 TCP probe streams  (default ports 30101 and 30102)

Every stream is a probe -> echo loop, so round-trip time (and therefore latency,
loss and jitter) is measured without needing the two clocks to be synchronized.
A realtime GUI (Tkinter, ships with Windows Python) shows per-stream loss,
latency and jitter, plus an overall connection quality score (ITU-T E-model
R-factor / MOS). If no display is available it falls back to a console UI
(keys: r = reset counters, q = quit; shows since-reset AND lifetime totals).

With --vxlan on both ends, all probe traffic is carried inside genuine VXLAN
encapsulation between the hosts (userspace VTEP, no admin rights) - used to
demonstrate transparent fragmentation of encapsulated traffic.

Typical use
-----------
On workstation A (IP 10.0.0.1):   python netquality.py --peer 10.0.0.2
On workstation B (IP 10.0.0.2):   python netquality.py --peer 10.0.0.1

That is all the configuration required - the protocol is fully symmetric.

Local loopback smoke test (one machine, Linux only - two loopback aliases):
    python netquality.py --bind 127.0.0.1 --peer 127.0.0.2 --no-gui
    python netquality.py --bind 127.0.0.2 --peer 127.0.0.1 --no-gui
"""

import argparse
import array
import json
import math
import os
import re
import socket
import struct
import sys
import threading
import time
import traceback
from collections import deque

__version__ = "1.6.2"

# Where --update / --check-update look for the latest release of this file.
# Override with --update-url (or keep a fork's URL here).
UPDATE_URL = ("https://raw.githubusercontent.com/robertsonc/netvitals/"
              "main/netquality.py")

# ---------------------------------------------------------------------------
# Wire protocol
# ---------------------------------------------------------------------------
# Every probe/echo packet has a fixed header. For UDP it is one datagram; for
# TCP every message is exactly `size` bytes so the reader can frame on length.
#
#   magic   : uint32  - identifies our traffic, ignores stray packets
#   ptype   : uint8   - PROBE or ECHO
#   sid     : uint8   - stream id (which port/proto this belongs to)
#   seq     : uint32  - per-stream sequence number
#   ts_ns   : uint64  - originator's monotonic clock at send time (echoed back)
#
# The reflector copies the header back verbatim with ptype flipped to ECHO, so
# the originator computes RTT = now - ts_ns purely against its OWN clock.

MAGIC = 0x4E51_5632  # "NQV2" (V2: echoes carry the reflector's clock, peer_ns)
# magic(I) type(B) sid(B) seq(I) ts_ns(Q) psize(H) rxsize(H) rxcount(I) peer_ns(Q)
#   psize   = the total size this packet is meant to be (self-describing; lets
#             the receiver assert it got a full-size datagram - jumbo testing).
#   rxsize  = bytes the reflector actually received (0 in a probe; filled into
#             the echo) so the originator learns the delivered size.
#   rxcount = the reflector's cumulative count of probes received on this stream
#             (0 in a probe; filled into the echo) so the originator can split
#             its round-trip loss into forward (probes that never reached the
#             peer) vs return (echoes that never made it back) - loss isolation.
#   peer_ns = the reflector's monotonic clock when it built the echo (0 in a
#             probe). The two clocks share no epoch, so peer_ns - ts_ns is the
#             forward one-way delay plus an unknown constant offset - useless
#             absolutely, but its CHANGE against a min-filtered baseline shows
#             which direction's delay is growing (see StreamStats.on_echo).
HEADER = struct.Struct("!IBBIQHHIQ")
HEADER_LEN = HEADER.size  # 34 bytes
MAX_SIZE = 65535          # psize/rxsize are uint16
MAX_COUNT = 0xFFFF_FFFF   # rxcount is uint32

TYPE_PROBE = 1
TYPE_ECHO = 2
# Side-channel test probe (MTU sweep, burst test): echoed like a probe but
# NOT folded into the reflector's gap tracking, so a test running alongside a
# live session can't pollute the session's forward/return loss isolation.
TYPE_TEST = 3

# Stream catalogue. Order is the display order in the UI; sids stay 0..3 so the
# colour map and chart series are stable regardless of which ports are chosen.
#   (sid, proto, port, label)
#
# Default ports live in the unassigned 30100/30200 block: below every OS
# ephemeral range (Windows 49152+, Linux 32768+) so the OS won't hand them to an
# outbound socket, and with no Wireshark dissector (unlike 5201, iPerf3's default
# port, which made Wireshark misparse our packets as iPerf3 traffic).
DEFAULT_UDP_PORTS = (30201, 30202)
DEFAULT_TCP_PORTS = (30101, 30102)


def build_streams(udp_ports, tcp_ports):
    """Build the stream catalogue from the chosen UDP/TCP port pairs."""
    streams = []
    sid = 0
    for port in udp_ports:
        streams.append((sid, "UDP", port, f"UDP-{port}"))
        sid += 1
    for port in tcp_ports:
        streams.append((sid, "TCP", port, f"TCP-{port}"))
        sid += 1
    return streams


STREAMS = build_streams(DEFAULT_UDP_PORTS, DEFAULT_TCP_PORTS)


def ports_summary():
    """e.g. 'UDP 30201/30202  TCP 30101/30102' from the current STREAMS."""
    udp = "/".join(str(p) for _, proto, p, _ in STREAMS if proto == "UDP")
    tcp = "/".join(str(p) for _, proto, p, _ in STREAMS if proto == "TCP")
    return f"UDP {udp}  TCP {tcp}"


def build_packet(ptype, sid, seq, ts_ns, size, rxsize=0, rxcount=0, peer_ns=0):
    """Build a fixed-size packet padded out to `size` bytes.

    `size` is stamped into the header (psize) so the receiver can confirm it got
    a full-size datagram; `rxsize`/`rxcount`/`peer_ns` are the size, cumulative
    probe count and clock the reflector observed (set only on echoes).
    """
    if size < HEADER_LEN:
        size = HEADER_LEN
    if size > MAX_SIZE:
        size = MAX_SIZE
    hdr = HEADER.pack(MAGIC, ptype, sid, seq & MAX_COUNT, ts_ns, size,
                      min(rxsize, MAX_SIZE), rxcount & MAX_COUNT, peer_ns)
    return hdr + b"\x00" * (size - HEADER_LEN)


def parse_header(data):
    """Return (ptype, sid, seq, ts_ns, psize, rxsize, rxcount, peer_ns) or None."""
    if len(data) < HEADER_LEN:
        return None
    fields = HEADER.unpack(data[:HEADER_LEN])
    if fields[0] != MAGIC:
        return None
    return fields[1:]  # ptype, sid, seq, ts_ns, psize, rxsize, rxcount, peer_ns


# Socket buffer size. Windows defaults to a small (~64 KB) UDP receive buffer.
# Thread-scheduler/timer granularity (~15 ms on Windows) makes probes go out in
# bursts; on a clean, low-jitter path those bursts arrive still bunched and can
# momentarily overrun a small receive buffer, dropping UDP datagrams that then
# look like packet loss. Enlarging the buffer absorbs the microbursts so the
# loss we report reflects the wire, not a local buffer overflow.
SOCK_BUF_BYTES = 4 * 1024 * 1024


def enlarge_socket_buffers(sock):
    """Best-effort enlarge of the send/receive buffers (ignored if capped)."""
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, SOCK_BUF_BYTES)
        except OSError:
            pass


def bind_exclusively(sock):
    """Bind-time socket options, per platform.

    On Windows SO_REUSEADDR lets a SECOND process bind the very same UDP/TCP
    port, after which inbound packets are split between the two processes
    nondeterministically — an accidentally double-launched instance reads as
    huge random packet loss. SO_EXCLUSIVEADDRUSE restores sane semantics.
    Elsewhere SO_REUSEADDR just skips TIME_WAIT on restart.
    """
    if sys.platform == "win32":
        opt = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if opt is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, opt, 1)
            except OSError:
                pass
    else:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def quench_udp_connreset(sock):
    """Stop Windows from surfacing ICMP Port Unreachable as an error on the
    UDP socket itself.

    When the peer app isn't running yet, our sendto() elicits ICMP Port
    Unreachable and Windows then raises ConnectionResetError (WSAECONNRESET)
    from the NEXT recvfrom()/sendto() on the same socket. The receive loops
    also catch that error, but each one still swallows a socket call - under
    a stream of ICMP (peer app down or restarting) that means silently
    dropped probes and echoes. This ioctl turns the reporting off entirely.

    NOTE: this must go through WSAIoctl directly. CPython's socket.ioctl()
    wrapper only accepts SIO_RCVALL / SIO_KEEPALIVE_VALS /
    SIO_LOOPBACK_FAST_PATH and raises ValueError for SIO_UDP_CONNRESET, so
    the obvious sock.ioctl(...) call is a silent no-op (an earlier version
    of this function did exactly that and quenched nothing).
    No-op on non-Windows platforms.
    """
    if sys.platform != "win32":
        return
    SIO_UDP_CONNRESET = 0x9800000C  # _WSAIOW(IOC_VENDOR, 12)
    try:
        import ctypes
        from ctypes import wintypes
        ws2 = ctypes.WinDLL("ws2_32")
        ws2.WSAIoctl.argtypes = [
            ctypes.c_void_p,                    # SOCKET s
            wintypes.DWORD,                     # dwIoControlCode
            ctypes.c_void_p, wintypes.DWORD,    # lpvInBuffer,  cbInBuffer
            ctypes.c_void_p, wintypes.DWORD,    # lpvOutBuffer, cbOutBuffer
            ctypes.POINTER(wintypes.DWORD),     # lpcbBytesReturned
            ctypes.c_void_p, ctypes.c_void_p,   # lpOverlapped, lpCompletionRoutine
        ]
        ws2.WSAIoctl.restype = ctypes.c_int
        report = wintypes.BOOL(0)               # FALSE -> stop reporting resets
        returned = wintypes.DWORD(0)
        ws2.WSAIoctl(sock.fileno(), SIO_UDP_CONNRESET,
                     ctypes.byref(report), ctypes.sizeof(report),
                     None, 0, ctypes.byref(returned), None, None)
    except Exception:
        pass  # best effort; the recv loops still catch ConnectionResetError


def resolve_peer_ip(peer):
    """Resolve the peer to an IP for source-address filtering (None if we
    can't resolve, in which case filtering is skipped)."""
    try:
        return socket.gethostbyname(peer)
    except OSError:
        return None


def set_dont_fragment(sock):
    """Set the IPv4 Don't-Fragment bit so oversized datagrams are dropped, not
    fragmented - required to actually test jumbo frames end to end. Returns
    True if it took effect. Platform-specific; best effort."""
    try:
        if sys.platform == "win32":
            ip_dontfrag = getattr(socket, "IP_DONTFRAGMENT", 14)
            sock.setsockopt(socket.IPPROTO_IP, ip_dontfrag, 1)
        else:
            ip_mtu_discover = getattr(socket, "IP_MTU_DISCOVER", 10)
            pmtudisc_do = getattr(socket, "IP_PMTUDISC_DO", 2)
            sock.setsockopt(socket.IPPROTO_IP, ip_mtu_discover, pmtudisc_do)
        return True
    except (OSError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# Per-stream statistics (thread-safe, sliding window)
# ---------------------------------------------------------------------------
class StreamStats:
    """Rolling-window stats for one originated stream.

    Loss accounting distinguishes three terminal outcomes for every probe:

      * recv  - echo returned within `timeout` (on time).
      * lost  - no echo within `timeout` and still none -> a real drop.
      * late  - echo arrived AFTER the timeout deadline (reordered / over-
                buffered). It physically came back, but too late to be useful
                to a real-time stream, so it is reclassified lost -> late.

    Loss% and Late% are computed over the sliding `window`; the quality score
    treats (loss + late) as the effective impairment.
    """

    def __init__(self, window=10.0, timeout=2.0, target_pps=None):
        self.lock = threading.Lock()
        self.window = window          # seconds of history kept for rates/loss
        self.timeout = timeout        # an un-echoed probe older than this = lost
        self.target_pps = target_pps  # offered probe rate (for throughput ratio)
        # All window bookkeeping uses time.monotonic(): an NTP step on the
        # wall clock must not empty the window or freeze rate/loss figures.
        self.window_start = time.monotonic()  # for accurate rates before window fills

        self.rtt_samples = deque()    # (t_mono, rtt_ms) for on-time echoes only
        self.tx_events = deque()      # t_mono of probes sent
        self.connect_samples = deque(maxlen=8)  # recent TCP connect times (ms)

        # Windowed per-probe outcomes. `resolved_order` keeps insertion order so
        # we can trim by time; `state` maps seq -> 'recv'|'lost'|'late' and is
        # updated in place when a lost probe is later reclassified as late.
        self.resolved_order = deque() # (resolve_mono, seq)
        self.state = {}               # seq -> outcome

        self.pending = {}             # seq -> (send_mono, send_monotonic_ns)
        self.jitter = 0.0             # RFC-3550 style smoothed jitter (ms)
        self.last_rtt = None
        self.last_echo_t = 0.0        # monotonic time of most recent echo (any kind)

        # One-way-delay drift. Each on-time echo gives two RELATIVE delays:
        # forward = peer_clock_at_echo - my_clock_at_send, return = my_clock_at
        # _receive - peer_clock_at_echo. Both contain the unknown clock offset
        # (equal and opposite), so only their movement means anything: the
        # drift of each against its min over ~60 s shows which DIRECTION is
        # queueing (long enough that a congestion episode can't drag the
        # baseline up with it, short enough that relative clock slew at tens
        # of ppm => ~1 ms/min stays negligible). Kept as 5 s bucket minima +
        # a short raw tail, NOT raw samples: this lock is shared with the
        # receive threads, so snapshot() must never scan minutes of samples
        # while echoes wait (1.5.0 did, and the stall clumped the echo path
        # into microbursts that read as return loss on busy hosts).
        self.owd_recent = deque(maxlen=15)   # last few (fwd_rel, rtn_rel)
        self.owd_buckets = deque()           # (bucket_end_mono, min_f, min_r)
        self.owd_bucket_s = 5.0
        self.owd_horizon = max(window, 60.0)
        self._owd_count = 0

        # Loss-pattern diagnostics: when each lost probe was reaped, kept for
        # ~60 s so the engine can classify recent loss as bursty vs scattered
        # and correlated-across-streams vs port-specific.
        self.loss_events = deque()    # t_mono of each probe declared lost
        self.diag_horizon = 60.0

        # cumulative session counters (for the footer / totals)
        self.cum_tx = 0
        self.cum_recv = 0
        self.cum_lost = 0
        self.cum_late = 0

        # Lifetime counters: same tallies as cum_* but NEVER cleared by
        # reset(), so the UI can show "since reset" and "lifetime" side by
        # side - the loss over the whole run vs. the loss since the last
        # reset, without restarting the app.
        self.life_tx = 0
        self.life_recv = 0
        self.life_lost = 0
        self.life_late = 0

        # packet-size verification (jumbo-frame testing)
        self.rx_echo_max = 0      # largest echo datagram received (return path)
        self.peer_rx_max = 0      # largest size the far end reported receiving
        self.size_mismatch = 0    # echoes whose length != the stamped size

        # Loss localization: the reflector detects forward loss as GAPS in the
        # peer's sequence numbers (epoch-independent, immune to which app started
        # first), and echoes the running gap count back. Forward = those gaps;
        # return = round-trip lost - forward. seq is monotonic for UDP; for TCP
        # it restarts each reconnect, which we detect as a large backward jump.
        self.refl_rx = 0          # probes we received from the peer (reference)
        self.refl_first = 0       # first peer seq seen this run (0 = unset)
        self.refl_max = 0         # highest peer seq seen this run
        self.refl_run = 0         # probes received in the current seq run
        self.refl_gap = 0         # forward-loss gaps finalized from prior runs
        # Candidate peer-restart marker: (seq, counted_into_run). A single
        # large backward seq jump may just be a deeply reordered packet; two
        # in a row with ascending seqs confirm the peer restarted.
        self._reset_pend = None
        self.peer_fwd = 0         # forward-loss count the peer reports (see on_echo)
        self.peer_fwd_seq = 0     # seq of the echo that carried peer_fwd
        # The peer's reflector counter is a LIFETIME total that survives our
        # Reset button and our process restarting. Baseline it against the
        # first echo we see so only gaps accrued during THIS session count.
        self.peer_fwd_base = None

    # -- producers (called from network threads) --------------------------
    def on_probe_rx(self, seq):
        """Reflector side: fold a received probe's seq into gap tracking and
        return the cumulative forward-loss count to stamp into the echo."""
        with self.lock:
            self.refl_rx += 1
            if self.refl_first == 0:
                self.refl_first = self.refl_max = seq
                self.refl_run = 1
            elif seq < self.refl_max - 100:
                # A large backward jump is EITHER the peer's app restarting
                # (its seq begins again near 1) or a packet reordered/delayed
                # by hundreds of positions. Require two such packets in a row
                # with ascending seqs before declaring a restart; a lone one
                # is treated as a very-late member of the current run, so deep
                # reordering can no longer fabricate hundreds of phantom
                # forward losses.
                if self._reset_pend is not None and 0 <= seq - self._reset_pend[0] <= 100:
                    pend_seq, pend_counted = self._reset_pend
                    run = self.refl_run - (1 if pend_counted else 0)
                    self.refl_gap += max(0, (self.refl_max - self.refl_first + 1) - run)
                    self.refl_first = pend_seq
                    self.refl_max = seq
                    self.refl_run = 2  # the candidate probe + this one
                    self._reset_pend = None
                else:
                    counted = seq >= self.refl_first
                    if counted:
                        self.refl_run += 1  # gap-filler within the current run
                    self._reset_pend = (seq, counted)
            else:
                self._reset_pend = None
                if seq > self.refl_max:
                    self.refl_max = seq
                self.refl_run += 1
            live_gap = max(0, (self.refl_max - self.refl_first + 1) - self.refl_run)
            return (self.refl_gap + live_gap) & MAX_COUNT

    def on_send(self, seq, send_ns):
        with self.lock:
            now_m = time.monotonic()
            self.pending[seq] = (now_m, send_ns)
            self.tx_events.append(now_m)
            self.cum_tx += 1
            self.life_tx += 1
            self._trim_locked()

    def cancel_send(self, seq):
        """Withdraw a probe registered with on_send whose transmit failed.

        Senders must register BEFORE transmitting: send calls release the
        GIL, and on a fast path the echo can come back and be processed
        before the sending thread runs again - an unregistered probe's echo
        is discarded as a duplicate and the probe then reads as (return)
        loss. Registering first closes that race; this undoes the
        registration on the rare failed transmit."""
        with self.lock:
            if self.pending.pop(seq, None) is not None:
                self.cum_tx -= 1
                self.life_tx -= 1
                if self.tx_events:
                    self.tx_events.pop()

    def on_echo(self, seq, ts_ns, now_ns, rx_len=0, psize=0, peer_rx=0,
                peer_fwd=0, peer_ns=0):
        with self.lock:
            rtt = (now_ns - ts_ns) / 1e6
            if rtt < 0:
                rtt = 0.0
            now_w = time.monotonic()
            # Size verification: rx_len = echo we got back (return path), peer_rx
            # = bytes the reflector reported (forward path). psize = intended.
            if rx_len > self.rx_echo_max:
                self.rx_echo_max = rx_len
            if peer_rx > self.peer_rx_max:
                self.peer_rx_max = peer_rx
            if psize and ((rx_len and rx_len != psize) or (peer_rx and peer_rx != psize)):
                self.size_mismatch += 1
            # Loss localization: peer_fwd = forward-loss gaps the peer's
            # reflector reports. Take the value carried by the highest-seq echo
            # seen (≈ the reflector's most recent count) rather than max-
            # latching, so a transient reorder spike in the peer's live gap
            # heals instead of ratcheting up forever. The first echo after a
            # reset (or process start) baselines the peer's lifetime counter,
            # since the reflector's total survives our Reset button / restart.
            if self.peer_fwd_base is None or peer_fwd < self.peer_fwd_base:
                # First echo of the session, or the peer's counter went
                # backward (its app restarted): re-baseline.
                self.peer_fwd_base = peer_fwd
            if seq >= self.peer_fwd_seq:
                self.peer_fwd_seq = seq
                self.peer_fwd = max(0, peer_fwd - self.peer_fwd_base)
            p = self.pending.pop(seq, None)
            if p is not None:
                # On-time echo.
                self.state[seq] = "recv"
                self.resolved_order.append((now_w, seq))
                self.rtt_samples.append((now_w, rtt))
                if peer_ns:
                    # Relative one-way delays (offset included; see __init__).
                    f = (peer_ns - ts_ns) / 1e6
                    r = (now_ns - peer_ns) / 1e6
                    self.owd_recent.append((f, r))
                    self._owd_count += 1
                    if (not self.owd_buckets
                            or now_w >= self.owd_buckets[-1][0]):
                        self.owd_buckets.append(
                            [now_w + self.owd_bucket_s, f, r])
                    else:
                        bkt = self.owd_buckets[-1]
                        if f < bkt[1]:
                            bkt[1] = f
                        if r < bkt[2]:
                            bkt[2] = r
                self.cum_recv += 1
                self.life_recv += 1
                if self.last_rtt is not None:
                    d = abs(rtt - self.last_rtt)
                    # smoothed mean deviation, RFC 3550 J += (|D|-J)/16
                    self.jitter += (d - self.jitter) / 16.0
                self.last_rtt = rtt
                self.last_echo_t = now_w
            elif self.state.get(seq) == "lost":
                # A previously reaped probe finally came back: it was late, not
                # lost. Reclassify so Loss% drops and Late% rises.
                self.state[seq] = "late"
                self.cum_lost -= 1
                self.cum_late += 1
                self.life_lost -= 1
                self.life_late += 1
                self.last_echo_t = now_w
            # else: duplicate, or so old it has been trimmed -> ignore.
            self._trim_locked()

    def reap(self):
        """Move probes with no echo within `timeout` into the lost bucket."""
        now_ns = time.monotonic_ns()
        cutoff = self.timeout * 1e9
        with self.lock:
            now_w = time.monotonic()
            dead = [s for s, (w, ns) in self.pending.items() if now_ns - ns > cutoff]
            for s in dead:
                self.pending.pop(s, None)
                self.state[s] = "lost"
                self.resolved_order.append((now_w, s))
                self.loss_events.append(now_w)
                self.cum_lost += 1
                self.life_lost += 1
            self._trim_locked()

    def on_connect(self, dt_ms):
        """Record a TCP connection-establishment time sample (client side)."""
        with self.lock:
            self.connect_samples.append(dt_ms)

    # -- consumer (called from UI thread) ---------------------------------
    def snapshot(self):
        with self.lock:
            self._trim_locked()
            now = time.monotonic()
            rtts = [r for _, r in self.rtt_samples]
            recv = lost = late = 0
            for st in self.state.values():
                if st == "recv":
                    recv += 1
                elif st == "lost":
                    lost += 1
                else:
                    late += 1
            decided = recv + lost + late
            loss = (lost / decided * 100.0) if decided else 0.0
            late_pct = (late / decided * 100.0) if decided else 0.0
            connected = (now - self.last_echo_t) < self.timeout if self.last_echo_t else False
            avg = (sum(rtts) / len(rtts)) if rtts else 0.0
            # RTT standard deviation over the window (PQI variance term).
            if len(rtts) > 1:
                rtt_std = math.sqrt(sum((r - avg) ** 2 for r in rtts) / len(rtts))
            else:
                rtt_std = 0.0
            # Stall rate: deliveries >= baseline + 200ms are almost certainly TCP
            # retransmissions (RTO / fast-retransmit) - the app-level retrans proxy.
            if rtts:
                stall_thr = min(rtts) + 200.0
                stall_pct = sum(1 for r in rtts if r > stall_thr) / len(rtts) * 100.0
            else:
                stall_pct = 0.0
            # Don't let a partially-filled window understate the packet rates.
            span = max(1e-3, min(self.window, now - self.window_start))
            tx_pps = len(self.tx_events) / span
            rx_pps = recv / span
            # Achieved echo rate vs offered probe rate = effective throughput
            # under backpressure (sendall stalls drag this below 1.0).
            if self.target_pps:
                tput_ratio = max(0.0, min(1.0, rx_pps / self.target_pps))
            else:
                tput_ratio = 1.0
            conn_list = sorted(self.connect_samples)
            connect_ms = conn_list[len(conn_list) // 2] if conn_list else None
            # Loss localization. The true round-trip loss (cum_lost) is split:
            # forward = the gaps the peer's reflector saw in our sequence (probes
            # that never reached it); return = whatever's left (echoes that never
            # made it back). This always reconciles: forward + return = cum_lost.
            fwd_lost = min(self.peer_fwd, self.cum_lost)
            rtn_lost = max(0, self.cum_lost - fwd_lost)
            fwd_pct = (fwd_lost / self.cum_tx * 100.0) if self.cum_tx else 0.0
            rtn_pct = (rtn_lost / self.cum_tx * 100.0) if self.cum_tx else 0.0
            # One-way drift per direction: median of the last few relative
            # delays, above each direction's min over the ~60 s of bucket
            # minima. The unknown clock offset cancels in the subtraction.
            # O(few dozen) on purpose - this lock stalls the receive threads.
            owd_fwd = owd_rtn = None
            if self._owd_count >= 5 and self.owd_buckets and self.owd_recent:
                base_f = min(b[1] for b in self.owd_buckets)
                base_r = min(b[2] for b in self.owd_buckets)
                recent_f = sorted(f for f, _ in self.owd_recent)
                recent_r = sorted(r for _, r in self.owd_recent)
                owd_fwd = max(0.0, recent_f[len(recent_f) // 2] - base_f)
                owd_rtn = max(0.0, recent_r[len(recent_r) // 2] - base_r)
            return {
                "connected": connected,
                "rtt_avg": avg,
                "rtt_min": min(rtts) if rtts else 0.0,
                "rtt_max": max(rtts) if rtts else 0.0,
                "latency": avg / 2.0,
                "jitter": self.jitter,
                "rtt_std": rtt_std,
                "stall_pct": stall_pct,
                "tput_ratio": tput_ratio,
                "connect_ms": connect_ms,
                "loss": loss,
                "late": late_pct,
                "tx_pps": tx_pps,
                "rx_pps": rx_pps,
                "samples": len(rtts),
                "cum_tx": self.cum_tx,
                "cum_recv": self.cum_recv,
                "cum_lost": self.cum_lost,
                "cum_late": self.cum_late,
                "life_tx": self.life_tx,
                "life_recv": self.life_recv,
                "life_lost": self.life_lost,
                "life_late": self.life_late,
                "rx_echo_max": self.rx_echo_max,
                "peer_rx_max": self.peer_rx_max,
                "size_mismatch": self.size_mismatch,
                "refl_rx": self.refl_rx,
                "peer_fwd": self.peer_fwd,
                "fwd_lost": fwd_lost,
                "rtn_lost": rtn_lost,
                "fwd_pct": fwd_pct,
                "rtn_pct": rtn_pct,
                "owd_fwd": owd_fwd,
                "owd_rtn": owd_rtn,
            }

    def window_rtts(self):
        """Copy of the RTT samples (ms) currently in the stats window."""
        with self.lock:
            return [r for _, r in self.rtt_samples]

    def recent_losses(self):
        """Copy of the loss-event times (monotonic s) from the last ~60 s."""
        with self.lock:
            return list(self.loss_events)

    def reset(self):
        """Drop all accumulated samples/counters (used by the GUI Reset button
        and the console 'r' key). The life_* lifetime counters deliberately
        survive, so "since reset" and "lifetime" can be shown side by side."""
        with self.lock:
            self.rtt_samples.clear()
            self.tx_events.clear()
            self.resolved_order.clear()
            self.state.clear()
            self.pending.clear()
            self.connect_samples.clear()
            self.owd_recent.clear()
            self.owd_buckets.clear()
            self._owd_count = 0
            self.loss_events.clear()
            self.jitter = 0.0
            self.last_rtt = None
            self.last_echo_t = 0.0
            self.window_start = time.monotonic()
            self.cum_tx = self.cum_recv = self.cum_lost = self.cum_late = 0
            self.rx_echo_max = self.peer_rx_max = self.size_mismatch = 0
            self.refl_rx = self.peer_fwd = 0
            self.refl_first = self.refl_max = self.refl_run = self.refl_gap = 0
            self._reset_pend = None
            # Re-baseline against the peer's lifetime reflector counter on the
            # next echo; the peer has no notion of our Reset button.
            self.peer_fwd_seq = 0
            self.peer_fwd_base = None

    def _trim_locked(self):
        now = time.monotonic()
        horizon = now - self.window
        while self.rtt_samples and self.rtt_samples[0][0] < horizon:
            self.rtt_samples.popleft()
        while self.tx_events and self.tx_events[0] < horizon:
            self.tx_events.popleft()
        while self.resolved_order and self.resolved_order[0][0] < horizon:
            _, seq = self.resolved_order.popleft()
            self.state.pop(seq, None)
        owd_h = now - self.owd_horizon
        while self.owd_buckets and self.owd_buckets[0][0] < owd_h:
            self.owd_buckets.popleft()
        diag_h = now - self.diag_horizon
        while self.loss_events and self.loss_events[0] < diag_h:
            self.loss_events.popleft()


# ---------------------------------------------------------------------------
# Quality scoring (ITU-T G.107 E-model, simplified)
# ---------------------------------------------------------------------------
def quality_score(latency_ms, loss_pct, jitter_ms):
    """Return (score 0-100, MOS 1-4.5, label) from one-way latency/loss/jitter.

    Uses the ITU-T E-model R-factor. Jitter is folded in as extra effective
    delay (a de-jitter buffer typically costs ~2x the jitter).
    """
    d = latency_ms + 2.0 * jitter_ms
    # Delay impairment (Id)
    Id = 0.024 * d + (0.11 * (d - 177.3) if d > 177.3 else 0.0)
    # Equipment/loss impairment (Ie-eff), common log approximation
    p = max(0.0, min(1.0, loss_pct / 100.0))
    Ie = 30.0 * math.log(1.0 + 15.0 * p)
    R = 93.2 - Id - Ie
    R = max(0.0, min(100.0, R))
    # R -> MOS
    if R <= 0:
        mos = 1.0
    else:
        mos = 1.0 + 0.035 * R + R * (R - 60.0) * (100.0 - R) * 7e-6
    mos = max(1.0, min(4.5, mos))
    label = score_label(R)
    return R, mos, label


def pqi_score(latency_ms, rtt_std_ms, retrans_pct, tput_ratio, connect_ms, rtt_ms):
    """Path Quality Index (PQI) for TCP streams, 0-100.

    MOS is a media metric and the wrong lens for TCP, which converts loss into
    delay via retransmission. PQI instead blends what actually shapes
    application experience on a TCP path:

      * RTT             - same delay-impairment curve as the E-model Id term.
      * RTT variance    - stddev over the window; erratic RTT = queue churn.
      * retransmission% - app-level proxy: deliveries stalled >= ~RTO beyond the
                          window's baseline RTT, plus lost/late probes.
      * eff. throughput - achieved echo rate / offered probe rate; TCP
                          backpressure (blocked sends) drags this below 1.
      * connect time    - establishment time beyond ~RTT means SYN loss
                          (each SYN retry costs a full RTO, seconds at worst).

    Returns (pqi, label) with the same 0-100 bands as the R-factor score.
    """
    d = latency_ms
    rtt_pen = 0.024 * d + (0.11 * (d - 177.3) if d > 177.3 else 0.0)
    var_pen = min(20.0, 0.3 * rtt_std_ms)
    p = max(0.0, min(1.0, retrans_pct / 100.0))
    retx_pen = 30.0 * math.log(1.0 + 15.0 * p)
    tput_pen = 25.0 * (1.0 - max(0.0, min(1.0, tput_ratio)))
    conn_pen = 0.0
    if connect_ms is not None:
        excess = max(0.0, connect_ms - (rtt_ms + 50.0))
        conn_pen = min(15.0, excess / 100.0)
    pqi = 100.0 - rtt_pen - var_pen - retx_pen - tput_pen - conn_pen
    pqi = max(0.0, min(100.0, pqi))
    return pqi, score_label(pqi)


def score_label(r):
    if r >= 80:
        return "Excellent"
    if r >= 70:
        return "Good"
    if r >= 60:
        return "Fair"
    if r >= 50:
        return "Poor"
    return "Bad"


def classify_loss_pattern(events_by_name, min_events=5, bin_s=0.25):
    """Classify the last ~60 s of loss across streams into a short sentence.

    events_by_name: {stream_name: [monotonic loss-reap times]}. Returns None
    when there is too little loss to characterize. Two independent axes:

      * texture - bursty (losses clump into sub-second bins: flap, reroute,
                  queue tail-drop) vs scattered (random-ish: noisy link, RED).
      * scope   - correlated (multiple streams lose in the same instant ->
                  path-wide event) vs one stream only (policer/ACL on that
                  port) vs one protocol only (QoS/ACL selecting on protocol).

    Loss times are reap times: every lost probe surfaces exactly `timeout`
    after it was sent, so simultaneous wire events stay simultaneous here.
    """
    total = sum(len(v) for v in events_by_name.values())
    if total < min_events:
        return None
    per_stream = {n: len(v) for n, v in events_by_name.items()}
    bin_streams = {}   # bin -> set(stream names losing in that bin)
    bin_count = {}     # bin -> losses in that bin
    for name, evs in events_by_name.items():
        for t in evs:
            b = int(t / bin_s)
            bin_count[b] = bin_count.get(b, 0) + 1
            bin_streams.setdefault(b, set()).add(name)
    nstreams = len(events_by_name)
    # scope: how much of the loss happened in instants shared by most streams?
    thresh = max(2, nstreams - 1)
    shared = sum(c for b, c in bin_count.items() if len(bin_streams[b]) >= thresh)
    dominant = max(per_stream, key=per_stream.get)
    dom_share = per_stream[dominant] / total
    udp_share = sum(c for n, c in per_stream.items() if n.startswith("UDP")) / total
    if shared / total > 0.5:
        scope = "all streams together — path-wide (flap / reroute / shared queue)"
    elif dom_share >= 0.8:
        scope = f"{dominant} only — port-specific (policer/ACL on that port?)"
    elif udp_share >= 0.9:
        scope = "UDP streams only — protocol-selective (QoS policy / ACL?)"
    elif udp_share <= 0.1:
        scope = "TCP streams only — protocol-selective (QoS policy / ACL?)"
    else:
        scope = "spread across streams"
    # texture: how much of the loss lives in bins far denser than the overall
    # loss RATE would fill by chance? A fixed count can't tell a flap from
    # merely heavy random loss - at high rates every bin holds several losses,
    # so the burst bar scales with the expected per-bin count (lam).
    times = [t for evs in events_by_name.values() for t in evs]
    dur = min(60.0, max(5.0, max(times) - min(times)))
    lam = total * bin_s / dur
    burst_bar = max(3, math.ceil(3.0 * lam))
    burst = sum(c for c in bin_count.values() if c >= burst_bar)
    texture = "bursty" if burst / total > 0.5 else "scattered"
    return f"{texture}, {scope}"


def loss_verdict(fwd_lost, rtn_lost, inflight=6):
    """Classify where a stream's loss is, from the forward/return split.

    `inflight` is a small allowance for packets legitimately in flight (a few
    per stream); over a long run real loss dwarfs it.
    """
    f = fwd_lost if fwd_lost > inflight else 0
    r = rtn_lost if rtn_lost > inflight else 0
    if f == 0 and r == 0:
        return "clean", "ok"
    if f and r > 3 * max(1, f):
        return "← return", "warn"
    if r and f > 3 * max(1, r):
        return "→ forward", "warn"
    if f and not r:
        return "→ forward", "warn"
    if r and not f:
        return "← return", "warn"
    return "both dirs", "warn"


def score_color(r):
    if r >= 80:
        return "#1a9850"
    if r >= 70:
        return "#66bd63"
    if r >= 60:
        return "#fee08b"
    if r >= 50:
        return "#fc8d59"
    return "#d73027"


# ---------------------------------------------------------------------------
# UDP stream: one bound socket per port, both originates and reflects.
# ---------------------------------------------------------------------------
class UDPStream:
    """One UDP port serving every configured peer: probes fan out to each
    peer on its own sequence/stats, and inbound packets demux by source
    address. A single peer is just the one-element case."""

    def __init__(self, cfg, peers, bind, size, interval, stats_of, stop,
                 dont_fragment=False):
        self.sid, _, self.port, self.name = cfg
        self.peers = list(peers)
        self.bind = bind
        self.size = size
        self.interval = interval
        self.stats_of = stats_of   # {peer: StreamStats}
        self.stop = stop
        self.dont_fragment = dont_fragment
        self.sock = None
        self.ip_of = {}            # resolved source IP -> peer
        self.threads = []

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bind_exclusively(s)        # a second accidental instance must fail loudly
        enlarge_socket_buffers(s)  # absorb Windows microbursts -> no phantom UDP loss
        quench_udp_connreset(s)    # peer not started yet must not error the socket
        if self.dont_fragment:
            set_dont_fragment(s)   # jumbo probes that don't fit are dropped, not split
        s.bind((self.bind, self.port))
        s.settimeout(0.5)
        self.sock = s
        for p in self.peers:
            ip = resolve_peer_ip(p)
            if ip is not None:
                self.ip_of[ip] = p
        self.threads = [
            threading.Thread(target=self._recv_loop, name=f"{self.name}-rx", daemon=True),
            threading.Thread(target=self._send_loop, name=f"{self.name}-tx", daemon=True),
        ]
        for t in self.threads:
            t.start()

    def _peer_for(self, src_ip):
        """Map a source address to a configured peer. Only talk to configured
        peers: a hostile/chatty LAN must not be able to skew stats or use us
        as a packet reflector. (Sole exception: a single unresolvable-at-
        start peer keeps the pre-mesh behavior of accepting its traffic.)"""
        peer = self.ip_of.get(src_ip)
        if peer is None and len(self.peers) == 1 and not self.ip_of:
            return self.peers[0]
        return peer

    def _send_loop(self):
        seqs = dict.fromkeys(self.peers, 0)
        next_t = time.monotonic()
        while not self.stop.is_set():
            for p in self.peers:
                seqs[p] += 1
                ns = time.monotonic_ns()
                pkt = build_packet(TYPE_PROBE, self.sid, seqs[p], ns, self.size)
                st = self.stats_of[p]
                # Register BEFORE transmitting: sendto releases the GIL and
                # on a fast path the echo can be processed before this thread
                # runs again - see StreamStats.cancel_send.
                st.on_send(seqs[p], ns)
                try:
                    self.sock.sendto(pkt, (p, self.port))
                except OSError:
                    st.cancel_send(seqs[p])
                st.reap()
            next_t += self.interval
            delay = next_t - time.monotonic()
            if delay > 0:
                self.stop.wait(delay)
            else:
                next_t = time.monotonic()

    def _recv_loop(self):
        while not self.stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except ConnectionResetError:
                # Windows: ICMP Port Unreachable from a prior sendto (peer app
                # not running yet). Not a socket failure — keep receiving.
                continue
            except OSError:
                if self.stop.is_set():
                    break
                time.sleep(0.1)  # unexpected; don't spin, don't die
                continue
            peer = self._peer_for(addr[0])
            if peer is None:
                continue
            stats = self.stats_of[peer]
            parsed = parse_header(data)
            if parsed is None:
                continue
            ptype, sid, seq, ts_ns, psize, rxsize, rxcount, peer_ns = parsed
            if ptype in (TYPE_PROBE, TYPE_TEST):
                # Reflect back, stamping the bytes and cumulative probe count we
                # received so the originator can verify size and split loss by
                # direction, plus our clock for one-way-delay drift. TEST
                # probes (MTU sweep / burst test side-channels) are echoed but
                # kept out of the gap tracking.
                rxlen = len(data)
                fwd = stats.on_probe_rx(seq) if ptype == TYPE_PROBE else 0
                echo = build_packet(TYPE_ECHO, sid, seq, ts_ns, rxlen,
                                    rxsize=rxlen, rxcount=fwd,
                                    peer_ns=time.monotonic_ns())
                try:
                    self.sock.sendto(echo, addr)
                except OSError:
                    pass
            elif ptype == TYPE_ECHO:
                stats.on_echo(seq, ts_ns, time.monotonic_ns(),
                              rx_len=len(data), psize=psize, peer_rx=rxsize,
                              peer_fwd=rxcount, peer_ns=peer_ns)


# ---------------------------------------------------------------------------
# TCP stream: we run BOTH a server (reflect peer's probes) and a client
# (originate our probes). Our displayed stats come from the client side.
# ---------------------------------------------------------------------------
def _recv_exact(sock, n, stop=None, idle_timeout=None):
    """Read exactly n bytes. Returns None if the stream dies, `stop` is set,
    or no data arrives for `idle_timeout` seconds (silent peer death — a
    blue-screened / hard-powered-off peer never sends FIN or RST, and without
    a deadline the reader thread would spin on 0.5 s timeouts forever)."""
    buf = bytearray()
    last_data = time.monotonic()
    while len(buf) < n:
        if stop is not None and stop.is_set():
            return None
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, BlockingIOError):
            if (idle_timeout is not None
                    and time.monotonic() - last_data > idle_timeout):
                return None
            continue
        except OSError:
            return None
        if not chunk:
            return None
        buf.extend(chunk)
        last_data = time.monotonic()
    return bytes(buf)


def _recv_msg(sock, stop=None, idle_timeout=None):
    """Read one framed message: the fixed header first, then the padding the
    header's own psize field declares.

    Framing is self-describing, so the two workstations may run different
    --size values without permanently desyncing the byte stream (which used
    to read as 100% phantom TCP loss). A magic mismatch means the stream is
    desynced or foreign; returning None makes the caller drop the connection,
    which is the only reliable way to resync."""
    hdr = _recv_exact(sock, HEADER_LEN, stop=stop, idle_timeout=idle_timeout)
    if hdr is None:
        return None
    fields = HEADER.unpack(hdr)
    if fields[0] != MAGIC:
        return None
    psize = fields[5]
    if psize < HEADER_LEN or psize > MAX_SIZE:
        return None
    if psize == HEADER_LEN:
        return hdr
    rest = _recv_exact(sock, psize - HEADER_LEN, stop=stop, idle_timeout=idle_timeout)
    if rest is None:
        return None
    return hdr + rest


class TCPStream:
    """One TCP port serving every configured peer: a single listener reflects
    each peer on its own connection/stats, and one client (plus handshake
    sampler) runs per peer. A single peer is just the one-element case."""

    def __init__(self, cfg, peers, bind, size, interval, stats_of, stop):
        self.sid, _, self.port, self.name = cfg
        self.peers = list(peers)
        self.bind = bind
        self.size = max(size, HEADER_LEN)
        self.interval = interval
        self.stats_of = stats_of   # {peer: StreamStats}
        self.stop = stop
        self.listen_sock = None
        self.ip_of = {}            # resolved source IP -> peer
        self.threads = []
        # Probe seq continues across reconnects (see _client_send).
        self._tx_seq = dict.fromkeys(self.peers, 0)
        # At most one live reflector connection PER PEER: when a peer
        # reconnects, its old (usually half-dead) connection is closed so the
        # thread exits instead of leaking, and so two connections can't
        # interleave probes into the same StreamStats.
        self._reflect_lock = threading.Lock()
        self._active_reflect = {}

    def start(self):
        for p in self.peers:
            ip = resolve_peer_ip(p)
            if ip is not None:
                self.ip_of[ip] = p
        self.threads = [threading.Thread(target=self._server_loop,
                                         name=f"{self.name}-srv", daemon=True)]
        for p in self.peers:
            self.threads.append(threading.Thread(
                target=self._client_manager, args=(p,),
                name=f"{self.name}-cli-{p}", daemon=True))
            self.threads.append(threading.Thread(
                target=self._connect_sampler, args=(p,),
                name=f"{self.name}-syn-{p}", daemon=True))
        for t in self.threads:
            t.start()

    def _peer_for(self, src_ip):
        """Same peer-set filter as UDPStream._peer_for."""
        peer = self.ip_of.get(src_ip)
        if peer is None and len(self.peers) == 1 and not self.ip_of:
            return self.peers[0]
        return peer

    # -- server side: reflect peer probes ---------------------------------
    def _server_loop(self):
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bind_exclusively(ls)
        warned = False
        while not self.stop.is_set():
            try:
                ls.bind((self.bind, self.port))
                ls.listen(8)
                break
            except OSError as e:
                # Port taken (lingering old instance, another app): keep
                # retrying instead of silently never reflecting — the only
                # symptom used to appear on the PEER's screen.
                if not warned:
                    print(f"{self.name}: cannot listen on {self.bind}:{self.port}"
                          f" ({e}) - retrying every 5s; until then the peer "
                          f"will show this stream down.", file=sys.stderr)
                    warned = True
                if self.stop.wait(5.0):
                    return
        if self.stop.is_set():
            return
        if warned:
            print(f"{self.name}: now listening on {self.bind}:{self.port}",
                  file=sys.stderr)
        ls.settimeout(0.5)
        self.listen_sock = ls
        while not self.stop.is_set():
            try:
                conn, addr = ls.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            peer = self._peer_for(addr[0])
            if peer is None:
                # Only reflect for configured peers (hostile-LAN hardening:
                # no thread-per-connection for arbitrary hosts).
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            threading.Thread(target=self._reflect_conn, args=(conn, peer),
                             daemon=True).start()

    def _reflect_conn(self, conn, peer):
        stats = self.stats_of[peer]
        conn.settimeout(0.5)
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        # A new connection does NOT displace the live one until it delivers a
        # real probe. The connect-time PQI sampler opens a throwaway
        # handshake every ~15 s, and adopting on accept made that handshake
        # close the LIVE reflector connection - killing the probes buffered
        # on it (counted by the reflector, echo never sent -> a steady
        # trickle of phantom "return loss" on every TCP stream, worse the
        # more peers/samplers there are).
        adopted = False
        try:
            with conn:
                while not self.stop.is_set():
                    # 30s with no bytes = silently dead peer (no FIN/RST after
                    # a crash/power-off); exit rather than leak this thread.
                    msg = _recv_msg(conn, stop=self.stop, idle_timeout=30.0)
                    if msg is None:
                        return
                    parsed = parse_header(msg)
                    if parsed is None:
                        continue
                    ptype, sid, seq, ts_ns, psize, rxsize, rxcount, peer_ns = parsed
                    if ptype != TYPE_PROBE:
                        continue
                    if not adopted:
                        # First probe: this IS the peer's live client now -
                        # retire the previous connection so two conns can't
                        # interleave probes into the same StreamStats.
                        with self._reflect_lock:
                            old = self._active_reflect.get(peer)
                            self._active_reflect[peer] = conn
                        if old is not None and old is not conn:
                            try:
                                old.close()  # unblocks its thread -> exits
                            except OSError:
                                pass
                        adopted = True
                    fwd = stats.on_probe_rx(seq)
                    # Echo at the PROBE's size (not our local --size) so the
                    # originator's reader frames it correctly even when the
                    # two ends run different sizes.
                    echo = build_packet(TYPE_ECHO, sid, seq, ts_ns, len(msg),
                                        rxsize=len(msg), rxcount=fwd,
                                        peer_ns=time.monotonic_ns())
                    try:
                        conn.sendall(echo)
                    except OSError:
                        return
        finally:
            if adopted:
                with self._reflect_lock:
                    if self._active_reflect.get(peer) is conn:
                        self._active_reflect.pop(peer, None)

    def _source_address(self):
        """Source address for outbound TCP, so the peer's reflector sees us
        arrive from the address it has configured as its --peer (essential on
        multi-homed hosts and the loopback smoke test)."""
        if self.bind in ("", "0.0.0.0"):
            return None
        return (self.bind, 0)

    # -- connection-establishment sampler (PQI input) ----------------------
    def _connect_sampler(self, peer):
        """Every ~15s, time a throwaway TCP handshake to the peer port."""
        while not self.stop.wait(15.0):
            t0 = time.monotonic()
            try:
                s = socket.create_connection((peer, self.port), timeout=3.0,
                                             source_address=self._source_address())
                self.stats_of[peer].on_connect((time.monotonic() - t0) * 1000.0)
                s.close()
            except OSError:
                pass  # peer down; connection health shows via the main stream

    # -- client side: originate probes ------------------------------------
    def _client_manager(self, peer):
        stats = self.stats_of[peer]
        while not self.stop.is_set():
            t0 = time.monotonic()
            try:
                cs = socket.create_connection((peer, self.port), timeout=2.0,
                                              source_address=self._source_address())
            except OSError:
                self.stop.wait(1.0)
                continue
            stats.on_connect((time.monotonic() - t0) * 1000.0)
            cs.settimeout(0.5)
            try:
                cs.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            rx = threading.Thread(target=self._client_recv, args=(cs, stats),
                                  daemon=True)
            rx.start()
            self._client_send(cs, peer, stats)  # blocks until the conn dies
            try:
                cs.close()
            except OSError:
                pass
            rx.join(timeout=1.0)
            if not self.stop.is_set():
                self.stop.wait(0.5)  # brief backoff before reconnect

    def _client_send(self, cs, peer, stats):
        # seq continues across reconnects so the peer's reflector sees ONE
        # monotonic sequence: the gap across a reconnect is exactly the probes
        # that died with the old connection (real forward loss), and pending
        # entries from the old connection are reaped as lost instead of being
        # silently overwritten by a restarted sequence.
        next_t = time.monotonic()
        while not self.stop.is_set():
            self._tx_seq[peer] += 1
            seq = self._tx_seq[peer]
            ns = time.monotonic_ns()
            pkt = build_packet(TYPE_PROBE, self.sid, seq, ns, self.size)
            # Register BEFORE transmitting (see StreamStats.cancel_send).
            stats.on_send(seq, ns)
            try:
                cs.sendall(pkt)
            except OSError:
                stats.cancel_send(seq)
                return
            stats.reap()
            next_t += self.interval
            delay = next_t - time.monotonic()
            if delay > 0:
                self.stop.wait(delay)
            else:
                next_t = time.monotonic()

    def _client_recv(self, cs, stats):
        while not self.stop.is_set():
            msg = _recv_msg(cs, stop=self.stop)
            if msg is None:
                return
            parsed = parse_header(msg)
            if parsed is None:
                continue
            ptype, sid, seq, ts_ns, psize, rxsize, rxcount, peer_ns = parsed
            if ptype == TYPE_ECHO:
                stats.on_echo(seq, ts_ns, time.monotonic_ns(),
                              rx_len=len(msg), psize=psize, peer_rx=rxsize,
                              peer_fwd=rxcount, peer_ns=peer_ns)


# ---------------------------------------------------------------------------
# VXLAN encapsulation (userspace VTEP)
# ---------------------------------------------------------------------------
# --vxlan carries every probe stream inside genuine VXLAN (RFC 7348): the app
# builds the whole inner Ethernet/IPv4/UDP-or-TCP packet itself and ships it
# in an outer UDP datagram to the peer's VXLAN port. The wire then carries
# real, dissectable VXLAN between the two hosts - no kernel VTEP, drivers or
# admin rights on either end, and it works the same on Windows and Linux.
#
# The point for demos: encapsulation adds a fixed overhead to every probe, so
# a probe sized to fit the path MTU natively no longer fits once encapsulated
# and the OUTER packet must fragment (or be dropped with --dont-fragment) -
# the "transparent fragmentation" case made visible with the same loss/size
# verification machinery the app already has.

VXLAN_DEFAULT_PORT = 4789   # IANA-assigned VXLAN port; Wireshark dissects it
VXLAN_DEFAULT_VNI = 4242

# Bytes ADDED on the wire versus a native probe (the outer IPv4+UDP headers
# replace the native ones like-for-like, so the extra is the VXLAN header
# plus the entire inner frame's headers):
VXLAN_OVERHEAD_UDP = 8 + 14 + 20 + 8    # VXLAN + inner Ether + IPv4 + UDP = 50
VXLAN_OVERHEAD_TCP = 8 + 14 + 20 + 20   # VXLAN + inner Ether + IPv4 + TCP = 62

# The OS caps a UDP datagram's payload at 65507 B; the biggest inner probe
# must still fit alongside the encap headers.
VXLAN_MAX_PROBE = 65507 - VXLAN_OVERHEAD_TCP


# ---------------------------------------------------------------------------
# EdgeConnect wire model (drives the GUI's Anatomy panel)
# ---------------------------------------------------------------------------
# Measured slicing/encapsulation behavior of an EdgeConnect SD-WAN fabric
# (AES-GCM-256 tunnels, Auto tunnel MTU 1488).  An inner IP packet above the
# slice payload budget is cut into budget-sized slices and every piece rides
# its own tunnel packet:
#
#   wire = GCM_FRAMING + CIPHER_BLOCK * ceil((piece + per_piece) / CIPHER_BLOCK)
#
# GCM_FRAMING is outer IPv4 20 + UDP 8 + SPI/seq 8 + IV 8 + ICV 16; per-piece
# framing is 12 B for a whole packet and 16 B for a slice (the extra 4 B is
# the reassembly offset).  This is a model of ONE measured fabric, not a
# protocol constant - tune the numbers here if your fabric differs.
EC_SLICE_BUDGET = 1360    # inner bytes per slice (empirically 1488 - 128)
EC_GCM_FRAMING = 60
EC_FRAMING_WHOLE = 12
EC_FRAMING_SLICE = 16
EC_CIPHER_BLOCK = 16
EC_TUNNEL_MTU = 1488      # Orchestrator-displayed Auto tunnel MTU


def ec_wire_view(inner):
    """Predict how the EdgeConnect fabric carries one `inner`-byte IP packet.

    Returns a list of (inner_piece_bytes, tunnel_packet_wire_bytes) - one
    entry per WAN packet: a single whole-packet encapsulation when the packet
    fits the slice budget, otherwise one entry per slice."""
    def wire(piece, framing):
        ct = piece + framing
        pad = (EC_CIPHER_BLOCK - ct % EC_CIPHER_BLOCK) % EC_CIPHER_BLOCK
        return EC_GCM_FRAMING + ct + pad
    if inner <= EC_SLICE_BUDGET:
        return [(inner, wire(inner, EC_FRAMING_WHOLE))]
    pieces, off = [], 0
    while off < inner:
        s = min(EC_SLICE_BUDGET, inner - off)
        pieces.append((s, wire(s, EC_FRAMING_SLICE)))
        off += s
    return pieces


def _inet_checksum(data):
    """RFC 1071 internet checksum, for the inner IPv4/UDP/TCP headers (so
    captures dissect as valid packets, not checksum errors)."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(array.array("H", data))     # native-endian 16-bit word sum
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xFFFF
    if sys.byteorder == "little":       # sum was native-endian; emit network order
        s = ((s & 0xFF) << 8) | (s >> 8)
    return s


def local_ip_toward(peer, bind):
    """The local IP the OS routes traffic to `peer` from - used as the inner
    IPv4 source when --bind is the 0.0.0.0 wildcard. No packet is sent."""
    if bind not in ("", "0.0.0.0"):
        return bind
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((peer, 9))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return "0.0.0.0"


def _mac_for_ip(ip):
    """Deterministic locally-administered MAC for an IP (02:4e + the four IP
    octets), so both ends' captures show the same stable inner MACs."""
    try:
        octets = socket.inet_aton(ip)
    except OSError:
        octets = b"\x00\x00\x00\x00"
    return b"\x02\x4e" + octets


class VXLANTunnel:
    """Minimal userspace VXLAN VTEP shared by all four probe streams.

    One UDP socket (default port 4789, --vxlan-port) both sends and receives
    the outer datagrams; both ends must run --vxlan with the same VNI and
    port. Inner packets are fully formed Ethernet+IPv4+UDP/TCP with valid
    checksums and the real host IPs, so transit gear and captures see
    ordinary VXLAN traffic.

    Inner TCP is EMULATED: each probe/echo rides in its own self-contained
    PSH|ACK segment with app-managed seq/ack numbers. On the wire it is real
    TCP-in-VXLAN, but there is no kernel TCP state machine inside the tunnel
    (no handshake, retransmission or congestion control), so TCP-stream loss
    shows directly as loss - exactly what a fragmentation demo wants.
    """

    def __init__(self, peer, bind, vni, port, stop, dont_fragment=False):
        self.peer = peer
        self.bind = bind
        self.vni = vni & 0xFFFFFF
        self.port = port
        self.stop = stop
        self.dont_fragment = dont_fragment
        self.sock = None
        self.peer_ip = None
        self.local_ip = None
        self.local_mac = self.peer_mac = b"\x00" * 6
        self.handlers = {}     # (proto, inner port) -> callback(payload bytes)
        self._lock = threading.Lock()
        self._ip_id = 0        # inner IPv4 identification counter
        self._tcp_seq = {}     # inner port -> next TCP seq we send
        self._tcp_ack = {}     # inner port -> next TCP seq we expect (their seq+len)
        self.thread = None

    def register(self, proto, port, handler):
        """Route decapsulated payloads for (proto, inner dst port) to handler."""
        self.handlers[(proto, port)] = handler

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bind_exclusively(s)
        enlarge_socket_buffers(s)
        quench_udp_connreset(s)
        if self.dont_fragment:
            set_dont_fragment(s)   # DF on the OUTER packet: encap overflow drops
        s.bind((self.bind, self.port))
        s.settimeout(0.5)
        self.sock = s
        self.peer_ip = resolve_peer_ip(self.peer)
        self.local_ip = local_ip_toward(self.peer, self.bind)
        self.local_mac = _mac_for_ip(self.local_ip)
        self.peer_mac = _mac_for_ip(self.peer_ip or "0.0.0.0")
        self.thread = threading.Thread(target=self._recv_loop, name="vxlan-rx",
                                       daemon=True)
        self.thread.start()

    # -- encapsulation ------------------------------------------------------
    def send(self, proto, port, payload):
        """Encapsulate one probe/echo message and send it to the peer's VXLAN
        port. Returns True if the datagram left the socket."""
        try:
            self.sock.sendto(self._encap(proto, port, payload),
                             (self.peer, self.port))
            return True
        except OSError:
            return False

    @staticmethod
    def _l4_checksum(src, dst, proto_num, segment):
        pseudo = src + dst + struct.pack("!BBH", 0, proto_num, len(segment))
        return _inet_checksum(pseudo + segment)

    def _encap(self, proto, port, payload):
        src = socket.inet_aton(self.local_ip or "0.0.0.0")
        dst = socket.inet_aton(self.peer_ip or "0.0.0.0")
        if proto == "TCP":
            proto_num = 6
            with self._lock:
                seq = self._tcp_seq.get(port, 1)
                self._tcp_seq[port] = (seq + len(payload)) & 0xFFFFFFFF
                ack = self._tcp_ack.get(port, 0)
            l4 = struct.pack("!HHIIBBHHH", port, port, seq, ack,
                             5 << 4, 0x18, 65535, 0, 0)   # PSH|ACK
            csum = self._l4_checksum(src, dst, proto_num, l4 + payload)
            l4 = l4[:16] + struct.pack("!H", csum) + l4[18:]
        else:
            proto_num = 17
            l4 = struct.pack("!HHHH", port, port, 8 + len(payload), 0)
            # A computed UDP checksum of 0 is transmitted as 0xFFFF (RFC 768).
            csum = self._l4_checksum(src, dst, proto_num, l4 + payload) or 0xFFFF
            l4 = l4[:6] + struct.pack("!H", csum)
        total = 20 + len(l4) + len(payload)
        with self._lock:
            self._ip_id = (self._ip_id + 1) & 0xFFFF
            ip_id = self._ip_id
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ip_id, 0, 64,
                         proto_num, 0, src, dst)
        ip = ip[:10] + struct.pack("!H", _inet_checksum(ip)) + ip[12:]
        eth = self.peer_mac + self.local_mac + b"\x08\x00"
        vxlan = struct.pack("!II", 0x08 << 24, self.vni << 8)
        return vxlan + eth + ip + l4 + payload

    # -- decapsulation ------------------------------------------------------
    def _decap(self, data):
        """Parse VXLAN + inner Ethernet/IPv4/L4. Returns (proto, port,
        payload) or None for anything that isn't ours. Inner checksums are
        not re-verified - the outer UDP checksum already covered the bytes."""
        if len(data) < 8 + 14 + 20 + 8:
            return None
        if not (data[0] & 0x08):                       # VNI-present flag
            return None
        if int.from_bytes(data[4:7], "big") != self.vni:
            return None
        eth = 8
        if data[eth + 12:eth + 14] != b"\x08\x00":     # inner EtherType IPv4
            return None
        ip = eth + 14
        if data[ip] >> 4 != 4:
            return None
        ihl = (data[ip] & 0x0F) * 4
        total = int.from_bytes(data[ip + 2:ip + 4], "big")
        end = min(len(data), ip + total)               # ignore trailing padding
        proto_num = data[ip + 9]
        l4 = ip + ihl
        if proto_num == 17 and end >= l4 + 8:
            dport = int.from_bytes(data[l4 + 2:l4 + 4], "big")
            ulen = int.from_bytes(data[l4 + 4:l4 + 6], "big")
            return "UDP", dport, data[l4 + 8:min(end, l4 + ulen)]
        if proto_num == 6 and end >= l4 + 20:
            dport = int.from_bytes(data[l4 + 2:l4 + 4], "big")
            seq = int.from_bytes(data[l4 + 4:l4 + 8], "big")
            doff = (data[l4 + 12] >> 4) * 4
            payload = data[l4 + doff:end]
            with self._lock:   # our next segment ACKs what we just received
                self._tcp_ack[dport] = (seq + len(payload)) & 0xFFFFFFFF
            return "TCP", dport, payload
        return None

    def _recv_loop(self):
        while not self.stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except ConnectionResetError:
                continue   # Windows ICMP Port Unreachable; peer not up yet
            except OSError:
                if self.stop.is_set():
                    break
                time.sleep(0.1)
                continue
            # Peer-only, like the native streams: a hostile/chatty LAN must
            # not be able to skew stats or bounce packets off the tunnel.
            if self.peer_ip is not None and addr[0] != self.peer_ip:
                continue
            decap = self._decap(data)
            if decap is None:
                continue
            proto, port, payload = decap
            handler = self.handlers.get((proto, port))
            if handler is not None:
                handler(payload)


class VXStream:
    """One probe stream carried through the shared VXLAN tunnel.

    Originates probes and reflects the peer's exactly like UDPStream, but
    every message is one inner packet inside the tunnel, stamped with the
    stream's catalogue protocol (UDP or TCP) and port. Framing is packet-per-
    probe even for the TCP streams, so the probe/echo state machine (and all
    loss/size accounting) is identical across all four streams."""

    def __init__(self, cfg, tunnel, size, interval, stats, stop):
        self.sid, self.proto, self.port, self.name = cfg
        self.tunnel = tunnel
        self.size = size
        self.interval = interval
        self.stats = stats
        self.stop = stop
        self.threads = []
        tunnel.register(self.proto, self.port, self._on_payload)

    def start(self):
        self.threads = [threading.Thread(target=self._send_loop,
                                         name=f"{self.name}-vxtx", daemon=True)]
        for t in self.threads:
            t.start()

    def _send_loop(self):
        seq = 0
        next_t = time.monotonic()
        while not self.stop.is_set():
            seq += 1
            ns = time.monotonic_ns()
            pkt = build_packet(TYPE_PROBE, self.sid, seq, ns, self.size)
            # Register BEFORE transmitting (see StreamStats.cancel_send).
            self.stats.on_send(seq, ns)
            if not self.tunnel.send(self.proto, self.port, pkt):
                self.stats.cancel_send(seq)
            self.stats.reap()
            next_t += self.interval
            delay = next_t - time.monotonic()
            if delay > 0:
                self.stop.wait(delay)
            else:
                next_t = time.monotonic()

    def _on_payload(self, payload):
        parsed = parse_header(payload)
        if parsed is None:
            return
        ptype, sid, seq, ts_ns, psize, rxsize, rxcount, peer_ns = parsed
        if ptype == TYPE_PROBE:
            rxlen = len(payload)
            fwd = self.stats.on_probe_rx(seq)
            echo = build_packet(TYPE_ECHO, sid, seq, ts_ns, rxlen,
                                rxsize=rxlen, rxcount=fwd,
                                peer_ns=time.monotonic_ns())
            self.tunnel.send(self.proto, self.port, echo)
        elif ptype == TYPE_ECHO:
            self.stats.on_echo(seq, ts_ns, time.monotonic_ns(),
                               rx_len=len(payload), psize=psize, peer_rx=rxsize,
                               peer_fwd=rxcount, peer_ns=peer_ns)


# ---------------------------------------------------------------------------
# Engine: owns all streams + their stats
# ---------------------------------------------------------------------------
class Engine:
    def __init__(self, peer=None, bind="0.0.0.0", size=200, pps=50, window=10.0,
                 timeout=2.0, history_seconds=300, loss_deadband=0.5,
                 dont_fragment=False, vxlan=None, peers=None, tcp_pps=None):
        # `peers` (a list) is the mesh form; `peer` is the classic 1:1 form.
        # Everything below is keyed per (peer, sid) pair; single-peer callers
        # keep using the peer-defaulted accessors and see no difference.
        self.peers = [p.strip() for p in (peers if peers else [peer])
                      if p and p.strip()]
        if not self.peers:
            raise ValueError("Engine needs at least one peer")
        self.peer = self.peers[0]
        if vxlan and len(self.peers) > 1:
            raise ValueError("VXLAN mesh is not supported yet (roadmap "
                             "phase 2) - use native transport for --peers")
        self.bind = bind
        self.size = size
        self.dont_fragment = dont_fragment
        self.vxlan = vxlan  # None, or {"vni": int, "port": int}
        self.stop = threading.Event()
        self.start_time = time.monotonic()
        self.last_reset = time.monotonic()
        self.history_seconds = history_seconds
        self.loss_deadband = loss_deadband  # combined loss+late below this reads as 0
        # The 50 pps / ~200 B UDP default deliberately matches a G.711 voice
        # stream (20 ms packetization); TCP models an interactive app, not
        # media, so its rate is independently tunable via --tcp-pps.
        rate_of = {"UDP": pps, "TCP": tcp_pps or pps}
        self.stats = {}      # (peer, sid) -> StreamStats
        self.streams = []
        # In VXLAN mode ALL four streams ride one shared userspace VTEP; the
        # native per-port UDP/TCP transports are not opened at all.
        self.tunnel = None
        if vxlan:
            self.tunnel = VXLANTunnel(self.peer, bind, vxlan["vni"],
                                      vxlan["port"], self.stop,
                                      dont_fragment=dont_fragment)
        # Per-second history ring buffers per (peer, stream) for the charts.
        H = history_seconds + 2
        self.history = {(p, cfg[0]): deque(maxlen=H)
                        for p in self.peers for cfg in STREAMS}
        # Aggregate histories per peer: directional one-way drift (mean over
        # the live UDP streams, stored per direction ready for the chart) and
        # the pooled-UDP RTT p5-p95 band for the latency chart.
        self.owd_hist_f = {p: deque(maxlen=H) for p in self.peers}
        self.owd_hist_r = {p: deque(maxlen=H) for p in self.peers}
        self.band_history = {p: deque(maxlen=H) for p in self.peers}
        self.history_lock = threading.Lock()
        # Loss-pattern verdict per peer, recomputed once per second by the
        # sampler so the GUI's snapshot() calls don't churn the stream locks.
        self._loss_pattern = dict.fromkeys(self.peers)
        for cfg in STREAMS:
            sid, proto, port, name = cfg
            interval = 1.0 / rate_of[proto]
            stats_of = {}
            for p in self.peers:
                st = StreamStats(window=window, timeout=timeout,
                                 target_pps=rate_of[proto])
                self.stats[(p, sid)] = st
                stats_of[p] = st
            if self.tunnel is not None:
                self.streams.append(VXStream(cfg, self.tunnel, size, interval,
                                             stats_of[self.peer], self.stop))
            elif proto == "UDP":
                self.streams.append(UDPStream(cfg, self.peers, bind, size,
                                              interval, stats_of, self.stop,
                                              dont_fragment=dont_fragment))
            else:
                self.streams.append(TCPStream(cfg, self.peers, bind, size,
                                              interval, stats_of, self.stop))

    def start(self):
        if self.tunnel is not None:
            self.tunnel.start()
        for s in self.streams:
            s.start()
        threading.Thread(target=self._sampler, name="history-sampler", daemon=True).start()

    def shutdown(self):
        self.stop.set()

    def effective_loss(self, loss, late):
        """Combined loss+late, with a deadband so trivial blips read as zero."""
        eff = min(100.0, loss + late)
        return 0.0 if eff < self.loss_deadband else eff

    def _sampler(self):
        """Append one history sample per stream every second.

        Everything is computed FIRST and history_lock is taken only for the
        appends: the GUI thread holds that lock while copying histories, and
        the per-stream stats locks (taken inside snapshot()) gate the receive
        threads - neither may wait on this thread's arithmetic."""
        udp_sids = {sid for sid, proto, _p, _n in STREAMS if proto == "UDP"}
        while not self.stop.wait(1.0):
            now = time.monotonic()  # chart X axis; immune to NTP steps
            results = []  # (peer, per_sid, fwd_s, rtn_s, band_s)
            for peer in self.peers:
                pooled = []
                for sid in udp_sids:
                    pooled.extend(self.stats[(peer, sid)].window_rtts())
                fwd_vals, rtn_vals = [], []
                per_sid = {}
                tx_pps_total = 0.0
                for sid, proto, _port, _name in STREAMS:
                    snap = self.stats[(peer, sid)].snapshot()
                    tx_pps_total += snap["tx_pps"]
                    eff = self.effective_loss(snap["loss"], snap["late"])
                    r, _, _ = quality_score(snap["latency"], eff, snap["jitter"])
                    up = snap["connected"]
                    per_sid[sid] = {
                        "t": now,
                        "rtt": snap["rtt_avg"] if up else None,
                        "loss": eff,
                        "jitter": snap["jitter"] if up else None,
                        "score": r if up else None,
                        "up": up,
                    }
                    if sid in udp_sids and up and snap["owd_fwd"] is not None:
                        fwd_vals.append(snap["owd_fwd"])
                        rtn_vals.append(snap["owd_rtn"])
                owd_up = bool(fwd_vals)
                fwd_s = {"t": now, "up": owd_up,
                         "v": sum(fwd_vals) / len(fwd_vals) if fwd_vals else None}
                rtn_s = {"t": now, "up": owd_up,
                         "v": sum(rtn_vals) / len(rtn_vals) if rtn_vals else None}
                # Pooled-UDP RTT band: the percentile of the pooled samples,
                # not a mix of per-stream percentiles.
                if len(pooled) >= 20:
                    pooled.sort()
                    band_s = {"t": now, "up": True,
                              "lo": pooled[int(0.05 * (len(pooled) - 1))],
                              "hi": pooled[int(0.95 * (len(pooled) - 1))]}
                else:
                    band_s = {"t": now, "up": False, "lo": None, "hi": None}
                # Loss-pattern verdict, cached for snapshot(). Bring-up churn
                # (probes sent before every stream was up) is excluded so it
                # can't mislabel the first minute of a run, and the verdict
                # respects the loss deadband: sub-deadband noise reads as 0
                # everywhere else on screen (score, loss chart), so the
                # pattern line must not nag about it either - and scope
                # claims like "TCP only" need more than a handful of events
                # to mean anything.
                diag_floor = self.start_time + 10.0
                floor_events = max(5, int(tx_pps_total * 60.0
                                          * self.loss_deadband / 100.0))
                self._loss_pattern[peer] = classify_loss_pattern(
                    {name: [t for t in self.stats[(peer, sid)].recent_losses()
                            if t > diag_floor]
                     for sid, proto, port, name in STREAMS},
                    min_events=floor_events)
                results.append((peer, per_sid, fwd_s, rtn_s, band_s))
            with self.history_lock:
                for peer, per_sid, fwd_s, rtn_s, band_s in results:
                    for sid, sample in per_sid.items():
                        self.history[(peer, sid)].append(sample)
                    self.owd_hist_f[peer].append(fwd_s)
                    self.owd_hist_r[peer].append(rtn_s)
                    self.band_history[peer].append(band_s)

    def history_copy(self, peer=None):
        peer = peer or self.peer
        with self.history_lock:
            return {sid: list(self.history[(peer, sid)])
                    for sid, *_ in STREAMS}

    def extra_history_copy(self, peer=None):
        """(owd_fwd, owd_rtn, band) sample lists for the aggregate charts."""
        peer = peer or self.peer
        with self.history_lock:
            return (list(self.owd_hist_f[peer]), list(self.owd_hist_r[peer]),
                    list(self.band_history[peer]))

    def snapshot(self, peer=None):
        """Return per-stream snapshots + overall aggregate quality for one
        peer pair (the first/only peer by default)."""
        peer = peer or self.peer
        rows = []
        scores = []
        proto_mos = {"UDP": [], "TCP": []}
        proto_score = {"UDP": [], "TCP": []}
        tot_tx = tot_recv = tot_lost = tot_late = 0
        tot_fwd = tot_rtn = 0
        life_tx = life_recv = life_lost = life_late = 0
        for sid, proto, port, name in STREAMS:
            snap = self.stats[(peer, sid)].snapshot()
            eff = self.effective_loss(snap["loss"], snap["late"])  # deadbanded impairment
            if proto == "TCP":
                # TCP gets a Path Quality Index, not MOS: retransmissions show
                # up as stalls/loss/late at the probe level, plus throughput
                # backpressure and connection-establishment time.
                retrans = min(100.0, snap["stall_pct"] + eff)
                score, label = pqi_score(snap["latency"], snap["rtt_std"], retrans,
                                         snap["tput_ratio"], snap["connect_ms"],
                                         snap["rtt_avg"])
                mos = None
            else:
                score, mos, label = quality_score(snap["latency"], eff, snap["jitter"])
            snap.update(sid=sid, proto=proto, port=port, name=name,
                        score=score, mos=mos, label=label, eff_loss=eff)
            rows.append(snap)
            tot_tx += snap["cum_tx"]
            tot_recv += snap["cum_recv"]
            tot_lost += snap["cum_lost"]
            tot_late += snap["cum_late"]
            tot_fwd += snap["fwd_lost"]
            tot_rtn += snap["rtn_lost"]
            life_tx += snap["life_tx"]
            life_recv += snap["life_recv"]
            life_lost += snap["life_lost"]
            life_late += snap["life_late"]
            if snap["connected"] and snap["samples"] > 0:
                scores.append(score)
                if mos is not None:
                    proto_mos[proto].append(mos)
                proto_score[proto].append(score)
        # Per-protocol headline numbers: UDP keeps MOS (a media metric), TCP
        # gets the average PQI of its live streams.
        udp_mos = sum(proto_mos["UDP"]) / len(proto_mos["UDP"]) if proto_mos["UDP"] else None
        udp_score = sum(proto_score["UDP"]) / len(proto_score["UDP"]) if proto_score["UDP"] else None
        tcp_pqi = sum(proto_score["TCP"]) / len(proto_score["TCP"]) if proto_score["TCP"] else None
        if scores:
            overall = sum(scores) / len(scores)
            worst = min(scores)
        else:
            overall = 0.0
            worst = 0.0
        decided = tot_recv + tot_lost + tot_late
        life_decided = life_recv + life_lost + life_late
        totals = {
            "tx": tot_tx, "recv": tot_recv, "lost": tot_lost, "late": tot_late,
            "loss_pct": (tot_lost / decided * 100.0) if decided else 0.0,
            "late_pct": (tot_late / decided * 100.0) if decided else 0.0,
            "fwd_lost": tot_fwd, "rtn_lost": tot_rtn,
            "fwd_pct": (tot_fwd / tot_tx * 100.0) if tot_tx else 0.0,
            "rtn_pct": (tot_rtn / tot_tx * 100.0) if tot_tx else 0.0,
            # lifetime counterparts: never reset while the app runs
            "life_tx": life_tx, "life_recv": life_recv,
            "life_lost": life_lost, "life_late": life_late,
            "life_loss_pct": (life_lost / life_decided * 100.0) if life_decided else 0.0,
            "life_late_pct": (life_late / life_decided * 100.0) if life_decided else 0.0,
        }
        # Aggregate size verification across the UDP streams (the jumbo-relevant
        # ones): "verified" once full-size datagrams have round-tripped both ways.
        udp_rows = [r for r in rows if r["proto"] == "UDP" and r["connected"]]
        if any(r["size_mismatch"] for r in rows):
            size_status = "mismatch"
        elif udp_rows and all(r["peer_rx_max"] >= self.size and r["rx_echo_max"] >= self.size
                              for r in udp_rows):
            size_status = "verified"
        else:
            size_status = "pending"
        # Diagnostic: TCP alive while EVERY UDP stream is silent is never a
        # healthy path - it means UDP is being dropped in the middle (port-
        # blocking firewall/ACL) or the peer runs an old version whose UDP
        # receive thread died (pre-1.1.0 WSAECONNRESET race). Surface it
        # instead of letting it read as mystery loss. A short grace period
        # avoids flapping while streams come up.
        tcp_up = any(r["proto"] == "TCP" and r["connected"] for r in rows)
        udp_up = any(r["proto"] == "UDP" and r["connected"] for r in rows)
        udp_silent = (tcp_up and not udp_up
                      and time.monotonic() - self.start_time > 15.0)
        return {
            "peer": peer,
            "rows": rows,
            "udp_silent": udp_silent,
            # 1/s via _sampler. Suppressed while the pair is fully down: a
            # dead peer makes only the still-sending streams accrue loss
            # events, which the classifier would misread as something
            # selective ("UDP only - QoS policy?") when the truth is simply
            # "no link".
            "loss_pattern": self._loss_pattern.get(peer) if scores else None,
            "overall": overall,
            "udp_mos": udp_mos,
            "udp_score": udp_score,
            "tcp_pqi": tcp_pqi,
            "worst": worst,
            "overall_label": score_label(overall) if scores else "No link",
            "uptime": time.monotonic() - self.start_time,
            "since_reset": time.monotonic() - self.last_reset,
            "links_up": len(scores),
            "totals": totals,
            "frame_size": self.size,
            "dont_fragment": self.dont_fragment,
            "vxlan": self.vxlan,
            "size_status": size_status,
        }

    def reset(self):
        """Clear all measurement state and chart history (for a clean demo).
        Lifetime totals keep accruing so loss over the whole run stays
        visible next to the fresh since-reset window."""
        for st in self.stats.values():
            st.reset()
        with self.history_lock:
            for dq in self.history.values():
                dq.clear()
            for hist in (self.owd_hist_f, self.owd_hist_r, self.band_history):
                for dq in hist.values():
                    dq.clear()
        self._loss_pattern = dict.fromkeys(self.peers)
        self.last_reset = time.monotonic()


# ---------------------------------------------------------------------------
# HPE-inspired theme + Canvas charts (no external dependencies)
# ---------------------------------------------------------------------------
HPE_GREEN = "#01A982"     # HPE signature green
HPE_GREEN_DK = "#017a5e"
BG = "#1a1d21"            # app background (HPE dark neutral)
PANEL = "#23272e"        # cards / chart panels
PANEL_HI = "#2c313a"
GRID = "#363b44"
TXT = "#f2f4f5"
TXT_DIM = "#9aa3ad"
FONT = "Segoe UI"

# distinct, on-brand line colours per stream
STREAM_COLORS = {0: "#01A982", 1: "#FF8300", 2: "#00B0E6", 3: "#FEC901"}



def _draw_ekg(canvas, color=HPE_GREEN, width=2):
    """Draw a small ECG/EKG heartbeat trace (P-QRS-T) onto a Tk Canvas.

    Coordinates are tuned for a ~52x34 canvas: flat baseline, small P bump, a
    sharp QRS spike, then a T bump back to baseline.
    """
    pts = [
        (2, 18), (12, 18),          # baseline
        (15, 14), (18, 18),         # P wave
        (21, 18), (23, 21),         # flat into Q dip
        (26, 4), (29, 30),          # R spike up, S dip down
        (32, 18), (36, 11),         # back to baseline, T wave
        (40, 18), (51, 18),         # baseline out
    ]
    flat = [c for xy in pts for c in xy]
    canvas.create_line(*flat, fill=color, width=width,
                       capstyle="round", joinstyle="round", smooth=False)


def _nice_ceiling(v):
    """Round a value up to a clean 1/2/2.5/5 * 10^n axis maximum."""
    if v <= 0:
        return 1.0
    exp = math.floor(math.log10(v))
    base = 10 ** exp
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * base:
            return m * base
    return 10 * base


BAND_FILL = "#3a6f7d"   # percentile band (stippled -> reads as translucent)


def _draw_chart(canvas, title, key, series, samples_by_sid, view_seconds, now,
                ymin_floor=1.0, unit="", value_fmt=None, band=None,
                band_label=None):
    """Render one time-series chart onto a Tk Canvas.

    series: list of (sid, color, short_label). samples_by_sid: {sid: [sample]}.
    Each sample is {'t', key..., 'up'}; None values break the line (gap = down).
    band: optional [{'t','lo','hi','up'}] drawn as a shaded region behind the
    series lines (None/down samples break it), labeled `band_label`.
    """
    if value_fmt is None:
        value_fmt = lambda v: f"{v:.0f}"
    w = canvas.winfo_width()
    h = canvas.winfo_height()
    if w < 30 or h < 30:
        return
    canvas.delete("all")
    canvas.create_rectangle(0, 0, w, h, fill=PANEL, outline=GRID)
    pad_l, pad_r, pad_t, pad_b = 46, 12, 30, 20
    pw, ph = w - pad_l - pad_r, h - pad_t - pad_b
    if pw < 10 or ph < 10:
        return
    title_id = canvas.create_text(12, 15, text=title, anchor="w", fill=TXT,
                                  font=(FONT, 10, "bold"))
    legend_x0 = canvas.bbox(title_id)[2] + 18  # start legend after the title

    # autoscale Y
    vmax = ymin_floor
    for sid, _c, _n in series:
        for s in samples_by_sid.get(sid, ()):
            v = s.get(key)
            if v is not None and s["up"]:
                vmax = max(vmax, v)
    if band:
        for s in band:
            if s.get("hi") is not None and s["up"]:
                vmax = max(vmax, s["hi"])
    vmax = _nice_ceiling(vmax)

    # horizontal gridlines + Y labels
    for i in range(5):
        yy = pad_t + ph * i / 4.0
        canvas.create_line(pad_l, yy, w - pad_r, yy, fill=GRID)
        canvas.create_text(pad_l - 5, yy, text=value_fmt(vmax * (1 - i / 4.0)),
                           anchor="e", fill=TXT_DIM, font=(FONT, 7))

    t0 = now - view_seconds

    def X(t):
        return pad_l + pw * (t - t0) / max(1e-3, view_seconds)

    def Y(v):
        return pad_t + ph * (1 - min(1.0, max(0.0, v) / vmax))

    # percentile band (behind the series lines; gaps where the link was down)
    if band:
        runs, cur = [], []
        for s in band:
            if s["t"] < t0:
                continue
            lo, hi = s.get("lo"), s.get("hi")
            if lo is None or hi is None or not s["up"]:
                if cur:
                    runs.append(cur)
                    cur = []
                continue
            cur.append((s["t"], lo, hi))
        if cur:
            runs.append(cur)
        for run in runs:
            # Decimate long runs: stippled polygons are the priciest thing on
            # these canvases and ~200 vertices per edge is visually identical.
            step = max(1, len(run) // 200)
            pts = run[::step]
            if pts[-1] is not run[-1]:
                pts.append(run[-1])
            if len(pts) < 2:
                continue
            top = [c for tt, lo, hi in pts for c in (X(tt), Y(hi))]
            bot = [c for tt, lo, hi in reversed(pts) for c in (X(tt), Y(lo))]
            canvas.create_polygon(*top, *bot, fill=BAND_FILL, outline="",
                                  stipple="gray50")

    # X axis time labels
    for frac, lbl in ((0.0, f"-{int(view_seconds)}s"),
                      (0.5, f"-{int(view_seconds / 2)}s"), (1.0, "now")):
        canvas.create_text(pad_l + pw * frac, h - 8, text=lbl, anchor="center",
                           fill=TXT_DIM, font=(FONT, 7))

    # series polylines (break on None = stream down)
    for sid, color, _n in series:
        pts = []
        for s in samples_by_sid.get(sid, ()):
            if s["t"] < t0:
                continue
            v = s.get(key)
            if v is None:
                if len(pts) >= 4:
                    canvas.create_line(*pts, fill=color, width=2)
                pts = []
                continue
            pts.extend((X(s["t"]), Y(v)))
        if len(pts) >= 4:
            canvas.create_line(*pts, fill=color, width=2)

    # legend with current values
    lx = legend_x0
    for sid, color, label in series:
        cur = None
        for s in reversed(samples_by_sid.get(sid, ())):
            if s.get(key) is not None:
                cur = s.get(key)
                break
        canvas.create_rectangle(lx, 11, lx + 9, 19, fill=color, outline="")
        txt = f"{label} {value_fmt(cur)}{unit}" if cur is not None else f"{label} -"
        tid = canvas.create_text(lx + 13, 15, text=txt, anchor="w",
                                 fill=TXT_DIM, font=(FONT, 8))
        lx = canvas.bbox(tid)[2] + 12
    if band and band_label:
        canvas.create_rectangle(lx, 11, lx + 9, 19, fill=BAND_FILL, outline="",
                                stipple="gray50")
        canvas.create_text(lx + 13, 15, text=band_label, anchor="w",
                           fill=TXT_DIM, font=(FONT, 8))


# ---------------------------------------------------------------------------
# Tkinter GUI (HPE-themed, with live + history charts)
# ---------------------------------------------------------------------------
def run_gui(engine, args):
    import tkinter as tk
    from tkinter import ttk

    view_seconds = float(args.history)
    series = [(sid, STREAM_COLORS[sid], name.split("-")[1])
              for sid, proto, port, name in STREAMS]

    root = tk.Tk()
    root.title(f"Network Vitals {__version__}  -  peer {args.peer}")
    root.geometry("1000x600")
    root.minsize(480, 320)
    root.configure(bg=BG)

    # ---- ttk dark theme ---------------------------------------------------
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("NQ.Treeview", background=PANEL, fieldbackground=PANEL,
                    foreground=TXT, rowheight=30, font=(FONT, 10), borderwidth=0)
    style.configure("NQ.Treeview.Heading", background=PANEL_HI, foreground=HPE_GREEN,
                    font=(FONT, 9, "bold"), relief="flat", borderwidth=0)
    style.map("NQ.Treeview.Heading", background=[("active", PANEL_HI)])
    style.map("NQ.Treeview", background=[("selected", HPE_GREEN_DK)],
              foreground=[("selected", "white")])

    # ---- header bar -------------------------------------------------------
    # row1 carries the branding and the score cluster; the button bar joins
    # row1 when the window is wide and drops to its own row underneath when
    # it is not, so the buttons can never sit on top of the health readout.
    header = tk.Frame(root, bg=BG, padx=14, pady=10)
    header.pack(fill="x", side="top")
    row1 = tk.Frame(header, bg=BG)
    row1.pack(fill="x", side="top")

    # EKG/heartbeat glyph (vector, drawn on a canvas)
    ekg = tk.Canvas(row1, width=54, height=34, bg=BG, highlightthickness=0)
    ekg.pack(side="left", padx=(0, 10))
    _draw_ekg(ekg)

    # packed AFTER the stats cluster below: pack grants space in packing
    # order, so the brand title truncates before the score cluster clips
    title_lbl = tk.Label(row1, text="Network Vitals", fg=TXT, bg=BG,
                         font=(FONT, 17, "bold"), anchor="w")

    btnbar = tk.Frame(header, bg=BG)  # placed by _reflow_header below

    def do_reset():
        engine.reset()  # charts + stats clear; they repopulate on the next tick

    reset_btn = tk.Button(btnbar, text="↺  Reset / Clear", command=do_reset,
                          bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                          activeforeground="white", relief="flat", bd=0,
                          highlightthickness=0, padx=12, pady=5,
                          font=(FONT, 9, "bold"), cursor="hand2")
    reset_btn.pack(side="left", padx=(0, 6))

    totals_shown = {"on": False}

    def do_toggle_totals():
        # Toggle the whole FRAME, not the tree inside it: an emptied,
        # still-packed frame keeps its last requested size, which is what
        # used to leave the bottom charts squeezed after closing the table.
        totals_shown["on"] = not totals_shown["on"]
        if totals_shown["on"]:
            totals_frame.pack(fill="x", side="bottom", before=charts)
            totals_btn.configure(text="▴  Totals")
        else:
            totals_frame.pack_forget()
            totals_btn.configure(text="▾  Totals")

    totals_btn = tk.Button(btnbar, text="▾  Totals", command=do_toggle_totals,
                           bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                           activeforeground="white", relief="flat", bd=0,
                           highlightthickness=0, padx=12, pady=5,
                           font=(FONT, 9, "bold"), cursor="hand2")
    totals_btn.pack(side="left", padx=(0, 6))

    isolate_shown = {"on": False}

    def do_toggle_isolate():
        isolate_shown["on"] = not isolate_shown["on"]
        if isolate_shown["on"]:
            iso_frame.pack(fill="x", side="bottom", before=charts)
            isolate_btn.configure(text="▴  Isolate")
        else:
            iso_frame.pack_forget()
            isolate_btn.configure(text="⇄  Isolate")

    isolate_btn = tk.Button(btnbar, text="⇄  Isolate", command=do_toggle_isolate,
                            bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                            activeforeground="white", relief="flat", bd=0,
                            highlightthickness=0, padx=12, pady=5,
                            font=(FONT, 9, "bold"), cursor="hand2")
    isolate_btn.pack(side="left", padx=(0, 6))

    anatomy_shown = {"on": False}

    def do_toggle_anatomy():
        anatomy_shown["on"] = not anatomy_shown["on"]
        if anatomy_shown["on"]:
            anat_frame.pack(fill="x", side="bottom", before=charts)
            anatomy_btn.configure(text="▴  Anatomy")
            draw_anatomy()
        else:
            anat_frame.pack_forget()
            anatomy_btn.configure(text="▦  Anatomy")

    anatomy_btn = tk.Button(btnbar, text="▦  Anatomy", command=do_toggle_anatomy,
                            bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                            activeforeground="white", relief="flat", bd=0,
                            highlightthickness=0, padx=12, pady=5,
                            font=(FONT, 9, "bold"), cursor="hand2")
    anatomy_btn.pack(side="left", padx=(0, 6))

    def do_fit_charts():
        """Collapse the bottom tables and force a fresh geometry pass so the
        charts reclaim the full current window space."""
        if totals_shown["on"]:
            do_toggle_totals()
        if isolate_shown["on"]:
            do_toggle_isolate()
        if anatomy_shown["on"]:
            do_toggle_anatomy()
        for c in (lat_canvas, loss_canvas, jit_canvas, owd_canvas):
            c.configure(width=100, height=80)
        root.update_idletasks()

    fit_btn = tk.Button(btnbar, text="⤢  Fit charts", command=do_fit_charts,
                        bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                        activeforeground="white", relief="flat", bd=0,
                        highlightthickness=0, padx=12, pady=5,
                        font=(FONT, 9, "bold"), cursor="hand2")
    fit_btn.pack(side="left")

    def do_update():
        # Explicit user action; a restart re-runs with this exact argv.
        open_update_dialog(root, args.update_url,
                           relaunch_argv=getattr(args, "_argv", None))

    upd_btn = tk.Button(btnbar, text="⟳  Update", command=do_update,
                        bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                        activeforeground="white", relief="flat", bd=0,
                        highlightthickness=0, padx=12, pady=5,
                        font=(FONT, 9, "bold"), cursor="hand2")
    upd_btn.pack(side="left", padx=(6, 0))

    # right-hand stat cluster: quality text + experience score + composite MOS
    stats = tk.Frame(row1, bg=BG)
    stats.pack(side="right")

    # Per-protocol headline metrics: UDP keeps MOS (a media metric); TCP gets
    # a Path Quality Index (RTT, RTT variance, retransmissions, throughput,
    # connection establishment) - MOS is the wrong lens for TCP.
    udp_mos_var = tk.StringVar(value="--")
    tcp_pqi_var = tk.StringVar(value="--")
    mos_block = tk.Frame(stats, bg=BG)
    mos_block.pack(side="right", padx=(14, 0))
    tk.Label(mos_block, text="UDP MOS", fg=TXT_DIM, bg=BG,
             font=(FONT, 8, "bold")).grid(row=0, column=0, sticky="e", padx=(0, 5))
    udp_mos_num = tk.Label(mos_block, textvariable=udp_mos_var,
                           font=(FONT, 14, "bold"), fg=TXT, bg=BG)
    udp_mos_num.grid(row=0, column=1, sticky="w")
    tk.Label(mos_block, text="TCP PQI", fg=TXT_DIM, bg=BG,
             font=(FONT, 8, "bold")).grid(row=1, column=0, sticky="e", padx=(0, 5))
    tcp_pqi_num = tk.Label(mos_block, textvariable=tcp_pqi_var,
                           font=(FONT, 14, "bold"), fg=TXT, bg=BG)
    tcp_pqi_num.grid(row=1, column=1, sticky="w")

    score_var = tk.StringVar(value="--")
    score_lbl = tk.Label(stats, textvariable=score_var, font=(FONT, 34, "bold"),
                         width=4, fg="white", bg="#555a61")
    score_lbl.pack(side="right")

    label_var = tk.StringVar(value="Starting...")
    sub_var = tk.StringVar(value="")
    txt = tk.Frame(stats, bg=BG)
    txt.pack(side="right", padx=(0, 12))
    tk.Label(txt, text="EXPERIENCE", fg=TXT_DIM, bg=BG,
             font=(FONT, 8, "bold")).pack(anchor="e")
    tk.Label(txt, textvariable=label_var, fg=TXT, bg=BG, anchor="e",
             font=(FONT, 17, "bold")).pack(anchor="e", fill="x")
    tk.Label(txt, textvariable=sub_var, fg=TXT_DIM, bg=BG, anchor="e",
             font=(FONT, 9)).pack(anchor="e", fill="x")

    title_lbl.pack(side="left", anchor="w")

    hdr = {"wide": None, "btn_req": 0}

    def _reflow_header(_event=None):
        w = header.winfo_width()
        if w <= 1:
            return  # not laid out yet
        if not hdr["btn_req"]:
            root.update_idletasks()  # settle requested sizes once
            hdr["btn_req"] = btnbar.winfo_reqwidth()
        need = (28 + ekg.winfo_reqwidth() + 10 + title_lbl.winfo_reqwidth()
                + 18 + hdr["btn_req"] + 16 + stats.winfo_reqwidth())
        wide = w >= need
        if wide == hdr["wide"]:
            return
        hdr["wide"] = wide
        btnbar.pack_forget()
        if wide:
            btnbar.pack(in_=row1, side="left", padx=(18, 0))
        else:
            btnbar.pack(in_=header, side="top", anchor="w", pady=(8, 0))

    header.bind("<Configure>", _reflow_header)
    stats.bind("<Configure>", _reflow_header)  # score/label text can widen

    # ---- footer (pinned to the bottom, before charts claim the middle) ----
    # Two short left-anchored lines instead of one mega-line: a label centers
    # its text in the space it gets, so the old single line clipped at BOTH
    # ends in a narrow window.  The warning gets a row only while active.
    footer = tk.Frame(root, bg=BG, padx=14, pady=6)
    footer.pack(fill="x", side="bottom")
    warn_var = tk.StringVar(value="")
    warn_lbl = tk.Label(footer, textvariable=warn_var, fg="#ffd27e", bg=BG,
                        font=(FONT, 9, "bold"), anchor="w")
    foot_path_var = tk.StringVar(value="")
    foot_path_lbl = tk.Label(footer, textvariable=foot_path_var, fg=TXT_DIM,
                             bg=BG, font=(FONT, 9), anchor="w")
    foot_path_lbl.pack(fill="x")
    foot_cnt_var = tk.StringVar(value="")
    tk.Label(footer, textvariable=foot_cnt_var, fg=TXT_DIM, bg=BG,
             font=(FONT, 9), anchor="w").pack(fill="x")

    # ---- totals table (hidden by default; toggled by the Totals button) ----
    totals_cols = ("stream", "sent", "recv", "lost", "late", "lossp",
                   "txb", "peerrx", "echorx", "size")
    totals_head = {"stream": "Stream", "sent": "Sent", "recv": "Received",
                   "lost": "Lost", "late": "Late", "lossp": "Loss %",
                   "txb": "TX B", "peerrx": "Peer RX B", "echorx": "My RX B",
                   "size": "Size"}
    totals_w = {"stream": 110, "sent": 78, "recv": 84, "lost": 64, "late": 60,
                "lossp": 64, "txb": 66, "peerrx": 78, "echorx": 72, "size": 80}
    totals_frame = tk.Frame(root, bg=BG, padx=12, pady=2)
    # not packed here — do_toggle_totals packs/unpacks the whole frame
    totals_tree = ttk.Treeview(totals_frame, columns=totals_cols, show="headings",
                               height=len(STREAMS), style="NQ.Treeview")
    totals_tree.pack(fill="x")
    for c in totals_cols:
        totals_tree.heading(c, text=totals_head[c])
        totals_tree.column(c, width=totals_w[c], anchor=("w" if c == "stream" else "e"),
                           stretch=(c == "stream"))
    totals_tree.tag_configure("ok", foreground="#7ee2b8")
    totals_tree.tag_configure("bad", foreground="#ffb3a6")
    for sid, proto, port, name in STREAMS:
        totals_tree.insert("", "end", iid=f"t{sid}",
                           values=(name, 0, 0, 0, 0, "0.0", 0, 0, 0, "-"))
    # frame stays unpacked -> hidden until the Totals button is clicked

    # ---- isolate table (hidden; splits loss into forward vs return) --------
    iso_cols = ("stream", "sent", "fwd", "fwdp", "rtn", "rtnp", "where")
    iso_head = {"stream": "Stream", "sent": "Sent",
                "fwd": "Fwd lost (→peer)", "fwdp": "Fwd %",
                "rtn": "Rtn lost (←peer)", "rtnp": "Rtn %", "where": "Where"}
    iso_w = {"stream": 110, "sent": 84, "fwd": 120, "fwdp": 70,
             "rtn": 120, "rtnp": 70, "where": 110}
    iso_frame = tk.Frame(root, bg=BG, padx=12, pady=2)
    # not packed here — do_toggle_isolate packs/unpacks the whole frame
    iso_tree = ttk.Treeview(iso_frame, columns=iso_cols, show="headings",
                            height=len(STREAMS), style="NQ.Treeview")
    iso_tree.pack(fill="x")
    for c in iso_cols:
        iso_tree.heading(c, text=iso_head[c])
        iso_tree.column(c, width=iso_w[c], anchor=("w" if c in ("stream", "where") else "e"),
                        stretch=(c == "stream"))
    iso_tree.tag_configure("ok", foreground="#7ee2b8")
    iso_tree.tag_configure("warn", foreground="#ffd27e")
    for sid, proto, port, name in STREAMS:
        iso_tree.insert("", "end", iid=f"i{sid}",
                        values=(name, 0, 0, "0.00", 0, "0.00", "…"))
    # frame stays unpacked -> hidden until the Isolate button is clicked

    # ---- anatomy panel (hidden; one probe's wire view through the fabric) --
    # Byte-proportional bars, LAN packet on top and its predicted tunnel
    # packets below, drawn from the EdgeConnect wire model (ec_wire_view).
    # Everything here is static per run (probe size, DF, VXLAN, pps), so it
    # redraws only on toggle and canvas resize - never in the refresh loop.
    anat_frame = tk.Frame(root, bg=BG, padx=12, pady=2)
    # not packed here — do_toggle_anatomy packs/unpacks the whole frame
    anat_canvas = tk.Canvas(anat_frame, bg=PANEL, highlightthickness=0,
                            height=204)
    anat_canvas.pack(fill="x")
    ANAT_PAY, ANAT_OH = "#00B0E6", "#FF8300"  # payload / encap overhead

    def draw_anatomy(_event=None):
        c = anat_canvas
        w = c.winfo_width()
        if w <= 1 or not anatomy_shown["on"]:
            return
        c.delete("all")
        probe = engine.size
        vx_on = bool(engine.vxlan)
        inner = probe + 28 + (VXLAN_OVERHEAD_UDP if vx_on else 0)
        pieces = ec_wire_view(inner)
        n = len(pieces)
        wan_total = sum(wr for _, wr in pieces)
        tax = (wan_total - inner) / inner * 100.0

        x0, gap, bh = 64, 6, 20
        usable = max(50, w - x0 - 16 - (n - 1) * gap)
        scale = usable / wan_total

        c.create_text(14, 16, anchor="w", fill=TXT, font=(FONT, 10, "bold"),
                      text="Wire anatomy — one UDP probe through the fabric")
        c.create_text(w - 14, 16, anchor="e", fill=TXT_DIM, font=(FONT, 8),
                      text=f"model: tunnel MTU {EC_TUNNEL_MTU} · slice budget "
                           f"{EC_SLICE_BUDGET} B · GCM framing {EC_GCM_FRAMING} B")

        y = 40  # LAN row: the one packet the fabric ingests on lan1
        c.create_text(x0 - 10, y + bh / 2, anchor="e", fill=TXT_DIM,
                      font=(FONT, 9, "bold"), text="LAN")
        c.create_rectangle(x0, y, x0 + inner * scale, y + bh,
                           fill=ANAT_PAY, outline="")
        parts = (f"probe {probe:,} + VXLAN {VXLAN_OVERHEAD_UDP} + IP/UDP 28"
                 if vx_on else f"probe {probe:,} + IP/UDP 28")
        df = "DF on" if args.dont_fragment else "DF off"
        c.create_text(x0 + 2, y + bh + 11, anchor="w", fill=TXT_DIM,
                      font=(FONT, 8), text=f"1 packet · {inner:,} B ({parts}) · {df}")

        y2 = y + bh + 30
        verb = (f"EC encrypts + encapsulates → 1 tunnel packet (no slicing: "
                f"{inner:,} B ≤ {EC_SLICE_BUDGET:,} B budget)" if n == 1 else
                f"EC slices + encapsulates → {n} tunnel packets")
        c.create_text(x0, y2, anchor="w", fill=HPE_GREEN,
                      font=(FONT, 9, "bold"), text=verb)

        y3 = y2 + 12  # WAN row: the tunnel packets, payload + overhead
        c.create_text(x0 - 10, y3 + bh / 2, anchor="e", fill=TXT_DIM,
                      font=(FONT, 9, "bold"), text="WAN")
        x = x0
        for s, wr in pieces:
            c.create_rectangle(x, y3, x + s * scale, y3 + bh,
                               fill=ANAT_PAY, outline="")
            c.create_rectangle(x + s * scale, y3, x + wr * scale, y3 + bh,
                               fill=ANAT_OH, outline="")
            if wr * scale >= 48:
                c.create_text(x + wr * scale / 2, y3 + bh + 11,
                              fill=TXT_DIM, font=(FONT, 8), text=f"{wr:,} B")
            x += wr * scale + gap

        y4 = y3 + bh + 28
        c.create_text(x0, y4, anchor="w", fill=TXT, font=(FONT, 9),
                      text=f"WAN: {n} packet{'s' if n > 1 else ''} · "
                           f"{wan_total:,} B on the wire · +{tax:.1f}% overhead"
                           f" · ×{n} packet amplification")
        c.create_text(x0, y4 + 18, anchor="w", fill=TXT_DIM, font=(FONT, 9),
                      text=f"predicted per UDP stream: {args.pps} pps LAN → "
                           f"{args.pps * n} pps WAN, each direction "
                           f"(echoes are full-size)")
        if inner > 1500:
            frags = -(-(inner - 20) // 1480)  # RFC 791: 1480 B payload per frag
            noec = (f"without the fabric at a 1500 B hop: DF on → PMTUD "
                    f"required (or black hole) · DF off → {frags} IP fragments,"
                    f" only #1 carries the L4 header")
        else:
            noec = "without the fabric: fits a standard 1500 B hop as-is"
        c.create_text(x0, y4 + 36, anchor="w", fill=TXT_DIM, font=(FONT, 9),
                      text=noec)

    anat_canvas.bind("<Configure>", draw_anatomy)

    # ---- charts: latency (top, full width), loss + jitter (bottom row) ----
    # Laid out with grid + row weights, NOT pack: pack hands the space freed
    # by a collapsing sibling (the Totals/Isolate tables) to the first
    # expandable widget only, so after opening and closing Totals the bottom
    # chart row stayed squeezed to a sliver until the app was restarted.
    # Grid weights re-distribute the space proportionally on every geometry
    # pass, so the charts always track the current window size.
    charts = tk.Frame(root, bg=BG, padx=12, pady=6)
    charts.pack(fill="both", expand=True)
    charts.columnconfigure(0, weight=1)
    charts.rowconfigure(0, weight=3, uniform="charts")
    charts.rowconfigure(1, weight=2, uniform="charts")
    # Small requested sizes: the drawn size is allocation-driven, and modest
    # requests keep the layout solvable at any window size.
    lat_canvas = tk.Canvas(charts, bg=PANEL, highlightthickness=0,
                           width=100, height=80)
    lat_canvas.grid(row=0, column=0, sticky="nsew", pady=(0, 6))
    bottom = tk.Frame(charts, bg=BG)
    bottom.grid(row=1, column=0, sticky="nsew")
    bottom.rowconfigure(0, weight=1)
    bottom.columnconfigure(0, weight=1, uniform="bottom")
    bottom.columnconfigure(1, weight=1, uniform="bottom")
    bottom.columnconfigure(2, weight=1, uniform="bottom")
    loss_canvas = tk.Canvas(bottom, bg=PANEL, highlightthickness=0,
                            width=100, height=80)
    loss_canvas.grid(row=0, column=0, sticky="nsew", padx=(0, 3))
    jit_canvas = tk.Canvas(bottom, bg=PANEL, highlightthickness=0,
                           width=100, height=80)
    jit_canvas.grid(row=0, column=1, sticky="nsew", padx=(3, 3))
    owd_canvas = tk.Canvas(bottom, bg=PANEL, highlightthickness=0,
                           width=100, height=80)
    owd_canvas.grid(row=0, column=2, sticky="nsew", padx=(3, 0))

    def refresh_body():
        snap = engine.snapshot()
        def set_metric(var, num, value, fmt, color_score):
            if value is None:
                var.set("--")
                num.configure(fg=TXT_DIM)
            else:
                var.set(fmt.format(value))
                num.configure(fg=score_color(color_score))

        if snap["links_up"] == 0:
            score_var.set("--")
            score_lbl.configure(bg="#555a61")
            set_metric(udp_mos_var, udp_mos_num, None, "", 0)
            set_metric(tcp_pqi_var, tcp_pqi_num, None, "", 0)
            label_var.set("Waiting for peer")
            sub_var.set(f"peer {args.peer} - no streams up yet")
        else:
            o = snap["overall"]
            score_var.set(f"{o:.0f}")
            score_lbl.configure(bg=score_color(o))
            set_metric(udp_mos_var, udp_mos_num, snap["udp_mos"], "{:.1f}",
                       snap["udp_score"] or 0)
            set_metric(tcp_pqi_var, tcp_pqi_num, snap["tcp_pqi"], "{:.0f}",
                       snap["tcp_pqi"] or 0)
            label_var.set(snap["overall_label"])
            sub_var.set(f"worst {snap['worst']:.0f}  -  "
                        f"{snap['links_up']}/{len(STREAMS)} streams up")

        up_s = int(snap["uptime"])
        t = snap["totals"]
        df = "on" if snap["dont_fragment"] else "off"
        size_tag = {"verified": "✓ verified", "mismatch": "⚠ MISMATCH",
                    "pending": "…"}[snap["size_status"]]
        vx = (f"  ·  VXLAN vni {snap['vxlan']['vni']} udp/{snap['vxlan']['port']}"
              if snap["vxlan"] else "")
        if snap.get("udp_silent"):
            warn_var.set("⚠ UDP silent while TCP is up — UDP blocked in the "
                         "path (firewall/ACL) or the peer runs an outdated "
                         "version; update BOTH ends")
        elif snap.get("loss_pattern"):
            warn_var.set(f"⚠ loss pattern (last 60 s): {snap['loss_pattern']}")
        else:
            warn_var.set("")
        if warn_var.get():
            if not warn_lbl.winfo_ismapped():
                warn_lbl.pack(fill="x", before=foot_path_lbl)
        elif warn_lbl.winfo_ismapped():
            warn_lbl.pack_forget()
        foot_path_var.set(
            f"peer {args.peer}  ·  {ports_summary()}  ·  "
            f"frame {snap['frame_size']} B  DF {df}  size {size_tag}{vx}  ·  "
            f"uptime {up_s // 3600:02d}:{(up_s % 3600) // 60:02d}:{up_s % 60:02d}")
        # lifetime repeats since-reset until the first reset — show it only
        # once it actually says something different
        life = ("" if t["life_tx"] == t["tx"] and t["life_lost"] == t["lost"]
                else f"  ·  lifetime  sent {t['life_tx']:,}  "
                     f"lost {t['life_lost']:,} ({t['life_loss_pct']:.2f}%)")
        foot_cnt_var.set(
            f"since reset  sent {t['tx']:,}  recv {t['recv']:,}  "
            f"lost {t['lost']:,} ({t['loss_pct']:.2f}%)  "
            f"fwd→ {t['fwd_lost']:,} ({t['fwd_pct']:.2f}%)  "
            f"rtn← {t['rtn_lost']:,} ({t['rtn_pct']:.2f}%){life}")

        if isolate_shown["on"]:
            for row in snap["rows"]:
                where, tag = loss_verdict(row["fwd_lost"], row["rtn_lost"])
                iso_tree.item(f"i{row['sid']}", tags=(tag,), values=(
                    row["name"], f"{row['cum_tx']:,}",
                    f"{row['fwd_lost']:,}", f"{row['fwd_pct']:.2f}",
                    f"{row['rtn_lost']:,}", f"{row['rtn_pct']:.2f}", where))

        if totals_shown["on"]:
            for row in snap["rows"]:
                decided = row["cum_recv"] + row["cum_lost"] + row["cum_late"]
                lossp = (row["cum_lost"] / decided * 100.0) if decided else 0.0
                full = (row["peer_rx_max"] >= snap["frame_size"]
                        and row["rx_echo_max"] >= snap["frame_size"])
                if row["size_mismatch"]:
                    size_cell, tag = f"⚠ {row['size_mismatch']}", "bad"
                elif full:
                    size_cell, tag = "OK", "ok"
                else:
                    size_cell, tag = "…", ""
                totals_tree.item(f"t{row['sid']}", tags=(tag,), values=(
                    row["name"], f"{row['cum_tx']:,}", f"{row['cum_recv']:,}",
                    f"{row['cum_lost']:,}", f"{row['cum_late']:,}", f"{lossp:.2f}",
                    snap["frame_size"], row["peer_rx_max"], row["rx_echo_max"],
                    size_cell))

        hist = engine.history_copy()
        owd_f, owd_r, band_hist = engine.extra_history_copy()
        now = time.monotonic()  # history samples are stamped with monotonic time
        _draw_chart(lat_canvas, "Latency (RTT, ms)", "rtt", series, hist,
                    view_seconds, now, ymin_floor=2.0, unit="",
                    value_fmt=lambda v: f"{v:.1f}" if v < 10 else f"{v:.0f}",
                    band=band_hist, band_label="p5–p95 (UDP)")
        _draw_chart(loss_canvas, "Loss + late (%)", "loss", series, hist,
                    view_seconds, now, ymin_floor=2.0, unit="%",
                    value_fmt=lambda v: f"{v:.0f}")
        _draw_chart(jit_canvas, "Jitter (ms)", "jitter", series, hist,
                    view_seconds, now, ymin_floor=1.0, unit="",
                    value_fmt=lambda v: f"{v:.1f}" if v < 10 else f"{v:.0f}")
        # Directional one-way drift: two aggregate lines (mean over live UDP
        # streams), each direction's delay growth above its ~60 s best. The
        # clocks' unknown offset cancels, so only the MOVEMENT is meaningful.
        _draw_chart(owd_canvas, "One-way drift (ms)", "v",
                    [("F", HPE_GREEN, "fwd→"), ("R", "#FF8300", "rtn←")],
                    {"F": owd_f, "R": owd_r},
                    view_seconds, now, ymin_floor=2.0, unit="",
                    value_fmt=lambda v: f"{v:.1f}" if v < 10 else f"{v:.0f}")

    def refresh():
        # One bad tick must not kill the whole update chain: on an unattended
        # demo screen a single swallowed exception used to freeze the UI on
        # stale numbers forever while probing kept running underneath.
        try:
            refresh_body()
        except tk.TclError:
            return  # window is being torn down
        except Exception:
            traceback.print_exc()
        try:
            root.after(args.refresh_ms, refresh)
        except tk.TclError:
            pass

    def on_close():
        engine.shutdown()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(120, refresh)  # let the window realize its size first
    root.mainloop()


# ---------------------------------------------------------------------------
# Mesh GUI (--peers): a row per pair, charts for the selected pair
# ---------------------------------------------------------------------------
def run_mesh_gui(engine, args):
    import tkinter as tk

    view_seconds = float(args.history)
    series = [(sid, STREAM_COLORS[sid], name.split("-")[1])
              for sid, proto, port, name in STREAMS]
    peers = engine.peers

    root = tk.Tk()
    root.title(f"Network Vitals {__version__}  -  mesh, {len(peers)} peers")
    root.geometry("1150x760")
    root.minsize(700, 500)
    root.configure(bg=BG)

    # ---- header -----------------------------------------------------------
    header = tk.Frame(root, bg=BG, padx=14, pady=10)
    header.pack(fill="x", side="top")
    ekg = tk.Canvas(header, width=54, height=34, bg=BG, highlightthickness=0)
    ekg.pack(side="left", padx=(0, 10))
    _draw_ekg(ekg)
    tk.Label(header, text="Network Vitals — mesh", fg=TXT, bg=BG,
             font=(FONT, 17, "bold"), anchor="w").pack(side="left")
    mesh_sub = tk.StringVar(value="")
    tk.Label(header, textvariable=mesh_sub, fg=TXT_DIM, bg=BG,
             font=(FONT, 10)).pack(side="left", padx=(16, 0))

    def mkbtn(text, cmd):
        return tk.Button(header, text=text, command=cmd,
                         bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                         activeforeground="white", relief="flat", bd=0,
                         highlightthickness=0, padx=12, pady=5,
                         font=(FONT, 9, "bold"), cursor="hand2")

    def do_update():
        open_update_dialog(root, args.update_url,
                           relaunch_argv=getattr(args, "_argv", None))

    mkbtn("⟳  Update", do_update).pack(side="right")
    mkbtn("↺  Reset / Clear", engine.reset).pack(side="right", padx=(0, 6))

    # ---- pair matrix: one row per peer, click to select --------------------
    # Local vantage only (phase 1): this node's half of the full N x N mesh.
    COLS = [("peer", "Peer", 20, "w"), ("score", "Score", 6, "center"),
            ("label", "", 10, "w"), ("rtt", "RTT ms", 8, "e"),
            ("loss", "Loss %", 8, "e"), ("jit", "Jitter", 8, "e"),
            ("up", "Up", 6, "center"), ("flag", "", 34, "w")]
    rowsF = tk.Frame(root, bg=BG, padx=12, pady=4)
    rowsF.pack(fill="x")
    rowsF.columnconfigure(len(COLS) - 1, weight=1)
    for c, (key, title, width, anchor) in enumerate(COLS):
        tk.Label(rowsF, text=title, width=width, anchor=anchor, bg=BG,
                 fg=HPE_GREEN, font=(FONT, 9, "bold")).grid(
            row=0, column=c, sticky="nsew", padx=1)

    sel = {"peer": peers[0]}
    row_widgets = {}

    def select_peer(p):
        sel["peer"] = p
        for peer, w in row_widgets.items():
            on = peer == p
            w["peer"].configure(text=("▶ " if on else "  ") + peer)
            for key, lbl in w.items():
                if key != "score":
                    lbl.configure(bg=PANEL_HI if on else PANEL)

    for r, p in enumerate(peers, start=1):
        w = {}
        for c, (key, _t, width, anchor) in enumerate(COLS):
            lbl = tk.Label(rowsF, text="", width=width, anchor=anchor,
                           bg=PANEL, fg=TXT, font=(FONT, 10), pady=4, padx=4)
            lbl.grid(row=r, column=c, sticky="nsew", padx=1, pady=1)
            lbl.bind("<Button-1>", lambda _e, peer=p: select_peer(peer))
            lbl.configure(cursor="hand2")
            w[key] = lbl
        w["flag"].configure(fg="#ffd27e", font=(FONT, 9))
        row_widgets[p] = w

    # ---- footer + charts for the selected pair ----------------------------
    footer = tk.Frame(root, bg=BG, padx=14, pady=6)
    footer.pack(fill="x", side="bottom")
    foot_var = tk.StringVar(value="")
    tk.Label(footer, textvariable=foot_var, fg=TXT_DIM, bg=BG,
             font=(FONT, 9), anchor="w").pack(fill="x")

    charts = tk.Frame(root, bg=BG, padx=12, pady=6)
    charts.pack(fill="both", expand=True)
    charts.columnconfigure(0, weight=1)
    charts.rowconfigure(0, weight=3, uniform="charts")
    charts.rowconfigure(1, weight=2, uniform="charts")
    lat_canvas = tk.Canvas(charts, bg=PANEL, highlightthickness=0,
                           width=100, height=80)
    lat_canvas.grid(row=0, column=0, sticky="nsew", pady=(0, 6))
    bottom = tk.Frame(charts, bg=BG)
    bottom.grid(row=1, column=0, sticky="nsew")
    bottom.rowconfigure(0, weight=1)
    canvases = []
    for c in range(3):
        bottom.columnconfigure(c, weight=1, uniform="bottom")
        cv = tk.Canvas(bottom, bg=PANEL, highlightthickness=0,
                       width=100, height=80)
        cv.grid(row=0, column=c, sticky="nsew",
                padx=((0, 3), (3, 3), (3, 0))[c])
        canvases.append(cv)
    loss_canvas, jit_canvas, owd_canvas = canvases

    def refresh_body():
        worst = None
        for p in peers:
            snap = engine.snapshot(p)
            w = row_widgets[p]
            t = snap["totals"]
            if snap["links_up"]:
                o = snap["overall"]
                if worst is None or o < worst[0]:
                    worst = (o, p)
                live = [r for r in snap["rows"] if r["connected"]]
                rtt = sum(r["rtt_avg"] for r in live) / len(live)
                jit = max(r["jitter"] for r in live)
                w["score"].configure(text=f"{o:.0f}", fg="white",
                                     bg=score_color(o))
                w["label"].configure(text=snap["overall_label"])
                w["rtt"].configure(text=f"{rtt:.1f}")
                w["jit"].configure(text=f"{jit:.1f}")
            else:
                w["score"].configure(text="--", fg=TXT_DIM, bg="#555a61")
                w["label"].configure(text="no link")
                w["rtt"].configure(text="-")
                w["jit"].configure(text="-")
            w["loss"].configure(text=f"{t['loss_pct']:.2f}")
            w["up"].configure(text=f"{snap['links_up']}/{len(STREAMS)}")
            flag = ("⚠ UDP silent — blocked or old peer version"
                    if snap["udp_silent"] else (snap["loss_pattern"] or ""))
            w["flag"].configure(text=flag)
        mesh_sub.set(f"{len(peers)} peers · worst pair: "
                     f"{worst[1]} ({worst[0]:.0f})" if worst else
                     f"{len(peers)} peers · waiting for links")

        p = sel["peer"]
        snap = engine.snapshot(p)
        t = snap["totals"]
        up_s = int(snap["uptime"])
        foot_var.set(
            f"pair → {p}  ·  {ports_summary()}  ·  frame {snap['frame_size']} B"
            f"  ·  uptime {up_s // 3600:02d}:{(up_s % 3600) // 60:02d}:"
            f"{up_s % 60:02d}  ·  since reset  sent {t['tx']:,}  "
            f"recv {t['recv']:,}  lost {t['lost']:,} ({t['loss_pct']:.2f}%)  "
            f"fwd→ {t['fwd_lost']:,}  rtn← {t['rtn_lost']:,}")
        hist = engine.history_copy(p)
        owd_f, owd_r, band_hist = engine.extra_history_copy(p)
        now = time.monotonic()
        _draw_chart(lat_canvas, f"Latency (RTT, ms) — {p}", "rtt", series,
                    hist, view_seconds, now, ymin_floor=2.0, unit="",
                    value_fmt=lambda v: f"{v:.1f}" if v < 10 else f"{v:.0f}",
                    band=band_hist, band_label="p5–p95 (UDP)")
        _draw_chart(loss_canvas, "Loss + late (%)", "loss", series, hist,
                    view_seconds, now, ymin_floor=2.0, unit="%",
                    value_fmt=lambda v: f"{v:.0f}")
        _draw_chart(jit_canvas, "Jitter (ms)", "jitter", series, hist,
                    view_seconds, now, ymin_floor=1.0, unit="",
                    value_fmt=lambda v: f"{v:.1f}" if v < 10 else f"{v:.0f}")
        _draw_chart(owd_canvas, "One-way drift (ms)", "v",
                    [("F", HPE_GREEN, "fwd→"), ("R", "#FF8300", "rtn←")],
                    {"F": owd_f, "R": owd_r},
                    view_seconds, now, ymin_floor=2.0, unit="",
                    value_fmt=lambda v: f"{v:.1f}" if v < 10 else f"{v:.0f}")

    def refresh():
        try:
            refresh_body()
        except tk.TclError:
            return  # window is being torn down
        except Exception:
            traceback.print_exc()
        try:
            root.after(args.refresh_ms, refresh)
        except tk.TclError:
            pass

    def on_close():
        engine.shutdown()
        root.destroy()

    select_peer(peers[0])
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(120, refresh)
    root.mainloop()


def run_console_mesh(engine, args):
    vt = enable_vt_mode()
    print(f"Network Vitals {__version__}  mesh: {', '.join(engine.peers)}  "
          f"bind={args.bind}  {ports_summary()}")
    print("Ctrl-C to stop.\n")
    try:
        with ConsoleKeys() as keys:
            while not engine.stop.is_set():
                if vt:
                    print("\033[2J\033[H", end="")
                else:
                    os.system("cls" if sys.platform == "win32" else "clear")
                print(f"  {'Peer':<22}{'Up':>5}{'Score':>7}  {'':<10}"
                      f"{'RTT ms':>8}{'Loss %':>8}{'Fwd':>6}{'Rtn':>6}")
                print("  " + "-" * 76)
                for p in engine.peers:
                    snap = engine.snapshot(p)
                    t = snap["totals"]
                    if snap["links_up"]:
                        live = [r for r in snap["rows"] if r["connected"]]
                        rtt = sum(r["rtt_avg"] for r in live) / len(live)
                        print(f"  {p:<22}{snap['links_up']:>3}/{len(STREAMS)}"
                              f"{snap['overall']:>7.0f}  "
                              f"{snap['overall_label']:<10}{rtt:>8.1f}"
                              f"{t['loss_pct']:>8.2f}{t['fwd_lost']:>6}"
                              f"{t['rtn_lost']:>6}")
                    else:
                        print(f"  {p:<22}  0/{len(STREAMS)}{'--':>7}  "
                              f"{'no link':<10}{'-':>8}{t['loss_pct']:>8.2f}"
                              f"{t['fwd_lost']:>6}{t['rtn_lost']:>6}")
                    warn = ("UDP silent - blocked or old peer version"
                            if snap["udp_silent"]
                            else snap["loss_pattern"])
                    if warn:
                        print(f"      ! {warn}")
                if keys.enabled:
                    print("\n  keys:  [r] reset counters    [q] quit")
                key = keys.poll(args.refresh_ms / 1000.0)
                if key == "r":
                    engine.reset()
                elif key in ("q", "\x03"):
                    return
    except KeyboardInterrupt:
        pass
    finally:
        engine.shutdown()


# ---------------------------------------------------------------------------
# Console UI (fallback when no display / --no-gui)
# ---------------------------------------------------------------------------
def enable_vt_mode():
    """Enable ANSI escape processing in the Windows console. Classic
    conhost/cmd.exe ships with it OFF, so without this the console UI prints
    literal '←[2J←[H' garbage instead of clearing the screen. Returns True if
    escapes will render."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        handle = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not k32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(k32.SetConsoleMode(
            handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
    except Exception:
        return False


class ConsoleKeys:
    """Non-blocking single-key reader for the console UI ('r' = reset
    counters, 'q' = quit). Windows polls msvcrt; POSIX puts the TTY in cbreak
    mode (restored on exit) and selects on stdin. When stdin isn't an
    interactive terminal (piped, service) key handling is simply disabled and
    poll() degrades to a plain sleep."""

    def __init__(self):
        self.enabled = False
        self._posix_state = None

    def __enter__(self):
        if sys.platform == "win32":
            try:
                import msvcrt  # noqa: F401
                self.enabled = True
            except ImportError:
                pass
        else:
            try:
                if sys.stdin.isatty():
                    import termios
                    import tty
                    fd = sys.stdin.fileno()
                    self._posix_state = (fd, termios.tcgetattr(fd))
                    tty.setcbreak(fd)  # keeps ISIG, so Ctrl-C still works
                    self.enabled = True
            except Exception:
                self._posix_state = None
        return self

    def __exit__(self, *exc):
        if self._posix_state is not None:
            import termios
            fd, old = self._posix_state
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
            except Exception:
                pass
        return False

    def poll(self, timeout):
        """Wait up to `timeout` seconds; return a lowercased key or None."""
        if not self.enabled:
            time.sleep(timeout)
            return None
        if sys.platform == "win32":
            import msvcrt
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if msvcrt.kbhit():
                    return msvcrt.getwch().lower()
                time.sleep(0.05)
            return None
        import select
        r, _, _ = select.select([sys.stdin], [], [], timeout)
        if r:
            return sys.stdin.read(1).lower()
        return None


def _hms(seconds):
    s = int(seconds)
    return f"{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"


def run_console(engine, args):
    vt = enable_vt_mode()
    print(f"Network Vitals {__version__}  peer={args.peer}  bind={args.bind}  "
          f"{ports_summary()}  {args.pps} probes/s/stream")
    print("Ctrl-C to stop.\n")
    try:
        run_console_loop(engine, args, vt)
    except KeyboardInterrupt:
        pass
    finally:
        engine.shutdown()


def run_console_loop(engine, args, vt):
    with ConsoleKeys() as keys:
        while not engine.stop.is_set():
            snap = engine.snapshot()
            if vt:
                print("\033[2J\033[H", end="")  # clear screen
            else:
                os.system("cls" if sys.platform == "win32" else "clear")
            o = snap["overall"]
            um = f"{snap['udp_mos']:.2f}" if snap["udp_mos"] is not None else "-"
            tq = f"{snap['tcp_pqi']:.0f}" if snap["tcp_pqi"] is not None else "-"
            print(f"  OVERALL QUALITY: {o:5.1f}/100  {snap['overall_label']:<10}"
                  f"  ({snap['links_up']}/{len(STREAMS)} streams up, worst {snap['worst']:.0f})"
                  f"   UDP MOS {um}   TCP PQI {tq}")
            print("  " + "-" * 100)
            print(f"  {'Stream':<10}{'Status':<8}{'RTT ms':>9}{'1-way':>9}"
                  f"{'Jitter':>9}{'Loss %':>9}{'Late %':>9}{'Score':>7}{'MOS':>6}"
                  f"{'TXpps':>8}{'RXpps':>8}")
            print("  " + "-" * 100)
            for r in snap["rows"]:
                st = "UP" if r["connected"] else "DOWN"
                mos_s = f"{r['mos']:.2f}" if r["mos"] is not None else "-"
                if r["connected"]:
                    print(f"  {r['name']:<10}{st:<8}{r['rtt_avg']:>9.2f}{r['latency']:>9.2f}"
                          f"{r['jitter']:>9.2f}{r['loss']:>9.1f}{r['late']:>9.1f}{r['score']:>7.0f}"
                          f"{mos_s:>6}{r['tx_pps']:>8.0f}{r['rx_pps']:>8.0f}")
                else:
                    print(f"  {r['name']:<10}{st:<8}{'-':>9}{'-':>9}{'-':>9}"
                          f"{r['loss']:>9.1f}{r['late']:>9.1f}{'-':>7}{'-':>6}"
                          f"{r['tx_pps']:>8.0f}{r['rx_pps']:>8.0f}")
            t = snap["totals"]
            df = "on" if snap["dont_fragment"] else "off"
            size_tag = {"verified": "verified", "mismatch": "MISMATCH",
                        "pending": "pending"}[snap["size_status"]]
            vx = (f"   VXLAN vni {snap['vxlan']['vni']} udp/{snap['vxlan']['port']}"
                  if snap["vxlan"] else "")
            print("  " + "-" * 100)
            print(f"  frame {snap['frame_size']} B   DF {df}   size {size_tag}{vx}"
                  f"   (UDP peer-RX / my-RX per stream:"
                  + "".join(f"  {r['name'].split('-')[1]} {r['peer_rx_max']}/{r['rx_echo_max']}"
                            for r in snap["rows"] if r["proto"] == "UDP") + ")")
            # Two totals lines: the resettable demo window and the lifetime
            # run, so loss over the whole duration and loss since the last
            # reset are both visible without restarting the app.
            print(f"  since reset ({_hms(snap['since_reset'])}):"
                  f"  sent {t['tx']:,}  recv {t['recv']:,}  "
                  f"lost {t['lost']:,} ({t['loss_pct']:.2f}%)  late {t['late']:,} "
                  f"({t['late_pct']:.2f}%)")
            print(f"  lifetime    ({_hms(snap['uptime'])}):"
                  f"  sent {t['life_tx']:,}  recv {t['life_recv']:,}  "
                  f"lost {t['life_lost']:,} ({t['life_loss_pct']:.2f}%)  "
                  f"late {t['life_late']:,} ({t['life_late_pct']:.2f}%)")
            print(f"  loss split (since reset):  forward -> {t['fwd_lost']:,} "
                  f"({t['fwd_pct']:.2f}%)   "
                  f"return <- {t['rtn_lost']:,} ({t['rtn_pct']:.2f}%)"
                  + "".join(f"   {r['name'].split('-')[1]}:{loss_verdict(r['fwd_lost'], r['rtn_lost'])[0]}"
                            for r in snap["rows"] if r["fwd_lost"] > 6 or r["rtn_lost"] > 6))
            if snap.get("udp_silent"):
                print("  ! UDP silent while TCP is up: UDP blocked in the path "
                      "(firewall/ACL) or the peer runs an outdated version - "
                      "update BOTH ends.")
            elif snap.get("loss_pattern"):
                print(f"  ! loss pattern (last 60 s): {snap['loss_pattern']}")
            if keys.enabled:
                print("  keys:  [r] reset counters    [q] quit    (Ctrl-C also quits)")
            key = keys.poll(args.refresh_ms / 1000.0)
            if key == "r":
                engine.reset()
            elif key in ("q", "\x03"):   # 'q', or Ctrl-C swallowed by getwch
                return


# ---------------------------------------------------------------------------
# Self-update: fetch the latest release of this file from UPDATE_URL and
# replace ourselves in place. Only runs when explicitly requested (--update /
# --check-update / update.bat) — a measurement tool must not phone home on
# its own, and a surprise fetch would skew the very numbers it reports.
# ---------------------------------------------------------------------------
def _parse_version(text):
    """Extract __version__ from source text as an int tuple, or None."""
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if not m:
        return None, None
    nums = tuple(int(x) for x in re.findall(r"\d+", m.group(1))[:3])
    return (nums or None), m.group(1)


def _is_cert_error(exc):
    """True when exc is (or wraps) an SSL certificate-verification failure -
    the 'unable to get local issuer certificate' class of errors."""
    import ssl
    candidates = (exc, getattr(exc, "reason", None), exc.__cause__)
    return any(isinstance(c, ssl.SSLCertVerificationError)
               for c in candidates if c is not None)


def _download_via_windows_tls(url, timeout, _curl=None, _ps="powershell"):
    """Fetch `url` with tools that validate TLS through Windows SChannel:
    curl.exe (ships with Windows 10 1803+), then PowerShell.

    Python's OpenSSL fails with 'unable to get local issuer certificate'
    in two situations SChannel handles fine: a corporate TLS-inspecting
    proxy whose root lives (only) in the Windows certificate store, and a
    server that omits its intermediate cert (SChannel fetches it via AIA;
    OpenSSL never does). Routing the download through curl/PowerShell
    applies the SAME trust decisions as Edge - verification stays on.
    Returns raw bytes; raises RuntimeError if both tools fail."""
    import subprocess
    import tempfile
    creation = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    errors = []

    if _curl is None:
        _curl = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                             "System32", "curl.exe")
        if not os.path.exists(_curl):
            _curl = "curl.exe"  # fall back to PATH
    try:
        out = subprocess.run(
            [_curl, "-sSfL", "--proto", "=https", "--proto-redir", "=https",
             "--max-time", str(int(timeout) * 2), url],
            capture_output=True, creationflags=creation, timeout=timeout * 4)
        if out.returncode == 0 and out.stdout:
            return out.stdout
        errors.append("curl: " + (out.stderr or b"").decode("utf-8",
                                                            "replace").strip())
    except (OSError, subprocess.TimeoutExpired) as e:
        errors.append(f"curl: {e}")

    # PowerShell fallback (Invoke-WebRequest -> .NET -> SChannel). The URL
    # and output path travel in environment variables so no user-influenced
    # text is ever spliced into the command string. -OutFile keeps the bytes
    # exact (console capture would re-encode them).
    tmp = tempfile.NamedTemporaryFile(prefix="nv-update-", delete=False)
    tmp.close()
    env = dict(os.environ, NV_UPDATE_URL=url, NV_UPDATE_OUT=tmp.name)
    try:
        out = subprocess.run(
            [_ps, "-NoProfile", "-NonInteractive", "-Command",
             "$ProgressPreference = 'SilentlyContinue'; "
             "[Net.ServicePointManager]::SecurityProtocol = "
             "[Net.ServicePointManager]::SecurityProtocol -bor 3072; "
             "Invoke-WebRequest -UseBasicParsing -Uri $env:NV_UPDATE_URL "
             "-OutFile $env:NV_UPDATE_OUT"],
            capture_output=True, creationflags=creation, env=env,
            timeout=timeout * 4)
        if out.returncode == 0:
            with open(tmp.name, "rb") as fh:
                data = fh.read()
            if data:
                return data
            errors.append("powershell: empty download")
        else:
            errors.append("powershell: " +
                          (out.stderr or b"").decode("utf-8",
                                                     "replace").strip())
    except (OSError, subprocess.TimeoutExpired) as e:
        errors.append(f"powershell: {e}")
    finally:
        try:
            os.remove(tmp.name)
        except OSError:
            pass
    raise RuntimeError("; ".join(errors) or "no downloader available")


def fetch_update(url, timeout=15):
    """Download the candidate source. Returns (source_text, version_tuple,
    version_string). Raises RuntimeError with a friendly message on any
    problem — network, HTTP, or a payload that isn't a plausible newer us."""
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            # urllib follows https->http redirects; installing code fetched
            # over plaintext is where the line is, so refuse the downgrade.
            final = getattr(resp, "url", None) or url
            if (url.lower().startswith("https:")
                    and not final.lower().startswith("https:")):
                raise RuntimeError(f"refusing redirect to insecure URL {final}")
            raw = resp.read()
    except (urllib.error.URLError, OSError) as e:
        cert_issue = _is_cert_error(e)
        if (cert_issue and sys.platform == "win32"
                and url.lower().startswith("https:")):
            # Python's own trust chain failed - retry through the Windows
            # certificate store (see _download_via_windows_tls). This is the
            # normal path behind corporate TLS-inspecting proxies.
            try:
                raw = _download_via_windows_tls(url, timeout)
            except RuntimeError as e2:
                raise RuntimeError(
                    f"download failed: {e} (then retried through the "
                    f"Windows certificate store, which also failed: {e2})"
                ) from e
        else:
            msg = f"download failed: {e}"
            if cert_issue:
                msg += (" - certificate verification failed. This usually "
                        "means a TLS-inspecting proxy whose root certificate "
                        "Python doesn't trust; on Windows the updater retries "
                        "through the system certificate store automatically.")
            raise RuntimeError(msg) from e
    try:
        src = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise RuntimeError(f"payload is not UTF-8 text: {e}") from e
    # Sanity: it must be valid Python and recognisably this application.
    try:
        compile(src, "netquality.py", "exec")
    except SyntaxError as e:
        raise RuntimeError(f"payload does not compile: {e}") from e
    if "MAGIC" not in src or "Network Vitals" not in src:
        raise RuntimeError("payload doesn't look like Network Vitals — wrong URL?")
    vtuple, vstr = _parse_version(src)
    if vtuple is None:
        raise RuntimeError("payload has no __version__")
    return src, vtuple, vstr


def install_update(src):
    """Write already-fetched-and-sanity-checked source over this file
    (previous copy kept as .bak; the swap itself is atomic). Returns the
    target path. Raises RuntimeError on any failure, including running as a
    packaged .exe (which cannot replace itself)."""
    if getattr(sys, "frozen", False):
        raise RuntimeError("this is a packaged .exe — it can't replace "
                           "itself. Download the new version (or rebuild "
                           "with build_exe.bat).")
    target = os.path.abspath(__file__)
    backup = target + ".bak"
    tmp = target + ".new"
    try:
        with open(target, "r", encoding="utf-8") as fh:
            current = fh.read()
        with open(backup, "w", encoding="utf-8") as fh:
            fh.write(current)
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(src)
        os.replace(tmp, target)  # atomic on the same filesystem
    except OSError as e:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise RuntimeError(f"install failed: {e}") from e
    return target


def relaunch(argv=None, delay=1.5):
    """Start a fresh copy of this app, detached, after `delay` seconds — long
    enough for the current process to exit and release its sockets, so the
    new instance can bind the same ports. Used after an in-app update."""
    import subprocess
    argv = list(argv or [])
    if getattr(sys, "frozen", False):
        # A packaged .exe can't run `python -c`; it also can't self-update,
        # so the port-release delay doesn't matter here. Spawn directly.
        subprocess.Popen([sys.executable] + argv)
        return
    inner = [sys.executable, os.path.abspath(__file__)] + argv
    subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess, sys, time; time.sleep(float(sys.argv[1])); "
         "subprocess.Popen(sys.argv[2:])",
         str(delay)] + inner)


def perform_update(url, apply=True):
    """Check (and optionally install) the latest version. Returns an exit
    code: 0 = up to date / updated, 1 = failed, 3 = update available (check
    mode only, so scripts can branch on it)."""
    local_v, _ = _parse_version(f'__version__ = "{__version__}"')
    print(f"Network Vitals {__version__}")
    print(f"Checking {url} …")
    try:
        src, remote_v, remote_s = fetch_update(url)
    except RuntimeError as e:
        print(f"Update check failed: {e}", file=sys.stderr)
        return 1
    if remote_v <= local_v:
        print(f"Already up to date (latest is {remote_s}).")
        return 0
    print(f"New version available: {remote_s}")
    if not apply:
        return 3
    try:
        target = install_update(src)
    except RuntimeError as e:
        print(f"Install failed: {e}", file=sys.stderr)
        return 1
    print(f"Updated {os.path.basename(target)} {__version__} -> {remote_s}.")
    print(f"(previous version saved as {os.path.basename(target)}.bak)")
    print("Restart the app to run the new version.")
    return 0


# ---------------------------------------------------------------------------
# Saved settings (used by the graphical launcher; the CLI stays canonical and
# never reads them - a script gets exactly the flags it passed, nothing more)
# ---------------------------------------------------------------------------
def config_dir():
    """Per-user config directory (created on demand by save_settings)."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "NetVitals")
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")
    return os.path.join(base, "netvitals")


def settings_path():
    return os.path.join(config_dir(), "settings.json")


def load_settings():
    """Best-effort read of the launcher settings; {} when absent or corrupt."""
    try:
        with open(settings_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(data):
    """Best-effort atomic write; launching must never fail on a settings file."""
    try:
        os.makedirs(config_dir(), exist_ok=True)
        tmp = settings_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
        os.replace(tmp, settings_path())
    except OSError:
        pass


def local_ips():
    """Best-effort list of this machine's non-loopback IPv4 addresses, the
    routable one first. connect() on a UDP socket sends NO packets - it only
    asks the OS which source address it would route from."""
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.0.2.1", 9))  # TEST-NET-1: never actually sent to
            ip = s.getsockname()[0]
            if not ip.startswith("127."):
                ips.append(ip)
        finally:
            s.close()
    except OSError:
        pass
    # Windows answers a query for the machine's own name locally; other
    # platforms may forward it to real DNS, which would break the "never
    # touches the network unless asked" rule - the UDP-trick address above
    # is all we list there.
    if sys.platform == "win32":
        try:
            for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
                if ip not in ips and not ip.startswith(("127.", "169.254.")):
                    ips.append(ip)
        except OSError:
            pass
    return ips


def _has_console():
    """True when a usable console is attached (always True off-Windows)."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.kernel32.GetConsoleWindow())
    except Exception:
        return True


def _alert_gui_error(msg):
    """Surface a fatal startup error in a dialog when there is no console to
    print to (a pythonw.exe shortcut) - dying silently is not an option."""
    if _has_console():
        return
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Network Vitals", msg)
        root.destroy()
    except Exception:
        pass  # headless AND console-less; stderr already got the message


def _spawn_in_new_console(argv):
    """Windows: re-run ourselves in a fresh console window. Console mode
    started from a GUI-only process (a pythonw.exe shortcut) has nowhere to
    draw, so the launcher hands the run to a real console instead."""
    import subprocess
    if getattr(sys, "frozen", False):
        cmd = [sys.executable] + argv
    else:
        exe = sys.executable
        if os.path.basename(exe).lower() == "pythonw.exe":
            console_exe = os.path.join(os.path.dirname(exe), "python.exe")
            if os.path.exists(console_exe):
                exe = console_exe
        cmd = [exe, os.path.abspath(__file__)] + argv
    subprocess.Popen(cmd, creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))


# ---------------------------------------------------------------------------
# Graphical launcher - the double-click experience. Running with no --peer
# opens this window instead of erroring: every option/switch is a field here,
# settings persist between runs, and updates install with one click.
# ---------------------------------------------------------------------------
def _fmt_num(v):
    """10.0 -> '10', 0.5 -> '0.5', 16777215 -> '16777215' - keep generated
    argv and messages human-friendly (never scientific notation)."""
    try:
        if float(v).is_integer():
            return str(int(v))
    except (TypeError, ValueError, OverflowError):
        pass
    return repr(float(v)) if isinstance(v, float) else str(v)


def _launcher_argv(vals):
    """Turn the launcher's raw field values into a CLI argv list. Validates
    everything, raising ValueError with a user-facing message. Only options
    that differ from the defaults are emitted, so the produced command line
    is exactly the one you would have typed by hand."""
    def num(label, raw, conv, lo, hi):
        try:
            v = conv(str(raw).strip())
        except (TypeError, ValueError):
            raise ValueError(f"{label}: '{raw}' is not a number.")
        if not (lo <= v <= hi):
            raise ValueError(f"{label} must be between {_fmt_num(lo)} "
                             f"and {_fmt_num(hi)}.")
        return v

    peer = (vals.get("peer") or "").strip()
    if not peer:
        raise ValueError("Peer IP is required - the address of the other "
                         "workstation running Network Vitals.")
    if "," in peer:
        # Mesh run: a comma-separated list of peers, one row per pair.
        try:
            plist = _peer_list(peer)
        except argparse.ArgumentTypeError as e:
            raise ValueError(f"Peers: {e}")
        argv = ["--peers", ",".join(plist)]
    else:
        argv = ["--peer", peer]

    size = num("Probe size", vals["size"], int, HEADER_LEN, MAX_SIZE)
    if size != 200:
        argv += ["--size", str(size)]
    pps = num("Probes/sec", vals["pps"], int, 1, 100000)
    if pps != 50:
        argv += ["--pps", str(pps)]
    if vals["dont_fragment"]:
        argv += ["--dont-fragment"]

    bind = (vals.get("bind") or "").strip() or "0.0.0.0"
    if bind != "0.0.0.0":
        argv += ["--bind", bind]
    for label, key, flag, default in (
            ("UDP ports", "udp_ports", "--udp-ports", DEFAULT_UDP_PORTS),
            ("TCP ports", "tcp_ports", "--tcp-ports", DEFAULT_TCP_PORTS)):
        raw = (vals.get(key) or "").strip()
        if raw:
            try:
                ports = _port_pair(raw)
            except argparse.ArgumentTypeError as e:
                raise ValueError(f"{label}: {e}")
            if ports != default:
                argv += [flag, "%d,%d" % ports]
    window = num("Window", vals["window"], float, 1.0, 3600.0)
    if window != 10.0:
        argv += ["--window", _fmt_num(window)]
    timeout = num("Probe timeout", vals["timeout"], float, 0.1, 60.0)
    if timeout != 2.0:
        argv += ["--timeout", _fmt_num(timeout)]
    deadband = num("Loss deadband", vals["loss_deadband"], float, 0.0, 100.0)
    if deadband != 0.5:
        argv += ["--loss-deadband", _fmt_num(deadband)]
    history = num("Chart history", vals["history"], int, 10, 86400)
    if history != 300:
        argv += ["--history", str(history)]
    refresh = num("UI refresh", vals["refresh_ms"], int, 50, 60000)
    if refresh != 500:
        argv += ["--refresh-ms", str(refresh)]
    if vals["vxlan"]:
        if argv[0] == "--peers":
            raise ValueError("VXLAN with multiple peers is not supported yet "
                             "- untick VXLAN or use a single peer.")
        argv += ["--vxlan"]
        vni = num("VXLAN VNI", vals["vxlan_vni"], int, 0, 0xFFFFFF)
        if vni != VXLAN_DEFAULT_VNI:
            argv += ["--vxlan-vni", str(vni)]
        vxport = num("VXLAN port", vals["vxlan_port"], int, 1, 65535)
        if vxport != VXLAN_DEFAULT_PORT:
            argv += ["--vxlan-port", str(vxport)]
    if vals["no_gui"]:
        argv += ["--no-gui"]
    return argv


def _open_tool_window(root, title, runner, thread_name):
    """Run a one-shot tool (`runner(out)`) in a background thread, streaming
    its output into a small window. The tools bind their own ephemeral port,
    so they can run while anything else is running on either end."""
    import queue
    import tkinter as tk

    q = queue.Queue()
    dlg = tk.Toplevel(root)
    dlg.title(title)
    dlg.configure(bg=BG)
    txt = tk.Text(dlg, width=76, height=18, bg=PANEL, fg=TXT, relief="flat",
                  font=("Consolas", 9), state="disabled", wrap="none",
                  highlightthickness=0, padx=8, pady=8)
    txt.pack(fill="both", expand=True, padx=10, pady=10)

    def worker():
        try:
            runner(lambda line="": q.put(str(line)))
        except Exception as e:  # show the failure, don't kill the launcher
            q.put(f"failed: {e}")
        q.put(None)  # done sentinel: stop polling

    threading.Thread(target=worker, name=thread_name, daemon=True).start()

    def poll():
        try:
            while True:
                line = q.get_nowait()
                if line is None:
                    return
                txt.configure(state="normal")
                txt.insert("end", line + "\n")
                txt.see("end")
                txt.configure(state="disabled")
        except queue.Empty:
            pass
        try:
            dlg.after(150, poll)
        except tk.TclError:
            pass  # window closed mid-sweep; the daemon thread just drains

    poll()


def open_update_dialog(root, update_url, relaunch_argv=None):
    """Check for / install updates from the GUI. The network is only touched
    after the user explicitly opens this dialog - the app never checks on its
    own. 'Install and restart' swaps the file (previous copy kept as .bak),
    starts a fresh instance a moment later (so the sockets are released
    first), and closes this one."""
    import tkinter as tk

    existing = getattr(root, "_nq_update_dialog", None)
    if existing is not None:
        try:
            if existing.winfo_exists():
                existing.lift()
                existing.focus_set()
                return
        except tk.TclError:
            pass

    dlg = tk.Toplevel(root)
    root._nq_update_dialog = dlg
    dlg.title("Network Vitals update")
    dlg.configure(bg=BG, padx=18, pady=14)
    dlg.resizable(False, False)
    dlg.transient(root)

    tk.Label(dlg, text=f"Installed version: {__version__}", fg=TXT, bg=BG,
             font=(FONT, 11, "bold")).pack(anchor="w")
    status_var = tk.StringVar(value="Checking ...")
    tk.Label(dlg, textvariable=status_var, fg=TXT_DIM, bg=BG, font=(FONT, 10),
             wraplength=430, justify="left").pack(anchor="w", pady=(6, 12))

    btns = tk.Frame(dlg, bg=BG)
    btns.pack(anchor="e", fill="x")

    def mkbtn(text, cmd, primary=False):
        return tk.Button(btns, text=text, command=cmd,
                         bg=(HPE_GREEN if primary else PANEL_HI),
                         fg=("white" if primary else TXT),
                         activebackground=HPE_GREEN_DK, activeforeground="white",
                         relief="flat", bd=0, highlightthickness=0,
                         padx=12, pady=5, font=(FONT, 9, "bold"), cursor="hand2")

    state = {"src": None, "vstr": None}
    outcome = {}  # worker thread -> UI poll loop; workers never touch Tk

    def check_worker():
        # Catch EVERYTHING: fetch_update wraps the expected failures in
        # RuntimeError, but a scheme-less --update-url raises ValueError and
        # a misbehaving proxy raises http.client exceptions - any escape
        # would kill this thread and leave the dialog on "Checking" forever.
        try:
            src, vt, vs = fetch_update(update_url)
            local_v, _ = _parse_version(f'__version__ = "{__version__}"')
            if vt <= local_v:
                outcome["check"] = ("uptodate", vs)
            else:
                outcome["check"] = ("available", (src, vs))
        except Exception as e:
            outcome["check"] = ("error", str(e) or e.__class__.__name__)

    def install_worker():
        try:
            install_update(state["src"])
            outcome["install"] = ("done", None)
        except Exception as e:
            outcome["install"] = ("error", str(e) or e.__class__.__name__)

    def close_app():
        try:
            root.destroy()
        except tk.TclError:
            pass

    def do_check():
        check_btn.configure(state="disabled")
        install_btn.pack_forget()
        status_var.set(f"Checking {update_url} ...")
        threading.Thread(target=check_worker, daemon=True).start()

    def do_install():
        install_btn.configure(state="disabled")
        check_btn.configure(state="disabled")
        status_var.set("Installing ...")
        threading.Thread(target=install_worker, daemon=True).start()

    check_btn = mkbtn("Check again", do_check)
    install_btn = mkbtn("Install and restart", do_install, primary=True)
    close_btn = mkbtn("Close", dlg.destroy)
    close_btn.pack(side="right")
    check_btn.pack(side="right", padx=(0, 6))
    # install_btn is packed only once an update is actually available

    def poll():
        if "check" in outcome:
            kind, val = outcome.pop("check")
            check_btn.configure(state="normal")
            if kind == "uptodate":
                status_var.set(f"You're on the latest version ({val}).")
            elif kind == "available":
                state["src"], state["vstr"] = val
                status_var.set(f"Version {state['vstr']} is available.")
                install_btn.configure(state="normal")
                install_btn.pack(side="right", padx=(0, 6))
            else:
                status_var.set(f"Update check failed: {val}")
        if "install" in outcome:
            kind, val = outcome.pop("install")
            if kind == "done":
                status_var.set(f"Updated to {state['vstr']}. Restarting ...")
                relaunch(relaunch_argv, delay=1.5)
                dlg.after(700, close_app)
                return  # going down; stop polling
            status_var.set(f"Install failed: {val}")
            check_btn.configure(state="normal")
            install_btn.configure(state="normal")  # allow a direct retry
        try:
            dlg.after(150, poll)
        except tk.TclError:
            pass  # dialog closed; workers finish into a dict nobody reads

    do_check()
    poll()


def run_launcher(update_url=UPDATE_URL):
    """Graphical launch window: pick the peer and every option without
    touching a command line. Returns the argv list to run with, or None when
    the window was closed (or the run was handed to a new console process).
    Raises RuntimeError when no display is available."""
    import tkinter as tk
    from tkinter import messagebox, ttk

    try:
        root = tk.Tk()
    except tk.TclError as e:
        raise RuntimeError(str(e)) from e

    root.title(f"Network Vitals {__version__} - launch")
    root.configure(bg=BG)
    root.resizable(False, False)

    s = load_settings()
    result = {"argv": None}
    adv = {"on": bool(s.get("advanced_open", False))}

    def sstr(key, default):
        v = s.get(key, default)
        return str(v) if v is not None else str(default)

    def sbool(key, default):
        v = s.get(key, default)
        return bool(v) if isinstance(v, (bool, int)) else default

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("NQ.TCombobox", fieldbackground=PANEL_HI, background=PANEL_HI,
                    foreground=TXT, arrowcolor=TXT, bordercolor=GRID,
                    lightcolor=PANEL_HI, darkcolor=PANEL_HI, insertcolor=TXT,
                    selectbackground=HPE_GREEN_DK, selectforeground="white")
    root.option_add("*TCombobox*Listbox.background", PANEL_HI)
    root.option_add("*TCombobox*Listbox.foreground", TXT)
    root.option_add("*TCombobox*Listbox.selectBackground", HPE_GREEN_DK)
    root.option_add("*TCombobox*Listbox.selectForeground", "white")

    # ---- header -----------------------------------------------------------
    header = tk.Frame(root, bg=BG, padx=16, pady=12)
    header.pack(fill="x")
    ekg = tk.Canvas(header, width=54, height=34, bg=BG, highlightthickness=0)
    ekg.pack(side="left", padx=(0, 10))
    _draw_ekg(ekg)
    tk.Label(header, text="Network Vitals", fg=TXT, bg=BG,
             font=(FONT, 17, "bold")).pack(side="left")
    tk.Label(header, text=f"v{__version__}", fg=TXT_DIM, bg=BG,
             font=(FONT, 10)).pack(side="left", padx=(8, 0), pady=(7, 0))
    ips = local_ips()
    if ips:
        tk.Label(header, text="this machine:  " + "   ".join(ips[:3]),
                 fg=TXT_DIM, bg=BG, font=(FONT, 9)).pack(side="right",
                                                         pady=(9, 0))

    body = tk.Frame(root, bg=BG, padx=18, pady=2)
    body.pack(fill="x")

    def mklabel(parent, text, row, dim=False):
        tk.Label(parent, text=text, fg=(TXT_DIM if dim else TXT), bg=BG,
                 font=(FONT, 10)).grid(row=row, column=0, sticky="w",
                                       pady=3, padx=(0, 10))

    def mkhint(parent, text, row):
        tk.Label(parent, text=text, fg=TXT_DIM, bg=BG,
                 font=(FONT, 8)).grid(row=row, column=2, sticky="w",
                                      padx=(10, 0))

    def mkentry(parent, var, row, width=16):
        e = tk.Entry(parent, textvariable=var, width=width, bg=PANEL_HI,
                     fg=TXT, insertbackground=TXT, relief="flat",
                     highlightthickness=1, highlightbackground=GRID,
                     highlightcolor=HPE_GREEN, font=(FONT, 10),
                     disabledbackground=PANEL, disabledforeground=TXT_DIM)
        e.grid(row=row, column=1, sticky="w", pady=3, ipady=2)
        return e

    def mkcheck(parent, text, var, row, column=1, columnspan=2):
        c = tk.Checkbutton(parent, text=text, variable=var, bg=BG, fg=TXT,
                           activebackground=BG, activeforeground=TXT,
                           selectcolor=PANEL_HI, font=(FONT, 9),
                           highlightthickness=0, anchor="w", cursor="hand2")
        c.grid(row=row, column=column, columnspan=columnspan, sticky="w", pady=2)
        return c

    # ---- basic options ------------------------------------------------------
    peer_var = tk.StringVar(value=sstr("peer", ""))
    recent = [p for p in s.get("recent_peers", []) if isinstance(p, str)]
    size_var = tk.StringVar(value=sstr("size", "200"))
    pps_var = tk.StringVar(value=sstr("pps", "50"))
    df_var = tk.BooleanVar(value=sbool("dont_fragment", False))

    mklabel(body, "Peer IP / host", 0)
    peer_box = ttk.Combobox(body, textvariable=peer_var, values=recent,
                            width=17, style="NQ.TCombobox", font=(FONT, 10))
    peer_box.grid(row=0, column=1, sticky="w", pady=3, ipady=1)
    mkhint(body, "the other workstation running Network Vitals", 0)

    mklabel(body, "Probe size (B)", 1)
    mkentry(body, size_var, 1)
    mkhint(body, "200 default · 1472 fills a 1500 MTU · 8972 a 9000 jumbo", 1)

    mklabel(body, "Probes/sec", 2)
    mkentry(body, pps_var, 2)
    mkhint(body, "per stream (default 50)", 2)

    mkcheck(body, "Don't fragment - drop oversized probes instead of "
                  "splitting them (jumbo testing)", df_var, 3)

    # ---- advanced options (collapsed by default) ----------------------------
    adv_btn = tk.Button(root, bg=BG, fg=TXT_DIM, activebackground=BG,
                        activeforeground=TXT, relief="flat", bd=0,
                        highlightthickness=0, font=(FONT, 9, "bold"),
                        cursor="hand2", anchor="w", padx=18)
    adv_btn.pack(fill="x", pady=(8, 0))

    adv_frame = tk.Frame(root, bg=BG, padx=18, pady=2)

    bind_var = tk.StringVar(value=sstr("bind", "0.0.0.0"))
    udp_var = tk.StringVar(value=sstr("udp_ports", "%d,%d" % DEFAULT_UDP_PORTS))
    tcp_var = tk.StringVar(value=sstr("tcp_ports", "%d,%d" % DEFAULT_TCP_PORTS))
    window_var = tk.StringVar(value=sstr("window", "10"))
    timeout_var = tk.StringVar(value=sstr("timeout", "2"))
    deadband_var = tk.StringVar(value=sstr("loss_deadband", "0.5"))
    history_var = tk.StringVar(value=sstr("history", "300"))
    refresh_var = tk.StringVar(value=sstr("refresh_ms", "500"))
    vx_var = tk.BooleanVar(value=sbool("vxlan", False))
    vni_var = tk.StringVar(value=sstr("vxlan_vni", str(VXLAN_DEFAULT_VNI)))
    vxport_var = tk.StringVar(value=sstr("vxlan_port", str(VXLAN_DEFAULT_PORT)))
    console_var = tk.BooleanVar(value=sbool("no_gui", False))

    rows = [("Bind address", bind_var, "local address to listen on"),
            ("UDP ports (A,B)", udp_var, "both ends must match"),
            ("TCP ports (A,B)", tcp_var, "both ends must match"),
            ("Window (s)", window_var, "sliding window for loss/jitter/rates"),
            ("Probe timeout (s)", timeout_var, "un-echoed probe counts lost after this"),
            ("Loss deadband (%)", deadband_var, "loss+late below this reads as 0"),
            ("Chart history (s)", history_var, "span of the history charts"),
            ("UI refresh (ms)", refresh_var, "dashboard redraw interval")]
    for i, (label, var, hint) in enumerate(rows):
        mklabel(adv_frame, label, i)
        mkentry(adv_frame, var, i)
        mkhint(adv_frame, hint, i)

    r = len(rows)
    mkcheck(adv_frame, "VXLAN encapsulation - carry all probe traffic inside "
                       "a userspace VTEP (both ends)", vx_var, r, column=0,
            columnspan=3)
    mklabel(adv_frame, "    VXLAN VNI", r + 1, dim=True)
    vni_entry = mkentry(adv_frame, vni_var, r + 1)
    mkhint(adv_frame, "must match on both ends", r + 1)
    mklabel(adv_frame, "    VXLAN UDP port", r + 2, dim=True)
    vxport_entry = mkentry(adv_frame, vxport_var, r + 2)
    mkhint(adv_frame, "outer tunnel port (default 4789)", r + 2)
    mkcheck(adv_frame, "Console UI - run in a terminal instead of this "
                       "dashboard", console_var, r + 3, column=0, columnspan=3)

    def sync_vxlan(*_):
        st = "normal" if vx_var.get() else "disabled"
        vni_entry.configure(state=st)
        vxport_entry.configure(state=st)

    vx_var.trace_add("write", sync_vxlan)
    sync_vxlan()

    def show_adv():
        adv_btn.configure(text="▾  Advanced options")
        adv_frame.pack(fill="x", after=adv_btn)

    def hide_adv():
        adv_btn.configure(text="▸  Advanced options")
        adv_frame.pack_forget()

    def toggle_adv():
        adv["on"] = not adv["on"]
        (show_adv if adv["on"] else hide_adv)()

    adv_btn.configure(command=toggle_adv)
    (show_adv if adv["on"] else hide_adv)()

    # ---- bottom bar ---------------------------------------------------------
    bar = tk.Frame(root, bg=BG, padx=18, pady=14)
    bar.pack(fill="x", side="bottom")

    def mkbarbtn(text, cmd, primary=False):
        return tk.Button(bar, text=text, command=cmd,
                         bg=(HPE_GREEN if primary else PANEL_HI),
                         fg=("white" if primary else TXT),
                         activebackground=HPE_GREEN_DK, activeforeground="white",
                         relief="flat", bd=0, highlightthickness=0,
                         padx=(16 if primary else 12), pady=6,
                         font=(FONT, 10 if primary else 9, "bold"),
                         cursor="hand2")

    def collect():
        return {
            "peer": peer_var.get().strip(),
            "size": size_var.get(), "pps": pps_var.get(),
            "dont_fragment": bool(df_var.get()),
            "bind": bind_var.get(), "udp_ports": udp_var.get(),
            "tcp_ports": tcp_var.get(), "window": window_var.get(),
            "timeout": timeout_var.get(), "loss_deadband": deadband_var.get(),
            "history": history_var.get(), "refresh_ms": refresh_var.get(),
            "vxlan": bool(vx_var.get()), "vxlan_vni": vni_var.get(),
            "vxlan_port": vxport_var.get(), "no_gui": bool(console_var.get()),
        }

    def persist(vals):
        data = dict(s)  # keep keys this version doesn't know about
        data.update(vals)
        peers = [vals["peer"]] + [p for p in recent if p != vals["peer"]]
        data["recent_peers"] = peers[:8]
        data["advanced_open"] = adv["on"]
        save_settings(data)

    def _finish_start(vals, argv):
        persist(vals)
        if vals["no_gui"] and not _has_console():
            # Started from a GUI-only process (pythonw shortcut): console
            # mode needs a real console, so hand the run to a fresh one.
            _spawn_in_new_console(argv)
            root.destroy()
            return
        result["argv"] = argv
        root.destroy()

    def do_start():
        if str(start_btn.cget("state")) == "disabled":
            return  # Enter pressed again while a resolve is in flight
        vals = collect()
        try:
            argv = _launcher_argv(vals)
        except ValueError as e:
            messagebox.showerror("Network Vitals", str(e), parent=root)
            return
        bind = (vals["bind"] or "").strip()
        if bind and bind != "0.0.0.0":
            # A bind typo would otherwise kill the app AFTER this window
            # closes - invisibly when started from a pythonw shortcut - and
            # be restored from the saved settings on the next launch too.
            try:
                probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    probe.bind((bind, 0))
                finally:
                    probe.close()
            except OSError as e:
                messagebox.showerror(
                    "Network Vitals",
                    f"Can't bind '{bind}': {e}\n\nUse one of this machine's "
                    f"addresses, or leave 0.0.0.0 for all interfaces.",
                    parent=root)
                return
        peer = vals["peer"].split(",")[0].strip()  # mesh: check the first
        try:
            socket.inet_aton(peer)      # numeric IPv4: no lookup needed
        except OSError:
            # Host name: resolve on a worker thread so a slow DNS server
            # can't freeze the window; the button says what's happening.
            start_btn.configure(state="disabled", text="Resolving ...")
            res = {}

            def resolver():
                try:
                    socket.getaddrinfo(peer, None, socket.AF_INET)
                    res["ok"] = True
                except OSError:
                    res["ok"] = False

            threading.Thread(target=resolver, daemon=True).start()

            def wait_resolve():
                if "ok" not in res:
                    root.after(100, wait_resolve)
                    return
                start_btn.configure(state="normal", text="▶  Start")
                if not res["ok"]:
                    messagebox.showerror(
                        "Network Vitals",
                        f"Peer '{peer}' is not a valid IPv4 address or a "
                        f"resolvable host name.", parent=root)
                    return
                _finish_start(vals, argv)

            wait_resolve()
            return
        _finish_start(vals, argv)

    def _tool_target(what):
        """Common peer/ports validation for the one-shot tools."""
        vals = collect()
        peer = vals["peer"].split(",")[0].strip()  # tools target one peer
        if not peer:
            messagebox.showerror("Network Vitals",
                                 f"Peer IP is required for a {what}.",
                                 parent=root)
            return None
        try:
            ports = (_port_pair(vals["udp_ports"])
                     if vals["udp_ports"].strip() else DEFAULT_UDP_PORTS)
        except argparse.ArgumentTypeError as e:
            messagebox.showerror("Network Vitals", f"UDP ports: {e}",
                                 parent=root)
            return None
        return peer, vals["bind"].strip() or "0.0.0.0", ports

    def do_sweep():
        target = _tool_target("MTU sweep")
        if target is None:
            return
        peer, bind, ports = target
        ns = argparse.Namespace(peer=peer, bind=bind, udp_ports=ports,
                                sweep_min=1400, sweep_max=9000)
        _open_tool_window(root, f"MTU sweep -> {peer}",
                          lambda out: run_mtu_sweep(ns, out=out), "mtu-sweep")

    def do_burst():
        target = _tool_target("burst test")
        if target is None:
            return
        peer, bind, ports = target
        ns = argparse.Namespace(peer=peer, bind=bind, udp_ports=ports,
                                burst_mbps=[1, 2, 5, 10, 25], burst_secs=3.0)
        _open_tool_window(root, f"Burst test -> {peer}",
                          lambda out: run_burst_test(ns, out=out), "burst-test")

    def do_update():
        # A restart from the launcher reopens the (new) launcher; a
        # non-default update URL stays on the relaunched command line.
        argv = ([] if update_url == UPDATE_URL
                else ["--update-url", update_url])
        open_update_dialog(root, update_url, relaunch_argv=argv)

    mkbarbtn("⟳  Check for updates", do_update).pack(side="left")
    start_btn = mkbarbtn("▶  Start", do_start, primary=True)
    start_btn.pack(side="right")
    mkbarbtn("MTU sweep", do_sweep).pack(side="right", padx=(0, 8))
    mkbarbtn("Burst test", do_burst).pack(side="right", padx=(0, 8))

    peer_box.focus_set()
    root.bind("<Return>", lambda _e: do_start())
    root.mainloop()
    return result["argv"]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def _peer_list(text):
    """Parse 'A,B,C' into a list of peer address strings."""
    peers = [p.strip() for p in text.split(",") if p.strip()]
    if not peers:
        raise argparse.ArgumentTypeError(
            "expected a comma-separated list of peer addresses")
    if len(set(peers)) != len(peers):
        raise argparse.ArgumentTypeError("duplicate peer in --peers")
    return peers


def _mbps_list(text):
    """Parse '1,5,25' into a list of per-stage Mbps floats."""
    try:
        vals = [float(x) for x in text.split(",") if x.strip()]
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid Mbps list: {text!r}")
    if not vals or any(v <= 0 or v > 500 for v in vals):
        raise argparse.ArgumentTypeError(
            "expected comma-separated Mbps values in (0, 500]")
    return vals


def _port_pair(text):
    """Parse 'A,B' into a (A, B) tuple of two valid ports."""
    parts = [p.strip() for p in text.split(",") if p.strip()]
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("expected exactly two ports, e.g. 30201,30202")
    try:
        ports = tuple(int(p) for p in parts)
    except ValueError:
        raise argparse.ArgumentTypeError("ports must be integers")
    for p in ports:
        if not (1 <= p <= 65535):
            raise argparse.ArgumentTypeError(f"port {p} out of range 1-65535")
    return ports


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Bidirectional UDP/TCP network quality probe between two workstations.")
    p.add_argument("--version", action="version",
                   version=f"Network Vitals {__version__}")
    p.add_argument("--update", action="store_true",
                   help="Fetch the latest version from the update URL, install "
                        "it in place, and exit.")
    p.add_argument("--check-update", action="store_true",
                   help="Report whether a newer version is available, then exit "
                        "(exit code 3 = update available).")
    p.add_argument("--update-url", default=UPDATE_URL,
                   help="Where --update/--check-update download from "
                        "(default: the netvitals GitHub repo).")
    p.add_argument("--peer", default=None,
                   help="IP address of the other workstation.")
    p.add_argument("--peers", type=_peer_list, default=None, metavar="A,B,...",
                   help="Comma-separated peer addresses for a MESH run: this "
                        "node probes every listed peer at once and the GUI "
                        "shows a row per pair. Every node runs with its own "
                        "list of the other nodes. Mutually exclusive with "
                        "--peer; not yet supported with --vxlan.")
    p.add_argument("--tcp-pps", type=int, default=None, metavar="N",
                   help="TCP probes per second per stream (default: same as "
                        "--pps). The UDP default of 50 pps deliberately "
                        "matches G.711 voice cadence (20 ms packetization); "
                        "TCP models an interactive app, so tune it "
                        "independently if desired.")
    p.add_argument("--bind", default="0.0.0.0",
                   help="Local address to bind/listen on (default: all interfaces).")
    p.add_argument("--udp-ports", type=_port_pair, default=DEFAULT_UDP_PORTS,
                   metavar="A,B",
                   help="The two UDP ports (default %d,%d)." % DEFAULT_UDP_PORTS)
    p.add_argument("--tcp-ports", type=_port_pair, default=DEFAULT_TCP_PORTS,
                   metavar="A,B",
                   help="The two TCP ports (default %d,%d)." % DEFAULT_TCP_PORTS)
    p.add_argument("--pps", type=int, default=50,
                   help="Probe packets per second, per stream (default 50).")
    p.add_argument("--size", type=int, default=200,
                   help="Probe packet size in bytes (default 200, min %d, max %d; "
                        "e.g. 8972 to fill a 9000-byte jumbo frame)."
                        % (HEADER_LEN, MAX_SIZE))
    p.add_argument("--dont-fragment", action="store_true",
                   help="Set the IPv4 Don't-Fragment bit on UDP so oversized probes "
                        "are dropped, not fragmented (required to truly test jumbo). "
                        "With --vxlan it applies to the OUTER packet, so encap "
                        "overflow drops instead of fragmenting.")
    p.add_argument("--vxlan", action="store_true",
                   help="Carry ALL probe traffic (UDP and TCP streams) inside "
                        "VXLAN encapsulation between the two hosts. The app is "
                        "its own userspace VTEP - no drivers or admin rights. "
                        "Both ends must run --vxlan (same VNI and port).")
    p.add_argument("--vxlan-vni", type=int, default=VXLAN_DEFAULT_VNI, metavar="N",
                   help="VXLAN Network Identifier, 0-16777215 (default %d). "
                        "Must match on both ends." % VXLAN_DEFAULT_VNI)
    p.add_argument("--vxlan-port", type=int, default=VXLAN_DEFAULT_PORT, metavar="P",
                   help="Outer UDP port for the VXLAN tunnel (default %d, the "
                        "IANA VXLAN port). Must match on both ends."
                        % VXLAN_DEFAULT_PORT)
    p.add_argument("--window", type=float, default=10.0,
                   help="Sliding window in seconds for loss/jitter/rates (default 10).")
    p.add_argument("--timeout", type=float, default=2.0,
                   help="Seconds before an un-echoed probe counts as lost (default 2).")
    p.add_argument("--loss-deadband", type=float, default=0.5,
                   help="Combined loss+late below this %% reads as 0 (default 0.5; 0 disables).")
    p.add_argument("--history", type=int, default=300,
                   help="Seconds of history shown in the charts (default 300).")
    p.add_argument("--refresh-ms", type=int, default=500,
                   help="UI refresh interval in ms (default 500).")
    p.add_argument("--no-gui", action="store_true",
                   help="Force the console UI even if a display is available.")
    p.add_argument("--no-launcher", action="store_true",
                   help="With no --peer, print an error instead of opening the "
                        "graphical launch window (for scripts).")
    p.add_argument("--mtu-sweep", action="store_true",
                   help="One-shot: binary-search the largest UDP payload that reaches "
                        "the peer unfragmented (peer must be running Network Vitals), "
                        "then exit. Honours --dont-fragment (implied on).")
    p.add_argument("--sweep-min", type=int, default=1400,
                   help="MTU sweep lower bound, UDP payload bytes (default 1400).")
    p.add_argument("--sweep-max", type=int, default=9000,
                   help="MTU sweep upper bound, UDP payload bytes (default 9000).")
    p.add_argument("--burst-test", action="store_true",
                   help="One-shot: staged UDP rate ramp against the peer "
                        "(responsiveness under load: bufferbloat / policer / "
                        "shaper signatures), then exit. Peer must be running "
                        "Network Vitals. Sends real traffic; echoes double it.")
    p.add_argument("--burst-mbps", type=_mbps_list, default=[1, 2, 5, 10, 25],
                   metavar="A,B,...",
                   help="Burst test stages in Mbps (default 1,2,5,10,25; "
                        "max 500 each).")
    p.add_argument("--burst-secs", type=float, default=3.0, metavar="S",
                   help="Seconds per burst stage (default 3).")
    return p.parse_args(argv)


def set_timer_resolution(period_ms):
    """Request a finer Windows scheduler tick (default ~15.6 ms -> period_ms).

    Smooth probe pacing instead of clumpy ~15 ms bursts, which is what causes
    occasional UDP receive-buffer drops on an otherwise-clean path. No-op (and
    harmless) on non-Windows platforms. Returns True if it was applied.
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        return ctypes.windll.winmm.timeBeginPeriod(int(period_ms)) == 0
    except Exception:
        return False


def clear_timer_resolution(period_ms):
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.winmm.timeEndPeriod(int(period_ms))
    except Exception:
        pass


def run_mtu_sweep(args, out=print):
    """Binary-search the largest UDP payload that reaches the peer unfragmented.

    Sends probes with DF set to the peer's UDP reflector and watches for echoes.
    Binds an ephemeral source port so it coexists with a normally-running
    instance on either end. Measures the FORWARD path MTU (this host -> peer);
    the return echo may fragment without affecting detection. `out` receives
    one line at a time (the launcher streams it into a window; the CLI prints).
    """
    peer, port = args.peer, args.udp_ports[0]
    lo = max(HEADER_LEN, min(args.sweep_min, MAX_SIZE))
    hi = max(lo, min(args.sweep_max, MAX_SIZE))
    out(f"MTU sweep -> {peer}:{port} (UDP, Don't-Fragment). "
        f"Peer must be running Network Vitals.")
    out("")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    enlarge_socket_buffers(sock)
    quench_udp_connreset(sock)  # peer down must read as 'dropped', not an error
    if not set_dont_fragment(sock):
        out("WARNING: could not set Don't-Fragment - results may reflect "
            "fragmentation, not true path MTU.")
        out("")
    try:
        sock.bind((args.bind, 0))  # ephemeral source port
    except OSError as e:
        out(f"bind failed: {e}")
        return
    sock.settimeout(0.4)
    seq = [0]

    def round_trips(size):
        """True if a probe of `size` bytes gets an echo back (4 tries)."""
        for _ in range(4):
            seq[0] += 1
            s = seq[0]
            pkt = build_packet(TYPE_TEST, 0, s, time.monotonic_ns(), size, rxsize=size)
            try:
                sock.sendto(pkt, (peer, port))
            except OSError:
                return False  # EMSGSIZE: exceeds the local NIC MTU
            deadline = time.monotonic() + 0.4
            while time.monotonic() < deadline:
                try:
                    data, _ = sock.recvfrom(MAX_SIZE)
                except socket.timeout:
                    break
                except OSError:
                    return False
                p = parse_header(data)
                if p and p[0] == TYPE_ECHO and p[2] == s:
                    return True
        return False

    if not round_trips(lo):
        out(f"  {lo} B payload did not round-trip - peer down, UDP {port} "
            f"blocked, or even the base size is being dropped.")
        sock.close()
        return
    out(f"  {lo:>5} B payload  ...  OK")
    best, blo, bhi = lo, lo + 1, hi
    while blo <= bhi:
        mid = (blo + bhi) // 2
        ok = round_trips(mid)
        out(f"  {mid:>5} B payload  ...  {'OK' if ok else 'dropped'}")
        if ok:
            best, blo = mid, mid + 1
        else:
            bhi = mid - 1
    sock.close()
    frame = best + 28  # + 20 IPv4 + 8 UDP
    out("")
    out(f"Largest UDP payload that traverses unfragmented:  {best} bytes")
    out(f"Forward path MTU (this host -> peer):            ~{frame} bytes")
    if frame >= 9000:
        out("=> Jumbo frames (>=9000) confirmed end to end.  ✓")
    elif frame > 1500:
        out(f"=> Larger-than-standard frames supported up to ~{frame} B "
            f"(but short of 9000 jumbo).")
    else:
        out("=> Standard 1500-byte MTU; no jumbo on this path.")


BURST_PROBE_SIZE = 1200   # fits one EC slice AND a standard 1500 B hop


def run_burst_test(args, out=print):
    """Responsiveness under load: staged UDP rate ramp against a running peer.

    The continuous probes measure the path at idle; this measures what LOAD
    does to it. Paced 1200 B test probes go from an ephemeral port to the
    peer's first UDP probe port, at each offered rate in turn, and the RTT/
    loss response names the path's behavior:

      * RTT grows with rate while loss stays low -> deep queue (bufferbloat).
      * loss appears above some rate, RTT flat   -> policer (hard rate cap).
      * RTT grows first, then loss               -> shaper (queue, then drop).

    Echoes are full-size, so the offered load is symmetric: both directions
    carry it at once and the figures are per direction. TEST-type probes are
    excluded from the peer's loss-isolation bookkeeping, so this can run
    beside a live session without skewing its numbers.
    """
    peer, port = args.peer, args.udp_ports[0]
    size = BURST_PROBE_SIZE
    stages = args.burst_mbps
    dur = args.burst_secs
    out(f"Burst test -> {peer}:{port} (UDP, {size} B probes). "
        f"Peer must be running Network Vitals.")
    out(f"Stages: {', '.join(f'{m:g}' for m in stages)} Mbps, {dur:g} s each. "
        f"This is real traffic, and echoes double it.")
    out("")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    enlarge_socket_buffers(sock)
    quench_udp_connreset(sock)
    try:
        sock.bind((args.bind, 0))  # ephemeral source port
    except OSError as e:
        out(f"bind failed: {e}")
        return
    sock.setblocking(False)
    seq = [0]

    def run_stage(pps, seconds):
        """Send paced probes for `seconds`; return (sent, rtts_ms)."""
        pending = {}
        rtts = []

        def drain():
            while True:
                try:
                    data, _addr = sock.recvfrom(MAX_SIZE)
                except (BlockingIOError, InterruptedError):
                    return
                except (ConnectionResetError, OSError):
                    return
                p = parse_header(data)
                if p and p[0] == TYPE_ECHO:
                    ns = pending.pop(p[2], None)
                    if ns is not None:
                        rtts.append((time.monotonic_ns() - ns) / 1e6)

        sent = 0
        # Accumulator pacing in ~2 ms ticks: sleep-per-packet can't pace
        # thousands of pps under Windows timer granularity, batches can.
        t_end = time.monotonic() + seconds
        last = time.monotonic()
        carry = 0.0
        while True:
            now = time.monotonic()
            if now >= t_end:
                break
            carry += (now - last) * pps
            last = now
            for _ in range(min(int(carry), 500)):
                seq[0] += 1
                ns = time.monotonic_ns()
                pkt = build_packet(TYPE_TEST, 0, seq[0], ns, size)
                pending[seq[0]] = ns  # register first: echoes race the GIL
                try:
                    sock.sendto(pkt, (peer, port))
                except (BlockingIOError, OSError):
                    pending.pop(seq[0], None)
                    carry = min(carry, 1.0)  # local backpressure: don't pile up
                    break
                sent += 1
                carry -= 1.0
            drain()
            time.sleep(0.002)
        t_drain = time.monotonic() + 0.6  # let stragglers arrive
        while time.monotonic() < t_drain:
            drain()
            time.sleep(0.005)
        return sent, rtts

    def pctl(sorted_vals, q):
        return sorted_vals[int(q * (len(sorted_vals) - 1))]

    # Baseline: the idle path, so stage RTTs have something to move against.
    base_sent, base_rtts = run_stage(20, 1.5)
    if len(base_rtts) < 10:
        out(f"  baseline got {len(base_rtts)}/{base_sent} echoes - peer down, "
            f"UDP {port} blocked, or both ends aren't on this version.")
        sock.close()
        return
    base_rtts.sort()
    base_med, base_p95 = pctl(base_rtts, 0.5), pctl(base_rtts, 0.95)
    out(f"  baseline (idle): RTT median {base_med:.1f} ms  p95 {base_p95:.1f} ms")
    out("")

    results = []
    for mbps in stages:
        pps = max(20, int(mbps * 1e6 / 8 / size))
        sent, rtts = run_stage(pps, dur)
        if not sent:
            out(f"  {mbps:6g} Mbps: could not send (local socket error)")
            continue
        loss = (sent - len(rtts)) / sent * 100.0
        offered = sent * size * 8 / dur / 1e6
        if rtts:
            rtts.sort()
            med, p95 = pctl(rtts, 0.5), pctl(rtts, 0.95)
            out(f"  {mbps:6g} Mbps offered ({offered:5.1f} achieved, {pps} pps): "
                f"loss {loss:5.1f}%   RTT med {med:6.1f} ms  p95 {p95:6.1f} ms")
        else:
            med = p95 = None
            out(f"  {mbps:6g} Mbps offered ({offered:5.1f} achieved, {pps} pps): "
                f"loss 100.0%   no echoes")
        results.append((mbps, loss, med, p95))
    sock.close()
    out("")

    # Verdicts. Thresholds are deliberately blunt: this names the SHAPE of
    # the response, the table above carries the exact numbers.
    clean = [m for m, loss, med, p95 in results
             if loss < 1.0 and p95 is not None and p95 < base_p95 + 30.0]
    bloated = [(m, p95) for m, loss, med, p95 in results
               if loss < 2.0 and p95 is not None and p95 > base_p95 + 100.0]
    capped = [(m, loss, med) for m, loss, med, p95 in results
              if loss >= 5.0 and med is not None]
    if clean:
        out(f"=> Clean up to {max(clean):g} Mbps offered "
            f"(loss <1%, p95 RTT within +30 ms of idle).")
    if bloated:
        m, p95 = bloated[0]
        out(f"=> Deep queue (bufferbloat-like): at {m:g} Mbps p95 RTT hit "
            f"{p95:.0f} ms (idle {base_p95:.1f} ms) before any real loss.")
    if capped:
        m, loss, med = capped[0]
        if med < base_med + 20.0:
            out(f"=> Policer-like: {loss:.0f}% loss at {m:g} Mbps with RTT "
                f"still flat ({med:.1f} ms) - a hard rate cap that drops, "
                f"not queues.")
        else:
            out(f"=> Shaper-like: {loss:.0f}% loss at {m:g} Mbps after RTT "
                f"grew to {med:.0f} ms - a queue that fills, then drops.")
    if not (clean or bloated or capped):
        out("=> No stage ran clean and none showed a clear queue/cap "
            "signature - see the table.")


def _normalize_peer_args(args):
    """Reconcile --peer/--peers so args.peer is always the first peer (every
    single-peer code path - footer, sweep/burst targets - keys off it).
    A comma list typed as --peer upgrades to a mesh instead of resolving as
    a bogus hostname. Returns False (after printing/alerting) on bad input.
    Must run again on args re-parsed from the launcher's argv."""
    if args.peer and "," in args.peer and not args.peers:
        try:
            args.peers = _peer_list(args.peer)
        except argparse.ArgumentTypeError as e:
            msg = f"--peer: {e}"
            print(f"error: {msg}", file=sys.stderr)
            _alert_gui_error(msg)
            return False
        args.peer = None
    if args.peers:
        if args.peer:
            msg = "use either --peer or --peers, not both"
            print(f"error: {msg}", file=sys.stderr)
            _alert_gui_error(msg)
            return False
        args.peer = args.peers[0]
    return True


def main(argv=None):
    cli_argv = list(argv) if argv is not None else sys.argv[1:]
    args = parse_args(cli_argv)
    args._argv = cli_argv  # what a post-update restart should re-run with

    if args.update or args.check_update:
        return perform_update(args.update_url, apply=args.update)

    if not _normalize_peer_args(args):
        return 2

    if not args.peer:
        # No peer given: open the graphical launcher (the double-click
        # experience) unless it's explicitly disabled or plainly can't work.
        if not (args.no_launcher or args.no_gui or args.mtu_sweep
                or args.burst_test):
            try:
                chosen = run_launcher(args.update_url)
            except (ImportError, RuntimeError) as e:
                print(f"note: graphical launcher unavailable ({e})",
                      file=sys.stderr)
            else:
                if chosen is None:
                    return 0  # launcher closed without starting a run
                if args.update_url != UPDATE_URL:
                    # keep a custom update source across the launcher hop
                    chosen = chosen + ["--update-url", args.update_url]
                args = parse_args(chosen)
                args._argv = chosen
                # The launcher's argv may carry --peers: normalize the fresh
                # args too. (1.6.0/1.6.1 skipped this, so starting a MESH
                # from the launcher died on "--peer is required" - written
                # to stderr, which a pythonw shortcut makes invisible.)
                if not _normalize_peer_args(args):
                    return 2
        if not args.peer:
            msg = ("--peer is required (except with --update/--check-update)")
            print(f"error: {msg}", file=sys.stderr)
            _alert_gui_error(msg)  # pythonw shortcut: stderr is invisible
            return 2

    args.size = max(HEADER_LEN, min(args.size, MAX_SIZE))
    if args.pps < 1:
        args.pps = 1
    if args.tcp_pps is not None and args.tcp_pps < 1:
        args.tcp_pps = 1

    vxlan = None
    if args.vxlan:
        if not (0 <= args.vxlan_vni <= 0xFFFFFF):
            print("error: --vxlan-vni must be 0..16777215", file=sys.stderr)
            return 2
        if not (1 <= args.vxlan_port <= 65535):
            print("error: --vxlan-port out of range 1-65535", file=sys.stderr)
            return 2
        if args.size > VXLAN_MAX_PROBE:
            print(f"note: --size capped to {VXLAN_MAX_PROBE} in VXLAN mode "
                  f"(encap headers must fit in the outer datagram).",
                  file=sys.stderr)
            args.size = VXLAN_MAX_PROBE
        if args.peers and len(args.peers) > 1:
            print("error: --vxlan with multiple --peers is not supported yet "
                  "(roadmap: static-FIB VXLAN mesh).", file=sys.stderr)
            return 2
        vxlan = {"vni": args.vxlan_vni, "port": args.vxlan_port}

    # Apply chosen ports (read as a module global by the engine and UI).
    global STREAMS
    STREAMS = build_streams(args.udp_ports, args.tcp_ports)

    if args.mtu_sweep:
        run_mtu_sweep(args)
        return

    if args.burst_test:
        run_burst_test(args)
        return

    set_timer_resolution(1)  # smooth pacing on Windows -> fewer microburst drops
    # Binding can transiently fail right after an in-app update restart (the
    # replaced instance is still letting go of the ports), so retry briefly
    # before declaring a real conflict - and declare it VISIBLY: under a
    # pythonw shortcut a raised traceback would vanish without a trace.
    engine = None
    last_err = None
    for attempt in range(4):
        engine = Engine(args.peer, args.bind, args.size, args.pps, args.window,
                        args.timeout, history_seconds=args.history,
                        loss_deadband=args.loss_deadband,
                        dont_fragment=args.dont_fragment, vxlan=vxlan,
                        peers=args.peers, tcp_pps=args.tcp_pps)
        try:
            engine.start()
            last_err = None
            break
        except OSError as e:
            last_err = e
            engine.shutdown()
            if attempt < 3:
                time.sleep(1.2)  # let the previous instance's sockets close
    if last_err is not None:
        if vxlan:
            msg = (f"Cannot bind the VXLAN tunnel on "
                   f"{args.bind}:{vxlan['port']}/udp ({last_err}). Another "
                   f"VTEP or instance on this port? Change it with "
                   f"--vxlan-port (on BOTH ends).")
        else:
            msg = (f"Cannot bind the probe ports on {args.bind} "
                   f"({last_err}). Is another Network Vitals instance "
                   f"already running on this machine?")
        print(f"error: {msg}", file=sys.stderr)
        _alert_gui_error(msg)
        return 2

    use_gui = not args.no_gui
    if use_gui:
        try:
            import tkinter  # noqa: F401
        except Exception:
            use_gui = False
            print("Tkinter not available - falling back to console UI.", file=sys.stderr)

    mesh = len(engine.peers) > 1
    gui_fn = run_mesh_gui if mesh else run_gui
    con_fn = run_console_mesh if mesh else run_console
    try:
        if use_gui:
            try:
                gui_fn(engine, args)
            except Exception as e:  # e.g. no display on a headless host
                print(f"GUI unavailable ({e}) - falling back to console UI.", file=sys.stderr)
                con_fn(engine, args)
        else:
            con_fn(engine, args)
    finally:
        engine.shutdown()
        clear_timer_resolution(1)


if __name__ == "__main__":
    sys.exit(main())
