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
import base64
import functools
import hashlib
import hmac
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

__version__ = "2.1.1"

# Where --update / --check-update look for the latest SIGNED release manifest. The
# manifest is verified against UPDATE_PUBKEY before anything is installed (fail closed),
# so the update channel is not a code-execution hole: a foreign URL cannot serve accepted
# code without the matching private key. A fork sets its own manifest URL + public key.
# Override with --update-url. See the self-update section below and UPDATE_SECURITY.md.
UPDATE_URL = "https://github.com/robertsonc/netvitals/releases/latest/download/manifest.json"

# Release manifests are signed offline; this app ships only the PUBLIC key and refuses any
# update whose manifest signature does not verify against it (fail closed). The private key
# is never shipped. A fork must replace this with its own key (openssl rsa -pubout) and
# repoint UPDATE_URL; until it does, updates fail closed - the safe state.
#
# Clients trust exactly the key compiled into the build they are running, so rotating this
# value requires shipping the change in a release signed with the PREVIOUS key. See the key
# management section of docs/UPDATE_SECURITY.md before touching it.
UPDATE_PUBKEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApRakvIgSthqF9tTb3Q1B
avHYJeuvH4McX59x7L4toEOm2hArGbXRnphH8LdpmTPFYEn7wpt20/KlCzyZQXuH
18hwFPsEWrPrPJ2a5O67kRd+c6jrGb/g6QaRCZBwAhxAZwuOa3qji/yslLXYgSdV
TQ+KMJuI24j5+lrpMwzpYjQ0iFDaoqA3UROEIav1rG7ntEns+dDieCwEXpnKeRfN
46TUrqLMdh7vz1E7MKsveXqNEZj0R0iKIdoFEWiVuey6eo7ryYfdEl1gmJKgtWYd
5xn1j+354QHobB6JzUj1ZQcj020g/qagGry/zPRLkTwChKUPC++3MahLiDpKoIbW
rQIDAQAB
-----END PUBLIC KEY-----
"""

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

# On-wire IPv4 header cost per probe, used wherever a rate in Mbps is
# converted to/from a rate in packets (--mbps, the offered-load readout).
# Ethernet framing is deliberately excluded: it varies by media (VLAN tags,
# FCS) while the IP-level figure is what shapers/policers meter.
IPV4_UDP_OVERHEAD = 28   # IPv4 20 + UDP 8
IPV4_TCP_OVERHEAD = 40   # IPv4 20 + TCP 20


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
# DSCP / ToS marking (R-6, 1.8.0): per-stream traffic classes
# ---------------------------------------------------------------------------
DSCP_NAMES = {
    "be": 0, "cs0": 0, "df": 0,
    "cs1": 8, "af11": 10, "af12": 12, "af13": 14,
    "cs2": 16, "af21": 18, "af22": 20, "af23": 22,
    "cs3": 24, "af31": 26, "af32": 28, "af33": 30,
    "cs4": 32, "af41": 34, "af42": 36, "af43": 38,
    "cs5": 40, "va": 44, "ef": 46, "cs6": 48, "cs7": 56,
}


def dscp_name(dscp):
    """Preferred display name for a DSCP value ('EF', 'AF41', '17', '-')."""
    if dscp is None:
        return "-"
    for name, v in DSCP_NAMES.items():
        if v == dscp and name not in ("cs0", "df"):
            return name.upper()
    return str(dscp)


def qwave_traffic_type(dscp):
    """Windows non-admin DSCP: qWAVE offers traffic TYPES, not code points,
    and the stack picks the DSCP per type (exact values need admin via
    QOSSetOutgoingDSCPValue). Map a requested DSCP to the nearest type and
    return (traffic_type, dscp_the_stack_applies) so the UI can report the
    wire truth instead of pretending the request was honored."""
    if dscp <= 0:
        return 0, 0      # BestEffort -> 0
    if dscp <= 8:
        return 1, 8      # Background -> CS1
    if dscp <= 31:
        return 2, 28     # ExcellentEffort -> AF32
    if dscp <= 40:
        return 3, 40     # AudioVideo -> CS5
    return 4, 56         # Voice -> CS7 (46/EF and up)


def _qwave_mark(sock, dscp, peer, port):
    """Add the socket to a qWAVE flow (Windows). Returns 'qwave:NN' with the
    DSCP the stack applies, or 'failed'. Never raises."""
    try:
        import ctypes
        from ctypes import wintypes

        class QOS_VERSION(ctypes.Structure):
            _fields_ = [("MajorVersion", wintypes.USHORT),
                        ("MinorVersion", wintypes.USHORT)]

        class SOCKADDR_IN(ctypes.Structure):
            _fields_ = [("sin_family", ctypes.c_short),
                        ("sin_port", ctypes.c_ushort),
                        ("sin_addr", ctypes.c_ubyte * 4),
                        ("sin_zero", ctypes.c_char * 8)]

        qwave = ctypes.windll.qwave
        handle = wintypes.HANDLE()
        if not qwave.QOSCreateHandle(ctypes.byref(QOS_VERSION(1, 0)),
                                     ctypes.byref(handle)):
            return "failed"
        ttype, applied = qwave_traffic_type(dscp)
        ip = socket.inet_aton(resolve_peer_ip(peer) or "0.0.0.0")
        dest = SOCKADDR_IN(socket.AF_INET, socket.htons(port),
                           (ctypes.c_ubyte * 4).from_buffer_copy(ip), b"")
        flow_id = wintypes.DWORD(0)
        QOS_NON_ADAPTIVE_FLOW = 2
        ok = qwave.QOSAddSocketToFlow(handle, sock.fileno(),
                                      ctypes.byref(dest), ttype,
                                      QOS_NON_ADAPTIVE_FLOW,
                                      ctypes.byref(flow_id))
        return f"qwave:{applied}" if ok else "failed"
    except Exception:
        return "failed"


def set_dscp(sock, dscp, peer=None, port=0):
    """Best-effort per-socket DSCP marking. Returns a status string:

      None        - no marking requested
      'os'        - IP_TOS accepted (POSIX: the kernel marks every packet
                    with exactly the requested code point)
      'qwave:NN'  - Windows qWAVE flow added; NN is the code point the
                    stack actually applies for the mapped traffic type
      'failed'    - nothing stuck; packets leave unmarked

    Windows silently ignores plain IP_TOS on ordinary sockets, hence the
    qWAVE path - the README roadmap's long-standing caveat, implemented."""
    if dscp is None:
        return None
    if sys.platform != "win32":
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, dscp << 2)
            return "os"
        except OSError:
            return "failed"
    return _qwave_mark(sock, dscp, peer, port)


def enable_tos_readback(sock):
    """Ask the OS to deliver each received datagram's TOS byte (IP_RECVTOS)
    so recvmsg() can report it - the DSCP-bleaching detector's input. POSIX
    only: Windows exposes neither IP_RECVTOS nor socket.recvmsg, so a
    Windows reflector reports nothing (shown as '?' on the other end)."""
    if not (hasattr(socket, "IP_RECVTOS") and hasattr(sock, "recvmsg")):
        return False
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
        return True
    except OSError:
        return False


def tos_from_ancdata(ancdata):
    """Extract the received TOS byte from recvmsg() ancillary data (Linux
    delivers cmsg IP_TOS, macOS IP_RECVTOS)."""
    for level, ctype, data in ancdata or ():
        if level == socket.IPPROTO_IP and data and ctype in (
                getattr(socket, "IP_TOS", -1),
                getattr(socket, "IP_RECVTOS", -1)):
            return data[0]
    return None


# The reflector reports the TOS byte it observed on the arriving probe by
# stamping two bytes of the echo's zero padding: a marker + the raw TOS.
# Wire-compatible with pre-1.8 peers, which leave the padding zeroed (reads
# as "no report"); needs >= 2 bytes of padding, so size-34 probes carry none.
TOS_REPORT_MAGIC = 0xD5


def stamp_tos_report(echo, tos):
    """Write the received-TOS report into an echo's padding bytes."""
    if tos is None or len(echo) < HEADER_LEN + 2:
        return echo
    b = bytearray(echo)
    b[HEADER_LEN] = TOS_REPORT_MAGIC
    b[HEADER_LEN + 1] = tos & 0xFF
    return bytes(b)


def parse_tos_report(payload):
    """Read a stamp_tos_report() report back out of an echo, or None when
    the peer didn't report (old version, minimal size, or no TOS seen)."""
    if (len(payload) >= HEADER_LEN + 2
            and payload[HEADER_LEN] == TOS_REPORT_MAGIC):
        return payload[HEADER_LEN + 1]
    return None


# ---------------------------------------------------------------------------
# ICMP error visibility without raw sockets (R-13, 2.0.0)
# ---------------------------------------------------------------------------
def enable_icmp_err(sock):
    """Linux: deliver ICMP errors for this socket's traffic on the error
    queue (IP_RECVERR) - lets the MTU sweep distinguish 'ICMP frag-needed
    (next-hop MTU=N) received' from a silent drop (PMTUD black hole), with
    no raw socket and no root. Unavailable elsewhere; returns True when on."""
    if not (hasattr(socket, "IP_RECVERR") and hasattr(sock, "recvmsg")):
        return False
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVERR, 1)
        return True
    except OSError:
        return False


def parse_icmp_err(ancdata):
    """Extract (icmp_type, icmp_code, info) from a MSG_ERRQUEUE ancillary
    message (struct sock_extended_err). info carries the next-hop MTU for
    type 3 / code 4. None when the cmsg isn't an ICMP-origin error."""
    ip_recverr = getattr(socket, "IP_RECVERR", 11)
    for level, ctype, data in ancdata or ():
        if level == socket.IPPROTO_IP and ctype == ip_recverr \
                and len(data) >= 12:
            _errno, origin, typ, code, _pad, info = struct.unpack_from(
                "=IBBBBI", data, 0)
            if origin == 2:            # SO_EE_ORIGIN_ICMP
                return typ, code, info
    return None


def parse_ipv4_fragment(pkt, l2_offset=0):
    """Classify one captured IPv4 packet for the fragment sniffer.

    Returns (is_fragment, is_first_fragment, proto_num, src_ip, dst_ip) or
    None when the bytes aren't parseable IPv4. A fragment has MF set or a
    non-zero offset; only the FIRST fragment (offset 0) carries the L4
    header."""
    i = l2_offset
    if len(pkt) < i + 20 or pkt[i] >> 4 != 4:
        return None
    flags_frag = int.from_bytes(pkt[i + 6:i + 8], "big")
    mf = bool(flags_frag & 0x2000)
    offset = flags_frag & 0x1FFF
    is_frag = mf or offset > 0
    src = socket.inet_ntoa(pkt[i + 12:i + 16])
    dst = socket.inet_ntoa(pkt[i + 16:i + 20])
    return is_frag, offset == 0, pkt[i + 9], src, dst


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

        # DSCP readback (1.8.0): the TOS byte the peer reported seeing on
        # our probes (forward path) and the TOS observed locally on the
        # peer's echoes (return path). None = not (yet) reported.
        self.fwd_tos = None
        self.rtn_tos = None

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
                peer_fwd=0, peer_ns=0, peer_tos=None, rx_tos=None):
        with self.lock:
            rtt = (now_ns - ts_ns) / 1e6
            if rtt < 0:
                rtt = 0.0
            now_w = time.monotonic()
            if peer_tos is not None:
                self.fwd_tos = peer_tos
            if rx_tos is not None:
                self.rtn_tos = rx_tos
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
                "fwd_tos": self.fwd_tos,
                "rtn_tos": self.rtn_tos,
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
            self.fwd_tos = None
            self.rtn_tos = None
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
    """Band colour for a 0-100 quality score, matching score_label()'s bands.

    Tuned for the dark glass theme: saturated enough to carry a glow, light
    enough to stay legible as text on a translucent surface."""
    if r >= 80:
        return "#20D9A2"    # excellent - mint
    if r >= 70:
        return "#8CD94E"    # good - lime
    if r >= 60:
        return "#FFC24B"    # fair - amber
    if r >= 50:
        return "#FF9245"    # poor - orange
    return "#FF5C6C"        # bad - red


# ---------------------------------------------------------------------------
# UDP stream: one bound socket per port, both originates and reflects.
# ---------------------------------------------------------------------------
class UDPStream:
    """One UDP port serving every configured peer: probes fan out to each
    peer on its own sequence/stats, and inbound packets demux by source
    address. A single peer is just the one-element case."""

    def __init__(self, cfg, peers, bind, sizes, interval, stats_of, stop,
                 dont_fragment=False, dscp=None):
        self.sid, _, self.port, self.name = cfg
        self.peers = list(peers)
        self.bind = bind
        # Probe size pattern: one entry = fixed size (the classic case),
        # several = cycled probe-by-probe (IMIX-style profiles, 1.8.0).
        self.sizes = tuple(sizes)
        self.interval = interval
        self.stats_of = stats_of   # {peer: StreamStats}
        self.stop = stop
        self.dont_fragment = dont_fragment
        self.dscp = dscp
        self.mark_status = None
        self.tos_readback = False
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
        # One socket per stream, so a per-socket mark IS a per-stream class;
        # echoes ride the same socket and carry the same code point.
        self.mark_status = set_dscp(s, self.dscp, peer=self.peers[0],
                                    port=self.port)
        # Deliver each datagram's TOS byte when the OS can: feeds both the
        # peer's forward-path report (we reflect what we saw) and our own
        # return-path observation - the DSCP bleaching detector.
        self.tos_readback = enable_tos_readback(s)
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
                size = self.sizes[(seqs[p] - 1) % len(self.sizes)]
                pkt = build_packet(TYPE_PROBE, self.sid, seqs[p], ns, size)
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
            tos = None
            try:
                if self.tos_readback:
                    data, ancdata, _flags, addr = self.sock.recvmsg(65535, 256)
                    tos = tos_from_ancdata(ancdata)
                else:
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
                # direction, plus our clock for one-way-delay drift (and the
                # TOS byte we observed, for the DSCP bleaching detector). TEST
                # probes (MTU sweep / burst test side-channels) are echoed but
                # kept out of the gap tracking.
                rxlen = len(data)
                fwd = stats.on_probe_rx(seq) if ptype == TYPE_PROBE else 0
                echo = build_packet(TYPE_ECHO, sid, seq, ts_ns, rxlen,
                                    rxsize=rxlen, rxcount=fwd,
                                    peer_ns=time.monotonic_ns())
                echo = stamp_tos_report(echo, tos)
                try:
                    self.sock.sendto(echo, addr)
                except OSError:
                    pass
            elif ptype == TYPE_ECHO:
                stats.on_echo(seq, ts_ns, time.monotonic_ns(),
                              rx_len=len(data), psize=psize, peer_rx=rxsize,
                              peer_fwd=rxcount, peer_ns=peer_ns,
                              peer_tos=parse_tos_report(data), rx_tos=tos)


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

    def __init__(self, cfg, peers, bind, sizes, interval, stats_of, stop,
                 dscp=None):
        self.sid, _, self.port, self.name = cfg
        self.peers = list(peers)
        self.bind = bind
        self.sizes = tuple(max(s, HEADER_LEN) for s in sizes)
        self.dscp = dscp
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
        # Echoes carry this stream's class too, so the RETURN path of the
        # peer's probes is policy-matched the same way (symmetric config).
        set_dscp(conn, self.dscp, peer=peer, port=self.port)
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
            set_dscp(cs, self.dscp, peer=peer, port=self.port)
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
            size = self.sizes[(seq - 1) % len(self.sizes)]
            pkt = build_packet(TYPE_PROBE, self.sid, seq, ns, size)
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
        """Route decapsulated payloads for (proto, inner dst port) to
        handler(payload, inner_tos)."""
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
    def send(self, proto, port, payload, tos=0):
        """Encapsulate one probe/echo message and send it to the peer's VXLAN
        port. `tos` marks the INNER IPv4 header (per-stream DSCP inside the
        tunnel; the shared outer socket stays unmarked). Returns True if the
        datagram left the socket."""
        try:
            self.sock.sendto(self._encap(proto, port, payload, tos),
                             (self.peer, self.port))
            return True
        except OSError:
            return False

    @staticmethod
    def _l4_checksum(src, dst, proto_num, segment):
        pseudo = src + dst + struct.pack("!BBH", 0, proto_num, len(segment))
        return _inet_checksum(pseudo + segment)

    def _encap(self, proto, port, payload, tos=0):
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
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, tos & 0xFF, total, ip_id, 0, 64,
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
        tos = data[ip + 1]
        if proto_num == 17 and end >= l4 + 8:
            dport = int.from_bytes(data[l4 + 2:l4 + 4], "big")
            ulen = int.from_bytes(data[l4 + 4:l4 + 6], "big")
            return "UDP", dport, data[l4 + 8:min(end, l4 + ulen)], tos
        if proto_num == 6 and end >= l4 + 20:
            dport = int.from_bytes(data[l4 + 2:l4 + 4], "big")
            seq = int.from_bytes(data[l4 + 4:l4 + 8], "big")
            doff = (data[l4 + 12] >> 4) * 4
            payload = data[l4 + doff:end]
            with self._lock:   # our next segment ACKs what we just received
                self._tcp_ack[dport] = (seq + len(payload)) & 0xFFFFFFFF
            return "TCP", dport, payload, tos
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
            proto, port, payload, tos = decap
            handler = self.handlers.get((proto, port))
            if handler is not None:
                handler(payload, tos)


class VXStream:
    """One probe stream carried through the shared VXLAN tunnel.

    Originates probes and reflects the peer's exactly like UDPStream, but
    every message is one inner packet inside the tunnel, stamped with the
    stream's catalogue protocol (UDP or TCP) and port. Framing is packet-per-
    probe even for the TCP streams, so the probe/echo state machine (and all
    loss/size accounting) is identical across all four streams."""

    def __init__(self, cfg, tunnel, sizes, interval, stats, stop, dscp=None):
        self.sid, self.proto, self.port, self.name = cfg
        self.tunnel = tunnel
        self.sizes = tuple(sizes)
        self.interval = interval
        self.stats = stats
        self.stop = stop
        self.dscp = dscp
        self.tos = (dscp << 2) if dscp else 0  # inner IPv4 TOS for this stream
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
            size = self.sizes[(seq - 1) % len(self.sizes)]
            pkt = build_packet(TYPE_PROBE, self.sid, seq, ns, size)
            # Register BEFORE transmitting (see StreamStats.cancel_send).
            self.stats.on_send(seq, ns)
            if not self.tunnel.send(self.proto, self.port, pkt, tos=self.tos):
                self.stats.cancel_send(seq)
            self.stats.reap()
            next_t += self.interval
            delay = next_t - time.monotonic()
            if delay > 0:
                self.stop.wait(delay)
            else:
                next_t = time.monotonic()

    def _on_payload(self, payload, tos=None):
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
            # Report the inner TOS we observed (bleaching detector), and
            # mark the echo with OUR class for this stream - symmetric.
            echo = stamp_tos_report(echo, tos)
            self.tunnel.send(self.proto, self.port, echo, tos=self.tos)
        elif ptype == TYPE_ECHO:
            self.stats.on_echo(seq, ts_ns, time.monotonic_ns(),
                               rx_len=len(payload), psize=psize, peer_rx=rxsize,
                               peer_fwd=rxcount, peer_ns=peer_ns,
                               peer_tos=parse_tos_report(payload), rx_tos=tos)


# ---------------------------------------------------------------------------
# Engine: owns all streams + their stats
# ---------------------------------------------------------------------------
class Engine:
    def __init__(self, peer=None, bind="0.0.0.0", size=200, pps=50, window=10.0,
                 timeout=2.0, history_seconds=300, loss_deadband=0.5,
                 dont_fragment=False, vxlan=None, peers=None, tcp_pps=None,
                 target_mbps=None, profiles=None, dscp=None):
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
        self.target_mbps = target_mbps      # --mbps target, or None (pps mode)
        # The 50 pps / ~200 B UDP default deliberately matches a G.711 voice
        # stream (20 ms packetization); TCP models an interactive app, not
        # media, so its rate is independently tunable via --tcp-pps.
        rate_of = {"UDP": pps, "TCP": tcp_pps or pps}
        # Per-stream traffic profiles (1.8.0): one (size pattern, pps or
        # None=base rate) per sid. None -> every stream at --size/--pps,
        # exactly the pre-profile behavior.
        if profiles is None:
            profiles = [((size,), None)] * len(STREAMS)
        self.profiles = list(profiles)
        # "profiles" tag in the UI only when SIZES vary: an --mbps-derived
        # rate override alone is already reported via offered/target.
        self.profiles_active = any(s != (size,) for s, _p in self.profiles)
        # Per-stream DSCP marking (1.8.0): requested code point per sid, or
        # None = unmarked. Application is best-effort per platform.
        self.dscp = list(dscp) if dscp else [None] * len(STREAMS)
        self.expect_size = {}  # sid -> largest payload the pattern sends
        self.mean_wire = {}    # sid -> mean IP bytes/probe (offered-load math)
        self.rate_of_sid = {}  # sid -> effective probe rate (pps)
        self.slices_of_sid = {}  # sid -> predicted WAN packets per probe
        # Scenario stage markers for the charts: (t_mono, label), trimmed to
        # the chart horizon by the sampler. wan/scenario are attached by
        # main() after construction (the sim WAN source needs the engine).
        self.markers = deque()
        self.wan = None        # WanCounters or None
        self.scenario = None   # ScenarioRunner or None
        self.frag = None       # FragmentSniffer or None (2.0.0)
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
            sizes, prof_pps = self.profiles[sid]
            stream_pps = prof_pps or rate_of[proto]
            interval = 1.0 / stream_pps
            self.expect_size[sid] = max(sizes)
            self.mean_wire[sid] = mean_wire_size(sizes, proto)
            self.rate_of_sid[sid] = stream_pps
            self.slices_of_sid[sid] = len(ec_wire_view(wan_inner_bytes(
                sum(sizes) / len(sizes), proto, bool(vxlan))))
            stats_of = {}
            for p in self.peers:
                st = StreamStats(window=window, timeout=timeout,
                                 target_pps=stream_pps)
                self.stats[(p, sid)] = st
                stats_of[p] = st
            if self.tunnel is not None:
                self.streams.append(VXStream(cfg, self.tunnel, sizes, interval,
                                             stats_of[self.peer], self.stop,
                                             dscp=self.dscp[sid]))
            elif proto == "UDP":
                self.streams.append(UDPStream(cfg, self.peers, bind, sizes,
                                              interval, stats_of, self.stop,
                                              dont_fragment=dont_fragment,
                                              dscp=self.dscp[sid]))
            else:
                self.streams.append(TCPStream(cfg, self.peers, bind, sizes,
                                              interval, stats_of, self.stop,
                                              dscp=self.dscp[sid]))

    def start(self):
        if self.tunnel is not None:
            self.tunnel.start()
        for s in self.streams:
            s.start()
        threading.Thread(target=self._sampler, name="history-sampler", daemon=True).start()

    def shutdown(self):
        self.stop.set()
        if self.wan is not None:
            self.wan.stop()
        if self.scenario is not None:
            self.scenario.stop()
        if self.frag is not None:
            self.frag.stop()

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
                horizon = now - self.history_seconds - 2
                while self.markers and self.markers[0][0] < horizon:
                    self.markers.popleft()

    def add_marker(self, label):
        """Record a scenario stage boundary for the charts."""
        with self.history_lock:
            self.markers.append((time.monotonic(), label))

    def markers_copy(self):
        with self.history_lock:
            return list(self.markers)

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
        offered_bps = 0.0  # achieved probe TX rate, IP level, this direction
        for sid, proto, port, name in STREAMS:
            snap = self.stats[(peer, sid)].snapshot()
            offered_bps += snap["tx_pps"] * self.mean_wire[sid] * 8.0
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
                        score=score, mos=mos, label=label, eff_loss=eff,
                        expect_size=self.expect_size[sid],
                        dscp_req=self.dscp[sid])
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
        elif udp_rows and all(r["peer_rx_max"] >= r["expect_size"]
                              and r["rx_echo_max"] >= r["expect_size"]
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
        # FEC verdict inputs (2.0.0): windowed probe impairment across live
        # streams vs the WAN counters' drop rate.
        live = [r for r in rows if r["connected"]]
        probe_eff = (sum(r["loss"] + r["late"] for r in live) / len(live)
                     if live else 0.0)
        udp_slices = max((self.slices_of_sid[r["sid"]] for r in rows
                          if r["proto"] == "UDP"), default=1)
        wan_status = self.wan.status() if self.wan else None
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
            # Offered probe load, this pair, this direction, IP level (probe
            # + IPv4/UDP-or-TCP headers). Echoes mirror probes, so the wire
            # carries roughly double at steady state. target_mbps is the
            # --mbps ask (None in pps mode) - showing both makes the offered
            # load a verifiable known quantity, not a computed hope.
            "offered_mbps": offered_bps / 1e6,
            "target_mbps": self.target_mbps,
            "profiles_active": self.profiles_active,
            # 1.9.0: measured WAN counters, scenario progress, and the
            # no-fabric-access slicing evidence (loss-ratio law).
            "wan": wan_status,
            "scenario": self.scenario.status() if self.scenario else None,
            "slice_evidence": slice_loss_evidence(rows, self.slices_of_sid,
                                                  self.loss_deadband),
            "predicted_wan_pps": sum(
                r["tx_pps"] * self.slices_of_sid[r["sid"]] * 2
                for r in rows),
            "frags": self.frag.status() if self.frag else None,
            "fec": fec_verdict(wan_status, probe_eff, udp_slices),
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
# Design system: a "spatial" glass theme, drawn entirely on Tk Canvases
# ---------------------------------------------------------------------------
# Tk has no compositor: every widget is opaque, there is no alpha channel, no
# backdrop blur and no anti-aliasing. Glassmorphism is therefore done here the
# only way it can be - by ARITHMETIC. Each surface colour is alpha-composited
# in Python against the one backdrop it will actually sit on, so "a 12% white
# card over the base" is resolved to a literal hex string before Tk ever sees
# it. Every frame in the app shares one flat backdrop (BG), which makes that
# compositing exact rather than approximate.
#
# Depth then comes from the three things a real compositor would hand us:
#   * soft shadows   - nested rounded rects fading out into the backdrop
#   * specular edges - a 1 px light hairline along the lit (top) edge of a card
#   * ambient glow   - radial washes bled behind accents and live chart lines


# Every colour in this UI is arithmetic, and the arithmetic is deterministic:
# a gradient asks for the same ~180 blends on every repaint, a radial wash for
# the same falloff steps, the theme for the same handful of tints. Memoising
# the three primitives turns all of that into dict hits from the second call
# onward - the single cheapest win available here, and exactly output-
# identical because they are pure functions of hashable arguments.
@functools.lru_cache(maxsize=4096)
def _rgb(c):
    """'#rrggbb' -> (r, g, b)."""
    c = c.lstrip("#")
    return (int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16))


def _hexc(t):
    """(r, g, b) -> '#rrggbb', clamped to the byte range."""
    return "#%02x%02x%02x" % tuple(max(0, min(255, int(round(v)))) for v in t)


@functools.lru_cache(maxsize=8192)
def _mix(c1, c2, t):
    """Blend two colours: t=0 -> c1, t=1 -> c2."""
    a, b = _rgb(c1), _rgb(c2)
    return _hexc(tuple(a[i] + (b[i] - a[i]) * t for i in range(3)))


def _over(fg, bg, alpha):
    """Composite `fg` over opaque `bg` at `alpha`. This is the glass trick:
    the caller states an intent ("white at 8%") and gets back the flat colour
    Tk needs, already resolved against the surface underneath."""
    return _mix(bg, fg, alpha)


def _lighten(c, t):
    return _mix(c, "#ffffff", t)


def _darken(c, t):
    return _mix(c, "#000000", t)


# --- base ------------------------------------------------------------------
HPE_GREEN = "#01A982"     # HPE signature green (brand constant)
BG = "#080B12"            # deep space base - the backdrop everything sits on

GLASS = "#A9C2FF"         # cool moonlight tint every glass surface is made of
SPEC = "#FFFFFF"          # specular highlight source

# The glass elevation ladder, stated as alpha over BG rather than as picked
# hex values - the whole point is that a surface's colour is derived from how
# much light it lets through, so the numbers below are the design decisions
# and the hex strings are just what they compile to.
PANEL_TOP = _over(GLASS, BG, 0.125)  # lit top edge of a card gradient
PANEL_LO = _over(GLASS, BG, 0.045)   # shaded bottom edge of a card gradient
GRID = _over(GLASS, BG, 0.155)       # card hairline border
STROKE_HI = _over(SPEC, BG, 0.22)    # specular top hairline

TXT = "#E9EEF7"
TXT_DIM = "#8D9AB3"
TXT_FAINT = "#5B6880"

ACCENT = HPE_GREEN                   # brand green, used for chrome
ACCENT_HI = "#2BE3B0"                # brighter green for glows and lit states
ACCENT_2 = "#38BDF8"                 # cyan
ACCENT_3 = "#8B7CFF"                 # violet
WARN = "#FFC24B"
DANGER = "#FF5C6C"

RADIUS = 16               # standard card corner
RADIUS_SM = 10            # chips, buttons, inner wells

# The glass level a hosting card settles on. Widgets parked inside one (a
# Treeview, a form) can only be a single flat colour, so the card and the ttk
# theme have to agree on exactly which colour that is.
CARD_LEVEL = 0.085
CARD_SURFACE = _over(GLASS, BG, CARD_LEVEL)

# Row accents for the tables. Full-strength ACCENT_HI on every clean row turns
# a table into a wall of glowing green, so the "everything is fine" state is
# deliberately the quiet one and only the exceptions are saturated.
OK_SOFT = _mix(ACCENT_HI, TXT, 0.45)
WARN_SOFT = _mix(WARN, TXT, 0.25)

FONT = "Segoe UI"
FONT_MONO = "Consolas"

# Preferred UI faces, best first. Segoe UI Variable is the Windows 11 system
# face; the rest are the sensible fallbacks on the platforms this also runs
# on. _resolve_fonts() picks the first one actually installed.
_FONT_STACK = ("Segoe UI Variable Text", "Segoe UI", "Inter", "SF Pro Text",
               "Helvetica Neue", "DejaVu Sans")
_MONO_STACK = ("Cascadia Mono", "Consolas", "SF Mono", "JetBrains Mono",
               "DejaVu Sans Mono", "Courier New")
_fonts_resolved = [False]


def _resolve_fonts(root):
    """Point FONT/FONT_MONO at the best face this machine actually has.

    Tk silently substitutes an unknown family, which on a non-Windows box
    turns the whole UI into the default bitmap face. Asking the font engine
    once at startup keeps the type crisp everywhere the app runs."""
    if _fonts_resolved[0]:
        return
    _fonts_resolved[0] = True
    global FONT, FONT_MONO
    try:
        import tkinter.font as tkfont
        have = {f.lower() for f in tkfont.families(root)}
    except Exception:               # no font engine: keep the Windows default
        return
    for name in _FONT_STACK:
        if name.lower() in have:
            FONT = name
            break
    for name in _MONO_STACK:
        if name.lower() in have:
            FONT_MONO = name
            break


# Per-stream line colors; cycles when a port list grows past the palette
# (1.8.0: up to 8 streams per protocol). The first four keep the historic
# 2 UDP + 2 TCP hues - brightened for legibility against the dark glass, so
# screenshots stay comparable across versions.
STREAM_PALETTE = ("#00D89F", "#FF9F45", "#38BDF8", "#FFD84D",
                  "#B08CFF", "#5EEAD4", "#FF8FC7", "#9AA7BE")


def stream_color(sid):
    return STREAM_PALETTE[sid % len(STREAM_PALETTE)]


# ---------------------------------------------------------------------------
# Canvas primitives: rounded geometry, gradients, shadows, glass cards
# ---------------------------------------------------------------------------
def _rr_points(x0, y0, x1, y1, r):
    """Control points for a corner-rounded rectangle drawn with
    create_polygon(smooth=True). Doubling the corner points is what turns Tk's
    spline into a clean quarter-round instead of a lozenge."""
    r = max(0, min(r, (x1 - x0) / 2.0, (y1 - y0) / 2.0))
    return (x0 + r, y0, x1 - r, y0, x1, y0, x1, y0 + r,
            x1, y1 - r, x1, y1, x1 - r, y1, x0 + r, y1,
            x0, y1, x0, y1 - r, x0, y0 + r, x0, y0)


def _round_rect(canvas, x0, y0, x1, y1, r=RADIUS, **kw):
    """Filled and/or outlined rounded rectangle.

    splinesteps=4 rather than Tk's default 12: the worst-case chord error on
    a 16 px corner is 0.08 px, so the curve is identical on screen while Tk
    flattens and re-rasterises a third of the vertices."""
    kw.setdefault("outline", "")
    kw.setdefault("splinesteps", 4)
    return canvas.create_polygon(*_rr_points(x0, y0, x1, y1, r), smooth=True,
                                 **kw)


def _rr_inset(dy, h, r):
    """Horizontal inset of a rounded rect's edge, `dy` px below its top."""
    d = min(dy, h - dy)
    if d >= r or r <= 0:
        return 0.0
    return r - math.sqrt(max(0.0, r * r - (r - d) * (r - d)))


def _rr_gradient(canvas, x0, y0, x1, y1, r, top, bottom, step=2, tint=None,
                 tint_alpha=0.18, tint_falloff=2.2, **kw):
    """Vertical gradient clipped to a rounded rect.

    Tk cannot clip, so the rounded silhouette is produced by shortening each
    scanline by the corner inset - exact, and cheaper than any stencil. An
    optional `tint` washes the lit top of the pane with an accent colour,
    which is what sells the surface as translucent rather than merely dark;
    because it rides on the scanlines it is clipped for free."""
    if tint is None and top == bottom:
        # A "gradient" with equal endpoints is a fill; emitting one line per
        # scanline for it is pure waste (and the rounded silhouette comes out
        # cleaner as a real curve than as stepped scanline insets).
        return _round_rect(canvas, x0, y0, x1, y1, r, fill=top, **kw)
    h = max(1.0, y1 - y0)
    step = max(1, int(step))
    y = y0
    while y < y1:
        t = (y - y0) / h
        ins = _rr_inset(y - y0, h, r)
        col = _mix(top, bottom, t)
        if tint:
            col = _over(tint, col, tint_alpha * (1.0 - t) ** tint_falloff)
        canvas.create_line(x0 + ins, y, x1 - ins, y, width=step + 1,
                           fill=col, **kw)
        y += step


def _shadow(canvas, x0, y0, x1, y1, r=RADIUS, base=BG, spread=9, dy=4,
            layers=6, strength=0.55, **kw):
    """Soft drop shadow: concentric rounded rects fading into `base`.

    Drawn outermost-first so each opaque ring covers the one before it - the
    overlap is what makes the ramp read as a blur rather than as bands."""
    for i in range(layers, 0, -1):
        g = i / float(layers)                 # 1.0 = outermost, faintest
        pad = spread * g
        a = strength * 0.05 * (1.0 - g + 0.35)
        col = _over("#000000", base, a)
        if col == base:
            # Against a near-black base most of this ramp quantises to the
            # backdrop itself: the layer is a real spline that renders no
            # visible pixel. Skip it, and stay correct if the base lightens.
            continue
        _round_rect(canvas, x0 - pad, y0 - pad + dy * g, x1 + pad,
                    y1 + pad + dy * g, r + pad, fill=col, **kw)


def _radial(canvas, cx, cy, rad, color, base, alpha=0.5, steps=16, **kw):
    """A soft radial wash - the ambient light bleeding through the glass.

    `base` must be the colour actually underneath, since the falloff is
    composited against it rather than blended by a GPU."""
    for i in range(steps, 0, -1):
        g = i / float(steps)
        a = alpha * (1.0 - g) ** 1.8
        if a <= 0.002:
            continue
        rr = rad * g
        canvas.create_oval(cx - rr, cy - rr, cx + rr, cy + rr,
                           fill=_over(color, base, a), outline="", **kw)


def _glass(canvas, x0, y0, x1, y1, r=RADIUS, base=BG, top=PANEL_TOP,
           bottom=PANEL_LO, border=GRID, specular=True, shadow=True,
           glow=None, glow_alpha=0.16, step=2, **kw):
    """The house card: shadow, gradient glass body, hairline, specular edge.

    Everything a compositor would do for a frosted pane, resolved to flat
    colours: `glow` washes the lit top of the pane with an accent, `specular`
    is the 1 px highlight where the light catches the top bevel."""
    if shadow:
        _shadow(canvas, x0, y0, x1, y1, r, base=base, **kw)
    _rr_gradient(canvas, x0, y0, x1, y1, r, top, bottom, step=step,
                 tint=glow, tint_alpha=glow_alpha, **kw)
    if border:
        _round_rect(canvas, x0, y0, x1, y1, r, fill="", outline=border,
                    width=1, **kw)
    if specular:
        canvas.create_line(x0 + r * 0.75, y0 + 1, x1 - r * 0.75, y0 + 1,
                           fill=STROKE_HI, width=1, **kw)


def _draw_ekg(canvas, color=ACCENT_HI, width=2, glow=True, base=BG, dx=0, dy=0):
    """Draw the ECG/EKG heartbeat trace (P-QRS-T) that is the app's mark.

    Coordinates are tuned for a ~52x34 canvas: flat baseline, small P bump, a
    sharp QRS spike, then a T bump back to baseline. The trace is stroked
    twice - a wide dim pass for the glow, a crisp pass on top - which is how
    every light source in this UI is faked.
    """
    pts = [
        (2, 18), (12, 18),          # baseline
        (15, 14), (18, 18),         # P wave
        (21, 18), (23, 21),         # flat into Q dip
        (26, 4), (29, 30),          # R spike up, S dip down
        (32, 18), (36, 11),         # back to baseline, T wave
        (40, 18), (51, 18),         # baseline out
    ]
    flat = [c for xy in pts for c in (xy[0] + dx, xy[1] + dy)]
    if glow:
        for w, a in ((width + 6, 0.10), (width + 3, 0.20)):
            canvas.create_line(*flat, fill=_over(color, base, a), width=w,
                               capstyle="round", joinstyle="round")
    canvas.create_line(*flat, fill=color, width=width,
                       capstyle="round", joinstyle="round", smooth=False)


def _draw_aurora(canvas, w, h, base=BG, blobs=None, seam=True):
    """Ambient light behind a full-bleed band (the header, the launcher hero).

    A Canvas clips to its own bounds, so the washes can run off the edges and
    be cut cleanly - no masking needed. Blobs are placed apart because each is
    composited against `base` rather than against whatever it overlaps."""
    canvas.create_rectangle(0, 0, w, h, fill=base, outline="")
    if blobs is None:
        blobs = ((0.06, 0.05, 1.15, ACCENT, 0.30),
                 (0.55, -0.35, 1.05, ACCENT_3, 0.17),
                 (0.97, 0.85, 0.95, ACCENT_2, 0.16))
    for fx, fy, frad, col, a in blobs:
        _radial(canvas, fx * w, fy * h, frad * h, col, base, alpha=a, steps=15)
    if seam:
        # the light hairline where the band meets the content below
        _draw_hairline(canvas, 0, h - 1, w, base=base)


def _draw_hairline(canvas, x0, y, x1, base=BG, color=GLASS, alpha=0.16,
                   segments=34):
    """A 1 px rule that fades out at both ends - a spatial-UI staple, and the
    only way an edge reads as soft when there is no alpha channel."""
    span = max(1.0, x1 - x0)
    for i in range(segments):
        t = i / float(segments)
        # bell-shaped falloff: full strength mid-span, nothing at the ends
        a = alpha * math.sin(math.pi * t) ** 0.7
        canvas.create_line(x0 + span * t, y, x0 + span * (t + 1.0 / segments), y,
                           fill=_over(color, base, a), width=1)


def _score_orb(canvas, cx, cy, rad, score, color, base=BG, caption=None,
               **kw):
    """The headline health readout: a glowing arc gauge wrapped round the
    score. The ring gives the bare number a scale to sit on, and the glow is
    what makes the state readable across a demo room."""
    dead = score is None
    col = _over(GLASS, base, 0.30) if dead else color

    if not dead:
        # Kept inside ~1.35r: a wider bloom gets sliced by the canvas edge in
        # a header band, and a clipped glow reads as a rendering seam.
        _radial(canvas, cx, cy, rad * 1.35, col, base, alpha=0.40, steps=14,
                **kw)
    # the glass disc the ring is inlaid into
    _rr_gradient(canvas, cx - rad, cy - rad, cx + rad, cy + rad, rad,
                 _over(GLASS, base, 0.17), _over(GLASS, base, 0.045), step=2,
                 **kw)
    canvas.create_oval(cx - rad, cy - rad, cx + rad, cy + rad, fill="",
                       outline=_over(GLASS, base, 0.20), width=1, **kw)

    ring = rad - 6
    box = (cx - ring, cy - ring, cx + ring, cy + ring)
    canvas.create_arc(*box, start=225, extent=-270, style="arc", width=5,
                      outline=_over("#000000", _over(GLASS, base, 0.11), 0.45),
                      **kw)
    if not dead:
        frac = max(0.0, min(1.0, score / 100.0))
        ext = -270.0 * frac
        if ext:
            for wid, a in ((12, 0.20), (8, 0.38)):   # glow under the arc
                canvas.create_arc(*box, start=225, extent=ext, style="arc",
                                  width=wid, **kw,
                                  outline=_over(col, _over(GLASS, base, 0.10), a))
            canvas.create_arc(*box, start=225, extent=ext, style="arc",
                              width=5, outline=col, **kw)
    canvas.create_text(cx, cy - (2 if caption else 0), anchor="center",
                       text=("--" if dead else f"{score:.0f}"),
                       fill=(TXT_FAINT if dead else TXT),
                       font=(FONT, max(14, int(rad * 0.62)), "bold"), **kw)
    if caption:
        canvas.create_text(cx, cy + rad * 0.52, anchor="center", text=caption,
                           fill=TXT_FAINT, font=(FONT, 7, "bold"), **kw)


def _metric_chip(canvas, x0, y0, x1, y1, label, value, color=None, base=BG,
                 **kw):
    """Small glass tile: a caption beside a number. Used for the UDP MOS /
    TCP PQI pair in the header."""
    _glass(canvas, x0, y0, x1, y1, r=RADIUS_SM, base=base,
           top=_over(GLASS, base, 0.11), bottom=_over(GLASS, base, 0.05),
           glow=color, glow_alpha=0.13, shadow=False, **kw)
    canvas.create_text(x0 + 11, (y0 + y1) / 2.0, anchor="w", text=label,
                       fill=TXT_FAINT, font=(FONT, 7, "bold"), **kw)
    canvas.create_text(x1 - 11, (y0 + y1) / 2.0, anchor="e", text=value,
                       fill=(color or TXT), font=(FONT, 13, "bold"), **kw)


# ---------------------------------------------------------------------------
# Glass widgets. Built lazily inside a function so that importing this module
# never imports tkinter - the console UI has to keep working on a box with no
# Tk installed at all.
# ---------------------------------------------------------------------------
_GLASS_WIDGETS = {}
_GLOW_PAD = 5      # slack around a pill so its outer glow has room to render

# Set while a window drag is in flight. Every surface in this UI is painted by
# hand, one canvas item per gradient scanline, and an opaque resize delivers a
# <Configure> for every intermediate size - tens per second. Repainting on
# each of them is what makes a drag feel like treacle, so the handlers stand
# down while this is true and one settle pass repaints everything at the end.
_RESIZING = [False]


def _glass_widgets():
    if _GLASS_WIDGETS:
        return _GLASS_WIDGETS
    import tkinter as tk

    class GlassButton(tk.Canvas):
        """A rounded glass pill that behaves like tk.Button.

        Tk's own button cannot be rounded, tinted or lit, so it is rebuilt on
        a Canvas. `configure`/`cget` still answer to `text` and `state`, so
        existing callers drive it exactly like the stock widget."""

        def __init__(self, parent, text="", command=None, primary=False,
                     toggle=False, base=BG, height=30, pad_x=15, size=9,
                     accent=ACCENT, min_width=0, check=False):
            super().__init__(parent, bg=base, highlightthickness=0, bd=0,
                             height=height + 2 * _GLOW_PAD, takefocus=0)
            self._text, self._command = text, command
            self._primary, self._toggle = primary, toggle
            self._check = check          # draw a tick box left of the label
            self._base, self._accent = base, accent
            self._ph, self._pad_x, self._size = height, pad_x, size
            self._min_w = min_width
            self._hover = self._press = self._on = False
            self._enabled = True
            self._measure()
            self.bind("<Enter>", self._enter)
            self.bind("<Leave>", self._leave)
            self.bind("<Button-1>", self._down)
            self.bind("<ButtonRelease-1>", self._up)
            self.bind("<Configure>", lambda _e: self._render())

        # -- geometry -------------------------------------------------------
        def _measure(self):
            try:
                import tkinter.font as tkfont
                tw = tkfont.Font(root=self, family=FONT, size=self._size,
                                 weight="bold").measure(self._text)
            except Exception:                     # no font engine: estimate
                tw = int(7.2 * len(self._text))
            pill = max(self._min_w, tw + self._pad_x * 2
                       + (22 if self._check else 0))
            super().configure(width=pill + 2 * _GLOW_PAD)

        # -- interaction ----------------------------------------------------
        def _enter(self, _e=None):
            if self._enabled:
                self._hover = True
                self.configure(cursor="hand2")
                self._render()

        def _leave(self, _e=None):
            self._hover = self._press = False
            self._render()

        def _down(self, _e=None):
            if self._enabled:
                self._press = True
                self._render()

        def _up(self, _e=None):
            was = self._press
            self._press = False
            self._render()
            if was and self._enabled and self._command:
                self._command()

        # -- tk.Button-compatible surface -----------------------------------
        def configure(self, cnf=None, **kw):
            if isinstance(cnf, dict):
                kw.update(cnf)
            redraw = False
            if "text" in kw:
                self._text = kw.pop("text")
                self._measure()
                redraw = True
            if "state" in kw:
                self._enabled = str(kw.pop("state")) != "disabled"
                self._hover = self._press = False
                redraw = True
            if "command" in kw:
                self._command = kw.pop("command")
            if "on" in kw:
                self._on = bool(kw.pop("on"))
                redraw = True
            if kw:
                super().configure(**kw)
            if redraw:
                self._render()

        config = configure

        def cget(self, key):
            if key == "text":
                return self._text
            if key == "state":
                return "normal" if self._enabled else "disabled"
            if key == "on":
                return self._on
            return super().cget(key)

        __getitem__ = cget

        def set_on(self, on):
            self.configure(on=on)

        # -- paint ----------------------------------------------------------
        def _render(self):
            self.delete("all")
            w = self.winfo_width() or self.winfo_reqwidth()
            p, h = _GLOW_PAD, self._ph
            x0, x1 = p, w - p
            if x1 - x0 < 4:
                return
            r = min(RADIUS_SM, h / 2.0)
            base, acc = self._base, self._accent
            dy = 1 if self._press else 0
            y0, y1 = p + dy, p + h + dy
            lit = self._primary or self._on

            if not self._enabled:
                top, bot = _over(GLASS, base, 0.05), _over(GLASS, base, 0.035)
                border, fg = _over(GLASS, base, 0.08), TXT_FAINT
            elif self._primary:
                top = _lighten(acc, 0.22 if self._hover else 0.10)
                bot = _darken(acc, 0.20)
                border, fg = _lighten(acc, 0.40), "#03130E"
            elif self._on:
                top = _over(acc, base, 0.34 if self._hover else 0.26)
                bot = _over(acc, base, 0.14)
                border, fg = _over(acc, base, 0.60), ACCENT_HI
            else:
                lvl = 0.135 if self._hover else 0.08
                top, bot = _over(GLASS, base, lvl + 0.045), _over(GLASS, base, lvl)
                border = _over(GLASS, base, 0.22 if self._hover else 0.14)
                fg = TXT if self._hover else _mix(TXT, TXT_DIM, 0.45)

            if self._enabled and (lit or self._hover):
                gcol = acc if lit else GLASS
                ga = 0.30 if lit else 0.13
                for pad, mul in ((5.0, 0.30), (3.0, 0.55), (1.5, 0.9)):
                    _round_rect(self, x0 - pad, y0 - pad, x1 + pad, y1 + pad,
                                r + pad, fill=_over(gcol, base, ga * mul * 0.42))
            _rr_gradient(self, x0, y0, x1, y1, r, top, bot, step=2)
            _round_rect(self, x0, y0, x1, y1, r, fill="", outline=border,
                        width=1)
            if self._enabled and not self._press:
                self.create_line(x0 + r * 0.8, y0 + 1, x1 - r * 0.8, y0 + 1,
                                 fill=_over(SPEC, top,
                                            0.30 if self._primary else 0.18),
                                 width=1)
            if self._check:
                # A tick box inside the pill, so a boolean still reads as a
                # boolean rather than as a button that happens to stay lit.
                cy, bs = (y0 + y1) / 2.0, 6.5
                bx = x0 + self._pad_x
                _round_rect(self, bx - bs, cy - bs, bx + bs, cy + bs, 4,
                            fill=(_over(acc, base, 0.55) if self._on
                                  else _over("#000000", top, 0.34)),
                            outline=(_lighten(acc, 0.3) if self._on
                                     else _over(GLASS, top, 0.22)), width=1)
                if self._on:
                    self.create_line(bx - 3.4, cy + 0.2, bx - 0.8, cy + 3.0,
                                     bx + 3.6, cy - 3.2, fill="#04140F",
                                     width=2, capstyle="round",
                                     joinstyle="round")
                self.create_text(bx + bs + 9, cy, text=self._text, anchor="w",
                                 fill=fg, font=(FONT, self._size, "bold"))
            else:
                self.create_text((x0 + x1) / 2.0, (y0 + y1) / 2.0,
                                 text=self._text, fill=fg,
                                 font=(FONT, self._size, "bold"))

    class GlassCard(tk.Canvas):
        """A rounded glass pane that hosts real widgets.

        Tk widgets are opaque rectangles, so a table or a form can never have
        a rounded edge of its own. Parking the child in a canvas window, inset
        from the card silhouette, buys back the rounded glass frame while
        leaving the child an ordinary widget."""

        def __init__(self, parent, base=BG, padx=14, pady=12, r=RADIUS,
                     glow=None, shadow=True, level=CARD_LEVEL, **kw):
            super().__init__(parent, bg=base, highlightthickness=0, bd=0,
                             height=60, **kw)
            self._base, self._padx, self._pady = base, padx, pady
            self._r, self._glow, self._shadow = r, glow, shadow
            # A hosting card keeps a near-flat gradient: the child frame can
            # only be one colour, so a strong ramp would show a seam at the
            # inset edge. The specular hairline supplies the depth instead.
            self._top = _over(GLASS, base, level + 0.022)
            self._bot = _over(GLASS, base, level - 0.018)
            self.surface = _over(GLASS, base, level)
            self.body = tk.Frame(self, bg=self.surface)
            self._win = None
            self.body.bind("<Configure>", self._sync_size)
            self.bind("<Configure>", self._repaint)

        def _sync_size(self, _e=None):
            """Track the hosted widget's natural size.

            Hosting inverts Tk's usual sizing: the canvas would otherwise
            report a stock 378x60 request and then FORCE the child down to
            that, silently clipping a form instead of growing to hold it. So
            the card asks for whatever the child asks for, plus its inset."""
            chrome_h = 2 * self._pady + 2 * _GLOW_PAD
            chrome_w = 2 * self._padx + 2 * _GLOW_PAD
            need_h = self.body.winfo_reqheight() + chrome_h
            need_w = self.body.winfo_reqwidth() + chrome_w
            kw = {}
            if abs(need_h - self.winfo_reqheight()) > 1:
                kw["height"] = need_h
            if abs(need_w - self.winfo_reqwidth()) > 1:
                kw["width"] = need_w
            if kw:
                super().configure(**kw)

        def _repaint(self, _e=None):
            if _RESIZING[0]:
                return
            w, h = self.winfo_width(), self.winfo_height()
            if w < 20 or h < 20:
                return
            # Delete the DRAWN items only. delete("all") would take the
            # canvas window item with them, which unmaps and remaps the hosted
            # widget - a full map round trip plus an expose of the whole table
            # on every repaint, and a visible flicker with it.
            m = _GLOW_PAD
            if self._win is None:
                self._win = self.create_window(m + self._padx, m + self._pady,
                                               window=self.body, anchor="nw")
            for item in self.find_all():
                if item != self._win:
                    self.delete(item)
            _glass(self, m, m, w - m, h - m, r=self._r, base=self._base,
                   top=self._top, bottom=self._bot, glow=self._glow,
                   glow_alpha=0.09, shadow=self._shadow, step=2)
            self.coords(self._win, m + self._padx, m + self._pady)
            self.itemconfigure(self._win,
                               width=max(10, w - 2 * (m + self._padx)))

    _GLASS_WIDGETS.update(button=GlassButton, card=GlassCard)
    return _GLASS_WIDGETS


def _style_tables(ttk, tk):
    """Dress ttk's Treeview to match the glass cards it gets hosted in.

    The row background has to be exactly CARD_SURFACE: the table is an opaque
    widget sitting inside the card's inset, so any drift shows up as a visible
    panel-within-a-panel."""
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("NQ.Treeview", background=CARD_SURFACE,
                    fieldbackground=CARD_SURFACE, foreground=TXT, rowheight=30,
                    font=(FONT, 10), borderwidth=0, relief="flat")
    style.configure("NQ.Treeview.Heading", background=CARD_SURFACE,
                    foreground=TXT_DIM, font=(FONT, 8, "bold"),
                    relief="flat", borderwidth=0, padding=(4, 6))
    style.map("NQ.Treeview.Heading",
              background=[("active", _over(GLASS, BG, CARD_LEVEL + 0.05))],
              foreground=[("active", TXT_DIM)])
    style.map("NQ.Treeview",
              background=[("selected", _over(ACCENT, CARD_SURFACE, 0.30))],
              foreground=[("selected", TXT)])
    style.layout("NQ.Treeview", [("NQ.Treeview.treearea", {"sticky": "nswe"})])


def _glass_entry(tk, parent, var, width, surface, justify="left", size=10):
    """A text field that reads as a well cut into the glass rather than a box
    sitting on it: recessed fill, hairline border, accent focus ring."""
    e = tk.Entry(parent, textvariable=var, width=width,
                 bg=_over("#000000", surface, 0.28), fg=TXT,
                 insertbackground=ACCENT_HI, relief="flat", bd=0,
                 highlightthickness=1,
                 highlightbackground=_over(GLASS, surface, 0.16),
                 highlightcolor=ACCENT, font=(FONT, size), justify=justify,
                 disabledbackground=_over("#000000", surface, 0.16),
                 disabledforeground=TXT_FAINT,
                 selectbackground=_over(ACCENT, surface, 0.40),
                 selectforeground=TXT)
    return e


def _flow_layout(container, widgets, gap_x=3, gap_y=4):
    """Left-to-right flow that wraps onto further rows as the window narrows.

    Tk has no wrapping container, and a toolbar of nine buttons has to survive
    a 480 px window - which is why the old header had to hand-juggle its
    button bar between two rows."""
    state = {"h": -1}

    def relayout(_e=None):
        if _RESIZING[0]:
            return
        w = container.winfo_width()
        if w <= 1:
            return
        x = y = rowh = 0
        for wd in widgets:
            ww, wh = wd.winfo_reqwidth(), wd.winfo_reqheight()
            if x and x + ww > w:
                x, y, rowh = 0, y + rowh + gap_y, 0
            wd.place(x=x, y=y)
            x += ww + gap_x
            rowh = max(rowh, wh)
        need = y + rowh
        if need != state["h"]:
            state["h"] = need
            container.configure(height=need)

    container.bind("<Configure>", relayout)
    container.after(0, relayout)
    return relayout


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


BAND_FILL = "#4FB3C9"   # percentile band, composited against the card


def _chart_geom(w, h):
    """Padding for a chart of this size. Small multiples get tighter margins
    so the plot area itself never collapses to a sliver.

    The top margin is deliberately thin: the title is a watermark inside the
    plot and the legend only exists on hover, so neither one is buying a
    header row at the expense of the data."""
    tight = h < 230
    return {"l": 52 if tight else 60, "r": 16 if tight else 22,
            "t": 22 if tight else 26, "b": 26 if tight else 30,
            "tight": tight}


# --- hover legend ----------------------------------------------------------
# The per-series key is a stack of pills at the plot's top-left that fades in
# under the pointer and back out when it leaves, so the resting chart spends
# all of its height on data. Tk cannot fade a widget - but every colour in
# this UI is composited by hand against a known backdrop anyway, so a fade is
# just the same pills re-blended a few times a second.
LEGEND_PILL_H = 20
LEGEND_PILL_GAP = 4


def _title_ink(well, legend_alpha):
    """Watermark strength for a chart title: ~70% of the text colour at rest,
    receding as the hover legend comes up over the same corner."""
    return _over(TXT, well, 0.70 - 0.42 * legend_alpha)


def _legend_state(canvas):
    """Per-canvas legend state, created (and bound) on first use."""
    st = getattr(canvas, "_nq_legend", None)
    if st is None:
        st = {"alpha": 0.0, "target": 0.0, "job": None, "open": set(),
              "hits": [], "items": (), "origin": None, "well": BG}
        canvas._nq_legend = st
        canvas.bind("<Enter>", lambda _e: _legend_show(canvas, True), add="+")
        canvas.bind("<Leave>", lambda _e: _legend_show(canvas, False), add="+")
        canvas.bind("<Button-1>", lambda e: _legend_click(canvas, e), add="+")
        canvas.bind("<Motion>", lambda e: _legend_motion(canvas, e), add="+")
    return st


def _legend_hit(canvas, x, y):
    for hx0, hy0, hx1, hy1, idx in canvas._nq_legend["hits"]:
        if hx0 <= x <= hx1 and hy0 <= y <= hy1:
            return idx
    return None


def _legend_paint(canvas):
    """Repaint the pill stack at the current fade level."""
    st = canvas._nq_legend
    canvas.delete("nqlegend")
    st["hits"] = []
    a = st["alpha"]
    well = st["well"]
    # Dim the title in step with the fade rather than waiting for the next
    # refresh tick, so the two never cross over at full strength.
    for tid in canvas.find_withtag("nqtitle"):
        canvas.itemconfigure(tid, fill=_title_ink(well, a))
    if a <= 0.02 or not st["items"] or not st["origin"]:
        return
    x0, y = st["origin"]
    # Eight streams per protocol is a supported config, and eight pills do not
    # fit a small multiple. Drop to what fits and say so, rather than running
    # the stack off the bottom of the plot.
    per = LEGEND_PILL_H + LEGEND_PILL_GAP
    fits = max(1, int(st.get("maxh", 1e6) // per))
    shown, hidden = st["items"], 0
    if len(shown) > fits:
        hidden = len(shown) - (fits - 1)
        shown = shown[:fits - 1]
    for i, (color, label, value) in enumerate(shown):
        # Collapsed shows the live number, which is what a glance wants;
        # clicking swaps in the stream's name for when it doesn't.
        text = f"{label}   {value}".strip() if i in st["open"] else (value or label)
        tid = canvas.create_text(x0 + 21, y + LEGEND_PILL_H / 2, text=text,
                                 anchor="w", fill=_over(TXT, well, 0.92 * a),
                                 font=(FONT, 8, "bold"), tags="nqlegend")
        x1 = canvas.bbox(tid)[2] + 10
        _round_rect(canvas, x0, y, x1, y + LEGEND_PILL_H, 9,
                    fill=_over(GLASS, well, 0.13 * a),
                    outline=_over(color, well, 0.55 * a), width=1,
                    tags="nqlegend")
        canvas.create_line(x0 + 10, y + 6, x0 + 10, y + LEGEND_PILL_H - 6,
                           fill=_over(color, well, a), width=3,
                           capstyle="round", tags="nqlegend")
        canvas.tag_raise(tid)
        st["hits"].append((x0, y, x1, y + LEGEND_PILL_H, i))
        y += per
    if hidden:
        tid = canvas.create_text(x0 + 12, y + LEGEND_PILL_H / 2,
                                 text=f"+{hidden} more", anchor="w",
                                 fill=_over(TXT_DIM, well, 0.92 * a),
                                 font=(FONT, 8), tags="nqlegend")
        _round_rect(canvas, x0, y, canvas.bbox(tid)[2] + 10,
                    y + LEGEND_PILL_H, 9,
                    fill=_over(GLASS, well, 0.13 * a),
                    outline=_over(GLASS, well, 0.22 * a), width=1,
                    tags="nqlegend")
        canvas.tag_raise(tid)


def _legend_step(canvas):
    st = canvas._nq_legend
    st["job"] = None
    a, target = st["alpha"], st["target"]
    if abs(target - a) < 0.03:
        st["alpha"] = target
    else:
        st["alpha"] = a + (target - a) * 0.34
        try:
            st["job"] = canvas.after(28, lambda: _legend_step(canvas))
        except Exception:
            return                      # canvas went away mid-fade
    _legend_paint(canvas)


def _legend_show(canvas, on):
    st = _legend_state(canvas)
    st["target"] = 1.0 if on else 0.0
    if not on and st.get("cursor"):
        st["cursor"] = ""
        canvas.configure(cursor="")
    if st["job"] is None and st["alpha"] != st["target"]:
        try:
            st["job"] = canvas.after(16, lambda: _legend_step(canvas))
        except Exception:
            pass


def _legend_click(canvas, event):
    st = _legend_state(canvas)
    if st["alpha"] < 0.4:
        return
    idx = _legend_hit(canvas, event.x, event.y)
    if idx is not None:
        st["open"].symmetric_difference_update({idx})
        _legend_paint(canvas)


def _legend_motion(canvas, event):
    st = _legend_state(canvas)
    if st["alpha"] < 0.4:
        return
    # Motion fires hundreds of times a second while the pointer crosses a
    # chart. Setting the cursor is a Tcl round trip plus an X attribute
    # change, so only do it when the answer actually changes.
    want = "hand2" if _legend_hit(canvas, event.x, event.y) is not None else ""
    if want != st.get("cursor"):
        st["cursor"] = want
        canvas.configure(cursor=want)


def _legend_items(key, series, samples_by_sid, value_fmt, unit, band,
                  band_label):
    """(colour, name, latest value) per series, plus the band if there is one."""
    out = []
    for sid, color, label in series:
        cur = None
        for s in reversed(samples_by_sid.get(sid, ())):
            if s.get(key) is not None:
                cur = s.get(key)
                break
        out.append((color, label,
                    f"{value_fmt(cur)}{unit}" if cur is not None else "-"))
    if band and band_label:
        out.append((BAND_FILL, band_label, ""))
    return tuple(out)


def _draw_chart(canvas, title, key, series, samples_by_sid, view_seconds, now,
                ymin_floor=1.0, unit="", value_fmt=None, band=None,
                band_label=None, markers=None, mark_labels=False,
                accent=None, base=BG):
    """Render one time-series chart as a floating glass card.

    series: list of (sid, color, short_label). samples_by_sid: {sid: [sample]}.
    Each sample is {'t', key..., 'up'}; None values break the line (gap = down).
    band: optional [{'t','lo','hi','up'}] drawn as a shaded region behind the
    series lines (None/down samples break it), labeled `band_label`.
    markers: optional [(t_mono, label)] scenario stage boundaries, drawn as
    dashed verticals (labels only when mark_labels, to keep small charts clean).

    The canvas paints its own card, so its widget background is the app base
    and the rounded corners resolve against it.
    """
    if value_fmt is None:
        value_fmt = lambda v: f"{v:.0f}"
    w = canvas.winfo_width()
    h = canvas.winfo_height()
    if w < 30 or h < 30:
        return

    # The card and the plot well are pure functions of the canvas size, and
    # they are by far the most expensive things here - a gradient is one line
    # item per scanline. So they are painted once per resize and left alone,
    # and only the data is torn down on each tick. That keeps a 2 Hz refresh
    # roughly as cheap as the flat-rectangle version it replaces.
    m = 4                                   # slack for the drop shadow
    cx0, cy0, cx1, cy1 = m, m, w - m, h - m
    accent = accent or (series[0][1] if series else ACCENT)
    surface = _mix(PANEL_TOP, PANEL_LO, 0.45)   # mean card tone, for blending
    g = _chart_geom(w, h)
    pad_l, pad_r = cx0 + g["l"], cx1 - g["r"]
    pad_t, pad_b = cy0 + g["t"], cy1 - g["b"]
    pw, ph = pad_r - pad_l, pad_b - pad_t
    if pw < 24 or ph < 24:
        return
    well = _over("#000000", surface, 0.30)   # what the plot content sits on

    chrome_key = (w, h, accent)
    if getattr(canvas, "_nq_chrome", None) != chrome_key:
        canvas.delete("all")
        _glass(canvas, cx0, cy0, cx1, cy1, r=RADIUS, base=base, glow=accent,
               glow_alpha=0.13, step=2)
        # The plot sits BELOW the glass rather than on it: a dark inset well
        # with its own top shadow, so the data reads as being seen through
        # the pane instead of printed on it.
        wx0, wy0 = pad_l - 9, pad_t - 9
        wx1, wy1 = pad_r + 10, pad_b + 9
        # This ramp crosses only ~17 8-bit quantisation steps over the whole
        # well, so a 2 px sample is ten times finer than anything that can
        # render. step=8 is still 2x oversampled and drops ~120 items.
        _rr_gradient(canvas, wx0, wy0, wx1, wy1, RADIUS_SM,
                     _over("#000000", surface, 0.38),
                     _over("#000000", surface, 0.20), step=8)
        canvas.create_line(wx0 + 8, wy0 + 1, wx1 - 8, wy0 + 1,
                           fill=_over("#000000", surface, 0.52), width=1)
        canvas._nq_chrome = chrome_key
        # Everything drawn from here on is data. Canvas ids only ever climb,
        # so remembering the last chrome id is enough to sweep the data away
        # on the next tick without tagging every single item.
        canvas._nq_static = max(canvas.find_all() or [0])
        canvas._nq_last = None
    else:
        # The history sampler appends once a SECOND, but the UI ticks twice a
        # second, so half of all redraws would re-render byte-identical data
        # for a sub-pixel shift of the time axis. Skip those. The pixel test
        # is what keeps it honest at a short --history, where half a second
        # of scroll is a visible jump rather than a rounding error.
        newest = 0.0
        for _sid, _c, _n in series:
            ss = samples_by_sid.get(_sid)
            if ss:
                newest = max(newest, ss[-1]["t"])
        if band:
            newest = max(newest, band[-1]["t"])
        state_key = (newest, len(markers) if markers else 0)
        last = getattr(canvas, "_nq_last", None)
        if (last is not None and last[0] == state_key
                and (now - last[1]) * pw / max(1e-3, view_seconds) < 1.5):
            return
        canvas._nq_last = (state_key, now)
        stale = [i for i in canvas.find_all() if i > canvas._nq_static]
        if stale:
            canvas.delete(*stale)

    # ---- autoscale --------------------------------------------------------
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

    t0 = now - view_seconds

    def X(t):
        return pad_l + pw * (t - t0) / max(1e-3, view_seconds)

    def Y(v):
        return pad_t + ph * (1 - min(1.0, max(0.0, v) / vmax))

    # ---- grid + Y labels --------------------------------------------------
    # Pick a row count whose labels are all distinct under this formatter: a
    # 2-unit axis divided four ways used to print "2 2 1 0 0", which reads as
    # a rendering bug rather than as a scale.
    for rows in ((4, 2) if not g["tight"] else (3, 2)):
        labels = [value_fmt(vmax * (1 - i / float(rows)))
                  for i in range(rows + 1)]
        if len(set(labels)) == len(labels):
            break
    for i, lbl in enumerate(labels):
        yy = pad_t + ph * i / float(rows)
        canvas.create_line(pad_l, yy, pad_r, yy,
                           fill=_over(GLASS, well, 0.10 if i else 0.16),
                           dash=(1, 3) if i else None)
        canvas.create_text(pad_l - 15, yy, text=lbl, anchor="e",
                           fill=TXT_FAINT, font=(FONT, 7))

    # ---- X axis time labels ----------------------------------------------
    for frac, lbl in ((0.0, f"-{int(view_seconds)}s"),
                      (0.5, f"-{int(view_seconds / 2)}s"), (1.0, "now")):
        canvas.create_text(pad_l + pw * frac, pad_b + 15, text=lbl,
                           anchor="center", fill=TXT_FAINT, font=(FONT, 7))

    # ---- title, as a watermark inside the plot ----------------------------
    # Drawn here, before the data, so the traces pass over it. A title you
    # already know is worth less than the reading it would otherwise hide,
    # and this buys the ~50 px that a dedicated header row used to cost. It
    # also recedes as the legend fades in, so the pills never have to fight
    # it for the same corner on a small multiple.
    canvas.create_text((pad_l + pad_r) / 2.0, pad_t + 14, text=title,
                       anchor="center", tags="nqtitle",
                       fill=_title_ink(well, _legend_state(canvas)["alpha"]),
                       font=(FONT, 9 if g["tight"] else 10, "bold"))

    # ---- percentile band --------------------------------------------------
    # A flat composited colour instead of the old 50% stipple: we know exactly
    # what is underneath, so the blend is smooth where the dither was coarse.
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
        fill = _over(BAND_FILL, well, 0.26)
        edge = _over(BAND_FILL, well, 0.44)
        for run in runs:
            if len(run) < 2:
                continue
            # Bucket the band the same way, taking the max of `hi` and the min
            # of `lo` per column: the shaded region can then only ever get
            # more conservative, never under-report its own spread.
            nb = max(2, min(len(run), int(pw / 12)))
            cols = []
            stepf = len(run) / float(nb)
            for b in range(nb):
                i0, i1 = int(b * stepf), min(len(run), int((b + 1) * stepf))
                if i1 <= i0:
                    continue
                chunk = run[i0:i1]
                cols.append((chunk[0][0], min(c[1] for c in chunk),
                             max(c[2] for c in chunk)))
            if cols[-1][0] != run[-1][0]:
                cols.append(run[-1])
            if len(cols) < 2:
                continue
            top = [c for tt, lo, hi in cols for c in (X(tt), Y(hi))]
            bot = [c for tt, lo, hi in reversed(cols) for c in (X(tt), Y(lo))]
            canvas.create_polygon(*top, *bot, fill=fill, outline="")
            canvas.create_line(*top, fill=edge, width=1)

    # ---- scenario stage markers (behind the series lines) -----------------
    if markers:
        for mt, mlabel in markers:
            if mt < t0 or mt > now:
                continue
            mx = X(mt)
            canvas.create_line(mx, pad_t, mx, pad_b,
                               fill=_over(ACCENT_3, well, 0.55), dash=(2, 4))
            if mark_labels and mlabel:
                lx2 = min(mx + 5, pad_r - 4)
                lid = canvas.create_text(lx2 + 6, pad_t + 9, text=mlabel,
                                         anchor="w", fill=_lighten(ACCENT_3, 0.3),
                                         font=(FONT, 7, "bold"))
                bx = canvas.bbox(lid)
                _round_rect(canvas, bx[0] - 5, bx[1] - 3, bx[2] + 5, bx[3] + 3,
                            6, fill=_over(ACCENT_3, well, 0.16))
                canvas.tag_raise(lid)

    # ---- series -----------------------------------------------------------
    # Each line is stroked more than once: wide dim halos underneath, then the
    # crisp stroke. That is the glow, and it is also what keeps a 2 px line
    # legible on top of the band without anti-aliasing to help.
    #
    # The halos are decimated and the crisp stroke is not. Every coordinate
    # costs a float->string conversion on the way into Tcl, and a 5-minute
    # history at 2 Hz is 600 points per series; spending that three times over
    # is what turns a redraw sluggish. A blur cannot show the difference, but
    # a dropped latency spike in the real line certainly would.
    halos = ((6, 0.10), (4, 0.20)) if not g["tight"] else ((4, 0.18),)
    fill_area = len(series) <= 2

    def _envelope(flat, buckets):
        """Reduce a flat [x0,y0,x1,y1,...] polyline to a min/max envelope of
        `buckets` columns.

        Index striding - the obvious way to thin a line - drops whichever
        samples fall between strides, and on these charts that is exactly the
        latency spike the operator is looking for. Keeping the extreme y in
        each column preserves the silhouette instead, so the halo still flares
        around a spike; it is only ever used for the decorative strokes, never
        for the data line itself.

        The old strided version quietly did nothing at the default sampling
        rate: integer `n // keep` with keep = pw/6 evaluates to 1 for a
        5-minute, 1 Hz history, so every halo was drawn at full resolution.
        """
        n = len(flat) // 2
        if buckets < 2 or n <= buckets * 2:
            return flat                       # already at or below target
        step = n / float(buckets)
        out = []
        for b in range(buckets):
            i0, i1 = int(b * step), min(n, int((b + 1) * step))
            if i1 <= i0:
                continue
            lo = hi = i0
            for i in range(i0 + 1, i1):
                y = flat[i * 2 + 1]
                if y < flat[lo * 2 + 1]:
                    lo = i
                elif y > flat[hi * 2 + 1]:
                    hi = i
            a, z = (lo, hi) if lo <= hi else (hi, lo)   # keep left-to-right
            out.extend((flat[a * 2], flat[a * 2 + 1]))
            if z != a:
                out.extend((flat[z * 2], flat[z * 2 + 1]))
        if out[-2:] != flat[-2:]:             # always end where the data ends
            out.extend(flat[-2:])
        return out

    for sid, color, _n in series:
        runs, pts = [], []
        for s in samples_by_sid.get(sid, ()):
            if s["t"] < t0:
                continue
            v = s.get(key)
            if v is None:
                if len(pts) >= 4:
                    runs.append(pts)
                pts = []
                continue
            pts.extend((X(s["t"]), Y(v)))
        if len(pts) >= 4:
            runs.append(pts)
        for run in runs:
            if fill_area:
                # gradient wash under the line, clipped by the polygon itself
                poly = list(run) + [run[-2], pad_b, run[0], pad_b]
                canvas.create_polygon(*poly, fill=_over(color, well, 0.13),
                                      outline="")
            halo_pts = _envelope(run, int(pw / 12))
            for wid, a in halos:
                canvas.create_line(*halo_pts, fill=_over(color, well, a),
                                   width=wid, capstyle="round",
                                   joinstyle="round")
            canvas.create_line(*run, fill=color, width=2, capstyle="round",
                               joinstyle="round")
        if runs:                       # live head: a lit dot at the last point
            hx, hy = runs[-1][-2], runs[-1][-1]
            if hx >= pad_r - 3:        # only when the series is actually current
                _radial(canvas, hx, hy, 9, color, well, alpha=0.55, steps=7)
                canvas.create_oval(hx - 2.6, hy - 2.6, hx + 2.6, hy + 2.6,
                                   fill=color, outline=_lighten(color, 0.55))

    # ---- hover legend ------------------------------------------------------
    # Values are handed to the pill stack rather than drawn now: the stack
    # only materialises under the pointer, and its fade animation repaints it
    # between refresh ticks off this same state.
    st = _legend_state(canvas)
    st["items"] = _legend_items(key, series, samples_by_sid, value_fmt, unit,
                                band, band_label)
    st["origin"] = (pad_l + 10, pad_t + 10)
    st["maxh"] = ph - 20
    st["well"] = well
    _legend_paint(canvas)


# ---------------------------------------------------------------------------
# Tkinter GUI (HPE-themed, with live + history charts)
# ---------------------------------------------------------------------------
def _set_window_icon(root):
    """Give the window - and, on Windows, the taskbar - the Network Vitals EKG icon. The
    AppUserModelID makes Windows group the app under its OWN taskbar button/icon instead of
    a generic pythonw one, so Network Vitals and Security Vitals each show their own logo."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("HPEAruba.NetworkVitals")
        except Exception:
            pass
        ico = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "netvitals.ico")
        try:
            if os.path.isfile(ico):
                root.iconbitmap(default=ico)
        except Exception:                      # non-fatal: a missing/bad icon just falls back
            pass


def run_gui(engine, args):
    """Live dashboard. Default: HPE Demo Instrument web UI (loopback + browser
    / Tk dock). Set NV_UI=tk to force the legacy glass Tk dashboard."""
    ui = (os.environ.get("NV_UI") or "web").strip().lower()
    if ui != "tk":
        try:
            import nv_webui
            return nv_webui.run_web_dashboard(sys.modules[__name__], engine, args)
        except Exception as e:
            print(f"web UI unavailable ({e}) - falling back to Tk dashboard.",
                  file=sys.stderr)
    return run_gui_tk(engine, args)


def run_gui_tk(engine, args):
    import tkinter as tk
    from tkinter import ttk

    view_seconds = float(args.history)
    series = [(sid, stream_color(sid), name.split("-")[1])
              for sid, proto, port, name in STREAMS]

    root = tk.Tk()
    _resolve_fonts(root)
    _set_window_icon(root)
    root.title(f"Network Vitals {__version__}  -  peer {args.peer}")
    root.geometry("1180x760")
    root.minsize(480, 340)
    root.configure(bg=BG)

    _style_tables(ttk, tk)

    # ---- hero band --------------------------------------------------------
    # Everything in the band is drawn as Canvas items rather than assembled
    # from widgets: a Tk widget is an opaque rectangle, so a Label parked on
    # the ambient gradient would punch a flat hole in it. Drawing instead
    # means the brand, the readouts and the light all composite properly, and
    # the band can re-lay itself out at any width in one pass.
    HERO_H = 108
    hero = tk.Canvas(root, bg=BG, highlightthickness=0, bd=0, height=HERO_H)
    hero.pack(fill="x", side="top")
    hero_state = {"score": None, "label": "Starting…", "sub": "", "detail": "",
                  "mos": None, "pqi": None, "mos_c": None, "pqi_c": None}

    # The band splits into three layers by how often each actually changes,
    # because a full repaint is ~175 canvas items and the refresh loop was
    # paying for all of it twice a second to move nothing:
    #   * backdrop  - aurora + brand lockup: a pure function of the width
    #   * orb       - only when the displayed integer score or its band moves
    #   * readouts  - text and chips, genuinely per-tick but cheap
    hero_cache = {"w": None, "orb": None, "fg": None}

    def paint_hero(_event=None):
        w = hero.winfo_width()
        if w < 10:
            return
        h = HERO_H

        if hero_cache["w"] != w:          # backdrop: width-invariant otherwise
            hero_cache.update(w=w, orb=None, fg=None)
            hero.delete("all")
            _draw_aurora(hero, w, h)
            _draw_ekg(hero, dx=20, dy=h / 2 - 24, width=2)
            hero.create_text(84, h / 2 - 12, anchor="w", text="Network Vitals",
                             fill=TXT, font=(FONT, 19, "bold"))

        score = hero_state["score"]
        col = score_color(score) if score is not None else TXT_DIM
        rad = 38
        cx = w - 22 - rad
        # The arc sweeps 2.7 deg per point and the label is a rounded integer,
        # so anything finer than a whole point is literally not renderable.
        orb_key = (None if score is None else round(score), col)
        if hero_cache["orb"] != orb_key:
            hero_cache["orb"] = orb_key
            hero.delete("heroorb")
            _score_orb(hero, cx, h / 2, rad, score, col, base=BG,
                       tags="heroorb")

        fg_key = (hero_state["sub"], hero_state["label"], hero_state["detail"],
                  hero_state["mos"], hero_state["mos_c"], hero_state["pqi"],
                  hero_state["pqi_c"])
        if hero_cache["fg"] == fg_key:
            return
        hero_cache["fg"] = fg_key
        hero.delete("herofg")

        hero.create_text(85, h / 2 + 12, anchor="w", tags="herofg",
                         text=hero_state["sub"] or f"peer {args.peer}",
                         fill=TXT_DIM, font=(FONT, 9))

        # Right-hand readout cluster, laid out right to left so the orb - the
        # one thing worth seeing from the back of a room - always owns the
        # corner, and the softer readouts drop off as the window narrows.
        x = cx - rad - 22
        if w >= 640:                      # experience text block
            left = x
            for dy, text, fill, font in (
                    (-24, "EXPERIENCE", TXT_FAINT, (FONT, 7, "bold")),
                    (-4, hero_state["label"], TXT, (FONT, 17, "bold")),
                    (18, hero_state["detail"], TXT_DIM, (FONT, 9))):
                tid = hero.create_text(x, h / 2 + dy, anchor="e", text=text,
                                       fill=fill, font=font, tags="herofg")
                left = min(left, hero.bbox(tid)[0])
            x = left - 20

        if w >= 940:                      # metric chips: first to go
            cw, ch = 122, 32
            _metric_chip(hero, x - cw, h / 2 - ch - 3, x, h / 2 - 3,
                         "UDP MOS", hero_state["mos"] or "--",
                         hero_state["mos_c"] or TXT_FAINT, tags="herofg")
            _metric_chip(hero, x - cw, h / 2 + 3, x, h / 2 + ch + 3,
                         "TCP PQI", hero_state["pqi"] or "--",
                         hero_state["pqi_c"] or TXT_FAINT, tags="herofg")

    hero.bind("<Configure>",
              lambda _e: None if _RESIZING[0] else paint_hero())

    # ---- toolbar ----------------------------------------------------------
    # Its own row, always: the old header shuffled the buttons in and out of
    # the brand row to stop them landing on the score readout. A wrapping flow
    # makes that dance unnecessary and survives narrower windows than it did.
    GlassButton = _glass_widgets()["button"]
    toolbar = tk.Frame(root, bg=BG, height=40)
    toolbar.pack(fill="x", side="top", padx=14, pady=(2, 8))
    toolbar.pack_propagate(False)

    def do_reset():
        engine.reset()  # charts + stats clear; they repopulate on the next tick

    reset_btn = GlassButton(toolbar, text="↺  Reset", command=do_reset)

    def _panel_toggle(state, frame, btn, on_show=None):
        """One collapsible bottom panel. The whole FRAME is packed/unpacked,
        not just its contents: an emptied but still-packed frame keeps its
        last requested size, which is what used to leave the charts squeezed
        after a table was closed."""
        def toggle():
            state["on"] = not state["on"]
            if state["on"]:
                frame.pack(fill="x", side="bottom", before=charts,
                           padx=12, pady=(0, 6))
                btn.set_on(True)
                if on_show:
                    on_show()
            else:
                frame.pack_forget()
                btn.set_on(False)
        return toggle

    totals_shown = {"on": False}
    isolate_shown = {"on": False}
    anatomy_shown = {"on": False}
    topo_shown = {"on": False}
    load_shown = {"on": False}

    totals_btn = GlassButton(toolbar, text="▤  Totals", toggle=True)
    isolate_btn = GlassButton(toolbar, text="⇄  Isolate", toggle=True)
    anatomy_btn = GlassButton(toolbar, text="▦  Anatomy", toggle=True)
    topo_btn = GlassButton(toolbar, text="≣  Topology", toggle=True)
    load_btn = GlassButton(toolbar, text="⚡  Load", toggle=True)

    def do_fit_charts():
        """Collapse the bottom panels and force a fresh geometry pass so the
        charts reclaim the full current window space."""
        for st, btn in ((totals_shown, totals_btn), (isolate_shown, isolate_btn),
                        (anatomy_shown, anatomy_btn), (topo_shown, topo_btn),
                        (load_shown, load_btn)):
            if st["on"]:
                st["on"] = False
                btn.set_on(False)
        for f in (totals_frame, iso_frame, anat_frame, topo_frame, load_frame):
            f.pack_forget()
        for c in (lat_canvas, loss_canvas, jit_canvas, owd_canvas):
            c.configure(width=100, height=80)
        root.update_idletasks()

    fit_btn = GlassButton(toolbar, text="⤢  Fit charts", command=do_fit_charts)

    def do_report():
        # The demo's leave-behind: a JSON + self-contained HTML pair.
        from tkinter import messagebox
        try:
            jp, hp = write_report(engine, args)
        except OSError as e:
            messagebox.showerror("Network Vitals", f"Report failed: {e}",
                                 parent=root)
            return
        messagebox.showinfo("Network Vitals",
                            f"Report written:\n{hp}\n{jp}", parent=root)

    rep_btn = GlassButton(toolbar, text="⭳  Report", command=do_report)

    def do_update():
        # Explicit user action; a restart re-runs with this exact argv.
        open_update_dialog(root, args.update_url,
                           relaunch_argv=getattr(args, "_argv", None))

    upd_btn = GlassButton(toolbar, text="⟳  Update", command=do_update)

    _toolbar_relayout = _flow_layout(
        toolbar, [reset_btn, totals_btn, isolate_btn, anatomy_btn, topo_btn,
                  load_btn, fit_btn, rep_btn, upd_btn])

    # ---- footer (pinned to the bottom, before charts claim the middle) ----
    # Two short left-anchored lines instead of one mega-line: a label centers
    # its text in the space it gets, so the old single line clipped at BOTH
    # ends in a narrow window.  The warning gets a row only while active.
    footer = tk.Frame(root, bg=BG, padx=18, pady=(0))
    footer.pack(fill="x", side="bottom")
    rule = tk.Canvas(footer, bg=BG, highlightthickness=0, height=1)
    rule.pack(fill="x", pady=(0, 8))
    rule.bind("<Configure>", lambda _e: None if _RESIZING[0] else
              (rule.delete("all"),
               _draw_hairline(rule, 0, 0, rule.winfo_width())))
    warn_var = tk.StringVar(value="")
    warn_lbl = tk.Label(footer, textvariable=warn_var, fg=WARN, bg=BG,
                        font=(FONT, 9, "bold"), anchor="w")
    scen_var = tk.StringVar(value="")
    scen_lbl = tk.Label(footer, textvariable=scen_var, fg=ACCENT_HI, bg=BG,
                        font=(FONT, 9, "bold"), anchor="w")
    foot_path_var = tk.StringVar(value="")
    foot_path_lbl = tk.Label(footer, textvariable=foot_path_var, fg=TXT_DIM,
                             bg=BG, font=(FONT, 9), anchor="w")
    foot_path_lbl.pack(fill="x")
    foot_cnt_var = tk.StringVar(value="")
    tk.Label(footer, textvariable=foot_cnt_var, fg=TXT_FAINT, bg=BG,
             font=(FONT, 9), anchor="w").pack(fill="x", pady=(1, 8))

    # ---- totals table (hidden by default; toggled by the Totals button) ----
    totals_cols = ("stream", "sent", "recv", "lost", "late", "lossp",
                   "txb", "peerrx", "echorx", "size", "dscp")
    totals_head = {"stream": "Stream", "sent": "Sent", "recv": "Received",
                   "lost": "Lost", "late": "Late", "lossp": "Loss %",
                   "txb": "TX B", "peerrx": "Peer RX B", "echorx": "My RX B",
                   "size": "Size", "dscp": "DSCP rq→f/r"}
    totals_w = {"stream": 110, "sent": 78, "recv": 84, "lost": 64, "late": 60,
                "lossp": 64, "txb": 66, "peerrx": 78, "echorx": 72, "size": 80,
                "dscp": 110}
    GlassCard = _glass_widgets()["card"]
    totals_frame = GlassCard(root, glow=ACCENT_2)
    # not packed here — the Totals toggle packs/unpacks the whole card
    totals_tree = ttk.Treeview(totals_frame.body, columns=totals_cols,
                               show="headings", height=len(STREAMS),
                               style="NQ.Treeview")
    totals_tree.pack(fill="x")
    for c in totals_cols:
        totals_tree.heading(c, text=totals_head[c])
        totals_tree.column(c, width=totals_w[c], anchor=("w" if c == "stream" else "e"),
                           stretch=(c == "stream"))
    totals_tree.tag_configure("ok", foreground=OK_SOFT)
    totals_tree.tag_configure("bad", foreground=DANGER)
    for sid, proto, port, name in STREAMS:
        totals_tree.insert("", "end", iid=f"t{sid}",
                           values=(name, 0, 0, 0, 0, "0.0", 0, 0, 0, "-", "-"))
    # frame stays unpacked -> hidden until the Totals button is clicked

    # ---- isolate table (hidden; splits loss into forward vs return) --------
    iso_cols = ("stream", "sent", "fwd", "fwdp", "rtn", "rtnp", "where")
    iso_head = {"stream": "Stream", "sent": "Sent",
                "fwd": "Fwd lost (→peer)", "fwdp": "Fwd %",
                "rtn": "Rtn lost (←peer)", "rtnp": "Rtn %", "where": "Where"}
    iso_w = {"stream": 110, "sent": 84, "fwd": 120, "fwdp": 70,
             "rtn": 120, "rtnp": 70, "where": 110}
    iso_frame = GlassCard(root, glow=ACCENT_3)
    # not packed here — the Isolate toggle packs/unpacks the whole card
    iso_tree = ttk.Treeview(iso_frame.body, columns=iso_cols, show="headings",
                            height=len(STREAMS), style="NQ.Treeview")
    iso_tree.pack(fill="x")
    for c in iso_cols:
        iso_tree.heading(c, text=iso_head[c])
        iso_tree.column(c, width=iso_w[c], anchor=("w" if c in ("stream", "where") else "e"),
                        stretch=(c == "stream"))
    iso_tree.tag_configure("ok", foreground=OK_SOFT)
    iso_tree.tag_configure("warn", foreground=WARN_SOFT)
    for sid, proto, port, name in STREAMS:
        iso_tree.insert("", "end", iid=f"i{sid}",
                        values=(name, 0, 0, "0.00", 0, "0.00", "…"))
    # frame stays unpacked -> hidden until the Isolate button is clicked

    # ---- anatomy panel (hidden; one probe's wire view through the fabric) --
    # Byte-proportional bars, LAN packet on top and its predicted tunnel
    # packets below, drawn from the EdgeConnect wire model (ec_wire_view).
    # Everything here is static per run (probe size, DF, VXLAN, pps), so it
    # redraws only on toggle and canvas resize - never in the refresh loop.
    anat_frame = tk.Frame(root, bg=BG)
    # not packed here — the Anatomy toggle packs/unpacks the whole frame
    anat_canvas = tk.Canvas(anat_frame, bg=BG, highlightthickness=0,
                            height=232)
    anat_canvas.pack(fill="x")
    ANAT_PAY, ANAT_OH = ACCENT_2, "#FF9F45"   # payload / encap overhead

    def draw_anatomy(_event=None):
        c = anat_canvas
        w = c.winfo_width()
        if w <= 1 or not anatomy_shown["on"]:
            return
        c.delete("all")
        h = int(c["height"])
        m = 4
        _glass(c, m, m, w - m, h - m, r=RADIUS, base=BG, glow=ANAT_PAY,
               glow_alpha=0.12)
        surf = _mix(PANEL_TOP, PANEL_LO, 0.45)
        probe = engine.size
        vx_on = bool(engine.vxlan)
        inner = probe + 28 + (VXLAN_OVERHEAD_UDP if vx_on else 0)
        pieces = ec_wire_view(inner)
        n = len(pieces)
        wan_total = sum(wr for _, wr in pieces)
        tax = (wan_total - inner) / inner * 100.0

        x0, gap, bh = 74, 6, 22
        usable = max(50, w - x0 - 28 - (n - 1) * gap)
        scale = usable / wan_total

        def bar(x, y, wid, color, r=5):
            """One byte-proportional block, lit from the top like everything
            else on the pane so the bars read as objects, not swatches."""
            if wid < 1.2:
                return
            _rr_gradient(c, x, y, x + wid, y + bh, min(r, wid / 2.0),
                         _lighten(color, 0.24), _darken(color, 0.18), step=2)

        c.create_text(20, 24, anchor="w", fill=TXT, font=(FONT, 10, "bold"),
                      text="Wire anatomy — one UDP probe through the fabric")
        c.create_text(w - 20, 24, anchor="e", fill=TXT_FAINT, font=(FONT, 8),
                      text=f"model: tunnel MTU {EC_TUNNEL_MTU} · slice budget "
                           f"{EC_SLICE_BUDGET} B · GCM framing {EC_GCM_FRAMING} B")

        y = 52  # LAN row: the one packet the fabric ingests on lan1
        c.create_text(x0 - 12, y + bh / 2, anchor="e", fill=TXT_DIM,
                      font=(FONT, 9, "bold"), text="LAN")
        bar(x0, y, inner * scale, ANAT_PAY)
        parts = (f"probe {probe:,} + VXLAN {VXLAN_OVERHEAD_UDP} + IP/UDP 28"
                 if vx_on else f"probe {probe:,} + IP/UDP 28")
        df = "DF on" if args.dont_fragment else "DF off"
        c.create_text(x0 + 2, y + bh + 12, anchor="w", fill=TXT_FAINT,
                      font=(FONT, 8), text=f"1 packet · {inner:,} B ({parts}) · {df}")

        y2 = y + bh + 32
        verb = (f"EC encrypts + encapsulates → 1 tunnel packet (no slicing: "
                f"{inner:,} B ≤ {EC_SLICE_BUDGET:,} B budget)" if n == 1 else
                f"EC slices + encapsulates → {n} tunnel packets")
        vid = c.create_text(x0 + 10, y2, anchor="w", fill=ACCENT_HI,
                            font=(FONT, 9, "bold"), text=verb)
        vb = c.bbox(vid)
        _round_rect(c, vb[0] - 9, vb[1] - 4, vb[2] + 9, vb[3] + 4, 9,
                    fill=_over(ACCENT, surf, 0.14))
        c.tag_raise(vid)

        y3 = y2 + 16  # WAN row: the tunnel packets, payload + overhead
        c.create_text(x0 - 12, y3 + bh / 2, anchor="e", fill=TXT_DIM,
                      font=(FONT, 9, "bold"), text="WAN")
        x = x0
        for s, wr in pieces:
            bar(x, y3, wr * scale, ANAT_OH)         # full block = wire bytes
            bar(x, y3, s * scale, ANAT_PAY)         # payload share on top
            if wr * scale >= 48:
                c.create_text(x + wr * scale / 2, y3 + bh + 12,
                              fill=TXT_FAINT, font=(FONT, 8), text=f"{wr:,} B")
            x += wr * scale + gap

        y4 = y3 + bh + 32
        c.create_text(x0, y4, anchor="w", fill=TXT, font=(FONT, 9),
                      text=f"WAN: {n} packet{'s' if n > 1 else ''} · "
                           f"{wan_total:,} B on the wire · +{tax:.1f}% overhead"
                           f" · ×{n} packet amplification")
        pps0 = engine.rate_of_sid.get(0, args.pps)
        c.create_text(x0, y4 + 18, anchor="w", fill=TXT_DIM, font=(FONT, 9),
                      text=f"predicted per UDP stream: {pps0:g} pps LAN → "
                           f"{pps0 * n:g} pps WAN, each direction "
                           f"(echoes are full-size)")
        if inner > 1500:
            frags = -(-(inner - 20) // 1480)  # RFC 791: 1480 B payload per frag
            noec = (f"without the fabric at a 1500 B hop: DF on → PMTUD "
                    f"required (or black hole) · DF off → {frags} IP fragments,"
                    f" only #1 carries the L4 header")
        else:
            noec = "without the fabric: fits a standard 1500 B hop as-is"
        c.create_text(x0, y4 + 36, anchor="w", fill=TXT_FAINT, font=(FONT, 9),
                      text=noec)
        c.create_text(x0, y4 + 54, anchor="w", fill=TXT_FAINT, font=(FONT, 9),
                      text=anat_wan_var.get())

    anat_canvas.bind("<Configure>",
                     lambda _e: None if _RESIZING[0] else draw_anatomy())
    # Measured WAN line inside the anatomy canvas (1.9.0): live counters
    # from --wan-counters next to the model's prediction - the loop closer.
    anat_wan_var = tk.StringVar(value="")

    # ---- topology strip (hidden; Host → EC → fabric → EC → Host with the
    # measured numbers moving, R-15) ------------------------------------------
    topo_frame = tk.Frame(root, bg=BG)
    # not packed here — the Topology toggle packs/unpacks the whole frame
    topo_canvas = tk.Canvas(topo_frame, bg=BG, highlightthickness=0,
                            height=136)
    topo_canvas.pack(fill="x")
    topo_state = {"snap": None}

    def draw_topology(_event=None):
        snap = topo_state["snap"]
        c = topo_canvas
        w = c.winfo_width()
        if w <= 1 or snap is None or not topo_shown["on"]:
            return
        c.delete("all")
        h = int(c["height"])
        m = 4
        _glass(c, m, m, w - m, h - m, r=RADIUS, base=BG, glow=ACCENT,
               glow_alpha=0.12)
        surf = _mix(PANEL_TOP, PANEL_LO, 0.45)
        lan_tx = sum(r["tx_pps"] for r in snap["rows"])
        lan_rx = sum(r["rx_pps"] for r in snap["rows"])
        pred = snap["predicted_wan_pps"]
        wan = snap.get("wan")
        meas = (wan["tx_pps"] if wan and wan["ok"]
                and wan["tx_pps"] is not None else None)
        amp = (meas / max(1.0, lan_tx + lan_rx)) if meas is not None else (
            pred / max(1.0, lan_tx + lan_rx))
        nodes = [("this host", f"{lan_tx:.0f} pps tx"),
                 ("EC (local)", f"×{amp:.2f} amplification"),
                 ("SD-WAN fabric",
                  (f"{meas:.0f} pps measured" if meas is not None
                   else f"{pred:.0f} pps predicted")),
                 ("EC (remote)", "reassembles"),
                 (f"peer {snap['peer']}", f"{lan_rx:.0f} pps back")]
        y0, bh = 26, 48
        avail = w - 40
        gap = max(26, min(46, (avail - 150 * len(nodes)) // max(1, len(nodes) - 1)))
        bw = max(96, (avail - gap * (len(nodes) - 1)) / float(len(nodes)))
        x = 20.0
        for i, (name, sub) in enumerate(nodes):
            hot = (i == 2)                    # the fabric is the subject here
            _glass(c, x, y0, x + bw, y0 + bh, r=RADIUS_SM, base=surf,
                   top=_over(ACCENT if hot else GLASS, surf, 0.22 if hot else 0.10),
                   bottom=_over(ACCENT if hot else GLASS, surf, 0.10 if hot else 0.04),
                   border=_over(ACCENT if hot else GLASS, surf, 0.45 if hot else 0.16),
                   shadow=False)
            c.create_text(x + bw / 2, y0 + 18, text=name,
                          fill=(ACCENT_HI if hot else TXT),
                          font=(FONT, 9, "bold"))
            c.create_text(x + bw / 2, y0 + 34, text=sub, fill=TXT_DIM,
                          font=(FONT, 8))
            if i < len(nodes) - 1:
                ax0, ax1 = x + bw + 5, x + bw + gap - 5
                ay = y0 + bh / 2
                if ax1 > ax0:
                    # forward on top, return underneath: two lanes, each
                    # glowing in its own direction's colour
                    for yy, col, arw in ((ay - 5, ACCENT_HI, "last"),
                                         (ay + 5, "#FF9F45", "first")):
                        c.create_line(ax0, yy, ax1, yy,
                                      fill=_over(col, surf, 0.22), width=6,
                                      capstyle="round")
                        c.create_line(ax0, yy, ax1, yy, fill=col, width=2,
                                      arrow=arw, arrowshape=(7, 8, 3))
            x += bw + gap
        wan_txt = ("WAN span: predicted "
                   f"{pred:.0f} pps"
                   + (f" · measured {meas:.0f} pps ({wan['kind']})"
                      if meas is not None else
                      "  ·  add --wan-counters to measure it"))
        c.create_text(20, y0 + bh + 26, anchor="w", fill=TXT_DIM,
                      font=(FONT, 9), text=wan_txt)

    topo_canvas.bind("<Configure>",
                     lambda _e: None if _RESIZING[0] else draw_topology())

    # ---- sustained load panel (hidden; the burst generator made resident) --
    # A known-quantity UDP load offered WHILE the scored streams keep
    # measuring, so the charts show what the load does to the path. TEST
    # probes are excluded from loss isolation on both ends; the optional
    # square wave is the calibration pattern for diffing WAN-side counters.
    load_gen = LoadGenerator(engine.peer, args.udp_ports[0], bind=args.bind,
                             dont_fragment=args.dont_fragment,
                             timeout=args.timeout)
    load_frame = GlassCard(root, glow=WARN)
    # not packed here — the Load toggle packs/unpacks the whole card
    load_inner = load_frame.body
    LOAD_BG = load_frame.surface
    load_mbps_var = tk.StringVar(value="5")
    load_sq_var = tk.BooleanVar(value=False)
    load_on_var = tk.StringVar(value="10")
    load_off_var = tk.StringVar(value="10")
    load_status_var = tk.StringVar(value="idle")
    load_hdr = tk.Frame(load_inner, bg=LOAD_BG)
    load_hdr.pack(fill="x")
    tk.Label(load_hdr, text="Sustained load", fg=TXT, bg=LOAD_BG,
             font=(FONT, 10, "bold")).pack(side="left")
    tk.Label(load_hdr, text=f"UDP {BURST_PROBE_SIZE} B TEST probes → "
                            f"{engine.peer}:{args.udp_ports[0]} · echoes "
                            f"double the wire load · excluded from loss "
                            f"isolation",
             fg=TXT_FAINT, bg=LOAD_BG, font=(FONT, 8)).pack(side="left",
                                                            padx=(10, 0))
    ctl = tk.Frame(load_inner, bg=LOAD_BG)
    ctl.pack(fill="x", pady=(8, 0))

    def _load_entry(var, width):
        return _glass_entry(tk, ctl, var, width, LOAD_BG, justify="right")

    tk.Label(ctl, text="Mbps", fg=TXT_DIM, bg=LOAD_BG,
             font=(FONT, 9)).pack(side="left")
    _load_entry(load_mbps_var, 6).pack(side="left", padx=(6, 14), ipady=3)
    # A glass toggle rather than a tk.Checkbutton: X11 draws that indicator
    # with a hard 3D bevel that no option can flatten, and one chrome box in
    # the middle of the panel undoes the whole surface treatment.
    sq_btn = GlassButton(ctl, text="⌁  square wave", base=LOAD_BG, toggle=True)

    def _toggle_square():
        load_sq_var.set(not load_sq_var.get())
        sq_btn.set_on(load_sq_var.get())

    sq_btn.configure(command=_toggle_square)
    sq_btn.pack(side="left")
    tk.Label(ctl, text="on s", fg=TXT_DIM, bg=LOAD_BG,
             font=(FONT, 9)).pack(side="left", padx=(10, 0))
    _load_entry(load_on_var, 4).pack(side="left", padx=(6, 0), ipady=3)
    tk.Label(ctl, text="off s", fg=TXT_DIM, bg=LOAD_BG,
             font=(FONT, 9)).pack(side="left", padx=(10, 0))
    _load_entry(load_off_var, 4).pack(side="left", padx=(6, 14), ipady=3)

    def do_load_start():
        if load_gen.running:
            load_gen.stop()
            load_start_btn.configure(text="▶  Start load")
            load_status_var.set("stopped")
            return
        try:
            mbps = float(load_mbps_var.get().strip())
            if not (0 < mbps <= 1000):
                raise ValueError
        except ValueError:
            load_status_var.set("enter a load in Mbps (0 < X ≤ 1000)")
            return
        on_s = off_s = 0.0
        if load_sq_var.get():
            try:
                on_s = float(load_on_var.get().strip())
                off_s = float(load_off_var.get().strip())
                if on_s <= 0 or off_s <= 0:
                    raise ValueError
            except ValueError:
                load_status_var.set("square wave needs positive on/off seconds")
                return
        err = load_gen.start(mbps, on_s, off_s)
        if err:
            load_status_var.set(err)
        else:
            load_start_btn.configure(text="■  Stop load")

    load_start_btn = GlassButton(ctl, text="▶  Start load",
                                 command=do_load_start, base=LOAD_BG,
                                 primary=True, accent=WARN)
    load_start_btn.pack(side="left")
    tk.Label(ctl, textvariable=load_status_var, fg=TXT_DIM, bg=LOAD_BG,
             font=(FONT, 9), anchor="w").pack(side="left", padx=(12, 0))
    if engine.vxlan:
        # A VXLAN-mode peer opens no native UDP listener, so there is
        # nothing to echo the load probes - don't offer a dead button.
        load_start_btn.configure(state="disabled")
        load_status_var.set("unavailable in VXLAN mode (the peer has no "
                            "native UDP listener to echo the load)")

    # ---- charts: latency (top, full width), loss + jitter (bottom row) ----
    # Laid out with grid + row weights, NOT pack: pack hands the space freed
    # by a collapsing sibling (the Totals/Isolate tables) to the first
    # expandable widget only, so after opening and closing Totals the bottom
    # chart row stayed squeezed to a sliver until the app was restarted.
    # Grid weights re-distribute the space proportionally on every geometry
    # pass, so the charts always track the current window size.
    # Chart canvases carry the app base colour, not a panel colour: each one
    # paints its own rounded glass card, and the corners have to resolve
    # against the backdrop for the card to read as a floating pane.
    charts = tk.Frame(root, bg=BG, padx=14, pady=2)
    charts.pack(fill="both", expand=True)
    charts.columnconfigure(0, weight=1)
    charts.rowconfigure(0, weight=3, uniform="charts")
    charts.rowconfigure(1, weight=2, uniform="charts")
    # Small requested sizes: the drawn size is allocation-driven, and modest
    # requests keep the layout solvable at any window size.
    lat_canvas = tk.Canvas(charts, bg=BG, highlightthickness=0,
                           width=100, height=80)
    lat_canvas.grid(row=0, column=0, sticky="nsew", pady=(0, 8))
    bottom = tk.Frame(charts, bg=BG)
    bottom.grid(row=1, column=0, sticky="nsew")
    bottom.rowconfigure(0, weight=1)
    bottom.columnconfigure(0, weight=1, uniform="bottom")
    bottom.columnconfigure(1, weight=1, uniform="bottom")
    bottom.columnconfigure(2, weight=1, uniform="bottom")
    loss_canvas = tk.Canvas(bottom, bg=BG, highlightthickness=0,
                            width=100, height=80)
    loss_canvas.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
    jit_canvas = tk.Canvas(bottom, bg=BG, highlightthickness=0,
                           width=100, height=80)
    jit_canvas.grid(row=0, column=1, sticky="nsew", padx=(4, 4))
    owd_canvas = tk.Canvas(bottom, bg=BG, highlightthickness=0,
                           width=100, height=80)
    owd_canvas.grid(row=0, column=2, sticky="nsew", padx=(4, 0))

    # The panel toggles can only be wired now that both the panels and the
    # charts they insert themselves above exist.
    for _btn, _state, _frame, _cb in (
            (totals_btn, totals_shown, totals_frame, None),
            (isolate_btn, isolate_shown, iso_frame, None),
            (anatomy_btn, anatomy_shown, anat_frame, draw_anatomy),
            (topo_btn, topo_shown, topo_frame, draw_topology),
            (load_btn, load_shown, load_frame, None)):
        _btn.configure(command=_panel_toggle(_state, _frame, _btn, _cb))

    def refresh_body():
        snap = engine.snapshot()

        def metric(value, fmt, color_score):
            if value is None:
                return "--", TXT_FAINT
            return fmt.format(value), score_color(color_score)

        if snap["links_up"] == 0:
            hero_state.update(score=None, label="Waiting for peer",
                              detail=f"peer {args.peer} — no streams up yet",
                              sub=f"peer {args.peer}",
                              mos="--", mos_c=TXT_FAINT,
                              pqi="--", pqi_c=TXT_FAINT)
        else:
            o = snap["overall"]
            mos, mos_c = metric(snap["udp_mos"], "{:.1f}", snap["udp_score"] or 0)
            pqi, pqi_c = metric(snap["tcp_pqi"], "{:.0f}", snap["tcp_pqi"] or 0)
            hero_state.update(
                score=o, label=snap["overall_label"],
                detail=f"worst {snap['worst']:.0f}  ·  "
                       f"{snap['links_up']}/{len(STREAMS)} streams up",
                sub=f"peer {args.peer}  ·  {snap['links_up']}/{len(STREAMS)} "
                    f"streams up",
                mos=mos, mos_c=mos_c, pqi=pqi, pqi_c=pqi_c)
        paint_hero()

        up_s = int(snap["uptime"])
        t = snap["totals"]
        df = "on" if snap["dont_fragment"] else "off"
        size_tag = {"verified": "✓ verified", "mismatch": "⚠ MISMATCH",
                    "pending": "…"}[snap["size_status"]]
        vx = (f"  ·  VXLAN vni {snap['vxlan']['vni']} udp/{snap['vxlan']['port']}"
              if snap["vxlan"] else "")
        bleached = [(r["name"], r["dscp_req"], r["fwd_tos"] >> 2)
                    for r in snap["rows"]
                    if r["dscp_req"] is not None and r["fwd_tos"] is not None
                    and (r["fwd_tos"] >> 2) != r["dscp_req"]]
        if snap.get("udp_silent"):
            warn_var.set("⚠ UDP silent while TCP is up — UDP blocked in the "
                         "path (firewall/ACL) or the peer runs an outdated "
                         "version; update BOTH ends")
        elif bleached:
            name, req, got = bleached[0]
            more = f" (+{len(bleached) - 1} more)" if len(bleached) > 1 else ""
            warn_var.set(f"⚠ DSCP rewritten mid-path: {name} sent "
                         f"{dscp_name(req)}, peer received {dscp_name(got)}"
                         f"{more} — bleaching/remap policy in the path")
        elif snap.get("fec"):
            warn_var.set(f"⚠ {snap['fec']}")
        elif snap.get("loss_pattern"):
            warn_var.set(f"⚠ loss pattern (last 60 s): {snap['loss_pattern']}")
        elif snap.get("slice_evidence"):
            warn_var.set(f"⚠ {snap['slice_evidence']}")
        else:
            warn_var.set("")
        if warn_var.get():
            if not warn_lbl.winfo_ismapped():
                warn_lbl.pack(fill="x", before=foot_path_lbl)
        elif warn_lbl.winfo_ismapped():
            warn_lbl.pack_forget()
        scn = snap.get("scenario")
        if scn:
            if scn["done"]:
                scen_var.set(f"scenario {scn['name']}: finished")
            elif scn["stage"] is not None:
                rep = (f"  ·  pass {scn['pass_n']}"
                       + (f"/{scn['repeat']}" if scn["repeat"] else " (loop)"))
                scen_var.set(f"scenario {scn['name']}:  stage {scn['idx']}/"
                             f"{scn['total']}  “{scn['stage']}”  "
                             f"{scn['remaining']:.0f} s left{rep}")
        else:
            scen_var.set("")
        if scen_var.get():
            if not scen_lbl.winfo_ismapped():
                scen_lbl.pack(fill="x", before=foot_path_lbl)
        elif scen_lbl.winfo_ismapped():
            scen_lbl.pack_forget()
        # Offered probe load (this direction, IP level): with --mbps show
        # achieved vs target so the known quantity is verifiable on screen.
        load_txt = f"  ·  probe load {snap['offered_mbps']:.2f} Mbps"
        if snap.get("target_mbps"):
            load_txt += f" / target {_fmt_num(snap['target_mbps'])}"
        frame_txt = (f"frame {snap['frame_size']} B" if not
                     snap.get("profiles_active") else "frames per profile")
        foot_path_var.set(
            f"peer {args.peer}  ·  {ports_summary()}  ·  "
            f"{frame_txt}  DF {df}  size {size_tag}{vx}"
            f"{load_txt}  ·  "
            f"uptime {up_s // 3600:02d}:{(up_s % 3600) // 60:02d}:{up_s % 60:02d}")
        if load_shown["on"] or load_gen.running:
            st = load_gen.status()
            if st["running"]:
                phase = ("" if not st["square"]
                         else ("  [wave: ON]" if st["phase_on"]
                               else "  [wave: off]"))
                load_status_var.set(
                    f"offering {st['mbps']:g} Mbps{phase}  ·  achieved "
                    f"{st['achieved_mbps']:.2f} Mbps  ·  loss "
                    f"{st['loss_pct']:.1f}%  late {st['late_pct']:.1f}%")
            elif str(load_start_btn.cget("text")).startswith("■"):
                # the generator died on its own (peer gone, socket error)
                load_start_btn.configure(text="▶  Start load")
                load_status_var.set(st["error"] or "stopped")
        # lifetime repeats since-reset until the first reset — show it only
        # once it actually says something different
        life = ("" if t["life_tx"] == t["tx"] and t["life_lost"] == t["lost"]
                else f"  ·  lifetime  sent {t['life_tx']:,}  "
                     f"lost {t['life_lost']:,} ({t['life_loss_pct']:.2f}%)")
        frags = snap.get("frags")
        frag_txt = ""
        if frags:
            frag_txt = (f"  ·  frags {frags['frags']:,}" if frags["ok"]
                        else "  ·  frag sniffer off (needs admin)")
        foot_cnt_var.set(
            f"since reset  sent {t['tx']:,}  recv {t['recv']:,}  "
            f"lost {t['lost']:,} ({t['loss_pct']:.2f}%)  "
            f"fwd→ {t['fwd_lost']:,} ({t['fwd_pct']:.2f}%)  "
            f"rtn← {t['rtn_lost']:,} ({t['rtn_pct']:.2f}%){life}{frag_txt}")

        if topo_shown["on"]:
            topo_state["snap"] = snap
            draw_topology()

        if anatomy_shown["on"]:
            wan = snap.get("wan")
            if wan is None:
                anat_wan_var.set("measured WAN: no counter source — start "
                                 "with --wan-counters sim | snmp:... | "
                                 "rest:... to close the loop")
            elif wan["ok"] and wan["tx_pps"] is not None:
                lan_pps = sum(r["tx_pps"] for r in snap["rows"]) * 2
                anat_wan_var.set(
                    f"measured WAN ({wan['kind']}):  tx {wan['tx_pps']:.0f} "
                    f"pps   rx {wan['rx_pps']:.0f} pps   ·   predicted "
                    f"{snap['predicted_wan_pps']:.0f} pps   ·   ×"
                    f"{wan['tx_pps'] / max(1.0, lan_pps):.2f} vs LAN "
                    f"({lan_pps:.0f} pps)")
            elif wan["ok"]:
                anat_wan_var.set(f"measured WAN ({wan['kind']}): first "
                                 f"poll…")
            else:
                anat_wan_var.set(f"measured WAN ({wan['kind']}): "
                                 f"{wan['detail']}")
            draw_anatomy()   # the measured line lives on the canvas now

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
                full = (row["peer_rx_max"] >= row["expect_size"]
                        and row["rx_echo_max"] >= row["expect_size"])
                if row["size_mismatch"]:
                    size_cell, tag = f"⚠ {row['size_mismatch']}", "bad"
                elif full:
                    size_cell, tag = "OK", "ok"
                else:
                    size_cell, tag = "…", ""
                if row["dscp_req"] is None and row["fwd_tos"] is None:
                    dscp_cell = "-"
                else:
                    f_ = (dscp_name(row["fwd_tos"] >> 2)
                          if row["fwd_tos"] is not None else "?")
                    r_ = (dscp_name(row["rtn_tos"] >> 2)
                          if row["rtn_tos"] is not None else "?")
                    dscp_cell = f"{dscp_name(row['dscp_req'])}→{f_}/{r_}"
                totals_tree.item(f"t{row['sid']}", tags=(tag,), values=(
                    row["name"], f"{row['cum_tx']:,}", f"{row['cum_recv']:,}",
                    f"{row['cum_lost']:,}", f"{row['cum_late']:,}", f"{lossp:.2f}",
                    row["expect_size"], row["peer_rx_max"], row["rx_echo_max"],
                    size_cell, dscp_cell))

        hist = engine.history_copy()
        owd_f, owd_r, band_hist = engine.extra_history_copy()
        marks = engine.markers_copy()
        now = time.monotonic()  # history samples are stamped with monotonic time
        _draw_chart(lat_canvas, "Latency (RTT, ms)", "rtt", series, hist,
                    view_seconds, now, ymin_floor=2.0, unit="",
                    value_fmt=lambda v: f"{v:.1f}" if v < 10 else f"{v:.0f}",
                    band=band_hist, band_label="p5–p95 (UDP)",
                    markers=marks, mark_labels=True)
        _draw_chart(loss_canvas, "Loss + late (%)", "loss", series, hist,
                    view_seconds, now, ymin_floor=2.0, unit="%",
                    value_fmt=lambda v: f"{v:.0f}", markers=marks)
        _draw_chart(jit_canvas, "Jitter (ms)", "jitter", series, hist,
                    view_seconds, now, ymin_floor=1.0, unit="",
                    value_fmt=lambda v: f"{v:.1f}" if v < 10 else f"{v:.0f}",
                    markers=marks)
        # Directional one-way drift: two aggregate lines (mean over live UDP
        # streams), each direction's delay growth above its ~60 s best. The
        # clocks' unknown offset cancels, so only the MOVEMENT is meaningful.
        _draw_chart(owd_canvas, "One-way drift (ms)", "v",
                    [("F", ACCENT_HI, "fwd→"), ("R", "#FF9F45", "rtn←")],
                    {"F": owd_f, "R": owd_r},
                    view_seconds, now, ymin_floor=2.0, unit="",
                    value_fmt=lambda v: f"{v:.1f}" if v < 10 else f"{v:.0f}",
                    markers=marks)

    # ---- resize coalescing --------------------------------------------------
    # A toplevel's name is in every descendant's bindtags, so this fires for
    # child <Configure>s too - and it fires on window MOVES, which currently
    # cost nothing and must keep costing nothing. Hence both filters.
    RESIZE_SETTLE_MS = 110
    resize = {"job": None, "wh": None}

    def _resize_settle():
        resize["job"] = None
        _RESIZING[0] = False
        try:
            _toolbar_relayout()
            paint_hero()
            rule.delete("all")
            _draw_hairline(rule, 0, 0, rule.winfo_width())
            for _card in (totals_frame, iso_frame, load_frame):
                if _card.winfo_ismapped():
                    _card._repaint()
            draw_anatomy()
            draw_topology()
            refresh_body()
        except tk.TclError:
            pass                       # window went away mid-drag

    def _on_root_configure(event):
        if event.widget is not root:
            return
        wh = (event.width, event.height)
        if wh == resize["wh"]:
            return                     # a move, not a resize
        resize["wh"] = wh
        _RESIZING[0] = True
        if resize["job"] is not None:
            root.after_cancel(resize["job"])
        resize["job"] = root.after(RESIZE_SETTLE_MS, _resize_settle)

    root.bind("<Configure>", _on_root_configure)

    def refresh():
        # One bad tick must not kill the whole update chain: on an unattended
        # demo screen a single swallowed exception used to freeze the UI on
        # stale numbers forever while probing kept running underneath.
        try:
            if not _RESIZING[0]:
                refresh_body()   # the settle pass repaints once, at final size
        except tk.TclError:
            return  # window is being torn down
        except Exception:
            traceback.print_exc()
        try:
            root.after(args.refresh_ms, refresh)
        except tk.TclError:
            pass

    def on_close():
        load_gen.stop()
        engine.shutdown()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(120, refresh)  # let the window realize its size first
    root.mainloop()


# ---------------------------------------------------------------------------
# Mesh GUI (--peers): a row per pair, charts for the selected pair
# ---------------------------------------------------------------------------
def run_mesh_gui(engine, args):
    ui = (os.environ.get("NV_UI") or "web").strip().lower()
    if ui != "tk":
        try:
            import nv_webui
            return nv_webui.run_web_mesh(sys.modules[__name__], engine, args)
        except Exception as e:
            print(f"web UI unavailable ({e}) - falling back to Tk mesh UI.",
                  file=sys.stderr)
    return run_mesh_gui_tk(engine, args)


def run_mesh_gui_tk(engine, args):
    import tkinter as tk

    view_seconds = float(args.history)
    series = [(sid, stream_color(sid), name.split("-")[1])
              for sid, proto, port, name in STREAMS]
    peers = engine.peers

    root = tk.Tk()
    _resolve_fonts(root)
    _set_window_icon(root)
    root.title(f"Network Vitals {__version__}  -  mesh, {len(peers)} peers")
    root.geometry("1260x820")
    root.minsize(700, 500)
    root.configure(bg=BG)
    GlassButton = _glass_widgets()["button"]

    # ---- hero band --------------------------------------------------------
    HERO_H = 82
    hero = tk.Canvas(root, bg=BG, highlightthickness=0, bd=0, height=HERO_H)
    hero.pack(fill="x", side="top")
    mesh_state = {"sub": "", "worst": None}
    mesh_hero_sig = {"v": None}

    def paint_hero(_e=None):
        w = hero.winfo_width()
        if w < 10:
            return
        # Everything here is a pure function of these values, and the refresh
        # loop calls it twice a second whether they moved or not.
        worst = mesh_state["worst"]
        sig = (w, mesh_state["sub"],
               None if worst is None else (round(worst[0]), worst[1]))
        if sig == mesh_hero_sig["v"]:
            return
        mesh_hero_sig["v"] = sig
        hero.delete("all")
        _draw_aurora(hero, w, HERO_H)
        _draw_ekg(hero, dx=20, dy=HERO_H / 2 - 20, width=2)
        title = hero.create_text(84, HERO_H / 2 - 9, anchor="w",
                                 text="Network Vitals", fill=TXT,
                                 font=(FONT, 18, "bold"))
        hero.create_text(85, HERO_H / 2 + 13, anchor="w",
                         text=mesh_state["sub"] or f"{len(peers)} peers",
                         fill=TXT_DIM, font=(FONT, 9))
        # "mesh" badge, so the two window types are never confused at a
        # glance. Placed off the measured title box, not a guessed offset -
        # the resolved UI face is not known until the window exists.
        bx = hero.bbox(title)[2] + 12
        bid = hero.create_text(bx + 10, HERO_H / 2 - 8, text="MESH",
                               fill=ACCENT_HI, font=(FONT, 8, "bold"),
                               anchor="w")
        bb = hero.bbox(bid)
        _round_rect(hero, bx, bb[1] - 5, bb[2] + 10, bb[3] + 5, 9,
                    fill=_over(ACCENT, BG, 0.20),
                    outline=_over(ACCENT, BG, 0.45))
        hero.tag_raise(bid)
        worst = mesh_state["worst"]
        if worst is not None and w >= 560:
            _score_orb(hero, w - 22 - 30, HERO_H / 2, 30, worst[0],
                       score_color(worst[0]), base=BG)
            hero.create_text(w - 88, HERO_H / 2 - 9, anchor="e",
                             text="WORST PAIR", fill=TXT_FAINT,
                             font=(FONT, 7, "bold"))
            hero.create_text(w - 88, HERO_H / 2 + 9, anchor="e",
                             text=worst[1], fill=TXT, font=(FONT, 12, "bold"))

    hero.bind("<Configure>", paint_hero)

    tools = tk.Frame(root, bg=BG, height=40)
    tools.pack(fill="x", side="top", padx=14, pady=(2, 8))
    tools.pack_propagate(False)

    def do_update():
        open_update_dialog(root, args.update_url,
                           relaunch_argv=getattr(args, "_argv", None))

    _flow_layout(tools, [GlassButton(tools, text="↺  Reset", command=engine.reset),
                         GlassButton(tools, text="⟳  Update", command=do_update)])

    # ---- pair matrix: one row per peer, click to select --------------------
    # Local vantage only (phase 1): this node's half of the full N x N mesh.
    # Drawn on a Canvas rather than assembled from Labels: a selected row can
    # then be a lit glass slab with a rounded edge and an accent rail, which
    # no grid of opaque Labels can be.
    COLS = [("peer", "Peer", 0.24, "w"), ("score", "Score", 0.09, "center"),
            ("label", "State", 0.13, "w"), ("rtt", "RTT ms", 0.10, "e"),
            ("loss", "Loss %", 0.10, "e"), ("jit", "Jitter", 0.10, "e"),
            ("up", "Up", 0.08, "center"), ("flag", "", 0.16, "w")]
    ROW_H, HEAD_H = 34, 24
    matrix = tk.Canvas(root, bg=BG, highlightthickness=0, bd=0,
                       height=HEAD_H + ROW_H * len(peers) + 22)
    matrix.pack(fill="x", padx=14)
    sel = {"peer": peers[0]}
    rows_data = {p: {} for p in peers}

    def _col_x(w):
        """Resolve the fractional column widths against the current width."""
        x0, inner = 14, w - 28 - 24
        out = []
        x = x0 + 12
        for key, title, frac, anchor in COLS:
            out.append((key, title, x, x + inner * frac, anchor))
            x += inner * frac
        return out

    matrix_sig = {"v": None}

    def draw_matrix(_e=None):
        w = matrix.winfo_width()
        if w < 40:
            return
        sig = (w, sel["peer"],
               tuple(tuple(sorted(rows_data[pp].items())) for pp in peers))
        if sig == matrix_sig["v"]:
            return
        matrix_sig["v"] = sig
        matrix.delete("all")
        h = HEAD_H + ROW_H * len(peers) + 14
        _glass(matrix, 4, 4, w - 4, h, r=RADIUS, base=BG, glow=ACCENT_2,
               glow_alpha=0.10)
        surf = _mix(PANEL_TOP, PANEL_LO, 0.45)
        cols = _col_x(w)
        for key, title, cx0, cx1, anchor in cols:
            tx = {"w": cx0, "e": cx1 - 8, "center": (cx0 + cx1) / 2}[anchor]
            matrix.create_text(tx, 4 + HEAD_H / 2 + 4, anchor=(
                {"w": "w", "e": "e", "center": "center"}[anchor]),
                text=title, fill=TXT_FAINT, font=(FONT, 8, "bold"))
        for i, p in enumerate(peers):
            y0 = 4 + HEAD_H + 6 + i * ROW_H
            y1 = y0 + ROW_H - 4
            d = rows_data[p]
            on = (p == sel["peer"])
            if on:
                _rr_gradient(matrix, 14, y0, w - 14, y1, RADIUS_SM,
                             _over(ACCENT, surf, 0.17),
                             _over(ACCENT, surf, 0.07), step=2)
                _round_rect(matrix, 14, y0, w - 14, y1, RADIUS_SM, fill="",
                            outline=_over(ACCENT, surf, 0.40), width=1)
                matrix.create_line(19, y0 + 7, 19, y1 - 7, fill=ACCENT_HI,
                                   width=3, capstyle="round")
            elif i % 2:
                _rr_gradient(matrix, 14, y0, w - 14, y1, RADIUS_SM,
                             _over(GLASS, surf, 0.035),
                             _over(GLASS, surf, 0.035), step=3)
            cy = (y0 + y1) / 2
            for key, _t, cx0, cx1, anchor in cols:
                val = d.get(key, "-")
                if key == "score":
                    col = d.get("score_color") or TXT_FAINT
                    mx = (cx0 + cx1) / 2
                    _round_rect(matrix, mx - 21, cy - 11, mx + 21, cy + 11, 9,
                                fill=_over(col, surf, 0.20),
                                outline=_over(col, surf, 0.50))
                    matrix.create_text(mx, cy, text=val, fill=col,
                                       font=(FONT, 11, "bold"))
                    continue
                fill, font = TXT, (FONT, 10)
                if key == "peer":
                    fill, font = (TXT if on else _mix(TXT, TXT_DIM, 0.3)), \
                                 (FONT, 10, "bold")
                elif key == "flag":
                    fill, font = WARN, (FONT, 8, "bold")
                elif key in ("label", "up"):
                    fill = TXT_DIM
                tx = {"w": cx0, "e": cx1 - 8, "center": (cx0 + cx1) / 2}[anchor]
                matrix.create_text(tx, cy, text=val, fill=fill, font=font,
                                   anchor={"w": "w", "e": "e",
                                           "center": "center"}[anchor])

    def on_matrix_click(event):
        i = int((event.y - 4 - HEAD_H - 6) // ROW_H)
        if 0 <= i < len(peers):
            sel["peer"] = peers[i]
            draw_matrix()

    matrix.bind("<Configure>", draw_matrix)
    matrix.bind("<Button-1>", on_matrix_click)
    matrix.configure(cursor="hand2")

    def select_peer(p):
        sel["peer"] = p
        draw_matrix()

    # ---- footer + charts for the selected pair ----------------------------
    footer = tk.Frame(root, bg=BG, padx=18)
    footer.pack(fill="x", side="bottom")
    rule = tk.Canvas(footer, bg=BG, highlightthickness=0, height=1)
    rule.pack(fill="x", pady=(0, 8))
    rule.bind("<Configure>", lambda _e: None if _RESIZING[0] else
              (rule.delete("all"),
               _draw_hairline(rule, 0, 0, rule.winfo_width())))
    foot_var = tk.StringVar(value="")
    tk.Label(footer, textvariable=foot_var, fg=TXT_DIM, bg=BG,
             font=(FONT, 9), anchor="w").pack(fill="x", pady=(0, 10))

    charts = tk.Frame(root, bg=BG, padx=14, pady=6)
    charts.pack(fill="both", expand=True)
    charts.columnconfigure(0, weight=1)
    charts.rowconfigure(0, weight=3, uniform="charts")
    charts.rowconfigure(1, weight=2, uniform="charts")
    lat_canvas = tk.Canvas(charts, bg=BG, highlightthickness=0,
                           width=100, height=80)
    lat_canvas.grid(row=0, column=0, sticky="nsew", pady=(0, 8))
    bottom = tk.Frame(charts, bg=BG)
    bottom.grid(row=1, column=0, sticky="nsew")
    bottom.rowconfigure(0, weight=1)
    canvases = []
    for c in range(3):
        bottom.columnconfigure(c, weight=1, uniform="bottom")
        cv = tk.Canvas(bottom, bg=BG, highlightthickness=0,
                       width=100, height=80)
        cv.grid(row=0, column=c, sticky="nsew",
                padx=((0, 4), (4, 4), (4, 0))[c])
        canvases.append(cv)
    loss_canvas, jit_canvas, owd_canvas = canvases

    def refresh_body():
        worst = None
        for p in peers:
            snap = engine.snapshot(p)
            d = rows_data[p]
            t = snap["totals"]
            d["peer"] = p
            if snap["links_up"]:
                o = snap["overall"]
                if worst is None or o < worst[0]:
                    worst = (o, p)
                live = [r for r in snap["rows"] if r["connected"]]
                rtt = sum(r["rtt_avg"] for r in live) / len(live)
                jit = max(r["jitter"] for r in live)
                d["score"] = f"{o:.0f}"
                d["score_color"] = score_color(o)
                d["label"] = snap["overall_label"]
                d["rtt"] = f"{rtt:.1f}"
                d["jit"] = f"{jit:.1f}"
            else:
                d["score"], d["score_color"] = "--", None
                d["label"] = "no link"
                d["rtt"] = d["jit"] = "-"
            d["loss"] = f"{t['loss_pct']:.2f}"
            d["up"] = f"{snap['links_up']}/{len(STREAMS)}"
            d["flag"] = ("⚠ UDP silent — blocked or old peer version"
                         if snap["udp_silent"] else (snap["loss_pattern"] or ""))
        mesh_state["worst"] = worst
        mesh_state["sub"] = (f"{len(peers)} peers  ·  worst pair "
                             f"{worst[1]} ({worst[0]:.0f})" if worst else
                             f"{len(peers)} peers  ·  waiting for links")
        paint_hero()
        draw_matrix()

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
                    [("F", ACCENT_HI, "fwd→"), ("R", "#FF9F45", "rtn←")],
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
    rate_txt = (f"target {args.mbps:g} Mbps" if args.mbps
                else f"{args.pps:g} probes/s/stream")
    print(f"Network Vitals {__version__}  peer={args.peer}  bind={args.bind}  "
          f"{ports_summary()}  {rate_txt}")
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
            load_txt = f"   probe load {snap['offered_mbps']:.2f} Mbps"
            if snap.get("target_mbps"):
                load_txt += f" / target {_fmt_num(snap['target_mbps'])}"
            frame_txt = (f"frame {snap['frame_size']} B"
                         if not snap.get("profiles_active")
                         else "frames per profile")
            print("  " + "-" * 100)
            print(f"  {frame_txt}   DF {df}   size {size_tag}{vx}"
                  f"{load_txt}   (UDP peer-RX / my-RX per stream:"
                  + "".join(f"  {r['name'].split('-')[1]} {r['peer_rx_max']}/{r['rx_echo_max']}"
                            for r in snap["rows"] if r["proto"] == "UDP") + ")")
            if any(r["dscp_req"] is not None or r["fwd_tos"] is not None
                   for r in snap["rows"]):
                def _dn(tos):
                    return dscp_name(tos >> 2) if tos is not None else "?"
                print("  DSCP req→fwd/rtn:  " + "   ".join(
                    f"{r['name'].split('-')[1]} "
                    f"{dscp_name(r['dscp_req'])}→{_dn(r['fwd_tos'])}/"
                    f"{_dn(r['rtn_tos'])}"
                    for r in snap["rows"]))
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
            wan = snap.get("wan")
            if wan:
                if wan["ok"] and wan["tx_pps"] is not None:
                    print(f"  WAN ({wan['kind']}):  tx {wan['tx_pps']:.0f} pps"
                          f"   rx {wan['rx_pps']:.0f} pps   predicted "
                          f"{snap['predicted_wan_pps']:.0f} pps")
                else:
                    print(f"  WAN ({wan['kind']}): "
                          f"{'first poll...' if wan['ok'] else wan['detail']}")
            scn = snap.get("scenario")
            if scn and scn["done"]:
                print(f"  scenario {scn['name']}: finished")
            elif scn and scn["stage"] is not None:
                rep = (f"  pass {scn['pass_n']}"
                       + (f"/{scn['repeat']}" if scn["repeat"] else " (loop)"))
                print(f"  scenario {scn['name']}: stage {scn['idx']}/"
                      f"{scn['total']} '{scn['stage']}'  "
                      f"{scn['remaining']:.0f}s left{rep}")
            frags = snap.get("frags")
            if frags:
                print("  frag sniffer: "
                      + (f"{frags['frags']:,} fragments seen "
                         f"({frags['firsts']:,} fragmented datagrams)"
                         if frags["ok"] else frags["error"] or "off"))
            if snap.get("udp_silent"):
                print("  ! UDP silent while TCP is up: UDP blocked in the path "
                      "(firewall/ACL) or the peer runs an outdated version - "
                      "update BOTH ends.")
            elif snap.get("fec"):
                print(f"  ! {snap['fec']}")
            elif snap.get("loss_pattern"):
                print(f"  ! loss pattern (last 60 s): {snap['loss_pattern']}")
            elif snap.get("slice_evidence"):
                print(f"  ! {snap['slice_evidence']}")
            if keys.enabled:
                print("  keys:  [r] reset counters    [w] write report    "
                      "[q] quit    (Ctrl-C also quits)")
            key = keys.poll(args.refresh_ms / 1000.0)
            if key == "r":
                engine.reset()
            elif key == "w":
                try:
                    _jp, hp = write_report(engine, args)
                    print(f"\n  report written: {hp}")
                except OSError as e:
                    print(f"\n  report failed: {e}")
                time.sleep(1.5)   # visible before the next screen clear
            elif key in ("q", "\x03"):   # 'q', or Ctrl-C swallowed by getwch
                return


# ---------------------------------------------------------------------------
# Self-update: fetch and VERIFY a signed release manifest from UPDATE_URL, then
# replace ourselves in place with the artifact it names. Only runs when explicitly
# requested (--update / --check-update / update.bat) — a measurement tool must not
# phone home on its own, and a surprise fetch would skew the very numbers it reports.
# Verification (RSA signature over the manifest + SHA-256 of the artifact) fails
# closed on any problem; see UPDATE_SECURITY.md.
# ---------------------------------------------------------------------------
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


def _download_bytes(url, timeout, max_bytes):
    """Download `url` (bounded), reusing the Windows certificate-store fallback for
    corporate TLS-inspecting proxies. Returns raw bytes; raises RuntimeError."""
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            # urllib follows https->http redirects; fetching code over plaintext is
            # where the line is, so refuse the downgrade.
            final = getattr(resp, "url", None) or url
            if (url.lower().startswith("https:")
                    and not final.lower().startswith("https:")):
                raise RuntimeError(f"refusing redirect to insecure URL {final}")
            raw = resp.read(max_bytes + 1)
    except (urllib.error.URLError, OSError) as e:
        cert_issue = _is_cert_error(e)
        if (cert_issue and sys.platform == "win32"
                and url.lower().startswith("https:")):
            # Python's own trust chain failed - retry through the Windows certificate
            # store (see _download_via_windows_tls). Normal behind corporate proxies.
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
    if len(raw) > max_bytes:
        raise RuntimeError("update response was larger than expected - refusing.")
    return raw


# ---------------------------------------------------------------------------
# Release-manifest signature verification (RSA-2048 / SHA-256 PKCS#1 v1.5), pure
# stdlib. RSA verify is modular exponentiation with the public exponent; PKCS#1
# v1.5 verify is a STRICT comparison against the fully reconstructed padded block
# (no lax parsing -> no forgery). Interoperates with `openssl dgst -sha256 -sign`.
# ---------------------------------------------------------------------------
_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _der_read(data, i):
    """Read one DER TLV. Returns (tag, value_bytes, next_index)."""
    if i + 2 > len(data):
        raise RuntimeError("truncated DER")
    tag = data[i]
    ln = data[i + 1]
    i += 2
    if ln & 0x80:
        nbytes = ln & 0x7F
        if nbytes == 0 or i + nbytes > len(data):
            raise RuntimeError("bad DER length")
        ln = int.from_bytes(data[i:i + nbytes], "big")
        i += nbytes
    if i + ln > len(data):
        raise RuntimeError("DER value exceeds buffer")
    return tag, data[i:i + ln], i + ln


def _parse_rsa_pub(pem):
    """Extract (n, e) from an RSA public key PEM (SubjectPublicKeyInfo or PKCS#1)."""
    body = re.sub(r"-----[^-]+-----", "", pem).replace("\n", "").replace("\r", "").strip()
    try:
        der = base64.b64decode(body, validate=True)   # binascii.Error is a ValueError
    except ValueError as e:
        raise RuntimeError(f"public key is not valid base64: {e}") from e
    if "BEGIN RSA PUBLIC KEY" in pem:                  # PKCS#1 RSAPublicKey
        _, seq, _ = _der_read(der, 0)
        _, nb, k = _der_read(seq, 0)
        _, eb, _ = _der_read(seq, k)
        return int.from_bytes(nb, "big"), int.from_bytes(eb, "big")
    _, spki, _ = _der_read(der, 0)                     # SubjectPublicKeyInfo
    _, _alg, j = _der_read(spki, 0)                    # AlgorithmIdentifier
    tag_bs, bs, _ = _der_read(spki, j)                 # BIT STRING
    if tag_bs != 0x03 or not bs:
        raise RuntimeError("malformed public key (expected BIT STRING)")
    _, seq, _ = _der_read(bs[1:], 0)                   # drop 'unused bits' byte
    _, nb, k = _der_read(seq, 0)
    _, eb, _ = _der_read(seq, k)
    return int.from_bytes(nb, "big"), int.from_bytes(eb, "big")


def verify_rsa_sha256(pubkey_pem, message, signature):
    """True iff `signature` is a valid RSA/SHA-256 PKCS#1 v1.5 signature over `message`
    under `pubkey_pem`. Never raises for a bad signature - returns False."""
    try:
        n, e = _parse_rsa_pub(pubkey_pem)
    except RuntimeError:
        return False
    if n <= 0 or e <= 0:
        return False
    k = (n.bit_length() + 7) // 8
    if k < 64 or len(signature) != k:                  # RSA-2048 => k == 256
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    digest_info = _SHA256_DIGESTINFO + hashlib.sha256(message).digest()
    ps_len = k - 3 - len(digest_info)
    if ps_len < 8:
        return False
    expected = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + digest_info
    return hmac.compare_digest(em, expected)


def _ver_tuple(s):
    """Order-comparable version tuple: plain 'X.Y[.Z]' releases and
    'X.Y.ZaN' alpha pre-releases ('1.8.0a2'). An alpha sorts BELOW its
    final (1.8.0a1 < 1.8.0a2 < 1.8.0 < 1.8.1a1), so UAT machines move
    a1 -> a2 -> final through the normal signed updater. The tuple is
    (major, minor, patch, is_final, alpha_n); unparseable -> None."""
    m = re.fullmatch(r"\s*v?(\d+)\.(\d+)(?:\.(\d+))?(?:a(\d+))?\s*", s or "")
    if m:
        major, minor, patch, alpha = m.groups()
        return (int(major), int(minor), int(patch or 0),
                1 if alpha is None else 0,
                int(alpha) if alpha is not None else 0)
    # Fallback for anything odd a manifest might carry: first three number
    # groups, treated as a final release (pre-1.8.0 behavior, widened).
    nums = re.findall(r"\d+", s or "")[:3]
    if not nums:
        return None
    parts = tuple(int(x) for x in nums)
    return parts + (0,) * (3 - len(parts)) + (1, 0)


def _parse_manifest(manifest_bytes):
    try:
        m = json.loads(manifest_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise RuntimeError(f"manifest is not valid JSON/UTF-8: {e}") from e
    if not isinstance(m, dict):
        raise RuntimeError("manifest is not an object")
    for key in ("version", "artifact", "sha256"):
        if not isinstance(m.get(key), str):
            raise RuntimeError(f"manifest missing string field {key!r}")
    if m["artifact"] != "netquality.py":
        raise RuntimeError(f"unexpected artifact name {m['artifact']!r}")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", m["sha256"]):
        raise RuntimeError("manifest sha256 is not a 64-hex digest")
    if _ver_tuple(m["version"]) is None:
        raise RuntimeError("manifest version is not parseable")
    return m


def check_update(url, timeout=15):
    """Fetch + verify the SIGNED release manifest at `url`. Returns the manifest dict for
    a strictly newer, correctly-signed release, or None if up to date. Raises RuntimeError
    and fails closed on any verification failure."""
    if not UPDATE_PUBKEY or "BEGIN" not in UPDATE_PUBKEY:
        raise RuntimeError("no update public key configured - refusing to update.")
    manifest = _download_bytes(url, timeout, 64 * 1024)
    sig = _download_bytes(url + ".sig", timeout, 4096)
    if not verify_rsa_sha256(UPDATE_PUBKEY, manifest, sig):
        raise RuntimeError("manifest signature did not verify - refusing (fail closed).")
    m = _parse_manifest(manifest)
    if _ver_tuple(m["version"]) <= _ver_tuple(__version__):
        return None
    return m


def download_and_install(manifest, url, timeout=30, target=None):
    """Download the artifact named by an already-verified manifest, check its SHA-256,
    install atomically (.new -> os.replace, previous copy kept as .bak), and re-verify the
    on-disk bytes before returning (closes the fetch->exec TOCTOU). Raises RuntimeError;
    never leaves a partial file. `target` defaults to this file (tests pass a temp path)."""
    if getattr(sys, "frozen", False):
        raise RuntimeError("this is a packaged .exe — it can't replace "
                           "itself. Download the new version (or rebuild "
                           "with build_exe.bat).")
    want = manifest["sha256"].lower()
    base = url.rsplit("/", 1)[0]
    data = _download_bytes(base + "/" + manifest["artifact"], timeout, 16 * 1024 * 1024)
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), want):
        raise RuntimeError("artifact sha256 does not match the signed manifest - refusing.")
    # Corruption checks (NOT trust - the signature is the trust): valid Python, and ours.
    try:
        src = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise RuntimeError(f"artifact is not UTF-8 text: {e}") from e
    try:
        compile(src, "netquality.py", "exec")
    except SyntaxError as e:
        raise RuntimeError(f"artifact does not compile: {e}") from e
    if "MAGIC" not in src or "Network Vitals" not in src:
        raise RuntimeError("artifact doesn't look like Network Vitals - refusing.")
    target = target or os.path.abspath(__file__)
    backup = target + ".bak"
    tmp = target + ".new"
    try:
        with open(target, "rb") as fh:
            current = fh.read()
        with open(backup, "wb") as fh:
            fh.write(current)
        with open(tmp, "wb") as fh:
            fh.write(data)
        with open(tmp, "rb") as fh:      # re-verify the on-disk bytes before the swap
            if not hmac.compare_digest(hashlib.sha256(fh.read()).hexdigest(), want):
                raise RuntimeError("on-disk artifact failed re-verification - refusing.")
        os.replace(tmp, target)          # atomic on the same filesystem
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
    """Check (and optionally install) the latest SIGNED version. Returns an exit code:
    0 = up to date / updated, 1 = failed, 3 = update available (check mode only, so
    scripts can branch on it). Fails closed on any verification failure."""
    print(f"Network Vitals {__version__}")
    print(f"Checking {url} …")
    try:
        m = check_update(url)
    except RuntimeError as e:
        print(f"Update check failed: {e}", file=sys.stderr)
        return 1
    if m is None:
        print("Already up to date.")
        return 0
    print(f"New signed version available: {m['version']}")
    if not apply:
        return 3
    try:
        target = download_and_install(m, url)
    except RuntimeError as e:
        print(f"Install failed: {e}", file=sys.stderr)
        return 1
    print(f"Updated {os.path.basename(target)} {__version__} -> {m['version']}.")
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
    mbps_raw = str(vals.get("mbps") or "").strip()
    if mbps_raw:
        mbps = num("Target Mbps", mbps_raw, float, 0.001, 1000.0)
        argv += ["--mbps", _fmt_num(mbps)]
    if vals["dont_fragment"]:
        argv += ["--dont-fragment"]

    bind = (vals.get("bind") or "").strip() or "0.0.0.0"
    if bind != "0.0.0.0":
        argv += ["--bind", bind]
    for label, key, flag, parser, default in (
            ("UDP ports", "udp_ports", "--udp-ports", _udp_port_list,
             DEFAULT_UDP_PORTS),
            ("TCP ports", "tcp_ports", "--tcp-ports", _tcp_port_list,
             DEFAULT_TCP_PORTS)):
        raw = (vals.get(key) or "").strip()
        if raw:
            try:
                ports = parser(raw)
            except argparse.ArgumentTypeError as e:
                raise ValueError(f"{label}: {e}")
            if ports != default:
                argv += [flag, ",".join(map(str, ports)) or "none"]
    for label, key, flag, parser in (
            ("Profiles", "profiles", "--profiles", _profile_list),
            ("DSCP", "dscp", "--dscp", _dscp_list)):
        raw = str(vals.get(key) or "").strip()
        if raw:
            try:
                parser(raw)
            except argparse.ArgumentTypeError as e:
                raise ValueError(f"{label}: {e}")
            argv += [flag, raw]
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
    _set_window_icon(dlg)
    head = tk.Canvas(dlg, bg=BG, highlightthickness=0, bd=0, height=46)
    head.pack(fill="x")

    def _paint_head(_e=None):
        w = head.winfo_width()
        if w < 10:
            return
        head.delete("all")
        _draw_aurora(head, w, 46)
        _draw_ekg(head, dx=14, dy=6, width=2)
        head.create_text(76, 23, anchor="w", text=title, fill=TXT,
                         font=(FONT, 11, "bold"))

    head.bind("<Configure>", _paint_head)
    # The tool output is a terminal transcript, so it keeps a recessed well
    # and a mono face rather than pretending to be a document.
    txt = tk.Text(dlg, width=76, height=18, bg=_over("#000000", BG, 0.45),
                  fg=TXT_DIM, relief="flat", font=(FONT_MONO, 9),
                  state="disabled", wrap="none", highlightthickness=1,
                  highlightbackground=GRID, highlightcolor=GRID,
                  insertbackground=ACCENT_HI, padx=12, pady=10,
                  selectbackground=_over(ACCENT, BG, 0.35))
    txt.pack(fill="both", expand=True, padx=14, pady=(4, 14))

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

    GlassButton = _glass_widgets()["button"]
    GlassCard = _glass_widgets()["card"]

    dlg = tk.Toplevel(root)
    root._nq_update_dialog = dlg
    dlg.title("Network Vitals update")
    dlg.configure(bg=BG)
    _set_window_icon(dlg)
    dlg.resizable(False, False)
    dlg.transient(root)

    card = GlassCard(dlg, glow=ACCENT, padx=20, pady=18)
    card.pack(fill="both", expand=True, padx=14, pady=(14, 8))
    SURF = card.surface
    ver = tk.Frame(card.body, bg=SURF)
    ver.pack(anchor="w", fill="x")
    tk.Label(ver, text="INSTALLED", fg=TXT_FAINT, bg=SURF,
             font=(FONT, 7, "bold")).pack(side="left", pady=(4, 0))
    tk.Label(ver, text=f"v{__version__}", fg=TXT, bg=SURF,
             font=(FONT, 13, "bold")).pack(side="left", padx=(8, 0))
    status_var = tk.StringVar(value="Checking ...")
    tk.Label(card.body, textvariable=status_var, fg=TXT_DIM, bg=SURF,
             font=(FONT, 10), wraplength=430, justify="left",
             anchor="w").pack(anchor="w", fill="x", pady=(10, 0))

    btns = tk.Frame(dlg, bg=BG, padx=14, pady=(0))
    btns.pack(anchor="e", fill="x", pady=(0, 10))

    def mkbtn(text, cmd, primary=False):
        return GlassButton(btns, text=text, command=cmd, primary=primary)

    state = {"manifest": None, "vstr": None}
    outcome = {}  # worker thread -> UI poll loop; workers never touch Tk

    def check_worker():
        # Catch EVERYTHING: check_update wraps the expected failures in RuntimeError,
        # but a scheme-less --update-url raises ValueError and a misbehaving proxy
        # raises http.client exceptions - any escape would kill this thread and leave
        # the dialog on "Checking" forever.
        try:
            m = check_update(update_url)
            if m is None:
                outcome["check"] = ("uptodate", __version__)
            else:
                outcome["check"] = ("available", m)
        except Exception as e:
            outcome["check"] = ("error", str(e) or e.__class__.__name__)

    def install_worker():
        try:
            download_and_install(state["manifest"], update_url)
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

    check_btn = mkbtn("⟳  Check again", do_check)
    install_btn = mkbtn("⭳  Install and restart", do_install, primary=True)
    close_btn = mkbtn("Close", dlg.destroy)
    close_btn.pack(side="right")
    check_btn.pack(side="right", padx=(0, 2))
    # install_btn is packed only once an update is actually available

    def poll():
        if "check" in outcome:
            kind, val = outcome.pop("check")
            check_btn.configure(state="normal")
            if kind == "uptodate":
                status_var.set(f"You're on the latest version ({val}).")
            elif kind == "available":
                state["manifest"], state["vstr"] = val, val["version"]
                status_var.set(f"Version {state['vstr']} is available.")
                install_btn.configure(state="normal")
                install_btn.pack(side="right", padx=(0, 2))
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
    ui = (os.environ.get("NV_UI") or "web").strip().lower()
    if ui != "tk":
        try:
            import nv_webui
            return nv_webui.run_web_launcher(sys.modules[__name__],
                                            update_url=update_url)
        except Exception as e:
            print(f"web launcher unavailable ({e}) - falling back to Tk.",
                  file=sys.stderr)
    return run_launcher_tk(update_url)


def run_launcher_tk(update_url=UPDATE_URL):
    """Legacy glass Tk launcher."""
    import tkinter as tk
    from tkinter import messagebox, ttk

    try:
        root = tk.Tk()
    except tk.TclError as e:
        raise RuntimeError(str(e)) from e
    _set_window_icon(root)

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

    GlassButton = _glass_widgets()["button"]
    GlassCard = _glass_widgets()["card"]
    SURF = CARD_SURFACE                      # what the form sits on
    WELL = _over("#000000", SURF, 0.28)      # recessed field fill

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("NQ.TCombobox", fieldbackground=WELL, background=WELL,
                    foreground=TXT, arrowcolor=TXT_DIM,
                    bordercolor=_over(GLASS, SURF, 0.16), lightcolor=WELL,
                    darkcolor=WELL, insertcolor=ACCENT_HI,
                    selectbackground=_over(ACCENT, SURF, 0.40),
                    selectforeground=TXT, padding=4)
    style.map("NQ.TCombobox", bordercolor=[("focus", ACCENT)],
              arrowcolor=[("active", ACCENT_HI)])
    root.option_add("*TCombobox*Listbox.background", WELL)
    root.option_add("*TCombobox*Listbox.foreground", TXT)
    root.option_add("*TCombobox*Listbox.selectBackground",
                    _over(ACCENT, SURF, 0.40))
    root.option_add("*TCombobox*Listbox.selectForeground", TXT)

    # ---- hero band --------------------------------------------------------
    HERO_H = 84
    hero = tk.Canvas(root, bg=BG, highlightthickness=0, bd=0, height=HERO_H,
                     width=760)
    hero.pack(fill="x")
    ips = local_ips()

    def paint_hero(_e=None):
        w = hero.winfo_width()
        if w < 10:
            return
        hero.delete("all")
        _draw_aurora(hero, w, HERO_H)
        _draw_ekg(hero, dx=20, dy=HERO_H / 2 - 20, width=2)
        tid = hero.create_text(84, HERO_H / 2 - 8, anchor="w",
                               text="Network Vitals", fill=TXT,
                               font=(FONT, 18, "bold"))
        hero.create_text(hero.bbox(tid)[2] + 9, HERO_H / 2 - 3, anchor="w",
                         text=f"v{__version__}", fill=TXT_FAINT,
                         font=(FONT, 9))
        hero.create_text(85, HERO_H / 2 + 14, anchor="w",
                         text="bidirectional path instrument — run the same "
                              "app on both ends", fill=TXT_DIM,
                         font=(FONT, 9))
        if ips:
            hero.create_text(w - 20, HERO_H / 2 - 8, anchor="e",
                             text="THIS MACHINE", fill=TXT_FAINT,
                             font=(FONT, 7, "bold"))
            hero.create_text(w - 20, HERO_H / 2 + 10, anchor="e",
                             text="   ".join(ips[:3]), fill=TXT_DIM,
                             font=(FONT_MONO, 9))

    hero.bind("<Configure>", paint_hero)

    body_card = GlassCard(root, glow=ACCENT, padx=18, pady=16)
    body_card.pack(fill="x", padx=14, pady=(2, 0))
    body = body_card.body

    def mklabel(parent, text, row, dim=False):
        tk.Label(parent, text=text, fg=(TXT_DIM if dim else TXT), bg=SURF,
                 font=(FONT, 10)).grid(row=row, column=0, sticky="w",
                                       pady=4, padx=(0, 12))

    def mkhint(parent, text, row):
        tk.Label(parent, text=text, fg=TXT_FAINT, bg=SURF,
                 font=(FONT, 8)).grid(row=row, column=2, sticky="w",
                                      padx=(12, 0))

    def mkentry(parent, var, row, width=16):
        e = _glass_entry(tk, parent, var, width, SURF)
        e.grid(row=row, column=1, sticky="w", pady=4, ipady=4)
        return e

    def mkcheck(parent, text, var, row, column=1, columnspan=2, hint=None):
        """A glass toggle standing in for tk.Checkbutton: X11 draws that
        widget's indicator with a hard 3D bevel no option can flatten."""
        b = GlassButton(parent, text=text, base=SURF, toggle=True, size=9,
                        check=True)

        def flip():
            var.set(not bool(var.get()))
            b.set_on(bool(var.get()))

        b.configure(command=flip)
        b.set_on(bool(var.get()))
        b.grid(row=row, column=column, columnspan=columnspan, sticky="w",
               pady=1)
        if hint:
            tk.Label(parent, text=hint, fg=TXT_FAINT, bg=SURF,
                     font=(FONT, 8)).grid(row=row, column=column + columnspan,
                                          sticky="w", padx=(12, 0))
        return b

    # ---- basic options ------------------------------------------------------
    peer_var = tk.StringVar(value=sstr("peer", ""))
    recent = [p for p in s.get("recent_peers", []) if isinstance(p, str)]
    size_var = tk.StringVar(value=sstr("size", "200"))
    pps_var = tk.StringVar(value=sstr("pps", "50"))
    mbps_var = tk.StringVar(value=sstr("mbps", ""))
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

    mklabel(body, "Target Mbps", 3)
    mkentry(body, mbps_var, 3)
    mkhint(body, "total probe Mbps for the box - overrides Probes/sec "
                 "(blank = off)", 3)

    mkcheck(body, "Don't fragment", df_var, 4, column=1, columnspan=1,
            hint="drop oversized probes instead of splitting them "
                 "(jumbo testing)")

    # ---- advanced options (collapsed by default) ----------------------------
    adv_row = tk.Frame(root, bg=BG)
    adv_row.pack(fill="x", padx=14, pady=(10, 0))
    adv_btn = GlassButton(adv_row, text="▸  Advanced options", size=9)
    adv_btn.pack(side="left")

    adv_card = GlassCard(root, glow=ACCENT, padx=18, pady=16)
    adv_frame = adv_card.body

    bind_var = tk.StringVar(value=sstr("bind", "0.0.0.0"))
    udp_var = tk.StringVar(value=sstr("udp_ports", "%d,%d" % DEFAULT_UDP_PORTS))
    tcp_var = tk.StringVar(value=sstr("tcp_ports", "%d,%d" % DEFAULT_TCP_PORTS))
    profiles_var = tk.StringVar(value=sstr("profiles", ""))
    dscp_var = tk.StringVar(value=sstr("dscp", ""))
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
            ("UDP ports (list)", udp_var, "1-8 ports, one stream each; both ends must match"),
            ("TCP ports (list)", tcp_var, "0-8 ports ('none' = UDP only); both ends must match"),
            ("Profiles", profiles_var, "per stream: voice, video, bulk, imix, SIZE or SIZExPPS"),
            ("DSCP", dscp_var, "per stream: EF, AF41, CS5, BE, 0-63 or '-' (blank = unmarked)"),
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
    mkcheck(adv_frame, "VXLAN encapsulation", vx_var, r, column=1,
            columnspan=1,
            hint="carry all probe traffic inside a userspace VTEP "
                 "(both ends)")
    mklabel(adv_frame, "    VXLAN VNI", r + 1, dim=True)
    vni_entry = mkentry(adv_frame, vni_var, r + 1)
    mkhint(adv_frame, "must match on both ends", r + 1)
    mklabel(adv_frame, "    VXLAN UDP port", r + 2, dim=True)
    vxport_entry = mkentry(adv_frame, vxport_var, r + 2)
    mkhint(adv_frame, "outer tunnel port (default 4789)", r + 2)
    mkcheck(adv_frame, "Console UI", console_var, r + 3, column=1,
            columnspan=1,
            hint="run in a terminal instead of this dashboard")

    def sync_vxlan(*_):
        st = "normal" if vx_var.get() else "disabled"
        vni_entry.configure(state=st)
        vxport_entry.configure(state=st)

    vx_var.trace_add("write", sync_vxlan)
    sync_vxlan()

    def show_adv():
        adv_btn.configure(text="▾  Advanced options")
        adv_btn.set_on(True)
        adv_card.pack(fill="x", after=adv_row, padx=14, pady=(8, 0))

    def hide_adv():
        adv_btn.configure(text="▸  Advanced options")
        adv_btn.set_on(False)
        adv_card.pack_forget()

    def toggle_adv():
        adv["on"] = not adv["on"]
        (show_adv if adv["on"] else hide_adv)()

    adv_btn.configure(command=toggle_adv)
    (show_adv if adv["on"] else hide_adv)()

    # ---- bottom bar ---------------------------------------------------------
    bar = tk.Frame(root, bg=BG, padx=14, pady=10)
    bar.pack(fill="x", side="bottom")

    def mkbarbtn(text, cmd, primary=False):
        return GlassButton(bar, text=text, command=cmd, primary=primary,
                           size=(10 if primary else 9),
                           pad_x=(20 if primary else 15),
                           height=(34 if primary else 30))

    def collect():
        return {
            "peer": peer_var.get().strip(),
            "size": size_var.get(), "pps": pps_var.get(),
            "mbps": mbps_var.get(),
            "dont_fragment": bool(df_var.get()),
            "bind": bind_var.get(), "udp_ports": udp_var.get(),
            "tcp_ports": tcp_var.get(), "profiles": profiles_var.get(),
            "dscp": dscp_var.get(), "window": window_var.get(),
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
            ports = (_udp_port_list(vals["udp_ports"])
                     if vals["udp_ports"].strip() else DEFAULT_UDP_PORTS)
        except argparse.ArgumentTypeError as e:
            messagebox.showerror("Network Vitals", f"UDP ports: {e}",
                                 parent=root)
            return None
        return peer, vals["bind"].strip() or "0.0.0.0", ports, vals

    def do_sweep():
        target = _tool_target("MTU sweep")
        if target is None:
            return
        peer, bind, ports, _vals = target
        ns = argparse.Namespace(peer=peer, bind=bind, udp_ports=ports,
                                sweep_min=1400, sweep_max=9000)
        _open_tool_window(root, f"MTU sweep -> {peer}",
                          lambda out: run_mtu_sweep(ns, out=out), "mtu-sweep")

    def do_burst():
        target = _tool_target("burst test")
        if target is None:
            return
        peer, bind, ports, vals = target
        # The form's DF choice rides along so a jumbo/DF demo setup bursts
        # the way it probes (run_burst_test defaults the rest).
        ns = argparse.Namespace(peer=peer, bind=bind, udp_ports=ports,
                                burst_mbps=[1, 2, 5, 10, 25], burst_secs=3.0,
                                dont_fragment=bool(vals["dont_fragment"]))
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
    mkbarbtn("⤢  MTU sweep", do_sweep).pack(side="right", padx=(0, 4))
    mkbarbtn("⚡  Burst test", do_burst).pack(side="right", padx=(0, 4))

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


MAX_STREAMS_PER_PROTO = 8


def _port_list(text, what, min_ports=1, allow_none=False):
    """Parse a comma list of 1-8 ports (1.8.0: the stream count per protocol
    is no longer fixed at two). 'none' -> () where a protocol may be dropped
    entirely (TCP-only match rules, pure-voice demos)."""
    raw = (text or "").strip()
    if allow_none and raw.lower() in ("none", "off", "0", ""):
        return ()
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    if not (min_ports <= len(parts) <= MAX_STREAMS_PER_PROTO):
        raise argparse.ArgumentTypeError(
            f"{what}: expected {min_ports}-{MAX_STREAMS_PER_PROTO} "
            f"comma-separated ports, got {len(parts)}")
    try:
        ports = tuple(int(p) for p in parts)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{what}: ports must be integers")
    for p in ports:
        if not (1 <= p <= 65535):
            raise argparse.ArgumentTypeError(
                f"{what}: port {p} out of range 1-65535")
    if len(set(ports)) != len(ports):
        raise argparse.ArgumentTypeError(f"{what}: duplicate port")
    return ports


def _udp_port_list(text):
    """--udp-ports: 1-8 ports. At least one UDP stream is required - the
    latency band, one-way drift and the one-shot tools all ride UDP."""
    return _port_list(text, "UDP ports", min_ports=1, allow_none=False)


def _tcp_port_list(text):
    """--tcp-ports: 0-8 ports; 'none' runs a UDP-only stream set."""
    return _port_list(text, "TCP ports", min_ports=1, allow_none=True)


# -- traffic profiles (R-3): per-stream size/rate mixes ----------------------
# name -> (payload size pattern in bytes, pps or None = inherit the base
# --pps/--tcp-pps rate). A multi-entry pattern cycles probe-by-probe (IMIX).
# 'imix' is the classic 7:4:1 mix of 64/576/1500-byte IP packets expressed
# as probe payloads (IP size - 28); its per-stream mean is ~354 B of payload.
TRAFFIC_PROFILES = {
    "default": (None, None),     # --size at the base rate
    "voice": ((200,), 50),       # G.711: 20 ms cadence
    "video": ((1200,), 90),      # conferencing-like: big frames, ~0.9 Mbps
    "bulk": ((1400,), 200),      # near-MTU filler, ~2.3 Mbps
    "imix": ((36,) * 7 + (548,) * 4 + (1472,), None),
}


def _profile_list(text):
    """--profiles: comma list, one entry per stream in stream (sid) order;
    streams beyond the list keep 'default'. An entry is a profile name, a
    payload SIZE, or SIZExPPS (e.g. 1200x90)."""
    out = []
    for tok in (t.strip() for t in (text or "").split(",")):
        if not tok:
            raise argparse.ArgumentTypeError("empty profile entry")
        low = tok.lower()
        if low in TRAFFIC_PROFILES:
            out.append(low)
            continue
        m = re.fullmatch(r"(\d+)(?:x(\d+(?:\.\d+)?))?", low)
        if not m:
            raise argparse.ArgumentTypeError(
                f"unknown profile {tok!r} - use one of "
                f"{', '.join(sorted(TRAFFIC_PROFILES))}, or SIZE / SIZExPPS")
        size = int(m.group(1))
        if not (HEADER_LEN <= size <= MAX_SIZE):
            raise argparse.ArgumentTypeError(
                f"profile size {size} out of range {HEADER_LEN}-{MAX_SIZE}")
        pps = float(m.group(2)) if m.group(2) else None
        if pps is not None and not (0 < pps <= 100000):
            raise argparse.ArgumentTypeError(
                f"profile rate {pps:g} out of range (0, 100000]")
        out.append((size, pps))
    if len(out) > 2 * MAX_STREAMS_PER_PROTO:
        raise argparse.ArgumentTypeError(
            f"more profile entries than possible streams "
            f"({2 * MAX_STREAMS_PER_PROTO} max)")
    return out


def _dscp_list(text):
    """--dscp: comma list, one code point per stream in sid order (streams
    beyond the list stay unmarked). Entries: EF, AF41, CS5, BE, 0-63, or
    '-'/'none' to leave that stream unmarked."""
    out = []
    for tok in (t.strip().lower() for t in (text or "").split(",")):
        if tok in ("", "-", "none"):
            out.append(None)
            continue
        if tok in DSCP_NAMES:
            out.append(DSCP_NAMES[tok])
            continue
        try:
            v = int(tok)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"unknown DSCP {tok!r} - use EF, AF41, CS5, BE, 0-63, or '-'")
        if not (0 <= v <= 63):
            raise argparse.ArgumentTypeError(f"DSCP {v} out of range 0-63")
        out.append(v)
    if len(out) > 2 * MAX_STREAMS_PER_PROTO:
        raise argparse.ArgumentTypeError(
            f"more DSCP entries than possible streams "
            f"({2 * MAX_STREAMS_PER_PROTO} max)")
    return out


def resolve_profiles(entries, n_streams, base_size):
    """Expand --profiles entries to one (sizes_pattern, pps_or_None) per
    stream in sid order; missing entries mean 'default' (--size, base rate)."""
    resolved = []
    for i in range(n_streams):
        e = entries[i] if entries and i < len(entries) else "default"
        if isinstance(e, tuple):
            sizes, pps = (e[0],), e[1]
        else:
            sizes, pps = TRAFFIC_PROFILES[e]
            if sizes is None:
                sizes = (base_size,)
        sizes = tuple(max(HEADER_LEN, min(MAX_SIZE, s)) for s in sizes)
        resolved.append((sizes, pps))
    return resolved


def mean_wire_size(sizes, proto):
    """Mean IP-level bytes per probe for a size pattern on one protocol."""
    overhead = IPV4_TCP_OVERHEAD if proto == "TCP" else IPV4_UDP_OVERHEAD
    return sum(sizes) / len(sizes) + overhead


def pps_for_streams(mbps, profiles, protos):
    """--mbps with per-stream profiles: equal bandwidth share per stream,
    each stream's pps derived from its own mean wire size (profile SIZES are
    kept, profile rates are overridden). Returns pps floats, floored at 0.1."""
    share = mbps * 1e6 / len(profiles) / 8.0
    return [max(0.1, share / mean_wire_size(sizes, proto))
            for (sizes, _pps), proto in zip(profiles, protos)]


def pps_from_mbps(mbps, size, udp_streams=2, tcp_streams=2):
    """Derive per-stream probe rates from a target offered load (--mbps).

    `mbps` is the box's total offered PROBE bandwidth per direction at the
    IP level (probe + IPv4/UDP-or-TCP headers, Ethernet excluded), split
    evenly across the streams; echoes mirror probes, so the wire carries
    roughly double per direction at steady state. Returns (udp_pps,
    tcp_pps) as floats - fractional rates are real rates, not rounding
    errors, so they are preserved. Each is floored at 0.1 pps (one probe
    per 10 s) so a tiny target with a big probe still measures something.
    """
    share = mbps * 1e6 / (udp_streams + tcp_streams) / 8.0  # bytes/s/stream
    udp_pps = share / (size + IPV4_UDP_OVERHEAD)
    tcp_pps = share / (size + IPV4_TCP_OVERHEAD)
    return max(0.1, udp_pps), max(0.1, tcp_pps)


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Bidirectional UDP/TCP network quality probe between two workstations.")
    p.add_argument("--version", action="version",
                   version=f"Network Vitals {__version__}")
    p.add_argument("--update", action="store_true",
                   help="Verify and install the latest SIGNED release (fail "
                        "closed), then exit.")
    p.add_argument("--check-update", action="store_true",
                   help="Report whether a newer SIGNED version is available, then "
                        "exit (exit code 3 = update available).")
    p.add_argument("--update-url", default=UPDATE_URL,
                   help="Signed release-manifest URL for --update/--check-update "
                        "(default: the netvitals GitHub releases). The manifest "
                        "signature is always verified against the built-in key.")
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
    p.add_argument("--udp-ports", type=_udp_port_list, default=DEFAULT_UDP_PORTS,
                   metavar="A,B,...",
                   help="1-%d UDP ports, one stream per port (default %d,%d). "
                        "At least one UDP stream is required."
                        % ((MAX_STREAMS_PER_PROTO,) + DEFAULT_UDP_PORTS))
    p.add_argument("--tcp-ports", type=_tcp_port_list, default=DEFAULT_TCP_PORTS,
                   metavar="A,B,...",
                   help="0-%d TCP ports, one stream per port (default %d,%d; "
                        "'none' runs UDP-only)."
                        % ((MAX_STREAMS_PER_PROTO,) + DEFAULT_TCP_PORTS))
    p.add_argument("--pps", type=int, default=50,
                   help="Probe packets per second, per stream (default 50).")
    p.add_argument("--mbps", type=float, default=None, metavar="X",
                   help="Target offered probe load for the box in Mbps (IP "
                        "level, per direction, probes only - echoes double "
                        "the wire load; max 1000). Splits evenly across the "
                        "four streams and derives each stream's rate from "
                        "--size, overriding --pps/--tcp-pps. The dashboard "
                        "footer shows offered vs target.")
    p.add_argument("--size", type=int, default=200,
                   help="Probe packet size in bytes (default 200, min %d, max %d; "
                        "e.g. 8972 to fill a 9000-byte jumbo frame)."
                        % (HEADER_LEN, MAX_SIZE))
    p.add_argument("--profiles", type=_profile_list, default=None,
                   metavar="P1,P2,...",
                   help="Per-stream traffic profiles in stream order (streams "
                        "beyond the list keep --size at the base rate): "
                        "voice, video, bulk, imix, SIZE, or SIZExPPS - e.g. "
                        "'voice,imix' shapes the first two streams. imix "
                        "cycles the classic 7:4:1 64/576/1500 B IP mix.")
    p.add_argument("--dscp", type=_dscp_list, default=None, metavar="D1,D2,...",
                   help="Per-stream DSCP code points in stream order (streams "
                        "beyond the list stay unmarked): EF, AF41, CS5, BE, "
                        "0-63, or '-' to skip a stream. POSIX marks the exact "
                        "value; Windows maps to the nearest qWAVE traffic "
                        "type (no admin needed) and the UI reports the code "
                        "point that actually went out. The Totals table "
                        "shows requested vs arrived (fwd/rtn readback).")
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
    p.add_argument("--slice-scan", action="store_true",
                   help="One-shot: scan probe size vs RTT/loss and detect "
                        "the WAN slice-boundary staircase, measuring the "
                        "fabric's real slice budget against the Anatomy "
                        "model constant. Peer must be running Network "
                        "Vitals (native mode).")
    p.add_argument("--wan-counters", type=_wan_spec, default=None,
                   metavar="SPEC",
                   help="Poll WAN-side packet counters and show MEASURED "
                        "WAN pps next to the predicted pps: 'sim[:NOISE]' "
                        "(built-in simulator via the EC slicing model), "
                        "'snmp:HOST,COMMUNITY,IFINDEX[,PORT]' (IF-MIB "
                        "64-bit counters), or 'rest:URL[|TOKEN[|TXKEY|"
                        "RXKEY]]' (generic JSON).")
    p.add_argument("--scenario", default=None, metavar="FILE",
                   help="Replay a JSON demo timeline: stages with secs, "
                        "load_mbps, square_on_s/off_s and reset, drawn as "
                        "stage markers on the charts. See the demo guide "
                        "for the format.")
    p.add_argument("--frag-sniffer", action="store_true",
                   help="Count IPv4 fragments to/from the peer at capture "
                        "level - proves whole-packet delivery vs kernel "
                        "reassembly of mid-path fragments. Needs root/"
                        "admin for the raw socket; reports 'unavailable' "
                        "otherwise instead of failing.")
    p.add_argument("--report", default=None, metavar="BASE",
                   help="On exit, write the demo report to BASE.json and "
                        "BASE.html. The dashboard's ⭳ Report button and "
                        "the console 'w' key write one on demand at any "
                        "time (to the NetVitals config dir).")
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
    # ICMP frag-needed visibility (2.0.0): with IP_RECVERR (Linux) the
    # sweep can tell a router SAYING 'fragmentation needed, MTU=N' from a
    # silent drop - a PMTUD black hole - without raw sockets or root.
    icmp_watch = enable_icmp_err(sock)
    icmp_seen = {}   # next-hop MTU -> hits
    seq = [0]

    def read_icmp_errs():
        if not icmp_watch:
            return
        dontwait = getattr(socket, "MSG_DONTWAIT", 0x40)
        for _ in range(8):
            try:
                _d, anc, _f, _a = sock.recvmsg(
                    512, 256, socket.MSG_ERRQUEUE | dontwait)
            except (BlockingIOError, OSError):
                return
            err = parse_icmp_err(anc)
            if err and err[0] == 3 and err[1] == 4:      # frag needed
                icmp_seen[err[2]] = icmp_seen.get(err[2], 0) + 1

    def round_trips(size):
        """True if a probe of `size` bytes gets an echo back (4 tries)."""
        for _ in range(4):
            seq[0] += 1
            s = seq[0]
            pkt = build_packet(TYPE_TEST, 0, s, time.monotonic_ns(), size, rxsize=size)
            try:
                sock.sendto(pkt, (peer, port))
            except OSError:
                read_icmp_errs()   # a queued ICMP error surfaces as OSError
                return False       # or EMSGSIZE: exceeds the local NIC MTU
            deadline = time.monotonic() + 0.4
            while time.monotonic() < deadline:
                try:
                    data, _ = sock.recvfrom(MAX_SIZE)
                except socket.timeout:
                    break
                except OSError:
                    read_icmp_errs()
                    break
                p = parse_header(data)
                if p and p[0] == TYPE_ECHO and p[2] == s:
                    return True
            read_icmp_errs()
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
    # ICMP verdict (2.0.0): did anything SAY the frames were too big?
    dropped_any = best < hi
    if icmp_seen:
        mtus = ", ".join(f"MTU={m}" for m in sorted(icmp_seen))
        out(f"=> ICMP 'fragmentation needed' received ({mtus}) - PMTUD "
            f"works on this path; endpoints learn the limit.")
    elif dropped_any and icmp_watch:
        out("=> Oversized probes were dropped SILENTLY (no ICMP came "
            "back): a PMTUD black hole - endpoints can't learn the limit, "
            "they just lose packets.")
    elif dropped_any:
        out("   (ICMP frag-needed detection needs Linux/IP_RECVERR; "
            "unavailable on this platform.)")


def detect_slice_boundaries(samples, min_step_ms=0.12):
    """Find WAN slice boundaries in a size-vs-RTT scan (R-12, 1.9.0).

    samples: [(inner_ip_bytes, median_rtt_ms, loss_pct)], ascending sizes.
    Every extra tunnel packet costs one more serialization + crypto pass,
    so the RTT-vs-size curve is a staircase: a boundary is a step UP that
    exceeds both `min_step_ms` and 4x the median step elsewhere, and STAYS
    up. Returns (boundaries, est_budget): the inner sizes where the steps
    landed and the median gap between them (the measured slice budget), or
    ([], None) when the curve is flat - i.e. no slicing fabric in the path."""
    steps = []
    for i in range(1, len(samples)):
        s0, r0, _ = samples[i - 1]
        s1, r1, _ = samples[i]
        steps.append((s1, r1 - r0))
    if not steps:
        return [], None
    mags = sorted(abs(d) for _, d in steps)
    noise = mags[len(mags) // 2]
    thresh = max(min_step_ms, 4.0 * noise)
    boundaries = []
    for i, (size, delta) in enumerate(steps):
        if delta < thresh:
            continue
        # must STAY up: the median of the next few samples doesn't fall back
        after = [r for _s, r, _l in samples[i + 1:i + 4]]
        before = samples[i][1]
        if after and sorted(after)[len(after) // 2] < before + thresh / 2:
            continue
        # merge near-duplicates from one boundary spanning two grid points
        if boundaries and size - boundaries[-1] <= 2 * (samples[1][0]
                                                        - samples[0][0]):
            continue
        boundaries.append(size)
    if len(boundaries) >= 2:
        gaps = [b - a for a, b in zip(boundaries, boundaries[1:])]
        est = sorted(gaps)[len(gaps) // 2]
    elif len(boundaries) == 1:
        est = boundaries[0]
    else:
        est = None
    return boundaries, est


def run_slice_scan(args, out=print):
    """One-shot slice-boundary scan (R-12): step the probe size across a
    uniform grid and measure median RTT + loss at each size, then detect
    the staircase the fabric's slicing imposes - measuring the REAL slice
    budget instead of trusting the Anatomy model's constants. Uses the
    TEST-probe side channel (ephemeral port, excluded from loss isolation)
    against a peer running Network Vitals in native mode."""
    peer, port = args.peer, args.udp_ports[0]
    lo_inner = 900                     # below any plausible slice budget
    hi_inner = min(int(EC_SLICE_BUDGET * 3.2) + 200, MAX_SIZE - 28)
    step = 32
    probes_per_size = 24
    out(f"Slice scan -> {peer}:{port} (UDP TEST probes, no DF). "
        f"Peer must be running Network Vitals.")
    out(f"Sizes {lo_inner}-{hi_inner} B (IP level) in {step} B steps, "
        f"{probes_per_size} probes each; model budget "
        f"{EC_SLICE_BUDGET} B for comparison.")
    out("")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    enlarge_socket_buffers(sock)
    quench_udp_connreset(sock)
    try:
        sock.bind((args.bind, 0))
    except OSError as e:
        out(f"bind failed: {e}")
        return
    sock.settimeout(0.25)
    seq = [0]

    def measure(payload):
        """Median RTT + loss for `probes_per_size` paced probes."""
        rtts, pending = [], {}
        for _ in range(probes_per_size):
            seq[0] += 1
            s = seq[0]
            pkt = build_packet(TYPE_TEST, 0, s, time.monotonic_ns(), payload)
            pending[s] = time.monotonic_ns()
            try:
                sock.sendto(pkt, (peer, port))
            except OSError:
                pending.pop(s, None)
            deadline = time.monotonic() + 0.005   # ~200 pps pacing
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                sock.settimeout(left)
                try:
                    data, _ = sock.recvfrom(MAX_SIZE)
                except socket.timeout:
                    break
                except OSError:
                    break
                p = parse_header(data)
                if p and p[0] == TYPE_ECHO:
                    ns = pending.pop(p[2], None)
                    if ns is not None:
                        rtts.append((time.monotonic_ns() - ns) / 1e6)
        t_end = time.monotonic() + 0.25          # drain stragglers
        while time.monotonic() < t_end and pending:
            sock.settimeout(0.05)
            try:
                data, _ = sock.recvfrom(MAX_SIZE)
            except (socket.timeout, OSError):
                continue
            p = parse_header(data)
            if p and p[0] == TYPE_ECHO:
                ns = pending.pop(p[2], None)
                if ns is not None:
                    rtts.append((time.monotonic_ns() - ns) / 1e6)
        loss = len(pending) / probes_per_size * 100.0
        med = sorted(rtts)[len(rtts) // 2] if rtts else None
        return med, loss

    samples = []
    for inner in range(lo_inner, hi_inner + 1, step):
        med, loss = measure(inner - 28)          # payload = inner IP - 28
        if med is None:
            out(f"  {inner:>5} B: no echoes - peer down or UDP blocked; "
                f"aborting.")
            sock.close()
            return
        samples.append((inner, med, loss))
    sock.close()

    boundaries, est = detect_slice_boundaries(samples)
    for inner, med, loss in samples:
        mark = "  << boundary" if inner in boundaries else ""
        if boundaries and inner in boundaries or inner % 256 < step:
            out(f"  {inner:>5} B  RTT med {med:6.2f} ms  loss {loss:4.1f}%"
                f"{mark}")
    out("")
    if not boundaries:
        out("=> No slice staircase detected: RTT is flat across the size "
            "range (no slicing fabric in this path, or the step cost is "
            "below the noise floor).")
        return
    out(f"=> RTT steps at inner sizes: "
        f"{', '.join(str(b) + ' B' for b in boundaries)}")
    out(f"=> Measured slice budget: ~{est} B  "
        f"(Anatomy model constant: {EC_SLICE_BUDGET} B)")
    if est and abs(est - EC_SLICE_BUDGET) > 64:
        out(f"=> The model constant looks off for THIS fabric - tune "
            f"EC_SLICE_BUDGET to ~{est} in netquality.py so the Anatomy "
            f"panel and slice predictions match reality.")
    else:
        out("=> Model and measurement agree: the Anatomy panel's slicing "
            "predictions hold for this fabric.")


BURST_PROBE_SIZE = 1200   # fits one EC slice AND a standard 1500 B hop


def burst_verdicts(results, base_med, base_p95):
    """Name the SHAPE of a burst-test response (the table carries the exact
    numbers; thresholds are deliberately blunt). `results` rows are
    (mbps, loss_pct, late_pct, rtt_med_ms, rtt_p95_ms): loss counts echoes
    that never returned at all, late the ones that returned past the probe
    timeout - a policer's drops never arrive, so late echoes don't trigger
    the rate-cap verdicts, but they do disqualify a stage from "clean".
    Returns the verdict lines, without the leading '=> '."""
    clean = [m for m, loss, late, med, p95 in results
             if loss + late < 1.0 and p95 is not None
             and p95 < base_p95 + 30.0]
    bloated = [(m, p95) for m, loss, late, med, p95 in results
               if loss + late < 2.0 and p95 is not None
               and p95 > base_p95 + 100.0]
    capped = [(m, loss, med) for m, loss, late, med, p95 in results
              if loss >= 5.0 and med is not None]
    lines = []
    if clean:
        lines.append(f"Clean up to {max(clean):g} Mbps offered "
                     f"(loss+late <1%, p95 RTT within +30 ms of idle).")
    if bloated:
        m, p95 = bloated[0]
        lines.append(f"Deep queue (bufferbloat-like): at {m:g} Mbps p95 RTT "
                     f"hit {p95:.0f} ms (idle {base_p95:.1f} ms) before any "
                     f"real loss.")
    if capped:
        m, loss, med = capped[0]
        if med < base_med + 20.0:
            lines.append(f"Policer-like: {loss:.0f}% loss at {m:g} Mbps with "
                         f"RTT still flat ({med:.1f} ms) - a hard rate cap "
                         f"that drops, not queues.")
        else:
            lines.append(f"Shaper-like: {loss:.0f}% loss at {m:g} Mbps after "
                         f"RTT grew to {med:.0f} ms - a queue that fills, "
                         f"then drops.")
    if not lines:
        lines.append("No stage ran clean and none showed a clear queue/cap "
                     "signature - see the table.")
    return lines


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
    # The launcher's tool window builds a minimal Namespace, so read the
    # session-wide options defensively.
    df_on = getattr(args, "dont_fragment", False)
    timeout_s = getattr(args, "timeout", None) or 2.0
    timeout_ms = timeout_s * 1000.0
    out(f"Burst test -> {peer}:{port} (UDP, {size} B probes, "
        f"DF {'on' if df_on else 'off'}). "
        f"Peer must be running Network Vitals.")
    out(f"Stages: {', '.join(f'{m:g}' for m in stages)} Mbps, {dur:g} s each. "
        f"This is real traffic, and echoes double it.")
    out("")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    enlarge_socket_buffers(sock)
    quench_udp_connreset(sock)
    if df_on:
        # Without DF a sub-1228-MTU hop silently fragments the 1200 B probes
        # (2 wire packets per probe) and the pps/rate math no longer means
        # what the table says.
        set_dont_fragment(sock)
    try:
        sock.bind((args.bind, 0))  # ephemeral source port
    except OSError as e:
        out(f"bind failed: {e}")
        return
    sock.setblocking(False)
    seq = [0]

    def run_stage(pps, seconds):
        """Send paced probes for `seconds`; return (sent, rtts_ms, late_ms).

        Same loss-vs-late split as the continuous engine: an echo within the
        probe timeout is on-time, one beyond it is LATE (reordered or
        over-buffered, but the path did deliver it), and only a probe that
        never returns at all counts as lost."""
        pending = {}
        rtts, late = [], []

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
                        rtt = (time.monotonic_ns() - ns) / 1e6
                        (late if rtt >= timeout_ms else rtts).append(rtt)

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
        # Let stragglers arrive so they can be counted LATE instead of lost:
        # drain up to the probe timeout (bounded), stopping early once every
        # in-flight probe is accounted for.
        t_drain = time.monotonic() + max(0.6, min(timeout_s, 2.0))
        while time.monotonic() < t_drain and pending:
            drain()
            time.sleep(0.005)
        drain()
        return sent, rtts, late

    def pctl(sorted_vals, q):
        return sorted_vals[int(q * (len(sorted_vals) - 1))]

    # Baseline: the idle path, so stage RTTs have something to move against.
    base_sent, base_rtts, base_late = run_stage(20, 1.5)
    base_got = sorted(base_rtts + base_late)
    if len(base_got) < 10:
        out(f"  baseline got {len(base_got)}/{base_sent} echoes - peer down, "
            f"UDP {port} blocked, or both ends aren't on this version.")
        sock.close()
        return
    base_med, base_p95 = pctl(base_got, 0.5), pctl(base_got, 0.95)
    out(f"  baseline (idle): RTT median {base_med:.1f} ms  p95 {base_p95:.1f} ms")
    out("")

    results = []
    for mbps in stages:
        pps = max(20, int(mbps * 1e6 / 8 / size))
        sent, rtts, late_l = run_stage(pps, dur)
        if not sent:
            out(f"  {mbps:6g} Mbps: could not send (local socket error)")
            continue
        loss = (sent - len(rtts) - len(late_l)) / sent * 100.0
        late_pct = len(late_l) / sent * 100.0
        offered = sent * size * 8 / dur / 1e6
        got = sorted(rtts + late_l)  # late echoes are real RTT samples: the
        if got:                      # queue they sat in belongs in the p95
            med, p95 = pctl(got, 0.5), pctl(got, 0.95)
            out(f"  {mbps:6g} Mbps offered ({offered:5.1f} achieved, {pps} pps): "
                f"loss {loss:5.1f}%  late {late_pct:4.1f}%   "
                f"RTT med {med:6.1f} ms  p95 {p95:6.1f} ms")
        else:
            med = p95 = None
            out(f"  {mbps:6g} Mbps offered ({offered:5.1f} achieved, {pps} pps): "
                f"loss 100.0%   no echoes")
        results.append((mbps, loss, late_pct, med, p95))
    sock.close()
    out("")

    for line in burst_verdicts(results, base_med, base_p95):
        out(f"=> {line}")


def square_phase(elapsed, on_s, off_s):
    """True while a square-wave load schedule is in its ON half.

    `off_s` <= 0 (or None) means no square wave: always on. The wave starts
    in the ON half at elapsed 0 and repeats every on_s + off_s seconds."""
    if not off_s or off_s <= 0:
        return True
    period = on_s + off_s
    if period <= 0 or on_s <= 0:
        return False
    return (elapsed % period) < on_s


class LoadGenerator:
    """Continuous paced UDP load against one peer, driven from the dashboard.

    The burst test's machinery made resident: TYPE_TEST probes (echoed by
    the peer but excluded from its loss-isolation bookkeeping) from an
    ephemeral source port, accumulator-paced in ~2 ms ticks, so a sustained
    known-quantity load can run WHILE the live charts show what it does to
    the scored streams. An optional square wave (on_s/off_s) turns the load
    on and off on a fixed cadence - the calibration pattern for diffing
    WAN-side counters against background traffic. Native transport only: a
    VXLAN-mode peer opens no native UDP listener to echo the probes.
    Echoes are full-size, so the offered load rides both directions."""

    STATS_WINDOW = 5.0  # seconds of history behind achieved-rate/loss

    def __init__(self, peer, port, bind="0.0.0.0", size=BURST_PROBE_SIZE,
                 dont_fragment=False, timeout=2.0):
        self.peer = peer
        self.port = port
        self.bind = bind
        self.size = size
        self.dont_fragment = dont_fragment
        self.timeout = timeout or 2.0
        self.lock = threading.Lock()
        self.stop_evt = None
        self.thread = None
        self.sock = None
        self.mbps = 0.0
        self.on_s = 0.0
        self.off_s = 0.0
        self.error = None
        # rolling stats, trimmed to STATS_WINDOW (guarded by self.lock)
        self._sent = deque()   # send times
        self._ok = deque()     # (arrival time, rtt_ms) - echo within timeout
        self._late = deque()   # (arrival time, rtt_ms) - echo past timeout
        self._lost = deque()   # reap times of probes that never returned
        self._phase_on = True
        self._t0 = None        # start time of the current run

    @property
    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self, mbps, on_s=0.0, off_s=0.0):
        """Begin offering `mbps` (probes only; echoes double the wire load).
        Returns None, or a user-facing error string on failure."""
        if self.running:
            return "already running"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        enlarge_socket_buffers(sock)
        quench_udp_connreset(sock)
        if self.dont_fragment:
            set_dont_fragment(sock)
        try:
            sock.bind((self.bind, 0))  # ephemeral: coexists with the session
        except OSError as e:
            sock.close()
            return f"bind failed: {e}"
        sock.setblocking(False)
        self.sock = sock
        self.mbps = float(mbps)
        self.on_s, self.off_s = float(on_s or 0.0), float(off_s or 0.0)
        self.error = None
        with self.lock:
            for dq in (self._sent, self._ok, self._late, self._lost):
                dq.clear()
        self._t0 = time.monotonic()
        self.stop_evt = threading.Event()
        self.thread = threading.Thread(target=self._run, name="load-gen",
                                       daemon=True)
        self.thread.start()
        return None

    def stop(self):
        if self.stop_evt is not None:
            self.stop_evt.set()

    def status(self):
        """Rolling view over the last STATS_WINDOW seconds."""
        now = time.monotonic()
        floor = now - self.STATS_WINDOW
        with self.lock:
            for dq in (self._sent, self._lost):
                while dq and dq[0] < floor:
                    dq.popleft()
            for dq in (self._ok, self._late):
                while dq and dq[0][0] < floor:
                    dq.popleft()
            sent, ok, late, lost = (len(self._sent), len(self._ok),
                                    len(self._late), len(self._lost))
            phase_on = self._phase_on
        elapsed = now - self._t0 if self._t0 is not None else self.STATS_WINDOW
        span = min(self.STATS_WINDOW, max(0.5, elapsed))
        achieved = sent * (self.size + IPV4_UDP_OVERHEAD) * 8.0 / span / 1e6
        decided = ok + late + lost
        return {
            "running": self.running, "mbps": self.mbps,
            "square": self.off_s > 0, "phase_on": phase_on,
            "achieved_mbps": achieved,
            "loss_pct": (lost / decided * 100.0) if decided else 0.0,
            "late_pct": (late / decided * 100.0) if decided else 0.0,
            "error": self.error,
        }

    def _run(self):
        sock, stop = self.sock, self.stop_evt
        pps = max(1.0, self.mbps * 1e6 / 8.0 / self.size)
        timeout_ns = int(self.timeout * 1e9)
        pending = {}   # seq -> send monotonic_ns
        seq = 0
        t0 = time.monotonic()
        last = t0
        carry = 0.0

        def drain(now):
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
                        rtt = (time.monotonic_ns() - ns) / 1e6
                        with self.lock:
                            if rtt >= self.timeout * 1000.0:
                                self._late.append((now, rtt))
                            else:
                                self._ok.append((now, rtt))

        def reap(now):
            """Probes past the timeout with no echo -> lost (a late echo can
            no longer match them; the burst tool tolerates that skew, and a
            sustained generator must not leak `pending` forever)."""
            if not pending:
                return
            cutoff = time.monotonic_ns() - timeout_ns - int(0.5e9)
            dead = [s for s, ns in pending.items() if ns < cutoff]
            if dead:
                with self.lock:
                    for s in dead:
                        del pending[s]
                        self._lost.append(now)

        while not stop.is_set():
            now = time.monotonic()
            on = square_phase(now - t0, self.on_s, self.off_s)
            with self.lock:
                self._phase_on = on
            if not on:
                drain(now)
                reap(now)
                carry = 0.0
                last = now
                time.sleep(0.02)
                continue
            carry += (now - last) * pps
            last = now
            for _ in range(min(int(carry), 500)):
                seq += 1
                ns = time.monotonic_ns()
                pkt = build_packet(TYPE_TEST, 0, seq, ns, self.size)
                pending[seq] = ns  # register first: echoes race the GIL
                try:
                    sock.sendto(pkt, (self.peer, self.port))
                except (BlockingIOError, OSError):
                    pending.pop(seq, None)
                    carry = min(carry, 1.0)  # local backpressure
                    break
                with self.lock:
                    self._sent.append(now)
                carry -= 1.0
            drain(now)
            reap(now)
            time.sleep(0.002)
        sock.close()


# ---------------------------------------------------------------------------
# Measured WAN counters (R-10, 1.9.0): poll the fabric's WAN-side packet
# counters and show MEASURED WAN pps next to the Anatomy panel's PREDICTED
# pps - live proof that 1 LAN packet becomes N WAN packets. Pluggable
# sources: 'sim' (derives counters from this engine's own offered load
# through the EC slicing model - the no-hardware UAT backend), 'snmp'
# (stdlib SNMPv2c GET of the IF-MIB 64-bit counters; covers EdgeConnect and
# any router), and 'rest' (generic JSON poller; the Orchestrator-specific
# endpoint/auth is a UAT deliverable, this is its stable integration point).
# ---------------------------------------------------------------------------
def wan_inner_bytes(payload_mean, proto, vxlan_on):
    """IP-level bytes the FABRIC ingests for one probe: native probes are
    payload + IPv4/L4 headers; in VXLAN mode the fabric sees the outer
    datagram (payload + encap overhead + outer IPv4/UDP)."""
    if vxlan_on:
        ov = VXLAN_OVERHEAD_UDP if proto == "UDP" else VXLAN_OVERHEAD_TCP
        return payload_mean + ov + 28
    return payload_mean + (IPV4_UDP_OVERHEAD if proto == "UDP"
                           else IPV4_TCP_OVERHEAD)


def _json_path(obj, path):
    """Follow a dotted key path ('data.if0.txPkts') into parsed JSON."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise KeyError(path)
    return cur


def _wan_spec(text):
    """--wan-counters SPEC parser.

      sim[:NOISE_PPS]              simulator (optional background pps noise)
      snmp:HOST,COMMUNITY,IFINDEX[,PORT]
      rest:URL[|TOKEN[|TX_KEY|RX_KEY]]   ('|' separators: URLs carry , and :)

    Returns a config dict; raises argparse.ArgumentTypeError on nonsense so
    a typo dies at the command line, not mid-demo."""
    raw = (text or "").strip()
    kind, _, rest = raw.partition(":")
    kind = kind.lower()
    if kind == "sim":
        # sim[:NOISE_PPS[:LOSS_PCT]] - LOSS_PCT makes the simulator report
        # WAN-side drops, so the FEC verdict can be rehearsed hardware-free.
        noise = loss = 0.0
        if rest:
            parts = rest.split(":")
            try:
                noise = float(parts[0]) if parts[0] else 0.0
                loss = float(parts[1]) if len(parts) > 1 and parts[1] else 0.0
            except ValueError:
                raise argparse.ArgumentTypeError(
                    f"sim spec is sim[:NOISE_PPS[:LOSS_PCT]], got {rest!r}")
            if not (0 <= noise <= 1e6) or not (0 <= loss <= 100):
                raise argparse.ArgumentTypeError("sim noise/loss out of range")
        return {"kind": "sim", "noise_pps": noise, "loss_pct": loss}
    if kind == "snmp":
        parts = [p.strip() for p in rest.split(",")]
        if len(parts) not in (3, 4) or not all(parts):
            raise argparse.ArgumentTypeError(
                "snmp spec is HOST,COMMUNITY,IFINDEX[,PORT]")
        try:
            ifindex = int(parts[2])
            port = int(parts[3]) if len(parts) == 4 else 161
        except ValueError:
            raise argparse.ArgumentTypeError("snmp IFINDEX/PORT must be integers")
        if not (1 <= port <= 65535) or ifindex < 1:
            raise argparse.ArgumentTypeError("snmp IFINDEX/PORT out of range")
        return {"kind": "snmp", "host": parts[0], "community": parts[1],
                "ifindex": ifindex, "port": port}
    if kind == "rest":
        parts = rest.split("|")
        if not parts[0].startswith(("http://", "https://")):
            raise argparse.ArgumentTypeError(
                "rest spec is URL[|TOKEN[|TX_KEY|RX_KEY]] with an http(s) URL")
        return {"kind": "rest", "url": parts[0],
                "token": parts[1] if len(parts) > 1 and parts[1] else None,
                "tx_key": parts[2] if len(parts) > 2 else "tx_pkts",
                "rx_key": parts[3] if len(parts) > 3 else "rx_pkts"}
    raise argparse.ArgumentTypeError(
        f"unknown WAN counter source {kind!r} (sim / snmp / rest)")


# -- minimal SNMPv2c (stdlib BER, just enough for one GET of 4 counters) ----
def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _ber(tag, payload):
    return bytes([tag]) + _ber_len(len(payload)) + payload


def _ber_int(v):
    body = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True)
    return _ber(0x02, body)


def _ber_oid(oid):
    parts = [int(x) for x in oid.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = b""
        chunk = bytes([p & 0x7F])
        p >>= 7
        while p:
            chunk = bytes([0x80 | (p & 0x7F)]) + chunk
            p >>= 7
        body += chunk
    return _ber(0x06, body)


def snmp_build_get(community, oids, req_id):
    """One SNMPv2c GetRequest for `oids` (list of dotted strings)."""
    binds = b"".join(_ber(0x30, _ber_oid(o) + _ber(0x05, b"")) for o in oids)
    pdu = _ber(0xA0, _ber_int(req_id) + _ber_int(0) + _ber_int(0)
               + _ber(0x30, binds))
    return _ber(0x30, _ber_int(1)                       # version = SNMPv2c
                + _ber(0x04, community.encode()) + pdu)


def _ber_walk(data, i, end):
    """Yield (tag, start, stop) for each TLV in data[i:end]."""
    while i < end:
        tag = data[i]
        ln = data[i + 1]
        i += 2
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(data[i:i + n], "big")
            i += n
        yield tag, i, i + ln
        i += ln


def snmp_parse_response(data):
    """Extract {oid_string: int} from a GetResponse. Unknown/absent values
    are simply missing from the result; the caller decides what's fatal."""
    def oid_str(body):
        out = [body[0] // 40, body[0] % 40]
        val = 0
        for b in body[1:]:
            val = (val << 7) | (b & 0x7F)
            if not (b & 0x80):
                out.append(val)
                val = 0
        return ".".join(map(str, out))

    result = {}
    try:
        (_, m0, m1), = ((t, a, b) for t, a, b in _ber_walk(data, 0, len(data)))
        fields = list(_ber_walk(data, m0, m1))
        pdu = next((f for f in fields if f[0] == 0xA2), None)
        if pdu is None:
            return result
        pdu_fields = list(_ber_walk(data, pdu[1], pdu[2]))
        if len(pdu_fields) < 4:
            return result
        vb_list = pdu_fields[3]
        for _tag, v0, v1 in _ber_walk(data, vb_list[1], vb_list[2]):
            inner = list(_ber_walk(data, v0, v1))
            if len(inner) != 2 or inner[0][0] != 0x06:
                continue
            oid = oid_str(data[inner[0][1]:inner[0][2]])
            vtag, a, b = inner[1]
            if vtag in (0x02, 0x41, 0x42, 0x43, 0x46):  # int/ctr32/gauge/ticks/ctr64
                result[oid] = int.from_bytes(data[a:b], "big")
    except (ValueError, IndexError):
        pass
    return result


IFHC_BASE = "1.3.6.1.2.1.31.1.1.1"   # IF-MIB 64-bit interface counters


class SnmpWanSource:
    """Cumulative WAN-interface counters over SNMPv2c: ifHCOutUcastPkts /
    ifHCInUcastPkts (+ octets). 'tx' is the interface's OUT direction -
    point it at the appliance's WAN interface."""
    kind = "snmp"

    IF_BASE = "1.3.6.1.2.1.2.2.1"     # classic 32-bit interface table

    def __init__(self, host, community, ifindex, port=161, timeout=1.5):
        self.host, self.community = host, community
        self.port, self.timeout = port, timeout
        self.oids = {
            "rx_pkts": f"{IFHC_BASE}.7.{ifindex}",
            "tx_pkts": f"{IFHC_BASE}.11.{ifindex}",
            "rx_bytes": f"{IFHC_BASE}.6.{ifindex}",
            "tx_bytes": f"{IFHC_BASE}.10.{ifindex}",
        }
        # Drop/error counters feed the FEC verdict (2.0.0). Optional: not
        # every device populates them, so absence is tolerated.
        self.opt_oids = {
            "rx_drops": f"{self.IF_BASE}.13.{ifindex}",
            "rx_errs": f"{self.IF_BASE}.14.{ifindex}",
            "tx_drops": f"{self.IF_BASE}.19.{ifindex}",
            "tx_errs": f"{self.IF_BASE}.20.{ifindex}",
        }
        self._req_id = 1
        self.detail = f"snmp {host} if{ifindex}"

    def poll(self):
        self._req_id = (self._req_id + 1) & 0x7FFFFFFF
        oids = list(self.oids.values()) + list(self.opt_oids.values())
        msg = snmp_build_get(self.community, oids, self._req_id)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        try:
            s.sendto(msg, (self.host, self.port))
            data, _ = s.recvfrom(65535)
        finally:
            s.close()
        values = snmp_parse_response(data)
        out = {}
        for name, oid in self.oids.items():
            if oid not in values:
                raise RuntimeError(f"SNMP response missing {name} ({oid})")
            out[name] = values[oid]
        for name, oid in self.opt_oids.items():
            if oid in values:
                out[name] = values[oid]
        return out


class RestWanSource:
    """Generic JSON counter poller: GET url, read cumulative packet counts
    at dotted key paths. Token goes out as both Authorization: Bearer and
    X-Auth-Token (Orchestrator-style); the exact EC endpoint is chosen at
    UAT against real gear - this class is the stable integration point."""
    kind = "rest"

    def __init__(self, url, token=None, tx_key="tx_pkts", rx_key="rx_pkts",
                 timeout=3.0):
        self.url, self.token = url, token
        self.tx_key, self.rx_key = tx_key, rx_key
        self.timeout = timeout
        self.detail = url

    def poll(self):
        import urllib.request
        req = urllib.request.Request(self.url)
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
            req.add_header("X-Auth-Token", self.token)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
        return {"tx_pkts": int(_json_path(doc, self.tx_key)),
                "rx_pkts": int(_json_path(doc, self.rx_key))}


class SimWanSource:
    """Simulated WAN counters: integrates the engine's own offered load
    through the EC slicing model (probes + reflected echoes, symmetric
    config) plus optional background noise. Proves the measured-vs-
    predicted workflow - and the square-wave calibration - with no fabric
    access at all. rates_fn() -> [(tx_pps, slices)] per stream."""
    kind = "sim"

    def __init__(self, rates_fn, noise_pps=0.0, loss_pct=0.0):
        self.rates_fn = rates_fn
        self.noise_pps = noise_pps
        self.loss_pct = loss_pct   # simulated WAN drop rate (FEC rehearsal)
        self.detail = "simulator (EC slicing model)"
        self._last = time.monotonic()
        self._tx = 0.0
        self._rx = 0.0
        self._drops = 0.0

    def poll(self):
        import random
        now = time.monotonic()
        dt = max(0.0, now - self._last)
        self._last = now
        wan_pps = sum(pps * slices * 2 for pps, slices in self.rates_fn())
        jitter = 1.0 + random.uniform(-0.02, 0.02)
        self._tx += (wan_pps * jitter + self.noise_pps) * dt
        self._rx += (wan_pps * jitter + self.noise_pps) * dt
        out = {"tx_pkts": int(self._tx), "rx_pkts": int(self._rx)}
        if self.loss_pct:
            self._drops += wan_pps * jitter * dt * self.loss_pct / 100.0
            out["rx_drops"] = int(self._drops)
        return out


class WanCounters:
    """Poll thread + rate derivation over a WAN counter source. Rates come
    from diffing successive cumulative polls; a counter going backwards
    (device reboot, 32-bit wrap) re-baselines instead of spiking."""

    POLL_S = 1.0

    def __init__(self, source):
        self.source = source
        self.lock = threading.Lock()
        self.stop_evt = threading.Event()
        self.thread = None
        self._prev = None      # (t, counters)
        self._status = {"kind": source.kind, "ok": False,
                        "detail": getattr(source, "detail", ""),
                        "tx_pps": None, "rx_pps": None,
                        "tx_mbps": None, "rx_mbps": None,
                        "drop_pps": None, "age": None}

    def start(self):
        self.thread = threading.Thread(target=self._run, name="wan-counters",
                                       daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_evt.set()

    def status(self):
        with self.lock:
            st = dict(self._status)
        if st["age"] is not None:
            st["age"] = time.monotonic() - st["age"]
        return st

    def _run(self):
        while not self.stop_evt.wait(self.POLL_S):
            try:
                cum = self.source.poll()
            except Exception as e:
                with self.lock:
                    self._status["ok"] = False
                    self._status["detail"] = f"{self.source.kind}: {e}"
                self._prev = None
                continue
            now = time.monotonic()
            rates = {}
            if self._prev is not None:
                pt, pcum = self._prev
                dt = max(1e-3, now - pt)
                for k in cum:
                    d = cum[k] - pcum.get(k, 0)
                    if d < 0:        # reboot / wrap: re-baseline this poll
                        rates = {}
                        break
                    rates[k] = d / dt
            self._prev = (now, cum)
            with self.lock:
                st = self._status
                st["ok"] = True
                st["detail"] = getattr(self.source, "detail", "")
                st["age"] = now
                if rates:
                    st["tx_pps"] = rates.get("tx_pkts")
                    st["rx_pps"] = rates.get("rx_pkts")
                    st["tx_mbps"] = (rates.get("tx_bytes", 0) * 8 / 1e6
                                     if "tx_bytes" in rates else None)
                    st["rx_mbps"] = (rates.get("rx_bytes", 0) * 8 / 1e6
                                     if "rx_bytes" in rates else None)
                    drops = [rates[k] for k in ("rx_drops", "rx_errs",
                                                "tx_drops", "tx_errs")
                             if k in rates]
                    st["drop_pps"] = sum(drops) if drops else None


def slice_loss_evidence(rows, slices_of_sid, deadband):
    """Live slicing evidence with NO fabric access (R-12 always-on variant):
    when two UDP streams whose probes slice into DIFFERENT WAN packet
    counts both lose, and the loss ratio tracks the slice-count ratio, the
    loss is happening per WAN packet - i.e. after slicing. Returns the
    verdict string, or None while the evidence isn't statistically there."""
    udp = [(r, slices_of_sid.get(r["sid"], 1)) for r in rows
           if r["proto"] == "UDP" and r["connected"]]
    if len(udp) < 2:
        return None
    small = min(udp, key=lambda x: x[1])
    large = max(udp, key=lambda x: x[1])
    n_s, n_l = small[1], large[1]
    if n_s == n_l:
        return None
    loss_s = small[0]["loss"] + small[0]["late"]
    loss_l = large[0]["loss"] + large[0]["late"]
    # Both must be real loss (above deadband), the small stream non-zero,
    # and enough decided probes behind each figure to mean something.
    if loss_s <= max(deadband, 0.2) or loss_l <= deadband:
        return None
    if small[0]["cum_tx"] < 200 or large[0]["cum_tx"] < 200:
        return None
    ratio = loss_l / loss_s
    expect = n_l / n_s
    if abs(ratio - expect) / expect > 0.35:
        return None
    return (f"{large[0]['name']} loses {ratio:.1f}× {small[0]['name']} "
            f"≈ its {n_l}-slice/{n_s}-slice ratio — per-WAN-packet loss "
            f"(slicing amplification measured live)")


def fec_verdict(wan, probe_loss_pct, slices):
    """R-11 (2.0.0): compare WAN-side drop counters with app-level probe
    loss and name what the fabric's repair machinery is doing.

      * WAN dropping while probes run clean -> FEC is repairing: the only
        way both can be true is packets being reconstructed after loss.
      * probe loss >> WAN slice loss -> amplification with no repair: one
        lost slice kills the whole N-slice packet.

    wan is WanCounters.status() (needs drop_pps + tx_pps: SNMP drop OIDs
    or the simulator's LOSS_PCT); slices is the sliced stream's WAN packet
    count. Returns the verdict string or None when there's nothing to say."""
    if not wan or not wan.get("ok") or wan.get("drop_pps") is None:
        return None
    tx = wan.get("tx_pps")
    if not tx or tx <= 1:
        return None
    drops = wan["drop_pps"]
    wan_loss = drops / (tx + drops) * 100.0
    if wan_loss < 0.05 and probe_loss_pct < 0.05:
        return None
    if wan_loss >= 0.05 and probe_loss_pct < max(0.1, wan_loss / 4.0):
        return (f"FEC repairing: WAN dropping {wan_loss:.2f}% "
                f"({drops:.0f} pps) while probes run {probe_loss_pct:.2f}% "
                f"clean — measured proof of repair")
    if (wan_loss >= 0.05 and slices > 1
            and probe_loss_pct >= wan_loss * max(1.5, 0.6 * slices)):
        return (f"loss amplification: probes lose {probe_loss_pct:.2f}% ≈ "
                f"{probe_loss_pct / wan_loss:.1f}× the WAN slice loss "
                f"({wan_loss:.2f}%) — a lost slice kills the whole "
                f"{slices}-slice packet (no FEC on this path)")
    return None


# ---------------------------------------------------------------------------
# Scenario scripting (R-4, 1.9.0): a JSON timeline the app replays, so a
# demo arc is one file instead of a memorized click sequence.
# ---------------------------------------------------------------------------
def parse_scenario(text):
    """Validate a scenario document -> (name, stages, repeat).

    {"name": "policy-demo", "repeat": 1, "stages": [
        {"name": "baseline", "secs": 60},
        {"name": "load", "secs": 30, "load_mbps": 10},
        {"name": "calibrate", "secs": 60, "load_mbps": 10,
         "square_on_s": 5, "square_off_s": 5},
        {"name": "clean slate", "secs": 5, "reset": true}]}

    repeat 0 = loop until the app closes. Raises ValueError with a
    user-facing message on any problem."""
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise ValueError(f"scenario is not valid JSON: {e}")
    if not isinstance(doc, dict):
        raise ValueError("scenario must be a JSON object")
    name = doc.get("name", "scenario")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("scenario 'name' must be a non-empty string")
    repeat = doc.get("repeat", 1)
    if not isinstance(repeat, int) or isinstance(repeat, bool) or repeat < 0:
        raise ValueError("'repeat' must be an integer >= 0 (0 = loop forever)")
    raw = doc.get("stages")
    if not isinstance(raw, list) or not raw:
        raise ValueError("scenario needs a non-empty 'stages' list")
    stages = []
    for i, s in enumerate(raw, 1):
        if not isinstance(s, dict):
            raise ValueError(f"stage {i} must be an object")
        st = {"name": str(s.get("name") or f"stage {i}")}
        secs = s.get("secs")
        if not isinstance(secs, (int, float)) or isinstance(secs, bool) \
                or secs <= 0:
            raise ValueError(f"stage {i} ({st['name']}): 'secs' must be > 0")
        st["secs"] = float(secs)
        mbps = s.get("load_mbps", 0)
        if not isinstance(mbps, (int, float)) or isinstance(mbps, bool) \
                or not (0 <= mbps <= 1000):
            raise ValueError(f"stage {i} ({st['name']}): 'load_mbps' must be "
                             f"in [0, 1000]")
        st["load_mbps"] = float(mbps)
        on_s = s.get("square_on_s", 0)
        off_s = s.get("square_off_s", 0)
        if bool(on_s) != bool(off_s):
            raise ValueError(f"stage {i} ({st['name']}): square_on_s and "
                             f"square_off_s go together")
        if on_s and not st["load_mbps"]:
            raise ValueError(f"stage {i} ({st['name']}): a square wave needs "
                             f"load_mbps > 0")
        for k, v in (("square_on_s", on_s), ("square_off_s", off_s)):
            if not isinstance(v, (int, float)) or isinstance(v, bool) or v < 0:
                raise ValueError(f"stage {i} ({st['name']}): '{k}' must be "
                                 f">= 0")
            st[k] = float(v)
        st["reset"] = bool(s.get("reset", False))
        stages.append(st)
    return name.strip(), stages, repeat


class ScenarioRunner:
    """Replay a parsed scenario against a running engine: stage markers on
    the charts, optional per-stage sustained load (its own LoadGenerator,
    native transport only), optional stat reset at a stage boundary."""

    def __init__(self, engine, args, scenario):
        self.engine = engine
        self.name, self.stages, self.repeat = scenario
        self.load = LoadGenerator(engine.peer, args.udp_ports[0],
                                  bind=args.bind,
                                  dont_fragment=args.dont_fragment,
                                  timeout=args.timeout)
        self.stop_evt = threading.Event()
        self.lock = threading.Lock()
        self._state = {"name": self.name, "stage": None, "idx": 0,
                       "total": len(self.stages), "pass_n": 1,
                       "repeat": self.repeat, "ends_at": None, "done": False}
        self.thread = threading.Thread(target=self._run, name="scenario",
                                       daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_evt.set()
        self.load.stop()

    def status(self):
        with self.lock:
            st = dict(self._state)
        if st["ends_at"] is not None:
            st["remaining"] = max(0.0, st["ends_at"] - time.monotonic())
        else:
            st["remaining"] = None
        return st

    def _swap_load(self, mbps, on_s, off_s):
        self.load.stop()
        for _ in range(100):            # let the old pacing thread exit
            if not self.load.running:
                break
            time.sleep(0.02)
        if mbps > 0:
            self.load.start(mbps, on_s, off_s)

    def _run(self):
        pass_n = 1
        while not self.stop_evt.is_set():
            for i, st in enumerate(self.stages):
                if self.stop_evt.is_set():
                    break
                with self.lock:
                    self._state.update(stage=st["name"], idx=i + 1,
                                       pass_n=pass_n,
                                       ends_at=time.monotonic() + st["secs"])
                self.engine.add_marker(st["name"])
                if st["reset"]:
                    self.engine.reset()
                self._swap_load(st["load_mbps"], st["square_on_s"],
                                st["square_off_s"])
                self.stop_evt.wait(st["secs"])
            if self.stop_evt.is_set() or (self.repeat
                                          and pass_n >= self.repeat):
                break
            pass_n += 1
        self.load.stop()
        self.engine.add_marker("end")
        with self.lock:
            self._state.update(stage=None, ends_at=None, done=True)


class FragmentSniffer:
    """Count IPv4 fragments to/from the peer (R-13, 2.0.0): app-level size
    checks can't distinguish the fabric delivering a WHOLE packet from the
    kernel quietly reassembling mid-path fragments - a capture-level
    fragment count can. Raw capture needs privileges (AF_PACKET: root/
    CAP_NET_RAW on Linux; SIO_RCVALL: admin on Windows), so this is
    best-effort: start() returns an error string instead of raising, and
    the UI shows 'unavailable' rather than lying with a zero."""

    def __init__(self, peer, bind="0.0.0.0"):
        self.peer = peer
        self.bind = bind
        self.stop_evt = threading.Event()
        self.thread = None
        self.sock = None
        self.l2_offset = 0
        self.error = None
        self.lock = threading.Lock()
        self._frags = 0     # continuation pieces + first fragments
        self._firsts = 0    # fragmented datagrams (first pieces only)

    def start(self):
        peer_ip = resolve_peer_ip(self.peer)
        if peer_ip is None:
            return "cannot resolve peer"
        self.peer_ip = peer_ip
        try:
            if sys.platform == "win32":
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_IP)
                bind_ip = self.bind if self.bind not in ("", "0.0.0.0") \
                    else local_ip_toward(self.peer, self.bind)
                s.bind((bind_ip, 0))
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                self.l2_offset = 0
            elif hasattr(socket, "AF_PACKET"):
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.htons(0x0800))
                self.l2_offset = 14
            else:
                return "raw capture not supported on this platform"
        except (OSError, PermissionError) as e:
            return (f"raw capture unavailable ({e}) - needs admin/root; "
                    f"fragment counting off")
        s.settimeout(0.5)
        self.sock = s
        self.thread = threading.Thread(target=self._run, name="frag-sniffer",
                                       daemon=True)
        self.thread.start()
        return None

    def stop(self):
        self.stop_evt.set()

    def status(self):
        with self.lock:
            return {"ok": self.sock is not None, "error": self.error,
                    "frags": self._frags, "firsts": self._firsts}

    def _run(self):
        while not self.stop_evt.is_set():
            try:
                pkt = self.sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            parsed = parse_ipv4_fragment(pkt, self.l2_offset)
            if parsed is None:
                continue
            is_frag, is_first, _proto, src, dst = parsed
            if not is_frag or self.peer_ip not in (src, dst):
                continue
            with self.lock:
                self._frags += 1
                if is_first:
                    self._firsts += 1
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Results export (R-19, 2.0.0): the demo's leave-behind
# ---------------------------------------------------------------------------
def build_report(engine, args):
    """Everything a POC leave-behind needs, as plain data: config, scores,
    per-stream stats, totals, diagnostics, WAN counters, scenario state."""
    snap = engine.snapshot()
    t = snap["totals"]
    rows = []
    for r in snap["rows"]:
        rows.append({k: r.get(k) for k in (
            "name", "proto", "port", "connected", "rtt_avg", "latency",
            "jitter", "loss", "late", "score", "mos", "label", "cum_tx",
            "cum_recv", "cum_lost", "cum_late", "fwd_lost", "rtn_lost",
            "peer_rx_max", "rx_echo_max", "expect_size", "dscp_req",
            "fwd_tos", "rtn_tos", "tx_pps")})
    return {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "version": __version__,
        "peer": snap["peer"],
        "command_line": " ".join(getattr(args, "_argv", []) or []),
        "uptime_s": round(snap["uptime"], 1),
        "since_reset_s": round(snap["since_reset"], 1),
        "overall": {"score": round(snap["overall"], 1),
                    "label": snap["overall_label"],
                    "worst": round(snap["worst"], 1),
                    "udp_mos": snap["udp_mos"], "tcp_pqi": snap["tcp_pqi"],
                    "links_up": snap["links_up"]},
        "offered_mbps": round(snap["offered_mbps"], 3),
        "target_mbps": snap["target_mbps"],
        "streams": rows,
        "totals": t,
        "diagnostics": {
            "udp_silent": snap["udp_silent"],
            "loss_pattern": snap["loss_pattern"],
            "slice_evidence": snap["slice_evidence"],
            "fec": snap["fec"],
            "size_status": snap["size_status"],
            "frags": snap["frags"],
        },
        "wan": snap["wan"],
        "scenario": snap["scenario"],
        "vxlan": snap["vxlan"],
    }


def render_report_html(data):
    """A self-contained single-file HTML report (inline CSS, no scripts):
    the demo's leave-behind. Tables mirror the dashboard's Totals/Isolate
    views; verdict lines carry the diagnostics that fired."""
    def esc(v):
        return (str(v).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;"))

    def num(v, fmt="{:.2f}"):
        return fmt.format(v) if isinstance(v, (int, float)) else "-"

    o = data["overall"]
    rows_html = ""
    for r in data["streams"]:
        dscp = "-"
        if r["dscp_req"] is not None or r["fwd_tos"] is not None:
            f_ = (dscp_name(r["fwd_tos"] >> 2)
                  if r["fwd_tos"] is not None else "?")
            r_ = (dscp_name(r["rtn_tos"] >> 2)
                  if r["rtn_tos"] is not None else "?")
            dscp = f"{dscp_name(r['dscp_req'])}→{f_}/{r_}"
        rows_html += (
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
            "<td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
            "<td>{}</td></tr>\n".format(
                esc(r["name"]),
                ('<span class="up">UP</span>' if r["connected"]
                 else '<span class="down">DOWN</span>'),
                num(r["rtt_avg"]), num(r["jitter"]), num(r["loss"], "{:.2f}"),
                num(r["late"], "{:.2f}"), num(r["score"], "{:.0f}"),
                num(r["mos"]) if r["mos"] is not None else "-",
                f"{r['cum_tx']:,}", f"{r['cum_lost']:,}", esc(dscp)))
    t = data["totals"]
    diags = [(k, v) for k, v in data["diagnostics"].items()
             if v not in (None, False) and k != "frags"]
    diag_html = "".join(f"<li><b>{esc(k)}:</b> {esc(v)}</li>"
                        for k, v in diags) or "<li>all clean</li>"
    wan = data["wan"]
    wan_html = ""
    if wan:
        wan_html = (
            '<h2>WAN counters ({})</h2>\n<div class="card"><div class="chips">'
            '<div class="chip"><span>tx</span><b>{} pps</b></div>'
            '<div class="chip"><span>rx</span><b>{} pps</b></div>{}'
            "</div></div>".format(
                esc(wan["kind"]), num(wan["tx_pps"], "{:.0f}"),
                num(wan["rx_pps"], "{:.0f}"),
                '<div class="chip"><span>drops</span><b>{} pps</b></div>'.format(
                    num(wan["drop_pps"], "{:.1f}"))
                if wan.get("drop_pps") is not None else ""))
    sc = score_color(o["score"] if isinstance(o["score"], (int, float)) else 0)
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Vitals report — {esc(data['peer'])}</title>
<style>
/* HPE Demo Instrument — shared with the live web dashboard (restrained). */
:root {{
  --bg: #0d1218; --surface: #1a2330; --stroke: #2a3545;
  --accent: #01a982; --accent-hi: #1ec9a0;
  --txt: #e8eef5; --dim: #8b9aab; --faint: #5c6b7d;
  --score: {sc};
}}
* {{ box-sizing: border-box; }}
body {{
  font-family: 'Segoe UI Variable Text','Segoe UI',system-ui,sans-serif;
  background:
    radial-gradient(80rem 28rem at 0% -20%, rgba(1,169,130,.07), transparent 55%),
    var(--bg);
  color: var(--txt); margin: 0; padding: 0 0 5rem; line-height: 1.45;
}}
.wrap {{ max-width: 78rem; margin: 0 auto; padding: 0 2rem; }}
header {{ padding: 2.4rem 0 1.4rem; }}
h1 {{
  font-size: 1.7rem; margin: 0; letter-spacing: -.02em; font-weight: 650;
  display: flex; align-items: center; gap: .7rem;
}}
h1 svg {{ color: var(--accent); flex: none; }}
h2 {{
  font-size: .7rem; text-transform: uppercase; letter-spacing: .12em;
  color: var(--faint); margin: 2.2rem 0 .75rem; font-weight: 700;
}}
.meta {{ color: var(--faint); font-size: .82rem; margin: .5rem 0 0; }}
.meta code {{
  font-family: {FONT_MONO!r},ui-monospace,monospace; font-size: .78rem;
  background: var(--surface); padding: .15rem .45rem; border-radius: .3rem;
}}
.card {{
  background: var(--surface); border: 1px solid var(--stroke);
  border-radius: 10px; padding: 1.25rem 1.4rem;
}}
.hero {{ display: flex; align-items: center; gap: 1.75rem; flex-wrap: wrap; }}
.orb {{
  width: 7.5rem; height: 7.5rem; border-radius: 50%; flex: none;
  display: grid; place-items: center; position: relative;
  border: 3px solid var(--score);
  background: #141b24;
}}
.orb b {{
  font-size: 2.4rem; letter-spacing: -.03em; font-weight: 650;
  font-variant-numeric: tabular-nums; color: var(--score);
}}
.verdict {{ flex: 1 1 16rem; }}
.verdict .label {{ font-size: 1.75rem; font-weight: 650; letter-spacing: -.02em; }}
.verdict .sub {{ color: var(--dim); font-size: .9rem; }}
.chips {{ display: flex; gap: .6rem; flex-wrap: wrap; margin-top: .9rem; }}
.chip {{
  background: #141b24; border: 1px solid var(--stroke);
  border-radius: 6px; padding: .45rem .8rem; font-size: .82rem;
}}
.chip span {{
  color: var(--faint); text-transform: uppercase; letter-spacing: .08em;
  font-size: .64rem; font-weight: 700; margin-right: .45rem;
}}
.chip b {{ font-variant-numeric: tabular-nums; }}
.scroll {{ overflow-x: auto; }}
table {{ border-collapse: collapse; width: 100%; font-size: .86rem; }}
th, td {{
  padding: .55rem .75rem; text-align: right; white-space: nowrap;
  border-bottom: 1px solid var(--stroke);
  font-variant-numeric: tabular-nums;
}}
th {{
  color: var(--faint); font-size: .66rem; text-transform: uppercase;
  letter-spacing: .09em;
}}
tbody tr:last-child td {{ border-bottom: 0; }}
tbody tr:hover td {{ background: rgba(1,169,130,.06); }}
td:first-child, th:first-child {{ text-align: left; font-weight: 600; }}
.up {{ color: var(--accent-hi); }} .down {{ color: #e45757; }}
ul {{ margin: 0; padding-left: 1.1rem; }}
li {{ margin: .3rem 0; }}
li b {{ color: #e6a23c; font-weight: 600; }}
footer {{ color: var(--faint); font-size: .76rem; margin-top: 2.4rem; }}
@media (max-width: 40rem) {{
  .wrap {{ padding: 0 1rem; }} .orb {{ width: 5.8rem; height: 5.8rem; }}
  .orb b {{ font-size: 1.8rem; }}
}}
</style></head><body>
<div class="wrap">
<header>
  <h1><svg width="47" height="30" viewBox="0 0 54 34" fill="none"
        aria-hidden="true"><polyline points="2,18 12,18 15,14 18,18 21,18
        23,21 26,4 29,30 32,18 36,11 40,18 51,18" stroke="currentColor"
        stroke-width="2.4" stroke-linecap="round"
        stroke-linejoin="round"/></svg>Network Vitals <span
    style="color:var(--faint);font-weight:400">report</span></h1>
  <p class="meta">generated {esc(data['generated'])} · v{esc(data['version'])}
   · peer {esc(data['peer'])} · uptime {data['uptime_s']} s ·
   <code>{esc(data['command_line'])}</code></p>
</header>

<div class="card hero">
  <div class="orb"><b>{o['score']}</b></div>
  <div class="verdict">
    <div class="label">{esc(o['label'])}</div>
    <div class="sub">worst {o['worst']} · {o['links_up']} streams up ·
      offered {data['offered_mbps']} Mbps{
        ' / target ' + str(data['target_mbps']) if data['target_mbps'] else ''}</div>
    <div class="chips">
      <div class="chip"><span>UDP MOS</span><b>{num(o['udp_mos'])}</b></div>
      <div class="chip"><span>TCP PQI</span><b>{num(o['tcp_pqi'], '{:.0f}')}</b></div>
      <div class="chip"><span>Sent</span><b>{t['tx']:,}</b></div>
      <div class="chip"><span>Lost</span><b>{t['lost']:,} ({t['loss_pct']:.2f}%)</b></div>
    </div>
  </div>
</div>
{wan_html}
<h2>Streams</h2>
<div class="card scroll">
<table><thead><tr><th>Stream</th><th>Status</th><th>RTT ms</th><th>Jitter</th>
<th>Loss %</th><th>Late %</th><th>Score</th><th>MOS</th><th>Sent</th>
<th>Lost</th><th>DSCP rq→f/r</th></tr></thead>
<tbody>
{rows_html}</tbody></table>
</div>

<h2>Totals (since reset)</h2>
<div class="card">
<p style="margin:0">sent {t['tx']:,} · received {t['recv']:,} ·
 lost {t['lost']:,} ({t['loss_pct']:.2f}%) · late {t['late']:,}
 ({t['late_pct']:.2f}%) · forward {t['fwd_lost']:,} ({t['fwd_pct']:.2f}%) ·
 return {t['rtn_lost']:,} ({t['rtn_pct']:.2f}%)</p>
<p class="meta">lifetime: sent {t['life_tx']:,} · lost {t['life_lost']:,}
 ({t['life_loss_pct']:.2f}%) · late {t['life_late']:,}
 ({t['life_late_pct']:.2f}%)</p>
</div>

<h2>Diagnostics</h2>
<div class="card"><ul>{diag_html}</ul></div>

<footer>Generated by Network Vitals v{esc(data['version'])} —
the SD-WAN demo traffic instrument.</footer>
</div>
</body></html>
"""


def write_report(engine, args, base=None):
    """Write the JSON + HTML report pair. `base` is a path base (without
    extension); default: config_dir()/reports/netvitals-<stamp>. Returns
    (json_path, html_path)."""
    data = build_report(engine, args)
    if base is None:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        rep_dir = os.path.join(config_dir(), "reports")
        os.makedirs(rep_dir, exist_ok=True)
        base = os.path.join(rep_dir, f"netvitals-{stamp}")
    jpath, hpath = base + ".json", base + ".html"
    with open(jpath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1)
    with open(hpath, "w", encoding="utf-8") as fh:
        fh.write(render_report_html(data))
    return jpath, hpath


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

    if args.slice_scan:
        run_slice_scan(args)
        return

    # Scenario: parse early so a bad file dies at the command line.
    scenario = None
    if args.scenario:
        try:
            with open(args.scenario, "r", encoding="utf-8") as fh:
                scenario = parse_scenario(fh.read())
        except OSError as e:
            print(f"error: cannot read scenario file: {e}", file=sys.stderr)
            return 2
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        if args.vxlan and any(s["load_mbps"] for s in scenario[1]):
            print("error: scenario load stages need native transport - a "
                  "--vxlan peer has no native UDP listener to echo them.",
                  file=sys.stderr)
            return 2

    # Per-stream profiles / DSCP lists resolve against the FINAL stream
    # catalogue (ports may add or drop streams) and the final probe size.
    profiles = None
    if args.profiles is not None:
        if len(args.profiles) > len(STREAMS):
            print(f"error: --profiles has {len(args.profiles)} entries but "
                  f"only {len(STREAMS)} streams are configured",
                  file=sys.stderr)
            return 2
        profiles = resolve_profiles(args.profiles, len(STREAMS), args.size)
    dscp = None
    if args.dscp is not None:
        if len(args.dscp) > len(STREAMS):
            print(f"error: --dscp has {len(args.dscp)} entries but only "
                  f"{len(STREAMS)} streams are configured", file=sys.stderr)
            return 2
        dscp = (list(args.dscp) + [None] * len(STREAMS))[:len(STREAMS)]

    # --mbps: derive each stream's rate from its own (mean) wire size, so
    # the offered-load math matches what is actually sent - profiles keep
    # their sizes, --mbps overrides their rates.
    if args.mbps is not None:
        if not (0 < args.mbps <= 1000):
            print("error: --mbps must be in (0, 1000]", file=sys.stderr)
            return 2
        if profiles is None:
            profiles = resolve_profiles(None, len(STREAMS), args.size)
        rates = pps_for_streams(args.mbps, profiles,
                                [cfg[1] for cfg in STREAMS])
        profiles = [(sizes, rate)
                    for (sizes, _p), rate in zip(profiles, rates)]
        print(f"note: --mbps {_fmt_num(args.mbps)} -> "
              + ", ".join(f"{STREAMS[i][3]} {rates[i]:.1f} pps"
                          for i in range(len(STREAMS)))
              + " (probes only; echoes double the wire load).",
              file=sys.stderr)

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
                        peers=args.peers, tcp_pps=args.tcp_pps,
                        target_mbps=args.mbps, profiles=profiles, dscp=dscp)
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

    # 1.9.0: measured-WAN poller and scenario runner ride on the engine.
    if args.wan_counters is not None:
        spec = args.wan_counters
        if spec["kind"] == "sim":
            def sim_rates(e=engine):
                rows = e.snapshot()["rows"]
                rates = [(r["tx_pps"], e.slices_of_sid[r["sid"]])
                         for r in rows]
                scn = e.scenario
                if scn is not None:
                    st = scn.load.status()
                    if st["running"]:
                        pps = (st["achieved_mbps"] * 1e6 / 8.0
                               / (BURST_PROBE_SIZE + IPV4_UDP_OVERHEAD))
                        rates.append((pps, len(ec_wire_view(
                            BURST_PROBE_SIZE + 28))))
                return rates
            source = SimWanSource(sim_rates, spec["noise_pps"],
                                  spec.get("loss_pct", 0.0))
        elif spec["kind"] == "snmp":
            source = SnmpWanSource(spec["host"], spec["community"],
                                   spec["ifindex"], spec["port"])
        else:
            source = RestWanSource(spec["url"], spec["token"],
                                   spec["tx_key"], spec["rx_key"])
        engine.wan = WanCounters(source)
        engine.wan.start()

    if scenario is not None:
        engine.scenario = ScenarioRunner(engine, args, scenario)
        engine.scenario.start()

    if args.frag_sniffer:
        engine.frag = FragmentSniffer(engine.peer, args.bind)
        err = engine.frag.start()
        if err:
            engine.frag.error = err
            print(f"note: {err}", file=sys.stderr)

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
        if args.report:
            try:
                _jp, hp = write_report(engine, args, base=args.report)
                print(f"report written: {hp}")
            except OSError as e:
                print(f"error: report failed: {e}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
