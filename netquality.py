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

__version__ = "2.0.0a1"

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
# Per-stream line colors; cycles when a port list grows past the palette
# (1.8.0: up to 8 streams per protocol). The first four match the historic
# 2 UDP + 2 TCP assignment so screenshots stay comparable across versions.
STREAM_PALETTE = ("#01A982", "#FF8300", "#00B0E6", "#FEC901",
                  "#C140FF", "#7ee2b8", "#ff7eb6", "#9aa3ad")


def stream_color(sid):
    return STREAM_PALETTE[sid % len(STREAM_PALETTE)]



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
                band_label=None, markers=None, mark_labels=False):
    """Render one time-series chart onto a Tk Canvas.

    series: list of (sid, color, short_label). samples_by_sid: {sid: [sample]}.
    Each sample is {'t', key..., 'up'}; None values break the line (gap = down).
    band: optional [{'t','lo','hi','up'}] drawn as a shaded region behind the
    series lines (None/down samples break it), labeled `band_label`.
    markers: optional [(t_mono, label)] scenario stage boundaries, drawn as
    dashed verticals (labels only when mark_labels, to keep small charts clean).
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

    # scenario stage markers (behind the series lines)
    if markers:
        for mt, mlabel in markers:
            if mt < t0 or mt > now:
                continue
            mx = X(mt)
            canvas.create_line(mx, pad_t, mx, pad_t + ph, fill="#5a6270",
                               dash=(3, 3))
            if mark_labels and mlabel:
                canvas.create_text(min(mx + 3, w - pad_r - 4), pad_t + 8,
                                   text=mlabel, anchor="w", fill=TXT_DIM,
                                   font=(FONT, 7))

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
    import tkinter as tk
    from tkinter import ttk

    view_seconds = float(args.history)
    series = [(sid, stream_color(sid), name.split("-")[1])
              for sid, proto, port, name in STREAMS]

    root = tk.Tk()
    _set_window_icon(root)
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

    topo_shown = {"on": False}

    def do_toggle_topo():
        topo_shown["on"] = not topo_shown["on"]
        if topo_shown["on"]:
            topo_frame.pack(fill="x", side="bottom", before=charts)
            topo_btn.configure(text="▴  Topology")
        else:
            topo_frame.pack_forget()
            topo_btn.configure(text="≣  Topology")

    topo_btn = tk.Button(btnbar, text="≣  Topology", command=do_toggle_topo,
                         bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                         activeforeground="white", relief="flat", bd=0,
                         highlightthickness=0, padx=12, pady=5,
                         font=(FONT, 9, "bold"), cursor="hand2")
    topo_btn.pack(side="left", padx=(0, 6))

    load_shown = {"on": False}

    def do_toggle_load():
        load_shown["on"] = not load_shown["on"]
        if load_shown["on"]:
            load_frame.pack(fill="x", side="bottom", before=charts)
            load_btn.configure(text="▴  Load")
        else:
            load_frame.pack_forget()
            load_btn.configure(text="⚡  Load")

    load_btn = tk.Button(btnbar, text="⚡  Load", command=do_toggle_load,
                         bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                         activeforeground="white", relief="flat", bd=0,
                         highlightthickness=0, padx=12, pady=5,
                         font=(FONT, 9, "bold"), cursor="hand2")
    load_btn.pack(side="left", padx=(0, 6))

    def do_fit_charts():
        """Collapse the bottom tables and force a fresh geometry pass so the
        charts reclaim the full current window space."""
        if totals_shown["on"]:
            do_toggle_totals()
        if isolate_shown["on"]:
            do_toggle_isolate()
        if anatomy_shown["on"]:
            do_toggle_anatomy()
        if topo_shown["on"]:
            do_toggle_topo()
        if load_shown["on"]:
            do_toggle_load()
        for c in (lat_canvas, loss_canvas, jit_canvas, owd_canvas):
            c.configure(width=100, height=80)
        root.update_idletasks()

    fit_btn = tk.Button(btnbar, text="⤢  Fit charts", command=do_fit_charts,
                        bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                        activeforeground="white", relief="flat", bd=0,
                        highlightthickness=0, padx=12, pady=5,
                        font=(FONT, 9, "bold"), cursor="hand2")
    fit_btn.pack(side="left")

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

    rep_btn = tk.Button(btnbar, text="⭳  Report", command=do_report,
                        bg=PANEL_HI, fg=TXT, activebackground=HPE_GREEN_DK,
                        activeforeground="white", relief="flat", bd=0,
                        highlightthickness=0, padx=12, pady=5,
                        font=(FONT, 9, "bold"), cursor="hand2")
    rep_btn.pack(side="left")

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
    scen_var = tk.StringVar(value="")
    scen_lbl = tk.Label(footer, textvariable=scen_var, fg=HPE_GREEN, bg=BG,
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
                   "txb", "peerrx", "echorx", "size", "dscp")
    totals_head = {"stream": "Stream", "sent": "Sent", "recv": "Received",
                   "lost": "Lost", "late": "Late", "lossp": "Loss %",
                   "txb": "TX B", "peerrx": "Peer RX B", "echorx": "My RX B",
                   "size": "Size", "dscp": "DSCP rq→f/r"}
    totals_w = {"stream": 110, "sent": 78, "recv": 84, "lost": 64, "late": 60,
                "lossp": 64, "txb": 66, "peerrx": 78, "echorx": 72, "size": 80,
                "dscp": 110}
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
                           values=(name, 0, 0, 0, 0, "0.0", 0, 0, 0, "-", "-"))
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
        c.create_text(x0, y4 + 36, anchor="w", fill=TXT_DIM, font=(FONT, 9),
                      text=noec)

    anat_canvas.bind("<Configure>", draw_anatomy)
    # Measured WAN line under the anatomy canvas (1.9.0): live counters
    # from --wan-counters next to the model's prediction - the loop closer.
    anat_wan_var = tk.StringVar(value="")
    tk.Label(anat_frame, textvariable=anat_wan_var, fg=TXT_DIM, bg=BG,
             font=(FONT, 9), anchor="w").pack(fill="x", pady=(2, 0))

    # ---- topology strip (hidden; Host → EC → fabric → EC → Host with the
    # measured numbers moving, R-15) ------------------------------------------
    topo_frame = tk.Frame(root, bg=BG, padx=12, pady=2)
    # not packed here — do_toggle_topo packs/unpacks the whole frame
    topo_canvas = tk.Canvas(topo_frame, bg=PANEL, highlightthickness=0,
                            height=118)
    topo_canvas.pack(fill="x")
    topo_state = {"snap": None}

    def draw_topology(_event=None):
        snap = topo_state["snap"]
        c = topo_canvas
        w = c.winfo_width()
        if w <= 1 or snap is None or not topo_shown["on"]:
            return
        c.delete("all")
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
        bw, bh, y0 = 150, 44, 22
        gap = max(24, (w - 28 - bw * len(nodes)) // max(1, len(nodes) - 1))
        x = 14
        for i, (name, sub) in enumerate(nodes):
            fill = PANEL_HI if i != 2 else HPE_GREEN_DK
            c.create_rectangle(x, y0, x + bw, y0 + bh, fill=fill,
                               outline=GRID)
            c.create_text(x + bw / 2, y0 + 15, text=name, fill=TXT,
                          font=(FONT, 9, "bold"))
            c.create_text(x + bw / 2, y0 + 31, text=sub, fill=TXT_DIM,
                          font=(FONT, 8))
            if i < len(nodes) - 1:
                ax0, ax1 = x + bw, x + bw + gap
                ay = y0 + bh / 2
                c.create_line(ax0, ay, ax1, ay, fill=HPE_GREEN, width=2,
                              arrow="last")
                c.create_line(ax0, ay + 8, ax1, ay + 8, fill="#FF8300",
                              width=2, arrow="first")
            x += bw + gap
        wan_txt = ("WAN span: predicted "
                   f"{pred:.0f} pps"
                   + (f" · measured {meas:.0f} pps ({wan['kind']})"
                      if meas is not None else
                      "  ·  add --wan-counters to measure it"))
        c.create_text(14, y0 + bh + 26, anchor="w", fill=TXT_DIM,
                      font=(FONT, 9), text=wan_txt)

    topo_canvas.bind("<Configure>", draw_topology)

    # ---- sustained load panel (hidden; the burst generator made resident) --
    # A known-quantity UDP load offered WHILE the scored streams keep
    # measuring, so the charts show what the load does to the path. TEST
    # probes are excluded from loss isolation on both ends; the optional
    # square wave is the calibration pattern for diffing WAN-side counters.
    load_gen = LoadGenerator(engine.peer, args.udp_ports[0], bind=args.bind,
                             dont_fragment=args.dont_fragment,
                             timeout=args.timeout)
    load_frame = tk.Frame(root, bg=BG, padx=12, pady=2)
    # not packed here — do_toggle_load packs/unpacks the whole frame
    load_inner = tk.Frame(load_frame, bg=PANEL, padx=10, pady=8)
    load_inner.pack(fill="x")
    load_mbps_var = tk.StringVar(value="5")
    load_sq_var = tk.BooleanVar(value=False)
    load_on_var = tk.StringVar(value="10")
    load_off_var = tk.StringVar(value="10")
    load_status_var = tk.StringVar(value="idle")
    load_hdr = tk.Frame(load_inner, bg=PANEL)
    load_hdr.pack(fill="x")
    tk.Label(load_hdr, text="Sustained load", fg=TXT, bg=PANEL,
             font=(FONT, 10, "bold")).pack(side="left")
    tk.Label(load_hdr, text=f"UDP {BURST_PROBE_SIZE} B TEST probes → "
                            f"{engine.peer}:{args.udp_ports[0]} · echoes "
                            f"double the wire load · excluded from loss "
                            f"isolation",
             fg=TXT_DIM, bg=PANEL, font=(FONT, 8)).pack(side="left",
                                                        padx=(10, 0))
    ctl = tk.Frame(load_inner, bg=PANEL)
    ctl.pack(fill="x", pady=(6, 0))

    def _load_entry(var, width):
        e = tk.Entry(ctl, textvariable=var, width=width, bg=PANEL_HI, fg=TXT,
                     insertbackground=TXT, relief="flat", highlightthickness=1,
                     highlightbackground=GRID, highlightcolor=HPE_GREEN,
                     font=(FONT, 10), justify="right")
        return e

    tk.Label(ctl, text="Mbps", fg=TXT_DIM, bg=PANEL,
             font=(FONT, 9)).pack(side="left")
    _load_entry(load_mbps_var, 6).pack(side="left", padx=(4, 12), ipady=1)
    tk.Checkbutton(ctl, text="square wave", variable=load_sq_var, bg=PANEL,
                   fg=TXT, activebackground=PANEL, activeforeground=TXT,
                   selectcolor=PANEL_HI, font=(FONT, 9), highlightthickness=0,
                   cursor="hand2").pack(side="left")
    tk.Label(ctl, text="on s", fg=TXT_DIM, bg=PANEL,
             font=(FONT, 9)).pack(side="left", padx=(8, 0))
    _load_entry(load_on_var, 4).pack(side="left", padx=(4, 0), ipady=1)
    tk.Label(ctl, text="off s", fg=TXT_DIM, bg=PANEL,
             font=(FONT, 9)).pack(side="left", padx=(8, 0))
    _load_entry(load_off_var, 4).pack(side="left", padx=(4, 12), ipady=1)

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

    load_start_btn = tk.Button(ctl, text="▶  Start load", command=do_load_start,
                               bg=PANEL_HI, fg=TXT,
                               activebackground=HPE_GREEN_DK,
                               activeforeground="white", relief="flat", bd=0,
                               highlightthickness=0, padx=12, pady=3,
                               font=(FONT, 9, "bold"), cursor="hand2")
    load_start_btn.pack(side="left")
    tk.Label(ctl, textvariable=load_status_var, fg=TXT_DIM, bg=PANEL,
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
                    [("F", HPE_GREEN, "fwd→"), ("R", "#FF8300", "rtn←")],
                    {"F": owd_f, "R": owd_r},
                    view_seconds, now, ymin_floor=2.0, unit="",
                    value_fmt=lambda v: f"{v:.1f}" if v < 10 else f"{v:.0f}",
                    markers=marks)

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
    import tkinter as tk

    view_seconds = float(args.history)
    series = [(sid, stream_color(sid), name.split("-")[1])
              for sid, proto, port, name in STREAMS]
    peers = engine.peers

    root = tk.Tk()
    _set_window_icon(root)
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
                state["manifest"], state["vstr"] = val, val["version"]
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

    mkcheck(body, "Don't fragment - drop oversized probes instead of "
                  "splitting them (jumbo testing)", df_var, 4)

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
                esc(r["name"]), "UP" if r["connected"] else "DOWN",
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
        wan_html = ("<p><b>WAN counters ({}):</b> tx {} pps · rx {} pps"
                    "{}</p>".format(
                        esc(wan["kind"]), num(wan["tx_pps"], "{:.0f}"),
                        num(wan["rx_pps"], "{:.0f}"),
                        f" · drops {num(wan['drop_pps'], '{:.1f}')} pps"
                        if wan.get("drop_pps") is not None else ""))
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Network Vitals report — {esc(data['peer'])}</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #1a1d21;
       color: #f2f4f5; margin: 2em; }}
h1 {{ color: #01A982; }} h2 {{ color: #9aa3ad; margin-top: 1.4em; }}
table {{ border-collapse: collapse; margin: 0.6em 0; }}
th, td {{ border: 1px solid #363b44; padding: 5px 10px; text-align: right; }}
th {{ background: #23272e; color: #01A982; }}
td:first-child, th:first-child {{ text-align: left; }}
.score {{ font-size: 2.4em; font-weight: bold; color: #01A982; }}
.meta {{ color: #9aa3ad; font-size: 0.9em; }}
ul {{ line-height: 1.6; }}
</style></head><body>
<h1>Network Vitals — demo report</h1>
<p class="meta">generated {esc(data['generated'])} · v{esc(data['version'])}
 · peer {esc(data['peer'])} · uptime {data['uptime_s']} s
 · <code>{esc(data['command_line'])}</code></p>
<p><span class="score">{o['score']}</span> {esc(o['label'])}
 (worst {o['worst']}, {o['links_up']} streams up)
 · UDP MOS {num(o['udp_mos'])} · TCP PQI {num(o['tcp_pqi'], '{:.0f}')}
 · offered {data['offered_mbps']} Mbps{
     ' / target ' + str(data['target_mbps']) if data['target_mbps'] else ''}</p>
{wan_html}
<h2>Streams</h2>
<table><tr><th>Stream</th><th>Status</th><th>RTT ms</th><th>Jitter</th>
<th>Loss %</th><th>Late %</th><th>Score</th><th>MOS</th><th>Sent</th>
<th>Lost</th><th>DSCP rq→f/r</th></tr>
{rows_html}</table>
<h2>Totals (since reset)</h2>
<p>sent {t['tx']:,} · received {t['recv']:,} · lost {t['lost']:,}
 ({t['loss_pct']:.2f}%) · late {t['late']:,} ({t['late_pct']:.2f}%) ·
 forward {t['fwd_lost']:,} ({t['fwd_pct']:.2f}%) · return {t['rtn_lost']:,}
 ({t['rtn_pct']:.2f}%)</p>
<p class="meta">lifetime: sent {t['life_tx']:,} · lost {t['life_lost']:,}
 ({t['life_loss_pct']:.2f}%) · late {t['life_late']:,}
 ({t['life_late_pct']:.2f}%)</p>
<h2>Diagnostics</h2>
<ul>{diag_html}</ul>
<p class="meta">Generated by Network Vitals v{esc(data['version'])} —
the SD-WAN demo traffic instrument.</p>
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
