# Network Vitals

A single, self-contained Python app (`netquality.py`) that precisely measures
**loss, latency and jitter** between two Windows workstations and rates the
connection with a **quality score**.

You run the *exact same program* on both machines. Each instance continuously
**sends and receives** four probe streams at once:

| Stream      | Protocol | Default port |
|-------------|----------|--------------|
| UDP-30201   | UDP      | 30201 |
| UDP-30202   | UDP      | 30202 |
| TCP-30101   | TCP      | 30101 |
| TCP-30102   | TCP      | 30102 |

The default ports live in the unassigned **30100/30200** block: below every OS
ephemeral range (so the OS won't reuse them) and with no Wireshark dissector.
(The earlier 5201/5202 defaults collided with **iPerf3's** default port, which
made Wireshark misparse our packets as iPerf3 and report bogus "loss / out-of-
order".) Override them with `--udp-ports A,B` / `--tcp-ports A,B` if your
firewall needs specific ports.

Traffic flows **bi-directionally on every stream, all the time**. The UI updates
in realtime and shows the connection's overall experience at a glance.

With `--vxlan` on both ends, all four streams travel inside genuine **VXLAN
encapsulation** between the hosts (userspace VTEP, no admin rights) — see
*VXLAN encapsulation* below for using it to demonstrate transparent
fragmentation.

The dashboard shows **four live + history charts**:

- **Latency (RTT, ms)** — one line per stream, over a shaded **p5–p95 band**
  of the pooled UDP samples: tail latency (bufferbloat, microbursts) widens
  the band even while the averages look fine.
- **Loss + late (%)** — one line per stream.
- **Jitter (ms)** — one line per stream.
- **One-way drift (ms)** — two lines, `fwd→` and `rtn←`: how much each
  *direction's* delay has grown above its recent (~60 s) best. Congestion is
  almost always directional; this names the direction without synchronized
  clocks (the echo carries the reflector's clock, the unknown offset cancels
  against a min-filtered baseline, and residual clock slew at tens of ppm is
  ~1 ms/min — negligible against real queueing).

plus, in the header:

- a big colour-coded **Experience score** (0–100, green = excellent → red = bad),
- a **UDP MOS** (E-model, averaged over the UDP streams) and a **TCP PQI** —
  MOS is a media metric and the wrong lens for TCP, which converts loss into
  delay via retransmission, so TCP streams get a **Path Quality Index**
  (0–100) instead, built from:
  - RTT (same delay-impairment curve as the E-model),
  - RTT variance (stddev over the window),
  - retransmission rate — measured at the app layer as *stalled deliveries*
    (echoes arriving ≥ ~RTO beyond the window's baseline RTT) plus lost/late
    probes,
  - effective throughput (achieved echo rate vs offered probe rate; TCP
    backpressure drags this below 1),
  - TCP connection-establishment time (every reconnect is timed, plus a
    throwaway handshake is sampled every ~15 s per TCP port; establishment
    well beyond the RTT means SYN loss),
- a **Reset / Clear** button that wipes the charts and all accumulated
  loss/latency/jitter stats so a demo can start from a clean slate,
- a **Totals** button that toggles a per-stream table of the since-reset
  counters (sent / received / lost / late / loss %). The bottom status bar
  always shows the aggregate **since reset** counters (cleared by
  **Reset / Clear**) *and* the **lifetime** counters (never cleared while the
  app runs), so the loss over the whole run stays visible across resets.
- an **Isolate** button that splits each stream's round-trip loss into a
  **forward** component (probes that never reached the peer) and a **return**
  component (echoes that never made it back), and names the failing leg — see
  *Locating loss* below.
- an **Anatomy** button that toggles a byte-proportional wire view of one
  probe through an EdgeConnect SD-WAN fabric: the LAN packet on top and the
  predicted tunnel packets (slices + encapsulation overhead) below, with the
  packet amplification factor and predicted WAN pps — see *Wire anatomy*
  below.

Charts keep a rolling history (default 5 minutes, `--history`). The window
resizes freely; the charts grow and shrink with it.

To stop trivial blips from denting a demo, a **loss deadband** (`--loss-deadband`,
default 0.5%) treats a combined loss+late below the threshold as 0 for the score
and the loss chart. (The lifetime totals always show the true raw counts.)

## Hardening & behavior notes

- **The measurement must not disturb the measured** (1.5.1). 1.5.0's one-way
  drift bookkeeping scanned minutes of samples *while holding the per-stream
  lock the receive threads need*, and its history sampler did its arithmetic
  under the chart-history lock. On busy hosts the stalls clumped the echo
  path into microbursts — visible as slowly growing jitter / p95 band and
  scattered **return-dominant loss on both ends of a clean path**. 1.5.1
  makes all hot-lock work O(small-constant) (bucketed minima instead of
  scans, sampling computed outside the locks, the loss-pattern verdict cached
  once per second) and decimates the band polygon. If 1.5.0 showed your
  clean path as lossy, update both ends and re-check before blaming the
  network.
- **Start order doesn't matter.** On Windows, probing a peer whose app isn't
  running yet used to kill the UDP receive thread (ICMP Port Unreachable
  surfaces as a socket error); this is now suppressed and either side can be
  started, stopped or rebooted at any time. (1.3.0 note: the suppression is
  now done via `WSAIoctl` directly — Python's `socket.ioctl()` silently
  rejects `SIO_UDP_CONNRESET`, so in 1.1.0–1.2.0 only the error-catching
  half of this fix was active and a stream of ICMP could still eat probes.)
- **"UDP silent" warning.** TCP streams flowing while *all* UDP streams are
  down is never a healthy path — it means UDP is blocked in the middle
  (firewall/ACL on ports 30201–30202) or the peer is running an outdated
  version whose UDP receive thread died (the pre-1.1.0 race above). Both UIs
  now call this out in the status bar instead of letting it read as loss;
  the remedy is opening the UDP ports and updating **both** ends.
- **Peer-only traffic.** Both the UDP and TCP listeners only answer the
  configured `--peer` address. Other hosts on the LAN can't skew the stats or
  use the tool as a packet reflector. (Run `--mtu-sweep` from the paired
  machine for the same reason.)
- **Mixed `--size` values interoperate.** TCP message framing is
  self-describing, so the two ends may run different probe sizes.
- **Restart-proof loss isolation.** The forward/return loss split survives
  peer restarts, the Reset button, and deep packet reordering; the peer's
  lifetime counters are re-baselined automatically.
- **Fit charts button.** If the charts ever end up mis-sized, ⤢ Fit charts
  collapses the Totals/Isolate tables and re-fits the charts to the current
  window. (The underlying layout bug — charts staying tiny after closing
  Totals — is also fixed.)
- **Single instance per port.** On Windows a second accidentally-launched
  instance now fails to bind instead of silently splitting packets with the
  first one (which used to read as huge random loss on both).

## Installing (Windows)

The easiest way onto a fresh workstation is the installer — it needs **no
admin rights** and takes care of Python too:

- **From a checkout / downloaded copy of this repo:** double-click
  **`install.bat`**.
- **From nothing** (PowerShell one-liner — downloads the installer and runs
  it; the first statement enables TLS 1.2, which Windows PowerShell 5.1
  doesn't use by default and GitHub requires):

  ```powershell
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; iwr -useb https://raw.githubusercontent.com/robertsonc/netvitals/main/install.ps1 -OutFile "$env:TEMP\nv-install.ps1"; powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\nv-install.ps1"
  ```

A setup window opens (install folder, shortcut choices, live log) and then:

1. **Python**: finds an existing Python 3.8+ with Tkinter; if there is none
   (or it lacks Tkinter), the official python.org **3.12** installer is
   downloaded and installed silently **per-user**.
2. **App files**: copied to `%LOCALAPPDATA%\Programs\NetVitals` (from the
   local folder when run out of a checkout, otherwise from GitHub).
3. **Shortcuts**: Start Menu + Desktop (both optional), launching the
   graphical **launch window** with no console window.
4. **Settings > Apps**: registers like a normal Windows app, with a working
   **Uninstall** entry (`uninstall.ps1`; saved settings survive a reinstall).

Scripted installs: `install.bat -Silent` (or run `install.ps1` directly with
`-Silent`, `-InstallDir`, `-NoDesktopShortcut`, `-NoStartMenuShortcut`,
`-SkipPythonInstall`, `-NoGui`).

## Requirements

- **Python 3.8+** (tested on 3.11/3.12; the installer above sets this up for
  you). Nothing to `pip install` — it uses only the standard library. The GUI
  uses Tkinter, which is included with the standard Python installer for
  Windows.
- No clock synchronization between the two machines is required (latency is
  measured by round-trip, so both clocks are irrelevant).

## Updating

The app updates itself from the [netvitals repo](https://github.com/robertsonc/netvitals),
**from inside the UI**:

- In the **launch window**: *⟳ Check for updates* (bottom-left).
- In the running **dashboard**: the *⟳ Update* button in the header.

Both open the same dialog: it reports whether a newer version exists and —
one click — installs it and restarts the app with the same options (the old
copy is kept as `netquality.py.bak`). The command line still works too:

```
update.bat                      REM or: python netquality.py --update
python netquality.py --check-update   REM report only (exit code 3 = update available)
```

`--update` downloads the latest `netquality.py`, sanity-checks it (compiles,
recognisably this app, higher `__version__`), keeps the previous copy as
`netquality.py.bak`, and swaps the file atomically. A packaged `.exe` can't
replace itself — rebuild with `build_exe.bat` after updating the source.
Updates are only ever fetched when explicitly requested (opening the update
dialog counts as a request); the app never phones home on its own.

**Corporate networks / `unable to get local issuer certificate`:** that error
is Python's bundled OpenSSL not trusting a TLS-inspecting proxy (whose root
lives only in the *Windows* certificate store), or a chain with a missing
intermediate that OpenSSL — unlike the browser — won't fetch. Since 1.3.1
the updater detects this and automatically retries the download through the
Windows certificate store (`curl.exe`/PowerShell → SChannel, the same trust
decisions as Edge), so updating works wherever the browser does — with TLS
verification still on. To lift a pre-1.3.1 install over this hump once,
re-run `install.bat` (the installer downloads via PowerShell already); after
that the in-app update works.

## Running it

### The launch window (easiest)

Start **Network Vitals** with no arguments — from the Start Menu shortcut, or:

```
python netquality.py
```

A launch window opens where everything is a field instead of a flag: peer IP
(with a history of recent peers), probe size, rate, Don't-Fragment, and under
*Advanced options* the bind address, ports, window/timeout/deadband, chart
history, VXLAN encapsulation and console mode. It also shows this machine's
IP (to type into the *other* machine), can run the **MTU sweep** from a
button, and checks for updates. Every choice is remembered for next time in
`%APPDATA%\NetVitals\settings.json` (Linux: `~/.config/netvitals/`).
Scripts that must fail instead of opening a window can pass `--no-launcher`.

### Command line

On **workstation A** (say its peer is `10.0.0.2`):

```
python netquality.py --peer 10.0.0.2
```

On **workstation B** (peer is `10.0.0.1`):

```
python netquality.py --peer 10.0.0.1
```

That's the entire configuration. Or double-click **`run.bat`** and type the
peer's IP when prompted. Site defaults (probe `--size`, `--dont-fragment`) are
set in variables at the top of `run.bat` — edit them once for your environment;
anything passed after the peer IP (`run.bat 10.0.0.2 --size 200`) overrides
them, since the last occurrence of a flag wins.

### Console mode (no GUI)

```
python netquality.py --peer 10.0.0.2 --no-gui
```

The app also falls back to the console UI automatically if no display / Tkinter
is available.

While it runs, the console UI accepts single-key commands:

| Key | Action |
|-----|--------|
| `r` | reset the *since reset* counters/stats — same as the GUI **Reset / Clear** button |
| `q` | quit (Ctrl-C also works) |

The status area shows **two totals lines**: *since reset* (the demo window —
press `r` to start it fresh at any time) and *lifetime* (since the app
started; never resets). That way you can show both the loss accumulated over
the whole duration and the loss within the last reset window, without
stopping and restarting the app. Key handling needs an interactive terminal;
when output is piped the keys are simply disabled and the display still works.

### Single-machine smoke test (Linux loopback aliases)

```
python netquality.py --bind 127.0.0.1 --peer 127.0.0.2 --no-gui
python netquality.py --bind 127.0.0.2 --peer 127.0.0.1 --no-gui
```

## How it works

Every packet is a fixed-size **probe** carrying a stream id, a sequence number,
and the sender's monotonic timestamp. The receiving side reflects it straight
back as an **echo** with the timestamp untouched. The originator then computes:

- **RTT** = `now − echoed_timestamp` (measured entirely on its own clock, so no
  time sync needed). **One-way latency** is reported as RTT/2.
- **Jitter** — RFC 3550 style smoothed mean deviation of successive RTTs.

### Loss vs. late — how a frame is judged "lost"

Every probe ends in exactly one of three outcomes, tallied over the sliding
`--window` (default 10s):

| Outcome | Meaning |
|---|---|
| **received** | echo came back within `--timeout` (default 2s) |
| **lost** | no echo within `--timeout`, and none since — a real drop |
| **late** | echo arrived **after** the `--timeout` deadline (reordered or over-buffered) |

So a frame is declared *lost* when its echo hasn't returned within `--timeout`.
**But what if it arrives after that?** It is *not* silently dropped: when the
late echo eventually appears, the probe is reclassified `lost → late`, so
**Loss %** reflects frames that *truly never came back* and **Late %** reflects
frames that *came back too late to be useful*. This separates a dead path from a
recoverable jitter/reorder event — they look identical if you only track "loss".

For the **quality score**, `loss + late` is treated as the effective impairment
(a real-time stream can't use a frame that misses its playout deadline either
way), but the two are reported separately so you can see which is happening.
Raise `--timeout` if you want to tolerate slower paths before counting late/lost;
lower it to be stricter about latency deadlines.

#### Why a *clean* link can show a little UDP loss (and impairment makes it vanish)

A counterintuitive thing you may see: a low-jitter path shows a small amount of
**UDP** loss, while adding jitter/delay impairment drives it to ~0. TCP streams
never show it. The cause is **microbursts**, not the wire:

- The OS thread scheduler / timer granularity (≈15 ms on Windows) makes the
  paced probes actually leave in small bursts rather than evenly spaced.
- On a clean, low-jitter path those bursts arrive **still bunched**, and a burst
  can momentarily overrun the socket receive buffer — a dropped datagram that
  looks like loss. (TCP can't show this; the kernel retransmits invisibly.)
- A jitter/delay impairment box **spreads packets out in time** (and buffers
  rather than drops), which *de-bursts* the arrivals — so the buffer never
  overruns and loss falls to zero.

To keep this local artifact out of the measurement, netquality (a) enlarges the
UDP socket send/receive buffers to a few MB (`SOCK_BUF_BYTES`) so microbursts are
absorbed, and (b) on Windows requests a 1 ms scheduler tick
(`timeBeginPeriod(1)`) so the probe pacing is smooth instead of clumping into
~15 ms bursts in the first place. Reported loss then reflects the path, not a
local buffer overflow.

If you still see a little UDP loss on a path you believe is clean, confirm
whether it's on the wire with a two-ended packet capture (e.g. Wireshark): on
each host capture `udp port 30201`, then compare how many probe datagrams one
host **sent** against how many the other host **received**. If sent > received,
the loss is real and on the network; if the counts match, it isn't leaving/
arriving as loss at all.

Because both instances originate probes *and* reflect the peer's probes on the
same ports, every stream carries traffic in both directions continuously. For
TCP, each instance runs both a listener (to reflect the peer) and a client
connection (to originate its own probes), with automatic reconnect.

### Quality score

The score (0–100) and MOS (1–4.5) come from the **ITU-T G.107 E-model**
R-factor, fed by one-way latency, loss, and jitter (jitter is folded in as
extra effective delay). The header shows the *average* across streams and calls
out the *worst* stream. Bands: Excellent ≥80, Good ≥70, Fair ≥60, Poor ≥50,
Bad below.

## Options

```
--peer IP          the other workstation's IP (required on the command line;
                   without it the graphical launch window opens instead)
--bind ADDR        local address to bind/listen on (default 0.0.0.0)
--udp-ports A,B    the two UDP ports (default 30201,30202)
--tcp-ports A,B    the two TCP ports (default 30101,30102)
--pps N            probes per second per stream (default 50)
--size N           probe packet size in bytes (default 200; e.g. 8972 for jumbo)
--dont-fragment    set the DF bit on UDP (oversized probes dropped, not split);
                   with --vxlan it applies to the OUTER packet
--vxlan            carry ALL probe traffic (UDP and TCP streams) inside VXLAN
                   encapsulation (userspace VTEP; both ends must enable it)
--vxlan-vni N      VXLAN Network Identifier (default 4242; must match both ends)
--vxlan-port P     outer UDP port for the tunnel (default 4789; must match both ends)
--window SECONDS   sliding window for loss/jitter/rate (default 10)
--timeout SECONDS  un-echoed probe -> lost after this (default 2)
--loss-deadband P  combined loss+late below P%% reads as 0 (default 0.5; 0 off)
--history SECONDS  span of the live/history charts (default 300)
--refresh-ms N     UI refresh interval (default 500)
--no-gui           force console UI
--no-launcher      with no --peer, error out instead of opening the launch window
--mtu-sweep        one-shot: find the largest UDP payload that crosses unfragmented
--sweep-min N      MTU sweep lower bound, payload bytes (default 1400)
--sweep-max N      MTU sweep upper bound, payload bytes (default 9000)
--burst-test       one-shot: staged rate ramp against the peer (bufferbloat /
                   policer / shaper signatures) - see "Burst test" below
--burst-mbps A,B   burst stages in Mbps (default 1,2,5,10,25)
--burst-secs S     seconds per burst stage (default 3)
```

At the defaults each stream is ~50 packets/s × 200 B ≈ 10 KB/s each way, i.e.
~80 KB/s total for the box — light enough to leave running, dense enough to
resolve loss and jitter well. Bump `--pps` / `--size` for a heavier load test.

## Locating loss

Round-trip loss alone can't tell you *where* a packet died. Each reflector
watches the **gaps in the peer's sequence numbers** (probes that never arrived)
and echoes the running gap count back, so the originator can decompose its
measured round-trip loss:

- **Forward loss** = the sequence gaps the peer saw (dropped on the way *to* the
  peer: my TX, the wire, or the peer's receive path).
- **Return loss** = round-trip loss − forward loss (dropped on the way *back*:
  the peer's TX, the wire, or my receive path).

Counting gaps in *the originator's own sequence space* makes this immune to
which app started first, and it always reconciles: **forward + return = the true
round-trip loss**.

The bottom status bar always shows the aggregate `fwd→` / `rtn←` split, and the
**Isolate** button opens a per-stream table with a **Where** verdict
(`→ forward`, `← return`, `both dirs`, or `clean`).

Because each host is symmetric, cross-referencing the two directions with each
host's own drop counters pins the exact segment. Key move: a NIC/host that is
dropping on **receive** (e.g. RX-ring overflow — Windows
`Get-NetAdapterStatistics` → `ReceivedDiscardedPackets` climbing) shows up as
**forward** loss on the *other* host's screen (its probes reached your wire but
were dropped before your reflector counted them). So "forward loss to host B" +
"B's `ReceivedDiscardedPackets` climbing in step" = B's receive ring, not the
network. Typical fixes for RX-ring overflow: raise the adapter's *Receive
Buffers*, and disable *RSC* / *Interrupt Moderation*.

> A few packets of in-flight skew can land on *return* on a very fast path; it
> washes out over a long run, and the per-stream verdict ignores single-digit
> counts. Trust the split once counts are in the hundreds+.

### Loss pattern

When loss is present, both UIs also name its **pattern** over the last 60 s,
on two independent axes:

- **texture** — `bursty` (losses clump into sub-second instants at densities
  far above the overall loss rate: link flap, reroute, queue tail-drop) vs
  `scattered` (random-ish: noisy link, RED/AQM).
- **scope** — `all streams together` (multiple streams losing in the same
  instants → a path-wide event), `<stream> only` (policer/ACL on that port),
  or `UDP/TCP streams only` (protocol-selective QoS policy).

So "2% loss" turns into, e.g., *"bursty, all streams together — path-wide
(flap / reroute / shared queue)"* or *"scattered, UDP-30201 only —
port-specific (policer/ACL on that port?)"*. The first ~10 s of a run are
excluded so bring-up churn doesn't mislabel a fresh session.

> **Version note:** the wire header changed in **1.5.0** (echoes now carry the
> reflector's clock for one-way drift), so **both ends must run 1.5.0+** — a
> mixed pair won't parse each other's packets and reads as "no link"
> (earlier header changes have the same rule).

## Jumbo-frame testing

Every probe stamps its own intended size into the packet, and the reflector
stamps back the number of bytes it actually received — so each end can confirm
full-size datagrams are crossing **in both directions**, not just that *some*
packet arrived.

Run on both ends with a jumbo payload and the Don't-Fragment bit set:

```
python netquality.py --peer 10.0.0.2 --size 8972 --dont-fragment
```

`8972` UDP payload + 8 (UDP) + 20 (IP) = a **9000-byte jumbo frame**. With
`--dont-fragment`, a probe that hits a hop with MTU < 9000 is **dropped instead
of fragmented**, so loss going to ~100% at jumbo size (while the link is clean
at small sizes) means the jumbo path is broken. Without DF, the OS would
silently fragment and reassemble, hiding the problem.

What to look at:

- **Status bar:** `frame 8972 B  DF on  size ✓ verified` once full-size
  datagrams have round-tripped on every UDP stream.
- **Totals table** (the *Totals* button): per stream, **TX B** (sent),
  **Peer RX B** (bytes the far end received — forward path), **My RX B** (bytes
  this end received — return path), and **Size** = `OK` when both match the
  configured size, or `⚠ N` on any mismatch.

### Path-MTU sweep

To discover the largest frame a path actually carries, point the sweep at a peer
that's running Network Vitals:

```
python netquality.py --peer 10.0.0.2 --mtu-sweep
```

It binary-searches the UDP payload size with DF set (binding an ephemeral port,
so it can run alongside a live instance) and reports the largest payload that
crosses unfragmented plus the forward path MTU, e.g.:

```
Largest UDP payload that traverses unfragmented:  8972 bytes
Forward path MTU (this host -> peer):            ~9000 bytes
=> Jumbo frames (>=9000) confirmed end to end.  ✓
```

## Burst test (responsiveness under load)

The continuous probes measure the path **at idle**; the burst test measures
what **load** does to it — the three most common "nothing is red but it's
slow" causes have distinct signatures:

```
python netquality.py --peer 10.0.0.2 --burst-test
```

It ramps paced 1200 B UDP probes through the offered rates (default
`1,2,5,10,25` Mbps, 3 s each; `--burst-mbps` / `--burst-secs` to change),
against a peer that is running Network Vitals, and reads the response:

- **RTT grows with rate while loss stays low** → a deep queue
  (bufferbloat-like).
- **Loss appears above some rate with RTT flat** → a policer (hard rate cap
  that drops instead of queueing).
- **RTT grows first, then loss** → a shaper (queue fills, then drops).
- Otherwise it reports the highest **clean** stage (loss <1%, p95 RTT within
  +30 ms of idle).

Also available as the **Burst test** button in the launch window, next to the
MTU sweep. Like the sweep it binds an ephemeral port and runs fine alongside
a live session — test probes are excluded from the loss-isolation bookkeeping
on both ends, so they don't skew the session's forward/return split. Echoes
are full-size: the offered load is carried **in both directions at once**,
and it is real traffic, so mind shared links at the higher stages.

## Wire anatomy (EdgeConnect slicing model)

When the two hosts sit behind **EdgeConnect** appliances, a large DF=1 probe
is not IP-fragmented on the WAN: the ingress EC **slices** it into
tunnel-sized pieces, encrypts and encapsulates each one, and the egress EC
reassembles the original packet before handing it to the LAN — so one LAN
packet becomes several WAN packets, invisibly to both hosts.

The **Anatomy** button shows exactly what that looks like for the probe size
you are running, drawn byte-proportionally:

- **LAN row** — the one packet the fabric ingests (probe payload + IP/UDP
  headers, + VXLAN encap when `--vxlan` is on), with the DF flag.
- **WAN row** — the predicted tunnel packets: payload in blue, per-packet
  encryption/encapsulation overhead in orange, wire bytes under each.
- The totals: WAN packet count, wire bytes, **overhead tax %**, the **×N
  packet amplification**, and the predicted WAN rate (`--pps` × N per UDP
  stream, each direction — echoes are full-size, so the return leg slices the
  same way).
- What the same packet would do **without** the fabric at a standard 1500 B
  hop: PMTUD-or-black-hole with DF on, or N IP fragments with DF off.

The model mirrors a **measured** AES-GCM-256 fabric (Auto tunnel MTU 1488):
slice payload budget 1360 B, 60 B GCM framing per tunnel packet
(outer IPv4 20 + UDP 8 + SPI/seq 8 + IV 8 + ICV 16), 12 B per-piece framing
for a whole packet / 16 B for a slice, padded to the 16 B cipher block:

```
wire = 60 + 16 x ceil((piece + framing) / 16)
```

A 3000 B packet therefore predicts 1360 + 1360 + 280 → three tunnel packets
of 1436 + 1436 + 364 B (+7.9%). The constants live in one block at the top of
`netquality.py` (`EC_SLICE_BUDGET` and friends) — tune them there if your
fabric measures differently. Note the numbers are a *prediction* from that
model, not a measurement of your fabric; pair the panel with the WAN-side
counters on the roadmap below to close the loop.

## VXLAN encapsulation (`--vxlan`)

Run **both ends** with `--vxlan` and every probe stream — the TCP streams as
well as the UDP ones — is carried inside genuine **VXLAN (RFC 7348)** between
the two hosts:

```
[outer IPv4][outer UDP :4789][VXLAN vni][inner Ethernet][inner IPv4][inner UDP/TCP][probe]
```

```
python netquality.py --peer 10.0.0.2 --vxlan
```

The app acts as its own **userspace VTEP**: it builds the whole inner
Ethernet/IPv4/UDP-or-TCP packet itself (valid checksums, deterministic
locally-administered MACs `02:4e:<ip>`, the real host IPs) and ships it in an
outer UDP datagram to the peer's VXLAN port. No kernel VTEP, drivers or admin
rights on either end, works the same on Windows and Linux, and Wireshark
dissects it as ordinary VXLAN on `udp/4789`. All the measurement machinery —
loss/late, forward/return isolation, size verification, the charts — works
identically in VXLAN mode; the status bar shows `VXLAN vni N udp/4789` while
the tunnel is active.

Every probe pays a fixed encapsulation overhead on the wire:

| Stream type | Extra bytes vs native | Breakdown |
|---|---|---|
| UDP | **+50 B** | VXLAN 8 + inner Ethernet 14 + inner IPv4 20 + inner UDP 8 |
| TCP | **+62 B** | VXLAN 8 + inner Ethernet 14 + inner IPv4 20 + inner TCP 20 |

### Demonstrating transparent fragmentation

That overhead is the demo: a probe sized to fit the path MTU natively no
longer fits once encapsulated, so the **outer** packet must fragment — and the
inner packet crosses untouched, reassembled transparently. On a standard
1500-byte path the outer frame is `20 (outer IP) + 8 (outer UDP) + 50 + probe`,
so the largest probe that avoids fragmentation is **1422 B**:

```
python netquality.py --peer 10.0.0.2 --vxlan --size 1422    # exactly fills 1500
python netquality.py --peer 10.0.0.2 --vxlan --size 1472    # overflows -> outer fragments
```

- **Without `--dont-fragment`** the oversized outer datagram is fragmented and
  reassembled transparently: the streams stay clean and full-size (`size
  ✓ verified`), and a capture shows the outer IPv4 fragments — transparent
  fragmentation working end to end.
- **With `--dont-fragment`** (DF on the *outer* packet) the oversized datagram
  is dropped instead, so loss jumping at the same `--size` that was clean
  natively pinpoints exactly where the encap overhead exceeds the path MTU.

Notes:

- **Both ends must run `--vxlan`** with the same `--vxlan-vni` and
  `--vxlan-port`; a mixed pair sees 100% loss (the probes land on a port the
  native transport isn't listening on).
- **TCP streams are emulated inside the tunnel**: each probe/echo rides in its
  own self-contained `PSH|ACK` segment with app-managed seq/ack numbers. On
  the wire it is real TCP-in-VXLAN that switches and captures dissect
  normally, but there is no kernel TCP state machine — no handshake,
  retransmission or congestion control — so TCP loss shows up *directly* as
  loss (like UDP) instead of being converted to delay, and the PQI's
  connection-establishment term is idle. That's exactly what you want when
  demonstrating what the fabric does to encapsulated packets.
- If the host already terminates real VXLAN on 4789 (or another instance is
  running), the bind fails with a clear error — move the tunnel with
  `--vxlan-port` on both ends.
- `--mtu-sweep` still measures the *native* path MTU; subtract the overhead
  above to know the largest probe that fits encapsulated.

## Windows firewall

The first time you run it, Windows may prompt to allow Python through the
firewall — allow it on the relevant networks. If it was dismissed, add inbound
rules for **UDP 30201–30202** and **TCP 30101–30102** (or whatever you set with
`--udp-ports`/`--tcp-ports`), or allow `python.exe`. In VXLAN mode the only
port that needs to be open is the tunnel itself: **UDP 4789** (or your
`--vxlan-port`).

## Building a standalone .exe (optional)

If you'd rather hand someone a single executable with no Python install, run
**`build_exe.bat`** (needs `pip install pyinstaller`). It produces
`dist\netquality.exe`, which you launch as:

```
netquality.exe --peer 10.0.0.2
```

## Roadmap — validating the fabric, not just the endpoints

*Shipped in 1.5.0:* directional **one-way drift** chart, the latency
**p5–p95 band**, the **loss pattern** diagnostic, and the **burst test** —
the host-side measurement tranche of this roadmap.

The app measures the **host view** (the "LAN row" of the anatomy panel); the
WAN middle is currently *predicted* by the model, not observed. Planned work
to close that gap, roughly in order:

1. **EC WAN counter polling (API or SNMP).** Poll the EdgeConnect WAN-side
   TX/RX packet counters and show *measured* WAN pps next to the anatomy
   panel's *predicted* pps — live proof that 1 LAN packet becomes N WAN
   packets. Open questions before this lands:
   - which appliance/Orchestrator REST endpoints (or SNMP OIDs — plain
     `ifHCIn/OutUcastPkts` would also cover non-EC devices) to poll, and how
     to authenticate;
   - **path selection**: the app runs point-to-point between two hosts, but
     the fabric path may be EC1↔EC2 direct *or* transit one or more hubs
     (EC1→hub→hub→EC2), so the tool must know *which* appliances and tunnels
     to poll. Initial scope is the direct EC1↔EC2 case (labs/demos);
     hub-transit topologies need either manual appliance lists or
     Orchestrator-driven path discovery.
   - **attribution** on busy fabrics: per-tunnel stats where available, plus
     a "calibration burst" mode (square-wave the probe rate and diff the
     counters between on/off windows) so the ratio is measurable next to
     background traffic.
2. **Slice-level vs probe-level loss / FEC verdict** (needs 1): WAN counters
   dropping while probe loss stays 0% is measured proof FEC is repairing;
   probe loss ≈ N × WAN slice loss quantifies loss amplification.
3. **Slice-boundary detector in the MTU sweep**: sweep size vs RTT/loss and
   detect the discontinuities at multiples of the slice budget — measures the
   real budget empirically instead of trusting the model constants. Related
   always-on variant: run a small (1-slice) and a large (N-slice) UDP stream
   concurrently and chart their loss ratio — sustained large ≈ N × small is
   live slicing evidence with no EC access at all.
4. **LAN fragment sniffer** (raw socket: `SIO_RCVALL` on Windows,
   `AF_PACKET` on Linux): count IP fragments arriving for the probe flow to
   prove the fabric delivered whole packets — app-level size checks can't
   distinguish EC reassembly from kernel reassembly of mid-path fragments.
5. **ICMP frag-needed listener**: during the sweep, report "ICMP Type 3/Code 4
   received (MTU=1500)" vs "silently dropped → PMTUD black hole".
6. **Coalescing detector**: receiver-side inter-arrival clustering (bundled
   small packets exit the far EC back-to-back) plus the ~1–3 ms wait-timer
   signature in small-probe RTT.
7. **Live topology strip**: Host → EC1 → fabric → EC2 → Host with measured
   pps at each hop and the amplification ratio on the tunnel span — the blog
   animation's layout, with real numbers moving.
8. **Per-DSCP probe classes**: parallel probe sets marked EF vs BE, charted
   side by side — on EdgeConnect this effectively tests per-overlay /
   business-intent behavior, and reading the received TOS back also catches
   DSCP bleaching mid-path. Caveat to resolve first: Windows ignores
   `IP_TOS` on ordinary sockets; DSCP marking without admin rights needs the
   qWAVE API (`QOSAddSocketToFlow`), whose non-admin path only offers the
   traffic-type-mapped code points — needs a spike before committing to UX.
9. **Point-to-multipoint / full mesh** (3-6 endpoints), phased:
   1. multi-peer engine (per-pair stats, peer-set filters) + an **N×N mesh
      matrix** view — cells colored by score/loss/RTT, click to drill into
      the pair's dashboard;
   2. **static-FIB VXLAN mesh** transport: each node's single outer UDP
      socket talks to all peers, demuxed by outer source IP, inner MAC/IP
      per node derived from a node index — a genuine static VXLAN full mesh,
      one open port per node;
   3. **common-endpoint auto-diagnosis** from the matrix: every pair touching
      node C degrading = C's site/link; only A-C degrading = that path;
   4. **hub/star mode** (spokes probe only the hub) to match EC hub
      topologies and keep probe count linear beyond demo scale.
