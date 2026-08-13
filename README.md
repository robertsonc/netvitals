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
  drawn as a glowing arc gauge so the state is readable from across a room,
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
- a **Reset** button that wipes the charts and all accumulated
  loss/latency/jitter stats so a demo can start from a clean slate,
- a **Totals** button that toggles a per-stream table of the since-reset
  counters (sent / received / lost / late / loss %). The bottom status bar
  always shows the aggregate **since reset** counters (cleared by
  **Reset**) *and* the **lifetime** counters (never cleared while the
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
- a **Load** button that toggles a sustained-load panel: a known-quantity
  UDP load (in Mbps, optionally square-waved on/off) offered *while* the
  scored streams keep measuring, so the charts show what the load does to
  the path — see *Sustained load* below.

Charts keep a rolling history (default 5 minutes, `--history`). The window
resizes freely; the charts grow and shrink with it.

To stop trivial blips from denting a demo, a **loss deadband** (`--loss-deadband`,
default 0.5%) treats a combined loss+late below the threshold as 0 for the score
and the loss chart. (The lifetime totals always show the true raw counts.)

## Hardening & behavior notes

- **Echoes can outrun the bookkeeping** (1.6.0). Probes were registered as
  "in flight" *after* the transmit call - but send syscalls release the GIL,
  so on a fast path (or under scheduler stalls) the echo could arrive and be
  processed *before* the sending thread ran again; the unrecognized echo was
  discarded as a duplicate and the probe read as **return loss** two seconds
  later. This produced a small, scattered, return-dominant loss trickle on
  perfectly clean paths - worse on loaded hosts and in mesh mode (every
  version up to 1.5.2 had it). Probes are now registered before transmit;
  a three-node loopback mesh measures **0.00%** where it read 1-3% before.
- **The PQI handshake sampler no longer disrupts the reflector** (1.6.0).
  The every-15 s throwaway TCP handshake used to be adopted as "the peer
  reconnected", closing the LIVE reflector connection and killing the probes
  buffered on it. A connection now becomes the reflector only after it
  delivers a real probe.
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

`--update` fetches a **signed release manifest**, verifies its RSA signature against the
public key built into the app (**fail closed** — an unsigned or wrong-signed update is
refused), requires a newer `__version__`, downloads the `netquality.py` artifact and checks
its SHA-256 against the signed manifest, then keeps the previous copy as `netquality.py.bak`
and swaps the file atomically (re-verifying the bytes on disk first). A packaged `.exe`
can't replace itself — rebuild with `build_exe.bat` after updating the source. Updates are
only ever fetched when explicitly requested (opening the update dialog counts as a request);
the app never phones home on its own. See
[docs/UPDATE_SECURITY.md](docs/UPDATE_SECURITY.md) for the signing and key model (releases
must be signed with `tools/sign_release.sh`, or updates fail closed).

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
(with a history of recent peers), probe size, rate (probes/sec or a target
Mbps for the box), Don't-Fragment, and under *Advanced options* the bind
address, ports, window/timeout/deadband, chart history, VXLAN encapsulation
and console mode. It also shows this machine's
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
| `r` | reset the *since reset* counters/stats — same as the GUI **Reset** button |
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

### Automated tests

The suite is plain `unittest` (no third-party test deps) and runs headless — no
peer, no sockets, no display needed:

```
python -m unittest discover -s tests -v
```

It covers the three things that can silently break without a running peer:

- **Self-update** (`test_update.py`) — signed-manifest verification, version
  monotonicity, and fail-closed install (needs `openssl` on `PATH`; those cases
  skip if it is missing).
- **Launcher / UI glue** (`test_launcher.py`) — the launch-window form → CLI
  argv translation, field validators, and settings persistence. This is the
  testable core of the GUI; the Tk widgets themselves still need the manual
  smoke run above.
- **Scoring & wire logic** (`test_scoring.py`) — the E-model/PQI scores and the
  label/colour bands, loss-pattern and loss-direction diagnostics the dashboard
  renders, and the packet build/parse round-trip.

CI (GitHub Actions, `.github/workflows/ci.yml`) runs the same suite on every
push and pull request across Python 3.8–3.12 on Linux plus Windows and macOS,
with a flake8 lint pass.

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
--peers A,B,...    MESH: probe every listed peer at once (see "Mesh mode");
                   each node runs with its own list of the other nodes
--tcp-pps N        TCP probes/s per stream (default: same as --pps; the UDP
                   50 pps default deliberately matches G.711 voice cadence,
                   TCP models an interactive app - tune independently)
--bind ADDR        local address to bind/listen on (default 0.0.0.0)
--udp-ports LIST   1-8 UDP ports, one stream per port (default 30201,30202)
--tcp-ports LIST   0-8 TCP ports, one stream per port (default 30101,30102;
                   'none' runs UDP-only)
--profiles LIST    per-stream traffic profiles in stream order: voice, video,
                   bulk, imix, SIZE or SIZExPPS (see "Traffic classes")
--dscp LIST        per-stream DSCP marking in stream order: EF, AF41, CS5,
                   BE, 0-63 or '-' (see "Traffic classes")
--pps N            probes per second per stream (default 50)
--mbps X           target offered probe load for the box in Mbps (IP level,
                   per direction, probes only - echoes double the wire load;
                   max 1000): splits evenly across the four streams, derives
                   each stream's rate from --size and overrides --pps /
                   --tcp-pps; the UI footer shows offered vs target
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
--slice-scan       one-shot: measure the fabric's REAL slice budget from the
                   RTT-vs-size staircase (see "Measuring the WAN side")
--wan-counters S   poll WAN-side packet counters and show measured WAN pps:
                   sim[:NOISE[:LOSS%]] | snmp:HOST,COMMUNITY,IFINDEX[,PORT] |
                   rest:URL[|TOKEN[|TXKEY|RXKEY]]; drop counters feed the
                   FEC verdict
--scenario FILE    replay a JSON demo timeline (stages with load/square-wave/
                   reset), drawn as stage markers on the charts
--frag-sniffer     count IPv4 fragments to/from the peer at capture level
                   (needs root/admin; reports unavailable otherwise)
--report BASE      write the demo report (BASE.json + BASE.html) on exit;
                   the ⭳ Report button / console 'w' key write on demand
```

At the defaults each stream is ~50 packets/s × 200 B ≈ 10 KB/s each way, i.e.
~80 KB/s total for the box — light enough to leave running, dense enough to
resolve loss and jitter well. Bump `--pps` / `--size` for a heavier load test,
or skip the arithmetic and name the load directly:

```
python netquality.py --peer 10.0.0.2 --mbps 8
```

`--mbps` splits the target evenly across the four streams and derives each
stream's rate from `--size` (the launcher has a *Target Mbps* field for the
same thing). The dashboard footer then shows **`probe load 7.98 Mbps /
target 8`** — the offered load is measured back, not assumed, so the demo's
known quantity is verifiable on screen. The figure is IP-level, per
direction, probes only; echoes double what's on the wire.

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
excluded so bring-up churn doesn't mislabel a fresh session, and the line
**respects `--loss-deadband`** (1.5.2): loss the score and loss chart already
read as 0 doesn't produce a pattern warning either — when the line speaks,
the 60 s loss rate is above the deadband and there are enough events for the
scope claim to be statistically meaningful. Raise or lower `--loss-deadband`
to tune both together.

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
- Otherwise it reports the highest **clean** stage (loss+late <1%, p95 RTT
  within +30 ms of idle).

Each stage reports **loss and late separately** (1.7.0), with the same
semantics as the continuous engine: an echo back within the probe
`--timeout` is on-time, one beyond it is *late* (the path delivered it, too
slowly to use), and only a probe that never returns is *loss*. A policer's
drops never arrive, so late echoes can't fake the rate-cap verdicts — but
they do disqualify a stage from "clean". Pass `--dont-fragment` to set DF on
the burst probes too (1.7.0; the launcher's checkbox rides along): without
it, a sub-1228-MTU hop silently fragments the 1200 B probes and the pps
math no longer means what the table says.

Also available as the **Burst test** button in the launch window, next to the
MTU sweep. Like the sweep it binds an ephemeral port and runs fine alongside
a live session — test probes are excluded from the loss-isolation bookkeeping
on both ends, so they don't skew the session's forward/return split. Echoes
are full-size: the offered load is carried **in both directions at once**,
and it is real traffic, so mind shared links at the higher stages.

## Sustained load (the Load button)

The burst test made resident (1.7.0): the dashboard's **⚡ Load** button
opens a panel that offers a continuous, known-quantity UDP load — same
1200 B TEST probes, same ephemeral port, same exclusion from the
loss-isolation bookkeeping — **while the four scored streams keep
measuring**. The charts become the story: start 20 Mbps and watch the
latency band, jitter and one-way drift react in real time; stop it and watch
them recover.

- **Mbps field**: the offered rate (probes only; echoes are full-size, so
  both directions carry it at once).
- **Square wave**: on/off seconds (default 10/10) turn the load into a
  calibration pattern — square-wave the rate and diff WAN-side counters
  between the on and off windows to attribute tunnel packets on a busy
  fabric (the measurement half of this is roadmap item 1).
- The panel shows **offered vs achieved** Mbps plus the load stream's own
  loss/late over the last ~5 s.

Native transport only (a VXLAN-mode peer opens no native UDP listener to
echo the probes — the button says so instead of failing silently), and
single-pair dashboards only for now (the mesh GUI doesn't carry the panel).

## Traffic classes & profiles (1.8.0)

The stream set itself is now a policy-matching instrument:

- **Port lists.** `--udp-ports` takes 1–8 ports and `--tcp-ports` 0–8
  (`none` = UDP-only), one stream per port — so the session can present
  flows on exactly the ports a customer's match rules key on
  (`--udp-ports 5060,30201,30202`). At least one UDP stream is always
  required (the latency band, one-way drift and the one-shot tools ride
  UDP). Both ends must run the same lists.
- **Per-stream profiles** (`--profiles`, launcher field under *Advanced*):
  one entry per stream in order — `voice` (200 B @ 50 pps), `video`
  (1200 B @ 90 pps), `bulk` (1400 B @ 200 pps), `imix` (the classic 7:4:1
  mix of 64/576/1500-byte IP packets, cycled probe-by-probe), a plain
  `SIZE`, or `SIZExPPS` (e.g. `1200x90`). Streams beyond the list keep
  `--size` at the base rate. `--mbps` composes with profiles: sizes are
  kept, and each stream's rate is derived from its own mean wire size so
  the box still offers exactly the target.
- **Per-stream DSCP** (`--dscp`, launcher field): `EF`, `AF41`, `CS5`,
  `BE`, a number 0–63, or `-` per stream. On Linux/macOS the exact code
  point is set (`IP_TOS`). On Windows plain IP_TOS is ignored, so the app
  uses the **qWAVE** API (no admin needed) — which only offers traffic
  *types*; the UI reports the code point the stack actually applies
  (e.g. requesting EF sends CS7). In VXLAN mode the **inner** IPv4 header
  carries the class.
- **Bleaching detection.** The reflector reports the TOS byte it actually
  received (stamped into the echo's padding — wire-compatible with older
  peers, which simply don't report), and each end also observes the TOS on
  arriving echoes. The **Totals** table shows `requested → forward/return`
  per stream (e.g. `EF→EF/EF`, or `EF→BE` when a mid-path policy rewrites
  it — which raises an explicit *DSCP rewritten mid-path* warning). ToS
  readback needs a POSIX receiver for native UDP streams; in VXLAN mode it
  works for all streams on every platform (the inner header is read
  directly), and native TCP streams show `?` (no per-segment readback).

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

## Measuring the WAN side (1.9.0)

Three ways to turn the Anatomy panel's *prediction* into *measurement*:

- **WAN counters** (`--wan-counters`): a poller thread reads the fabric's
  WAN-side packet counters once a second and the Anatomy panel (and the
  console) shows **measured WAN pps next to the predicted pps** — live
  proof that 1 LAN packet becomes N WAN packets. Sources:
  - `sim[:NOISE_PPS]` — a built-in simulator that integrates this
    instance's own offered load through the EC slicing model (plus
    optional background noise), so the whole workflow — including the
    square-wave calibration below — runs with **no fabric access at all**;
  - `snmp:HOST,COMMUNITY,IFINDEX[,PORT]` — stdlib SNMPv2c GET of the
    IF-MIB 64-bit counters (`ifHCIn/OutUcastPkts`); works against
    EdgeConnect or any router/switch;
  - `rest:URL[|TOKEN[|TX_KEY|RX_KEY]]` — generic JSON poller (dotted key
    paths; token sent as both `Authorization: Bearer` and `X-Auth-Token`).
    The Orchestrator-specific endpoint is chosen during UAT against real
    gear; this is its stable integration point.
  On busy fabrics, square-wave the load (the ⚡ Load panel or a scenario
  stage) and diff the counters between on and off windows — the load's
  WAN footprint falls out of the subtraction.
- **Slice scan** (`--slice-scan`): a one-shot that steps the probe size
  across a uniform grid and reads the RTT-vs-size **staircase** the
  slicing fabric imposes — measuring the *real* slice budget instead of
  trusting `EC_SLICE_BUDGET`, and telling you when the model constant
  needs tuning. On a path with no slicing fabric it says so.
- **Slice-loss ratio (always on)**: run two UDP streams whose probes slice
  into different WAN packet counts (e.g. `--profiles 200,3000`) and, when
  both lose, the app checks whether the loss ratio tracks the slice-count
  ratio — sustained `large ≈ N × small` is live slicing evidence with no
  fabric access, called out in the status line.
- **FEC verdict (2.0.0)**: when the counter source reports drops (the SNMP
  discard/error OIDs, or the simulator's `sim:NOISE:LOSS%` knob), the app
  compares WAN-side loss with app-level probe loss and names the result:
  **WAN dropping while probes run clean = FEC repairing, measured**; probe
  loss ≈ N× the WAN slice loss = amplification with no repair. Silent when
  neither is proven.
- **Topology strip (2.0.0)**: the **≣ Topology** button draws
  Host → EC → fabric → EC → peer with the live numbers moving — LAN pps,
  predicted/measured WAN pps and the amplification ratio on the tunnel
  span.
- **PMTUD verdict in the sweep (2.0.0)**: on Linux the MTU sweep also
  listens for ICMP *fragmentation-needed* on the socket error queue (no
  raw socket, no root) and reports **"ICMP frag-needed received
  (MTU=N)"** vs **"dropped silently → PMTUD black hole"**.
- **Fragment sniffer (2.0.0, `--frag-sniffer`)**: counts IPv4 fragments
  to/from the peer at capture level — distinguishing the fabric delivering
  whole packets from the kernel quietly reassembling mid-path fragments.
  Needs root/admin for the raw socket; degrades to an honest
  "unavailable".

## Demo report (2.0.0)

One click, one leave-behind: the dashboard's **⭳ Report** button (console:
the `w` key; CLI: `--report BASE` on exit) writes a timestamped **JSON +
self-contained HTML** pair — scores, per-stream stats incl. DSCP readback,
totals, forward/return split, every diagnostic that fired (loss pattern,
slice evidence, FEC verdict), WAN counters and scenario state. On-demand
reports land in the NetVitals config dir under `reports/`.

## Scenario scripting (`--scenario`, 1.9.0)

A demo arc as a JSON file instead of a memorized click sequence:

```json
{"name": "policy-demo", "repeat": 1, "stages": [
  {"name": "baseline",  "secs": 60},
  {"name": "load",      "secs": 30, "load_mbps": 10},
  {"name": "calibrate", "secs": 60, "load_mbps": 10,
   "square_on_s": 5, "square_off_s": 5},
  {"name": "clean slate", "secs": 5, "reset": true}]}
```

Each stage can hold a sustained load (`load_mbps`, optionally square-waved),
and/or reset the since-reset stats. Stage boundaries are drawn as dashed
**markers on all four charts** (labeled on the latency chart), the footer
shows the live stage/pass countdown, and `repeat: 0` loops until the app
closes. Load stages need native transport (not `--vxlan`) and target the
first peer.

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

## Mesh mode (`--peers`)

With three or more endpoints, run every node with a comma-separated list of
the **other** nodes (the launcher's peer field accepts the same list):

```
node A:  python netquality.py --peers 10.0.0.2,10.0.0.3
node B:  python netquality.py --peers 10.0.0.1,10.0.0.3
node C:  python netquality.py --peers 10.0.0.1,10.0.0.2
```

Each node probes every listed peer with the full four-stream suite - the
same ports serve all peers (inbound traffic is demuxed by source address,
and only configured peers are answered), so the firewall story is unchanged.
The mesh GUI shows **a row per pair** - score tile, label, RTT, loss,
jitter, streams-up, and the UDP-silent / loss-pattern flag - with the header
naming the current **worst pair**. Click a row to point the four charts
(latency + band, loss, jitter, one-way drift) and the footer at that pair;
the console UI prints the same table. Loss isolation, size verification and
scoring are all per pair.

Notes:

- This is each node's **local half** of the full N×N mesh (phase 1); the
  cross-node matrix and common-endpoint auto-diagnosis are on the roadmap.
- A **hub/star** layout works today by simply giving the spokes only the
  hub in their list.
- `--vxlan` is single-peer for now (the static-FIB VXLAN mesh is roadmap
  phase 2), and the one-shot tools (MTU sweep, burst test) target the first
  peer in the list.
- Probe load scales with the peer count: N peers = N × the usual per-pair
  rate (at defaults, ~80 KB/s each way per peer).

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

> **See also:** [docs/SDWAN_DEMO_GUIDE.md](docs/SDWAN_DEMO_GUIDE.md) — the
> SD-WAN demo traffic guide: a solution overview, the full test-case catalog
> with exact traffic quantities, and the extended feature roadmap organized
> around known-quantity traffic generation.

*Shipped in 1.5.0:* directional **one-way drift** chart, the latency
**p5–p95 band**, the **loss pattern** diagnostic, and the **burst test** —
the host-side measurement tranche of this roadmap.

*Shipped in 1.7.0* (the guide's Milestone 1.7 — known-quantity controls):
**`--mbps` target-bandwidth mode** with the offered-vs-target footer
readout, the **sustained-load panel** (⚡ Load button, with the square-wave
calibration schedule), and the **hardened burst test** (optional DF,
loss-vs-late split in stages and verdicts).

*Shipped in 2.0.0* (Milestone 2.0 — proving the fabric): the **FEC
verdict** (WAN drop counters vs probe loss: repair proven or amplification
named), the sweep's **PMTUD verdict** (ICMP frag-needed vs silent black
hole, via the Linux error queue — no root), the **fragment sniffer**
(`--frag-sniffer`, capture-level whole-packet-delivery proof), the live
**topology strip** (≣ button), and the **demo report** (⭳ button /
`--report`: JSON + self-contained HTML leave-behind).

*Shipped in 1.9.0* (Milestone 1.9 — measuring the WAN side): **WAN counter
polling** (`--wan-counters`: SNMP / generic REST / a no-hardware simulator)
with measured-vs-predicted WAN pps in the Anatomy panel, the **slice scan**
(`--slice-scan`, measures the real slice budget from the RTT staircase),
the always-on **slice-loss-ratio evidence**, and **scenario scripting**
(`--scenario` JSON timelines with chart stage markers).

*Shipped in 1.8.0* (Milestone 1.8 — the policy-classification surface):
**configurable stream sets** (1–8 UDP + 0–8 TCP port lists), **per-stream
traffic profiles** incl. IMIX, **per-stream DSCP marking** (exact on POSIX,
qWAVE traffic types on Windows) with **forward/return ToS readback and
bleaching detection** — see *Traffic classes & profiles*. Alpha releases
(`1.8.0a1`) now order correctly in the signed updater for UAT flows.

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
   1. ~~multi-peer engine (per-pair stats, peer-set filters) + a per-pair
      mesh view — a row per pair, click to drill into the pair's charts~~
      — **shipped in 1.6.0** (`--peers`, see *Mesh mode*);
   2. **static-FIB VXLAN mesh** transport: each node's single outer UDP
      socket talks to all peers, demuxed by outer source IP, inner MAC/IP
      per node derived from a node index — a genuine static VXLAN full mesh,
      one open port per node;
   3. **common-endpoint auto-diagnosis** from the matrix: every pair touching
      node C degrading = C's site/link; only A-C degrading = that path;
   4. **hub/star mode** (spokes probe only the hub) to match EC hub
      topologies and keep probe count linear beyond demo scale.
