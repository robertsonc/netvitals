# Network Vitals — SD-WAN Demo Traffic Guide

**Purpose of this document.** Network Vitals (`netquality.py`, v1.6.2) is used in
SD-WAN demonstrations to generate a **known quantity of high-quality,
instrumented traffic** between endpoints behind EdgeConnect appliances, so that
traffic policies — QoS, path steering, policers/shapers, FEC, tunnel
encapsulation and MTU handling — can be exercised and their effects **shown
live on screen**. This guide documents:

1. [Solution Overview](#1-solution-overview) — what the tool is and why its
   traffic is a *known quantity*;
2. [User Guide](#2-user-guide) — every test case the app supports **today**,
   with the exact traffic each one generates and the policy behavior it
   exercises;
3. [Roadmap of Features](#3-roadmap-of-features) — what it can support
   **tomorrow**, phased around the demo-traffic mission.

---

# 1. Solution Overview

## 1.1 What it is

A single, self-contained, pure-stdlib Python application. The **same program
runs on both (or all) endpoints**; each instance simultaneously:

- **originates** paced probe packets toward its peer(s), and
- **reflects** every probe it receives straight back as an echo.

Every probe carries a 34-byte header (magic `NQV2`, stream id, sequence
number, the sender's monotonic timestamp, a self-describing size field, and
reflector-filled fields for received-bytes / received-count / reflector
clock), zero-padded to the configured `--size`. Because latency is measured
round-trip on the originator's own clock, **no clock synchronization is
needed anywhere**.

Four continuous streams run per peer pair, all bidirectional, all the time:

| Stream (sid) | Protocol | Default port | Models |
|---|---|---|---|
| UDP-30201 (0) | UDP | 30201 | Real-time media (G.711 voice cadence) |
| UDP-30202 (1) | UDP | 30202 | Real-time media (second class/path) |
| TCP-30101 (2) | TCP | 30101 | Interactive application |
| TCP-30102 (3) | TCP | 30102 | Interactive application |

The default ports sit in the unassigned 30100/30200 block — below every OS
ephemeral range and free of Wireshark dissector collisions — and are
overridable (`--udp-ports A,B`, `--tcp-ports A,B`) to line up with whatever
match rules a demo needs.

## 1.2 Why the traffic is a "known quantity"

Every dimension of the offered load is deterministic and operator-set:

- **Rate**: `--pps` probes/s per stream (default 50 = one probe every 20 ms,
  deliberately matching G.711 voice packetization); `--tcp-pps` splits the
  TCP rate from the UDP rate; or name the bandwidth directly with
  `--mbps X` (1.7.0) — the target splits evenly across the streams, the
  rates derive from `--size`, and the footer shows **offered vs target** so
  the known quantity is verified on screen, not assumed.
- **Size**: `--size` bytes per probe (default 200; 34 min, 65535 max), one
  knob for all streams. Echoes mirror the probe size, so **every stream's
  load is symmetric in both directions**.
- **Protocol/port**: two fixed UDP flows + two fixed TCP flows per pair, on
  known ports — stable 5-tuples that policy match rules can target.
- **Encapsulation**: optional genuine VXLAN (RFC 7348) around *all four
  streams* with a fixed, documented overhead (+50 B per UDP probe, +62 B per
  TCP probe).
- **Calibrated bandwidth ladder**: the burst test offers exact Mbps stages
  (default 1, 2, 5, 10, 25) of paced 1200-byte UDP, in both directions at
  once.

### Steady-state load at the defaults

Each host, per peer, per direction, per stream sends 50 probes/s **and** 50
echoes/s of the peer's probes → ~100 pps per stream per direction:

| Accounting level | Per UDP stream / direction | Whole box / direction (4 streams) |
|---|---|---|
| App payload (200 B) | 20 KB/s | 80 KB/s |
| IP level (UDP +28 B, TCP +40 B) | ~22.8 KB/s | ~94 KB/s ≈ **0.75 Mbps** |

Scaling is linear in `--pps`, `--size`, and peer count. Rule of thumb per
direction on the wire:

```
UDP stream:  bps ≈ 2 × pps × (size + 28) × 8
TCP stream:  bps ≈ 2 × tcp_pps × (size + 40) × 8     (plus ACK overhead)
box total  ≈ sum over 4 streams × number of peers
```

> **Site-default callout:** the fleet launcher `run.bat` overrides the CLI
> defaults with `--size 8164 --dont-fragment` (= exact 8192-byte IP packets).
> At 50 pps that is ~3.3 Mbps of probe traffic per UDP stream each way
> (echoes double it) — roughly **40× the CLI-default bandwidth** — and DF
> makes any hop with MTU < 8192 read as 100 % loss. Know which launcher
> you're demoing with.

## 1.3 What the instrument shows (the demo payoff)

Generating load is half the story; every packet is also a measurement:

- **Live charts** (5-min rolling history, `--history`): RTT per stream over a
  pooled p5–p95 latency band, loss+late %, jitter (RFC 3550-style), and
  **one-way drift** per direction (`fwd→` / `rtn←`) — directional congestion
  without synchronized clocks.
- **Header tiles**: color-coded Experience score (ITU-T G.107 E-model
  R-factor, 0–100), UDP MOS (1–4.5), and a TCP **Path Quality Index** built
  from RTT, RTT variance, app-layer retransmission signature, throughput
  ratio, and TCP connect time.
- **Diagnostics that name the cause**: forward-vs-return loss isolation
  (which leg dropped it), loss-pattern classification (bursty vs scattered ×
  path-wide vs port-specific vs protocol-selective — i.e. *"policer/ACL on
  that port?"* appears on screen), "UDP silent" firewall detection, and
  per-stream size verification for jumbo/fragmentation proof.
- **Wire anatomy panel**: a byte-proportional prediction of how the
  EdgeConnect fabric slices and encapsulates the current probe size (slice
  budget 1360 B, AES-GCM-256 framing, tunnel MTU 1488), with packet
  amplification factor and predicted WAN pps.

## 1.4 Deployment shape

- **Zero dependencies**: Python 3.8+ standard library only; Tkinter GUI with
  automatic console fallback; optional PyInstaller `.exe`.
- **No admin rights** for anything — including the userspace VXLAN VTEP.
- **Windows-first hardening**: 4 MiB socket buffers and a 1 ms scheduler tick
  so pacing is smooth and microbursts don't read as phantom loss; ICMP
  port-unreachable quench so start order never matters; exclusive port bind
  so a double launch fails loudly instead of corrupting stats.
- **Peer-only traffic**: reflectors answer configured peers only — the tool
  cannot be used as an open packet reflector, and third parties can't skew a
  demo.
- **Software quality**: unit suite (scoring/diagnostics, signed-update
  verification, launcher glue) runs in CI across Python 3.8–3.12 on
  Linux/Windows/macOS with a flake8 pass; self-update is RSA-signed and
  fail-closed.

---

# 2. User Guide

## 2.1 Setup

1. **Install** (Windows, no admin): double-click `install.bat` from a
   checkout, or use the PowerShell one-liner in the README. Start-Menu and
   Desktop shortcuts open the graphical launcher.
2. **Firewall**: allow inbound **UDP 30201–30202** and **TCP 30101–30102**
   (native mode), or **only UDP 4789** in VXLAN mode — the whole session
   collapses to one port.
3. **Version parity**: both ends must run **1.5.0+** (the `NQV2` wire header);
   a mixed pair reads as "no link". Update from the UI (⟳), `update.bat`, or
   `--update`.
4. **Start it** — three equivalent ways:
   - **Launcher** (no arguments): every option is a form field, settings
     persist, shows this machine's IP to type into the other end, and has
     MTU-sweep / Burst-test buttons.
   - **CLI**: `python netquality.py --peer <other-ip>` on each end.
   - **`run.bat`**: prompts for the peer, applies the site defaults
     (`--size 8164 --dont-fragment` — see the callout above).
   - Console mode: `--no-gui` (keys: `r` = reset, `q` = quit).

## 2.2 The dials (known-quantity controls)

| Flag | Default | Effect on the offered load |
|---|---|---|
| `--pps N` | 50 | probes/s per stream (UDP; TCP too unless `--tcp-pps`) |
| `--tcp-pps N` | = `--pps` | independent TCP cadence |
| `--mbps X` | off | target offered probe load for the box (IP level, per direction, probes only; echoes double the wire); derives rates from `--size`, overrides `--pps`/`--tcp-pps` |
| `--size N` | 200 | bytes per probe, all streams (34–65535) |
| `--dont-fragment` | off | DF bit: oversized probes drop instead of fragment |
| `--udp-ports A,B` / `--tcp-ports A,B` | 30201,30202 / 30101,30102 | the match-rule surface |
| `--vxlan` (+`--vxlan-vni`, `--vxlan-port`) | off (4242, 4789) | encapsulate all four streams |
| `--peers A,B,…` | — | mesh: full four-stream suite to every listed peer |
| `--window` / `--timeout` / `--loss-deadband` | 10 s / 2 s / 0.5 % | measurement window, lost-declaration deadline, demo blip suppression |
| `--burst-mbps A,B,…` / `--burst-secs S` | 1,2,5,10,25 / 3 | burst-test ladder |
| `--sweep-min` / `--sweep-max` | 1400 / 9000 | MTU sweep bounds |

A probe is judged **received** (echo within `--timeout`), **lost** (never
echoed), or **late** (echo after the deadline — reclassified from lost, so
Loss % is *truly never returned* and Late % is *returned too late to use*).
The score treats loss+late as the effective impairment; `--loss-deadband`
(default 0.5 %) keeps trivial blips from denting a demo while lifetime
counters keep the raw truth.

## 2.3 Test-case catalog — what the app supports today

Each entry: what it demonstrates, how to run it, the traffic it generates
(the known quantity), and what to show on screen.

### T1. Baseline path quality (voice + interactive app)

- **Demonstrates:** steady-state path health through the fabric; the
  reference state every policy demo starts from.
- **Run:** `python netquality.py --peer <ip>` on both ends.
- **Traffic:** 4 streams × 50 pps × 200 B, bidirectional; ≈ 0.75 Mbps per
  direction total. UDP cadence = G.711 (20 ms); TCP models an interactive
  app.
- **Show:** Experience score ≥ 80 "Excellent", flat charts, one-way drift
  hugging zero. Press **Reset / Clear** to start the demo window clean.

### T2. Known-load scaling and soak

- **Demonstrates:** a precise, sustained offered load (e.g. to sit just
  under/over a policer or to fill a small circuit) that can run for hours.
- **Run:** name the load directly — `--mbps 8` (1.7.0) offers exactly 8 Mbps
  of probes per direction for the box, split evenly across the four streams
  with the rates derived from `--size`; or raise the dials by hand, e.g.
  `--pps 250 --size 1000` ≈ 4.1 Mbps per direction per UDP stream (formula
  in §1.2). The launcher's *Target Mbps* field does the same as `--mbps`.
- **Traffic:** exactly what the formula says — pacing is accumulator-based
  and the Windows 1 ms timer keeps it smooth rather than bursty.
- **Show:** the footer's `probe load X.XX Mbps / target Y` readout — the
  offered load is measured back, so the known quantity is verifiable on
  screen; Totals table (sent/received/lost/late per stream) reconciling
  against the far end; lifetime vs since-reset counters.

### T3. QoS / policy classification targets (port-based steering)

- **Demonstrates:** per-class treatment — steer each stream down a different
  path/overlay/queue and watch per-stream lines diverge in real time.
- **Run:** defaults, or remap ports onto the policy under test:
  `--udp-ports 5060,30202` puts stream 0 wherever the voice policy matches.
- **Traffic:** four distinct, stable 5-tuples. **Directional caveat:** UDP
  streams are port-symmetric (src = dst), matchable in both directions; TCP
  probe flows have an ephemeral client source port, so return-direction
  port matches only see the server side (30101/30102).
- **Show:** per-stream latency/loss/jitter lines separating as the policy
  bites; loss-pattern line naming `"<stream> only — port-specific
  (policer/ACL on that port?)"` when one class is dropped.

### T4. Protocol-selective policy / firewall proof ("UDP silent")

- **Demonstrates:** a policy or ACL that treats UDP and TCP differently —
  including the classic "voice ports blocked in the middle".
- **Run:** defaults; apply the UDP-blocking policy mid-demo.
- **Show:** the status bar calls out **"UDP silent"** explicitly (TCP up +
  all-UDP down is never a healthy path), and the loss-pattern line reports
  `"UDP streams only — protocol-selective (QoS policy?)"`.

### T5. Jumbo frames and fragmentation behavior

- **Demonstrates:** whether full-size datagrams cross the fabric — and
  whether the path fragments, black-holes, or delivers them intact.
- **Run:** `--size 8972 --dont-fragment` on both ends (8972 + 28 = 9000-byte
  frame). Without DF the OS fragments silently; with DF a small-MTU hop
  turns jumbo probes into 100 % loss — the difference *is* the demo.
- **Traffic:** 50 pps × 9000 B ≈ 3.6 Mbps of probes per UDP stream each way
  — ~7.2 Mbps per direction per stream once echoes are counted.
- **Show:** status bar `frame 8972 B DF on size ✓ verified` (both directions
  round-tripped full-size); Totals columns TX B / Peer RX B / My RX B with
  per-stream `Size OK` / `⚠ N` — app-level proof of delivery, per direction.

### T6. Path-MTU discovery sweep

- **Demonstrates:** the largest frame the path actually carries, found
  empirically in seconds.
- **Run:** `--mtu-sweep` (CLI or launcher button) against a running peer;
  bounds `--sweep-min 1400` / `--sweep-max 9000`.
- **Traffic:** a DF-on binary search of UDP payload sizes from an ephemeral
  port (coexists with a live session; TEST-type probes stay out of the live
  session's loss bookkeeping).
- **Show:** `Largest UDP payload that traverses unfragmented: N bytes` and
  forward path MTU = N + 28.
- **Caveats:** measures the **native** path only (subtract 50/62 B for the
  VXLAN answer); UDP only; the sweep host must be a configured peer of the
  target instance, and the target must be running in native (non-VXLAN)
  mode.

### T7. Burst test — the calibrated bandwidth ladder

- **Demonstrates:** what *load* does to the path, and which of the three
  "nothing is red but it's slow" causes is present. This is the app's only
  calibrated-Mbps generator today.
- **Run:** `--burst-test` (CLI or launcher button); stages `--burst-mbps`,
  duration `--burst-secs`.
- **Traffic:** paced 1200-byte UDP probes (fits one EC slice *and* a 1500-B
  hop) from an ephemeral port to the peer's first UDP port. Stage rate →
  pps: `pps = Mbps × 10⁶ / 8 / 1200` → 1 Mbps = 104 pps, 5 = 520, 10 = 1041,
  25 = 2604 (cap 500 Mbps/stage). Echoes are full-size: **the offered load
  rides both directions at once**. A 1.5-s idle baseline precedes the ladder.
- **Show:** the per-stage table (offered vs achieved Mbps, loss *and late*,
  RTT median/p95) and the verdict:
  - RTT grows, loss low → **deep queue (bufferbloat)** (p95 > idle + 100 ms);
  - hard loss ≥ 5 % with RTT flat → **policer** (drops, doesn't queue);
  - RTT grows *then* hard loss → **shaper**;
  - otherwise → highest **clean** stage (loss+late < 1 %, p95 within +30 ms
    of idle).
- **1.7.0 hardening:** stages split **loss vs late** with the continuous
  engine's semantics (echo past `--timeout` = late, never returned = loss),
  so a policer's hard drops and a deep queue's stragglers are no longer
  conflated — late echoes can't fake a rate-cap verdict, but they do
  disqualify "clean". `--dont-fragment` now applies to burst probes too
  (the launcher's DF checkbox rides along); without it a sub-1228-MTU hop
  silently fragments the 1200 B probes and the pps math changes.
- **Caveats:** same reachability rules as the sweep (native-mode peer,
  tool host must be a configured peer).

### T8. VXLAN encapsulation and transparent fragmentation

- **Demonstrates:** real VXLAN riding the fabric with a fixed, visible
  overhead — and the fabric fragmenting/reassembling the *outer* packet
  transparently while the inner packet crosses untouched.
- **Run:** `--vxlan` on **both** ends (same `--vxlan-vni`/`--vxlan-port`).
  The canonical pair on a 1500-B path:
  - `--vxlan --size 1422` → outer exactly 1500 B (1422 + 50 encap + 28
    outer IP/UDP): clean;
  - `--vxlan --size 1472` → outer overflows: fragments transparently
    (streams stay `size ✓ verified`), or **drops** with `--dont-fragment`
    (DF applies to the outer packet) — pinpointing exactly where encap
    overhead exceeds path MTU.
- **Traffic:** all four streams inside genuine RFC 7348 VXLAN on one outer
  UDP 5-tuple (port 4789 both ways): +50 B per UDP probe, +62 B per TCP
  probe; valid inner checksums and deterministic MACs (`02:4e:<ip>`), so
  Wireshark dissects everything cleanly. Inner TCP is app-emulated
  (self-contained PSH|ACK segments, no kernel state machine) — TCP loss
  shows *as loss*, which is what an encapsulation demo wants.
- **Show:** status bar `VXLAN vni N udp/4789`; all measurement machinery
  (isolation, size verification, charts) works identically; a capture
  showing outer IPv4 fragments while the app reports zero loss *is* the
  transparent-fragmentation proof.
- **Caveats:** a mixed pair (one end native) reads 100 % loss; single-peer
  only (mesh over VXLAN is roadmap); one deterministic outer 5-tuple is
  ideal for a single policy match but useless for per-flow ECMP demos;
  one-shot tools don't run against a VXLAN-mode peer.

### T9. Loss localization — which leg dropped it

- **Demonstrates:** turning "2 % loss" into *"forward leg"* or *"return
  leg"*, and from there into which appliance/segment to blame.
- **Run:** any continuous session; press **Isolate**.
- **How it works:** the reflector counts gaps in the *originator's own
  sequence space* and echoes the running gap count back; forward loss = gaps
  the peer saw, return = round-trip − forward. Always reconciles; survives
  restarts, resets, and reordering; single-digit counts are ignored
  (per-direction in-flight allowance of 6).
- **Show:** per-stream **Where** verdict (`→ forward`, `← return`,
  `both dirs`, `clean`) plus the aggregate `fwd→ / rtn←` split in the status
  bar. Cross-reference both hosts' screens to pin the segment (a host
  dropping on receive shows as *forward* loss on the **other** host's
  screen).

### T10. Loss-pattern classification — what kind of drop policy

- **Demonstrates:** naming the *mechanism* behind loss, live: policer vs
  flap vs random noise, and which classes it touches.
- **Run:** any continuous session with loss above the deadband (60-s window,
  first ~10 s of a run excluded, ≥ 5 events).
- **Show:** two independent axes on one line — **texture** (`bursty` = drops
  clumped into sub-second instants: flap/reroute/tail-drop, vs `scattered`:
  noisy link / RED-AQM) × **scope** (`all streams together` = path-wide,
  `<stream> only` = port policer/ACL, `UDP/TCP streams only` =
  protocol-selective QoS).

### T11. Directional congestion — one-way drift

- **Demonstrates:** *which direction* is congested — without synchronized
  clocks (echoes carry the reflector's clock; the unknown offset cancels
  against a ~60-s min-filtered baseline).
- **Run:** any continuous session; load one direction (e.g. a T7 burst or an
  external transfer).
- **Show:** the drift chart's `fwd→` and `rtn←` lines separating; the loaded
  direction rises while the other stays flat.

### T12. Wire anatomy — the EdgeConnect slicing calculator

- **Demonstrates:** what the fabric does to one LAN packet, byte-for-byte:
  slices, encapsulation overhead, packet amplification, predicted WAN pps.
- **Run:** press **Anatomy** in the dashboard at any probe size.
- **Model:** measured AES-GCM-256 fabric, tunnel MTU 1488: slice budget
  1360 B; wire = 60 + 16 × ⌈(piece + framing)/16⌉ (framing 12 B whole /
  16 B slice). Examples: default 228-B inner → one 300-B tunnel packet
  (+31.6 % overhead tax); 3000-B probe → 3 WAN packets (1436 + 1436 + 364).
- **Show:** LAN row vs predicted WAN row drawn byte-proportionally; ×N
  amplification; predicted WAN pps (= pps × N per UDP stream per direction —
  echoes slice the same way); what the same packet would do at a plain
  1500-B hop (PMTUD black hole with DF, N fragments without).
- **Caveat:** a *prediction* from constants (`EC_SLICE_BUDGET` etc., tunable
  in source), not a measurement — closing that loop is Roadmap R-1.

### T13. Multi-site mesh

- **Demonstrates:** N sites probing each other with the full four-stream
  suite; per-pair scores side by side; hub/spoke by construction.
- **Run:** each node lists the others: `--peers 10.0.0.2,10.0.0.3`
  (hub/star: spokes list only the hub). Same ports serve all peers (demux by
  source address; only configured peers answered).
- **Traffic:** linear in peers — N peers ≈ N × 0.75 Mbps per direction at
  defaults.
- **Show:** a row per pair (score tile, RTT, loss, jitter, streams-up,
  worst-pair callout in the header); click a row to point all four charts at
  that pair. Loss isolation, size verification and scoring are per pair.
- **Caveats:** this is each node's local half of the N×N matrix (cross-node
  view is roadmap); `--vxlan` and `--peers` are mutually exclusive; one-shot
  tools target the first listed peer.

### T14. Demo hygiene and operator controls

- **Reset / Clear** (GUI button / `r` in console): wipes charts and
  since-reset stats for a clean demo window; lifetime counters survive so
  the whole-run truth stays available.
- **Loss deadband** (0.5 % default): sub-threshold blips read as 0 for the
  score, loss chart *and* the loss-pattern line; raw counts always kept.
- **Totals / Isolate / Anatomy / Fit charts** toggles; ⟳ Update in-app.
- **Single instance per port**: a second accidental launch fails loudly.
- **Start-order freedom**: either side can start/stop/reboot at any time.

### T15. Sustained load with the charts watching (⚡ Load, 1.7.0)

- **Demonstrates:** what a known load does to the path *while the scored
  streams keep measuring* — start the load, watch latency band / jitter /
  one-way drift react on the live charts, stop it, watch them recover. The
  square wave is the calibration pattern for WAN-side counter attribution.
- **Run:** dashboard → **⚡ Load** → enter Mbps (and optionally square-wave
  on/off seconds, default 10/10) → *Start load*.
- **Traffic:** continuous paced 1200-byte UDP TEST probes from an ephemeral
  port to the peer's first UDP port — the burst-test machinery made
  resident. Echoes are full-size, so the load rides both directions;
  excluded from loss isolation on both ends. The panel shows **offered vs
  achieved** Mbps plus the load stream's own loss/late over the last ~5 s.
- **Show:** the panel's achieved rate against the charts' reaction; with
  the square wave, the on/off periods lining up with drift/jitter swings —
  and, on the fabric side, WAN counters stepping in the same cadence.
- **Caveats:** native mode only (a VXLAN peer has no native UDP listener to
  echo the probes — the panel says so); single-pair dashboard only (not in
  the mesh GUI); DF on the load probes follows the session's
  `--dont-fragment`.

### T16. Per-class DSCP marking and bleaching detection (1.8.0)

- **Demonstrates:** business-intent overlay / per-class QoS steering with
  differently-marked probe classes side by side — and *proof* of what code
  point actually crossed, catching DSCP bleaching/remap policies live.
- **Run:** `--dscp EF,AF41,-,BE` (one entry per stream in order; launcher
  field under Advanced). Pair with profiles for realistic classes:
  `--profiles voice,video --dscp EF,AF41`.
- **Traffic:** identical probe machinery, per-stream code points. POSIX
  marks exactly (`IP_TOS`); Windows maps through qWAVE traffic types
  without admin (request EF → the stack sends CS7 — the UI reports the
  truth). VXLAN mode marks the **inner** header.
- **Show:** Totals column `DSCP rq→f/r` per stream (`EF→EF/EF` clean;
  `EF→BE/...` bleached, which also raises the *DSCP rewritten mid-path*
  warning line); per-class latency/loss lines diverging as the fabric
  treats classes differently.
- **Caveats:** forward/return readback needs a POSIX receiver for native
  UDP; VXLAN mode reads back on all streams and platforms; native TCP
  streams show `?`. Both ends should run 1.8.0+ for the report (older
  reflectors are compatible but report nothing).

### T17. Stream sets and mixed application classes (1.8.0)

- **Demonstrates:** a one-box multi-application load matrix — flows on the
  exact ports a policy matches, each shaped like a different app.
- **Run:** e.g. `--udp-ports 5060,30201,30202 --tcp-ports 30101
  --profiles voice,imix,default,bulk` (1–8 UDP + 0–8 TCP streams; `none`
  drops TCP entirely). `--mbps X` still holds the box at a known total —
  each stream's rate derives from its own mean wire size.
- **Show:** per-stream chart lines (one color per stream, up to 16),
  Totals rows with per-stream expected sizes (IMIX verifies at 1472 B),
  the footer's `frames per profile` tag and offered-vs-target readout.
- **Caveats:** at least one UDP stream always required; both ends must run
  identical port lists; the mesh GUI and console scale with the stream
  count automatically.

### T18. Measured WAN counters and the calibration diff (1.9.0)

- **Demonstrates:** *measured* WAN pps next to the Anatomy panel's
  *predicted* pps — 1 LAN packet becoming N WAN packets, observed, not
  modeled; and on busy fabrics, isolating the demo's footprint by
  square-waving the load and diffing the counters between on/off windows.
- **Run:** `--wan-counters snmp:<wan-router>,public,<ifindex>` (any
  SNMP-capable device), `rest:URL|TOKEN|tx.path|rx.path`, or
  `--wan-counters sim` for the no-hardware rehearsal. Open **Anatomy** for
  the measured line; the console prints it too.
- **Show:** measured tx/rx pps vs predicted pps and the ×N-vs-LAN ratio;
  with a square-wave stage running, the counters stepping in cadence.

### T19. Slice-budget measurement and live slicing evidence (1.9.0)

- **Demonstrates:** the fabric's real slice budget measured from the wire
  (RTT-vs-size staircase), and per-WAN-packet loss proven from the loss
  ratio of a 1-slice vs N-slice stream pair — both with zero EC access.
- **Run:** one-shot `--slice-scan` against a running native peer; or
  continuously, `--profiles 200,3000` and watch for the slice-loss-ratio
  line when loss appears.
- **Show:** the scan's boundary list and measured budget vs the model
  constant; the status line naming `N-slice/1-slice` loss amplification.

### T20. Scripted demo arcs (--scenario, 1.9.0)

- **Demonstrates:** a hands-free, repeatable demo: baseline → load →
  calibration square wave → clean slate, with stage markers on the charts.
- **Run:** `--scenario demo.json` (format in the README); `repeat: 0`
  loops for a booth/kiosk demo.
- **Show:** dashed stage markers (labeled on the latency chart), the
  footer's stage countdown, and the charts reacting per stage.
- **Caveats:** load stages need native transport and target the first
  peer; a stage with `reset: true` wipes the since-reset window (lifetime
  counters survive, as always).

### T21. FEC proof and loss amplification (2.0.0)

- **Demonstrates:** *measured* proof that FEC is repairing — WAN counters
  dropping while probes run clean — or its absence: probe loss amplified
  by the slice count.
- **Run:** `--wan-counters snmp:...` against a device exposing
  discard/error counters (or `sim:0:1.5` to rehearse: the simulator drops
  1.5 % on the WAN while the clean path keeps probes at 0 %).
- **Show:** the status line naming the verdict; the Anatomy/Topology
  panels carrying the measured rates behind it; the report capturing it.

### T22. PMTUD black-hole naming and fragment counting (2.0.0)

- **Demonstrates:** whether an MTU limit is *announced* (ICMP
  frag-needed, PMTUD works) or *silent* (black hole); and at capture
  level, whether whole packets or kernel-reassembled fragments arrived.
- **Run:** `--mtu-sweep` (the ICMP verdict is automatic on Linux, no
  root); `--frag-sniffer` alongside a session (needs root/admin).
- **Show:** the sweep's closing verdict line; the footer/console fragment
  counter staying at 0 while jumbo sizes verify = the fabric delivered
  whole packets.

### T23. Live topology strip (2.0.0)

- **Demonstrates:** the whole story on one strip — Host → EC → fabric →
  EC → peer with LAN pps, predicted/measured WAN pps and the ×N
  amplification moving live.
- **Run:** dashboard → **≣ Topology** (pair with `--wan-counters` for the
  measured span).

### T24. The leave-behind report (2.0.0)

- **Demonstrates:** the demo's evidence as a file: scores, per-stream
  stats with DSCP readback, totals, forward/return split, every fired
  diagnostic, WAN counters, scenario state.
- **Run:** **⭳ Report** in the dashboard, `w` in the console, or
  `--report BASE` for an automatic write at exit.
- **Show:** the self-contained HTML opens anywhere; the JSON feeds
  before/after diffs and CI-style acceptance checks.

## 2.4 Constraint summary (read before scripting a demo)

| Constraint | Detail |
|---|---|
| IPv4 only | DF handling and VXLAN inner packets are IPv4 |
| Per-stream sizes/rates via `--profiles` (1.8.0) | named profiles + IMIX shipped; still no time-varying ramps in the continuous engine (Roadmap R-4) |
| Stream count: 1–8 UDP + 0–8 TCP (1.8.0) | at least one UDP stream always required; both ends must run identical port lists |
| DSCP marking shipped (1.8.0) | exact on POSIX; Windows non-admin goes through qWAVE traffic types (EF request → CS7 on the wire, reported honestly); native-UDP readback needs a POSIX receiver, VXLAN readback works everywhere, native TCP shows `?` |
| One-shot tools (sweep/burst/slice-scan) and the Load panel | UDP-only, native-mode peers only, tool host must be a configured peer on the target; Load panel is single-pair GUI only |
| Privilege boundaries (2.0.0) | frag sniffer needs root/admin (raw capture); the sweep's ICMP verdict needs Linux (IP_RECVERR, no root); FEC verdict needs a drop-reporting counter source |
| Version parity | both ends ≥ 1.5.0; VXLAN both-ends-or-neither, same VNI/port |
| Burst test / Load | both directions carry the offered load (echoes are full-size); burst DF is opt-in via `--dont-fragment` |

---

# 3. Roadmap of Features

**Mission:** make Network Vitals the definitive way to generate a *known
quantity* of high-quality traffic that exercises SD-WAN traffic policies —
and to *prove on screen* what the fabric did with it.

Guiding principles carried forward from the codebase: the measurement must
not disturb the measured; fail visible, never silent; stdlib-only and no
admin rights; every number on screen is either measured or clearly labeled a
prediction.

Items are grouped in four phases. "EC" = EdgeConnect. Existing README
roadmap items are folded in and renumbered (`R-n`).

## Phase 1 — Make "known quantity" a first-class control

*Theme: today the operator computes bandwidth from pps × size; tomorrow they
should dial bandwidth directly, shape it over time, and mix classes.*

- **R-1. Target-bandwidth mode.** ✅ **Shipped in 1.7.0**: `--mbps X` (and
  the launcher's *Target Mbps* field) splits the target across the four
  streams, derives the rates from `--size`, and the footer shows **offered
  vs target** continuously. Turns every demo request ("give me exactly
  8 Mbps of voice-like traffic") into one flag.
- **R-2. Sustained-load mode in the dashboard.** ✅ **Shipped in 1.7.0**:
  the **⚡ Load** button offers a continuous known-quantity UDP load
  (start/stop, rate field, offered-vs-achieved readout) while the live
  charts show its impact, including the **square-wave scheduler** (N s on /
  N s off) — the "calibration burst" needed to attribute WAN-side counters
  on busy fabrics (pairs with R-12). Native-mode, single-pair dashboard.
- **R-3. Per-stream profiles and IMIX.** ✅ **Shipped in 1.8.0**:
  `--profiles` assigns each stream a named mix (`voice` 200 B @ 50 pps,
  `video` 1200 B @ 90 pps, `bulk` 1400 B @ 200 pps, `imix` 7:4:1 of
  64/576/1500-byte IP packets cycled probe-by-probe) or a custom
  `SIZE`/`SIZExPPS`; `--mbps` composes (sizes kept, per-stream rates
  derived from each stream's own mean wire size).
- **R-4. Scenario scripting.** ✅ **Shipped in 1.9.0**: `--scenario FILE`
  replays a JSON timeline (per-stage secs, load_mbps, square-wave on/off,
  reset) with dashed stage markers on all four charts and a live
  stage/pass countdown in the footer; `repeat: 0` loops a demo forever.
- **R-5. Burst-test hardening.** ◐ **Partially shipped in 1.7.0**:
  `--dont-fragment` now applies to burst probes (they used to silently
  fragment below 1228-B MTU paths), and stages report **loss vs late**
  separately with the continuous engine's semantics (late echoes can't fake
  a rate-cap verdict). Remaining: an optional TCP burst stage, and running
  the burst/sweep tools against a VXLAN-mode peer.

## Phase 2 — Exercise the policy classification surface

*Theme: SD-WAN policies match on DSCP, ports, protocols and app signatures;
the tool should be able to present all of those dimensions deliberately.*

- **R-6. Per-DSCP probe classes** *(README #8)*. ✅ **Shipped in 1.8.0**:
  `--dscp` marks each stream (exact `IP_TOS` on POSIX; qWAVE traffic types
  on Windows without admin, with the applied code point reported honestly),
  the reflector reports the received TOS back (wire-compatible echo-padding
  stamp), and the Totals table + warning line surface **bleaching/remap**
  per stream in both directions. VXLAN mode marks and reads the inner
  header on all platforms.
- **R-7. Configurable stream sets.** ✅ **Shipped in 1.8.0**: `--udp-ports`
  takes 1–8 ports and `--tcp-ports` 0–8 (`none` = UDP-only), one stream per
  port, so a session presents flows on the exact ports a customer's policy
  matches (443, 5060, 3389, …); charts, tables, mesh and console all scale.
- **R-8. Elastic (real-TCP) load stream.** An optional kernel-TCP bulk
  transfer stream (congestion-controlled, like iperf) alongside the fixed-
  rate probes — shows shapers/QoS acting on elastic traffic while the
  probe streams measure the collateral effect on real-time classes. The
  probes stay the instrument; this adds the workload.
- **R-9. First-packet app-signature presets.** Optional payload/port presets
  that make streams classifiable by first-packet/DPI app recognition
  (RTP-shaped payloads on 5004, TLS-hello-shaped on 443) for app-based
  steering demos, clearly labeled as emulation.

## Phase 3 — Prove what the fabric did (measured WAN side)

*Theme: today the WAN middle is predicted by the Anatomy model; tomorrow it
is measured. (This is the existing README roadmap, carried forward.)*

- **R-10. EC WAN counter polling** *(README #1)*. ◐ **Shipped in 1.9.0**
  as a pluggable collector: `--wan-counters` polls **SNMP** (stdlib v2c,
  IF-MIB 64-bit counters — covers EC and any router), a **generic REST**
  JSON endpoint, or the built-in **simulator** (integrates this instance's
  own load through the EC slicing model — the no-hardware UAT backend);
  measured WAN pps renders next to the Anatomy panel's predicted pps, and
  the square-wave calibration isolates the load's footprint on busy
  fabrics. Remaining for UAT against real gear: the Orchestrator-specific
  endpoint/auth preset and hub-transit path selection.
- **R-11. FEC verdict** *(README #2)*. ✅ **Shipped in 2.0.0**: the WAN
  counter source's drop rates (SNMP discard/error OIDs; `sim:NOISE:LOSS%`
  for rehearsal) are compared with app-level probe loss — WAN dropping
  while probes run clean is called out as **measured FEC repair**, and
  probe loss ≈ N× WAN slice loss as **amplification with no repair**;
  silent when neither is proven.
- **R-12. Slice-boundary detector** *(README #3)*. ✅ **Shipped in 1.9.0**:
  `--slice-scan` measures the real slice budget from the RTT-vs-size
  staircase (and says when the Anatomy model constant needs tuning), and
  the always-on **slice-loss-ratio evidence** watches any two UDP streams
  with different slice counts (e.g. `--profiles 200,3000`) and calls out
  `large ≈ N × small` loss as live per-WAN-packet loss — no EC access
  needed for either.
- **R-13. LAN fragment sniffer + ICMP listener** *(README #4, #5)*.
  ✅ **Shipped in 2.0.0**: `--frag-sniffer` counts IPv4 fragments to/from
  the peer at capture level (AF_PACKET / SIO_RCVALL — needs root/admin,
  degrades to an honest "unavailable"), and the MTU sweep now reads the
  Linux socket error queue (IP_RECVERR, **no root needed**) to report
  "ICMP frag-needed received (MTU=N)" vs "silently dropped → PMTUD black
  hole".
- **R-14. Coalescing detector** *(README #6)*: receiver-side inter-arrival
  clustering + the ~1–3 ms wait-timer signature in small-probe RTT.
- **R-15. Live topology strip** *(README #7)*. ✅ **Shipped in 2.0.0**: the
  **≣ Topology** button draws Host → EC → fabric → EC → peer with live
  numbers — LAN pps, predicted/measured WAN pps, amplification on the
  tunnel span.

## Phase 4 — Scale, repeatability, reporting

- **R-16. VXLAN mesh** *(README #9.2)*: static-FIB userspace VXLAN full mesh —
  one outer socket per node, demuxed by outer source IP; removes today's
  `--vxlan` × `--peers` exclusivity.
- **R-17. Cross-node matrix + auto-diagnosis** *(README #9.3)*: aggregate the
  per-node views into the full N×N matrix; "every pair touching node C
  degraded ⇒ C's site/link" called out automatically.
- **R-18. Hub/star mode** *(README #9.4)*: first-class spoke→hub topology
  (works by list construction today) to keep probe count linear at scale.
- **R-19. Results export & demo report.** ◐ **Shipped in 2.0.0**: the
  **⭳ Report** button (console `w`; `--report BASE` at exit) writes a
  timestamped JSON + self-contained HTML pair — scores, per-stream stats
  incl. DSCP readback, totals, every fired diagnostic, WAN counters and
  scenario state. Remaining: embedded chart images and a before/after-
  policy comparison view.
- **R-20. Headless/automation mode.** `--json` periodic stats on stdout, a
  local metrics endpoint (Prometheus-style), and scripted pass/fail
  assertions with exit codes ("loss < 0.5 % and p95 < 80 ms for 10 min") —
  turns demos into repeatable acceptance tests.
- **R-21. IPv6.** Dual-stack probes, DF/PMTU semantics via `IPV6_DONTFRAG`,
  VXLAN inner v6.

## Suggested sequencing

| Milestone | Contents | Rationale |
|---|---|---|
| **1.7** ✅ shipped | R-1, R-2, R-5 (DF + late split; TCP/VXLAN burst deferred) | Biggest demo wins, no new privileges/protocols: dial-a-bandwidth + sustained load on the live charts |
| **1.8** ✅ shipped | R-6, R-3, R-7 + alpha-aware updater | The policy-classification surface: DSCP + multi-class mixes + configurable stream sets |
| **1.9** ✅ shipped | R-10 (collector + simulator; Orchestrator preset at UAT), R-12, R-4 | First measured-WAN loop (counters + calibration burst + scripted scenarios) |
| **2.0** ✅ shipped (2.0.0a1) | R-11, R-13, R-15, R-19 (charts-in-report deferred) | The full "prove the fabric" story + the leave-behind report |
| **2.x** | R-8, R-9, R-14, R-16 – R-18, R-20, R-21 | Scale-out, automation, elastic loads |

---

*Sources: `netquality.py` v1.6.2 (all constants and thresholds verified
against code), `README.md`, `run.bat`, `tests/`, `.github/workflows/ci.yml`.*
