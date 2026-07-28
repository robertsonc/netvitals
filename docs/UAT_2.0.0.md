# UAT checklist — Network Vitals 2.0.0

Acceptance testing for the 2.0.0 release. Every case here needs something CI and loopback
smoke tests cannot provide: **real SD-WAN gear, elevated privileges, a second platform, or a
real client doing a real update.**

Test-case style follows `SDWAN_DEMO_GUIDE.md` (T1–T17). Those are demo scripts — how to
*show* a feature. These are acceptance tests — how to *prove* it, and what counts as a
failure.

## How to use this

Record a result per case: **PASS** / **FAIL** / **BLOCKED** (couldn't run) / **N/A**. Copy
the summary table at the bottom into your notes and fill it in as you go. Attach the demo
report (`⭳ Report`) wherever a case produces one — the JSON pair is the evidence.

Legend for what a failure means:

| | |
|---|---|
| 🔴 **Blocker** | ship-stopping. Fix forward before wider rollout. |
| 🟡 **Defect** | real bug, not ship-stopping. File it. |
| ⚪ **Limit** | documented platform/privilege limit. Confirm it degrades honestly; not a bug. |

## Already verified — do not redo

These were checked during the release and need no UAT time:

- 127 unit tests pass on Linux, macOS and Windows across Python 3.8–3.12 (CI).
- Signed-release integrity: signature verifies over the exact manifest bytes, tampered
  manifest and tampered signature both rejected, artifact SHA-256 matches the signed
  manifest, artifact byte-identical to `git show v2.0.0:netquality.py`. Run against the
  **public** release assets, not local copies.
- Version ordering: `1.6.2`, `1.7.0`, `1.8.0`, `1.9.0` and `2.0.0a1` all sort below `2.0.0`.
- On-wire probe format is byte-identical to the 1.x series (`MAGIC`, `TYPE_*`,
  `TOS_REPORT_MAGIC`, `HEADER.pack` all unchanged), so 1.9 and 2.0 peers interoperate.
  U11 exercises this in the field rather than by inspection.

## Environments

| Ref | Needs |
|---|---|
| **E1** | Two Windows workstations either side of an EdgeConnect fabric — the reference demo setup |
| **E2** | A device whose WAN interface counters are SNMP-readable (`ifHCInUcastPkts` etc. + discard/error OIDs) |
| **E3** | A real Orchestrator REST endpoint plus a token |
| **E4** | A Linux host (for `IP_RECVERR`, and root for the frag sniffer) |
| **E5** | A workstation where an elevated/admin shell is acceptable |
| **E6** | A client already running **1.9.0** that has never seen 2.0.0 |

Rehearse anything you can with `--wan-counters sim:0:1.5` before touching real gear — the
simulator drives the same code path as SNMP/REST, so you'll recognise a correct verdict when
you see one.

---

## A. The update path

Highest priority: 2.0.0 is live at `releases/latest` and every existing client will take it
automatically. These cases test the mechanism everyone depends on.

### U1. A real 1.9.0 client updates to 2.0.0 🔴

- **Why:** the signed-update path has been verified against the published bytes from this
  machine, but never end to end on a client that actually applies the update.
- **Environment:** E6.
- **Run:** on the 1.9.0 client, `netquality.py --check-update`, then `--update`.
- **Pass:** `--check-update` reports 2.0.0 available; `--update` fetches, verifies against
  the embedded `UPDATE_PUBKEY`, replaces the file, and the app restarts reporting
  `__version__ = 2.0.0`. No manual intervention.
- **Fail:** any signature/verification error, a partial write, or an app that will not start
  afterwards. **Stop the rollout and report immediately** — this affects every install.
- **Record:** exact output of both commands.

### U2. A tampered update is refused ⚪→🔴

- **Why:** fail-closed is the entire security property. It is unit-tested; this proves it on
  a real client against real network fetching.
- **Run:** point a client at a manifest whose signature does not match (a local HTTP server
  serving a one-byte-edited `manifest.json` with the genuine `.sig` reproduces it).
- **Pass:** the client refuses, says so clearly, and **leaves the installed version
  untouched**.
- **Fail:** any path where a bad signature results in a changed `netquality.py`. 🔴

### U3. Update on Windows 🟡

- **Why:** file replacement while running behaves differently on Windows.
- **Environment:** E1.
- **Pass:** as U1, on Windows, including the running-executable replacement.

---

## B. Fabric measurement — needs real gear

### U4. FEC verdict against real drop counters 🟡

- **Why:** the headline 2.0 claim. `fec_verdict()` is unit-tested for verdict shape, but has
  never seen a real device's discard counters move.
- **Environment:** E2. Cleanest validation is a policer or impairment on the tunnel interface
  so WAN discards genuinely rise.
- **Run:** `--wan-counters snmp:HOST,COMMUNITY,IFINDEX` with traffic flowing, then induce WAN
  loss.
- **Pass — one of these two, matching reality:**
  - Fabric repairing: `FEC repairing: WAN dropping N.NN% (N pps) while probes run N.NN%
    clean — measured proof of repair`
  - No repair, multi-slice probes: `loss amplification: probes lose N.NN% ≈ N.N× the WAN
    slice loss (N.NN%) — a lost slice kills the whole N-slice packet (no FEC on this path)`
- **Also pass:** *silence* when neither is statistically proven. The verdict is deliberately
  conservative — no message is a valid, correct outcome, not a missing feature.
- **Thresholds** (so you can tell a wrong verdict from a quiet one): nothing fires below
  0.05% WAN loss. "FEC repairing" needs probe loss under `max(0.1%, wan_loss/4)`.
  Amplification needs >1 slice and probe loss at least `wan_loss × max(1.5, 0.6 × slices)`.
- **Fail:** a verdict that contradicts what the fabric is actually doing — especially "FEC
  repairing" on a path with no FEC configured. A wrong verdict is worse than none.
- **Record:** the verdict line, the device's raw counter values, and the fabric's actual FEC
  configuration.

### U5. SNMP source against real hardware 🟡

- **Why:** the SNMPv2c client is ~120 lines of hand-rolled BER built for this. Unit tests
  cover encode/decode round-trips against its own primitives — not against a real agent.
- **Environment:** E2. Get `IFINDEX` from `snmpwalk ifDescr`.
- **Pass:** measured WAN pps appears beside predicted in the Anatomy panel and tracks offered
  load. Counters that wrap or reset (reboot the device if you can) **re-baseline rather than
  spiking**.
- **Also check:** a device *without* discard/error OIDs is tolerated — those are optional; the
  poller should keep working and simply not produce a FEC verdict.
- **Fail:** BER parse errors, silently wrong counters, or a wrap that produces a huge false
  spike. 🟡

### U6. REST source against the real Orchestrator 🟡

- **Why:** the `rest:URL[|TOKEN[|TX_KEY|RX_KEY]]` contract is designed to absorb the real
  endpoint without code changes. This is the test of that claim. **The Orchestrator-specific
  preset is explicitly not in 2.0.0** — deferred R-10 scope.
- **Environment:** E3.
- **Run:** `--wan-counters "rest:URL|TOKEN|tx.dotted.path|rx.dotted.path"`. The token is sent
  as both `Authorization: Bearer` and `X-Auth-Token`.
- **Pass:** counters poll and track. Record the working URL and JSON key paths — **that is the
  deliverable** for baking in a preset later.
- **Fail:** the generic poller cannot express what the endpoint needs. That is design
  feedback, not a bug — capture exactly what was missing.

### U7. Slice scan against a real slicing fabric 🟡

- **Why:** unit tests detect staircases in synthetic data. Real RTT curves are noisy.
- **Run:** `--slice-scan` across the fabric, then again on a path with no slicing.
- **Pass:** on the fabric, boundary sizes and a measured slice budget, with a tuning hint if
  it disagrees with `EC_SLICE_BUDGET`. On a non-slicing path, a clean negative.
- **Fail:** boundaries reported on a slice-free path (false positive — worse than a miss), or
  no staircase where slicing demonstrably occurs.
- **Record:** measured budget vs the model constant. If they disagree consistently, the
  constant needs tuning and that is a follow-up.

### U8. Topology strip shows live measured numbers ⚪

- **Run:** **≣ Topology** with `--wan-counters` active.
- **Pass:** `Host → EC → fabric → EC → peer` with LAN pps, predicted *and* measured WAN pps,
  and the ×N amplification ratio, all moving. Without `--wan-counters`, predicted only, and
  it says so rather than showing a zero.

---

## C. Privilege and platform paths

The point of these is as much the **graceful degradation** as the feature. An honest
"unavailable" is a pass. A crash or a lie is not.

### U9. Fragment sniffer, elevated 🟡

- **Environment:** E5, Linux (`AF_PACKET`) and Windows (`SIO_RCVALL`).
- **Run:** `--frag-sniffer` from an elevated shell, with traffic that fragments (oversized
  probes, DF off).
- **Pass:** IPv4 fragments to/from the peer are counted; a clean whole-packet path counts
  zero.
- **Fail:** miscounts, or the capture thread destabilising the measurement.

### U10. Fragment sniffer, unelevated ⚪

- **Run:** the same, from a normal shell.
- **Pass:** the app **stays fully functional** and reports something like `raw capture
  unavailable (...) - needs admin/root; fragment counting off` in the footer/console.
- **Fail:** an exception, a hang, a refusal to start, or — worst — a **zero fragment count
  presented as a real measurement**. Reporting zero without capture would be lying. 🔴

### U11. PMTUD verdict on Linux 🟡

- **Environment:** E4. Needs a path with a sub-1500 hop.
- **Run:** `--mtu-sweep`.
- **Pass — matching reality, one of:**
  - `=> ICMP 'fragmentation needed' received (MTU=N) - PMTUD works on this path; endpoints
    learn the limit.`
  - `=> Oversized probes were dropped SILENTLY (no ICMP came back): a PMTUD black hole -
    endpoints can't learn the limit, they just lose packets.`
- **Fail:** the wrong verdict — a black hole is a real network finding and a false one sends
  people chasing nothing.

### U12. PMTUD verdict off Linux ⚪

- **Environment:** E1 (Windows) and macOS if available.
- **Pass:** the sweep still reports MTU results, and where probes were dropped it says
  `(ICMP frag-needed detection needs Linux/IP_RECVERR; unavailable on this platform.)` — no
  verdict guessed. This is by design: the app uses no privileged sockets anywhere.

---

## D. Interop and regression

### U13. 1.9.0 ↔ 2.0.0 interop 🔴

- **Why:** a staged rollout means mixed versions. Wire compatibility was established by
  inspection; this proves it.
- **Environment:** E6 plus a 2.0.0 host.
- **Run:** 2.0.0 on one end, 1.9.0 on the other, full session.
- **Pass:** all streams measure normally, scores and loss/latency/jitter behave, no
  version-related warnings.
- **Watch:** DSCP forward/return readback and one-way drift — both ride data the *peer*
  stamps, so they are the most likely place a mismatch would surface.
- **Fail:** any measurement that only works when both ends are 2.0.0. 🔴

### U14. 1.8-era features still work on a real fabric 🟡

- **Why:** 2.0 stacked on 1.9 which stacked on 1.8. Regression checked by diff, not in the
  field.
- **Run:** `--profiles voice,video --dscp EF,AF41` across the fabric.
- **Pass:** Totals shows `DSCP rq→f/r` per stream; a fabric that remaps raises *DSCP rewritten
  mid-path*. Per-class lines diverge where the fabric treats classes differently.
- **Note:** native-UDP readback needs a POSIX receiver; VXLAN reads back everywhere; native
  TCP shows `?`. Those are ⚪, not failures.

### U15. Demo report as a leave-behind ⚪

- **Run:** `⭳ Report` (console `w`; or `--report BASE` to write at exit) after a session that
  fired several diagnostics.
- **Default location:** `~/.config/netvitals/reports/netvitals-<stamp>.{json,html}`
  (`%APPDATA%\NetVitals\reports\` on Windows).
- **Pass:** JSON + HTML pair; the HTML opens **on a machine with no network** and renders
  fully — it must fetch nothing external. Scores, per-stream table with DSCP readback,
  totals, forward/return split, every diagnostic that fired, WAN counters and scenario state
  all present.
- **Check:** feed a hostile peer name or scenario name (`<script>alert(1)</script>`) and
  confirm it renders as text. HTML-escaping is unit-tested; this confirms it end to end.
- **Known gaps, not failures:** no embedded chart images, no before/after-policy comparison —
  both explicitly deferred from 2.0.
- **Fail:** any external fetch, or unescaped data.

### U16. Scenario scripting through a full demo 🟡

- **Run:** `--scenario FILE` with a realistic arc (baseline → load → square-wave → reset),
  `repeat: 0` for a booth loop.
- **Pass:** stage markers on all four charts, footer countdown and pass counter correct,
  loads actually offered, resets clearing since-reset stats while lifetime totals survive.
  A malformed file fails **at the command line with a per-stage error**, not mid-demo.
- **Note:** load stages need native transport (not `--vxlan`) and target the first peer. ⚪

---

## Results

| Case | Area | Sev | Result | Notes / evidence |
|---|---|---|---|---|
| U1 | 1.9→2.0 real update | 🔴 | | |
| U2 | Tampered update refused | 🔴 | | |
| U3 | Update on Windows | 🟡 | | |
| U4 | FEC verdict, real counters | 🟡 | | |
| U5 | SNMP source, real device | 🟡 | | |
| U6 | REST source, Orchestrator | 🟡 | | |
| U7 | Slice scan, real fabric | 🟡 | | |
| U8 | Topology strip measured | ⚪ | | |
| U9 | Frag sniffer, elevated | 🟡 | | |
| U10 | Frag sniffer, unelevated | 🔴 | | |
| U11 | PMTUD verdict, Linux | 🟡 | | |
| U12 | PMTUD verdict, off-Linux | ⚪ | | |
| U13 | 1.9 ↔ 2.0 interop | 🔴 | | |
| U14 | DSCP/profiles on fabric | 🟡 | | |
| U15 | Demo report | ⚪ | | |
| U16 | Scenario scripting | 🟡 | | |

## If something fails

**Clients auto-update, and the updater accepts only strictly newer versions.** There is no
rollback: a broken 2.0.0 is corrected by shipping 2.0.1, never by republishing 2.0.0 or
reverting to 1.9.0. Existing installs would ignore both.

So:

1. **Blocker (🔴) found** — fix forward and cut 2.0.1 promptly. Anyone who has already
   updated is on the broken build until you do.
2. **Defect (🟡)** — file it, batch it into the next release.
3. **Limit (⚪) that degrades badly** — treat as 🟡. The design commitment is that unavailable
   features say so and the app keeps working.

Release procedure: `RELEASING.md` (manual signing) or `AGENTIC_RELEASING.md` (agent signs via
`NV_RELEASE_PASSIN`), both in `~/.config/netvitals/`.
