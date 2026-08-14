# UAT checklist — Network Vitals 2.1.0

Acceptance testing for the 2.1.0 release. Every case here needs something CI and headless
smoke tests cannot provide: **real SD-WAN gear, elevated privileges, a second platform, a real
display, or a real client doing a real update.**

Test-case style follows `SDWAN_DEMO_GUIDE.md` (T1–T17). Those are demo scripts — how to
*show* a feature. These are acceptance tests — how to *prove* it, and what counts as a
failure.

> **Supersedes the 2.0.0 checklist.** That list was published but never executed — no results
> were recorded against it — so **U1–U16 carry over unchanged in substance**. The 2.0 fabric,
> privilege and interop features are identical in 2.1.0, so those cases apply directly; only
> the version numbers in the update-path and interop cases have moved. Sections A–D are the
> 2.0 tranche, still outstanding. **Section E is new**, covering the 2.1.0 interface.

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

- The unit suite passes on Linux, macOS and Windows across Python 3.8–3.12 (CI), plus flake8
  and shellcheck. That includes behaviour tests for `tools/sign_release.sh` — pass-phrase
  source validation, manifest canonicalisation, and the guarantee that a failed signing
  leaves no signature behind — so the release tooling itself no longer rests on manual runs.
- Signed-release integrity: signature verifies over the exact manifest bytes, tampered
  manifest and tampered signature both rejected, artifact SHA-256 matches the signed
  manifest, artifact byte-identical to `git show v2.1.0:netquality.py`, artifact compiles.
  Run against the **public** release assets, not local copies.
- Version ordering: `1.9.0`, `2.0.0`, `2.0.1` and `2.1.0a1` all sort below `2.1.0`.
- On-wire probe format is byte-identical to the 1.x and 2.0 series (`MAGIC`, `TYPE_*`,
  `TOS_REPORT_MAGIC`, `HEADER.pack` all unchanged), so 2.0 and 2.1 peers interoperate.
  **U13 exercises this in the field** rather than by inspection.
- The 2.1.0 interface was rendered and inspected under Xvfb at every entry point, and the
  hover legend has a scripted pass over synthetic pointer events (16 assertions). Neither
  substitutes for a real display — that is what Section E is for.

## Environments

| Ref | Needs |
|---|---|
| **E1** | Two Windows workstations either side of an EdgeConnect fabric — the reference demo setup |
| **E2** | A device whose WAN interface counters are SNMP-readable (`ifHCInUcastPkts` etc. + discard/error OIDs) |
| **E3** | A real Orchestrator REST endpoint plus a token |
| **E4** | A Linux host (for `IP_RECVERR`, and root for the frag sniffer) |
| **E5** | A workstation where an elevated/admin shell is acceptable |
| **E6** | A client already running **2.0.0** that has never seen 2.1.0 |
| **E7** | A real display with a real pointer — and for the across-the-room cases, the screen and viewing distance an actual demo uses |

Rehearse anything you can with `--wan-counters sim:0:1.5` before touching real gear — the
simulator drives the same code path as SNMP/REST, so you'll recognise a correct verdict when
you see one.

---

## A. The update path

Highest priority: 2.1.0 is live at `releases/latest` and every existing client will take it
automatically. These cases test the mechanism everyone depends on.

### U1. A real 2.0.0 client updates to 2.1.0 🔴

- **Why:** the signed-update path has been verified against the published bytes from the
  release machine, but never end to end on a client that actually applies the update. It has
  now carried four releases without this check.
- **Environment:** E6.
- **Run:** on the 2.0.0 client, `netquality.py --check-update`, then `--update`.
- **Pass:** `--check-update` reports 2.1.0 available; `--update` fetches, verifies against
  the embedded `UPDATE_PUBKEY`, replaces the file, and the app restarts reporting
  `__version__ = 2.1.0`. No manual intervention.
- **Fail:** any signature/verification error, a partial write, or an app that will not start
  afterwards. **Stop the rollout and report immediately** — this affects every install.
- **Record:** exact output of both commands.

### U2. A tampered update is refused 🔴

- **Why:** fail-closed is the entire security property. It is unit-tested; this proves it on
  a real client against real network fetching.
- **Run:** point a client at a manifest whose signature does not match (a local HTTP server
  serving a one-byte-edited `manifest.json` with the genuine `.sig` reproduces it).
- **Pass:** the client refuses, says so clearly, and **leaves the installed version
  untouched**.
- **Fail:** any path where a bad signature results in a changed `netquality.py`.

### U3. Update on Windows 🟡

- **Why:** file replacement while running behaves differently on Windows.
- **Environment:** E1.
- **Pass:** as U1, on Windows, including the running-executable replacement.

---

## B. Fabric measurement — needs real gear

Carried over from the 2.0.0 tranche. Unchanged in 2.1.0 and still unexecuted.

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
  spike.

### U6. REST source against the real Orchestrator 🟡

- **Why:** the `rest:URL[|TOKEN[|TX_KEY|RX_KEY]]` contract is designed to absorb the real
  endpoint without code changes. This is the test of that claim. **The Orchestrator-specific
  preset is still not shipped as of 2.1.0** — deferred R-10 scope.
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
- **2.1.0 note:** the strip was restyled with the rest of the front end. Confirm the numbers
  are still legible against the new surface, not just present.

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

### U10. Fragment sniffer, unelevated 🔴

- **Run:** the same, from a normal shell.
- **Pass:** the app **stays fully functional** and reports something like `raw capture
  unavailable (...) - needs admin/root; fragment counting off` in the footer/console.
- **Fail:** an exception, a hang, a refusal to start, or — worst — a **zero fragment count
  presented as a real measurement**. Reporting zero without capture would be lying.

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

### U13. 2.0.0 ↔ 2.1.0 interop 🔴

- **Why:** a staged rollout means mixed versions. Wire compatibility was established by
  inspection; this proves it.
- **Environment:** E6 plus a 2.1.0 host.
- **Run:** 2.1.0 on one end, 2.0.0 on the other, full session.
- **Pass:** all streams measure normally, scores and loss/latency/jitter behave, no
  version-related warnings.
- **Watch:** DSCP forward/return readback and one-way drift — both ride data the *peer*
  stamps, so they are the most likely place a mismatch would surface.
- **Fail:** any measurement that only works when both ends are 2.1.0.

### U14. 1.8-era features still work on a real fabric 🟡

- **Why:** each milestone stacked on the last, and the front end was rebuilt in 2.1.0.
  Regression checked by diff and headless render, not in the field.
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
- **2.1.0 note:** the report HTML was restyled to match the new theme. Re-confirm the
  **no-external-fetch** property specifically — a restyle is exactly where a web font or CDN
  stylesheet slips in. Open it with the network off and watch for missing glyphs.
- **Known gaps, not failures:** no embedded chart images, no before/after-policy comparison.
- **Fail:** any external fetch, or unescaped data.

### U16. Scenario scripting through a full demo 🟡

- **Run:** `--scenario FILE` with a realistic arc (baseline → load → square-wave → reset),
  `repeat: 0` for a booth loop.
- **Pass:** stage markers on all four charts, footer countdown and pass counter correct,
  loads actually offered, resets clearing since-reset stats while lifetime totals survive.
  A malformed file fails **at the command line with a per-stage error**, not mid-demo.
- **Note:** load stages need native transport (not `--vxlan`) and target the first peer. ⚪

---

## E. The interface (new in 2.1.0)

The redesign was rendered and inspected under Xvfb, and the hover legend has a scripted pass
over synthetic pointer events. What neither can tell you is whether the result **works in the
room it is used in** — at a real viewing distance, on demo hardware, with a real pointer.

### U17. Hover legend on a real display 🟡

- **Why:** the 16-assertion pass drives synthetic `<Enter>`/`<Leave>`/click events under
  Xvfb. Real pointers move continuously, cross card boundaries, and arrive mid-refresh.
- **Environment:** E7.
- **Run:** move across all four charts, in and out repeatedly, pause on boundaries, click
  pills to expand and collapse, and do it while data is actively updating.
- **Pass:** pills fade in under the pointer and back out on leave; one pill per series plus
  the percentile band; clicking expands exactly the clicked pill and widens it; a refresh
  tick while hovering does not drop the legend; the watermark title dims as the legend rises
  so the two never fight at full strength.
- **Also check:** run **8 UDP streams** and confirm the stack truncates inside the plot with a
  `+N more` pill rather than overflowing.
- **Fail:** flicker, a legend stuck visible after leaving, pills that swallow clicks meant for
  the chart, or the title and legend both at full strength at once.

### U18. Charts at rest, unattended 🟡

- **Why:** **a deliberate trade-off in 2.1.0** — at rest the charts no longer show current
  per-stream values; they appear on hover. On an unattended demo screen the live head dots
  still carry each series' colour at the right edge, but the numbers are gone until someone
  moves the pointer. This is the case most likely to produce a real complaint.
- **Environment:** E7, at the viewing distance and screen an actual demo uses.
- **Run:** leave a session running with nobody touching the mouse, as at a booth.
- **Pass:** a viewer can still tell what the connection is doing — which series is which, and
  whether anything is wrong — from the score orb, chart shapes and coloured head dots alone.
- **Fail / feedback:** if the missing numbers make an unattended screen materially less
  useful, that is the trigger for the always-visible compact rail the change already
  anticipates. Record the judgement either way — this is the one case where "it feels worse"
  is a legitimate, actionable result.

### U19. Readable across a room 🟡

- **Why:** the arc-gauge score orb exists specifically to be read from a distance. That is a
  claim about physical legibility, and it cannot be checked on the machine that drew it.
- **Environment:** E7.
- **Pass:** from normal demo viewing distance, the score value and its colour band are
  unambiguous, and the four charts are distinguishable. Score-band colours read correctly on
  the dark surface — green/amber/red are distinct, including for a red-green colour-blind
  viewer if you can check.
- **Fail:** a score you have to walk up to, or bands that are hard to tell apart.

### U20. Windows rendering and font resolution 🟡

- **Why:** the font stack is resolved against installed families at startup, and picking up
  Segoe UI Variable on Windows 11 is a Windows-specific claim that cannot be tested on Linux.
  Tk's rendering differs meaningfully per platform.
- **Environment:** E1 (Windows 11, and Windows 10 if any demo box still runs it).
- **Run:** every entry point — launcher (basic and advanced), dashboard wide and narrowed,
  each collapsible panel, Fit charts, mesh view, update dialog, MTU-sweep tool window.
- **Pass:** proportional fonts throughout with no bitmap fallback; no clipped labels, no
  overlapping text, no misaligned glass edges at any window size or DPI scaling setting.
- **Also check:** a non-100% display scaling setting (125% / 150%), which is common on
  laptops.
- **Fail:** bitmap fallback fonts, clipping, or layout that breaks under DPI scaling.

### U21. Redraw cost on demo hardware 🟡

- **Why:** a full 4-chart redraw measures ~40 ms on the development display, against ~28 ms
  for the flat rendering it replaces, with a 500 ms default refresh. Demo laptops are weaker,
  and some run on integrated graphics or battery-saver clocks.
- **Environment:** the actual machines used for demos.
- **Run:** a full session with 5 minutes of history, all panels open, ideally alongside the
  load generator so the app is doing real work.
- **Pass:** the UI stays responsive, refresh keeps up with the configured interval, and CPU
  is not pegged. Resizing is smooth.
- **Fail:** visible stutter, refresh falling behind, or a fan-spinning idle. If a weak machine
  struggles, record which and how badly — that is the input for whether a reduced-effects mode
  is needed.

### U22. Mesh view 🟡

- **Why:** the peer matrix is now drawn on a Canvas rather than laid out as widgets — a
  structural change, not a repaint, and the mesh path gets less use than the single-pair
  dashboard.
- **Run:** a three-or-more node mesh; select different pairs; resize the window.
- **Pass:** the selected pair reads clearly as a lit slab with its accent rail; every cell is
  legible and correctly labelled; selection tracks clicks accurately including after a resize.
- **Fail:** mis-registered click targets after resize, unreadable cells, or a selection that
  does not match what was clicked.

### U23. Console UI and axis labels ⚪

- **Why:** the console UI is stated to be untouched by the redesign, and the axis-label fix
  (choosing a row count whose labels are all distinct, so a 2-unit axis stops printing
  `2 2 1 0 0`) is easy to confirm and easy to regress.
- **Run:** start with the console UI on a headless box; separately, drive a chart to a small
  value range (a very clean path, where loss and jitter sit near zero).
- **Pass:** console UI starts clean and behaves as before, `r` resets. No chart prints
  duplicate axis labels at any value range.
- **Fail:** console UI broken by the redesign — it is the fallback when Tk is unavailable, so
  a break there removes the only option on those hosts.

---

## Results

| Case | Area | Sev | Result | Notes / evidence |
|---|---|---|---|---|
| U1 | 2.0→2.1 real update | 🔴 | | |
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
| U13 | 2.0 ↔ 2.1 interop | 🔴 | | |
| U14 | DSCP/profiles on fabric | 🟡 | | |
| U15 | Demo report (restyled) | ⚪ | | |
| U16 | Scenario scripting | 🟡 | | |
| U17 | Hover legend, real display | 🟡 | | |
| U18 | Charts at rest, unattended | 🟡 | | |
| U19 | Readable across a room | 🟡 | | |
| U20 | Windows rendering / fonts | 🟡 | | |
| U21 | Redraw cost, demo hardware | 🟡 | | |
| U22 | Mesh view | 🟡 | | |
| U23 | Console UI, axis labels | ⚪ | | |

## If something fails

**Clients auto-update, and the updater accepts only strictly newer versions.** There is no
rollback: a broken 2.1.0 is corrected by shipping 2.1.1, never by republishing 2.1.0 or
reverting to 2.0.0. Existing installs would ignore both.

So:

1. **Blocker (🔴) found** — fix forward and cut 2.1.1 promptly. Anyone who has already
   updated is on the broken build until you do.
2. **Defect (🟡)** — file it, batch it into the next release.
3. **Limit (⚪) that degrades badly** — treat as 🟡. The design commitment is that unavailable
   features say so and the app keeps working.

Release procedure: `RELEASING.md` (manual signing) or `AGENTIC_RELEASING.md` (agent signs via
`NV_RELEASE_PASSIN`), both in `~/.config/netvitals/`.
