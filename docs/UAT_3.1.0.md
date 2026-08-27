# UAT checklist — Network Vitals 3.1.0

Acceptance testing for the 3.1.0 release. Every case here needs something CI and headless
smoke tests cannot provide: **real SD-WAN gear, elevated privileges, a second platform, a real
display, or a real client doing a real update.**

Test-case style follows `SDWAN_DEMO_GUIDE.md` (T1–T17). Those are demo scripts — how to
*show* a feature. These are acceptance tests — how to *prove* it, and what counts as a
failure.

> **Supersedes the 2.1.0 checklist**, which itself superseded the 2.0.0 one. Neither was ever
> executed — no results were recorded against either — so everything below is outstanding, not
> re-testing.
>
> **Sections A–D carry over in substance.** The measurement engine, fabric features, privilege
> paths and interop behaviour are unchanged since 2.x; only version numbers moved. **Sections E
> and F are new**, and replace the old Section E entirely: 3.0.0 moved the default interface from
> Tk to a browser-served web UI, and 3.1.0 opens it in a frameless Chromium app-mode window, so
> the old hover-legend and glass-rendering cases now describe a non-default path.

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
  manifest, artifact byte-identical to `git show v3.1.0:netquality.py`, artifact compiles.
  Run against the **public** release assets, not local copies.
- Version ordering: `3.0.0`, `3.0.1`, `3.0.2` and `3.1.0a1` all sort below `3.1.0`.
- On-wire probe format is byte-identical to the 1.x and 2.x series (`MAGIC`, `TYPE_*`,
  `TOS_REPORT_MAGIC`, `HEADER.pack` all unchanged), so 2.x and 3.x peers interoperate.
  **U13 exercises this in the field** rather than by inspection.
- The web UI is covered by `tests/test_webui.py`: app-mode launch, the no-Chromium and
  `NV_APPWIN=0` fallbacks, `Popen` failure falling back to a browser tab, headless skipping
  app mode, embedded-zip round-trip, and dock teardown surviving worker-thread GC. Those are
  unit tests against stubs — they prove the decisions, not that a window appears on a real
  desktop. That is what Section E is for.
- The UI packed into the shipped artifact matches `ui/` and `nv_webui.py` at content level.
  Worth knowing because `netquality.py` now contains *generated* content: "the artifact matches
  the git tag" no longer proves the shipped UI matches the UI sources, since a stale embed would
  be identical in both. Checked per release by decoding `_NV_WEBUI_ZIP_B64` and comparing all 10
  entries by SHA-256. (A naive re-pack byte-differs — that is zip timestamp metadata, not drift.)
- The browser launch was reviewed for injection: `Popen` with an argv list, no `shell=True`
  anywhere, internally generated URL, executable from a path/registry probe.

## Environments

| Ref | Needs |
|---|---|
| **E1** | Two Windows workstations either side of an EdgeConnect fabric — the reference demo setup |
| **E2** | A device whose WAN interface counters are SNMP-readable (`ifHCInUcastPkts` etc. + discard/error OIDs) |
| **E3** | A real Orchestrator REST endpoint plus a token |
| **E4** | A Linux host (for `IP_RECVERR`, and root for the frag sniffer) |
| **E5** | A workstation where an elevated/admin shell is acceptable |
| **E6** | A client already running **3.0.1** that has never seen 3.1.0 |
| **E7** | A real display — and for the across-the-room cases, the screen and viewing distance an actual demo uses |
| **E8** | A Windows box **with** Edge/Chrome/Chromium installed (the reference demo platform) and one **without** any Chromium, for the fallback path |

Rehearse anything you can with `--wan-counters sim:0:1.5` before touching real gear — the
simulator drives the same code path as SNMP/REST, so you'll recognise a correct verdict when
you see one.

---

## A. The update path

Highest priority: 3.1.0 is live at `releases/latest` and every existing client will take it
automatically. These cases test the mechanism everyone depends on.

### U1. A real 3.0.1 client updates to 3.1.0 🔴

- **Why:** the signed-update path has been verified against the published bytes from the
  release machine, but never end to end on a client that actually applies the update. It has
  now carried four releases without this check.
- **Environment:** E6.
- **Run:** on the 3.0.1 client, `netquality.py --check-update`, then `--update`.
- **Pass:** `--check-update` reports 3.1.0 available; `--update` fetches, verifies against
  the embedded `UPDATE_PUBKEY`, replaces the file, and the app restarts reporting
  `__version__ = 3.1.0`. No manual intervention.
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

Carried over unchanged. These features are identical in 3.1.0 and have still never been run against real gear.

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
  preset is still not shipped as of 3.1.0** — deferred R-10 scope.
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
- **3.x note:** the strip was restyled with the rest of the front end. Confirm the numbers
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

### U13. 3.0.1 ↔ 3.1.0 interop 🔴

- **Why:** a staged rollout means mixed versions. Wire compatibility was established by
  inspection; this proves it.
- **Environment:** E6 plus a 3.1.0 host.
- **Run:** 3.1.0 on one end, 3.0.1 on the other, full session.
- **Pass:** all streams measure normally, scores and loss/latency/jitter behave, no
  version-related warnings.
- **Watch:** DSCP forward/return readback and one-way drift — both ride data the *peer*
  stamps, so they are the most likely place a mismatch would surface.
- **Fail:** any measurement that only works when both ends are 3.1.0.

### U14. 1.8-era features still work on a real fabric 🟡

- **Why:** each milestone stacked on the last, and the front end was rebuilt twice since.
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
- **3.x note:** the report HTML was restyled to match the new theme. Re-confirm the
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

## E. The web UI (new in 3.x)

3.0.0 replaced the Tk dashboard with a loopback HTTP server and a browser front end; 3.1.0
presents it as a frameless Chromium app-mode window. `tests/test_webui.py` covers the launch
*decisions* against stubs. None of it proves a window appears on a real desktop, that the
server is unreachable from the network it is demoing, or that the UI survives a real update.

### U17. App-mode window on the demo platform 🔴

- **Why:** the headline 3.1.0 change, and the first thing anyone sees. Only ever exercised
  against a stubbed `Popen`.
- **Environment:** E8 (Windows, Chromium present).
- **Run:** launch normally, then again after resizing and closing, to confirm geometry is
  restored from the profile.
- **Pass:** a frameless window with its own taskbar entry — no address bar, no tab strip. It
  uses the dedicated profile under `config_dir()/appwin`, so it carries none of your browsing
  session, extensions or logged-in accounts. First run sizes to 1280×860; later runs restore
  whatever size you left it.
- **Also check:** the small Tk dock appears alongside and its **Quit** actually stops the
  process, and closing the app window does not leave an orphaned `netquality.py` running.
- **Fail:** a normal browser tab where Chromium is installed, a window that steals the
  operator's default-browser session, or a dock whose Quit leaves the process alive.

### U18. Every fallback path 🟡

- **Why:** three independent routes back to a plain browser tab, each a different failure mode.
- **Run each, on E8's no-Chromium box where noted:**
  1. `NV_APPWIN=0` with Chromium present
  2. no Chromium installed at all
  3. Chromium present but `Popen` fails (rename the exe, or point it at a non-executable)
- **Pass:** all three open a working UI in the default browser. No traceback, no hang, no
  silent nothing-happens.
- **Fail:** any path where the app starts, binds a port, and never shows a UI — the operator
  has no way to tell it is running.

### U19. The server is not reachable off-box 🔴

- **Why:** this listens on a machine plugged into a customer network. The bind is
  `127.0.0.1` in source, but that claim should be verified from the wire, not from a grep.
- **Environment:** E1, both ends.
- **Run:** start a session, find the port (`netstat -ano | findstr LISTENING`, or `ss -ltnp`),
  then from the **peer machine** try `curl http://<demo-box-ip>:<port>/` and
  `http://<demo-box-ip>:<port>/api/snapshot`.
- **Pass:** connection refused / no route from off-box, while `http://127.0.0.1:<port>/` works
  locally. The listening socket shows `127.0.0.1:<port>`, not `0.0.0.0:<port>`.
- **Fail:** anything answering from another host. That would expose the whole control API —
  including load generation and update-apply — to the customer's network. **Stop and report.**

### U20. The embedded UI survives a real signed update 🔴

- **Why:** the entire reason `ui/` and `nv_webui.py` are packed into `netquality.py`. An update
  replaces **one file**, and the UI has to still come up on the other side. Never tested on a
  real client.
- **Environment:** E6.
- **Run:** on a 3.0.1 client that has no `nv_webui.py` sibling (an installed client, not a git
  checkout), update to 3.1.0 and relaunch.
- **Pass:** the app extracts the UI and starts normally. Check `_nv_webui_extract_3.1.0/`
  appears next to `netquality.py` — or, if that directory is read-only,
  `config_dir()/webui/3.1.0/`.
- **Also check:** the old `_nv_webui_extract_3.0.1/` is left behind. That is expected (the
  version is in the name) but confirm it accumulates rather than corrupts, and note the disk
  cost if it looks unreasonable.
- **Fail:** a client that updates and then cannot render a UI. That is an unrecoverable-looking
  break for a non-technical operator, even though the measurement engine is fine.

### U21. No SIGABRT after traffic starts 🔴

- **Why:** 3.0.0 aborted the process shortly after traffic started —
  `Tcl_AsyncDelete: async handler deleted by the wrong thread` — because a destroyed Tk dock
  root was cyclic garbage collected on whichever thread next triggered the GC. 3.0.1 pins dock
  roots and collects on the main thread. The fix is sound in principle and has a regression
  test, but it is a **timing- and threading-dependent crash**, which is exactly the kind that a
  unit test can miss.
- **Run:** a full session with real traffic, left running **at least as long as a real demo** —
  30+ minutes, ideally an hour. Include the launcher → dashboard handoff, a Load run, a Reset,
  and a mesh session. Repeat on Windows and Linux.
- **Pass:** no abort, no `Tcl_AsyncDelete`, no silent process death. Clean exit via dock Quit.
- **Fail:** any abort. Capture stderr verbatim — the Tcl message names the failing condition.

### U22. Launcher, dashboard and mesh 🟡

- **Run:** launcher → enter peer → Start → dashboard. Separately, a 3+ node mesh.
- **Pass:** the advanced disclosure round-trips settings; the handoff from launcher to
  dashboard leaves exactly one UI window and one process; mesh shows the worst-pair meter,
  the peer table, and charts for the selected pair, with selection tracking clicks.
- **Also check:** Tools → Totals / Isolate / Anatomy / Topology / Load each open and show live
  data, and **Report** writes the pair.

### U23. Readable across a room 🟡

- **Why:** the Experience meter is explicitly a broadcast-style readout. That is a claim about
  physical legibility and cannot be checked on the machine that drew it.
- **Environment:** E7, at real demo viewing distance.
- **Pass:** the score and its colour band are unambiguous from across the room; the four charts
  are distinguishable. Check the score bands read correctly for a red-green colour-blind viewer
  if you can.

### U24. Performance on demo hardware 🟡

- **Why:** the UI is now a browser engine plus a Python HTTP server polling at 1 Hz, on top of
  the measurement threads. The 2.1.x CPU work was measured against the Tk renderer, which no
  longer applies.
- **Environment:** the actual demo laptops, on battery as well as mains.
- **Pass:** UI stays responsive, charts keep up, no fan-spinning idle, and the measurement is
  not disturbed — compare loss/latency against a `--no-gui` run on the same path. **The
  instrument must not perturb what it measures**; that principle predates the web UI and still
  governs.
- **Fail:** measurable degradation in the numbers when the UI is open. Record which machine.

---

## F. Legacy and fallback interfaces

Still supported, no longer the default, and correspondingly easy to break without noticing.

### U25. Legacy Tk dashboard (`NV_UI=tk`) 🟡

- **Why:** the whole glass Tk UI is still in the file and still reachable. Nothing in the 3.x
  work exercises it.
- **Run:** `NV_UI=tk` with a live session on E7.
- **Pass:** the glass dashboard opens and behaves as it did in 2.1.1 — hover-reveal legend pills
  fading in under the pointer, click-to-expand, `+N more` truncation with 8 streams, watermark
  titles under the traces, all four charts live. No SIGABRT here either.
- **Note:** this is the 2.1.x interface. If it has quietly rotted, that is worth knowing before
  someone reaches for it as a fallback mid-demo.

### U26. Console UI, headless 🟡

- **Why:** the last resort when there is no display, and the only option on a headless box.
- **Run:** a session over SSH with no `DISPLAY` / no Tk.
- **Pass:** falls back to the console UI without a traceback; `r` resets counters, `q` quits;
  the readout updates.
- **Fail:** a crash or a hang where the app should have degraded — on a headless host there is
  nothing else to fall back to.

---

## Known issues — do not re-report

Open at the time of writing. Confirming them is not a UAT finding; finding them **worse than
described**, or finding a *new* path to them, is.

| | Issue | Status |
|---|---|---|
| #36 | `_ensure_nv_webui()` prefers an unsigned sibling `nv_webui.py` over the signed embedded copy | open |
| #37 | Extracted UI is reused without re-validation; the `.ok` marker is written but never read | open |
| #38 | No Origin/CSRF check on state-changing POSTs, including `/api/update/apply` | open, partially mitigated by the dedicated Chromium profile in 3.1.0 |
| #39 | `/assets/` unanchored prefix check and unresolved symlinks | open |

U19 and U20 overlap #36–#39 deliberately: they test the properties those issues threaten, from
the outside, on a real client.

## Results

| Case | Area | Sev | Result | Notes / evidence |
|---|---|---|---|---|
| U1 | 3.0.1→3.1.0 real update | 🔴 | | |
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
| U13 | 3.0.1 ↔ 3.1.0 interop | 🔴 | | |
| U14 | DSCP/profiles on fabric | 🟡 | | |
| U15 | Demo report | ⚪ | | |
| U16 | Scenario scripting | 🟡 | | |
| U17 | App-mode window | 🔴 | | |
| U18 | Fallback paths | 🟡 | | |
| U19 | Not reachable off-box | 🔴 | | |
| U20 | Embedded UI survives update | 🔴 | | |
| U21 | No SIGABRT after traffic | 🔴 | | |
| U22 | Launcher / dashboard / mesh | 🟡 | | |
| U23 | Readable across a room | 🟡 | | |
| U24 | Performance on demo hardware | 🟡 | | |
| U25 | Legacy Tk (`NV_UI=tk`) | 🟡 | | |
| U26 | Console UI, headless | 🟡 | | |

## If something fails

**Clients auto-update, and the updater accepts only strictly newer versions.** There is no
rollback: a broken 3.1.0 is corrected by shipping 3.1.1, never by republishing 3.1.0 or
reverting to 3.0.1. Existing installs would ignore both.

So:

1. **Blocker (🔴) found** — fix forward and cut 3.1.1 promptly. Anyone who has already
   updated is on the broken build until you do.
2. **Defect (🟡)** — file it, batch it into the next release.
3. **Limit (⚪) that degrades badly** — treat as 🟡. The design commitment is that unavailable
   features say so and the app keeps working.

Six cases are 🔴 here against three in the 2.1.0 list, and five of the six are new. That is the
cost of moving the interface: the measurement engine is the same code it has been for releases,
but how the operator reaches it changed twice in a month.

Release procedure: `RELEASING.md` (manual signing) or `AGENTIC_RELEASING.md` (agent signs via
`NV_RELEASE_PASSIN`), both in `~/.config/netvitals/`.
