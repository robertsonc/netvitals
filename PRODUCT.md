# Product

<!-- impeccable:product-schema 1 -->


## Platform

desktop (Windows primary; Tk or hosted local UI also runs where Python + display exist)

## Stack

**Decision (proposed):** keep a **single replaceable artifact** so in-app Update stays as smooth as today (signed manifest → verify → atomic install → relaunch).

- Measurement engine, CLI, updater: Python stdlib (unchanged trust model).
- UI: **embedded Operate UI** (HTML/CSS/JS constants or an archive embedded in `netquality.py`) hosted on localhost, shown in a native window when possible (Windows WebView2 via stdlib/ctypes) with browser fallback; thin Tk allowed as chrome/dock if needed.
- **Rejected for v1 unless Update protocol is extended:** pip-dependent UI frameworks (PyQt, CustomTkinter, Electron) that break one-file signed replace or require a separate runtime install.
- Optional later: extend manifest to a signed zip while preserving the same Update button UX.

## Users

1. **Primary — SE / sales engineer** running a live EdgeConnect SD-WAN demo: standing room, projector/TV, needs the path story readable at a glance and tools reachable without hunting.
2. **Secondary — executive / customer stakeholder** watching: cares about “is it good?” and clear proof when policy changes the path.
3. **Tertiary — network engineer** digging: Totals, Isolate, Anatomy, Topology, Load, DSCP/VXLAN detail.

## Product Purpose

Network Vitals is a bidirectional path instrument: the same program runs on both ends, continuously probing UDP/TCP streams, and scores **Experience**, **UDP MOS**, and **TCP PQI** so SD-WAN policy effects are visible live.

Success: in a demo, an SE can show path health, induce a policy/load change, and have the room see the effect within seconds — then leave a credible HTML/JSON report.

## Positioning

Not a generic speed test. A **known-quantity, bidirectional, multi-stream path instrument** built for EdgeConnect SD-WAN demos (QoS, steering, FEC, encapsulation, MTU) with forward/return loss isolation and fabric wire anatomy.

## Brand commitments

- Name: **Network Vitals**
- HPE green `#01A982` as primary brand accent
- Assets: `assets/hpe_logo.svg` / `.png`, `assets/netvitals.ico` (EKG mark)
- Enterprise HPE product craft (GreenLake-adjacent clarity) — not neon/cyber hobby chrome
- Room-readable health meter remains a product requirement

## Capabilities (preserve)

- Launcher, live dashboard, mesh dashboard, update dialog, HTML+JSON report, console mode
- Streams, scoring, Reset, Totals, Isolate, Anatomy, Topology, Load, Report, Update
- VXLAN, DSCP, profiles, scenarios, signed self-update for `netquality.py`

## Constraints

- Do not break probe protocol, scoring math, or signed update fail-closed behavior
- Upgrade UX must remain one-click smooth (parity with today’s Update → relaunch)
- All listed UI surfaces redesign together under one visual system
- Windows is the demo platform of record

## Accessibility

- Operable contrast for dark demo rooms and projected displays
- Keyboard focus for primary actions where the stack allows
- Prefer real text in the web UI over canvas-only labels for the main chrome

## Open decisions / follow-ups

- Host resolved: **browser + Tk dock** (WebView2 deferred; no pip).
- Signed update still replaces only `netquality.py`. Full UI refresh for field installs needs `tools/embed_ui.py` inlined into the artifact (follow-up) so `ui/` + `nv_webui.py` travel with the signed file.
