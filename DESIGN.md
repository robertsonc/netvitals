---
name: Network Vitals
description: HPE Demo Instrument — restrained Operate UI for bidirectional path quality demos.
colors:
  bg: "#0d1218"
  bg-elev: "#141b24"
  surface: "#1a2330"
  surface-2: "#222c3a"
  stroke: "#2a3545"
  text: "#e8eef5"
  text-dim: "#8b9aab"
  text-faint: "#5c6b7d"
  accent: "#01a982"
  accent-hi: "#1ec9a0"
  warn: "#e6a23c"
  danger: "#e45757"
typography:
  ui:
    fontFamily: "Segoe UI Variable Text, Segoe UI, Helvetica Neue, system-ui, sans-serif"
  mono:
    fontFamily: "Cascadia Mono, Consolas, SF Mono, ui-monospace, monospace"
rounded:
  sm: "6px"
  md: "10px"
spacing:
  sm: "8px"
  md: "16px"
  lg: "24px"
---

# Design System — Network Vitals

## 1. Visual world

**HPE Demo Instrument.** Cool charcoal ground, flat elevated panels, HPE green `#01A982` only for OK state and primary actions. Semantic amber/red for faults. No aurora blobs, violet accents, glass blur stacks, or neon orb glow.

## 2. Mode

Operate (dashboard, launcher, mesh, dialogs). Read (HTML report leave-behind).

## 3. First viewport (dashboard)

Top status rail → monumental Experience meter + MOS/PQI → Reset / Report / Tools → latency chart full width → loss / jitter / drift row → footer counters.

## 4. Components

- Primary button: HPE green fill, dark text
- Secondary button: flat surface + stroke
- Tools menu: disclosure for Totals, Isolate, Anatomy, Topology, Load, Fit, Update
- Charts: graticule grid, desaturated stream colors, optional p5–p95 band
- Panels: flat cards, tabular data

## 5. Stack

Web UI in `ui/` served by `nv_webui.py` over loopback, opened as a frameless Chromium app-mode window (`msedge`/`chrome --app`, dedicated profile dir) when one is installed — else a browser tab, and `NV_APPWIN=0` forces the tab; Tk dock for process chrome. `NV_UI=tk` forces legacy glass UI.

## 6. Anti-patterns

Forbidden: purple/violet decorative accents, multi-layer glass shadows as identity, emoji toolbar glyphs as the icon system, nine peer-level toolbar buttons.
