/* Chaos Monkey dashboard. Plain JavaScript, no dependencies, works offline.
   Everything that comes from the network is inserted with textContent, never as HTML. */
"use strict";

const $ = (id) => document.getElementById(id);
const SVG = "http://www.w3.org/2000/svg";
let S = null;                 // last /api/state
let SERIES = {};              // leg id -> points from /api/series
let logAfter = 0;
const LOG = [];
let selectedTrial = null;
let pendingAction = null;
let formsFilled = false;

/* ---------- small helpers ---------- */

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "style") el.style.cssText = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
function s(tag, attrs, text) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  if (text !== undefined) el.textContent = text;
  return el;
}
const pad = (n) => String(n).padStart(2, "0");
const clock = (ms) => { const d = new Date(ms); return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
const num = (v, digits = 1) => (v === null || v === undefined ? "–" : Number(v).toFixed(digits));
const pct = (v) => (v === null || v === undefined ? "–" : (v >= 10 ? v.toFixed(1) : v.toFixed(2)) + "%");
const ms = (v) => (v === null || v === undefined ? "–" : v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2));
const dur = (millis) => (millis === null || millis === undefined ? "–" : millis >= 10000 ? (millis / 1000).toFixed(1) + " s" : millis >= 1000 ? (millis / 1000).toFixed(2) + " s" : Math.round(millis) + " ms");
const mmss = (sec) => `${pad(Math.floor(Math.max(0, sec) / 60))}:${pad(Math.floor(Math.max(0, sec) % 60))}`;
const bps = (v) => (!v ? "–" : v >= 1e6 ? (v / 1e6).toFixed(2) + " Mbit/s" : (v / 1e3).toFixed(0) + " kbit/s");
const ago = (sec) => (sec < 2 ? "now" : sec < 90 ? `${Math.round(sec)} s ago` : sec < 5400 ? `${Math.round(sec / 60)} min ago` : `${Math.round(sec / 3600)} h ago`);

async function api(path, body, method) {
  const opts = { method: method || (body ? "POST" : "GET"), headers: { "X-Chaoslab": "1" } };
  if (body) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch (e) { /* empty body */ }
  if (res.status === 401) { $("login").showModal(); throw new Error("Sign in first."); }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}
function say(id, text, kind) { const el = $(id); el.textContent = text || ""; el.className = "msg" + (kind ? " " + kind : ""); }
async function act(msgId, fn, okText) {
  try { const out = await fn(); say(msgId, okText || (out && out.message) || "", "good"); refresh(); return out; }
  catch (e) { say(msgId, e.message, "err"); return null; }
}

/* ---------- navigation and theme ---------- */

function show(tab) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.setAttribute("aria-selected", b.dataset.tab === tab));
  document.querySelectorAll("main > .tab").forEach((t) => t.classList.toggle("active", t.id === "tab-" + tab));
  if (location.hash !== "#" + tab) history.replaceState(null, "", "#" + tab);
  render();
}
const activeTab = () => (document.querySelector(".tab-btn[aria-selected=true]") || {}).dataset?.tab || "overview";
document.querySelectorAll(".tab-btn").forEach((b) => b.addEventListener("click", () => show(b.dataset.tab)));
document.addEventListener("click", (e) => {
  const go = e.target.closest("[data-goto]"); if (go) show(go.dataset.goto);
  const copy = e.target.closest("[data-copy]");
  if (copy) {
    const text = $(copy.dataset.copy).textContent;
    (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).catch(() => {
      const r = document.createRange(); r.selectNodeContents($(copy.dataset.copy));
      const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r); document.execCommand("copy");
    });
    copy.textContent = "Copied"; setTimeout(() => (copy.textContent = "Copy"), 1200);
  }
});
$("theme").addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  document.documentElement.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("chaoslab-theme", document.documentElement.dataset.theme); } catch (e) { /* private mode */ }
  render();
});
try { const t = localStorage.getItem("chaoslab-theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) { /* private mode */ }

/* ---------- charts ---------- */

const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
function legColors() {
  // Colour follows the leg, not its rank: slots are handed out by leg id and never reshuffled.
  const ids = Object.keys(S.legs).map(Number).sort((a, b) => a - b);
  const out = {};
  ids.forEach((id, i) => { out[id] = i < 8 ? css(`--s${i + 1}`) : css("--s-other"); });
  return out;
}
function niceMax(v, floor) {
  v = Math.max(v, floor);
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
function faultWindows(t0, t1) {
  const out = [];
  const add = (a, b, label) => { if (a && (b || t1) > t0 && a < t1) out.push({ t0: Math.max(a, t0), t1: Math.min(b || t1, t1), label }); };
  for (const t of S.trials) add(t.tInject, t.tRestore || t.ended, t.fault.label);
  if (S.current) add(S.current.tInject, S.current.tRestore, S.current.fault.label);
  return out;
}

/* One line chart, one y axis. opts: {series:[{label,color,pts:[[t,v]]}], t0, t1, unit, floor, height, windows} */
function chart(el, opts) {
  const W = Math.max(280, el.clientWidth || 600), H = opts.height || 150;
  const m = { l: 40, r: 10, t: 14, b: 18 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  let top = 0;
  for (const se of opts.series) for (const p of se.pts) if (p[1] !== null && p[1] > top) top = p[1];
  const ymax = niceMax(top, opts.floor || 1);
  const x = (t) => m.l + ((t - opts.t0) / (opts.t1 - opts.t0)) * iw;
  const y = (v) => m.t + ih - (Math.min(v, ymax) / ymax) * ih;
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, height: H, role: "img", "aria-label": opts.aria || "chart" });

  for (const w of opts.windows || []) {
    svg.append(s("rect", { class: "win", x: x(w.t0), y: m.t, width: Math.max(1, x(w.t1) - x(w.t0)), height: ih }));
    svg.append(s("line", { class: "win-edge", x1: x(w.t0), x2: x(w.t0), y1: m.t, y2: m.t + ih }));
    if (x(w.t1) - x(w.t0) > 40 && opts.labelWindows) svg.append(s("text", { class: "win-label", x: x(w.t0) + 4, y: m.t - 3 }, w.label));
  }
  for (const f of [0, 0.5, 1]) {
    const yy = m.t + ih - f * ih;
    svg.append(s("line", { class: f === 0 ? "axis" : "grid", x1: m.l, x2: W - m.r, y1: yy, y2: yy }));
    const v = ymax * f;
    svg.append(s("text", { x: m.l - 6, y: yy + 3, "text-anchor": "end" }, (v >= 10 || v === 0 ? v.toFixed(0) : v.toFixed(v >= 1 ? 1 : 2)) + (f === 1 ? opts.unit : "")));
  }
  const span = (opts.t1 - opts.t0) / 1000, step = span > 400 ? 120 : 60;
  for (let back = 0; back <= span; back += step) {
    const xx = x(opts.t1 - back * 1000);
    svg.append(s("text", { x: xx, y: H - 4, "text-anchor": back === 0 ? "end" : "middle" }, back === 0 ? "now" : `-${back / 60}m`));
  }
  for (const se of opts.series) {
    let d = "", prev = null;
    for (const p of se.pts) {
      if (p[1] === null || p[0] < opts.t0) { prev = null; continue; }
      d += (prev !== null && p[0] - prev < 2600 ? "L" : "M") + x(p[0]).toFixed(1) + " " + y(p[1]).toFixed(1);
      prev = p[0];
    }
    if (d) svg.append(s("path", { class: "line", d, stroke: se.color }));
  }
  const hair = s("line", { class: "hair", y1: m.t, y2: m.t + ih, visibility: "hidden" });
  svg.append(hair);
  el.replaceChildren(svg);
  const tip = h("div", { class: "tip", hidden: true });
  el.append(tip);

  const hover = () => {
    if (el._hx === null || el._hx === undefined) { tip.hidden = true; hair.setAttribute("visibility", "hidden"); return; }
    const px = Math.min(W - m.r, Math.max(m.l, el._hx * (W / el.clientWidth)));
    const t = Math.round((opts.t0 + ((px - m.l) / iw) * (opts.t1 - opts.t0)) / 1000) * 1000;
    hair.setAttribute("x1", x(t)); hair.setAttribute("x2", x(t)); hair.setAttribute("visibility", "visible");
    tip.replaceChildren(h("div", { class: "t", text: clock(t) }));
    for (const se of opts.series) {
      let best = null;
      for (const p of se.pts) if (Math.abs(p[0] - t) <= 1500 && (best === null || Math.abs(p[0] - t) < Math.abs(best[0] - t))) best = p;
      const v = best && best[1] !== null ? (opts.unit === "%" ? pct(best[1]) : ms(best[1]) + " " + opts.unit) : "–";
      tip.append(h("div", { class: "row" }, h("i", { class: "key", style: `border-color:${se.color}` }), h("b", { text: v }), h("span", { text: se.label })));
    }
    tip.hidden = false;
    const left = el._hx + 14 + tip.offsetWidth > el.clientWidth ? el._hx - 14 - tip.offsetWidth : el._hx + 14;
    tip.style.left = Math.max(0, left) + "px"; tip.style.top = "8px";
  };
  if (!el._wired) {
    el._wired = true;
    el.addEventListener("pointermove", (e) => { el._hx = e.clientX - el.getBoundingClientRect().left; el._hover && el._hover(); });
    el.addEventListener("pointerleave", () => { el._hx = null; el._hover && el._hover(); });
  }
  el._hover = hover;
  hover();
}

function legend(el, items) {
  el.replaceChildren(...items.map((i) => h("span", {}, h("i", { class: "key", style: `border-color:${i.color}` }), i.label)));
}

/* ---------- rendering ---------- */

const PHASES = [["precheck", "Prepare"], ["baseline", "Baseline"], ["inject", "Inject"], ["hold", "Hold"],
  ["restore", "Recover"], ["settle", "Settle"], ["verdict", "Verdict"]];
const PHASE_ALIAS = { failover: "inject", verify: "restore" };
const KIND = { wan: "WAN interface", vrrp: "VRRP master", span: "Fabric span" };
const faultText = (f) => f.label + (f.direction ? ` · ${f.direction === "down" ? "toward the site" : f.direction === "up" ? "away from the site" : "both directions"}` : "");
const legLabel = (l) => `${l.flow}: ${l.src} → ${l.dst}`;

function renderTop() {
  const st = $("engine-state");
  const label = { idle: "Idle", discovering: "Discovering", running: "Running", stopping: "Stopping" }[S.status] || S.status;
  st.textContent = label;
  st.className = "state " + ({ running: "bad", stopping: "warn", discovering: "info" }[S.status] || "");
  $("pill-mode").hidden = !S.demo; $("pill-mode").textContent = "Simulated"; $("pill-mode").className = "pill info";
  $("banner-demo").hidden = !S.demo;
  const held = S.held.length;
  $("pill-held").textContent = `${held} held`; $("pill-held").className = "pill " + (held ? "bad" : "");
  const online = S.agents.filter((a) => a.online).length;
  $("pill-agents").textContent = `${online}/${S.agents.length} endpoints`;
  $("pill-agents").className = "pill " + (S.agents.length && online === S.agents.length ? "ok" : S.agents.length ? "warn" : "");
  $("clock").textContent = new Date(S.now).toISOString().slice(0, 19).replace("T", " ") + " UTC";
  $("foot-version").textContent = "v" + S.version;
  $("n-trials").textContent = S.trials.length || "";
  $("n-flows").textContent = S.flows.length || "";
  $("n-endpoints").textContent = S.agents.length || "";
  $("n-targets").textContent = S.targets.length || "";
}

function renderTodo() {
  const connected = S.drivers.length > 0;
  const steps = [
    [S.agents.length >= 2, "Add two or more endpoints", "One command per test host. They generate the traffic and measure it.", "endpoints", "Add endpoints"],
    [S.flows.length > 0, "Create a flow", "Point to point, point to multipoint or mesh, TCP or UDP.", "flows", "Create a flow"],
    [connected, "Connect something to break", "An EdgeConnect Orchestrator (WAN interfaces, VRRP) or an Autopod lab (ISP spans).", "settings", "Connect"],
    [S.targets.length > 0, "Discover targets and set the scope", "Read-only. Nothing is touched until you start a run.", "targets", "Discover"],
    [S.trials.length > 0, "Run", "Each trial records what the flows saw before, during and after the fault.", null, null],
  ];
  const done = steps.every((x) => x[0]);
  $("todo-card").hidden = done;
  if (done) return;
  $("todo").replaceChildren(...steps.map(([ok, title, text, tab, btn], i) =>
    h("div", { class: "todo-row" + (ok ? " done" : "") }, h("span", { class: "n", text: ok ? "✓" : i + 1 }),
      h("div", {}, h("b", { text: title }), h("p", { text })),
      !ok && tab ? h("button", { class: "btn sm", "data-goto": tab, text: btn }) : null)));
}

function renderTrialCard() {
  const c = S.current;
  const phase = PHASE_ALIAS[S.phase] || S.phase;
  $("btn-stop").hidden = !(S.status === "running" || S.status === "discovering");
  $("btn-skip").hidden = S.phase !== "waiting";
  $("holdbox").hidden = true;
  if (!c) {
    $("trial-eyebrow").textContent = S.status === "running" ? "Between trials" : "No trial running";
    let title = "Idle";
    if (S.status === "discovering") title = "Discovering targets…";
    else if (S.phase === "waiting" && S.nextCycleAt) title = `Next trial in ${mmss((S.nextCycleAt - S.now) / 1000)}`;
    else if (S.status === "stopping") title = "Stopping and restoring…";
    else if (S.trials.length) { const t = S.trials[0]; title = `Last: ${t.fault.label} on ${t.target.name}`; }
    $("trial-title").textContent = title;
    const tags = [];
    if (S.status === "idle" && S.trials.length) {
      const t = S.trials[0];
      tags.push(h("span", { class: "chip " + (t.success ? "ok" : "hot"), text: t.success ? "recovered" : "failed" }));
      if (t.worstMs !== null && t.worstMs !== undefined) tags.push(h("span", { class: "chip", text: t.worstMs ? `worst interruption ${dur(t.worstMs)}` : "no interruption measured" }));
    }
    $("trial-tags").replaceChildren(...tags);
    $("steps").replaceChildren();
    $("trial-line").textContent = S.run && S.status !== "idle" ? `Run: ${S.run.done} of ${S.run.total || "∞"} done · ${S.run.ok} recovered · ${S.run.failed} failed` : "";
    return;
  }
  $("trial-eyebrow").textContent = `Current trial · cycle ${c.cycle}${S.run && S.run.total ? " of " + S.run.total : ""}`;
  $("trial-title").replaceChildren(c.fault.label, h("em", { text: " on " }), c.target.name);
  $("trial-tags").replaceChildren(
    h("span", { class: "chip hot", text: "failure injection" }), h("span", { class: "chip", text: KIND[c.target.kind] || c.target.kind }),
    c.fault.direction ? h("span", { class: "chip", text: faultText(c.fault).split(" · ")[1] }) : null,
    h("span", { class: "chip", text: c.target.group }), c.target.detail ? h("span", { class: "chip", text: c.target.detail }) : null);
  const at = {};
  for (const p of c.phases) { const k = PHASE_ALIAS[p.phase] || p.phase; if (!(k in at)) at[k] = p.at; }
  const idx = PHASES.findIndex((p) => p[0] === phase);
  $("steps").replaceChildren(...PHASES.map(([key, label], i) =>
    h("div", { class: "step" + (i < idx ? " done" : i === idx ? " now" : "") }, label, h("small", { text: at[key] ? clock(at[key]) : "" }))));
  let line = { precheck: "Checking the target is healthy before touching it", baseline: "Measuring the flows before the fault",
    inject: c.target.kind === "vrrp" ? "Fault applied · watching for VRRP failover" : "Applying the fault", hold: "Fault in place",
    restore: "Fault removed · confirming recovery", settle: "Recovered · measuring the flows after the fault", verdict: "Collecting the last measurements" }[phase] || "";
  if (phase === "hold" && c.holdUntil) {
    $("holdbox").hidden = false; $("hold-count").textContent = mmss((c.holdUntil - S.now) / 1000);
    line += ` · restores in ${mmss((c.holdUntil - S.now) / 1000)} · ${c.hold} s hold`;
  }
  if (c.facts && c.facts.failover_seconds) line += ` · failover seen after ${c.facts.failover_seconds} s`;
  $("trial-line").textContent = line;
}

function renderKpis() {
  const done = S.trials.length, ok = S.trials.filter((t) => t.success).length;
  $("k-rate").textContent = done ? (100 * ok / done).toFixed(1) + "%" : "–";
  $("k-rate-s").textContent = done ? `${ok} recovered · ${done - ok} failed` : "no trials yet";
  const measured = S.trials.filter((t) => t.worstMs !== null && t.worstMs !== undefined && t.legs);
  if (measured.length) {
    const worst = measured.reduce((a, b) => (b.worstMs > a.worstMs ? b : a));
    $("k-worst").replaceChildren(...(worst.worstMs ? dur(worst.worstMs).split(" ").map((p, i) => (i ? h("small", { text: p }) : p)) : ["none"]));
    $("k-worst-s").textContent = worst.worstMs ? `${worst.fault.label} on ${worst.target.name}` : `across ${measured.length} measured trial(s)`;
  } else { $("k-worst").textContent = "–"; $("k-worst-s").textContent = "measured by endpoint flows"; }
  const legs = Object.values(S.legs).filter((l) => !l.stale);
  if (legs.length) {
    const worst = legs.reduce((a, b) => ((b.loss || 0) > (a.loss || 0) ? b : a));
    $("k-loss").textContent = pct(worst.loss || 0);
    $("k-loss").className = "v" + ((worst.loss || 0) >= 1 ? " bad-text" : "");
    $("k-loss-s").textContent = (worst.loss || 0) > 0 ? `worst: ${worst.src} → ${worst.dst}` : `${legs.length} leg(s) clean, last 5 s`;
    const rtts = legs.map((l) => l.rtt).filter((v) => v !== null && v !== undefined);
    $("k-rtt").replaceChildren(rtts.length ? ms(rtts.reduce((a, b) => a + b, 0) / rtts.length) : "–", h("small", { text: "ms" }));
    const down = legs.filter((l) => l.down).length;
    $("k-rtt-s").textContent = down ? `${down} leg(s) interrupted right now` : "mean across legs";
  } else { $("k-loss").textContent = "–"; $("k-rtt").textContent = "–"; $("k-loss-s").textContent = "no flow reporting"; $("k-rtt-s").textContent = ""; }
}

function legRow(id, l, color) {
  const status = l.stale ? ["", "no data"] : l.down ? ["bad", "interrupted " + dur(S.now - l.down.start_ms)] : (l.loss || 0) >= 1 ? ["warn", "lossy"] : ["ok", "clean"];
  return h("tr", {}, h("td", {}, h("i", { class: "key", style: `border-color:${color}` }), legLabel(l)),
    h("td", {}, h("i", { class: "dot " + status[0] }), status[1]),
    h("td", { class: "num", text: l.stale ? "–" : pct(l.loss) }),
    h("td", { class: "num", text: l.stale ? "–" : `${pct(l.fwdLoss)} / ${pct(l.revLoss)}` }),
    h("td", { class: "num", text: l.stale ? "–" : ms(l.rtt) }), h("td", { class: "num", text: l.stale ? "–" : ms(l.rttP99) }),
    h("td", { class: "num", text: l.stale ? "–" : `${ms(l.fwdJit)} / ${ms(l.revJit)}` }),
    h("td", { class: "num", text: l.stale ? "–" : bps(l.bps) }),
    h("td", { text: l.proto.toUpperCase() + (l.proto === "tcp" && l.retx > 0 ? ` · ${l.retx} retx` : "") }));
}

function renderOverviewFlows() {
  const colors = legColors();
  const ids = Object.keys(S.legs).map(Number).sort((a, b) => a - b);
  const t1 = S.now - 1500, t0 = t1 - 300000;
  const has = ids.some((id) => (SERIES[id] || []).length);
  $("ov-empty").hidden = has; $("ov-loss").hidden = !has; $("ov-rtt").hidden = !has;
  const shown = ids.slice(0, 8), rest = ids.slice(8);
  legend($("ov-legend"), shown.map((id) => ({ color: colors[id], label: legLabel(S.legs[id]) }))
    .concat(rest.length ? [{ color: css("--s-other"), label: `${rest.length} more leg(s)` }] : []));
  if (has) {
    const windows = faultWindows(t0, t1);
    const mk = (idx) => ids.map((id) => ({ label: legLabel(S.legs[id]), color: colors[id], pts: (SERIES[id] || []).map((p) => [p[0], p[idx]]) }));
    chart($("ov-loss"), { series: mk(1), t0, t1, unit: "%", floor: 1, windows, labelWindows: true, aria: "Packet loss per leg" });
    chart($("ov-rtt"), { series: mk(4), t0, t1, unit: "ms", floor: 1, windows, aria: "Round-trip time per leg" });
  }
  const head = h("tr", {}, ...["Leg", "State", "Loss", "Fwd / return loss", "RTT ms", "p99 ms", "Jitter fwd / ret ms", "Offered", "Proto"]
    .map((t, i) => h("th", { class: i >= 2 && i <= 7 ? "num" : "", text: t })));
  $("ov-legs").replaceChildren(h("thead", {}, head), h("tbody", {}, ...ids.map((id) => legRow(id, S.legs[id], colors[id]))));
  $("ov-legs").hidden = !ids.length;
}

function renderRun() {
  const inScope = S.targets.filter((t) => !t.excluded).length;
  $("scope-chip").textContent = S.targets.length ? `scope: ${inScope} of ${S.targets.length} targets` : "scope: nothing discovered";
  const busy = S.status !== "idle";
  $("btn-run").disabled = busy; $("btn-discover").disabled = busy; $("btn-discover2").disabled = busy;
  if (!formsFilled) {
    formsFilled = true;
    const d = S.defaults;
    $("r-cycles").value = d.cycles; $("r-hold").value = d.holdMin; $("r-wait").value = S.demo ? 10 : d.wait;
    $("r-baseline").value = d.baseline; $("r-settle").value = S.demo ? 10 : d.settle;
    if (S.demo) $("r-hold").value = 12;
    $("r-faults").replaceChildren(...S.presets.map((p) => h("label", { class: "check" }, h("input", { type: "checkbox", value: p.id, checked: true }), p.label)));
    $("o-verify").checked = true;
  }
  $("events").replaceChildren(...(LOG.length ? LOG.slice(-60).reverse().map((m) =>
    h("div", { class: "event " + m.level }, h("time", { text: clock(m.t * 1000) }), h("span", { text: m.msg })))
    : [h("div", { class: "faint", text: "Nothing has happened yet." })]));
}

function renderTrials() {
  $("trials-empty").hidden = S.trials.length > 0;
  $("trials-sub").textContent = S.trials.length ? `· ${S.trials.length} most recent first` : "";
  const head = h("tr", {}, ...["#", "Time", "Target", "Fault", "Hold", "Outcome", "Recovery", "Worst interruption", "Legs hit", "Loss in fault", "RTT shift"]
    .map((t, i) => h("th", { class: i >= 4 && i !== 5 ? "num" : "", text: t })));
  $("trials-table").replaceChildren(h("thead", {}, head), h("tbody", {}, ...S.trials.map((t) =>
    h("tr", { class: "click" + (selectedTrial === t.id ? " sel" : ""), onclick: () => openTrial(t.id) },
      h("td", { class: "mono", text: t.id }), h("td", { class: "mono", text: clock(t.started) }),
      h("td", {}, t.target.name, h("span", { class: "faint", text: t.target.kind === "span" ? "" : " · " + t.target.group })),
      h("td", { text: faultText(t.fault) }), h("td", { class: "num", text: t.hold + " s" }),
      h("td", {}, h("i", { class: "dot " + (t.success ? "ok" : "bad") }), t.success ? "recovered" : "failed"),
      h("td", { class: "num", text: t.recovery === null || t.recovery === undefined ? "–" : t.recovery + " s" }),
      h("td", { class: "num" + (t.worstMs >= 1000 ? " bad-text" : ""), text: !t.legs ? "not measured" : t.worstMs ? dur(t.worstMs) : "none" }),
      h("td", { class: "num", text: t.legs ? `${t.affected} of ${t.legs}` : "–" }),
      h("td", { class: "num", text: t.legs ? pct(t.faultLoss) : "–" }),
      h("td", { class: "num", text: t.rttShiftMs === null || t.rttShiftMs === undefined ? "–" : (t.rttShiftMs >= 0 ? "+" : "") + ms(t.rttShiftMs) + " ms" })))));
  $("trials-table").hidden = !S.trials.length;
}

async function openTrial(id) {
  selectedTrial = selectedTrial === id ? null : id;
  renderTrials();
  const box = $("trial-detail");
  if (!selectedTrial) { box.hidden = true; return; }
  let t;
  try { t = await api("api/trials/" + id); } catch (e) { box.hidden = false; box.textContent = e.message; return; }
  const facts = t.facts || {};
  const phases = (t.phases || []).filter((p) => p.phase !== "verdict").map((p, i, all) => `${p.phase} ${(((all[i + 1] ? all[i + 1].at : t.ended) - p.at) / 1000).toFixed(1)} s`).join("  ›  ");
  const kv = h("dl", { class: "kv" },
    h("dt", { text: "Target" }), h("dd", { text: `${t.target.name} · ${t.target.group} · ${t.target.detail || ""}` }),
    h("dt", { text: "Fault" }), h("dd", { text: faultText(t.fault) + (t.fault.spec ? "  " + JSON.stringify(t.fault.spec) : "") }),
    h("dt", { text: "Outcome" }), h("dd", { class: t.success ? "ok-text" : "bad-text", text: t.success ? "Recovered" : "Failed: " + (t.reason || "") }),
    h("dt", { text: "Phases" }), h("dd", { class: "mono", text: phases }),
    h("dt", { text: "Control plane" }), h("dd", { class: "mono", text: Object.entries(facts).map(([k, v]) => `${k}=${v}`).join("  ") || "–" }));
  const legs = (t.impact && t.impact.legs) || [];
  const cell = (w) => (w ? [pct(w.loss), w.fwdLoss !== null && w.fwdLoss !== undefined ? h("div", { class: "faint", style: "font-size:10.5px", text: `fwd ${pct(w.fwdLoss)} · ret ${pct(w.revLoss)}` }) : null] : "–");
  const table = h("table", {}, h("thead", {}, h("tr", {}, ...["Leg", "Loss before", "Loss during fault", "Loss after", "RTT before → during → after ms", "Worst interruption", "First hit after inject", "Interruptions"]
    .map((x, i) => h("th", { class: i >= 1 ? "num" : "", text: x })))),
    h("tbody", {}, ...legs.map((l) => h("tr", {}, h("td", { style: "white-space:nowrap" }, h("i", { class: "dot " + (l.affected ? "bad" : "ok") }), legLabel(l)),
      h("td", { class: "num" }, cell(l.base)), h("td", { class: "num" }, cell(l.fault)), h("td", { class: "num" }, cell(l.after)),
      h("td", { class: "num", text: `${ms(l.base && l.base.rtt)} → ${ms(l.fault && l.fault.rtt)} → ${ms(l.after && l.after.rtt)}` }),
      h("td", { class: "num" + (l.worstMs >= 1000 ? " bad-text" : ""), text: l.worstMs ? dur(l.worstMs) : "none" }),
      h("td", { class: "num", text: l.firstHitMs === null || l.firstHitMs === undefined ? "–" : dur(Math.max(0, l.firstHitMs)) }),
      h("td", { class: "num", text: l.outages.length })))));
  box.hidden = false;
  box.replaceChildren(h("div", { class: "lbl", text: `Trial ${t.id} · cycle ${t.cycle}` }), h("div", { style: "height:10px" }), kv,
    h("div", { style: "height:14px" }),
    legs.length ? h("div", { class: "tbl-wrap" }, table) : h("p", { class: "note", text: "No endpoint flow was reporting during this trial, so its impact on traffic was not measured." }),
    legs.length ? h("p", { class: "note", style: "margin-top:10px", text: "An interruption is a run of consecutive unanswered probes; its length is accurate to one packet interval of the flow. Forward and return loss come from joining the sender's count with the reflector's for the same second." }) : null);
}

const PRESETS = { Voice: { proto: "udp", size: 200, pps: 50, dscp: 46 }, Video: { proto: "udp", size: 1200, pps: 90, dscp: 34 },
  Transactional: { proto: "tcp", size: 512, pps: 20, dscp: 18 }, Bulk: { proto: "tcp", size: 1400, pps: 400, dscp: 10 } };

function renderFlows() {
  if (!$("flow-presets").childElementCount) {
    $("flow-presets").replaceChildren(h("span", { class: "lbl", text: "Presets" }), ...Object.entries(PRESETS).map(([name, p]) =>
      h("button", { class: "btn sm", text: name, onclick: () => { $("f-proto").value = p.proto; $("f-size").value = p.size; $("f-pps").value = p.pps; $("f-dscp").value = p.dscp; if (!$("f-name").value) $("f-name").value = name; rateHint(); } })));
    ["f-size", "f-pps"].forEach((id) => $(id).addEventListener("input", rateHint)); rateHint();
  }
  const sig = S.agents.map((a) => a.id + a.name).join("|");
  if ($("f-src").dataset.sig !== sig) {
    $("f-src").dataset.sig = sig;
    const opts = () => S.agents.map((a) => h("option", { value: a.id, text: `${a.name} (${a.testAddr || "no address"})` }));
    $("f-src").replaceChildren(...opts()); $("f-dsts").replaceChildren(...opts());
  }
  $("flows-none").hidden = S.flows.length > 0;
  const names = Object.fromEntries(S.agents.map((a) => [a.id, a.name]));
  const t1 = S.now - 1500, t0 = t1 - 300000, windows = faultWindows(t0, t1);
  const c1 = css("--s1"), c2 = css("--s2");
  const cards = $("flow-cards");
  const want = S.flows.map((f) => "flow-" + f.id);
  [...cards.children].forEach((c) => { if (!want.includes(c.id)) c.remove(); });
  for (const f of S.flows) {
    let card = $("flow-" + f.id);
    if (!card) {
      card = h("div", { class: "panel", id: "flow-" + f.id }, h("div", { class: "ph" }, h("h2", {}), h("div", { class: "tools" })), h("div", { class: "pb" }));
      cards.append(card);
    }
    const shape = { ptp: "point to point", ptmp: "point to multipoint", mesh: "full mesh" }[f.topology];
    card.querySelector("h2").replaceChildren(f.name, h("span", { text: ` · ${shape} · ${f.proto.toUpperCase()} ${f.size} B × ${f.pps} pps · DSCP ${f.dscp} · port ${f.port} · ${f.legs.length} leg(s)` }));
    card.querySelector(".tools").replaceChildren(
      h("span", { class: "chip " + (f.enabled ? "ok" : ""), text: f.enabled ? "running" : "paused" }),
      h("button", { class: "btn sm", text: f.enabled ? "Pause" : "Resume", onclick: () => act("flow-msg", () => api("api/flows/" + f.id, { enabled: !f.enabled })) }),
      h("button", { class: "btn sm danger", text: "Delete", onclick: () => { if (confirm(`Delete flow "${f.name}"? Its history stays in past trials.`)) act("flow-msg", () => api("api/flows/" + f.id, null, "DELETE")); } }));
    const body = card.querySelector(".pb");
    for (const leg of f.legs) {
      let row = $("leg-" + leg.id);
      if (!row) {
        row = h("div", { id: "leg-" + leg.id }, h("div", { class: "chart-title" }, h("b", {}), h("span", {})),
          h("div", { class: "legend" }), h("div", { class: "minis" },
            ...["Loss by direction, %", "One-way delay, ms (estimate)", "Jitter by direction, ms"].map((t) => h("div", {}, h("div", { class: "lbl", text: t }), h("div", { class: "chart" })))));
        legend(row.querySelector(".legend"), [{ color: c1, label: "forward (source → destination)" }, { color: c2, label: "return" }]);
        body.append(row);
      }
      const l = S.legs[leg.id] || { stale: true };
      row.querySelector("b").textContent = `${names[leg.src] || "?"} → ${names[leg.dst] || "?"}`;
      row.querySelector(".chart-title span").textContent = l.stale ? "no data in the last few seconds"
        : `loss ${pct(l.loss)} · RTT ${ms(l.rtt)} ms (p99 ${ms(l.rttP99)}) · jitter ${ms(l.fwdJit)} / ${ms(l.revJit)} ms · ` +
          `${(l.kts & 1) ? "kernel" : "user-space"} receive stamps at the far end, ${(l.kts & 2) ? "kernel" : "user-space"} here` +
          (l.reord ? ` · ${l.reord} reordered` : "") + (l.late ? ` · ${l.late} late` : "") + (l.dup ? ` · ${l.dup} duplicate` : "");
      const pts = SERIES[leg.id] || [];
      const charts = row.querySelectorAll(".chart");
      const two = (a, b) => [{ label: "forward", color: c1, pts: pts.map((p) => [p[0], p[a]]) }, { label: "return", color: c2, pts: pts.map((p) => [p[0], p[b]]) }];
      chart(charts[0], { series: two(2, 3), t0, t1, unit: "%", floor: 1, windows, height: 120 });
      chart(charts[1], { series: two(8, 9), t0, t1, unit: "ms", floor: 1, windows, height: 120 });
      chart(charts[2], { series: two(6, 7), t0, t1, unit: "ms", floor: 0.5, windows, height: 120 });
    }
  }
}
function rateHint() {
  const b = Number($("f-size").value) * Number($("f-pps").value) * 8;
  $("f-rate-hint").textContent = b ? `${bps(b)} of payload per leg, each way unless replies are small` : "";
}

function renderEndpoints() {
  const sel = $("ctl-addr");
  const sig = S.addresses.join(",");
  if (sel.dataset.sig !== sig) {
    sel.dataset.sig = sig;
    const here = location.hostname;
    const list = [...new Set([...(["localhost", "127.0.0.1", "::1"].includes(here) ? [] : [here]), ...S.addresses])];
    sel.replaceChildren(...list.map((a) => h("option", { value: a, text: a })));
  }
  const base = `http://${sel.value || location.hostname}:${S.port}`;
  $("cmd-linux").textContent = `curl -fsSL '${base}/install.sh?token=${S.joinToken}' | sudo sh`;
  $("cmd-wget").textContent = `wget -qO- '${base}/install.sh?token=${S.joinToken}' | sudo sh`;
  $("cmd-win").textContent = `irm '${base}/install.ps1?token=${S.joinToken}' | iex`;
  $("join-token").textContent = S.joinToken;
  const missing = S.builds.filter((b) => b.size === null);
  $("builds-note").textContent = missing.length
    ? `Agent builds missing on this controller: ${missing.map((b) => `${b.os}/${b.arch}`).join(", ")}. On the controller run "python3 -m chaoslab build-agents" (needs Go once), or use a release bundle, which already contains them.`
    : `Agent ${S.agentVersion} is available for ${S.builds.map((b) => `${b.os}/${b.arch}`).join(", ")}. The address above must be reachable from the test hosts.`;
  $("builds-note").className = "note" + (missing.length ? " warn-text" : "");
  $("ep-empty").hidden = S.agents.length > 0; $("ep-table").hidden = !S.agents.length;
  $("ep-sub").textContent = S.agents.length ? `· ${S.agents.filter((a) => a.online).length} online` : "";
  const head = h("tr", {}, ...["Endpoint", "State", "System", "Agent", "Test address", "Receive stamps", "Clock vs controller", "Notes", ""].map((t) => h("th", { text: t })));
  $("ep-table").replaceChildren(h("thead", {}, head), h("tbody", {}, ...S.agents.map((a) => {
    const notes = [...a.problems, ...Object.entries(a.legProblems || {}).filter(([, v]) => v).map(([k, v]) => `leg ${k}: ${v}`)];
    if (a.noDscp && a.noDscp.length) notes.push("DSCP marking not confirmed by the OS (on Windows it needs a QoS policy)");
    if (a.addrs.length > 1 && !a.pinned) notes.push("several addresses: confirm the test address");
    if (a.orphaned) notes.push("stopped sending after losing the controller for 15 minutes");
    if (a.backlog > 50) notes.push(`${a.backlog} results queued`);
    const addrSel = h("select", { class: "in sm", onchange: (e) => act("ep-msg", () => api("api/agents/" + a.id, { testAddr: e.target.value }), "Test address updated") },
      ...[...new Set([a.testAddr, ...a.addrs].filter(Boolean))].map((x) => h("option", { value: x, text: x, selected: x === a.testAddr })));
    return h("tr", {}, h("td", {}, h("b", { style: "font-weight:500", text: a.name }), a.hostname && a.hostname !== a.name ? h("span", { class: "faint", text: " · " + a.hostname }) : null),
      h("td", {}, h("i", { class: "dot " + (a.online ? "ok" : "bad") }), a.online ? "online" : "offline · " + ago(S.now / 1000 - a.lastSeen)),
      h("td", { text: `${a.os}/${a.arch}` }),
      h("td", { class: a.version !== S.agentVersion && a.version !== "sim" ? "warn-text" : "", text: a.version || "?" }),
      h("td", {}, addrSel), h("td", { text: a.kernelTs ? "kernel" : "user space" }),
      h("td", { class: "mono", text: `${a.offsetMs >= 0 ? "+" : ""}${a.offsetMs} ms` }),
      h("td", { class: notes.length ? "warn-text" : "faint", text: notes.join("; ") || "–" }),
      h("td", {}, h("button", { class: "btn sm", text: "Rename", onclick: () => { const n = prompt("Name for this endpoint", a.name); if (n) act("ep-msg", () => api("api/agents/" + a.id, { name: n })); } }), " ",
        h("button", { class: "btn sm danger", text: "Remove", onclick: () => { if (confirm(`Remove ${a.name}? Uninstall the agent on the host as well, or it will enrol again.`)) act("ep-msg", () => api("api/agents/" + a.id, null, "DELETE")); } })));
  })));
}

function renderTargets() {
  $("targets-empty").hidden = S.targets.length > 0; $("targets-table").hidden = !S.targets.length;
  const inScope = S.targets.filter((t) => !t.excluded).length;
  $("targets-sub").textContent = S.targets.length ? `· ${inScope} of ${S.targets.length} in scope · discovered ${ago(S.now / 1000 - S.discoveredAt)}` : "";
  if (document.activeElement && document.activeElement.closest("#targets-table")) return;   // do not rebuild under an open select
  const last = {};
  for (const t of [...S.trials].reverse()) last[t.target.key] = t;
  const busy = S.status !== "idle";
  const rows = [];
  let group = null;
  const labels = Object.fromEntries(S.drivers.map((d) => [d.driver, d.label]));
  for (const t of [...S.targets].sort((a, b) => (a.driver + a.group + a.kind + a.name).localeCompare(b.driver + b.group + b.kind + b.name))) {
    const g = `${labels[t.driver] || t.driver} · ${t.group}`;
    if (g !== group) { group = g; rows.push(h("tr", { class: "group" }, h("td", { colspan: 6, text: g }))); }
    const lt = last[t.key];
    let faultSel = null, dirSel = null;
    if (t.kind === "span") {
      const legacy = t.meta && t.meta.legacy;
      faultSel = h("select", { class: "in sm" }, ...S.presets.filter((p) => !(legacy && p.kind === "down")).map((p) => h("option", { value: p.id, text: p.label })));
      dirSel = h("select", { class: "in sm" }, ...(legacy ? [["down", "toward the site"]] : [["down", "toward the site"], ["up", "away from the site"], ["both", "both"]]).map(([v, x]) => h("option", { value: v, text: x })));
    }
    rows.push(h("tr", {},
      h("td", {}, h("input", { type: "checkbox", checked: !t.excluded, disabled: busy, title: "In scope for runs", onchange: () => toggleScope(t.key) })),
      h("td", {}, t.name, h("div", { class: "faint mono", style: "font-size:11px", text: t.detail })),
      h("td", {}, h("span", { class: "chip " + ({ wan: "info", vrrp: "warn", span: "" }[t.kind]), text: KIND[t.kind] })),
      h("td", {}, lt ? [h("i", { class: "dot " + (lt.success ? "ok" : "bad") }), lt.success ? "recovered" : "failed", h("span", { class: "faint", text: lt.legs ? ` · ${lt.worstMs ? dur(lt.worstMs) : "no"} interruption` : "" })] : h("span", { class: "faint", text: "not tested" })),
      h("td", {}, faultSel, faultSel ? " " : null, dirSel),
      h("td", {}, h("button", { class: "btn sm", text: "Test", disabled: busy, onclick: () => startTest(t, faultSel && faultSel.value, dirSel && dirSel.value) }))));
  }
  const head = h("tr", {}, ...["Scope", "Target", "Kind", "Last trial", "Fault for a single test", ""].map((x) => h("th", { text: x })));
  $("targets-table").replaceChildren(h("thead", {}, head), h("tbody", {}, ...rows));
}
function toggleScope(key) {
  const excluded = S.targets.filter((t) => (t.key === key ? !t.excluded : t.excluded)).map((t) => t.key);
  act("targets-msg", () => api("api/scope", { excluded }));
}

function renderEvidence() {
  const head = h("tr", {}, ...["Time", "Action", "Target", "Where", "Result", "Detail"].map((x) => h("th", { text: x })));
  api("api/audit").then((d) => {
    $("audit-table").replaceChildren(h("thead", {}, head), h("tbody", {}, ...d.audit.map((a) =>
      h("tr", {}, h("td", { class: "mono", text: new Date(a.ts * 1000).toISOString().slice(0, 19).replace("T", " ") }), h("td", { class: "mono", text: a.action }),
        h("td", { text: a.target || "–" }), h("td", { text: a.scope || "–" }),
        h("td", { class: a.result === "FAILED" ? "bad-text" : a.result === "PENDING" ? "warn-text" : "", text: a.result }), h("td", { class: "muted", text: a.detail || "" })))));
  }).catch(() => {});
}

function renderSettings() {
  $("held-list").replaceChildren(...(S.held.length ? S.held.map((x) => h("div", {}, h("i", { class: "dot bad" }), `${x.what} (${x.how})`))
    : ["Nothing is being held broken by this controller."]));
  $("btn-restore").disabled = S.status !== "idle";
  const by = Object.fromEntries(S.drivers.map((d) => [d.driver, d]));
  const chip = (id, d) => { $(id).textContent = d ? (d.lastError ? "error" : "connected") : "not connected"; $(id).className = "chip " + (d ? (d.lastError ? "hot" : "ok") : ""); };
  chip("orch-chip", by.orchestrator); chip("prime-chip", by.autopod);
  if (by.orchestrator && !$("o-url").value && document.activeElement !== $("o-url")) $("o-url").value = by.orchestrator.url;
  if (by.autopod && !$("p-url").value && document.activeElement !== $("p-url")) { $("p-url").value = by.autopod.url; $("p-lab").value = by.autopod.lab; }
  const rows = [["Version", `controller ${S.version}, agent ${S.agentVersion}`], ["Mode", S.demo ? "simulated lab (--demo)" : "live"],
    ["Dashboard access", S.open ? "open to anyone who can reach this port (set CHAOSLAB_PASSWORD to require a password)" : "password required"],
    ["Listening on", S.addresses.map((a) => `${a}:${S.port}`).join(", ") || `port ${S.port}`]];
  for (const d of S.drivers) rows.push([d.label, [d.url, d.lab, d.auth, d.mode, d.lastError ? "last error: " + d.lastError : ""].filter(Boolean).join(" · ")]);
  $("about").replaceChildren(...rows.flatMap(([k, v]) => [h("dt", { text: k }), h("dd", { text: v })]));
}

function render() {
  if (!S) return;
  renderTop();
  const tab = activeTab();
  if (tab === "overview") { renderTodo(); renderTrialCard(); renderKpis(); renderOverviewFlows(); renderRun(); }
  else if (tab === "trials") renderTrials();
  else if (tab === "flows") renderFlows();
  else if (tab === "endpoints") renderEndpoints();
  else if (tab === "targets") renderTargets();
  else if (tab === "settings") renderSettings();
}

/* ---------- actions ---------- */

const checked = (id) => [...$(id).querySelectorAll("input:checked")].map((i) => i.value);
const numOrNull = (id) => ($(id).value === "" ? null : Number($(id).value));
function runParams() {
  return { cycles: numOrNull("r-cycles"), holdMin: numOrNull("r-hold"), holdMax: numOrNull("r-holdmax"), wait: numOrNull("r-wait"),
    baseline: numOrNull("r-baseline"), settle: numOrNull("r-settle"), selection: $("r-selection").value, seed: numOrNull("r-seed"),
    kinds: checked("r-kinds"), faults: checked("r-faults"), directions: checked("r-dirs") };
}
function confirmLive(title, text, items, go) {
  if (S.demo) { go({}); return; }
  $("confirm-title").textContent = title; $("confirm-text").textContent = text;
  $("confirm-list").replaceChildren(...items.map((i) => h("li", { text: i })));
  $("confirm-ack").checked = false; $("confirm-go").disabled = true;
  pendingAction = go; $("confirm").showModal();
}
$("confirm-ack").addEventListener("change", (e) => { $("confirm-go").disabled = !e.target.checked; });
$("confirm-cancel").addEventListener("click", () => $("confirm").close());
$("confirm-go").addEventListener("click", () => { $("confirm").close(); if (pendingAction) pendingAction({ acknowledge: true }); pendingAction = null; });

$("btn-run").addEventListener("click", () => {
  const p = runParams();
  const pool = S.targets.filter((t) => !t.excluded && p.kinds.includes(t.kind));
  const by = {}; for (const t of pool) by[t.group] = (by[t.group] || 0) + 1;
  confirmLive("Start this run?", `${p.cycles || "Unlimited"} cycle(s), ${p.holdMin}${p.holdMax ? "–" + p.holdMax : ""} s hold. One target at a time is broken, held, and restored.` +
    (S.targets.length ? "" : " Targets have not been discovered yet: the run discovers first and then uses EVERYTHING it finds."),
    S.targets.length ? [`${pool.length} target(s) in scope on: ${Object.keys(by).join(", ") || "nothing"}`, ...S.drivers.map((d) => `${d.label}: ${d.url || ""} ${d.lab || ""}`)] : S.drivers.map((d) => `${d.label}: ${d.url || ""} ${d.lab || ""}`),
    (ack) => act("run-msg", () => api("api/run", { ...p, ...ack }), "Run started"));
});
function startTest(t, fault, direction) {
  const p = runParams();
  confirmLive("Break this one target now?", `${fault ? S.presets.find((x) => x.id === fault).label : "Admin down"} for ${p.holdMin} s, then restore.`,
    [`${t.name} · ${t.group}`, t.detail], (ack) => act("targets-msg", () => api("api/test", { ...p, key: t.key, fault, direction, ...ack }), "Test started").then((ok) => ok && show("overview")));
}
$("btn-stop").addEventListener("click", () => act("run-msg", () => api("api/stop", {}), "Stopping"));
$("btn-skip").addEventListener("click", () => act("run-msg", () => api("api/skip", {})));
$("btn-discover").addEventListener("click", () => act("run-msg", () => api("api/discover", {}), "Discovering"));
$("btn-discover2").addEventListener("click", () => act("targets-msg", () => api("api/discover", {}), "Discovering"));
$("scope-all").addEventListener("click", () => act("targets-msg", () => api("api/scope", { excluded: [] })));
$("scope-none").addEventListener("click", () => act("targets-msg", () => api("api/scope", { excluded: S.targets.map((t) => t.key) })));
$("btn-restore").addEventListener("click", () => act("held-msg", async () => {
  const out = await api("api/restore", {});
  if (out.errors && out.errors.length) throw new Error("Could not restore: " + out.errors.join("; "));
  return out;
}, "Restore requested"));
$("btn-flow").addEventListener("click", () => act("flow-msg", () => api("api/flows", {
  name: $("f-name").value, topology: $("f-topology").value, proto: $("f-proto").value, src: $("f-src").value,
  dsts: [...$("f-dsts").selectedOptions].map((o) => o.value), size: Number($("f-size").value), pps: Number($("f-pps").value),
  dscp: Number($("f-dscp").value), port: Number($("f-port").value), timeoutMs: Number($("f-timeout").value),
  minEcho: $("f-minecho").checked, allowFragments: $("f-jumbo").checked }), "Flow created").then((ok) => { if (ok) $("f-name").value = ""; }));
$("btn-rotate").addEventListener("click", () => { if (confirm("Issue a new join token? Enrolled endpoints keep working; install commands copied earlier stop working.")) act("ep-msg", () => api("api/token/rotate", {}), "New token issued"); });
$("ctl-addr").addEventListener("change", renderEndpoints);
$("btn-orch").addEventListener("click", () => act("orch-msg", () => api("api/connections/orchestrator", {
  url: $("o-url").value, token: $("o-token").value, username: $("o-user").value, password: $("o-pass").value,
  verifyTls: $("o-verify").checked, queryAuth: $("o-query").checked })).then((ok) => { if (ok) { $("o-token").value = ""; $("o-pass").value = ""; } }));
$("btn-orch-off").addEventListener("click", () => act("orch-msg", () => api("api/connections/orchestrator", { disconnect: true })));
$("btn-prime").addEventListener("click", () => act("prime-msg", () => api("api/connections/autopod", {
  url: $("p-url").value, lab: $("p-lab").value, username: $("p-user").value, password: $("p-pass").value, token: $("p-token").value }))
  .then((ok) => { if (ok) { $("p-pass").value = ""; $("p-token").value = ""; } }));
$("btn-prime-off").addEventListener("click", () => act("prime-msg", () => api("api/connections/autopod", { disconnect: true })));
$("login-go").addEventListener("click", async () => {
  try { await api("api/login", { password: $("login-pass").value }); $("login").close(); refresh(); }
  catch (e) { $("login-msg").textContent = e.message; }
});

/* ---------- polling ---------- */

let busy = false;
async function refresh() {
  if (busy) return;
  busy = true;
  try {
    const tab = activeTab();
    const wantSeries = tab === "overview" || tab === "flows";
    const [state, series] = await Promise.all([api("api/state?log=" + logAfter), wantSeries ? api("api/series?window=320") : null]);
    S = state;
    if (series) SERIES = series.series;
    for (const m of S.log) { LOG.push(m); logAfter = Math.max(logAfter, m.n); }
    if (LOG.length > 400) LOG.splice(0, LOG.length - 400);
    $("banner-offline").hidden = true; $("pill-live").className = "pill ok"; $("pill-live").textContent = "Live";
    render();
    if (tab === "evidence") renderEvidence();
  } catch (e) {
    if (e.message !== "Sign in first.") { $("banner-offline").hidden = false; $("pill-live").className = "pill bad"; $("pill-live").textContent = "Offline"; }
  } finally { busy = false; }
}
const fromHash = () => { const t = (location.hash || "#overview").slice(1).replace(/[^a-z]/g, ""); return $("tab-" + t) ? t : "overview"; };
addEventListener("hashchange", () => { if (fromHash() !== activeTab()) show(fromHash()); });
show(fromHash());
refresh();
setInterval(refresh, 1000);
addEventListener("resize", render);
