(function () {
  const $ = (id) => document.getElementById(id);
  const state = {
    panels: {},
    series: [],
    viewSeconds: 300,
    refreshMs: 500,
    loadRunning: false,
    path: "private",   // "private" (fabric peer) | "public" (breakout/SSE)
    hasPublic: false,
  };

  const PATH_ROLE = {
    private: "Private · SD-WAN fabric",
    public: "Public · breakout / SSE",
  };

  function scoreClass(score) {
    if (score == null) return "idle";
    if (score >= 80) return "ok";
    if (score >= 50) return "mid";
    return "bad";
  }

  function fmt(n, digits) {
    if (n == null || Number.isNaN(n)) return "—";
    return Number(n).toFixed(digits);
  }

  async function api(path, opts) {
    const r = await fetch(path, opts);
    if (!r.ok) {
      const t = await r.text();
      throw new Error(t || r.statusText);
    }
    const ct = r.headers.get("content-type") || "";
    if (ct.includes("application/json")) return r.json();
    return r.text();
  }

  function setPanel(name, on) {
    state.panels[name] = on;
    const el = $("panel-" + name);
    if (el) el.classList.toggle("open", !!on);
    document.querySelectorAll("#toolsMenu [data-panel]").forEach((btn) => {
      btn.classList.toggle("on", !!state.panels[btn.dataset.panel]);
    });
  }

  function wireChrome() {
    $("btnReset").onclick = () => api("/api/reset", { method: "POST" }).catch(alert);
    $("btnReport").onclick = async () => {
      try {
        const res = await api("/api/report", { method: "POST" });
        alert("Report written:\n" + (res.html || res.path || JSON.stringify(res)));
      } catch (e) { alert(String(e.message || e)); }
    };
    $("btnTools").onclick = (e) => {
      e.stopPropagation();
      $("toolsMenu").classList.toggle("open");
    };
    document.addEventListener("click", () => $("toolsMenu").classList.remove("open"));
    $("toolsMenu").addEventListener("click", (e) => e.stopPropagation());

    document.querySelectorAll("#toolsMenu [data-panel]").forEach((btn) => {
      btn.onclick = () => {
        const name = btn.dataset.panel;
        setPanel(name, !state.panels[name]);
      };
    });
    document.querySelector('[data-action="fit"]').onclick = () => {
      Object.keys(state.panels).forEach((k) => setPanel(k, false));
      window.dispatchEvent(new Event("resize"));
    };
    document.querySelector('[data-action="update"]').onclick = async () => {
      try {
        const res = await api("/api/update/check");
        if (!res.available) {
          alert(res.message || "Already up to date.");
          return;
        }
        if (!confirm("Update to v" + res.version + "?\nThe app will relaunch.")) return;
        await api("/api/update/apply", { method: "POST" });
        alert("Update installed — relaunching…");
      } catch (e) { alert(String(e.message || e)); }
    };

    $("btnLoad").onclick = async () => {
      try {
        if (state.loadRunning) {
          await api("/api/load/stop", { method: "POST" });
          state.loadRunning = false;
          $("btnLoad").textContent = "Start load";
          $("loadStatus").textContent = "stopped";
          return;
        }
        const body = {
          mbps: Number($("loadMbps").value),
          square: $("loadSquare").checked,
          on_s: Number($("loadOn").value),
          off_s: Number($("loadOff").value),
          target: state.hasPublic ? $("loadTarget").value : "private",
        };
        const res = await api("/api/load/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
        if (res.error) { $("loadStatus").textContent = res.error; return; }
        state.loadRunning = true;
        $("btnLoad").textContent = "Stop load";
        $("loadStatus").textContent = "running";
      } catch (e) { $("loadStatus").textContent = String(e.message || e); }
    };
  }

  function renderMeter(snap, paths) {
    const up = snap.links_up > 0;
    const score = up ? snap.overall : null;
    const isPublic = snap.role === "public";
    const el = $("scoreNum");
    el.textContent = score == null ? "—" : Math.round(score);
    el.className = "meter-score " + scoreClass(score);
    $("meterBand").querySelector(".meter-label").textContent = paths
      ? `Experience · ${isPublic ? "public path" : "private path"}` : "Experience";
    $("scoreLabel").textContent = up ? snap.overall_label
      : (isPublic ? "Waiting for public endpoint" : "Waiting for peer");
    const egress = isPublic && snap.egress && snap.egress.length
      ? ` · egress ${snap.egress.join(", ")}` : "";
    $("scoreDetail").textContent = up
      ? `worst ${Math.round(snap.worst)} · ${snap.links_up}/${snap.stream_count} streams up${egress}`
      : `${isPublic ? "public endpoint" : "peer"} ${snap.peer} — no streams up yet`;
    const fill = $("scoreFill");
    fill.style.width = (score == null ? 0 : Math.max(0, Math.min(100, score))) + "%";
    fill.style.background = score == null ? "var(--stroke-hi)"
      : score >= 80 ? "var(--accent)" : score >= 50 ? "var(--warn)" : "var(--danger)";
    $("mosVal").textContent = snap.udp_mos == null ? "—" : Number(snap.udp_mos).toFixed(1);
    $("pqiVal").textContent = snap.tcp_pqi == null ? "—" : Math.round(snap.tcp_pqi);
    $("peerSub").textContent = paths
      ? `private ${paths[0].peer} · public ${paths[1].peer}`
      : `peer ${snap.peer} · ${snap.links_up}/${snap.stream_count} streams up`;
    const pill = $("streamPill");
    pill.textContent = `${snap.links_up}/${snap.stream_count} up`;
    pill.className = "pill " + (snap.links_up ? "on" : "");
  }

  function pathMeta(p) {
    if (!p.up) return `${p.peer} · no echoes yet`;
    const rtt = p.rtt == null ? "—" : Number(p.rtt).toFixed(1);
    let meta = `${p.peer} · RTT ${rtt} ms · loss ${Number(p.loss_pct).toFixed(2)}%`;
    if (p.role === "public" && p.egress && p.egress.length) {
      meta += ` · egress ${p.egress.join(", ")}`;
    }
    return meta;
  }

  function renderPaths(paths) {
    const box = $("paths");
    state.hasPublic = !!paths;
    if (!paths) { box.hidden = true; return; }
    box.hidden = false;
    if (!box.children.length) {
      for (const p of paths) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "path";
        btn.dataset.path = p.role;
        btn.innerHTML = '<span class="path-role"></span><b class="path-score"></b>'
          + '<span class="path-meta"></span>';
        btn.querySelector(".path-role").textContent = PATH_ROLE[p.role] || p.role;
        btn.onclick = () => {
          if (state.path === p.role) return;
          state.path = p.role;
          // Load follows the path on screen unless a run is already going.
          if (!state.loadRunning) $("loadTarget").value = p.role;
          tick();
        };
        box.appendChild(btn);
      }
    }
    for (const p of paths) {
      const btn = box.querySelector(`[data-path="${p.role}"]`);
      if (!btn) continue;
      btn.setAttribute("aria-pressed", String(state.path === p.role));
      const sc = btn.querySelector(".path-score");
      sc.textContent = p.score == null ? "—" : Math.round(p.score);
      sc.className = "path-score " + scoreClass(p.score);
      btn.querySelector(".path-meta").textContent = pathMeta(p);
      btn.title = `${PATH_ROLE[p.role] || p.role}: ${p.label}`;
    }
  }

  function renderWarn(snap) {
    const rail = $("warnRail");
    const msg = snap.warning || "";
    if (!msg) { rail.className = "warn-rail"; rail.textContent = ""; return; }
    rail.textContent = msg;
    rail.className = "warn-rail show" + (snap.warning_level === "bad" ? " bad" : "");
  }

  function dscpCell(row) {
    if (row.dscp_req == null && row.fwd_tos == null) return "—";
    const f = row.fwd_tos != null ? (row.fwd_tos >> 2) : "?";
    const r = row.rtn_tos != null ? (row.rtn_tos >> 2) : "?";
    return `${row.dscp_name || row.dscp_req}→${f}/${r}`;
  }

  function renderTables(snap) {
    const tb = $("totalsTable").querySelector("tbody");
    tb.innerHTML = "";
    for (const row of snap.rows) {
      const decided = row.cum_recv + row.cum_lost + row.cum_late;
      const lossp = decided ? (row.cum_lost / decided * 100) : 0;
      const tr = document.createElement("tr");
      if (row.size_mismatch) tr.className = "bad";
      tr.innerHTML = `<td>${row.name}</td><td>${row.cum_tx.toLocaleString()}</td>
        <td>${row.cum_recv.toLocaleString()}</td><td>${row.cum_lost.toLocaleString()}</td>
        <td>${row.cum_late.toLocaleString()}</td><td>${lossp.toFixed(2)}</td>
        <td>${row.size_mismatch ? "MISMATCH" : row.expect_size}</td><td>${dscpCell(row)}</td>`;
      tb.appendChild(tr);
    }
    const ib = $("isoTable").querySelector("tbody");
    ib.innerHTML = "";
    for (const row of snap.rows) {
      const tr = document.createElement("tr");
      if (row.where_tag === "bad") tr.className = "bad";
      else if (row.where_tag === "warn") tr.className = "warn";
      tr.innerHTML = `<td>${row.name}</td><td>${row.cum_tx.toLocaleString()}</td>
        <td>${row.fwd_lost.toLocaleString()}</td><td>${Number(row.fwd_pct).toFixed(2)}</td>
        <td>${row.rtn_lost.toLocaleString()}</td><td>${Number(row.rtn_pct).toFixed(2)}</td>
        <td>${row.where || "…"}</td>`;
      ib.appendChild(tr);
    }
  }

  function renderFooter(snap) {
    const t = snap.totals;
    let load = ` · probe load ${snap.offered_mbps.toFixed(2)} Mbps`;
    if (snap.target_mbps) load += ` / target ${snap.target_mbps}`;
    const vx = snap.vxlan ? ` · VXLAN vni ${snap.vxlan.vni} udp/${snap.vxlan.port}` : "";
    const who = snap.role === "public" ? "public" : "peer";
    $("footPath").textContent =
      `${who} ${snap.peer} · ${snap.ports} · frame ${snap.frame_size} B DF ${snap.dont_fragment ? "on" : "off"} · size ${snap.size_status}${vx}${load}`;
    $("footCnt").textContent =
      `since reset  sent ${t.tx.toLocaleString()}  lost ${t.lost.toLocaleString()} (${t.loss_pct.toFixed(2)}%)  late ${t.late.toLocaleString()} (${t.late_pct.toFixed(2)}%)   ·   lifetime  sent ${t.life_tx.toLocaleString()}  lost ${t.life_lost.toLocaleString()} (${t.life_loss_pct.toFixed(2)}%)`;
  }

  function renderAnatomy(snap) {
    if (!state.panels.anatomy) return;
    const a = snap.anatomy;
    if (!a) return;
    $("anatBody").innerHTML =
      `<p><b>LAN</b> 1 packet · ${a.inner.toLocaleString()} B · ${a.parts} · DF ${a.df}</p>
       <p style="color:var(--accent-hi)">${a.verb}</p>
       <p><b>WAN</b> ${a.n} packet${a.n === 1 ? "" : "s"} · ${a.wan_total.toLocaleString()} B · +${a.tax.toFixed(1)}% overhead · ×${a.n} amplification</p>
       <p style="color:var(--txt-dim)">${a.predict}</p>
       <p style="color:var(--txt-faint)">${a.noec}</p>
       ${a.wan_line ? `<p style="color:var(--txt-faint)">${a.wan_line}</p>` : ""}`;
    if (a.note) {
      const note = document.createElement("p");
      note.style.color = "var(--warn)";
      note.textContent = a.note;
      $("anatBody").prepend(note);
    }
  }

  function renderTopo(snap) {
    if (!state.panels.topology) return;
    const t = snap.topology;
    if (!t) return;
    $("topoBody").innerHTML =
      `<p style="font-variant-numeric:tabular-nums">${t.summary}</p>
       <p style="color:var(--txt-dim)">${t.detail || ""}</p>`;
  }

  function ensureLegend(series) {
    const leg = $("legLat");
    if (leg.dataset.ready === "1") return;
    leg.innerHTML = series.map((s) =>
      `<span><i style="background:${s.color}"></i>${s.label}</span>`).join("");
    leg.dataset.ready = "1";
  }

  function renderCharts(payload) {
    const now = payload.now;
    const series = payload.series;
    ensureLegend(series);
    const common = {
      now, viewSeconds: state.viewSeconds, series, samples: payload.history,
      markers: payload.markers,
    };
    NVCharts.drawChart($("cLat"), { ...common, key: "rtt", yminFloor: 2, band: payload.band, unit: "" });
    NVCharts.drawChart($("cLoss"), { ...common, key: "loss", yminFloor: 2, unit: "%" });
    NVCharts.drawChart($("cJit"), { ...common, key: "jitter", yminFloor: 1, unit: "" });
    NVCharts.drawChart($("cOwd"), {
      now, viewSeconds: state.viewSeconds,
      key: "v", yminFloor: 2, unit: "",
      series: [
        { id: "F", label: "fwd→", color: "#1ec9a0" },
        { id: "R", label: "rtn←", color: "#e6a23c" },
      ],
      samples: { F: payload.owd_f, R: payload.owd_r },
      markers: payload.markers,
    });
  }

  async function tick() {
    try {
      const q = state.path === "public" ? "?path=public" : "";
      const payload = await api("/api/snapshot" + q);
      state.viewSeconds = payload.view_seconds || state.viewSeconds;
      state.series = payload.series || [];
      if (!payload.paths) state.path = "private";
      renderPaths(payload.paths);
      renderMeter(payload.snap, payload.paths);
      renderWarn(payload.snap);
      renderTables(payload.snap);
      renderFooter(payload.snap);
      renderAnatomy(payload.snap);
      renderTopo(payload.snap);
      renderCharts(payload);
      if (payload.load) {
        $("loadTargetWrap").hidden = !payload.load.public;
        if (payload.load.running) $("loadTarget").value = payload.load.target;
        $("loadTarget").disabled = !!payload.load.running;
        state.loadRunning = !!payload.load.running;
        $("btnLoad").textContent = state.loadRunning ? "Stop load" : "Start load";
        if (payload.load.status) $("loadStatus").textContent = payload.load.status;
        if (payload.load.disabled) {
          $("btnLoad").disabled = true;
          $("loadStatus").textContent = payload.load.status || "unavailable";
        }
      }
      $("versionTag").textContent = "v" + (payload.version || "");
    } catch (e) {
      console.warn(e);
    }
  }

  wireChrome();
  tick();
  setInterval(tick, state.refreshMs);
  window.addEventListener("resize", () => tick());
})();
