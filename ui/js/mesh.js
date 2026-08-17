(function () {
  const $ = (id) => document.getElementById(id);
  const state = { peer: null, viewSeconds: 300, refreshMs: 500 };

  function scoreClass(score) {
    if (score == null) return "idle";
    if (score >= 80) return "ok";
    if (score >= 50) return "mid";
    return "bad";
  }

  async function api(path, opts) {
    const r = await fetch(path, opts);
    if (!r.ok) throw new Error(await r.text());
    const ct = r.headers.get("content-type") || "";
    return ct.includes("json") ? r.json() : r.text();
  }

  function renderMeter(mesh) {
    const w = mesh.worst;
    const score = w && w.score != null ? w.score : null;
    const el = $("scoreNum");
    el.textContent = score == null ? "—" : Math.round(score);
    el.className = "meter-score " + scoreClass(score);
    $("scoreLabel").textContent = w ? w.label : "Waiting for peers";
    $("scoreDetail").textContent = w
      ? `worst pair · peer ${w.peer}`
      : `${mesh.peers.length} peers configured`;
    const fill = $("scoreFill");
    fill.style.width = (score == null ? 0 : Math.max(0, Math.min(100, score))) + "%";
    fill.style.background = score == null ? "var(--stroke-hi)"
      : score >= 80 ? "var(--accent)" : score >= 50 ? "var(--warn)" : "var(--danger)";
    $("peerSub").textContent = `${mesh.peers.length} peers · selected ${state.peer || "—"}`;
    $("streamPill").textContent = `${mesh.peers.length} peers`;
    $("selPeer").textContent = state.peer || "—";
    $("pairsUp").textContent = `${mesh.pairs_up}/${mesh.peers.length}`;
  }

  function renderPairs(mesh) {
    const tb = $("pairsTable").querySelector("tbody");
    tb.innerHTML = "";
    for (const row of mesh.rows) {
      const tr = document.createElement("tr");
      if (row.peer === state.peer) tr.style.background = "rgba(1,169,130,0.10)";
      if (!row.up) tr.className = "bad";
      tr.innerHTML = `<td><input type="radio" name="pair" value="${row.peer}" ${row.peer === state.peer ? "checked" : ""}></td>
        <td>${row.peer}</td>
        <td>${row.links_up}/${row.stream_count}</td>
        <td>${row.score == null ? "—" : Math.round(row.score)}</td>
        <td>${row.label}</td>
        <td>${row.rtt == null ? "—" : Number(row.rtt).toFixed(1)}</td>
        <td>${Number(row.loss_pct).toFixed(2)}</td>
        <td>${row.jitter == null ? "—" : Number(row.jitter).toFixed(1)}</td>`;
      tr.onclick = () => {
        state.peer = row.peer;
        api("/api/mesh/select", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ peer: row.peer }),
        }).then(tick).catch(console.warn);
      };
      tb.appendChild(tr);
    }
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
      now, viewSeconds: state.viewSeconds, key: "v", yminFloor: 2, unit: "",
      series: [
        { id: "F", label: "fwd→", color: "#1ec9a0" },
        { id: "R", label: "rtn←", color: "#e6a23c" },
      ],
      samples: { F: payload.owd_f, R: payload.owd_r },
      markers: payload.markers,
    });
  }

  function renderFooter(snap) {
    if (!snap) return;
    const t = snap.totals;
    $("footPath").textContent =
      `selected ${snap.peer} · ${snap.ports} · offered ${snap.offered_mbps.toFixed(2)} Mbps`;
    $("footCnt").textContent =
      `since reset sent ${t.tx.toLocaleString()} lost ${t.lost.toLocaleString()} (${t.loss_pct.toFixed(2)}%)`;
  }

  async function tick() {
    try {
      const q = state.peer ? `?peer=${encodeURIComponent(state.peer)}` : "";
      const payload = await api("/api/mesh/snapshot" + q);
      state.viewSeconds = payload.view_seconds || state.viewSeconds;
      if (!state.peer && payload.mesh.peers.length) {
        state.peer = (payload.mesh.worst && payload.mesh.worst.peer)
          || payload.mesh.peers[0];
      }
      renderMeter(payload.mesh);
      renderPairs(payload.mesh);
      renderCharts(payload);
      renderFooter(payload.snap);
      $("versionTag").textContent = "v" + (payload.version || "");
    } catch (e) {
      console.warn(e);
    }
  }

  $("btnReset").onclick = () => api("/api/reset", { method: "POST" }).catch(alert);
  $("btnReport").onclick = async () => {
    try {
      const res = await api("/api/report", { method: "POST" });
      alert("Report written:\n" + (res.html || ""));
    } catch (e) { alert(String(e.message || e)); }
  };
  $("btnUpdate").onclick = async () => {
    try {
      const res = await api("/api/update/check");
      if (!res.available) { alert(res.message || "Already up to date."); return; }
      if (!confirm("Update to v" + res.version + "?")) return;
      await api("/api/update/apply", { method: "POST" });
    } catch (e) { alert(String(e.message || e)); }
  };

  tick();
  setInterval(tick, state.refreshMs);
  window.addEventListener("resize", () => tick());
})();
