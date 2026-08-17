/* Chart helpers — graticule-style canvas plots for Network Vitals */
(function (global) {
  const COLORS = ["#4db6a0", "#6a9fbf", "#c4a35a", "#b07a8c"];

  function cssVar(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  }

  function niceCeil(v) {
    if (!(v > 0)) return 1;
    const exp = Math.floor(Math.log10(v));
    const f = v / Math.pow(10, exp);
    const nf = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
    return nf * Math.pow(10, exp);
  }

  function drawChart(canvas, opts) {
    const dpr = window.devicePixelRatio || 1;
    const cssW = canvas.clientWidth || 300;
    const cssH = canvas.clientHeight || 120;
    if (canvas.width !== Math.floor(cssW * dpr) || canvas.height !== Math.floor(cssH * dpr)) {
      canvas.width = Math.floor(cssW * dpr);
      canvas.height = Math.floor(cssH * dpr);
    }
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssW, cssH);

    const pad = { l: 36, r: 10, t: 8, b: 18 };
    const pw = Math.max(10, cssW - pad.l - pad.r);
    const ph = Math.max(10, cssH - pad.t - pad.b);
    const now = opts.now;
    const span = opts.viewSeconds || 300;
    const t0 = now - span;
    const key = opts.key;
    const series = opts.series || [];
    const samples = opts.samples || {};
    const band = opts.band || null;

    let ymax = opts.yminFloor || 1;
    for (const s of series) {
      for (const pt of samples[s.id] || []) {
        const v = pt[key];
        if (v != null && v > ymax) ymax = v;
      }
    }
    if (band) {
      for (const pt of band) {
        if (pt.hi != null && pt.hi > ymax) ymax = pt.hi;
      }
    }
    ymax = niceCeil(ymax);

    const stroke = cssVar("--stroke", "#2a3545");
    const faint = cssVar("--txt-faint", "#5c6b7d");
    const well = cssVar("--bg", "#0d1218");

    ctx.fillStyle = well;
    ctx.fillRect(pad.l, pad.t, pw, ph);

    ctx.strokeStyle = stroke;
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (let i = 0; i <= 4; i++) {
      const y = pad.t + (ph * i) / 4;
      ctx.moveTo(pad.l, y);
      ctx.lineTo(pad.l + pw, y);
    }
    ctx.stroke();

    ctx.fillStyle = faint;
    ctx.font = "10px " + cssVar("--font", "sans-serif");
    ctx.textAlign = "right";
    ctx.textBaseline = "middle";
    for (let i = 0; i <= 4; i++) {
      const y = pad.t + (ph * i) / 4;
      const val = ymax * (1 - i / 4);
      const label = opts.unit === "%"
        ? val.toFixed(0) + "%"
        : val < 10 ? val.toFixed(1) : val.toFixed(0);
      ctx.fillText(label, pad.l - 6, y);
    }
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    [[0, `-${Math.round(span)}s`], [0.5, `-${Math.round(span / 2)}s`], [1, "now"]].forEach(([f, lbl]) => {
      ctx.fillText(lbl, pad.l + pw * f, pad.t + ph + 4);
    });

    function xOf(t) { return pad.l + pw * ((t - t0) / span); }
    function yOf(v) { return pad.t + ph * (1 - v / ymax); }

    if (band && band.length) {
      ctx.beginPath();
      let started = false;
      for (const pt of band) {
        if (!pt.up || pt.lo == null || pt.t < t0) continue;
        const x = xOf(pt.t), y = yOf(pt.hi);
        if (!started) { ctx.moveTo(x, y); started = true; }
        else ctx.lineTo(x, y);
      }
      for (let i = band.length - 1; i >= 0; i--) {
        const pt = band[i];
        if (!pt.up || pt.lo == null || pt.t < t0) continue;
        ctx.lineTo(xOf(pt.t), yOf(pt.lo));
      }
      if (started) {
        ctx.closePath();
        ctx.fillStyle = "rgba(1,169,130,0.12)";
        ctx.fill();
      }
    }

    series.forEach((s, idx) => {
      const pts = samples[s.id] || [];
      ctx.beginPath();
      let pen = false;
      for (const pt of pts) {
        const v = pt[key];
        if (v == null || pt.t < t0 || pt.up === false) { pen = false; continue; }
        const x = xOf(pt.t), y = yOf(v);
        if (!pen) { ctx.moveTo(x, y); pen = true; }
        else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = s.color || COLORS[idx % COLORS.length];
      ctx.lineWidth = 1.6;
      ctx.lineJoin = "round";
      ctx.stroke();
    });

    if (opts.markers) {
      ctx.setLineDash([3, 4]);
      ctx.strokeStyle = "rgba(139,154,171,0.55)";
      for (const [t] of opts.markers) {
        if (t < t0) continue;
        const x = xOf(t);
        ctx.beginPath();
        ctx.moveTo(x, pad.t);
        ctx.lineTo(x, pad.t + ph);
        ctx.stroke();
      }
      ctx.setLineDash([]);
    }
  }

  global.NVCharts = { drawChart, COLORS };
})(window);
