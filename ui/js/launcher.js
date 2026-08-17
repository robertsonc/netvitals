(function () {
  const $ = (id) => document.getElementById(id);
  let adv = false;

  async function api(path, opts) {
    const r = await fetch(path, opts);
    const ct = r.headers.get("content-type") || "";
    const body = ct.includes("json") ? await r.json() : await r.text();
    if (!r.ok) throw new Error((body && body.error) || body || r.statusText);
    return body;
  }

  function collect() {
    return {
      peer: $("peer").value.trim(),
      size: $("size").value.trim(),
      pps: $("pps").value.trim(),
      mbps: $("mbps").value.trim(),
      dont_fragment: $("df").checked,
      bind: $("bind").value.trim(),
      udp_ports: $("udp").value.trim(),
      tcp_ports: $("tcp").value.trim(),
      profiles: $("profiles").value.trim(),
      dscp: $("dscp").value.trim(),
      window: $("window").value.trim(),
      timeout: $("timeout").value.trim(),
      loss_deadband: $("deadband").value.trim(),
      history: $("history").value.trim(),
      refresh_ms: $("refresh").value.trim(),
      vxlan: $("vxlan").checked,
      vxlan_vni: $("vni").value.trim(),
      vxlan_port: $("vxport").value.trim(),
      no_gui: $("console").checked,
    };
  }

  $("btnAdv").onclick = () => {
    adv = !adv;
    $("advPanel").style.display = adv ? "block" : "none";
    $("btnAdv").textContent = (adv ? "▾" : "▸") + " Advanced options";
  };

  $("btnUpdate").onclick = async () => {
    try {
      const res = await api("/api/update/check");
      if (!res.available) { alert(res.message || "Already up to date."); return; }
      if (!confirm("Update to v" + res.version + "?")) return;
      await api("/api/update/apply", { method: "POST" });
      alert("Update installed — relaunching…");
    } catch (e) { alert(String(e.message || e)); }
  };

  $("launchForm").onsubmit = async (e) => {
    e.preventDefault();
    $("err").style.display = "none";
    try {
      const res = await api("/api/launcher/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(collect()),
      });
      if (res.ok) {
        /* server closes launcher after handing off argv */
        document.body.innerHTML = "<div class='launch'><p>Starting…</p></div>";
      }
    } catch (err) {
      $("err").style.display = "block";
      $("err").textContent = String(err.message || err);
    }
  };

  api("/api/launcher/bootstrap").then((b) => {
    $("ver").textContent = "v" + b.version;
    if (b.local_ips && b.local_ips.length) {
      $("localIps").textContent = "This machine: " + b.local_ips.slice(0, 3).join("   ");
    }
    const s = b.settings || {};
    if (s.peer) $("peer").value = s.peer;
    if (s.size != null) $("size").value = s.size;
    if (s.pps != null) $("pps").value = s.pps;
    if (s.mbps) $("mbps").value = s.mbps;
    $("df").checked = !!s.dont_fragment;
    if (s.bind) $("bind").value = s.bind;
    if (s.udp_ports) $("udp").value = s.udp_ports;
    if (s.tcp_ports) $("tcp").value = s.tcp_ports;
    if (s.window) $("window").value = s.window;
    if (s.timeout) $("timeout").value = s.timeout;
    if (s.loss_deadband != null) $("deadband").value = s.loss_deadband;
    if (s.history) $("history").value = s.history;
    if (s.refresh_ms) $("refresh").value = s.refresh_ms;
    $("vxlan").checked = !!s.vxlan;
    if (s.vxlan_vni) $("vni").value = s.vxlan_vni;
    if (s.vxlan_port) $("vxport").value = s.vxlan_port;
    $("console").checked = !!s.no_gui;
    const dl = $("recentPeers");
    (b.recent_peers || []).forEach((p) => {
      const o = document.createElement("option");
      o.value = p;
      dl.appendChild(o);
    });
    if (s.advanced_open) $("btnAdv").click();
  }).catch((e) => {
    $("err").style.display = "block";
    $("err").textContent = String(e.message || e);
  });
})();
