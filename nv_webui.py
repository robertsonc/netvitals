"""HPE Demo Instrument web UI host for Network Vitals.

Serves the embedded/sibling `ui/` assets over loopback and bridges Engine
snapshots to the dashboard / launcher. Kept as a sibling module so the UI
layer stays readable; `netquality.py` imports it at GUI entrypoints. For
single-file signed updates, `tools/embed_ui.py` can fold assets into the
main module later without changing the HTTP contract.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


def _ui_root():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "ui")


def _read_ui(path):
    """Read a UI file from the sibling ui/ tree."""
    root = _ui_root()
    full = os.path.normpath(os.path.join(root, path.lstrip("/")))
    if not full.startswith(os.path.normpath(root) + os.sep) and full != os.path.normpath(root):
        return None
    if not os.path.isfile(full):
        return None
    with open(full, "rb") as fh:
        return fh.read()


_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".json": "application/json",
}


def _ctype(path):
    ext = os.path.splitext(path)[1].lower()
    return _CONTENT_TYPES.get(ext, "application/octet-stream")


def _json_safe(obj):
    """Make Engine snapshot structures JSON-serializable."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {str(k): _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, bytes):
        return obj.decode("utf-8", "replace")
    return str(obj)


def _pick_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _warning_from_snap(nv, snap):
    bleached = []
    for r in snap["rows"]:
        if (r.get("dscp_req") is not None and r.get("fwd_tos") is not None
                and (r["fwd_tos"] >> 2) != r["dscp_req"]):
            bleached.append(r)
    if snap.get("udp_silent"):
        return ("UDP silent while TCP is up — UDP blocked in the path "
                "(firewall/ACL) or the peer runs an outdated version; "
                "update BOTH ends", "bad")
    if bleached:
        r = bleached[0]
        more = f" (+{len(bleached) - 1} more)" if len(bleached) > 1 else ""
        return (f"DSCP rewritten mid-path: {r['name']} sent "
                f"{nv.dscp_name(r['dscp_req'])}, peer received "
                f"{nv.dscp_name(r['fwd_tos'] >> 2)}{more} — bleaching/remap "
                f"policy in the path", "warn")
    if snap.get("fec"):
        return (str(snap["fec"]), "warn")
    if snap.get("loss_pattern"):
        return (f"loss pattern (last 60 s): {snap['loss_pattern']}", "warn")
    if snap.get("slice_evidence"):
        return (str(snap["slice_evidence"]), "warn")
    return ("", "")


def _anatomy_payload(nv, engine, args, snap):
    probe = engine.size
    vx_on = bool(engine.vxlan)
    inner = probe + 28 + (nv.VXLAN_OVERHEAD_UDP if vx_on else 0)
    pieces = nv.ec_wire_view(inner)
    n = len(pieces)
    wan_total = sum(wr for _, wr in pieces)
    tax = (wan_total - inner) / inner * 100.0 if inner else 0.0
    parts = (f"probe {probe:,} + VXLAN {nv.VXLAN_OVERHEAD_UDP} + IP/UDP 28"
             if vx_on else f"probe {probe:,} + IP/UDP 28")
    df = "on" if args.dont_fragment else "off"
    verb = (f"EC encrypts + encapsulates → 1 tunnel packet (no slicing: "
            f"{inner:,} B ≤ {nv.EC_SLICE_BUDGET:,} B budget)" if n == 1 else
            f"EC slices + encapsulates → {n} tunnel packets")
    pps0 = engine.rate_of_sid.get(0, args.pps)
    predict = (f"predicted per UDP stream: {pps0:g} pps LAN → "
               f"{pps0 * n:g} pps WAN, each direction (echoes are full-size)")
    if inner > 1500:
        frags = -(-(inner - 20) // 1480)
        noec = (f"without the fabric at a 1500 B hop: DF on → PMTUD "
                f"required (or black hole) · DF off → {frags} IP fragments, "
                f"only #1 carries the L4 header")
    else:
        noec = "without the fabric: fits a standard 1500 B hop as-is"
    wan_line = ""
    if snap.get("wan"):
        wan_line = f"measured WAN: {snap['wan']}"
    return {
        "inner": inner, "parts": parts, "df": df, "verb": verb, "n": n,
        "wan_total": wan_total, "tax": tax, "predict": predict, "noec": noec,
        "wan_line": wan_line, "pieces": pieces,
    }


def _topology_payload(snap):
    t = snap["totals"]
    summary = (f"{snap['peer']}  ·  {snap['links_up']} streams up  ·  "
               f"Experience {snap['overall']:.0f} ({snap['overall_label']})")
    detail = (f"loss {t['loss_pct']:.2f}%  ·  fwd {t['fwd_pct']:.2f}%  ·  "
              f"rtn {t['rtn_pct']:.2f}%  ·  offered {snap['offered_mbps']:.2f} Mbps")
    return {"summary": summary, "detail": detail}


def _enrich_rows(nv, snap):
    rows = []
    for r in snap["rows"]:
        rr = dict(r)
        where, tag = nv.loss_verdict(r["fwd_lost"], r["rtn_lost"])
        rr["where"] = where
        rr["where_tag"] = tag
        rr["dscp_name"] = (nv.dscp_name(r["dscp_req"])
                           if r.get("dscp_req") is not None else None)
        # Drop non-JSON bits if any
        rows.append(_json_safe(rr))
    return rows


def build_dashboard_payload(nv, engine, args, load_gen=None):
    snap = engine.snapshot()
    warn, level = _warning_from_snap(nv, snap)
    out = dict(snap)
    out["rows"] = _enrich_rows(nv, snap)
    out["warning"] = warn
    out["warning_level"] = level
    out["stream_count"] = len(nv.STREAMS)
    out["ports"] = nv.ports_summary()
    out["anatomy"] = _anatomy_payload(nv, engine, args, snap)
    out["topology"] = _topology_payload(snap)

    hist = engine.history_copy()
    owd_f, owd_r, band = engine.extra_history_copy()
    marks = engine.markers_copy()
    series = [{"id": sid, "label": name.split("-")[1],
               "color": ["#4db6a0", "#6a9fbf", "#c4a35a", "#b07a8c"][sid % 4]}
              for sid, proto, port, name in nv.STREAMS]
    # History keys are ints — JSON object keys become strings; keep ints in lists
    hist_out = {str(k): _json_safe(v) for k, v in hist.items()}

    load = None
    if load_gen is not None:
        st = load_gen.status() if load_gen.running else {"running": False}
        load = {
            "running": load_gen.running,
            "status": ("running · "
                       f"{st.get('achieved_mbps', 0):.2f} Mbps achieved"
                       if load_gen.running else "idle"),
            "disabled": bool(engine.vxlan),
        }
        if engine.vxlan:
            load["status"] = ("unavailable in VXLAN mode "
                              "(peer has no native UDP listener)")

    return {
        "version": nv.__version__,
        "view_seconds": float(args.history),
        "refresh_ms": int(getattr(args, "refresh_ms", 500) or 500),
        "now": time.monotonic(),
        "series": series,
        "history": hist_out,
        "owd_f": _json_safe(owd_f),
        "owd_r": _json_safe(owd_r),
        "band": _json_safe(band),
        "markers": _json_safe(marks),
        "snap": _json_safe(out),
        "load": load,
    }


class _UiContext:
    def __init__(self, mode, nv, **kw):
        self.mode = mode  # "dashboard" | "launcher" | "mesh"
        self.nv = nv
        self.engine = kw.get("engine")
        self.args = kw.get("args")
        self.load_gen = kw.get("load_gen")
        self.launcher_result = kw.get("launcher_result")  # dict with argv
        self.shutdown = threading.Event()
        self.update_url = kw.get("update_url") or nv.UPDATE_URL


def make_handler(ctx: _UiContext):
    nv = ctx.nv

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            return  # quiet — demo UI shouldn't spam the console

        def _send(self, code, body, ctype="application/json; charset=utf-8"):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b"{}"
            return json.loads(raw.decode("utf-8") or "{}")

        def do_GET(self):
            try:
                path = urlparse(self.path).path
                if path == "/" or path == "/index.html":
                    page = ("launcher.html" if ctx.mode == "launcher"
                            else "dashboard.html")
                    data = _read_ui(page)
                    if not data:
                        self._send(500, b"UI assets missing (ui/ not found)",
                                   "text/plain; charset=utf-8")
                        return
                    self._send(200, data, "text/html; charset=utf-8")
                    return
                if path.startswith("/css/") or path.startswith("/js/"):
                    data = _read_ui(path)
                    if not data:
                        self._send(404, b"not found", "text/plain")
                        return
                    self._send(200, data, _ctype(path))
                    return
                if path.startswith("/assets/"):
                    # Serve repo assets (HPE logo) when present
                    rel = path[len("/assets/"):]
                    root = os.path.dirname(os.path.abspath(nv.__file__))
                    full = os.path.normpath(os.path.join(root, "assets", rel))
                    if not full.startswith(os.path.join(root, "assets")):
                        self._send(404, b"not found", "text/plain")
                        return
                    if not os.path.isfile(full):
                        self._send(404, b"not found", "text/plain")
                        return
                    with open(full, "rb") as fh:
                        self._send(200, fh.read(), _ctype(full))
                    return
                if path == "/api/snapshot" and ctx.engine is not None:
                    payload = build_dashboard_payload(
                        nv, ctx.engine, ctx.args, ctx.load_gen)
                    self._send(200, json.dumps(payload).encode("utf-8"))
                    return
                if path == "/api/launcher/bootstrap" and ctx.mode == "launcher":
                    s = nv.load_settings()
                    body = {
                        "version": nv.__version__,
                        "local_ips": nv.local_ips(),
                        "settings": s,
                        "recent_peers": s.get("recent_peers") or [],
                        "defaults": {
                            "udp_ports": "%d,%d" % nv.DEFAULT_UDP_PORTS,
                            "tcp_ports": "%d,%d" % nv.DEFAULT_TCP_PORTS,
                            "vxlan_vni": nv.VXLAN_DEFAULT_VNI,
                            "vxlan_port": nv.VXLAN_DEFAULT_PORT,
                        },
                    }
                    self._send(200, json.dumps(body).encode("utf-8"))
                    return
                if path == "/api/update/check":
                    try:
                        m = nv.check_update(ctx.update_url)
                    except RuntimeError as e:
                        self._send(200, json.dumps({
                            "available": False, "message": str(e),
                        }).encode("utf-8"))
                        return
                    if m is None:
                        self._send(200, json.dumps({
                            "available": False,
                            "message": "Already up to date.",
                        }).encode("utf-8"))
                    else:
                        self._send(200, json.dumps({
                            "available": True, "version": m["version"],
                        }).encode("utf-8"))
                    return
                self._send(404, b"not found", "text/plain")
            except Exception:
                self._send(500, traceback.format_exc().encode("utf-8"),
                           "text/plain; charset=utf-8")

        def do_POST(self):
            try:
                path = urlparse(self.path).path
                if path == "/api/reset" and ctx.engine is not None:
                    ctx.engine.reset()
                    self._send(200, b'{"ok":true}')
                    return
                if path == "/api/report" and ctx.engine is not None:
                    jp, hp = nv.write_report(ctx.engine, ctx.args)
                    self._send(200, json.dumps({
                        "ok": True, "json": jp, "html": hp,
                    }).encode("utf-8"))
                    return
                if path == "/api/load/start" and ctx.load_gen is not None:
                    body = self._read_json()
                    if ctx.engine.vxlan:
                        self._send(200, json.dumps({
                            "error": "unavailable in VXLAN mode",
                        }).encode("utf-8"))
                        return
                    mbps = float(body.get("mbps") or 0)
                    if not (0 < mbps <= 1000):
                        self._send(200, json.dumps({
                            "error": "enter a load in Mbps (0 < X ≤ 1000)",
                        }).encode("utf-8"))
                        return
                    on_s = off_s = 0.0
                    if body.get("square"):
                        on_s = float(body.get("on_s") or 0)
                        off_s = float(body.get("off_s") or 0)
                        if on_s <= 0 or off_s <= 0:
                            self._send(200, json.dumps({
                                "error": "square wave needs positive on/off seconds",
                            }).encode("utf-8"))
                            return
                    err = ctx.load_gen.start(mbps, on_s, off_s)
                    self._send(200, json.dumps({
                        "ok": not err, "error": err,
                    }).encode("utf-8"))
                    return
                if path == "/api/load/stop" and ctx.load_gen is not None:
                    ctx.load_gen.stop()
                    self._send(200, b'{"ok":true}')
                    return
                if path == "/api/launcher/start" and ctx.mode == "launcher":
                    vals = self._read_json()
                    # Normalize fields expected by _launcher_argv
                    vals.setdefault("profiles", "")
                    vals.setdefault("dscp", "")
                    try:
                        argv = nv._launcher_argv(vals)
                    except ValueError as e:
                        self._send(400, json.dumps({
                            "error": str(e),
                        }).encode("utf-8"))
                        return
                    # Persist settings like the Tk launcher
                    try:
                        s = nv.load_settings()
                        s.update({
                            "peer": vals.get("peer", ""),
                            "size": vals.get("size", "200"),
                            "pps": vals.get("pps", "50"),
                            "mbps": vals.get("mbps", ""),
                            "dont_fragment": bool(vals.get("dont_fragment")),
                            "bind": vals.get("bind", "0.0.0.0"),
                            "udp_ports": vals.get("udp_ports", ""),
                            "tcp_ports": vals.get("tcp_ports", ""),
                            "window": vals.get("window", "10"),
                            "timeout": vals.get("timeout", "2"),
                            "loss_deadband": vals.get("loss_deadband", "0.5"),
                            "history": vals.get("history", "300"),
                            "refresh_ms": vals.get("refresh_ms", "500"),
                            "vxlan": bool(vals.get("vxlan")),
                            "vxlan_vni": vals.get("vxlan_vni"),
                            "vxlan_port": vals.get("vxlan_port"),
                            "no_gui": bool(vals.get("no_gui")),
                        })
                        recent = [p for p in s.get("recent_peers", [])
                                  if isinstance(p, str) and p != vals.get("peer")]
                        if vals.get("peer"):
                            recent = [vals["peer"]] + recent
                        s["recent_peers"] = recent[:12]
                        nv.save_settings(s)
                    except Exception:
                        pass
                    ctx.launcher_result["argv"] = argv
                    ctx.shutdown.set()
                    self._send(200, b'{"ok":true}')
                    return
                if path == "/api/update/apply":
                    try:
                        m = nv.check_update(ctx.update_url)
                        if m is None:
                            self._send(200, json.dumps({
                                "ok": False, "message": "Already up to date.",
                            }).encode("utf-8"))
                            return
                        nv.download_and_install(m, ctx.update_url)
                        argv = list(getattr(ctx.args, "_argv", []) or [])
                        threading.Thread(
                            target=lambda: (time.sleep(0.4), nv.relaunch(argv)),
                            daemon=True).start()
                        ctx.shutdown.set()
                        self._send(200, b'{"ok":true}')
                    except RuntimeError as e:
                        self._send(400, json.dumps({
                            "error": str(e),
                        }).encode("utf-8"))
                    return
                self._send(404, b"not found", "text/plain")
            except Exception:
                self._send(500, traceback.format_exc().encode("utf-8"),
                           "text/plain; charset=utf-8")

    return Handler


def _open_host(url):
    """Open the UI: prefer default browser (cross-platform, no pip)."""
    try:
        webbrowser.open(url)
    except Exception:
        pass


def _run_server(ctx, title="Network Vitals"):
    port = _pick_port()
    handler = make_handler(ctx)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    url = f"http://127.0.0.1:{port}/"
    thread = threading.Thread(target=httpd.serve_forever, name="nv-ui", daemon=True)
    thread.start()
    _open_host(url)

    # Tiny Tk dock: keeps a process window + Quit on machines with a display.
    dock = {"root": None}
    try:
        import tkinter as tk
        root = tk.Tk()
        dock["root"] = root
        nv = ctx.nv
        nv._resolve_fonts(root)
        nv._set_window_icon(root)
        root.title(title)
        root.geometry("420x120")
        root.configure(bg="#0d1218")
        tk.Label(root, text=title, fg="#e8eef5", bg="#0d1218",
                 font=(nv.FONT, 12, "bold")).pack(anchor="w", padx=16, pady=(14, 4))
        tk.Label(root, text=f"UI open at {url}", fg="#8b9aab", bg="#0d1218",
                 font=(nv.FONT, 9)).pack(anchor="w", padx=16)
        bar = tk.Frame(root, bg="#0d1218")
        bar.pack(fill="x", padx=16, pady=12)

        def open_again():
            _open_host(url)

        def quit_app():
            ctx.shutdown.set()

        tk.Button(bar, text="Open UI", command=open_again).pack(side="left")
        tk.Button(bar, text="Quit", command=quit_app).pack(side="left", padx=8)

        def poll():
            if ctx.shutdown.is_set():
                try:
                    root.destroy()
                except Exception:
                    pass
                return
            root.after(200, poll)

        root.protocol("WM_DELETE_WINDOW", quit_app)
        root.after(200, poll)
        root.mainloop()
    except Exception:
        # Headless / no Tk: block until shutdown (e.g. launcher start).
        while not ctx.shutdown.wait(0.5):
            pass

    try:
        httpd.shutdown()
    except Exception:
        pass
    try:
        httpd.server_close()
    except Exception:
        pass


def run_web_dashboard(nv, engine, args):
    load_gen = None
    try:
        udp_port = args.udp_ports[0] if getattr(args, "udp_ports", None) else nv.DEFAULT_UDP_PORTS[0]
        load_gen = nv.LoadGenerator(engine.peer, udp_port, bind=args.bind,
                                    dont_fragment=args.dont_fragment,
                                    timeout=args.timeout)
    except Exception:
        load_gen = None
    ctx = _UiContext("dashboard", nv, engine=engine, args=args,
                     load_gen=load_gen,
                     update_url=getattr(args, "update_url", None))
    try:
        _run_server(ctx, title=f"Network Vitals {nv.__version__} — peer {args.peer}")
    finally:
        if load_gen is not None and load_gen.running:
            load_gen.stop()


def run_web_mesh(nv, engine, args):
    # Mesh uses the same dashboard payload against the first peer for v1;
    # pair selection can deepen later without changing the host.
    run_web_dashboard(nv, engine, args)


def run_web_launcher(nv, update_url=None):
    result = {"argv": None}
    ctx = _UiContext("launcher", nv, launcher_result=result,
                     update_url=update_url or nv.UPDATE_URL,
                     args=type("A", (), {"_argv": [], "update_url": update_url})())
    _run_server(ctx, title=f"Network Vitals {nv.__version__} — launch")
    return result["argv"]
