"""The dashboard's HTTP server: static UI, the JSON API behind it, the agent control channel,
agent downloads and install scripts. Plain HTTP by design: this runs inside closed labs."""
from __future__ import annotations

import csv
import io
import json
import logging
import mimetypes
import os
import re
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

from . import AGENT_VERSION, __version__, installers
from .drivers import DriverError
from .drivers.autopod import PRESETS, AutopodDriver
from .drivers.orchestrator import OrchestratorDriver
from .engine import DEFAULTS, LIMITS, Engine, EngineError
from .fleet import LIMITS as FLOW_LIMITS
from .fleet import Fleet, FleetError
from .store import Store

LOG = logging.getLogger(__name__)
WEB = os.path.join(os.path.dirname(__file__), "web")
BUILDS = {"chaos-agent-linux-amd64": ("linux", "amd64"), "chaos-agent-linux-arm64": ("linux", "arm64"),
          "chaos-agent-windows-amd64.exe": ("windows", "amd64")}
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]+(:\d{1,5})?$|^\[[0-9A-Fa-f:]+\](:\d{1,5})?$")
MAX_UI_BODY, MAX_AGENT_BODY = 256 << 10, 16 << 20


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def local_addresses() -> List[str]:
    """This machine's IPv4 addresses, best effort, without third-party modules."""
    found = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(info[4][0])
    except OSError:
        pass
    for probe in ("10.255.255.255", "172.31.255.255", "192.168.255.255", "198.18.255.255"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((probe, 9))        # no packet is sent: this only asks the routing table
            found.add(s.getsockname()[0])
        except OSError:
            pass
        finally:
            s.close()
    return sorted(a for a in found if not a.startswith("127.") and a != "0.0.0.0")


class App:
    """Everything the request handlers need, in one place."""

    def __init__(self, store: Store, fleet: Fleet, engine: Engine, *, dist: str, demo: bool, port: int,
                 password: str = ""):
        self.store, self.fleet, self.engine = store, fleet, engine
        self.dist, self.demo, self.port, self.password = dist, demo, port, password
        self.sessions: set = set()
        self.started = time.time()

    # ----- connections -----

    def load_connections(self) -> None:
        """Rebuild drivers from saved settings; environment variables win over what was saved."""
        if self.demo:
            return
        env = os.environ
        orch = self.store.get("conn.orchestrator") or {}
        if env.get("CHAOSLAB_ORCH_URL"):
            orch = {"url": env["CHAOSLAB_ORCH_URL"], "token": env.get("CHAOSLAB_ORCH_TOKEN", ""),
                    "verifyTls": env.get("CHAOSLAB_ORCH_VERIFY_TLS", "1") != "0"}
        if orch.get("url"):
            self.engine.set_driver("orchestrator", self._orch(orch))
        prime = self.store.get("conn.autopod") or {}
        if env.get("CHAOSLAB_PRIME_URL"):
            prime = {"url": env["CHAOSLAB_PRIME_URL"], "lab": env.get("CHAOSLAB_PRIME_LAB", ""),
                     "username": env.get("CHAOSLAB_PRIME_USER", ""), "password": env.get("CHAOSLAB_PRIME_PASSWORD", ""),
                     "token": env.get("CHAOSLAB_PRIME_TOKEN", "")}
        if prime.get("url") and prime.get("lab"):
            self.engine.set_driver("autopod", self._prime(prime))

    @staticmethod
    def _orch(c: Dict[str, Any]) -> OrchestratorDriver:
        return OrchestratorDriver(c["url"], token=c.get("token", ""), username=c.get("username", ""),
                                  password=c.get("password", ""), query_auth=bool(c.get("queryAuth")),
                                  verify_tls=c.get("verifyTls", True))

    @staticmethod
    def _prime(c: Dict[str, Any]) -> AutopodDriver:
        return AutopodDriver(c["url"], c["lab"], username=c.get("username", ""), password=c.get("password", ""),
                             token=c.get("token", ""))

    @staticmethod
    def _url(raw: Any, what: str) -> str:
        if not isinstance(raw, str) or not raw.strip():
            raise ApiError(400, f"Enter the {what} URL, for example https://{what.lower().split()[0]}.lab")
        parts = urlsplit(raw.strip())
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ApiError(400, "Enter a full URL starting with http:// or https://")
        if parts.username or parts.password:
            raise ApiError(400, "Do not put credentials in the URL. Use the fields below.")
        return f"{parts.scheme}://{parts.netloc}"

    def connect(self, kind: str, data: Dict[str, Any]) -> str:
        if self.demo:
            raise ApiError(400, "Demo mode uses the simulated lab only. Restart without --demo to connect to a real one.")
        if not self.engine.idle():
            raise ApiError(400, "Stop the current run before changing a connection.")
        if data.get("disconnect") is True:
            self.engine.set_driver(kind, None)
            self.store.put(f"conn.{kind}", {})
            self.store.audit("CONNECTION_REMOVED", scope=kind)
            return "Disconnected."
        if kind == "orchestrator":
            conf = {"url": self._url(data.get("url"), "Orchestrator"), "token": str(data.get("token") or "").strip(),
                    "username": str(data.get("username") or "").strip(), "password": str(data.get("password") or ""),
                    "queryAuth": data.get("queryAuth") is True, "verifyTls": data.get("verifyTls") is not False}
            if not conf["token"] and not (conf["username"] and conf["password"]):
                raise ApiError(400, "Enter an API key, or a user name and password.")
            driver: Any = self._orch(conf)
        else:
            conf = {"url": self._url(data.get("url"), "Prime"), "lab": str(data.get("lab") or "").strip(),
                    "username": str(data.get("username") or "").strip(), "password": str(data.get("password") or ""),
                    "token": str(data.get("token") or "").strip()}
            if not re.fullmatch(r"[a-z][a-z0-9]*", conf["lab"]):
                raise ApiError(400, "Enter the lab id, for example lab1.")
            if not conf["token"] and not (conf["username"] and conf["password"]):
                raise ApiError(400, "Enter a Prime user name and password, or a service token with the chaos grant.")
            driver = self._prime(conf)
        try:
            message = driver.probe()            # one read-only call; nothing is applied unless it works
        except DriverError as exc:
            raise ApiError(400, str(exc))
        try:
            self.engine.set_driver(kind, driver)
        except EngineError as exc:
            raise ApiError(400, str(exc))
        self.store.put(f"conn.{kind}", conf)
        self.store.audit("CONNECTION_CHANGED", scope=kind, target=conf["url"])
        self.engine.say("warn", f"Connection changed: {driver.label} is now {conf['url']}. Run discovery.")
        return message

    # ----- state for the browser -----

    def builds(self) -> List[Dict[str, Any]]:
        out = []
        for name, (os_name, arch) in BUILDS.items():
            path = os.path.join(self.dist, name)
            out.append({"file": name, "os": os_name, "arch": arch,
                        "size": os.path.getsize(path) if os.path.isfile(path) else None})
        return out

    @staticmethod
    def brief(t: Dict[str, Any]) -> Dict[str, Any]:
        impact = t.get("impact") or {}
        return {"id": t.get("id"), "cycle": t["cycle"], "run": t["run"], "target": t["target"], "fault": t["fault"],
                "hold": t["hold"], "started": t["started"], "ended": t.get("ended"), "tInject": t.get("t_inject"),
                "tRestore": t.get("t_restore"), "success": t["success"], "reason": t.get("reason", ""),
                "recovery": (t.get("facts") or {}).get("recovery_seconds"),
                "worstMs": impact.get("worstMs"), "affected": impact.get("affected"),
                "legs": len(impact.get("legs") or []), "faultLoss": impact.get("faultLoss"),
                "rttShiftMs": impact.get("rttShiftMs"),
                "phases": t.get("phases", [])}

    def state(self, log_after: int) -> Dict[str, Any]:
        e = self.engine
        trials = e.trials(200)
        current = None
        if e.current:
            c = e.current
            current = {"cycle": c["cycle"], "target": c["target"], "fault": c["fault"], "hold": c["hold"],
                       "phases": c["phases"], "started": c["started"], "tInject": c.get("t_inject"),
                       "tRestore": c.get("t_restore"), "holdUntil": c.get("hold_until"), "facts": c.get("facts", {})}
        names = self.fleet.leg_names()
        latest = self.fleet.latest()
        return {
            "now": int(time.time() * 1000), "version": __version__, "agentVersion": AGENT_VERSION, "demo": self.demo,
            "status": e.status, "phase": e.phase, "current": current, "run": e.run,
            "nextCycleAt": int(e.next_cycle_at * 1000) if e.next_cycle_at else None,
            "targets": [dict(t.public(), excluded=t.key in e.excluded) for t in e.targets],
            "discoveredAt": e.discovered_at, "held": e.held(),
            "drivers": [d.status() for d in e.drivers.values()],
            "trials": [self.brief(t) for t in trials],
            "agents": self.fleet.agents(), "flows": self.fleet.flows(),
            "legs": {str(k): dict(v, **latest.get(k, {"stale": True})) for k, v in names.items()},
            "joinToken": self.fleet.join_token, "builds": self.builds(), "addresses": local_addresses(),
            "port": self.port, "presets": PRESETS, "defaults": DEFAULTS, "limits": LIMITS,
            "flowLimits": FLOW_LIMITS, "open": not self.password,
            "log": [m for m in e.log if m["n"] > log_after],
            "audit": self.store.rows("SELECT * FROM audit ORDER BY id DESC LIMIT 12"),
        }

    def export(self, name: str) -> Tuple[str, str, str]:
        trials = list(reversed(self.engine.trials(100000)))
        if name == "trials.json":
            return json.dumps(trials, indent=2), "application/json", "chaos_trials.json"
        if name == "audit.json":
            return (json.dumps(self.store.rows("SELECT * FROM audit ORDER BY id"), indent=2), "application/json",
                    "chaos_audit.json")
        if name == "trials.csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["trial", "cycle", "started", "driver", "kind", "group", "target", "fault", "direction",
                        "hold_s", "outcome", "recovery_s", "worst_interruption_ms", "legs_affected", "legs_measured",
                        "loss_during_fault_pct", "rtt_shift_ms", "reason"])
            for t in trials:
                b = self.brief(t)
                w.writerow([b["id"], b["cycle"], time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(b["started"] / 1000)),
                            b["target"]["driver"], b["target"]["kind"], b["target"]["group"], b["target"]["name"],
                            b["fault"]["label"], b["fault"].get("direction", ""), b["hold"],
                            "recovered" if b["success"] else "failed", b["recovery"] if b["recovery"] is not None else "",
                            b["worstMs"] if b["worstMs"] is not None else "", b["affected"] if b["affected"] is not None else "",
                            b["legs"], b["faultLoss"] if b["faultLoss"] is not None else "",
                            b["rttShiftMs"] if b["rttShiftMs"] is not None else "", b["reason"]])
            return buf.getvalue(), "text/csv", "chaos_trials.csv"
        raise ApiError(404, "Unknown export")


def make_handler(app: App) -> type:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "ChaosLab"

        def log_message(self, fmt: str, *args: Any) -> None:      # quiet: one line per sync would drown the log
            LOG.debug("%s %s", self.address_string(), fmt % args)

        # ----- plumbing -----

        def _send(self, status: int, body: bytes, ctype: str, extra: Optional[Dict[str, str]] = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, obj: Any, status: int = 200, extra: Optional[Dict[str, str]] = None) -> None:
            self._send(status, json.dumps(obj, separators=(",", ":")).encode(), "application/json", extra)

        def _text(self, text: str, status: int = 200) -> None:
            self._send(status, text.encode(), "text/plain; charset=utf-8")

        def _body(self, limit: int) -> Dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                raise ApiError(400, "bad Content-Length")
            if length > limit:
                raise ApiError(413, "request too large")
            raw = self.rfile.read(length) if length else b""
            if not raw:
                return {}
            try:
                data = json.loads(raw)
            except ValueError:
                raise ApiError(400, "the request body is not JSON")
            if not isinstance(data, dict):
                raise ApiError(400, "the request body must be a JSON object")
            return data

        def _controller_url(self) -> str:
            host = self.headers.get("Host", "")
            if not HOST_RE.match(host):       # it is pasted into a shell script, so be strict
                host = f"{(local_addresses() or ['127.0.0.1'])[0]}:{app.port}"
            return f"http://{host}"

        def _authed(self) -> bool:
            if not app.password:
                return True
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "chaoslab" and v in app.sessions:
                    return True
            return False

        def _guard(self) -> None:
            """Dashboard API calls: optional password, and a custom header on anything that changes
            state so that another web page open in the operator's browser cannot drive this one."""
            if not self._authed():
                raise ApiError(401, "Sign in first.")
            if self.command != "GET" and self.headers.get("X-Chaoslab") != "1":
                raise ApiError(403, "Missing X-Chaoslab header.")

        # ----- dispatch -----

        def do_GET(self) -> None:
            self._dispatch()

        def do_HEAD(self) -> None:
            self._dispatch()

        def do_POST(self) -> None:
            self._dispatch()

        def do_DELETE(self) -> None:
            self._dispatch()

        def _dispatch(self) -> None:
            parts = urlsplit(self.path)
            path, query = parts.path, {k: v[0] for k, v in parse_qs(parts.query).items()}
            try:
                if path.startswith("/api/agent/"):
                    self._agent(path)
                elif path.startswith("/api/"):
                    self._api(path, query)
                else:
                    self._public(path, query)
            except ApiError as exc:
                self._json({"error": str(exc)}, exc.status)
            except (EngineError, FleetError) as exc:
                self._json({"error": str(exc)}, 400)
            except PermissionError as exc:
                self._json({"error": str(exc)}, 403)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception:                           # a handler bug must not take the server thread down
                LOG.exception("request failed: %s %s", self.command, path)
                self._json({"error": "internal error; see the controller log"}, 500)

        # ----- agents -----

        def _agent(self, path: str) -> None:
            if self.command != "POST":
                raise ApiError(405, "POST only")
            data = self._body(MAX_AGENT_BODY)
            remote = self.client_address[0]
            if path == "/api/agent/hello":
                if not app.fleet.token_ok(data.get("token")):
                    raise ApiError(403, "unknown join token")
                self._json({"ok": True, "controller": "Chaos Monkey", "version": __version__})
            elif path == "/api/agent/enroll":
                self._json(app.fleet.enroll(data, remote))
            elif path == "/api/agent/sync":
                agent = app.fleet.authenticate(self.headers.get("X-Agent-Id"), self.headers.get("X-Agent-Key"))
                if not agent:
                    raise ApiError(401, "unknown agent")
                self._json(app.fleet.sync(agent, data, remote))
            else:
                raise ApiError(404, "not found")

        # ----- public: UI, downloads, install scripts -----

        def _public(self, path: str, query: Dict[str, str]) -> None:
            if self.command not in ("GET", "HEAD"):
                raise ApiError(405, "GET only")
            scripts = {"/install.sh": (installers.SH, installers.BAD_TOKEN_SH),
                       "/install.ps1": (installers.PS1, installers.BAD_TOKEN_PS1)}
            if path in scripts:
                good, bad = scripts[path]
                token = query.get("token", "")
                if not app.fleet.token_ok(token):
                    return self._text(bad, 403)
                return self._text(installers.render(good, self._controller_url(), token))
            if path == "/uninstall.sh":
                return self._text(installers.UNINSTALL_SH)
            if path == "/uninstall.ps1":
                return self._text(installers.UNINSTALL_PS1)
            if path.startswith("/dl/"):
                name = path[4:]
                if name not in BUILDS:
                    raise ApiError(404, "no such agent build")
                full = os.path.join(app.dist, name)
                if not os.path.isfile(full):
                    raise ApiError(404, f"{name} has not been built on the controller yet. On the controller run: "
                                        "python3 -m chaoslab build-agents")
                with open(full, "rb") as fh:
                    return self._send(200, fh.read(), "application/octet-stream",
                                      {"Content-Disposition": f'attachment; filename="{name}"'})
            rel = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
            full = os.path.realpath(os.path.join(WEB, rel))
            if not full.startswith(os.path.realpath(WEB) + os.sep) or not os.path.isfile(full):
                raise ApiError(404, "not found")
            ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript",):
                ctype += "; charset=utf-8"
            with open(full, "rb") as fh:
                self._send(200, fh.read(), ctype)

        # ----- dashboard API -----

        def _api(self, path: str, query: Dict[str, str]) -> None:
            e, fleet, method = app.engine, app.fleet, self.command
            if path == "/api/login" and method == "POST":
                data = self._body(MAX_UI_BODY)
                if self.headers.get("X-Chaoslab") != "1":
                    raise ApiError(403, "Missing X-Chaoslab header.")
                supplied = str(data.get("password") or "")
                if not app.password or not secrets.compare_digest(supplied.encode(), app.password.encode()):
                    time.sleep(0.5)
                    raise ApiError(401, "Wrong password.")
                token = secrets.token_urlsafe(24)
                app.sessions.add(token)
                return self._json({"ok": True}, extra={
                    "Set-Cookie": f"chaoslab={token}; Path=/; HttpOnly; SameSite=Strict"})
            self._guard()
            data = self._body(MAX_UI_BODY) if method in ("POST", "DELETE") else {}

            def need_ack() -> None:
                if not app.demo and data.get("acknowledge") is not True:
                    raise ApiError(400, "Confirm that you are authorised to disrupt these targets before starting.")

            if method == "GET":
                if path == "/api/state":
                    return self._json(app.state(int(query.get("log", "0") or 0)))
                if path == "/api/series":
                    window = max(30, min(900, int(query.get("window", "300") or 300)))
                    return self._json({"now": int(time.time() * 1000), "window": window,
                                       "series": {str(k): v for k, v in fleet.series(window).items()}})
                if path.startswith("/api/trials/"):
                    row = app.store.one("SELECT id, data FROM trials WHERE id=?", (path.rsplit("/", 1)[1],))
                    if not row:
                        raise ApiError(404, "no such trial")
                    return self._json(dict(json.loads(row["data"]), id=row["id"]))
                if path == "/api/audit":
                    return self._json({"audit": app.store.rows("SELECT * FROM audit ORDER BY id DESC LIMIT 1000")})
                if path.startswith("/api/export/"):
                    body, ctype, name = app.export(path.rsplit("/", 1)[1])
                    return self._send(200, body.encode(), ctype, {"Content-Disposition": f'attachment; filename="{name}"'})
                raise ApiError(404, "not found")

            if method == "POST":
                if path == "/api/discover":
                    e.discover()
                    return self._json({"status": "discovering"})
                if path == "/api/run":
                    need_ack()
                    e.start(data)
                    return self._json({"status": "started"})
                if path == "/api/test":
                    need_ack()
                    key = data.get("key")
                    if not isinstance(key, str) or not any(t.key == key for t in e.targets):
                        raise ApiError(400, "Unknown target. Run discovery first.")
                    e.start(data, only=key, fault_id=data.get("fault") or None, direction=data.get("direction") or None)
                    return self._json({"status": "started"})
                if path == "/api/stop":
                    e.stop()
                    return self._json({"status": e.status})
                if path == "/api/skip":
                    e.skip_wait()
                    return self._json({"status": "ok"})
                if path == "/api/scope":
                    excluded = data.get("excluded")
                    if not isinstance(excluded, list) or not all(isinstance(k, str) for k in excluded):
                        raise ApiError(400, "'excluded' must be a list of target keys")
                    e.set_scope(excluded)
                    return self._json({"status": "ok", "inScope": len(e.in_scope())})
                if path == "/api/restore":
                    if not e.idle():
                        raise ApiError(400, "A run is active. Use Stop: it restores as part of stopping.")
                    errors = e.restore_all()
                    return self._json({"status": "ok", "errors": errors})
                if path in ("/api/connections/orchestrator", "/api/connections/autopod"):
                    return self._json({"status": "ok", "message": app.connect(path.rsplit("/", 1)[1], data)})
                if path == "/api/flows":
                    return self._json({"status": "ok", "id": fleet.create_flow(data)})
                if path.startswith("/api/flows/"):
                    fleet.set_flow_enabled(self._id(path), data.get("enabled") is True)
                    return self._json({"status": "ok"})
                if path.startswith("/api/agents/"):
                    fleet.update_agent(path.rsplit("/", 1)[1], data)
                    return self._json({"status": "ok"})
                if path == "/api/token/rotate":
                    return self._json({"status": "ok", "token": fleet.rotate_token()})
                raise ApiError(404, "not found")

            if method == "DELETE":
                if path.startswith("/api/flows/"):
                    fleet.delete_flow(self._id(path))
                    return self._json({"status": "ok"})
                if path.startswith("/api/agents/"):
                    fleet.remove_agent(path.rsplit("/", 1)[1])
                    return self._json({"status": "ok"})
            raise ApiError(404, "not found")

        @staticmethod
        def _id(path: str) -> int:
            try:
                return int(path.rsplit("/", 1)[1])
            except ValueError:
                raise ApiError(400, "bad id")

    return Handler


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


def serve(app: App, host: str, port: int) -> Server:
    server = Server((host, port), make_handler(app))
    threading.Thread(target=server.serve_forever, daemon=True, name="http").start()
    return server
