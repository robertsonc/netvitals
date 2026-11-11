"""In-process stand-ins for the two real APIs the drivers talk to, served over real HTTP on loopback."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class _Server:
    def __init__(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _go(self):
                parts = urlsplit(self.path)
                query = {k: v[0] for k, v in parse_qs(parts.query).items()}
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                outer.calls.append((self.command, self.path, body))
                status, out = outer.handle(self.command, parts.path, query, body, self.headers)
                raw = json.dumps(out).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = do_POST = _go

        self.calls = []
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class FakeOrchestrator(_Server):
    """Two appliances forming a VRRP pair, each with two WAN interfaces. Mastership follows interface state."""

    def __init__(self, token="key"):
        super().__init__()
        self.token = token
        self.ifaces = {n: {i: {"ifname": i, "admin": True, "oper": True, "mac": f"00:00:00:00:0{n[0]}:{k}"}
                           for k, i in enumerate(("wan0", "wan1", "wan1.20", "lan0"))} for n in ("1.NE", "2.NE")}
        self.prio = {"1.NE": 110, "2.NE": 100}
        self.posts = []

    def handle(self, method, path, query, body, headers):
        if headers.get("X-Auth-Token") != self.token:
            return 401, {"message": "bad token"}
        nepk = query.get("nePk", "")
        if path == "/gms/rest/appliance":
            return 200, [{"nePk": n, "hostName": f"edge-{n[0]}", "site": "HQ", "model": "EC-V"} for n in self.ifaces]
        if path == "/gms/rest/deployment":
            return 200, {"sysConfig": {"ifLabels": {"wan": [{"id": "1", "name": "INET1"}, {"id": "2", "name": "MPLS"}]}},
                         "modeIfs": [{"ifName": "wan0", "applianceIPs": [{"wanSide": True, "ip": "198.51.100.1", "label": "1"}]},
                                     {"ifName": "wan1", "applianceIPs": [{"wanSide": True, "ip": "169.254.0.1", "label": "2"},
                                                                         {"wanSide": True, "ip": "198.51.100.9", "label": "2", "vlan": 20}]},
                                     {"ifName": "lan0", "applianceIPs": [{"wanSide": False, "ip": "10.0.0.2"}]}]}
        if path == "/gms/rest/appliance/rest" and nepk in self.ifaces:
            if query.get("url") == "vrrp":
                up = [n for n in self.ifaces if self.ifaces[n]["lan0"]["admin"]]
                master = max(up, key=lambda n: self.prio[n]) if up else None
                mode = "Init" if nepk not in up else "Master" if nepk == master else "Backup"
                return 200, [{"groupId": 10, "interface": "lan0", "priority": self.prio[nepk], "mode": mode,
                              "vipaddr": "10.0.0.1", "enable": "Up", "preempt": True}]
            if query.get("url") == "networkInterfaces":
                if method == "POST":
                    self.posts.append((nepk, body))
                    for row in body["ifInfo"]:
                        self.ifaces[nepk][row["ifname"]]["admin"] = bool(row["admin"])
                        self.ifaces[nepk][row["ifname"]]["oper"] = bool(row["admin"])
                    return 200, {}
                return 200, {"ifInfo": list(self.ifaces[nepk].values())}
        return 404, {"message": "no such resource"}


class FakePrime(_Server):
    """Prime with (or without) the span API, following autopod docs/SPAN-CHAOS-API.md."""

    def __init__(self, spans=True, users=None):
        super().__init__()
        self.spans_api = spans
        self.users = users or {"eng": "pw"}
        self.tokens = set()
        self.logins = 0
        self.state = {f"{s}:{k}": {"link": "up", "down": None, "up": None, "expires_at": None, "owner": None, "unknown": []}
                      for s in ("dal", "aus") for k in ("wan-a", "wan-b", "uplink-a", "xc")}
        self.legacy = []

    def _span(self, sid, probe=False):
        site, kind = sid.split(":")
        out = {"id": sid, "site": site, "site_name": site.title(), "role": "hub" if site == "dal" else "branch",
               "kind": kind.split("-")[0], "isp": "isp-a" if kind.endswith("-a") else None, "label": f"{site} {kind}",
               "a": {"device": f"{site}-ecv-01", "iface": "wan0"}, "b": {"device": f"{site}-isp-a", "iface": "eth1"},
               "directions": {"down": "ISP → EC-V", "up": "EC-V → ISP"}, "node": "node1", "state": self.state[sid]}
        if probe:
            st = self.state[sid]
            out["live"] = {"link": st["link"], "down": "netem" if st["down"] else None, "up": "netem" if st["up"] else None}
        return out

    def handle(self, method, path, query, body, headers):
        if path == "/api/v2/auth/login":
            self.logins += 1
            if self.users.get(body.get("username")) != body.get("password"):
                return 401, {"detail": "bad credentials"}
            token = f"session-{self.logins}"
            self.tokens.add(token)
            return 200, {"username": body["username"], "role": "eng", "token": token}
        if headers.get("Authorization", "")[7:] not in self.tokens:
            return 401, {"detail": "not authenticated"}
        if path == "/api/v1/labs/lab1":
            return 200, {"lab_id": "lab1", "features": {"spans": True} if self.spans_api else {},
                         "impairment_site_allowlist": ["dal"],
                         "sites": [{"code": "dal", "role": "hub"}, {"code": "aus", "role": "branch"},
                                   {"code": "rem", "role": "remote"}]}
        if path == "/api/v1/labs/lab1/control/wan-impairment":
            self.legacy.append(body)
            return 200, {"lab_id": "lab1", "output": "ok"}
        if not self.spans_api:
            return 404, {"detail": "Not Found"}
        if path == "/api/v1/labs/lab1/spans":
            return 200, {"lab_id": "lab1", "api": "spans/1", "max_ttl_s": 3600,
                         "spans": [self._span(s, query.get("probe") == "1") for s in self.state]}
        if path == "/api/v1/labs/lab1/spans/clear":
            active = [s for s, st in self.state.items() if st["down"] or st["up"] or st["link"] == "down"]
            for s in active:
                self.state[s].update(link="up", down=None, up=None, expires_at=None, owner=None)
            return 200, {"cleared": active, "errors": []}
        prefix = "/api/v1/labs/lab1/spans/"
        if path.startswith(prefix):
            sid, action = path[len(prefix):].rsplit("/", 1)
            if sid not in self.state:
                return 404, {"error": {"code": "SPAN_NOT_FOUND", "title": "No such span", "detail": f"{sid} is not a span of lab1"}}
            st = self.state[sid]
            if action == "impair":
                if not isinstance(body.get("ttl_s"), int) or isinstance(body.get("ttl_s"), bool):
                    return 400, {"error": {"code": "INVALID_SPAN_REQUEST", "detail": "ttl_s must be an integer"}}
                if set(body) - {"down", "up", "ttl_s", "owner"}:
                    return 400, {"error": {"code": "INVALID_SPAN_REQUEST", "detail": "unknown field"}}
                for d in ("down", "up"):
                    if d in body:
                        st[d] = body[d]
                st.update(expires_at="soon", owner=body.get("owner"))
            elif action == "link":
                st["link"] = body["state"]
                st.update(expires_at="soon" if body["state"] == "down" else None, owner=body.get("owner"))
            elif action == "clear":
                st.update(link="up", down=None, up=None, expires_at=None, owner=None, unknown=[])
            else:
                return 404, {"detail": "Not Found"}
            return 200, {"span": self._span(sid)}
        return 404, {"detail": "Not Found"}
