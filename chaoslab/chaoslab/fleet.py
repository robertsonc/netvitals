"""Endpoints and flows: enrolment, desired configuration, result ingest and the numbers derived from it."""
from __future__ import annotations

import ipaddress
import json
import logging
import secrets
import threading
import time
from typing import Any, Dict, List, Optional

from .store import Store

LOG = logging.getLogger(__name__)

ONLINE_WITHIN = 6.0          # seconds without a sync before an agent shows as offline
LIVE_KEEP = 900              # seconds of per-leg history held in memory for the charts
LIMITS = {"port": (1, 65535), "size": (44, 9000), "pps": (0.1, 50000), "dscp": (0, 63),
          "timeout_ms": (50, 10000)}
TOPOLOGIES = ("ptp", "ptmp", "mesh")
MAX_LEGS_PER_FLOW = 240


class FleetError(ValueError):
    """A request the fleet refuses; the message is shown to the operator."""


def _new_token() -> str:
    # Opaque and unsigned on purpose: it is looked up, never verified. Readable enough to retype.
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return "cm-" + "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))


class Fleet:
    def __init__(self, store: Store):
        self.store = store
        self._lock = threading.RLock()
        self.rev = int(time.time() * 1000)
        self._legs: Dict[int, Dict[str, Any]] = {}       # leg id -> {flow, src, dst}
        self._offset_ms: Dict[str, int] = {}             # agent id -> controller clock minus agent clock
        self._live: Dict[int, Dict[int, Dict[str, Any]]] = {}
        self._open: Dict[int, Dict[str, Any]] = {}       # leg -> outage still in progress
        if not store.get("join_token"):
            store.put("join_token", _new_token())
        self._reload()

    # ----- join token -----

    @property
    def join_token(self) -> str:
        return self.store.get("join_token")

    def rotate_token(self) -> str:
        token = _new_token()
        self.store.put("join_token", token)
        self.store.audit("JOIN_TOKEN_ROTATED", detail="agents already enrolled keep working")
        return token

    def token_ok(self, token: Any) -> bool:
        return isinstance(token, str) and secrets.compare_digest(token.encode(), self.join_token.encode())

    # ----- agents -----

    def _reload(self) -> None:
        with self._lock:
            self._legs = {r["id"]: {"flow": r["flow_id"], "src": r["src"], "dst": r["dst"]}
                          for r in self.store.rows("SELECT * FROM legs")}
            self._offset_ms = {r["id"]: r["offset_ns"] // 1_000_000
                               for r in self.store.rows("SELECT id, offset_ns FROM agents")}
            self.rev = max(self.rev + 1, int(time.time() * 1000))

    @staticmethod
    def _clean_addrs(raw: Any) -> List[str]:
        out = []
        for a in raw if isinstance(raw, list) else []:
            try:
                out.append(str(ipaddress.IPv4Address(a)))
            except (ipaddress.AddressValueError, TypeError):
                continue
        return out[:32]

    def enroll(self, data: Dict[str, Any], remote: str) -> Dict[str, str]:
        if not self.token_ok(data.get("token")):
            raise PermissionError("unknown join token: copy the install command from the dashboard again")
        instance = str(data.get("instance") or "")[:64]
        if len(instance) < 8:
            raise FleetError("enrolment needs an instance id")
        addrs = self._clean_addrs(data.get("addrs"))
        name = str(data.get("name") or data.get("hostname") or "endpoint")[:60].strip() or "endpoint"
        now = time.time()
        with self._lock:
            row = self.store.one("SELECT * FROM agents WHERE instance=?", (instance,))
            if row:      # a reinstall keeps its identity, its flows and its history
                key = secrets.token_urlsafe(24)
                self.store.run("UPDATE agents SET key=?, hostname=?, os=?, arch=?, version=?, addrs=?, remote=?, "
                               "last_seen=? WHERE id=?",
                               (key, str(data.get("hostname", ""))[:120], str(data.get("os", ""))[:20],
                                str(data.get("arch", ""))[:20], str(data.get("version", ""))[:20],
                                json.dumps(addrs), remote, now, row["id"]))
                self.store.audit("AGENT_REENROLLED", target=row["name"], detail=f"from {remote}")
                return {"agent_id": row["id"], "key": key, "name": row["name"]}
            taken = {r["name"] for r in self.store.rows("SELECT name FROM agents")}
            base, n = name, 2
            while name in taken:
                name, n = f"{base}-{n}", n + 1
            agent_id, key = "a" + secrets.token_hex(4), secrets.token_urlsafe(24)
            test_addr = remote if remote in addrs else (addrs[0] if addrs else "")
            self.store.run("INSERT INTO agents(id, key, instance, name, hostname, os, arch, version, addrs, test_addr, "
                           "remote, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (agent_id, key, instance, name, str(data.get("hostname", ""))[:120],
                            str(data.get("os", ""))[:20], str(data.get("arch", ""))[:20],
                            str(data.get("version", ""))[:20], json.dumps(addrs), test_addr, remote, now, now))
            self.store.audit("AGENT_ENROLLED", target=name, detail=f"{data.get('os')}/{data.get('arch')} from {remote}")
            self._reload()
            return {"agent_id": agent_id, "key": key, "name": name}

    def authenticate(self, agent_id: Any, key: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(agent_id, str) or not isinstance(key, str):
            return None
        row = self.store.one("SELECT * FROM agents WHERE id=?", (agent_id,))
        if row and secrets.compare_digest(row["key"].encode(), key.encode()):
            return row
        return None

    def agents(self) -> List[Dict[str, Any]]:
        now, out = time.time(), []
        for r in self.store.rows("SELECT * FROM agents ORDER BY name"):
            status = json.loads(r["status"] or "{}")
            out.append({"id": r["id"], "name": r["name"], "hostname": r["hostname"], "os": r["os"], "arch": r["arch"],
                        "version": r["version"], "addrs": json.loads(r["addrs"]), "testAddr": r["test_addr"],
                        "pinned": bool(r["pinned"]), "remote": r["remote"], "firstSeen": r["first_seen"],
                        "lastSeen": r["last_seen"], "online": now - (r["last_seen"] or 0) < ONLINE_WITHIN,
                        "offsetMs": r["offset_ns"] // 1_000_000, "kernelTs": status.get("kernel_ts"),
                        "clock": status.get("clock"), "backlog": status.get("backlog", 0),
                        "problems": status.get("problems") or [], "legProblems": status.get("legs") or {},
                        "noDscp": status.get("no_dscp") or [], "orphaned": status.get("orphaned", False)})
        return out

    def update_agent(self, agent_id: str, data: Dict[str, Any]) -> None:
        row = self.store.one("SELECT * FROM agents WHERE id=?", (agent_id,))
        if not row:
            raise FleetError("unknown endpoint")
        if "name" in data:
            name = str(data["name"]).strip()[:60]
            if not name:
                raise FleetError("a name is required")
            if self.store.one("SELECT 1 FROM agents WHERE name=? AND id<>?", (name, agent_id)):
                raise FleetError(f"another endpoint is already called {name}")
            self.store.run("UPDATE agents SET name=? WHERE id=?", (name, agent_id))
        if "testAddr" in data:
            addr = str(data["testAddr"]).strip()
            try:
                addr = str(ipaddress.IPv4Address(addr))
            except ipaddress.AddressValueError:
                raise FleetError(f"{addr!r} is not an IPv4 address")
            # Pinned: senders bind to it, so traffic leaves by the data NIC on a multi-homed host.
            self.store.run("UPDATE agents SET test_addr=?, pinned=1 WHERE id=?", (addr, agent_id))
        self._reload()

    def remove_agent(self, agent_id: str) -> None:
        row = self.store.one("SELECT name FROM agents WHERE id=?", (agent_id,))
        if not row:
            raise FleetError("unknown endpoint")
        used = [f["name"] for f in self.flows() if agent_id == f["src"] or agent_id in f["dsts"]]
        if used:
            raise FleetError(f"{row['name']} is used by flow {used[0]!r}: delete the flow first")
        self.store.run("DELETE FROM agents WHERE id=?", (agent_id,))
        self.store.audit("AGENT_REMOVED", target=row["name"])
        self._reload()

    # ----- flows -----

    def flows(self) -> List[Dict[str, Any]]:
        legs: Dict[int, List[Dict[str, Any]]] = {}
        for r in self.store.rows("SELECT * FROM legs ORDER BY id"):
            legs.setdefault(r["flow_id"], []).append({"id": r["id"], "src": r["src"], "dst": r["dst"]})
        out = []
        for r in self.store.rows("SELECT * FROM flows ORDER BY id"):
            out.append({"id": r["id"], "name": r["name"], "topology": r["topology"], "proto": r["proto"],
                        "src": r["src"], "dsts": json.loads(r["dsts"]), "port": r["port"], "size": r["size"],
                        "pps": r["pps"], "dscp": r["dscp"], "minEcho": bool(r["min_echo"]),
                        "timeoutMs": r["timeout_ms"], "enabled": bool(r["enabled"]), "legs": legs.get(r["id"], [])})
        return out

    @staticmethod
    def _number(data: Dict[str, Any], key: str, default: Any, kind: type = int) -> Any:
        raw = data.get(key, default)
        if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
            raise FleetError(f"'{key}' must be a number")
        try:
            value = kind(raw)
        except (TypeError, ValueError):
            raise FleetError(f"'{key}' must be a number")
        lo, hi = LIMITS[key]
        if not lo <= value <= hi:
            raise FleetError(f"'{key}' must be between {lo} and {hi}")
        return value

    def create_flow(self, data: Dict[str, Any]) -> int:
        name = str(data.get("name") or "").strip()[:60]
        if not name:
            raise FleetError("give the flow a name")
        topology, proto = data.get("topology", "ptp"), data.get("proto", "udp")
        if topology not in TOPOLOGIES:
            raise FleetError("'topology' must be ptp, ptmp or mesh")
        if proto not in ("udp", "tcp"):
            raise FleetError("'proto' must be udp or tcp")
        known = {a["id"] for a in self.agents()}
        src, dsts = data.get("src"), data.get("dsts")
        if src not in known:
            raise FleetError("choose a source endpoint")
        if not isinstance(dsts, list) or not dsts or any(d not in known for d in dsts):
            raise FleetError("choose at least one destination endpoint")
        dsts = list(dict.fromkeys(d for d in dsts if d != src))
        if not dsts:
            raise FleetError("the destination must be a different endpoint from the source")
        if topology == "ptp" and len(dsts) != 1:
            raise FleetError("a point-to-point flow has exactly one destination")
        port = self._number(data, "port", 30200)
        size = self._number(data, "size", 200)
        pps = self._number(data, "pps", 50, float)
        dscp = self._number(data, "dscp", 0)
        timeout = self._number({"timeout_ms": data.get("timeoutMs", data.get("timeout_ms", 1000))},
                               "timeout_ms", 1000)
        if proto == "udp" and size > 1472 and not data.get("allowFragments"):
            raise FleetError("UDP payloads above 1472 bytes fragment on a 1500-byte path. "
                             "Tick 'allow jumbo' if the path carries jumbo frames.")
        members = [src] + dsts
        pairs = ([(a, b) for a in members for b in members if a != b] if topology == "mesh"
                 else [(src, d) for d in dsts])
        if len(pairs) > MAX_LEGS_PER_FLOW:
            raise FleetError(f"that is {len(pairs)} legs; the limit per flow is {MAX_LEGS_PER_FLOW}")
        with self._lock:
            cur = self.store.run(
                "INSERT INTO flows(name, topology, proto, src, dsts, port, size, pps, dscp, min_echo, timeout_ms, "
                "enabled, created) VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?)",
                (name, topology, proto, src, json.dumps(dsts), port, size, pps, dscp,
                 int(bool(data.get("minEcho"))), timeout, time.time()))
            flow_id = cur.lastrowid
            self.store.many("INSERT INTO legs(flow_id, src, dst) VALUES(?,?,?)", [(flow_id, a, b) for a, b in pairs])
            self.store.audit("FLOW_CREATED", target=name, detail=f"{topology} {proto} {size}B x {pps:g} pps, "
                                                                 f"{len(pairs)} leg(s)")
            self._reload()
        return flow_id

    def set_flow_enabled(self, flow_id: int, enabled: bool) -> None:
        if not self.store.one("SELECT 1 FROM flows WHERE id=?", (flow_id,)):
            raise FleetError("unknown flow")
        self.store.run("UPDATE flows SET enabled=? WHERE id=?", (int(enabled), flow_id))
        self._reload()

    def delete_flow(self, flow_id: int) -> None:
        row = self.store.one("SELECT name FROM flows WHERE id=?", (flow_id,))
        if not row:
            raise FleetError("unknown flow")
        with self._lock:
            self.store.run("DELETE FROM legs WHERE flow_id=?", (flow_id,))
            self.store.run("DELETE FROM flows WHERE id=?", (flow_id,))
            self.store.audit("FLOW_DELETED", target=row["name"])
            self._reload()

    def leg_names(self) -> Dict[int, Dict[str, Any]]:
        """leg id -> names for display."""
        names = {a["id"]: a["name"] for a in self.agents()}
        out = {}
        for f in self.flows():
            for leg in f["legs"]:
                out[leg["id"]] = {"flow": f["name"], "flowId": f["id"], "proto": f["proto"], "pps": f["pps"],
                                  "src": names.get(leg["src"], "?"), "dst": names.get(leg["dst"], "?"),
                                  "srcId": leg["src"], "dstId": leg["dst"]}
        return out

    def config_for(self, agent_id: str) -> Dict[str, Any]:
        agents = {a["id"]: a for a in self.agents()}
        send, reflect = [], []
        for f in self.flows():
            if not f["enabled"]:
                continue
            for leg in f["legs"]:
                if leg["src"] == agent_id:
                    dst = agents.get(leg["dst"])
                    if not dst or not dst["testAddr"]:
                        continue
                    me = agents[agent_id]
                    send.append({"leg": leg["id"], "proto": f["proto"], "dst": dst["testAddr"], "port": f["port"],
                                 "size": f["size"], "pps": f["pps"], "dscp": f["dscp"],
                                 "timeout_ms": f["timeoutMs"], "min_echo": f["minEcho"],
                                 "bind": me["testAddr"] if me["pinned"] else ""})
                if leg["dst"] == agent_id:
                    reflect.append({"leg": leg["id"], "proto": f["proto"], "port": f["port"], "dscp": f["dscp"]})
        return {"rev": self.rev, "send": send, "reflect": reflect}

    # ----- ingest -----

    def sync(self, agent: Dict[str, Any], data: Dict[str, Any], remote: str) -> Dict[str, Any]:
        t_recv = time.time_ns()
        agent_id = agent["id"]
        status = data.get("status") if isinstance(data.get("status"), dict) else {}
        offset_ns = int(data.get("ctl_offset_ns") or 0)
        with self._lock:
            self._offset_ms[agent_id] = offset_ns // 1_000_000
        self.store.run("UPDATE agents SET last_seen=?, offset_ns=?, status=?, addrs=?, version=?, remote=? WHERE id=?",
                       (time.time(), offset_ns, json.dumps(status)[:8000],
                        json.dumps(self._clean_addrs(status.get("addrs"))), str(status.get("version", ""))[:20],
                        remote, agent_id))
        self.ingest(agent_id, data.get("tx") or [], data.get("rx") or [], data.get("events") or [])
        out: Dict[str, Any] = {"t_recv": t_recv, "cfg_rev": self.rev, "sync_ms": 1000}
        if data.get("cfg_rev") != self.rev:
            out["cfg"] = self.config_for(agent_id)
        out["t_reply"] = time.time_ns()
        return out

    def ingest(self, agent_id: str, tx: List[Any], rx: List[Any], events: List[Any]) -> None:
        """Store what an agent measured. Records for legs the agent is not part of are dropped."""
        with self._lock:
            legs, offsets = self._legs, dict(self._offset_ms)
        tx_rows, rx_rows, ev_rows = [], [], []
        for r in tx:
            leg = legs.get(r.get("leg")) if isinstance(r, dict) else None
            if not leg or leg["src"] != agent_id:
                continue
            try:
                rtt = [int(v) for v in r["rtt"]]
                row = {"leg": int(r["leg"]), "ts": int(r["ts"]), "sent": int(r["sent"]), "rcv": int(r["rcv"]),
                       "late": int(r.get("late", 0)), "dup": int(r.get("dup", 0)), "reord": int(r.get("reord", 0)),
                       "bytes": int(r.get("bytes", 0)), "rtt_min": rtt[0], "rtt_avg": rtt[1], "rtt_max": rtt[2],
                       "rtt_p50": rtt[3], "rtt_p95": rtt[4], "rtt_p99": rtt[5], "fwd": int(r.get("fwd", 0)),
                       "rev": int(r.get("rev", 0)), "fj": int(r.get("fj", 0)), "rj": int(r.get("rj", 0)),
                       "tj": int(r.get("tj", 0)), "retx": int(r.get("retx", 0)), "srtt": int(r.get("srtt", 0)),
                       "reconn": int(r.get("reconn", 0)), "ttl": int(r.get("ttl", 0)), "kts": int(r.get("kts", 0))}
            except (KeyError, TypeError, ValueError, IndexError):
                continue
            row["ts_ms"] = row["ts"] * 1000 + offsets.get(agent_id, 0)
            tx_rows.append(row)
        for r in rx:
            leg = legs.get(r.get("leg")) if isinstance(r, dict) else None
            if not leg or leg["dst"] != agent_id:
                continue
            try:
                row = {"leg": int(r["leg"]), "ts": int(r["ts"]), "rx": int(r["rx"]), "dup": int(r.get("dup", 0)),
                       "reord": int(r.get("reord", 0))}
            except (KeyError, TypeError, ValueError):
                continue
            row["ts_ms"] = row["ts"] * 1000 + offsets.get(leg["src"], 0)     # keyed by the SENDER's clock
            rx_rows.append(row)
        for e in events:
            leg = legs.get(e.get("leg")) if isinstance(e, dict) else None
            if not leg or leg["src"] != agent_id:
                continue
            try:
                start, end = int(e["start"]), int(e.get("end") or 0)
                off = offsets.get(agent_id, 0)
                ev_rows.append({"leg": int(e["leg"]), "start_ns": start, "start_ms": start // 1_000_000 + off,
                                "end_ms": (end // 1_000_000 + off) if end else None, "lost": int(e.get("lost", 0)),
                                "open": bool(e.get("open"))})
            except (KeyError, TypeError, ValueError):
                continue
        if tx_rows:
            self.store.add_tx(tx_rows)
        if rx_rows:
            self.store.add_rx(rx_rows)
        if ev_rows:
            self.store.add_outages(ev_rows)
        with self._lock:
            for row in tx_rows:
                self._live_row(row["leg"], row["ts"], row["ts_ms"]).update(row)
            for row in rx_rows:
                self._live_row(row["leg"], row["ts"], row["ts_ms"]).update(
                    {"rx": row["rx"], "rx_dup": row["dup"], "rx_reord": row["reord"]})
            for ev in ev_rows:
                if ev["open"]:
                    self._open[ev["leg"]] = ev
                else:
                    self._open.pop(ev["leg"], None)

    def _live_row(self, leg: int, ts: int, ts_ms: int) -> Dict[str, Any]:
        series = self._live.setdefault(leg, {})
        row = series.get(ts)
        if row is None:
            row = series[ts] = {"ts": ts, "ts_ms": ts_ms}
            if len(series) > LIVE_KEEP + 60:
                for k in sorted(series)[:60]:
                    del series[k]
        return row

    def _recent(self, leg: int) -> List[Dict[str, Any]]:
        series = self._live.get(leg, {})
        return [series[k] for k in sorted(series)]

    # ----- derived numbers -----

    @staticmethod
    def point(row: Dict[str, Any]) -> Optional[List[Any]]:
        """One chart point: [ms, loss %, fwd loss %, rev loss %, rtt ms, p99 ms, fwd jitter ms, rev jitter ms,
        fwd delay ms, rev delay ms, sent]. Direction split is None until the reflector's row arrives."""
        sent = row.get("sent")
        if not sent:
            return None
        rcv = row.get("rcv") or 0
        loss = 100.0 * (sent - rcv) / sent
        fwd = rev = None
        if row.get("rx") is not None:
            fwd = 100.0 * max(0, sent - row["rx"]) / sent
            rev = 100.0 * max(0, min(row["rx"], sent) - rcv) / sent
        has = rcv > 0
        ms = lambda key: round(row.get(key, 0) / 1000.0, 3) if has else None      # noqa: E731
        return [row["ts_ms"], round(loss, 2), None if fwd is None else round(fwd, 2),
                None if rev is None else round(rev, 2), ms("rtt_avg"), ms("rtt_p99"), ms("fj"), ms("rj"),
                ms("fwd"), ms("rev"), sent]

    def series(self, window_s: int) -> Dict[int, List[List[Any]]]:
        cutoff = int((time.time() - window_s) * 1000)
        with self._lock:
            return {leg: [p for p in (self.point(r) for r in self._recent(leg) if r["ts_ms"] >= cutoff) if p]
                    for leg in self._live}

    def latest(self, seconds: int = 5) -> Dict[int, Dict[str, Any]]:
        """Per leg: the last few seconds summarised, for the table and the tiles."""
        now_ms = int(time.time() * 1000)
        out: Dict[int, Dict[str, Any]] = {}
        with self._lock:
            for leg in self._live:
                recent = [r for r in self._recent(leg)[-(seconds + 6):] if r.get("sent")]
                recent = [r for r in recent if now_ms - r["ts_ms"] < (seconds + 5) * 1000][-seconds:]
                if not recent:
                    out[leg] = {"stale": True, "down": self._open.get(leg)}
                    continue
                out[leg] = dict(summarise(recent), stale=False, age_ms=now_ms - recent[-1]["ts_ms"],
                                down=self._open.get(leg))
        return out

    def window(self, t0_ms: int, t1_ms: int) -> Dict[int, Dict[str, Any]]:
        """Per leg: everything measured between two controller-clock instants."""
        out: Dict[int, List[Dict[str, Any]]] = {}
        for r in self.store.rows("SELECT * FROM samples WHERE ts_ms >= ? AND ts_ms < ? AND sent IS NOT NULL "
                                 "ORDER BY ts", (t0_ms, t1_ms)):
            out.setdefault(r["leg"], []).append(r)
        return {leg: summarise(rows) for leg, rows in out.items()}

    def outages(self, t0_ms: int, t1_ms: int) -> Dict[int, List[Dict[str, Any]]]:
        """Per leg: interruptions that overlap the window. Open ones run to `t1_ms`."""
        out: Dict[int, List[Dict[str, Any]]] = {}
        for r in self.store.rows("SELECT * FROM outages WHERE start_ms < ? AND (end_ms IS NULL OR end_ms > ?) "
                                 "ORDER BY start_ms", (t1_ms, t0_ms)):
            end = r["end_ms"] if r["end_ms"] is not None else t1_ms
            out.setdefault(r["leg"], []).append({"start": r["start_ms"], "end": r["end_ms"], "open": bool(r["open"]),
                                                 "lost": r["lost"], "ms": max(0, end - r["start_ms"])})
        return out


def summarise(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Collapse per-second rows into one set of numbers. Means are weighted by packets answered;
    percentiles of percentiles are not meaningful, so the tail is reported as the worst second's p99."""
    sent = sum(r["sent"] or 0 for r in rows)
    rcv = sum(r["rcv"] or 0 for r in rows)
    split = [r for r in rows if r.get("rx") is not None]
    split_sent = sum(r["sent"] or 0 for r in split)
    fwd_lost = sum(max(0, (r["sent"] or 0) - r["rx"]) for r in split)
    rev_lost = sum(max(0, min(r["rx"], r["sent"] or 0) - (r["rcv"] or 0)) for r in split)

    def mean(key: str) -> Optional[float]:
        return round(sum((r.get(key) or 0) * (r["rcv"] or 0) for r in rows) / rcv / 1000.0, 3) if rcv else None

    answered = [r for r in rows if r["rcv"]]
    retx = [r["retx"] for r in rows if (r.get("retx") or 0) > 0]
    return {
        "seconds": len(rows), "sent": sent, "rcv": rcv, "lost": sent - rcv,
        "loss": round(100.0 * (sent - rcv) / sent, 3) if sent else None,
        "fwdLoss": round(100.0 * fwd_lost / split_sent, 3) if split_sent else None,
        "revLoss": round(100.0 * rev_lost / split_sent, 3) if split_sent else None,
        "rtt": mean("rtt_avg"), "rttMin": round(min(r["rtt_min"] for r in answered) / 1000.0, 3) if answered else None,
        "rttP99": round(max(r["rtt_p99"] for r in answered) / 1000.0, 3) if answered else None,
        "rttMax": round(max(r["rtt_max"] for r in answered) / 1000.0, 3) if answered else None,
        "fwd": mean("fwd"), "rev": mean("rev"), "fwdJit": mean("fj"), "revJit": mean("rj"), "jit": mean("tj"),
        "late": sum(r.get("late") or 0 for r in rows), "dup": sum(r.get("dup") or 0 for r in rows),
        "reord": sum(r.get("reord") or 0 for r in rows), "retx": sum(retx),
        "reconn": sum(r.get("reconn") or 0 for r in rows),
        "bps": round(8.0 * sum(r.get("bytes") or 0 for r in rows) / len(rows)) if rows else 0,
        "kts": min((r.get("kts") or 0) for r in rows) if rows else 0,
    }
