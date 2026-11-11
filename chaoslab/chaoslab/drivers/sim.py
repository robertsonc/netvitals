"""A simulated lab for `--demo`: nothing real is contacted.

It stands in for all three things the real tool talks to: an Orchestrator (WAN interfaces and a
VRRP pair), an autopod fabric (ISP spans) and a handful of endpoints running flows. The traffic
model is deliberately simple but causal: a fault changes what the simulated flows measure, with
the direction, the detection delay and the failover an SD-WAN edge would show, so the dashboard
can be explored and demonstrated end to end.

Every number it produces is invented. Do not read anything about a real fabric into it.
"""
from __future__ import annotations

import random
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from . import Driver, Fault, Sleeper, Target
from .autopod import DIRECTIONS, PRESETS

SITES = {  # code: (name, role, one-way latency to the core in ms)
    "dal": ("Dallas", "hub", 2.0), "lon": ("London", "hub", 38.0),
    "aus": ("Austin", "branch", 4.0), "chi": ("Chicago", "branch", 9.0), "par": ("Paris", "branch", 42.0),
}
HOSTS = {"dal": "linux", "lon": "linux", "aus": "windows", "chi": "linux", "par": "windows"}
LABELS = {"a": "INET1", "b": "INET2"}
SEVERE_LOSS, SEVERE_DELAY = 10.0, 250.0     # beyond these the simulated edge steers away
FAILBACK_S = 5.0


class SimLab(Driver):
    name = "sim"
    label = "Simulated lab"

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)
        self._lock = threading.Lock()
        self._faults: Dict[Tuple[str, str], Dict[str, Any]] = {}    # (site, transport) -> fault
        self._vrrp: Dict[str, Dict[str, Any]] = {}                  # site -> gateway failover
        self._held: Dict[str, str] = {}
        self._runs: Dict[int, Dict[str, Any]] = {}                  # leg -> outage tracking
        self._prev: Dict[int, Tuple[float, float]] = {}

    # ----- Driver -----

    def configured(self) -> bool:
        return True

    def status(self) -> Dict[str, Any]:
        return {"driver": self.name, "label": self.label, "url": "", "auth": "none",
                "mode": "simulation: nothing real is contacted", "lastOk": time.time(), "lastError": ""}

    def probe(self) -> str:
        return "Using the built-in simulated lab. Nothing real is contacted."

    def discover(self) -> List[Target]:
        time.sleep(0.4)
        out: List[Target] = []
        for site, (name, role, _) in SITES.items():
            for x, wan in (("a", "wan0"), ("b", "wan1")):
                out.append(Target(f"sim:wan:{site}:{x}", self.name, "wan", f"{site}-ecv-01",
                                  f"{wan} ({LABELS[x]})", f"198.51.100.{len(out) + 10}",
                                  {"site": site, "x": x, "label": LABELS[x]}))
            for x in ("a", "b"):
                out.append(Target(f"sim:span:{site}:wan-{x}", self.name, "span", site,
                                  f"{site} EC-V wan{'01'[x == 'b']} ↔ ISP-{x.upper()}",
                                  f"{site}-ecv-01:wan{'01'[x == 'b']} ↔ {site}-isp-{x}:eth1",
                                  {"site": site, "x": x, "span": f"{site}:wan-{x}", "role": role,
                                   "directions": {"down": f"ISP-{x.upper()} → EC-V", "up": f"EC-V → ISP-{x.upper()}"}}))
            if role == "hub":
                out.append(Target(f"sim:vrrp:{site}", self.name, "vrrp", f"{site}-ecv-01", "VRRP 10 on lan0",
                                  "priority 110 · VIP 10.0.0.1", {"site": site, "vrid": 10}))
        return out

    def faults(self, target: Target) -> List[Fault]:
        if target.kind != "span":
            return [Fault("admin-down", "Admin down", "down")]
        out = []
        for p in PRESETS:
            if p["kind"] == "down":
                out.append(Fault(p["id"], p["label"], "down"))
            else:
                out += [Fault(p["id"], p["label"], "impair", dict(p["spec"]), d) for d in DIRECTIONS]
        return out

    def inject(self, target: Target, fault: Fault, ttl_s: int) -> None:
        time.sleep(self._rng.uniform(0.05, 0.25))
        now, site = time.time(), target.meta["site"]
        with self._lock:
            if target.kind == "vrrp":
                self._vrrp[site] = {"t0": now, "t1": None, "fo": self._rng.uniform(1.2, 2.8),
                                    "back": self._rng.uniform(0.2, 0.6)}
            else:
                spec = fault.spec or {}
                dead = fault.kind == "down" or spec.get("loss_pct", 0) >= 100
                detect = self._rng.uniform(0.3, 0.9) if fault.kind == "down" else \
                    self._rng.uniform(0.7, 1.6) if dead else self._rng.uniform(1.8, 3.2)
                self._faults[(site, target.meta["x"])] = {
                    "t0": now, "t1": None, "down": fault.kind == "down", "spec": spec,
                    "dir": fault.direction or "both", "detect": detect,
                    "severe": dead or spec.get("loss_pct", 0) >= SEVERE_LOSS or spec.get("delay_ms", 0) >= SEVERE_DELAY}
            self._held[target.key] = f"{target.describe()}: {fault.label}"

    def after_inject(self, target: Target, fault: Fault, sleep: Sleeper) -> Dict[str, Any]:
        if target.kind != "vrrp":
            return {}
        fo = self._vrrp[target.meta["site"]]["fo"]
        sleep(fo)
        return {"failover_detected": True, "failover_seconds": round(fo, 1),
                "new_master": f"{target.meta['site']}-ecv-02"}

    def restore(self, target: Target, fault: Fault) -> None:
        time.sleep(self._rng.uniform(0.05, 0.25))
        now = time.time()
        with self._lock:
            if target.kind == "vrrp":
                if target.meta["site"] in self._vrrp:
                    self._vrrp[target.meta["site"]]["t1"] = now
            else:
                f = self._faults.get((target.meta["site"], target.meta["x"]))
                if f and f["t1"] is None:
                    f["t1"] = now
            self._held.pop(target.key, None)

    def verify(self, target: Target, fault: Fault, sleep: Sleeper) -> Tuple[bool, Dict[str, Any]]:
        if target.kind == "span":
            return True, {"recovery_seconds": 0.2, "read_back": True}
        if self._rng.random() < 0.06:       # now and then an interface is slow to come back
            sleep(8.0)
            return False, {"interface_recovered": False,
                           "reason": "interface did not become operational (simulated slow recovery)"}
        took = self._rng.uniform(2.0, 6.0)
        sleep(took)
        facts: Dict[str, Any] = {"interface_recovered": True, "recovery_seconds": round(took, 1)}
        if target.kind == "vrrp":
            sleep(3.0)
            facts.update(vrrp_stabilized=True, final_master=target.group, original_master_restored=True,
                         stabilize_seconds=3.0, preempt=True)
        return True, facts

    def held(self) -> List[Dict[str, str]]:
        with self._lock:
            return [{"driver": self.name, "what": w, "how": "simulated fault"} for w in self._held.values()]

    def restore_all(self) -> List[str]:
        now = time.time()
        with self._lock:
            for f in self._faults.values():
                f["t1"] = f["t1"] or now
            for v in self._vrrp.values():
                v["t1"] = v["t1"] or now
            self._held.clear()
        return []

    # ----- traffic model -----

    def _site(self, site: str, t: float) -> Tuple[bool, bool, float, float, float, float, float]:
        """What one site's WAN edge does to a packet at time t:
        (dead toward site, dead away from site, loss% in, loss% out, delay ms in, delay ms out, extra ms)."""
        v = self._vrrp.get(site)
        if v and (v["t0"] <= t < v["t0"] + v["fo"] or (v["t1"] and v["t1"] <= t < v["t1"] + v["back"])):
            return True, True, 0, 0, 0, 0, 0
        a, b = self._faults.get((site, "a")), self._faults.get((site, "b"))

        def active(f: Optional[Dict[str, Any]]) -> bool:
            return bool(f) and f["t0"] <= t and (f["t1"] is None or t < f["t1"])

        on_b = bool(a and a["severe"] and t >= a["t0"] + a["detect"] and (a["t1"] is None or t < a["t1"] + FAILBACK_S))
        if on_b and active(b) and b["severe"] and not active(a):
            on_b = False
        f, extra = (b, 7.0) if on_b else (a, 0.0)
        if not active(f):
            return False, False, 0, 0, 0, 0, extra
        if f["down"]:
            return True, True, 0, 0, 0, 0, extra
        spec, d = f["spec"], f["dir"]
        loss, delay = spec.get("loss_pct", 0.0), spec.get("delay_ms", 0.0)
        jit = spec.get("jitter_ms", 0.0)
        din = delay + self._rng.uniform(-jit, jit) if d in ("down", "both") else 0.0
        dout = delay + self._rng.uniform(-jit, jit) if d in ("up", "both") else 0.0
        return (False, False, loss if d in ("down", "both") else 0.0, loss if d in ("up", "both") else 0.0,
                max(0.0, din), max(0.0, dout), extra)

    def second(self, leg: int, src: str, dst: str, pps: float, sec: int) -> Tuple[Dict, Dict, List[Dict]]:
        """Simulate one sender-clock second of one leg. Returns (tx record, rx record, outage events)."""
        n = max(1, int(round(pps)))
        base = SITES[src][2] + SITES[dst][2]
        rtts: List[float] = []
        fwds: List[float] = []
        revs: List[float] = []
        fj = rj = 0.0
        jn = rx = 0
        events: List[Dict[str, Any]] = []
        run = self._runs.setdefault(leg, {"n": 0, "start": 0, "open": False})
        min_run = max(3, int(pps * 0.05 + 0.999))
        with self._lock:
            for i in range(n):
                t = sec + i / n
                s_dead_in, s_dead_out, s_li, s_lo, s_di, s_do, s_x = self._site(src, t)
                d_dead_in, d_dead_out, d_li, d_lo, d_di, d_do, d_x = self._site(dst, t)
                r = self._rng.random
                fwd_ok = not (s_dead_out or d_dead_in) and r() * 100 >= s_lo and r() * 100 >= d_li
                rev_ok = fwd_ok and not (d_dead_out or s_dead_in) and r() * 100 >= d_lo and r() * 100 >= s_li
                rx += fwd_ok
                if rev_ok:
                    fwd = base + s_x + d_x + s_do + d_di + abs(self._rng.gauss(0, 0.25))
                    rev = base + s_x + d_x + d_do + s_di + abs(self._rng.gauss(0, 0.25))
                    prev = self._prev.get(leg)
                    if prev:
                        fj, rj, jn = fj + abs(fwd - prev[0]), rj + abs(rev - prev[1]), jn + 1
                    self._prev[leg] = (fwd, rev)
                    rtts.append(fwd + rev)
                    fwds.append(fwd)
                    revs.append(rev)
                    if run["open"]:
                        events.append({"leg": leg, "start": run["start"], "end": int(t * 1e9), "lost": run["n"],
                                       "open": False})
                    run["n"], run["open"] = 0, False
                else:
                    if run["n"] == 0:
                        run["start"] = int(t * 1e9)
                    run["n"] += 1
                    if not run["open"] and run["n"] >= min_run:
                        run["open"] = True
                        events.append({"leg": leg, "start": run["start"], "end": 0, "lost": run["n"], "open": True})
        us = lambda v: int(v * 1000)                                      # noqa: E731
        rtts.sort()
        k = len(rtts)
        pct = lambda p: us(rtts[min(k - 1, max(0, (k * p + 99) // 100 - 1))]) if k else 0   # noqa: E731
        tx = {"leg": leg, "ts": sec, "sent": n, "rcv": k, "late": 0, "dup": 0, "reord": 0, "bytes": n * 200,
              "rtt": [us(rtts[0]) if k else 0, us(sum(rtts) / k) if k else 0, us(rtts[-1]) if k else 0,
                      pct(50), pct(95), pct(99)],
              "fwd": us(sum(fwds) / k) if k else 0, "rev": us(sum(revs) / k) if k else 0,
              "fj": us(fj / jn) if jn else 0, "rj": us(rj / jn) if jn else 0,
              "tj": us((fj + rj) / jn) if jn else 0, "retx": 0, "srtt": 0, "reconn": 0, "ttl": 61, "kts": 3}
        return tx, {"leg": leg, "ts": sec, "rx": rx, "dup": 0, "reord": 0}, events


def run_sim_fleet(lab: SimLab, fleet: Any) -> None:
    """Enrol the simulated endpoints, give them two flows, and feed measurements for ever."""
    ids: Dict[str, str] = {}
    for site, os_name in HOSTS.items():
        got = fleet.enroll({"token": fleet.join_token, "instance": f"sim-{site}-0000", "name": f"{site}-host",
                            "hostname": f"{site}-host", "os": os_name, "arch": "amd64", "version": "sim",
                            "addrs": [f"10.{list(SITES).index(site) + 1}.1.10"]}, "sim")
        ids[site] = got["agent_id"]
    site_of = {agent: site for site, agent in ids.items()}
    if not fleet.flows():
        fleet.create_flow({"name": "Voice hub to branches", "topology": "ptmp", "proto": "udp", "src": ids["dal"],
                           "dsts": [ids["aus"], ids["chi"], ids["par"]], "size": 200, "pps": 50, "dscp": 46})
        fleet.create_flow({"name": "Transactions lon to aus", "topology": "ptp", "proto": "tcp", "src": ids["lon"],
                           "dsts": [ids["aus"]], "size": 512, "pps": 20, "dscp": 18})

    def loop() -> None:
        done = int(time.time()) - 2
        while True:
            time.sleep(0.25)
            target = int(time.time()) - 2          # real agents trail real time by about this much too
            if target <= done:
                continue
            for agent in ids.values():
                fleet.store.run("UPDATE agents SET last_seen=? WHERE id=?", (time.time(), agent))
            for sec in range(done + 1, target + 1):
                for flow in fleet.flows():
                    if not flow["enabled"]:
                        continue
                    for leg in flow["legs"]:
                        src, dst = site_of.get(leg["src"]), site_of.get(leg["dst"])
                        if not src or not dst:
                            continue
                        tx, rx, events = lab.second(leg["id"], src, dst, flow["pps"], sec)
                        fleet.ingest(leg["src"], [tx], [], events)
                        fleet.ingest(leg["dst"], [], [rx], [])
            done = target
    threading.Thread(target=loop, daemon=True, name="sim-fleet").start()
