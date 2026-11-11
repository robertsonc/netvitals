"""Autopod lab fabric: impairments and link faults on the ISP containers, through Prime.

With a Prime that has the span API (`features.spans`), every span of the lab is a target: the
EC-V to ISP links, the ISP uplinks and the ISP cross-connect, each in either direction, with a
dead-man timer held by Prime itself. See autopod docs/SPAN-CHAOS-API.md.

Against an older Prime this falls back to the profile endpoint, which only reaches the sites
Prime's own allowlist permits, only shapes the ISP to EC-V direction, has no link-down and no
dead-man. The dashboard says which mode is in use.
"""
from __future__ import annotations

import logging
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from ..rest import Http, HttpError
from . import Driver, DriverError, Fault, Sleeper, Target

LOG = logging.getLogger(__name__)
OWNER = "chaoslab"

# The impairment menu. `spec` uses Prime's own field names (scripts/impairment_profiles.py).
PRESETS: List[Dict[str, Any]] = [
    {"id": "link-down", "label": "Link down", "kind": "down"},
    {"id": "blackhole", "label": "Blackhole (100% loss, carrier stays up)", "kind": "impair", "spec": {"loss_pct": 100}},
    {"id": "loss-2", "label": "2% loss", "kind": "impair", "spec": {"loss_pct": 2}},
    {"id": "loss-10", "label": "10% loss", "kind": "impair", "spec": {"loss_pct": 10}},
    {"id": "loss-30", "label": "30% loss", "kind": "impair", "spec": {"loss_pct": 30}},
    {"id": "delay-100", "label": "+100 ms delay, 10 ms jitter", "kind": "impair",
     "spec": {"delay_ms": 100, "jitter_ms": 10}},
    {"id": "delay-300", "label": "+300 ms delay, 30 ms jitter", "kind": "impair",
     "spec": {"delay_ms": 300, "jitter_ms": 30}},
    {"id": "brownout", "label": "Brownout (3% loss, +150 ms, 40 ms jitter)", "kind": "impair",
     "spec": {"loss_pct": 3, "delay_ms": 150, "jitter_ms": 40}},
    {"id": "rate-1m", "label": "Rate limit 1 Mbit/s", "kind": "impair", "spec": {"rate_kbit": 1000}},
]
DIRECTIONS = ("down", "up", "both")


class AutopodDriver(Driver):
    name = "autopod"
    label = "Autopod Prime"

    def __init__(self, url: str, lab: str, *, username: str = "", password: str = "", token: str = "",
                 http: Optional[Http] = None):
        self.url, self.lab = url.rstrip("/"), lab
        self.username, self._password, self._token = username, password, token
        self._static_token = bool(token)
        self.http = http or Http(self.url, timeout=45)   # Prime runs ssh to the node inside the request
        self.spans_api = False
        self.max_ttl = 3600
        self.lab_info: Dict[str, Any] = {}
        self._held: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._last_ok: Optional[float] = None
        self._last_error = ""

    # ----- transport -----

    def _login(self) -> None:
        if self._static_token:
            raise DriverError("Prime rejected the service token (does it carry the chaos grant for this lab?)")
        if not self.username:
            raise DriverError("no Prime credentials configured")
        try:
            out = self.http.request("POST", f"/api/v2/auth/login?lab={urllib.parse.quote(self.lab)}",
                                    {"username": self.username, "password": self._password})
        except HttpError as exc:
            raise DriverError(f"Prime login failed: {exc}")
        self._token = out.get("token", "")
        if not self._token:
            raise DriverError("Prime login answered without a token")

    def _call(self, method: str, path: str, body: Any = None, *, retries: int = 0) -> Any:
        for attempt in (0, 1):
            if not self._token:
                self._login()
            self.http.headers["Authorization"] = f"Bearer {self._token}"
            try:
                out = self.http.request(method, path, body, retries=retries)
                self._last_ok, self._last_error = time.time(), ""
                return out
            except HttpError as exc:
                if exc.status == 401 and attempt == 0 and not self._static_token:
                    self._token = ""        # session expired (12 h): log in again, once
                    continue
                self._last_error = str(exc)
                raise DriverError(str(exc))
        raise DriverError("Prime authentication failed")

    def _lab(self, suffix: str = "") -> str:
        return f"/api/v1/labs/{urllib.parse.quote(self.lab)}{suffix}"

    # ----- Driver -----

    def configured(self) -> bool:
        return bool(self.url and self.lab)

    def status(self) -> Dict[str, Any]:
        return {"driver": self.name, "label": self.label, "url": self.url, "lab": self.lab,
                "auth": "service token" if self._static_token else f"user {self.username}",
                "mode": "span API" if self.spans_api else "legacy profile endpoint",
                "lastOk": self._last_ok, "lastError": self._last_error}

    def probe(self) -> str:
        info = self._call("GET", self._lab(), retries=2)
        self.lab_info = info if isinstance(info, dict) else {}
        self.spans_api = bool((self.lab_info.get("features") or {}).get("spans"))
        sites = len(self.lab_info.get("sites") or [])
        mode = ("span API available: every span, both directions" if self.spans_api else
                "this Prime has no span API: limited to the sites its allowlist permits, ISP to EC-V direction only")
        return f"Connected to {self.lab} on Prime: {sites} site{'s' if sites != 1 else ''}; {mode}."

    def discover(self) -> List[Target]:
        self.probe()
        if self.spans_api:
            out = self._call("GET", self._lab("/spans"), retries=2)
            self.max_ttl = int(out.get("max_ttl_s") or 3600)
            targets = []
            for s in out.get("spans") or []:
                a, b = s.get("a") or {}, s.get("b") or {}
                targets.append(Target(
                    key=f"autopod:{self.lab}:{s['id']}", driver=self.name, kind="span", group=s.get("site", "?"),
                    name=s.get("label") or s["id"],
                    detail=f"{a.get('device', '?')}:{a.get('iface', '?')} ↔ {b.get('device', '?')}:{b.get('iface', '?')}",
                    meta={"span": s["id"], "site": s.get("site"), "role": s.get("role"), "span_kind": s.get("kind"),
                          "isp": s.get("isp"), "directions": s.get("directions") or {}, "legacy": False}))
            return targets
        # Legacy Prime: one target per ISP at each site the allowlist lets us reach individually.
        allow = self.lab_info.get("impairment_site_allowlist")
        sites = [s for s in self.lab_info.get("sites") or [] if s.get("role") != "remote"]
        if isinstance(allow, list):
            sites = [s for s in sites if s.get("code") in allow]
        targets = []
        for s in sites:
            for isp, letter, wan in (("isp-a", "a", "wan0"), ("isp-b", "b", "wan1")):
                targets.append(Target(
                    key=f"autopod:{self.lab}:{s['code']}:wan-{letter}", driver=self.name, kind="span",
                    group=s["code"], name=f"{s['code']} EC-V {wan} ↔ ISP-{letter.upper()}",
                    detail="legacy: ISP → EC-V only",
                    meta={"span": f"{s['code']}:wan-{letter}", "site": s["code"], "role": s.get("role"),
                          "span_kind": "wan", "isp": isp, "legacy": True}))
        return targets

    def faults(self, target: Target) -> List[Fault]:
        out = []
        for p in PRESETS:
            if p["kind"] == "down":
                if not target.meta.get("legacy"):
                    out.append(Fault(p["id"], p["label"], "down"))
                continue
            for direction in (("down",) if target.meta.get("legacy") else DIRECTIONS):
                out.append(Fault(p["id"], p["label"], "impair", dict(p["spec"]), direction))
        return out

    def inject(self, target: Target, fault: Fault, ttl_s: int) -> None:
        span, ttl = target.meta["span"], max(1, min(int(ttl_s), self.max_ttl))
        with self._lock:
            self._held[target.key] = f"{target.describe()}: {fault.label}"
        if target.meta.get("legacy"):
            self._call("POST", self._lab("/control/wan-impairment"),
                       {"scope": target.meta["site"], "spec": {target.meta["isp"]: fault.spec}})
            return
        path = self._lab(f"/spans/{urllib.parse.quote(span, safe=':')}")
        if fault.kind == "down":
            self._call("POST", path + "/link", {"state": "down", "ttl_s": ttl, "owner": OWNER})
            return
        body: Dict[str, Any] = {"ttl_s": ttl, "owner": OWNER}
        for direction in (("down", "up") if fault.direction == "both" else (fault.direction,)):
            body[direction] = fault.spec
        self._call("POST", path + "/impair", body)

    def restore(self, target: Target, fault: Fault) -> None:
        if target.meta.get("legacy"):
            # The old endpoint can only clear a whole site, both ISPs at once.
            self._call("POST", self._lab("/control/wan-impairment"),
                       {"scope": target.meta["site"], "profile": "clear"}, retries=2)
        else:
            self._call("POST", self._lab(f"/spans/{urllib.parse.quote(target.meta['span'], safe=':')}/clear"),
                       {}, retries=2)        # clear is idempotent on Prime, so it is safe to repeat
        with self._lock:
            self._held.pop(target.key, None)

    def verify(self, target: Target, fault: Fault, sleep: Sleeper) -> Tuple[bool, Dict[str, Any]]:
        if target.meta.get("legacy"):
            return True, {"recovery_seconds": 0.0, "note": "legacy Prime: state not read back"}
        started = time.time()
        out = self._call("GET", self._lab("/spans?probe=1"), retries=2)
        span = next((s for s in out.get("spans") or [] if s.get("id") == target.meta["span"]), None)
        if span is None:
            return False, {"reason": "Prime no longer lists this span"}
        state, live = span.get("state") or {}, span.get("live") or {}
        problems = []
        if state.get("link") not in (None, "up") or live.get("link") == "down":
            problems.append("link is still down")
        if state.get("down") or state.get("up") or live.get("down") or live.get("up"):
            problems.append("an impairment is still present")
        if state.get("unknown"):       # Prime could not vouch for these parts after a node command failed
            problems.append("Prime cannot confirm the state of: " + ", ".join(state["unknown"]))
        # A probe that could not read the node proves nothing either way; say so instead of passing it off.
        read_back = bool(live) and not live.get("error")
        facts = {"recovery_seconds": round(time.time() - started, 1), "read_back": read_back}
        if live.get("error"):
            facts["note"] = f"Prime could not read the node back: {live['error']}"
        if problems:
            facts["reason"] = "; ".join(problems)
        return not problems, facts

    def held(self) -> List[Dict[str, str]]:
        with self._lock:
            return [{"driver": self.name, "what": what, "how": "impaired"} for what in self._held.values()]

    def restore_all(self) -> List[str]:
        errors: List[str] = []
        with self._lock:
            keys = list(self._held)
        if not self.spans_api:
            for site in {k.split(":")[2] for k in keys}:
                try:
                    self._call("POST", self._lab("/control/wan-impairment"), {"scope": site, "profile": "clear"})
                except DriverError as exc:
                    errors.append(f"{site}: {exc}")
        else:
            try:
                out = self._call("POST", self._lab("/spans/clear"), {}, retries=2)
                errors += [f"{e.get('span')}: {e.get('error')}" for e in out.get("errors") or []]
            except DriverError as exc:
                errors.append(str(exc))
        if not errors:
            with self._lock:
                self._held.clear()
        return errors
