"""HPE Aruba EdgeConnect Orchestrator: WAN interface and VRRP master faults.

Ported from SD-WAN Chaos Monkey. The API surface is unchanged and deliberately small:

    GET  /gms/rest/appliance
    GET  /gms/rest/deployment?nePk=
    GET  /gms/rest/appliance/rest?nePk=&url=networkInterfaces
    POST /gms/rest/appliance/rest?nePk=&url=networkInterfaces      (the only write)
    GET  /gms/rest/appliance/rest?nePk=&url=vrrp&cached=false

The write is a full-state replace of the appliance's interface list with one admin flag changed,
which keeps MAC and label fields intact on virtual appliances and makes a replay harmless.
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
LINK_LOCAL = "169.254."
DOWN = Fault("admin-down", "Admin down", "down")


def _list(result: Any, keys: Tuple[str, ...], single: str) -> List[Dict[str, Any]]:
    if isinstance(result, list):
        return [r for r in result if isinstance(r, dict)]
    if isinstance(result, dict):
        for key in keys:
            if isinstance(result.get(key), list):
                return [r for r in result[key] if isinstance(r, dict)]
        if single in result:
            return [result]
    return []


class OrchestratorDriver(Driver):
    name = "orchestrator"
    label = "EdgeConnect Orchestrator"
    VERIFY_EVERY = 2.0

    def __init__(self, url: str, *, token: str = "", username: str = "", password: str = "",
                 query_auth: bool = False, verify_tls: bool = True, http: Optional[Http] = None):
        self.url = url.rstrip("/")
        headers, query, basic = {}, {}, None
        if token and query_auth:
            query["apiKey"] = token
        elif token:
            headers["X-Auth-Token"] = token
        elif username:
            basic = (username, password)
        self.auth = "API key (query)" if query else "API key" if token else "basic" if username else "none"
        self.verify_tls = verify_tls
        self.http = http or Http(self.url, headers=headers, query=query, basic=basic, verify_tls=verify_tls,
                                 timeout=30)
        self._names: Dict[str, str] = {}
        self._held: Dict[Tuple[str, str], str] = {}     # (nePk, ifname) -> description
        self._lock = threading.Lock()
        self._last_ok: Optional[float] = None
        self._last_error = ""

    # ----- transport -----

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        try:
            # GETs are safe to repeat; so is the POST, because it is a full-state write.
            out = self.http.request(method, path, body, retries=3)
            self._last_ok, self._last_error = time.time(), ""
            return out
        except HttpError as exc:
            self._last_error = str(exc)
            raise DriverError(str(exc))

    def _interfaces(self, nepk: str) -> Dict[str, Any]:
        return self._call("GET", f"/gms/rest/appliance/rest?nePk={urllib.parse.quote(nepk)}&url=networkInterfaces")

    def _iface(self, nepk: str, ifname: str) -> Optional[Dict[str, Any]]:
        for row in _list(self._interfaces(nepk), ("interfaces", "ifInfo"), "ifname"):
            if ifname in (row.get("ifname"), row.get("name"), row.get("interface")):
                return row
        return None

    def _vrrp(self, nepk: str) -> List[Dict[str, Any]]:
        out = self._call("GET", f"/gms/rest/appliance/rest?nePk={urllib.parse.quote(nepk)}&url=vrrp&cached=false")
        return _list(out, (), "groupId")

    def _vrrp_group(self, nepk: str, vrid: int) -> Optional[Dict[str, Any]]:
        return next((g for g in self._vrrp(nepk) if g.get("groupId") == vrid), None)

    def _set_admin(self, nepk: str, ifname: str, up: bool, what: str) -> None:
        path = f"/gms/rest/appliance/rest?nePk={urllib.parse.quote(nepk)}&url=networkInterfaces"
        state = self._call("GET", path)
        if not isinstance(state, dict) or not isinstance(state.get("ifInfo"), list):
            raise DriverError(f"could not read the interface list of {self._names.get(nepk, nepk)}")
        row = next((r for r in state["ifInfo"] if isinstance(r, dict) and r.get("ifname") == ifname), None)
        if row is None:
            raise DriverError(f"{ifname} is not in the interface list of {self._names.get(nepk, nepk)}")
        row["admin"] = up
        self._call("POST", path, state)
        with self._lock:
            if up:
                self._held.pop((nepk, ifname), None)
            else:
                self._held[(nepk, ifname)] = what

    # ----- Driver -----

    def configured(self) -> bool:
        return bool(self.url)

    def status(self) -> Dict[str, Any]:
        return {"driver": self.name, "label": self.label, "url": self.url, "auth": self.auth,
                "verifyTls": self.verify_tls, "lastOk": self._last_ok, "lastError": self._last_error}

    def probe(self) -> str:
        """One read-only call. Returns a sentence for the operator, raises DriverError otherwise."""
        count = len(_list(self._call("GET", "/gms/rest/appliance"), ("appliances", "nodes", "data", "items"), "nePk"))
        host = urllib.parse.urlsplit(self.url).netloc
        return f"Connected to {host}: {count} appliance{'s' if count != 1 else ''} visible."

    def discover(self) -> List[Target]:
        targets: List[Target] = []
        rows = _list(self._call("GET", "/gms/rest/appliance"), ("appliances", "nodes", "data", "items"), "nePk")
        self._names = {}
        for row in rows:
            nepk = str(row.get("nePk") or "")
            if not nepk:
                continue
            host = row.get("hostName") or f"Appliance-{nepk}"
            site = row.get("site") or ""
            self._names[nepk] = host
            try:
                deployment = self._call("GET", f"/gms/rest/deployment?nePk={urllib.parse.quote(nepk)}")
            except DriverError as exc:
                LOG.warning("no deployment data for %s: %s", host, exc)
                deployment = {}
            labels = {str(lbl.get("id", "")): lbl.get("name", "")
                      for lbl in ((deployment.get("sysConfig") or {}).get("ifLabels") or {}).get("wan", [])}
            for mode_if in deployment.get("modeIfs", []) or []:
                for ip in mode_if.get("applianceIPs", []) or []:
                    address = ip.get("ip", "")
                    if not ip.get("wanSide") or address.startswith(LINK_LOCAL):
                        continue
                    ifname = mode_if.get("ifName", "")
                    if ip.get("vlan"):
                        ifname = f"{ifname}.{ip['vlan']}"
                    label_id = str(ip.get("label", ""))
                    label = labels.get(label_id) or (f"WAN-{label_id}" if label_id else "WAN")
                    targets.append(Target(
                        key=f"orch:wan:{nepk}:{ifname}", driver=self.name, kind="wan", group=host,
                        name=f"{ifname} ({label})", detail=address,
                        meta={"nepk": nepk, "ifname": ifname, "label": label, "ip": address, "site": site}))
            try:
                groups = self._vrrp(nepk)
            except DriverError as exc:
                LOG.warning("no VRRP data for %s: %s", host, exc)
                groups = []
            for g in groups:
                vrid, ifname = g.get("groupId"), g.get("interface", "")
                if vrid is None or not ifname or str(g.get("enable", "")).lower() != "up":
                    continue
                if str(g.get("mode", "")).upper() != "MASTER":
                    continue        # only the current master can be failed over
                targets.append(Target(
                    key=f"orch:vrrp:{nepk}:{vrid}", driver=self.name, kind="vrrp", group=host,
                    name=f"VRRP {vrid} on {ifname}", detail=f"priority {g.get('priority', '?')} · VIP {g.get('vipaddr', '?')}",
                    meta={"nepk": nepk, "ifname": ifname, "vrid": vrid, "site": site,
                          "priority": g.get("priority")}))
        return targets

    def faults(self, target: Target) -> List[Fault]:
        return [DOWN]

    def precheck(self, target: Target, fault: Fault) -> Tuple[bool, str]:
        nepk, ifname = target.meta["nepk"], target.meta["ifname"]
        if target.kind == "vrrp":
            group = self._vrrp_group(nepk, target.meta["vrid"])
            mode = str((group or {}).get("mode", "unavailable")).upper()
            if mode != "MASTER":
                return False, f"VRRP instance is not MASTER (it is {mode})"
            ifname = group.get("interface", ifname)
            target.meta["ifname"] = ifname
            target.meta["preempt"] = bool(group.get("preempt", False))
        row = self._iface(nepk, ifname)
        if row is None:
            return False, f"could not read the state of {ifname}"
        if not (row.get("admin") and row.get("oper")):
            return False, f"{ifname} is not up before the test (admin={row.get('admin')}, oper={row.get('oper')})"
        return True, ""

    def inject(self, target: Target, fault: Fault, ttl_s: int) -> None:
        self._set_admin(target.meta["nepk"], target.meta["ifname"], False, target.describe())

    def after_inject(self, target: Target, fault: Fault, sleep: Sleeper) -> Dict[str, Any]:
        if target.kind != "vrrp":
            return {}
        nepk, vrid = target.meta["nepk"], target.meta["vrid"]
        started, facts = time.time(), {"failover_detected": False}
        while time.time() - started < 30:
            try:
                group = self._vrrp_group(nepk, vrid)
            except DriverError:
                group = None
            if group and str(group.get("mode", "")).upper() != "MASTER":
                facts.update(failover_detected=True, failover_seconds=round(time.time() - started, 1))
                master = self._master(vrid)
                if master:
                    facts["new_master"] = master[1]
                break
            if sleep(2.0):
                break
        return facts

    def _master(self, vrid: int) -> Optional[Tuple[str, str]]:
        for nepk, name in self._names.items():
            try:
                group = self._vrrp_group(nepk, vrid)
            except DriverError:
                continue
            if group and str(group.get("mode", "")).upper() == "MASTER":
                return nepk, name
        return None

    def restore(self, target: Target, fault: Fault) -> None:
        self._set_admin(target.meta["nepk"], target.meta["ifname"], True, target.describe())

    def verify(self, target: Target, fault: Fault, sleep: Sleeper) -> Tuple[bool, Dict[str, Any]]:
        nepk, ifname = target.meta["nepk"], target.meta["ifname"]
        started, facts = time.time(), {"interface_recovered": False}
        while time.time() - started < 60:
            try:
                row = self._iface(nepk, ifname)
            except DriverError:
                row = None
            if row and row.get("admin") and row.get("oper"):
                facts.update(interface_recovered=True, recovery_seconds=round(time.time() - started, 1))
                break
            if sleep(self.VERIFY_EVERY):
                return False, facts
        if not facts["interface_recovered"]:
            facts["reason"] = f"{ifname} did not become operational within 60 s of the restore"
            return False, facts
        if target.kind != "vrrp":
            return True, facts

        # VRRP: three consecutive readings with the original master in MASTER or BACKUP and
        # somebody holding mastership. Who ends up master depends on preempt and is recorded,
        # not judged.
        vrid, stable, started = target.meta["vrid"], 0, time.time()
        facts.update(vrrp_stabilized=False, preempt=target.meta.get("preempt"))
        while time.time() - started < 90:
            try:
                group = self._vrrp_group(nepk, vrid)
            except DriverError:
                group = None
            master = self._master(vrid)
            mode = str((group or {}).get("mode", "")).upper()
            stable = stable + 1 if (mode in ("MASTER", "BACKUP") and master) else 0
            if stable >= 3:
                facts.update(vrrp_stabilized=True, final_master=master[1],
                             original_master_restored=master[0] == nepk,
                             stabilize_seconds=round(time.time() - started, 1))
                return True, facts
            if sleep(5.0):
                return False, facts
        facts["reason"] = "VRRP did not stabilise within 90 s"
        return False, facts

    def held(self) -> List[Dict[str, str]]:
        with self._lock:
            return [{"driver": self.name, "what": what, "how": "admin down"} for what in self._held.values()]

    def restore_all(self) -> List[str]:
        errors = []
        with self._lock:
            items = list(self._held.items())
        for (nepk, ifname), what in items:
            try:
                self._set_admin(nepk, ifname, True, what)
            except DriverError as exc:
                errors.append(f"{what}: {exc}")
        return errors
