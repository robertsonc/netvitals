"""The chaos engine: pick a target, break it, hold, put it back, and record what the flows saw.

One trial:

    precheck -> baseline -> inject -> [failover] -> hold -> restore -> verify -> settle -> verdict

`baseline` and `settle` exist for the measurements: the trial's impact is the difference between
what the endpoint flows measured before the fault, during it, and after the restore.
"""
from __future__ import annotations

import json
import logging
import random
import threading
import time
from typing import Any, Dict, List, Optional

from .drivers import Driver, DriverError, Fault, Target
from .fleet import Fleet
from .store import Store

LOG = logging.getLogger(__name__)

LIMITS = {"cycles": (1, 10000), "wait": (0, 86400), "holdMin": (1, 3300), "holdMax": (1, 3300),
          "baseline": (0, 300), "settle": (0, 600)}
DEFAULTS = {"cycles": 5, "wait": 60, "holdMin": 30, "holdMax": None, "baseline": 10, "settle": 20,
            "selection": "random", "kinds": ["wan", "vrrp", "span"], "faults": None, "seed": None}
SELECTIONS = ("random", "sequential")
COLLECT_GRACE = 4.0     # seconds to let the last per-second records arrive before judging a trial
TTL_MARGIN = 180        # dead-man margin on top of the hold, for drivers that support one
MAX_LOG = 400


class EngineError(ValueError):
    """A request the engine refuses; the message is shown to the operator."""


def _now_ms() -> int:
    return int(time.time() * 1000)


class Engine:
    def __init__(self, store: Store, fleet: Fleet):
        self.store, self.fleet = store, fleet
        self.drivers: Dict[str, Driver] = {}
        self.status = "idle"                    # idle | discovering | running | stopping
        self.phase: Optional[str] = None
        self.targets: List[Target] = []
        self.excluded: set = set(store.get("excluded", []))
        self.discovered_at: Optional[float] = None
        self.current: Optional[Dict[str, Any]] = None
        self.run: Optional[Dict[str, Any]] = None
        self.next_cycle_at: Optional[float] = None
        self.log: List[Dict[str, Any]] = []
        self._log_seq = 0
        self._lock = threading.Lock()           # held for the whole of a run or a discovery
        self._stop = threading.Event()
        self._skip = threading.Event()
        self._rng = random.Random()
        self._seq_index = 0

    # ----- logging -----

    def say(self, level: str, message: str) -> None:
        self._log_seq += 1
        self.log.append({"n": self._log_seq, "t": time.time(), "level": level, "msg": message})
        del self.log[:-MAX_LOG]
        LOG.log({"error": logging.ERROR, "warn": logging.WARNING}.get(level, logging.INFO), message)

    # ----- drivers and targets -----

    def set_driver(self, name: str, driver: Optional[Driver]) -> None:
        if not self.idle():
            raise EngineError("Stop the current run before changing a connection.")
        old = self.drivers.get(name)
        if old and old.held():
            raise EngineError("That connection still holds faults. Restore them first.")
        if driver is None:
            self.drivers.pop(name, None)
        else:
            self.drivers[name] = driver
        self.targets = [t for t in self.targets if t.driver != name]

    def idle(self) -> bool:
        return self.status == "idle"

    def in_scope(self, kinds: Optional[List[str]] = None) -> List[Target]:
        return [t for t in self.targets if t.key not in self.excluded and (kinds is None or t.kind in kinds)]

    def set_scope(self, excluded: List[str]) -> None:
        if not self.idle():
            raise EngineError("Scope can only change while idle.")
        known = {t.key for t in self.targets}
        unknown = [k for k in excluded if k not in known]
        if unknown:
            raise EngineError(f"Unknown target: {unknown[0]}")
        self.excluded = set(excluded)
        self.store.put("excluded", sorted(self.excluded))
        self.say("info", f"Scope updated: {len(self.in_scope())} of {len(self.targets)} targets in scope")

    def held(self) -> List[Dict[str, str]]:
        return [h for d in self.drivers.values() for h in d.held()]

    def _discover(self) -> bool:
        self.status, self.phase = "discovering", None
        found: List[Target] = []
        for driver in self.drivers.values():
            if not driver.configured():
                continue
            self.say("info", f"Discovering targets on {driver.label} (read-only)…")
            try:
                got = driver.discover()
            except DriverError as exc:
                self.say("error", f"Discovery on {driver.label} failed: {exc}")
                continue
            self.say("info", f"{driver.label}: {len(got)} target{'s' if len(got) != 1 else ''}")
            found += got
        self.targets = found
        self.excluded &= {t.key for t in found}
        self.discovered_at = time.time()
        if not found:
            self.say("error", "No targets found. Check the connections in Settings.")
        return bool(found)

    # ----- waiting -----

    def _sleep(self, seconds: float) -> bool:
        """Wait, returning True as soon as a stop is requested."""
        return self._stop.wait(max(0.0, seconds))

    def _set_phase(self, phase: Optional[str]) -> None:
        self.phase = phase
        if phase and self.current is not None:
            self.current["phases"].append({"phase": phase, "at": _now_ms()})

    # ----- one trial -----

    def _trial(self, run_id: int, cycle: int, target: Target, fault: Fault, p: Dict[str, Any]) -> Dict[str, Any]:
        driver = self.drivers[target.driver]
        hold = p["holdMin"] if not p.get("holdMax") or p["holdMax"] <= p["holdMin"] else \
            self._rng.randint(p["holdMin"], p["holdMax"])
        trial: Dict[str, Any] = {
            "run": run_id, "cycle": cycle, "target": target.public(), "fault": fault.public(), "hold": hold,
            "phases": [], "started": _now_ms(), "facts": {}, "success": False, "reason": ""}
        self.current = trial
        what = f"{fault.label}{' (' + fault.direction + ')' if fault.direction else ''} on {target.describe()}"
        self.say("info", f"Cycle {cycle}: {what}")
        injected = False
        try:
            self._set_phase("precheck")
            ok, why = driver.precheck(target, fault)
            if not ok:
                raise DriverError(why)
            self._set_phase("baseline")
            if self._sleep(p["baseline"]):
                raise _Stopped()

            self._set_phase("inject")
            self.store.audit("FAULT_INJECT", target=target.describe(), scope=driver.label, detail=fault.label,
                             result="PENDING")
            trial["t_inject"] = _now_ms()
            injected = True
            driver.inject(target, fault, hold + TTL_MARGIN)
            self.store.audit("FAULT_INJECT", target=target.describe(), scope=driver.label, detail=fault.label)

            if target.kind == "vrrp":
                self._set_phase("failover")
            trial["facts"].update(driver.after_inject(target, fault, self._sleep))

            self._set_phase("hold")
            trial["hold_until"] = _now_ms() + hold * 1000
            stopped = self._sleep(hold)
            trial.pop("hold_until", None)

            self._set_phase("restore")
            self._restore(driver, target, fault)
            injected = False
            trial["t_restore"] = _now_ms()

            self._set_phase("verify")
            ok, facts = driver.verify(target, fault, self._sleep)
            trial["facts"].update(facts)
            if target.kind == "vrrp" and not trial["facts"].get("failover_detected"):
                ok = False
                trial["facts"].setdefault("reason", "no VRRP failover was observed within 30 s of the fault")
            trial["success"] = ok
            trial["reason"] = "" if ok else str(trial["facts"].get("reason") or "did not recover cleanly")
            if stopped:
                trial["reason"] = (trial["reason"] + " " if trial["reason"] else "") + "(hold cut short by operator)"
            elif ok:
                self._set_phase("settle")
                self._sleep(p["settle"])
        except _Stopped:
            trial["reason"] = "stopped by operator before the fault was injected"
        except DriverError as exc:
            trial["reason"] = str(exc)
            self.say("error", f"Cycle {cycle}: {exc}")
        except Exception as exc:    # thread boundary: one bad trial must not kill the run or skip the restore
            LOG.exception("trial failed unexpectedly")
            trial["reason"] = f"unexpected error: {exc}"
        finally:
            if injected:            # something failed between inject and restore: put it back regardless
                try:
                    self._restore(driver, target, fault)
                    trial["t_restore"] = _now_ms()
                except DriverError as exc:
                    self.say("error", f"RESTORE FAILED for {target.describe()}: {exc}. Check it by hand.")
                    trial["reason"] += f" RESTORE FAILED: {exc}"
        trial["ended"] = _now_ms()

        # Let the last seconds of measurements arrive (records trail real time by one to three
        # seconds), then work out what the flows saw.
        self._set_phase("verdict")
        if trial.get("t_inject"):
            time.sleep(COLLECT_GRACE)
            trial["impact"] = self.impact(trial, p["baseline"])
        self._finish_trial(trial)
        return trial

    def _restore(self, driver: Driver, target: Target, fault: Fault) -> None:
        self.store.audit("FAULT_RESTORE", target=target.describe(), scope=driver.label, result="PENDING")
        try:
            driver.restore(target, fault)
        except DriverError as exc:
            self.store.audit("FAULT_RESTORE", target=target.describe(), scope=driver.label, detail=str(exc),
                             result="FAILED")
            raise
        self.store.audit("FAULT_RESTORE", target=target.describe(), scope=driver.label)

    def _finish_trial(self, trial: Dict[str, Any]) -> None:
        cur = self.store.run("INSERT INTO trials(run_id, cycle, started_ms, ended_ms, success, data) "
                             "VALUES(?,?,?,?,?,?)",
                             (trial["run"], trial["cycle"], trial["started"], trial["ended"], int(trial["success"]),
                              json.dumps(trial)))
        trial["id"] = cur.lastrowid
        impact = trial.get("impact") or {}
        note = ""
        if impact.get("legs"):
            worst = impact.get("worstMs") or 0
            note = (f" · flows: worst interruption {worst} ms, " if worst else " · flows: no interruption, ") + \
                   f"{impact.get('faultLoss', 0):.2f}% loss during the fault across {len(impact['legs'])} leg(s)"
        name = f"{trial['fault']['label']} on {trial['target']['name']} ({trial['target']['group']})"
        if trial["success"]:
            self.say("ok", f"Cycle {trial['cycle']}: {name} recovered{note}")
        else:
            self.say("error", f"Cycle {trial['cycle']}: {name}: {trial['reason']}{note}")
        self.store.audit("TRIAL_VERDICT", target=name, detail=trial["reason"] or note.strip(" ·"),
                         result="RECOVERED" if trial["success"] else "FAILED")
        if self.run:
            self.run["done"] += 1
            self.run["ok" if trial["success"] else "failed"] += 1
        self.current = None
        self._set_phase(None)

    def impact(self, trial: Dict[str, Any], baseline_s: int) -> Dict[str, Any]:
        """What the endpoint flows measured around one trial."""
        t_inject = trial["t_inject"]
        t_restore = trial.get("t_restore") or trial["ended"]
        t_end = trial["ended"]
        # Whole sender-clock seconds: skip the second the fault lands in when taking the baseline.
        base = self.fleet.window(t_inject - baseline_s * 1000 - 1000, t_inject - 1000) if baseline_s else {}
        during = self.fleet.window(t_inject, t_restore)
        after = self.fleet.window(t_restore, t_end + 2000)
        outages = self.fleet.outages(t_inject - 500, t_end + 2000)
        names = self.fleet.leg_names()
        legs, worst, lost, sent = [], 0, 0, 0
        shift: Optional[float] = None
        for leg in sorted(set(base) | set(during) | set(after) | set(outages)):
            if leg not in names:
                continue
            events = outages.get(leg, [])
            longest = max((e["ms"] for e in events), default=0)
            d = during.get(leg) or {}
            b = base.get(leg) or {}
            first_hit = min((e["start"] - t_inject for e in events if e["start"] >= t_inject - 500), default=None)
            # Delay counts as impact too: a brownout that adds 300 ms loses nothing and still hurts.
            delta = round(d["rtt"] - b["rtt"], 3) if d.get("rtt") is not None and b.get("rtt") is not None else None
            slower = delta is not None and delta >= max(5.0, 0.25 * b["rtt"])
            hit = bool(events) or slower or ((d.get("loss") or 0) > (b.get("loss") or 0) + 0.5)
            legs.append({"leg": leg, **names[leg], "base": b or None, "fault": d or None,
                         "after": after.get(leg), "outages": events, "worstMs": longest,
                         "firstHitMs": first_hit, "rttShiftMs": delta, "affected": hit})
            if delta is not None and (shift is None or delta > shift):
                shift = delta
            worst = max(worst, longest)
            lost += d.get("lost") or 0
            sent += d.get("sent") or 0
        return {"legs": legs, "worstMs": worst, "rttShiftMs": shift, "affected": sum(1 for l in legs if l["affected"]),
                "faultLoss": round(100.0 * lost / sent, 3) if sent else 0.0, "faultLost": lost}

    # ----- runs -----

    def _params(self, data: Dict[str, Any]) -> Dict[str, Any]:
        p = dict(DEFAULTS)
        for key, (lo, hi) in LIMITS.items():
            raw = data.get(key, p[key])
            if raw is None or raw == "":
                if key in ("holdMax", "cycles"):
                    p[key] = None
                    continue
                raise EngineError(f"'{key}' is required")
            if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
                raise EngineError(f"'{key}' must be a whole number")
            try:
                value = int(raw)
            except ValueError:
                raise EngineError(f"'{key}' must be a whole number")
            if not lo <= value <= hi:
                raise EngineError(f"'{key}' must be between {lo} and {hi}")
            p[key] = value
        if p["holdMax"] is not None and p["holdMax"] < p["holdMin"]:
            raise EngineError("Maximum hold must be at least the minimum hold.")
        p["selection"] = data.get("selection", p["selection"])
        if p["selection"] not in SELECTIONS:
            raise EngineError("'selection' must be random or sequential")
        kinds = data.get("kinds", p["kinds"])
        if not isinstance(kinds, list) or not kinds or any(k not in ("wan", "vrrp", "span") for k in kinds):
            raise EngineError("'kinds' must list at least one of wan, vrrp, span")
        p["kinds"] = kinds
        faults = data.get("faults")
        if faults is not None and (not isinstance(faults, list) or not all(isinstance(f, str) for f in faults)):
            raise EngineError("'faults' must be a list of fault ids")
        p["faults"] = faults or None
        directions = data.get("directions")
        if directions is not None and (not isinstance(directions, list) or
                                       any(d not in ("down", "up", "both") for d in directions)):
            raise EngineError("'directions' may contain down, up and both")
        p["directions"] = directions or None
        seed = data.get("seed")
        if seed not in (None, ""):
            try:
                p["seed"] = int(seed)
            except (TypeError, ValueError):
                raise EngineError("'seed' must be a whole number")
        return p

    def _pick_fault(self, target: Target, p: Dict[str, Any]) -> Optional[Fault]:
        menu = self.drivers[target.driver].faults(target)
        if target.kind == "span":
            if p.get("faults"):
                menu = [f for f in menu if f.id in p["faults"]]
            if p.get("directions"):
                menu = [f for f in menu if not f.direction or f.direction in p["directions"]]
        return self._rng.choice(menu) if menu else None

    def _next_target(self, pool: List[Target], selection: str) -> Target:
        if selection == "sequential":
            target = pool[self._seq_index % len(pool)]
            self._seq_index += 1
            return target
        return self._rng.choice(pool)

    def start(self, data: Dict[str, Any], *, only: Optional[str] = None, fault_id: Optional[str] = None,
              direction: Optional[str] = None) -> None:
        """Start a run in the background. `only` runs one cycle against one target key."""
        p = self._params(data)
        if not any(d.configured() for d in self.drivers.values()):
            raise EngineError("Nothing to break yet. Connect an Orchestrator or an Autopod lab in Settings.")
        if not self._lock.acquire(blocking=False):
            raise EngineError("Busy: a run or a discovery is already in progress.")
        self._stop.clear()
        self.status = "discovering"
        threading.Thread(target=self._run, args=(p, only, fault_id, direction), daemon=True, name="chaos-run").start()

    def _run(self, p: Dict[str, Any], only: Optional[str], fault_id: Optional[str],
             direction: Optional[str]) -> None:
        try:
            if p["seed"] is not None:
                self._rng = random.Random(p["seed"])
            if (not self.targets or not only) and not self._discover():
                return
            if only:
                pool = [t for t in self.targets if t.key == only]
                if not pool:
                    self.say("error", "That target is no longer in the inventory. Run discovery again.")
                    return
                p = dict(p, cycles=1)
            else:
                pool = self.in_scope(p["kinds"])
                if not pool:
                    self.say("error", "No targets in scope for this run. Check the scope and the target kinds.")
                    return
            run_id = int(time.time())
            self.run = {"id": run_id, "started": time.time(), "total": p["cycles"], "done": 0, "ok": 0, "failed": 0,
                        "params": p, "single": bool(only)}
            self.status = "running"
            self.store.audit("RUN_START", scope=f"{len(pool)} target(s)",
                             detail=f"cycles={p['cycles'] or 'until stopped'} hold={p['holdMin']}"
                                    f"{'-' + str(p['holdMax']) if p['holdMax'] else ''}s wait={p['wait']}s")
            self.say("info", f"Run started: {p['cycles'] or 'unlimited'} cycle(s), {len(pool)} target(s) in scope")
            cycle = 0
            while not self._stop.is_set() and (p["cycles"] is None or cycle < p["cycles"]):
                cycle += 1
                target = self._next_target(pool, p["selection"])
                if only and fault_id:
                    menu = [f for f in self.drivers[target.driver].faults(target)
                            if f.id == fault_id and (not direction or f.direction in ("", direction))]
                    fault = menu[0] if menu else None
                else:
                    fault = self._pick_fault(target, p)
                if fault is None:
                    self.say("warn", f"No permitted fault for {target.describe()}; skipped")
                    continue
                self._trial(run_id, cycle, target, fault, p)
                if not self._stop.is_set() and (p["cycles"] is None or cycle < p["cycles"]) and p["wait"]:
                    self._skip.clear()
                    self.next_cycle_at = time.time() + p["wait"]
                    self._set_phase("waiting")
                    while time.time() < self.next_cycle_at and not self._stop.is_set() and not self._skip.is_set():
                        time.sleep(0.2)
                    self.next_cycle_at = None
                    self._set_phase(None)
            self.say("info", "Run stopped by operator" if self._stop.is_set() else "Run complete")
            self.store.audit("RUN_END", detail=f"{self.run['ok']} recovered, {self.run['failed']} failed")
        except Exception as exc:
            LOG.exception("run failed")
            self.say("error", f"Run failed: {exc}")
        finally:
            self._cleanup()

    def discover(self) -> None:
        if not any(d.configured() for d in self.drivers.values()):
            raise EngineError("Nothing to discover yet. Connect an Orchestrator or an Autopod lab in Settings.")
        if not self._lock.acquire(blocking=False):
            raise EngineError("Busy: a run or a discovery is already in progress.")
        self._stop.clear()
        self.status = "discovering"

        def work() -> None:
            try:
                self._discover()
            except Exception as exc:
                LOG.exception("discovery failed")
                self.say("error", f"Discovery failed: {exc}")
            finally:
                self._cleanup(restore=False)
        threading.Thread(target=work, daemon=True, name="chaos-discover").start()

    def _cleanup(self, restore: bool = True) -> None:
        try:
            if restore:
                for error in self.restore_all(quiet=True):
                    self.say("error", f"RESTORE FAILED: {error}")
        finally:
            self.current, self.next_cycle_at, self.phase = None, None, None
            self.status = "idle"
            self._lock.release()

    def stop(self) -> None:
        if self.status in ("running", "discovering"):
            self.status = "stopping"
            self.say("warn", "Stop requested: ending the hold and restoring")
            self._stop.set()

    def skip_wait(self) -> None:
        self._skip.set()

    def restore_all(self, quiet: bool = False) -> List[str]:
        """Put back everything any driver is holding. Safe to call at any time, including at exit."""
        errors: List[str] = []
        for driver in self.drivers.values():
            held = driver.held()
            if not held:
                continue
            if not quiet:
                self.say("warn", f"Restoring {len(held)} fault(s) held on {driver.label}")
            self.store.audit("RESTORE_ALL", scope=driver.label, detail=f"{len(held)} held", result="PENDING")
            got = driver.restore_all()
            self.store.audit("RESTORE_ALL", scope=driver.label, detail="; ".join(got),
                             result="FAILED" if got else "OK")
            errors += got
        return errors

    # ----- history -----

    def trials(self, limit: int = 200) -> List[Dict[str, Any]]:
        rows = self.store.rows("SELECT id, data FROM trials ORDER BY id DESC LIMIT ?", (limit,))
        out = []
        for r in rows:
            t = json.loads(r["data"])
            t["id"] = r["id"]
            out.append(t)
        return out


class _Stopped(Exception):
    pass
