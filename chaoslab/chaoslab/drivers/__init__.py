"""Fault drivers. A driver knows how to find things that can be broken, break one, and put it back.

The engine is the only caller. Every driver keeps its own list of what it is currently holding
broken, so "restore everything" works even when a trial died half way.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


class DriverError(Exception):
    """An action against the lab failed. The message is shown to the operator as is."""


@dataclass
class Target:
    key: str                    # stable across discoveries, unique across drivers
    driver: str
    kind: str                   # wan | vrrp | span
    group: str                  # appliance or site: what the target belongs to
    name: str
    detail: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)

    def describe(self) -> str:
        return self.name if self.kind == "span" else f"{self.name} on {self.group}"

    def public(self) -> Dict[str, Any]:
        return {"key": self.key, "driver": self.driver, "kind": self.kind, "group": self.group,
                "name": self.name, "detail": self.detail, "meta": self.meta}


@dataclass
class Fault:
    id: str
    label: str
    kind: str                               # down | impair
    spec: Optional[Dict[str, float]] = None  # netem fields for kind == impair
    direction: str = ""                     # down | up | both, for span impairments

    def public(self) -> Dict[str, Any]:
        return {"id": self.id, "label": self.label, "kind": self.kind, "spec": self.spec,
                "direction": self.direction}


# Sleep that returns True when the operator asked to stop. Drivers use it for every wait.
Sleeper = Callable[[float], bool]


class Driver:
    name = "driver"
    label = "Driver"

    def configured(self) -> bool:
        raise NotImplementedError

    def status(self) -> Dict[str, Any]:
        """Connection facts for the Settings page. Never includes credentials."""
        raise NotImplementedError

    def discover(self) -> List[Target]:
        raise NotImplementedError

    def faults(self, target: Target) -> List[Fault]:
        raise NotImplementedError

    def precheck(self, target: Target, fault: Fault) -> Tuple[bool, str]:
        return True, ""

    def inject(self, target: Target, fault: Fault, ttl_s: int) -> None:
        raise NotImplementedError

    def after_inject(self, target: Target, fault: Fault, sleep: Sleeper) -> Dict[str, Any]:
        """Observe the control plane reacting (VRRP failover). Returns facts for the trial record."""
        return {}

    def restore(self, target: Target, fault: Fault) -> None:
        raise NotImplementedError

    def verify(self, target: Target, fault: Fault, sleep: Sleeper) -> Tuple[bool, Dict[str, Any]]:
        """Confirm the target is healthy again. Returns (ok, facts incl. recovery_seconds)."""
        return True, {}

    def held(self) -> List[Dict[str, str]]:
        """What this driver is holding broken right now."""
        return []

    def restore_all(self) -> List[str]:
        """Best-effort restore of everything held. Returns error messages."""
        return []
