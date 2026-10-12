from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from netlab.checks import Finding, Kind
from netlab.model import Network


class Action(str, Enum):
    INTERFACE_UP = "interface_up"
    RECREATE_TUNNEL = "recreate_tunnel"
    REAPPLY_CONFIG = "reapply_config"
    CLEAR_BGP = "clear_bgp"
    CLEAR_BGP_SOFT = "clear_bgp_soft"
    ESCALATE = "escalate"


LAYER: dict[Kind, int] = {
    Kind.COLLECTION_ERROR: 0,
    Kind.INTERFACE_ADMIN_DOWN: 1,
    Kind.INTERFACE_OPER_DOWN: 1,
    Kind.TUNNEL_MISSING: 1,
    Kind.BGP_PEER_MISSING: 2,
    Kind.BGP_POLICY_MISMATCH: 2,
    Kind.BGP_PEER_DOWN: 3,
    Kind.OSPF_NEIGHBOR_DOWN: 3,
    Kind.ISIS_ADJACENCY_DOWN: 3,
    Kind.LDP_NEIGHBOR_DOWN: 3,
    Kind.ROUTE_MISSING: 4,
    Kind.ROUTE_WRONG_PROTOCOL: 4,
    Kind.PING_FAILED: 4,
}


@dataclass(frozen=True)
class Step:
    action: Action
    router: str
    target: str = ""


@dataclass
class Plan:
    root_cause: str
    steps: list[Step]
    cause: list[Finding]
    symptoms: list[Finding] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return ";".join(f"{s.action.value}:{s.router}:{s.target}" for s in self.steps)

    @property
    def escalation(self) -> bool:
        return all(s.action is Action.ESCALATE for s in self.steps)


@dataclass(frozen=True)
class StepResult:
    step: Step
    ok: bool
    detail: str = ""


class Actuator(Protocol):
    def interface_up(self, router: str, interface: str) -> StepResult: ...
    def recreate_tunnel(self, router: str, tunnel: str) -> StepResult: ...
    def reapply_config(self, router: str) -> StepResult: ...
    def clear_bgp(self, router: str, peer: str, soft: bool) -> StepResult: ...


DriftFn = Callable[[str], list[str]]


class Topology:
    """Address and link lookups used to correlate findings across routers."""

    def __init__(self, net: Network) -> None:
        self.net = net
        self.owner: dict[str, tuple[str, str]] = {}
        self.subnets: dict[tuple[str, str], list[ipaddress.IPv4Network]] = {}
        for r in net.routers.values():
            for i in r.interfaces.values():
                for a in i.ipv4:
                    iface = ipaddress.IPv4Interface(a)
                    self.owner[str(iface.ip)] = (r.name, i.name)
                    self.subnets.setdefault((r.name, i.name), []).append(iface.network)

    def peer_of(self, router: str, interface: str) -> tuple[str, str] | None:
        iface = self.net.routers[router].interfaces.get(interface)
        if iface is None or iface.peer is None:
            return None
        return iface.peer_router or "", iface.peer_interface or ""

    def router_for(self, address: str) -> str | None:
        hit = self.owner.get(address)
        return hit[0] if hit else None

    def bgp_description(self, router: str, address: str) -> str:
        bgp = self.net.routers[router].bgp
        for n in bgp.neighbors if bgp else []:
            if n.address == address:
                return n.description or address
        return address


def _fmt(f: Finding) -> str:
    return f"{f.router} {f.kind.value} {f.target}" + (f" ({f.detail})" if f.detail else "")


def plan_remediation(findings: list[Finding], topo: Topology, drift: DriftFn) -> list[Plan]:
    """Pick the lowest failing layer, explain higher-layer findings as its symptoms, and plan fixes."""
    actionable = [f for f in findings if f.kind is not Kind.COLLECTION_ERROR]
    if not actionable:
        return []
    layer = min(LAYER[f.kind] for f in actionable)
    causes = [f for f in actionable if LAYER[f.kind] == layer]
    symptoms = [f for f in actionable if LAYER[f.kind] > layer]
    planner = {1: _plan_link, 2: _plan_config, 3: _plan_sessions, 4: _plan_reachability}[layer]
    plans = planner(causes, topo, drift)
    for p in plans:
        p.symptoms = symptoms
    return plans


def _plan_link(causes: list[Finding], topo: Topology, drift: DriftFn) -> list[Plan]:
    plans: list[Plan] = []
    admin_down = {(f.router, f.target) for f in causes if f.kind is Kind.INTERFACE_ADMIN_DOWN}
    tunnels = {t.name for t in topo.net.tunnels}
    for f in causes:
        if f.kind is Kind.INTERFACE_ADMIN_DOWN:
            if f.target in tunnels:
                plans.append(
                    Plan(
                        f"tunnel {f.target} on {f.router} is administratively down",
                        [Step(Action.INTERFACE_UP, f.router, f.target)],
                        [f],
                    )
                )
                continue
            peer = topo.peer_of(f.router, f.target)
            peer_txt = f"; link partner {peer[0]}:{peer[1]} lost carrier" if peer else ""
            plans.append(
                Plan(
                    f"{f.router}:{f.target} was shut (admin down){peer_txt}. Adjacencies and sessions "
                    "over this link drop, and routes learned across it are withdrawn",
                    [Step(Action.INTERFACE_UP, f.router, f.target)],
                    [f],
                )
            )
        elif f.kind is Kind.INTERFACE_OPER_DOWN:
            peer = topo.peer_of(f.router, f.target)
            if peer and peer in admin_down:
                continue
            plans.append(
                Plan(
                    f"{f.router}:{f.target} has no carrier while admin up on both ends: "
                    "physical/veth fault, not fixable from config",
                    [Step(Action.ESCALATE, f.router, f.target)],
                    [f],
                )
            )
        elif f.kind is Kind.TUNNEL_MISSING:
            plans.append(
                Plan(
                    f"tunnel interface {f.target} is missing on {f.router} (deleted or never created)",
                    [Step(Action.RECREATE_TUNNEL, f.router, f.target)],
                    [f],
                )
            )
    return plans


def _plan_config(causes: list[Finding], topo: Topology, drift: DriftFn) -> list[Plan]:
    plans: list[Plan] = []
    by_router: dict[str, list[Finding]] = {}
    for f in causes:
        by_router.setdefault(f.router, []).append(f)
    for router, fs in by_router.items():
        evidence = drift(router)
        steps = [Step(Action.REAPPLY_CONFIG, router)]
        reasons: list[str] = []
        for f in fs:
            desc = topo.bgp_description(router, f.target)
            if f.kind is Kind.BGP_PEER_MISSING:
                reasons.append(f"BGP neighbor {f.target} ({desc}) was deleted from the running config")
            else:
                reasons.append(f"BGP neighbor {f.target} ({desc}) has an unexpected route-map ({f.detail})")
                steps.append(Step(Action.CLEAR_BGP_SOFT, router, f.target))
        root_cause = "; ".join(reasons) + ": config drift from intended state"
        plans.append(Plan(root_cause, steps, fs, evidence=evidence))
    return plans


def _plan_sessions(causes: list[Finding], topo: Topology, drift: DriftFn) -> list[Plan]:
    plans: list[Plan] = []
    drift_cache: dict[str, list[str]] = {}

    def drifted(router: str) -> list[str]:
        if router not in drift_cache:
            drift_cache[router] = drift(router)
        return drift_cache[router]

    cleared: set[frozenset[str]] = set()
    for f in causes:
        remote = topo.router_for(f.target) if f.kind in (Kind.BGP_PEER_DOWN, Kind.LDP_NEIGHBOR_DOWN) else None
        involved = [f.router] + ([remote] if remote else [])
        for r in involved:
            lines = drifted(r)
            if lines:
                plans.append(
                    Plan(
                        f"{f.router} {f.kind.value} {f.target}: running config on {r} differs from intent",
                        [Step(Action.REAPPLY_CONFIG, r)],
                        [f],
                        evidence=lines,
                    )
                )
                break
        else:
            if f.kind is Kind.BGP_PEER_DOWN:
                session = frozenset({f.router, remote or f.target})
                if session in cleared:
                    continue
                cleared.add(session)
                plans.append(
                    Plan(
                        f"BGP session {f.router} -> {f.target} stuck in {f.detail} with links up and config "
                        "in sync: likely a stale FSM/TCP state, hard-clearing the session",
                        [Step(Action.CLEAR_BGP, f.router, f.target)],
                        [f],
                    )
                )
            else:
                plans.append(
                    Plan(
                        f"{_fmt(f)} with links up and config in sync: needs an operator",
                        [Step(Action.ESCALATE, f.router, f.target)],
                        [f],
                    )
                )
    return _dedupe(plans)


def _plan_reachability(causes: list[Finding], topo: Topology, drift: DriftFn) -> list[Plan]:
    drifted = {r: lines for r in topo.net.routers if (lines := drift(r))}
    if drifted:
        return [
            Plan(
                f"control plane is up but {len(causes)} reachability check(s) fail; "
                f"{r} running config differs from intent (likely policy/origination change)",
                [Step(Action.REAPPLY_CONFIG, r)],
                causes,
                evidence=lines,
            )
            for r, lines in drifted.items()
        ]
    return [
        Plan(
            "reachability failures with sessions up and configs in sync: needs an operator",
            [Step(Action.ESCALATE, f.router, f.target) for f in causes],
            causes,
        )
    ]


def _dedupe(plans: list[Plan]) -> list[Plan]:
    seen: dict[str, Plan] = {}
    for p in plans:
        if p.key in seen:
            seen[p.key].cause += p.cause
            continue
        seen[p.key] = p
    return list(seen.values())


@dataclass
class Remediator:
    """Applies plans with guardrails: per-plan cooldown, attempt cap, and a settle window."""

    actuator: Actuator
    cooldown_s: float = 30.0
    settle_s: float = 12.0
    max_attempts: int = 3
    clock: Callable[[], float] = time.monotonic
    _last_run: dict[str, float] = field(default_factory=dict)
    _attempts: dict[str, int] = field(default_factory=dict)
    _settle_until: float = 0.0

    def reset(self) -> None:
        self._attempts.clear()
        self._last_run.clear()
        self._settle_until = 0.0

    def settling(self) -> bool:
        return self.clock() < self._settle_until

    def allowed(self, plan: Plan) -> tuple[bool, str]:
        now = self.clock()
        if now < self._settle_until:
            return False, "settling after previous remediation"
        if plan.escalation:
            last = self._last_run.get(plan.key)
            return (last is None or now - last >= self.cooldown_s * 2), "escalation already raised"
        last = self._last_run.get(plan.key)
        if last is not None and now - last < self.cooldown_s:
            return False, "cooldown"
        if self._attempts.get(plan.key, 0) >= self.max_attempts:
            return False, "max attempts reached"
        return True, ""

    def mark(self, plan: Plan) -> None:
        self._last_run[plan.key] = self.clock()

    def execute(self, plan: Plan) -> list[StepResult]:
        self.mark(plan)
        if plan.escalation:
            return [StepResult(s, True, "escalated") for s in plan.steps]
        self._attempts[plan.key] = self._attempts.get(plan.key, 0) + 1
        results: list[StepResult] = []
        for s in plan.steps:
            if s.action is Action.INTERFACE_UP:
                res = self.actuator.interface_up(s.router, s.target)
            elif s.action is Action.RECREATE_TUNNEL:
                res = self.actuator.recreate_tunnel(s.router, s.target)
            elif s.action is Action.REAPPLY_CONFIG:
                res = self.actuator.reapply_config(s.router)
            elif s.action is Action.CLEAR_BGP:
                res = self.actuator.clear_bgp(s.router, s.target, soft=False)
            elif s.action is Action.CLEAR_BGP_SOFT:
                res = self.actuator.clear_bgp(s.router, s.target, soft=True)
            else:
                res = StepResult(s, True, "escalated")
            results.append(res)
        self._settle_until = self.clock() + self.settle_s
        return results
