from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from netlab.checks import Finding, Kind
from netlab.model import Network
from netlab.remediation import Action, Remediator, Step, StepResult, Topology, plan_remediation


def F(router: str, kind: Kind, target: str, detail: str = "") -> Finding:
    return Finding(router, kind, target, detail)


def no_drift(router: str) -> list[str]:
    return []


@pytest.fixture
def topo(net: Network) -> Topology:
    return Topology(net)


def steps(plans: list) -> list[tuple[Action, str, str]]:  # type: ignore[type-arg]
    return [(s.action, s.router, s.target) for p in plans for s in p.steps]


def test_link_down_unshuts_interface_and_explains_symptoms(topo: Topology) -> None:
    findings = [
        F("dca-edge", Kind.INTERFACE_ADMIN_DOWN, "eth2", "admin down"),
        F("bb1", Kind.INTERFACE_OPER_DOWN, "eth1"),
        F("bb1", Kind.BGP_PEER_DOWN, "172.16.10.0", "state Active"),
        F("dca-edge", Kind.BGP_PEER_DOWN, "172.16.10.1", "state Active"),
        F("bb2", Kind.ROUTE_MISSING, "10.0.1.1/32"),
        F("dca-r1", Kind.PING_FAILED, "dca-r1-to-dcb-r1"),
    ]
    plans = plan_remediation(findings, topo, no_drift)
    assert steps(plans) == [(Action.INTERFACE_UP, "dca-edge", "eth2")]
    assert "bb1:eth1 lost carrier" in plans[0].root_cause
    assert {f.kind for f in plans[0].symptoms} == {Kind.BGP_PEER_DOWN, Kind.ROUTE_MISSING, Kind.PING_FAILED}


def test_carrier_loss_without_shut_end_escalates(topo: Topology) -> None:
    plans = plan_remediation([F("bb1", Kind.INTERFACE_OPER_DOWN, "eth1")], topo, no_drift)
    assert steps(plans) == [(Action.ESCALATE, "bb1", "eth1")]
    assert plans[0].escalation


def test_deleted_neighbor_reapplies_config(topo: Topology) -> None:
    evidence = ["+ router bgp 65000", "+ neighbor 172.16.20.0 remote-as 65002"]
    findings = [
        F("bb2", Kind.BGP_PEER_MISSING, "172.16.20.0"),
        F("dcb-edge", Kind.BGP_PEER_DOWN, "172.16.20.1", "state Active"),
        F("dcb-edge", Kind.ROUTE_MISSING, "10.0.1.1/32"),
    ]
    plans = plan_remediation(findings, topo, lambda r: evidence if r == "bb2" else [])
    assert steps(plans) == [(Action.REAPPLY_CONFIG, "bb2", "")]
    assert "172.16.20.0 (dcb-edge) was deleted" in plans[0].root_cause
    assert plans[0].evidence == evidence


def test_bad_route_map_reapplies_and_soft_clears(topo: Topology) -> None:
    findings = [
        F("bb1", Kind.BGP_POLICY_MISMATCH, "172.16.10.0", "in=RM-CHAOS-DENY out=RM-EBGP-OUT"),
        F("bb2", Kind.ROUTE_MISSING, "10.0.1.1/32"),
    ]
    plans = plan_remediation(findings, topo, no_drift)
    assert steps(plans) == [
        (Action.REAPPLY_CONFIG, "bb1", ""),
        (Action.CLEAR_BGP_SOFT, "bb1", "172.16.10.0"),
    ]
    assert "unexpected route-map" in plans[0].root_cause


def test_stuck_session_is_cleared_once_per_session(topo: Topology) -> None:
    findings = [
        F("bb1", Kind.BGP_PEER_DOWN, "10.0.0.2", "state Active"),
        F("bb2", Kind.BGP_PEER_DOWN, "10.0.0.1", "state Active"),
    ]
    plans = plan_remediation(findings, topo, no_drift)
    assert steps(plans) == [(Action.CLEAR_BGP, "bb1", "10.0.0.2")]


def test_session_down_with_drift_on_remote_reapplies_remote(topo: Topology) -> None:
    findings = [F("dcb-edge", Kind.BGP_PEER_DOWN, "172.16.20.1", "state Idle")]
    plans = plan_remediation(findings, topo, lambda r: ["- neighbor 172.16.20.0 shutdown"] if r == "bb2" else [])
    assert steps(plans) == [(Action.REAPPLY_CONFIG, "bb2", "")]


def test_igp_adjacency_down_without_drift_escalates(topo: Topology) -> None:
    plans = plan_remediation([F("dcb-r1", Kind.ISIS_ADJACENCY_DOWN, "dcb-edge")], topo, no_drift)
    assert steps(plans) == [(Action.ESCALATE, "dcb-r1", "dcb-edge")]


def test_reachability_with_drift_reapplies_drifted_router(topo: Topology) -> None:
    findings = [F("bb2", Kind.ROUTE_MISSING, "10.0.2.1/32")]
    plans = plan_remediation(findings, topo, lambda r: ["- network 10.0.2.1/32"] if r == "dcb-edge" else [])
    assert steps(plans) == [(Action.REAPPLY_CONFIG, "dcb-edge", "")]


def test_reachability_without_drift_escalates(topo: Topology) -> None:
    plans = plan_remediation([F("dca-r1", Kind.PING_FAILED, "dca-r1-to-dcb-r1")], topo, no_drift)
    assert all(p.escalation for p in plans)


def test_collection_errors_alone_do_nothing(topo: Topology) -> None:
    assert plan_remediation([F("bb1", Kind.COLLECTION_ERROR, "show bgp summary json")], topo, no_drift) == []


@dataclass
class FakeActuator:
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def interface_up(self, router: str, interface: str) -> StepResult:
        self.calls.append(("up", router, interface))
        return StepResult(Step(Action.INTERFACE_UP, router, interface), True)

    def recreate_tunnel(self, router: str, tunnel: str) -> StepResult:
        self.calls.append(("tunnel", router, tunnel))
        return StepResult(Step(Action.RECREATE_TUNNEL, router, tunnel), True)

    def reapply_config(self, router: str) -> StepResult:
        self.calls.append(("reapply", router))
        return StepResult(Step(Action.REAPPLY_CONFIG, router), True)

    def clear_bgp(self, router: str, peer: str, soft: bool) -> StepResult:
        self.calls.append(("clear", router, peer, "soft" if soft else "hard"))
        return StepResult(Step(Action.CLEAR_BGP, router, peer), True)


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def test_remediator_guardrails(topo: Topology) -> None:
    clock, act = Clock(), FakeActuator()
    rem = Remediator(act, cooldown_s=30, settle_s=10, max_attempts=2, clock=clock)
    plan = plan_remediation([F("bb1", Kind.BGP_POLICY_MISMATCH, "172.16.10.0")], topo, no_drift)[0]

    assert rem.allowed(plan) == (True, "")
    rem.execute(plan)
    assert act.calls == [("reapply", "bb1"), ("clear", "bb1", "172.16.10.0", "soft")]

    clock.t += 5
    assert rem.allowed(plan) == (False, "settling after previous remediation")
    clock.t += 10
    assert rem.allowed(plan) == (False, "cooldown")
    clock.t += 30
    assert rem.allowed(plan)[0]
    rem.execute(plan)
    clock.t += 100
    assert rem.allowed(plan) == (False, "max attempts reached")
    rem.reset()
    assert rem.allowed(plan)[0]


def test_escalations_are_not_executed_and_rate_limited(topo: Topology) -> None:
    clock, act = Clock(), FakeActuator()
    rem = Remediator(act, cooldown_s=30, clock=clock)
    plan = plan_remediation([F("bb1", Kind.INTERFACE_OPER_DOWN, "eth1")], topo, no_drift)[0]
    rem.execute(plan)
    assert act.calls == []
    clock.t += 30
    assert not rem.allowed(plan)[0]
    clock.t += 31
    assert rem.allowed(plan)[0]
