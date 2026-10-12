from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from prometheus_client import generate_latest

from netlab.checks import Intent
from netlab.collect import PingResult
from netlab.lab import Capabilities, Lab
from netlab.metrics import Metrics
from netlab.model import Network
from netlab.monitor import Monitor
from netlab.parsers import RouterSnapshot, parse_interfaces
from netlab.remediation import Remediator

from .conftest import FakeRunner, fixture_json
from .test_remediation import Clock, FakeActuator

CAPS = Capabilities(gre=False, ipip=False, mpls_forwarding=False)


class Scripted:
    """Serves healthy snapshots built from intent, optionally with dca-edge:eth2 shut."""

    def __init__(self, net: Network, intent: Intent) -> None:
        self.net, self.intent, self.broken = net, intent, False

    def __call__(self) -> tuple[dict[str, RouterSnapshot], list[PingResult]]:
        from netlab.parsers import (
            BgpPeerState,
            BgpPolicy,
            InterfaceState,
            IsisAdjacency,
            LdpNeighbor,
            OspfNeighbor,
            RouteEntry,
        )

        snaps: dict[str, RouterSnapshot] = {}
        for name, ri in self.intent.routers.items():
            s = RouterSnapshot(name)
            s.interfaces = {i: InterfaceState(i, True, True) for i in ri.interfaces_up}
            s.bgp_peers = {a: BgpPeerState(a, 1, "Established", 1) for a in ri.bgp_peers}
            s.bgp_policy = {a: BgpPolicy(p.route_map_in, p.route_map_out) for a, p in ri.bgp_peers.items()}
            s.ospf_neighbors = {n: OspfNeighbor(n, "Full/-", "eth1") for n in ri.ospf_neighbors}
            s.isis_adjacencies = [IsisAdjacency(n, "eth1", 2, "Up") for n in ri.isis_adjacencies]
            s.ldp_neighbors = {n: LdpNeighbor(n, "OPERATIONAL") for n in ri.ldp_neighbors}
            s.routes = {p: RouteEntry(p, proto, True) for p, proto in ri.routes.items()}
            snaps[name] = s
        if self.broken:
            snaps["dca-edge"].interfaces = parse_interfaces(fixture_json("link_down", "dca-edge_interface"))
            snaps["bb1"].bgp_peers["172.16.10.0"] = BgpPeerState("172.16.10.0", 65001, "Active", 0)
        return snaps, [PingResult("dca-r1-to-dcb-r1", "dca-r1", "10.0.2.1", not self.broken, 0.1)]


@pytest.fixture
def setup(net: Network, intent: Intent, tmp_path: Path) -> tuple[Monitor, Scripted, FakeActuator, Clock]:
    clock, act = Clock(), FakeActuator()
    scripted = Scripted(net, intent)
    mon = Monitor(
        Lab(net, FakeRunner(), tmp_path),
        intent,
        CAPS,
        Metrics(),
        Remediator(act, clock=clock),
        status_file=tmp_path / "status.json",
        collector=scripted,
    )
    return mon, scripted, act, clock


def test_healthy_poll(setup: tuple[Monitor, Scripted, FakeActuator, Clock], tmp_path: Path) -> None:
    mon, _, act, _ = setup
    res = mon.poll_once()
    assert res.findings == [] and res.plans == [] and act.calls == []
    status = json.loads((tmp_path / "status.json").read_text())
    assert status["healthy"] and status["incident"] is None
    assert b"netlab_healthy 1.0" in generate_latest(mon.metrics.registry)


def test_failure_is_detected_fixed_and_resolved(
    setup: tuple[Monitor, Scripted, FakeActuator, Clock], caplog: pytest.LogCaptureFixture
) -> None:
    mon, scripted, act, clock = setup
    caplog.set_level(logging.INFO, logger="netlab.monitor")
    mon.poll_once()
    scripted.broken = True
    res = mon.poll_once()
    assert act.calls == [("up", "dca-edge", "eth2")]
    assert mon.incident is not None
    assert {p.root_cause.split(" ")[0] for p in res.plans} == {"dca-edge:eth2"}

    clock.t += 1
    mon.poll_once()
    assert act.calls == [("up", "dca-edge", "eth2")], "no repeat while settling"

    scripted.broken = False
    mon.poll_once()
    assert mon.incident is None
    events = [r.getMessage() for r in caplog.records]
    for e in ("incident_opened", "finding_detected", "diagnosis", "remediation_applied", "incident_resolved"):
        assert e in events
    metrics = generate_latest(mon.metrics.registry).decode()
    assert 'netlab_remediations_total{action="interface_up",result="ok"} 1.0' in metrics
    assert "netlab_incidents_total 1.0" in metrics


def test_diagnose_only_mode(setup: tuple[Monitor, Scripted, FakeActuator, Clock]) -> None:
    mon, scripted, act, _ = setup
    mon.remediate = False
    scripted.broken = True
    mon.poll_once()
    assert act.calls == []
