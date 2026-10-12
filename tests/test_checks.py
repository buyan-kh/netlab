from __future__ import annotations

from netlab.checks import Intent, Kind, PeerIntent, RouterIntent, check_pings, check_tunnels, runnable_pings
from netlab.checks import check_router as check
from netlab.collect import PingResult
from netlab.lab import Capabilities
from netlab.model import Network
from netlab.parsers import (
    RouterSnapshot,
    parse_bgp_neighbors_policy,
    parse_bgp_summary,
    parse_interfaces,
    parse_isis_neighbors,
    parse_ospf_neighbors,
    parse_routes,
)

from .conftest import fixture_json

NO_TUNNELS = Capabilities(gre=False, ipip=False, mpls_forwarding=False)
ALL = Capabilities(gre=True, ipip=True, mpls_forwarding=True)


def kinds(findings: list) -> set[tuple[Kind, str]]:  # type: ignore[type-arg]
    return {(f.kind, f.target) for f in findings}


def test_healthy_bb1_bgp_and_ldp(intent: Intent) -> None:
    snap = RouterSnapshot(
        "bb1",
        bgp_peers=parse_bgp_summary(fixture_json("healthy", "bb1_bgp_summary")),
        bgp_policy=parse_bgp_neighbors_policy(fixture_json("healthy", "bb1_bgp_neighbors")),
    )
    ri = intent.routers["bb1"]
    only_bgp = RouterIntent(bgp_peers=ri.bgp_peers)
    assert check(only_bgp, snap) == []


def test_healthy_igp_and_routes(intent: Intent) -> None:
    dca = RouterSnapshot(
        "dca-edge",
        interfaces=parse_interfaces(fixture_json("healthy", "dca-edge_interface")),
        ospf_neighbors=parse_ospf_neighbors(fixture_json("healthy", "dca-edge_ospf_neighbor")),
    )
    ri = intent.routers["dca-edge"]
    assert check(RouterIntent(interfaces_up=ri.interfaces_up, ospf_neighbors=ri.ospf_neighbors), dca) == []

    dcb = RouterSnapshot(
        "dcb-edge", isis_adjacencies=parse_isis_neighbors(fixture_json("healthy", "dcb-edge_isis_neighbor"))
    )
    assert check(RouterIntent(isis_adjacencies=intent.routers["dcb-edge"].isis_adjacencies), dcb) == []

    for router, fixture in (("bb2", "bb2_route"), ("dca-r1", "dca-r1_route")):
        snap = RouterSnapshot(router, routes=parse_routes(fixture_json("healthy", fixture)))
        assert check(RouterIntent(routes=intent.routers[router].routes), snap) == []


def test_link_down_local_side(intent: Intent) -> None:
    snap = RouterSnapshot("dca-edge", interfaces=parse_interfaces(fixture_json("link_down", "dca-edge_interface")))
    found = check(RouterIntent(interfaces_up=intent.routers["dca-edge"].interfaces_up), snap)
    assert kinds(found) == {(Kind.INTERFACE_ADMIN_DOWN, "eth2")}


def test_link_down_remote_side(intent: Intent) -> None:
    snap = RouterSnapshot(
        "bb1",
        interfaces=parse_interfaces(fixture_json("link_down", "bb1_interface")),
        bgp_peers=parse_bgp_summary(fixture_json("link_down", "bb1_bgp_summary")),
    )
    ri = intent.routers["bb1"]
    found = check(RouterIntent(interfaces_up=ri.interfaces_up, bgp_peers=ri.bgp_peers), snap)
    assert kinds(found) == {(Kind.INTERFACE_OPER_DOWN, "eth1"), (Kind.BGP_PEER_DOWN, "172.16.10.0")}


def test_link_down_routes_withdrawn_downstream(intent: Intent) -> None:
    snap = RouterSnapshot("bb2", routes=parse_routes(fixture_json("link_down", "bb2_route")))
    found = check(RouterIntent(routes=intent.routers["bb2"].routes), snap)
    assert kinds(found) == {(Kind.ROUTE_MISSING, "10.0.1.1/32"), (Kind.ROUTE_MISSING, "10.0.1.2/32")}


def test_config_delete(intent: Intent) -> None:
    bb2 = RouterSnapshot("bb2", bgp_peers=parse_bgp_summary(fixture_json("config_delete", "bb2_bgp_summary")))
    assert kinds(check(RouterIntent(bgp_peers=intent.routers["bb2"].bgp_peers), bb2)) == {
        (Kind.BGP_PEER_MISSING, "172.16.20.0")
    }
    dcb = RouterSnapshot(
        "dcb-edge",
        bgp_peers=parse_bgp_summary(fixture_json("config_delete", "dcb-edge_bgp_summary")),
        routes=parse_routes(fixture_json("config_delete", "dcb-edge_route")),
    )
    ri = intent.routers["dcb-edge"]
    found = check(RouterIntent(bgp_peers=ri.bgp_peers, routes=ri.routes), dcb)
    assert kinds(found) == {
        (Kind.BGP_PEER_DOWN, "172.16.20.1"),
        (Kind.ROUTE_MISSING, "10.0.1.1/32"),
        (Kind.ROUTE_MISSING, "10.0.1.2/32"),
    }


def test_bad_route_map(intent: Intent) -> None:
    snap = RouterSnapshot(
        "bb1",
        bgp_peers=parse_bgp_summary(fixture_json("bad_route_map", "bb1_bgp_summary")),
        bgp_policy=parse_bgp_neighbors_policy(fixture_json("bad_route_map", "bb1_bgp_neighbors")),
    )
    found = check(RouterIntent(bgp_peers=intent.routers["bb1"].bgp_peers), snap)
    assert kinds(found) == {(Kind.BGP_POLICY_MISMATCH, "172.16.10.0")}
    assert "RM-CHAOS-DENY" in found[0].detail


def test_wrong_protocol() -> None:
    snap = RouterSnapshot("dca-r1", routes=parse_routes(fixture_json("healthy", "dca-r1_route")))
    found = check(RouterIntent(routes={"10.0.1.2/32": "isis"}), snap)
    assert kinds(found) == {(Kind.ROUTE_WRONG_PROTOCOL, "10.0.1.2/32")}


def test_missing_interface_counts_as_down() -> None:
    found = check(RouterIntent(interfaces_up=["eth9"]), RouterSnapshot("x"))
    assert kinds(found) == {(Kind.INTERFACE_ADMIN_DOWN, "eth9")}


def test_collection_errors_surface() -> None:
    snap = RouterSnapshot("bb1", errors=["show bgp summary json: timeout"])
    found = check(RouterIntent(bgp_peers={"10.0.0.2": PeerIntent()}), snap)
    assert (Kind.COLLECTION_ERROR, "show bgp summary json") in kinds(found)


def test_tunnels_skipped_without_kernel_support(net: Network) -> None:
    snaps = {r: RouterSnapshot(r) for r in net.routers}
    assert check_tunnels(net, NO_TUNNELS, snaps) == []
    found = check_tunnels(net, ALL, snaps)
    assert {(f.router, f.target) for f in found} == {
        ("dca-edge", "gre-ab"),
        ("dcb-edge", "gre-ab"),
        ("dca-r1", "ipip-ab"),
        ("dcb-r1", "ipip-ab"),
    }


def test_pings_filtered_by_capability(intent: Intent, net: Network) -> None:
    assert [p.name for p in runnable_pings(intent, net, NO_TUNNELS)] == ["dca-r1-to-dcb-r1"]
    assert len(runnable_pings(intent, net, ALL)) == 3
    found = check_pings([PingResult("gre-ab", "dca-edge", "192.168.100.2", False, None)])
    assert kinds(found) == {(Kind.PING_FAILED, "gre-ab")}
