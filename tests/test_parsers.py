from __future__ import annotations

from netlab.parsers import (
    parse_bgp_neighbors_policy,
    parse_bgp_summary,
    parse_interfaces,
    parse_isis_neighbors,
    parse_ldp_neighbors,
    parse_ospf_neighbors,
    parse_routes,
)

from .conftest import fixture_json


def test_interfaces_healthy() -> None:
    ifs = parse_interfaces(fixture_json("healthy", "dca-edge_interface"))
    assert set(ifs) == {"eth0", "eth1", "eth2", "lo"}
    assert ifs["eth2"].admin_up and ifs["eth2"].oper_up
    assert ifs["eth2"].addresses == ("172.16.10.0/31",)


def test_interface_admin_down_has_no_operational_status_key() -> None:
    raw = fixture_json("link_down", "dca-edge_interface")
    assert "operationalStatus" not in raw["eth2"]
    eth2 = parse_interfaces(raw)["eth2"]
    assert not eth2.admin_up and not eth2.oper_up


def test_interface_partner_loses_carrier() -> None:
    eth1 = parse_interfaces(fixture_json("link_down", "bb1_interface"))["eth1"]
    assert eth1.admin_up and not eth1.oper_up


def test_bgp_summary_established() -> None:
    peers = parse_bgp_summary(fixture_json("healthy", "bb1_bgp_summary"))
    assert set(peers) == {"10.0.0.2", "172.16.10.0"}
    assert all(p.established for p in peers.values())
    assert peers["172.16.10.0"].remote_as == 65001
    assert peers["172.16.10.0"].prefixes_received == 2
    assert peers["10.0.0.2"].description == "bb2"


def test_bgp_summary_after_link_down() -> None:
    peer = parse_bgp_summary(fixture_json("link_down", "bb1_bgp_summary"))["172.16.10.0"]
    assert peer.state == "Active" and not peer.established
    assert peer.prefixes_received == 0


def test_bgp_summary_after_neighbor_deleted() -> None:
    peers = parse_bgp_summary(fixture_json("config_delete", "bb2_bgp_summary"))
    assert "172.16.20.0" not in peers
    assert peers["10.0.0.1"].established
    remote = parse_bgp_summary(fixture_json("config_delete", "dcb-edge_bgp_summary"))["172.16.20.1"]
    assert not remote.established


def test_bgp_policy() -> None:
    pol = parse_bgp_neighbors_policy(fixture_json("healthy", "bb1_bgp_neighbors"))
    assert pol["172.16.10.0"].route_map_in == "RM-EBGP-IN"
    assert pol["172.16.10.0"].route_map_out == "RM-EBGP-OUT"
    assert pol["10.0.0.2"].route_map_in is None
    bad = parse_bgp_neighbors_policy(fixture_json("bad_route_map", "bb1_bgp_neighbors"))
    assert bad["172.16.10.0"].route_map_in == "RM-CHAOS-DENY"


def test_bad_route_map_keeps_session_up_but_drops_prefixes() -> None:
    peer = parse_bgp_summary(fixture_json("bad_route_map", "bb1_bgp_summary"))["172.16.10.0"]
    assert peer.established and peer.prefixes_received == 0


def test_ospf_neighbors() -> None:
    nbrs = parse_ospf_neighbors(fixture_json("healthy", "dca-edge_ospf_neighbor"))
    n = nbrs["10.0.1.1"]
    assert n.full and n.state == "Full/-" and n.interface == "eth1"


def test_isis_neighbors_skip_passive_circuits() -> None:
    adj = parse_isis_neighbors(fixture_json("healthy", "dcb-edge_isis_neighbor"))
    assert len(adj) == 1
    assert adj[0].system == "dcb-r1" and adj[0].interface == "eth1" and adj[0].level == 2 and adj[0].up


def test_ldp_neighbors() -> None:
    nbrs = parse_ldp_neighbors(fixture_json("healthy", "bb1_ldp_neighbor"))
    assert nbrs["10.0.0.2"].operational


def test_routes_select_best_entry() -> None:
    routes = parse_routes(fixture_json("healthy", "dca-r1_route"))
    assert routes["0.0.0.0/0"].protocol == "ospf"
    assert routes["0.0.0.0/0"].nexthops == ("172.16.1.1",)
    assert routes["10.0.1.1/32"].protocol == "connected"


def test_routes_recursive_bgp_nexthop_resolves_to_igp() -> None:
    r = parse_routes(fixture_json("healthy", "bb2_route"))["10.0.1.1/32"]
    assert r.protocol == "bgp" and r.installed
    assert r.nexthops == ("172.16.0.0",)


def test_routes_withdrawn_after_link_down() -> None:
    routes = parse_routes(fixture_json("link_down", "bb2_route"))
    assert "10.0.1.1/32" not in routes and "10.0.1.2/32" not in routes
    assert routes["10.0.2.1/32"].protocol == "bgp"
