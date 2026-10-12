from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from netlab.model import ModelError, Network, load_network
from netlab.render import render_router, render_topology, write_build

from .conftest import ROOT


def conf(net: Network, router: str) -> str:
    return render_router(net, net.routers[router]).frr_conf


def test_ospf_site_router(net: Network) -> None:
    c = conf(net, "dca-edge")
    assert "interface eth1\n ip address 172.16.1.1/31\n ip ospf area 0.0.0.0\n" in c
    assert " ip ospf network point-to-point" in c
    assert " ip ospf hello-interval 1\n" in c and " ip ospf dead-interval 4\n" in c
    assert "router ospf\n ospf router-id 10.0.1.2\n default-information originate always\n" in c
    assert "router isis" not in c and "mpls ldp" not in c


def test_isis_site_router(net: Network) -> None:
    c = conf(net, "dcb-edge")
    assert "router isis core\n is-type level-2-only\n net 49.0002.0100.0000.2002.00\n" in c
    assert " default-information originate ipv4 level-2 always" in c
    assert "interface lo\n ip address 10.0.2.2/32\n ip router isis core\n isis passive\n" in c
    assert " isis network point-to-point" in c
    assert "router ospf" not in c


def test_ebgp_edge_gets_policy_and_networks(net: Network) -> None:
    c = conf(net, "dcb-edge")
    assert "router bgp 65002" in c
    for prefix in ("10.0.2.1/32", "10.0.2.2/32"):
        assert f"  network {prefix}\n" in c
    assert "  neighbor 172.16.20.1 route-map RM-EBGP-IN in" in c
    assert "  neighbor 172.16.20.1 route-map RM-EBGP-OUT out" in c
    assert "ip prefix-list PL-LAB-PREFIXES seq 10 permit 10.0.0.0/8 le 32" in c
    assert " neighbor 172.16.20.1 timers connect 5" in c


def test_route_reflector_and_ibgp(net: Network) -> None:
    c = conf(net, "bb1")
    assert " bgp cluster-id 10.0.0.1" in c
    assert " neighbor 10.0.0.2 update-source lo" in c
    assert "  neighbor 10.0.0.2 next-hop-self" in c
    assert "  neighbor 10.0.0.2 route-reflector-client" in c
    assert "neighbor 10.0.0.2 route-map" not in c
    c2 = conf(net, "bb2")
    assert "route-reflector-client" not in c2 and "cluster-id" not in c2


def test_ldp_only_on_backbone(net: Network) -> None:
    c = conf(net, "bb1")
    assert "mpls ldp\n router-id 10.0.0.1\n" in c
    assert "  discovery transport-address 10.0.0.1" in c
    assert "  interface eth2\n" in c
    assert "  interface eth1\n" not in c
    for r in ("dca-r1", "dca-edge", "dcb-edge", "dcb-r1"):
        assert "mpls ldp" not in conf(net, r)


def test_internal_router_has_no_bgp(net: Network) -> None:
    c = conf(net, "dca-r1")
    assert "router bgp" not in c and "prefix-list" not in c and "route-map" not in c


def test_daemons_file(net: Network) -> None:
    lines = render_router(net, net.routers["bb1"]).daemons.splitlines()
    assert "bgpd=yes" in lines and "ospfd=yes" in lines and "ldpd=yes" in lines
    assert "isisd=no" in lines and "ripd=no" in lines
    dcb = render_router(net, net.routers["dcb-r1"]).daemons.splitlines()
    assert "isisd=yes" in dcb and "bgpd=no" in dcb


def test_topology(net: Network) -> None:
    topo = yaml.safe_load(render_topology(net))
    assert topo["name"] == "netlab"
    assert set(topo["topology"]["nodes"]) == set(net.routers)
    endpoints = [tuple(link["endpoints"]) for link in topo["topology"]["links"]]
    assert len(endpoints) == 5
    assert ("dca-edge:eth2", "bb1:eth1") in endpoints
    node = topo["topology"]["nodes"]["bb1"]
    assert node["binds"] == ["configs/bb1:/etc/frr"]
    assert node["exec"] == ["ip route del default"]


def test_write_build(net: Network, tmp_path: Path) -> None:
    written = write_build(net, tmp_path)
    assert (tmp_path / "netlab.clab.yml").exists()
    assert (tmp_path / "configs" / "bb2" / "frr.conf").read_text().startswith("frr version")
    assert len(written) == 3 * len(net.routers) + 1


def _mutate(tmp_path: Path, fn: object) -> Path:
    raw = yaml.safe_load((ROOT / "lab" / "network.yml").read_text())
    fn(raw)  # type: ignore[operator]
    p = tmp_path / "network.yml"
    p.write_text(yaml.safe_dump(raw))
    return p


def test_rejects_asymmetric_link(tmp_path: Path) -> None:
    def bad(raw: dict) -> None:  # type: ignore[type-arg]
        raw["routers"]["bb1"]["interfaces"]["eth2"]["peer"] = "bb2:eth2"

    with pytest.raises(ModelError, match="not symmetric"):
        load_network(_mutate(tmp_path, bad))


def test_rejects_subnet_mismatch(tmp_path: Path) -> None:
    def bad(raw: dict) -> None:  # type: ignore[type-arg]
        raw["routers"]["bb1"]["interfaces"]["eth2"]["ipv4"] = ["172.16.9.0/31"]

    with pytest.raises(ModelError, match="different subnets"):
        load_network(_mutate(tmp_path, bad))
