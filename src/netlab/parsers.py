from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class InterfaceState:
    name: str
    admin_up: bool
    oper_up: bool
    addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class BgpPeerState:
    address: str
    remote_as: int
    state: str
    prefixes_received: int
    description: str = ""

    @property
    def established(self) -> bool:
        return self.state == "Established"


@dataclass(frozen=True)
class BgpPolicy:
    route_map_in: str | None
    route_map_out: str | None


@dataclass(frozen=True)
class OspfNeighbor:
    router_id: str
    state: str
    interface: str

    @property
    def full(self) -> bool:
        return self.state.split("/", 1)[0] == "Full"


@dataclass(frozen=True)
class IsisAdjacency:
    system: str
    interface: str
    level: int
    state: str

    @property
    def up(self) -> bool:
        return self.state == "Up"


@dataclass(frozen=True)
class LdpNeighbor:
    neighbor_id: str
    state: str

    @property
    def operational(self) -> bool:
        return self.state == "OPERATIONAL"


@dataclass(frozen=True)
class RouteEntry:
    prefix: str
    protocol: str
    installed: bool
    nexthops: tuple[str, ...] = ()


@dataclass
class RouterSnapshot:
    router: str
    interfaces: dict[str, InterfaceState] = field(default_factory=dict)
    bgp_peers: dict[str, BgpPeerState] = field(default_factory=dict)
    bgp_policy: dict[str, BgpPolicy] = field(default_factory=dict)
    ospf_neighbors: dict[str, OspfNeighbor] = field(default_factory=dict)
    isis_adjacencies: list[IsisAdjacency] = field(default_factory=list)
    ldp_neighbors: dict[str, LdpNeighbor] = field(default_factory=dict)
    routes: dict[str, RouteEntry] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def parse_interfaces(data: dict[str, Any]) -> dict[str, InterfaceState]:
    """`show interface json`. FRR omits operationalStatus when the interface is admin down."""
    out: dict[str, InterfaceState] = {}
    for name, info in data.items():
        flags = str(info.get("flags", ""))
        admin_up = info.get("administrativeStatus") == "up"
        oper_status = info.get("operationalStatus")
        oper_up = oper_status == "up" if oper_status is not None else admin_up and "LOWER_UP" in flags
        addrs = tuple(a["address"] for a in info.get("ipAddresses", []) if ":" not in a.get("address", ":"))
        out[name] = InterfaceState(name=name, admin_up=admin_up, oper_up=oper_up, addresses=addrs)
    return out


def parse_bgp_summary(data: dict[str, Any]) -> dict[str, BgpPeerState]:
    """`show bgp summary json` (IPv4 unicast)."""
    peers = data.get("ipv4Unicast", {}).get("peers", {})
    return {
        addr: BgpPeerState(
            address=addr,
            remote_as=int(p.get("remoteAs", 0)),
            state=str(p.get("state", "Unknown")),
            prefixes_received=int(p.get("pfxRcd", 0) or 0),
            description=str(p.get("desc", "")),
        )
        for addr, p in peers.items()
    }


def parse_bgp_neighbors_policy(data: dict[str, Any]) -> dict[str, BgpPolicy]:
    """`show bgp neighbors json`: per-peer IPv4 unicast route-maps."""
    out: dict[str, BgpPolicy] = {}
    for addr, info in data.items():
        if not isinstance(info, dict) or "addressFamilyInfo" not in info:
            continue
        af = info["addressFamilyInfo"].get("ipv4Unicast", {})
        out[addr] = BgpPolicy(
            route_map_in=af.get("routeMapForIncomingAdvertisements"),
            route_map_out=af.get("routeMapForOutgoingAdvertisements"),
        )
    return out


def parse_ospf_neighbors(data: dict[str, Any]) -> dict[str, OspfNeighbor]:
    """`show ip ospf neighbor json`. ifaceName is "<ifname>:<local address>"."""
    out: dict[str, OspfNeighbor] = {}
    for rid, entries in data.get("neighbors", {}).items():
        for e in entries:
            out[rid] = OspfNeighbor(
                router_id=rid,
                state=str(e.get("nbrState", "Down")),
                interface=str(e.get("ifaceName", "")).split(":", 1)[0],
            )
    return out


def parse_isis_neighbors(data: dict[str, Any]) -> list[IsisAdjacency]:
    """`show isis neighbor json`. Passive circuits appear as bare {"circuit": N} entries."""
    out: list[IsisAdjacency] = []
    for area in data.get("areas", []):
        for c in area.get("circuits", []):
            if "adj" not in c:
                continue
            out.append(
                IsisAdjacency(
                    system=str(c["adj"]),
                    interface=str(c.get("interface", "")),
                    level=int(c.get("level", 0)),
                    state=str(c.get("state", "Down")),
                )
            )
    return out


def parse_ldp_neighbors(data: dict[str, Any]) -> dict[str, LdpNeighbor]:
    """`show mpls ldp neighbor json`."""
    return {
        n["neighborId"]: LdpNeighbor(neighbor_id=n["neighborId"], state=str(n.get("state", "")))
        for n in data.get("neighbors", [])
        if "neighborId" in n
    }


def parse_routes(data: dict[str, Any]) -> dict[str, RouteEntry]:
    """`show ip route json`: keep the selected entry per prefix."""
    out: dict[str, RouteEntry] = {}
    for prefix, entries in data.items():
        selected = [e for e in entries if e.get("selected")]
        if not selected:
            continue
        e = selected[0]
        hops = tuple(
            nh.get("ip") or nh.get("interfaceName", "")
            for nh in e.get("nexthops", [])
            if nh.get("active") and not nh.get("recursive")
        )
        out[prefix] = RouteEntry(
            prefix=prefix,
            protocol=str(e.get("protocol", "")),
            installed=bool(e.get("installed", False)),
            nexthops=hops,
        )
    return out
