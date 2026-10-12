from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ModelError(ValueError):
    pass


@dataclass(frozen=True)
class Interface:
    name: str
    ipv4: list[str] = field(default_factory=list)
    ospf: str | None = None
    isis: str | None = None
    ldp: bool = False
    peer: str | None = None

    @property
    def peer_router(self) -> str | None:
        return self.peer.split(":", 1)[0] if self.peer else None

    @property
    def peer_interface(self) -> str | None:
        return self.peer.split(":", 1)[1] if self.peer else None


@dataclass(frozen=True)
class BgpNeighbor:
    address: str
    remote_as: int
    description: str = ""
    update_source: str | None = None
    next_hop_self: bool = False
    route_reflector_client: bool = False


@dataclass(frozen=True)
class Bgp:
    asn: int
    neighbors: list[BgpNeighbor]
    networks: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Ospf:
    area: str = "0.0.0.0"
    default_originate: bool = False


@dataclass(frozen=True)
class Isis:
    net: str
    default_originate: bool = False
    is_type: str = "level-2-only"


@dataclass(frozen=True)
class Ldp:
    transport_address: str


@dataclass(frozen=True)
class Router:
    name: str
    site: str
    router_id: str
    interfaces: dict[str, Interface]
    ospf: Ospf | None = None
    isis: Isis | None = None
    bgp: Bgp | None = None
    ldp: Ldp | None = None

    @property
    def daemons(self) -> list[str]:
        enabled = []
        if self.bgp:
            enabled.append("bgpd")
        if self.ospf:
            enabled.append("ospfd")
        if self.isis:
            enabled.append("isisd")
        if self.ldp:
            enabled.append("ldpd")
        return enabled


@dataclass(frozen=True)
class TunnelEnd:
    router: str
    local: str
    address: str


@dataclass(frozen=True)
class Tunnel:
    name: str
    type: str
    a: TunnelEnd
    b: TunnelEnd

    def ends(self) -> list[tuple[TunnelEnd, TunnelEnd]]:
        return [(self.a, self.b), (self.b, self.a)]


@dataclass(frozen=True)
class Timers:
    bgp_keepalive: int = 3
    bgp_hold: int = 9
    bgp_connect_retry: int = 5
    ospf_hello: int = 1
    ospf_dead: int = 4
    isis_hello: int = 1
    isis_hello_multiplier: int = 3


@dataclass(frozen=True)
class Link:
    a_router: str
    a_interface: str
    b_router: str
    b_interface: str


@dataclass(frozen=True)
class Network:
    name: str
    image: str
    mgmt_subnet: str
    timers: Timers
    routers: dict[str, Router]
    tunnels: list[Tunnel]

    def container(self, router: str) -> str:
        return f"clab-{self.name}-{router}"

    @property
    def links(self) -> list[Link]:
        seen: set[frozenset[str]] = set()
        links: list[Link] = []
        for router in self.routers.values():
            for iface in router.interfaces.values():
                if not iface.peer:
                    continue
                key = frozenset({f"{router.name}:{iface.name}", iface.peer})
                if key in seen:
                    continue
                seen.add(key)
                links.append(Link(router.name, iface.name, iface.peer_router or "", iface.peer_interface or ""))
        return links


def _interface(name: str, raw: dict[str, Any]) -> Interface:
    addrs = [str(a) for a in raw.get("ipv4", [])]
    for addr in addrs:
        ipaddress.ip_interface(addr)
    return Interface(
        name=name,
        ipv4=addrs,
        ospf=raw.get("ospf"),
        isis=raw.get("isis"),
        ldp=bool(raw.get("ldp", False)),
        peer=raw.get("peer"),
    )


def _router(name: str, raw: dict[str, Any]) -> Router:
    interfaces = {n: _interface(n, v or {}) for n, v in raw.get("interfaces", {}).items()}
    bgp = None
    if "bgp" in raw:
        b = raw["bgp"]
        bgp = Bgp(
            asn=int(b["asn"]),
            networks=[str(n) for n in b.get("networks", [])],
            neighbors=[BgpNeighbor(**n) for n in b.get("neighbors", [])],
        )
    ospf = None
    if "ospf" in raw:
        o = raw["ospf"]
        ospf = Ospf(area=str(o.get("area", "0.0.0.0")), default_originate=bool(o.get("default_originate", False)))
    isis = Isis(**raw["isis"]) if "isis" in raw else None
    ldp = Ldp(**raw["ldp"]) if "ldp" in raw else None
    return Router(
        name=name,
        site=raw["site"],
        router_id=str(raw["router_id"]),
        interfaces=interfaces,
        ospf=ospf,
        isis=isis,
        bgp=bgp,
        ldp=ldp,
    )


def _tunnel(raw: dict[str, Any]) -> Tunnel:
    if raw["type"] not in {"gre", "ipip"}:
        raise ModelError(f"tunnel {raw['name']}: unsupported type {raw['type']}")
    return Tunnel(
        name=raw["name"],
        type=raw["type"],
        a=TunnelEnd(**raw["a"]),
        b=TunnelEnd(**raw["b"]),
    )


def validate(net: Network) -> None:
    for router in net.routers.values():
        for iface in router.interfaces.values():
            if iface.peer is None:
                continue
            peer_router, peer_if = iface.peer_router, iface.peer_interface
            if peer_router not in net.routers:
                raise ModelError(f"{router.name}:{iface.name} peers with unknown router {peer_router}")
            other = net.routers[peer_router].interfaces.get(peer_if or "")
            if other is None or other.peer != f"{router.name}:{iface.name}":
                raise ModelError(f"{router.name}:{iface.name} -> {iface.peer} is not symmetric")
            for mine in iface.ipv4:
                for theirs in other.ipv4:
                    if ipaddress.ip_interface(mine).network != ipaddress.ip_interface(theirs).network:
                        raise ModelError(f"{router.name}:{iface.name} and {iface.peer} are on different subnets")
        if any(i.ldp for i in router.interfaces.values()) and router.ldp is None:
            raise ModelError(f"{router.name}: ldp interfaces set but no ldp block")
    for tun in net.tunnels:
        for end in (tun.a, tun.b):
            if end.router not in net.routers:
                raise ModelError(f"tunnel {tun.name}: unknown router {end.router}")


def load_network(path: Path) -> Network:
    raw = yaml.safe_load(path.read_text())
    lab = raw["lab"]
    net = Network(
        name=lab["name"],
        image=lab["image"],
        mgmt_subnet=lab.get("mgmt_subnet", "172.20.20.0/24"),
        timers=Timers(**raw.get("timers", {})),
        routers={n: _router(n, r) for n, r in raw["routers"].items()},
        tunnels=[_tunnel(t) for t in raw.get("tunnels", [])],
    )
    validate(net)
    return net
