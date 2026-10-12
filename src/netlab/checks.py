from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from netlab.collect import PingResult
from netlab.lab import Capabilities
from netlab.model import Network
from netlab.parsers import RouterSnapshot


class Kind(str, Enum):
    COLLECTION_ERROR = "collection_error"
    INTERFACE_ADMIN_DOWN = "interface_admin_down"
    INTERFACE_OPER_DOWN = "interface_oper_down"
    BGP_PEER_MISSING = "bgp_peer_missing"
    BGP_PEER_DOWN = "bgp_peer_down"
    BGP_POLICY_MISMATCH = "bgp_policy_mismatch"
    OSPF_NEIGHBOR_DOWN = "ospf_neighbor_down"
    ISIS_ADJACENCY_DOWN = "isis_adjacency_down"
    LDP_NEIGHBOR_DOWN = "ldp_neighbor_down"
    ROUTE_MISSING = "route_missing"
    ROUTE_WRONG_PROTOCOL = "route_wrong_protocol"
    TUNNEL_MISSING = "tunnel_missing"
    PING_FAILED = "ping_failed"


@dataclass(frozen=True)
class Finding:
    router: str
    kind: Kind
    target: str
    detail: str = ""

    @property
    def key(self) -> str:
        return f"{self.router}/{self.kind.value}/{self.target}"


@dataclass(frozen=True)
class PeerIntent:
    route_map_in: str | None = None
    route_map_out: str | None = None


@dataclass(frozen=True)
class RouterIntent:
    interfaces_up: list[str] = field(default_factory=list)
    ospf_neighbors: list[str] = field(default_factory=list)
    isis_adjacencies: list[str] = field(default_factory=list)
    ldp_neighbors: list[str] = field(default_factory=list)
    bgp_peers: dict[str, PeerIntent] = field(default_factory=dict)
    routes: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class PingIntent:
    name: str
    router: str
    destination: str
    source: str | None = None
    tunnel: str | None = None


@dataclass(frozen=True)
class Intent:
    routers: dict[str, RouterIntent]
    pings: list[PingIntent]


def _router_intent(raw: dict[str, Any]) -> RouterIntent:
    return RouterIntent(
        interfaces_up=list(raw.get("interfaces_up", [])),
        ospf_neighbors=[str(x) for x in raw.get("ospf_neighbors", [])],
        isis_adjacencies=[str(x) for x in raw.get("isis_adjacencies", [])],
        ldp_neighbors=[str(x) for x in raw.get("ldp_neighbors", [])],
        bgp_peers={str(k): PeerIntent(**(v or {})) for k, v in raw.get("bgp_peers", {}).items()},
        routes={str(k): str(v) for k, v in raw.get("routes", {}).items()},
    )


def parse_intent(raw: dict[str, Any]) -> Intent:
    return Intent(
        routers={name: _router_intent(r or {}) for name, r in raw.get("routers", {}).items()},
        pings=[
            PingIntent(
                name=p["name"],
                router=p["from"],
                destination=str(p["to"]),
                source=p.get("source"),
                tunnel=p.get("tunnel"),
            )
            for p in raw.get("pings", [])
        ],
    )


def load_intent(path: Path) -> Intent:
    return parse_intent(yaml.safe_load(path.read_text()))


def check_router(intent: RouterIntent, snap: RouterSnapshot) -> list[Finding]:
    r = snap.router
    out = [Finding(r, Kind.COLLECTION_ERROR, err.split(":", 1)[0], err) for err in snap.errors]

    for name in intent.interfaces_up:
        st = snap.interfaces.get(name)
        if st is None or not st.admin_up:
            out.append(Finding(r, Kind.INTERFACE_ADMIN_DOWN, name, "missing" if st is None else "admin down"))
        elif not st.oper_up:
            out.append(Finding(r, Kind.INTERFACE_OPER_DOWN, name, "admin up, no carrier"))

    for addr, want in intent.bgp_peers.items():
        peer = snap.bgp_peers.get(addr)
        if peer is None:
            out.append(Finding(r, Kind.BGP_PEER_MISSING, addr, "not in running config"))
            continue
        if not peer.established:
            out.append(Finding(r, Kind.BGP_PEER_DOWN, addr, f"state {peer.state}"))
        pol = snap.bgp_policy.get(addr)
        if pol is not None and (pol.route_map_in, pol.route_map_out) != (want.route_map_in, want.route_map_out):
            out.append(
                Finding(
                    r,
                    Kind.BGP_POLICY_MISMATCH,
                    addr,
                    f"in={pol.route_map_in} out={pol.route_map_out}, "
                    f"expected in={want.route_map_in} out={want.route_map_out}",
                )
            )

    for rid in intent.ospf_neighbors:
        nbr = snap.ospf_neighbors.get(rid)
        if nbr is None or not nbr.full:
            out.append(Finding(r, Kind.OSPF_NEIGHBOR_DOWN, rid, "absent" if nbr is None else nbr.state))

    up_systems = {a.system for a in snap.isis_adjacencies if a.up}
    for system in intent.isis_adjacencies:
        if system not in up_systems:
            out.append(Finding(r, Kind.ISIS_ADJACENCY_DOWN, system, "no Up adjacency"))

    for nid in intent.ldp_neighbors:
        ldp = snap.ldp_neighbors.get(nid)
        if ldp is None or not ldp.operational:
            out.append(Finding(r, Kind.LDP_NEIGHBOR_DOWN, nid, "absent" if ldp is None else ldp.state))

    for prefix, proto in intent.routes.items():
        route = snap.routes.get(prefix)
        if route is None:
            out.append(Finding(r, Kind.ROUTE_MISSING, prefix, f"expected via {proto}"))
        elif route.protocol != proto:
            out.append(Finding(r, Kind.ROUTE_WRONG_PROTOCOL, prefix, f"via {route.protocol}, expected {proto}"))
    return out


def check_tunnels(net: Network, caps: Capabilities, snaps: dict[str, RouterSnapshot]) -> list[Finding]:
    out: list[Finding] = []
    for tun in net.tunnels:
        if not caps.supports(tun.type):
            continue
        for end in (tun.a, tun.b):
            snap = snaps.get(end.router)
            if snap is None or snap.errors:
                continue
            st = snap.interfaces.get(tun.name)
            if st is None:
                out.append(Finding(end.router, Kind.TUNNEL_MISSING, tun.name, f"{tun.type} interface absent"))
            elif not st.admin_up:
                out.append(Finding(end.router, Kind.INTERFACE_ADMIN_DOWN, tun.name, "tunnel admin down"))
    return out


def runnable_pings(intent: Intent, net: Network, caps: Capabilities) -> list[PingIntent]:
    by_name = {t.name: t for t in net.tunnels}
    return [
        p for p in intent.pings if p.tunnel is None or (p.tunnel in by_name and caps.supports(by_name[p.tunnel].type))
    ]


def check_pings(results: list[PingResult]) -> list[Finding]:
    return [
        Finding(p.router, Kind.PING_FAILED, p.name, f"no reply from {p.destination}")
        for p in results
        if not p.success and not p.skipped
    ]


def evaluate(
    intent: Intent,
    net: Network,
    caps: Capabilities,
    snaps: dict[str, RouterSnapshot],
    pings: list[PingResult],
) -> list[Finding]:
    findings: list[Finding] = []
    for name, ri in intent.routers.items():
        if name in snaps:
            findings += check_router(ri, snaps[name])
    findings += check_tunnels(net, caps, snaps)
    findings += check_pings(pings)
    return findings
