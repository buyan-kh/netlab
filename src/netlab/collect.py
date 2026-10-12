from __future__ import annotations

import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from netlab.model import Network
from netlab.parsers import (
    RouterSnapshot,
    parse_bgp_neighbors_policy,
    parse_bgp_summary,
    parse_interfaces,
    parse_isis_neighbors,
    parse_ldp_neighbors,
    parse_ospf_neighbors,
    parse_routes,
)
from netlab.runner import CommandError, RouterShell

_RTT = re.compile(r"time=([\d.]+) ?ms")


@dataclass(frozen=True)
class PingResult:
    name: str
    router: str
    destination: str
    success: bool
    rtt_ms: float | None
    skipped: bool = False


def collect_router(shell: RouterShell, net: Network, router: str) -> RouterSnapshot:
    r = net.routers[router]
    snap = RouterSnapshot(router=router)

    def grab(cmd: str, parse: Callable[[Any], None]) -> None:
        try:
            parse(shell.vtysh_json(router, cmd))
        except (CommandError, ValueError, KeyError, TypeError) as exc:
            snap.errors.append(f"{cmd}: {exc}")

    def set_interfaces(d: Any) -> None:
        snap.interfaces = parse_interfaces(d)

    def set_routes(d: Any) -> None:
        snap.routes = parse_routes(d)

    def set_bgp(d: Any) -> None:
        snap.bgp_peers = parse_bgp_summary(d)

    def set_policy(d: Any) -> None:
        snap.bgp_policy = parse_bgp_neighbors_policy(d)

    def set_ospf(d: Any) -> None:
        snap.ospf_neighbors = parse_ospf_neighbors(d)

    def set_isis(d: Any) -> None:
        snap.isis_adjacencies = parse_isis_neighbors(d)

    def set_ldp(d: Any) -> None:
        snap.ldp_neighbors = parse_ldp_neighbors(d)

    grab("show interface json", set_interfaces)
    grab("show ip route json", set_routes)
    if r.bgp:
        grab("show bgp summary json", set_bgp)
        grab("show bgp neighbors json", set_policy)
    if r.ospf:
        grab("show ip ospf neighbor json", set_ospf)
    if r.isis:
        grab("show isis neighbor json", set_isis)
    if r.ldp:
        grab("show mpls ldp neighbor json", set_ldp)
    return snap


def ping(shell: RouterShell, name: str, router: str, destination: str, source: str | None) -> PingResult:
    argv = ["ping", "-c", "1", "-W", "1"]
    if source:
        argv += ["-I", source]
    res = shell.exec(router, [*argv, destination], timeout=5)
    m = _RTT.search(res.stdout)
    return PingResult(name, router, destination, res.ok, float(m.group(1)) if m else None)


def collect_all(shell: RouterShell, net: Network, workers: int = 8) -> dict[str, RouterSnapshot]:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {r: pool.submit(collect_router, shell, net, r) for r in net.routers}
        return {r: f.result() for r, f in futures.items()}
