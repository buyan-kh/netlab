from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined

from netlab.model import Network, Router

ALL_DAEMONS = [
    "bgpd",
    "ospfd",
    "ospf6d",
    "ripd",
    "ripngd",
    "isisd",
    "pimd",
    "pim6d",
    "ldpd",
    "nhrpd",
    "eigrpd",
    "babeld",
    "sharpd",
    "pbrd",
    "bfdd",
    "fabricd",
    "vrrpd",
    "pathd",
]
ISIS_TAG = "core"


def _env() -> Environment:
    return Environment(
        loader=PackageLoader("netlab", "templates"),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


@dataclass(frozen=True)
class RenderedRouter:
    frr_conf: str
    daemons: str
    vtysh_conf: str


def render_router(net: Network, router: Router) -> RenderedRouter:
    env = _env()
    ebgp = [n for n in router.bgp.neighbors if n.remote_as != router.bgp.asn] if router.bgp else []
    rr_clients = [n for n in router.bgp.neighbors if n.route_reflector_client] if router.bgp else []
    frr = env.get_template("frr.conf.j2").render(
        router=router,
        timers=net.timers,
        isis_tag=ISIS_TAG,
        ebgp_neighbors=ebgp,
        rr_clients=rr_clients,
    )
    daemons = env.get_template("daemons.j2").render(router=router, all_daemons=ALL_DAEMONS)
    vtysh = env.get_template("vtysh.conf.j2").render()
    return RenderedRouter(frr_conf=frr, daemons=daemons, vtysh_conf=vtysh)


def render_topology(net: Network) -> str:
    return _env().get_template("topology.clab.yml.j2").render(net=net)


def write_build(net: Network, build_dir: Path) -> list[Path]:
    written: list[Path] = []
    for router in net.routers.values():
        out = build_dir / "configs" / router.name
        out.mkdir(parents=True, exist_ok=True)
        rendered = render_router(net, router)
        for name, body in (
            ("frr.conf", rendered.frr_conf),
            ("daemons", rendered.daemons),
            ("vtysh.conf", rendered.vtysh_conf),
        ):
            path = out / name
            # frr-reload's "write memory" replaces frr.conf with a file owned by the container's frr user.
            path.unlink(missing_ok=True)
            path.write_text(body)
            written.append(path)
    topo = build_dir / f"{net.name}.clab.yml"
    topo.write_text(render_topology(net))
    written.append(topo)
    return written
