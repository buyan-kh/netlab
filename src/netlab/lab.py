from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path

from netlab.model import Network, Tunnel, TunnelEnd
from netlab.render import render_router, write_build
from netlab.runner import CommandResult, RouterShell, Runner, privileged

log = logging.getLogger("netlab.lab")

INTENDED_PATH = "/tmp/netlab-intended.conf"
FRR_RELOAD = "/usr/lib/frr/frr-reload.py"
# The running version string carries a "_git" suffix, and zebra prints "ipv6 forwarding"
# at boot but not after a reload even though the kernel sysctl is unchanged.
DRIFT_IGNORE = ("frr version", "ipv6 forwarding", "no ipv6 forwarding")


@dataclass(frozen=True)
class Capabilities:
    gre: bool
    ipip: bool
    mpls_forwarding: bool

    def supports(self, tunnel_type: str) -> bool:
        return bool(getattr(self, tunnel_type, False))

    @classmethod
    def load(cls, path: Path) -> Capabilities:
        if not path.exists():
            return cls(gre=True, ipip=True, mpls_forwarding=True)
        return cls(**json.loads(path.read_text()))


def tunnel_commands(tunnel: Tunnel, local: TunnelEnd, remote: TunnelEnd) -> list[list[str]]:
    return [
        [
            "ip",
            "link",
            "add",
            tunnel.name,
            "type",
            tunnel.type,
            "local",
            local.local,
            "remote",
            remote.local,
            "ttl",
            "64",
        ],
        ["ip", "addr", "add", local.address, "dev", tunnel.name],
        ["ip", "link", "set", tunnel.name, "up"],
    ]


class Lab:
    def __init__(self, net: Network, runner: Runner, build_dir: Path) -> None:
        self.net = net
        self.runner = runner
        self.build_dir = build_dir
        self.shell = RouterShell(runner, {r: net.container(r) for r in net.routers})

    @property
    def topology_file(self) -> Path:
        return self.build_dir / f"{self.net.name}.clab.yml"

    @property
    def capabilities_file(self) -> Path:
        return self.build_dir / "capabilities.json"

    def render(self) -> list[Path]:
        return write_build(self.net, self.build_dir)

    def _clab(self, *args: str, timeout: float = 300) -> CommandResult:
        argv = privileged(["containerlab", *args, "-t", str(self.topology_file)])
        res = self.runner.run(argv, timeout=timeout)
        if not res.ok:
            raise RuntimeError(f"containerlab {args[0]} failed: {res.stderr.strip() or res.stdout.strip()}")
        return res

    def deploy(self) -> str:
        self.render()
        res = self._clab("deploy", "--reconfigure")
        return (res.stderr + res.stdout).strip()

    def up(self) -> Capabilities:
        self.deploy()
        return self.post_deploy()

    def post_deploy(self) -> Capabilities:
        caps = self.probe_capabilities()
        self.capabilities_file.write_text(json.dumps(asdict(caps), indent=2) + "\n")
        self.create_tunnels(caps)
        return caps

    def down(self) -> None:
        self._clab("destroy", "--cleanup")

    def probe_capabilities(self) -> Capabilities:
        router = next(iter(self.net.routers))
        found: dict[str, bool] = {}
        for kind in ("gre", "ipip"):
            res = self.shell.exec(
                router, ["ip", "link", "add", "nlprobe0", "type", kind, "local", "127.0.0.1", "remote", "127.0.0.2"]
            )
            found[kind] = res.ok
            if res.ok:
                self.shell.exec(router, ["ip", "link", "del", "nlprobe0"])
            else:
                log.warning("kernel lacks %s tunnel support: %s", kind, res.stderr.strip())
        mpls = self.shell.exec(router, ["test", "-e", "/proc/sys/net/mpls/platform_labels"]).ok
        if not mpls:
            log.warning("kernel lacks MPLS forwarding (no /proc/sys/net/mpls); LDP runs control-plane only")
        return Capabilities(gre=found["gre"], ipip=found["ipip"], mpls_forwarding=mpls)

    def create_tunnels(self, caps: Capabilities) -> None:
        for tunnel in self.net.tunnels:
            if not caps.supports(tunnel.type):
                log.warning("skipping tunnel %s: %s not supported by host kernel", tunnel.name, tunnel.type)
                continue
            for local, remote in tunnel.ends():
                self.create_tunnel_end(tunnel, local, remote)

    def create_tunnel_end(self, tunnel: Tunnel, local: TunnelEnd, remote: TunnelEnd) -> bool:
        self.shell.exec(local.router, ["ip", "link", "del", tunnel.name])
        for argv in tunnel_commands(tunnel, local, remote):
            res = self.shell.exec(local.router, argv)
            if not res.ok:
                log.error("tunnel %s on %s: %s", tunnel.name, local.router, res.stderr.strip())
                return False
        return True

    def push(self, router: str) -> CommandResult:
        conf = render_router(self.net, self.net.routers[router]).frr_conf
        copy = self.shell.exec(router, ["sh", "-c", f"cat > {INTENDED_PATH}"], stdin=conf)
        if not copy.ok:
            return copy
        return self.shell.exec(router, ["python3", FRR_RELOAD, "--reload", INTENDED_PATH], timeout=60)

    def config_drift(self, router: str) -> list[str]:
        """Lines frr-reload would change to converge running config onto the intended config."""
        conf = render_router(self.net, self.net.routers[router]).frr_conf
        self.shell.exec(router, ["sh", "-c", f"cat > {INTENDED_PATH}"], stdin=conf)
        res = self.shell.exec(router, ["python3", FRR_RELOAD, "--test", INTENDED_PATH], timeout=60)
        return parse_reload_test(res.stdout)


def parse_reload_test(output: str) -> list[str]:
    changes: list[str] = []
    section = ""
    for raw in output.splitlines():
        line = raw.rstrip()
        if line.startswith("Lines To Delete"):
            section = "-"
            continue
        if line.startswith("Lines To Add"):
            section = "+"
            continue
        if not section or not line.strip() or set(line.strip()) <= {"="}:
            continue
        if line.startswith(DRIFT_IGNORE):
            continue
        changes.append(f"{section} {line.strip()}")
    return changes
