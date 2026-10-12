from __future__ import annotations

from netlab.lab import Lab
from netlab.remediation import Action, Step, StepResult


class LabActuator:
    def __init__(self, lab: Lab) -> None:
        self.lab = lab

    def interface_up(self, router: str, interface: str) -> StepResult:
        res = self.lab.shell.exec(router, ["ip", "link", "set", "dev", interface, "up"])
        return StepResult(Step(Action.INTERFACE_UP, router, interface), res.ok, res.stderr.strip())

    def recreate_tunnel(self, router: str, tunnel: str) -> StepResult:
        step = Step(Action.RECREATE_TUNNEL, router, tunnel)
        for t in self.lab.net.tunnels:
            if t.name != tunnel:
                continue
            for local, remote in t.ends():
                if local.router == router:
                    return StepResult(step, self.lab.create_tunnel_end(t, local, remote))
        return StepResult(step, False, "unknown tunnel")

    def reapply_config(self, router: str) -> StepResult:
        res = self.lab.push(router)
        detail = "" if res.ok else (res.stderr.strip().splitlines() or [""])[-1]
        return StepResult(Step(Action.REAPPLY_CONFIG, router), res.ok, detail)

    def clear_bgp(self, router: str, peer: str, soft: bool) -> StepResult:
        cmd = f"clear bgp ipv4 unicast {peer}" + (" soft" if soft else "")
        res = self.lab.shell.vtysh(router, cmd)
        action = Action.CLEAR_BGP_SOFT if soft else Action.CLEAR_BGP
        return StepResult(Step(action, router, peer), res.ok, res.stdout.strip() or res.stderr.strip())
