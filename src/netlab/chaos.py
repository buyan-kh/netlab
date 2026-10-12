from __future__ import annotations

import json
import platform
import statistics
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from netlab.checks import Intent, Kind, evaluate, runnable_pings
from netlab.collect import collect_all, ping
from netlab.lab import Capabilities, Lab
from netlab.remediation import Action
from netlab.runner import CommandError, CommandResult


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    router: str
    commands: list[list[str]]
    expect_kind: Kind
    expect_action: Action

    def inject(self, lab: Lab) -> list[CommandResult]:
        results = []
        for argv in self.commands:
            res = lab.shell.exec(self.router, argv)
            if not res.ok:
                raise CommandError(res)
            results.append(res)
        return results


SCENARIOS: dict[str, Scenario] = {
    s.name: s
    for s in [
        Scenario(
            name="link-down",
            description="shut dca-edge eth2 (DC-A uplink to the backbone)",
            router="dca-edge",
            commands=[["ip", "link", "set", "dev", "eth2", "down"]],
            expect_kind=Kind.INTERFACE_ADMIN_DOWN,
            expect_action=Action.INTERFACE_UP,
        ),
        Scenario(
            name="config-delete",
            description="delete the eBGP neighbor to dcb-edge from bb2's running config",
            router="bb2",
            commands=[["vtysh", "-c", "configure terminal", "-c", "router bgp 65000", "-c", "no neighbor 172.16.20.0"]],
            expect_kind=Kind.BGP_PEER_MISSING,
            expect_action=Action.REAPPLY_CONFIG,
        ),
        Scenario(
            name="bad-route-map",
            description="attach a deny-all inbound route-map to bb1's eBGP session with dca-edge",
            router="bb1",
            commands=[
                [
                    "vtysh",
                    "-c",
                    "configure terminal",
                    "-c",
                    "route-map RM-CHAOS-DENY deny 10",
                    "-c",
                    "exit",
                    "-c",
                    "router bgp 65000",
                    "-c",
                    "address-family ipv4 unicast",
                    "-c",
                    "neighbor 172.16.10.0 route-map RM-CHAOS-DENY in",
                ]
            ],
            expect_kind=Kind.BGP_POLICY_MISMATCH,
            expect_action=Action.REAPPLY_CONFIG,
        ),
    ]
}


class EventTail:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.offset = path.stat().st_size if path.exists() else 0

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open() as fh:
            fh.seek(self.offset)
            chunk = fh.read()
        end = chunk.rfind("\n") + 1
        self.offset += len(chunk[:end].encode())
        out = []
        for line in chunk[:end].splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out


@dataclass
class RunResult:
    scenario: str
    description: str
    started_at: str
    success: bool
    injected_epoch: float
    detected_epoch: float | None = None
    diagnosed_epoch: float | None = None
    remediated_epoch: float | None = None
    recovered_epoch: float | None = None
    mttd_s: float | None = None
    time_to_diagnose_s: float | None = None
    time_to_remediate_s: float | None = None
    mttr_s: float | None = None
    correct_root_cause: bool = False
    root_cause: str | None = None
    actions: list[str] = field(default_factory=list)
    findings_detected: list[str] = field(default_factory=list)
    verified_healthy: bool = False
    monitor_interval_s: float | None = None
    host_kernel: str = field(default_factory=platform.release)
    error: str | None = None


def _status(path: Path) -> dict[str, Any]:
    try:
        return dict(json.loads(path.read_text()))
    except (OSError, json.JSONDecodeError):
        return {}


def wait_healthy(status_file: Path, timeout: float = 120.0, stable_s: float = 4.0) -> bool:
    """Wait until the daemon has reported healthy for `stable_s` seconds on fresh polls."""
    deadline = time.time() + timeout
    healthy_since: float | None = None
    while time.time() < deadline:
        st = _status(status_file)
        fresh = st.get("epoch", 0) > time.time() - 10
        if fresh and st.get("healthy") and st.get("incident") is None:
            healthy_since = healthy_since or time.time()
            if time.time() - healthy_since >= stable_s:
                return True
        else:
            healthy_since = None
        time.sleep(0.5)
    return False


def verify_healthy(lab: Lab, intent: Intent, caps: Capabilities) -> bool:
    snaps = collect_all(lab.shell, lab.net)
    pings = [ping(lab.shell, p.name, p.router, p.destination, p.source) for p in runnable_pings(intent, lab.net, caps)]
    return not evaluate(intent, lab.net, caps, snaps, pings)


def run_scenario(
    lab: Lab,
    intent: Intent,
    caps: Capabilities,
    scenario: Scenario,
    log_file: Path,
    status_file: Path,
    timeout: float = 120.0,
    clock: Callable[[], float] = time.time,
) -> RunResult:
    tail = EventTail(log_file)
    t0 = clock()
    result = RunResult(
        scenario=scenario.name,
        description=scenario.description,
        started_at=datetime.fromtimestamp(t0, tz=timezone.utc).isoformat(timespec="seconds"),
        success=False,
        injected_epoch=round(t0, 3),
        monitor_interval_s=_status(status_file).get("interval_s"),
    )
    try:
        scenario.inject(lab)
    except CommandError as exc:
        result.error = f"injection failed: {exc}"
        return result

    deadline = t0 + timeout
    while clock() < deadline and result.recovered_epoch is None:
        for ev in tail.read():
            name, ts = ev.get("event"), float(ev.get("epoch", 0))
            if ts < t0:
                continue
            if name == "finding_detected":
                result.findings_detected.append(f"{ev['router']} {ev['kind']} {ev['target']}")
                if result.detected_epoch is None:
                    result.detected_epoch = ts
            elif name == "diagnosis" and result.diagnosed_epoch is None:
                causes = ev.get("cause", [])
                if any(c["kind"] == scenario.expect_kind.value and c["router"] == scenario.router for c in causes):
                    result.diagnosed_epoch = ts
                    result.correct_root_cause = True
                    result.root_cause = ev.get("root_cause")
            elif name == "remediation_applied":
                result.actions.append(ev.get("plan", ""))
                if result.remediated_epoch is None and scenario.expect_action.value in ev.get("plan", ""):
                    result.remediated_epoch = ts
            elif name == "incident_resolved" and result.detected_epoch is not None:
                result.recovered_epoch = ts
        time.sleep(0.2)

    def delta(ts: float | None) -> float | None:
        return round(ts - t0, 3) if ts is not None else None

    result.mttd_s = delta(result.detected_epoch)
    result.time_to_diagnose_s = delta(result.diagnosed_epoch)
    result.time_to_remediate_s = delta(result.remediated_epoch)
    result.mttr_s = delta(result.recovered_epoch)
    if result.recovered_epoch is None:
        result.error = f"not recovered within {timeout:.0f}s"
        return result
    result.verified_healthy = verify_healthy(lab, intent, caps)
    result.success = result.verified_healthy and result.correct_root_cause
    return result


def restore(lab: Lab) -> None:
    for name, router in lab.net.routers.items():
        for iface in router.interfaces:
            if iface != "lo":
                lab.shell.exec(name, ["ip", "link", "set", "dev", iface, "up"])
        lab.push(name)


def append_result(path: Path, result: RunResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        fh.write(json.dumps(asdict(result)) + "\n")


def load_results(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def summarize(results: list[dict[str, Any]]) -> str:
    rows = [
        "| scenario | runs | recovered | correct root cause | MTTD mean / max (s) | MTTR mean / p50 / max (s) |",
        "|---|---|---|---|---|---|",
    ]
    by: dict[str, list[dict[str, Any]]] = {}
    for r in results:
        by.setdefault(r["scenario"], []).append(r)
    for name, runs in by.items():
        ok = [r for r in runs if r["success"]]
        mttd = [r["mttd_s"] for r in ok if r["mttd_s"] is not None]
        mttr = [r["mttr_s"] for r in ok if r["mttr_s"] is not None]
        rc = sum(1 for r in runs if r["correct_root_cause"])
        d = f"{statistics.mean(mttd):.2f} / {max(mttd):.2f}" if mttd else "n/a"
        m = f"{statistics.mean(mttr):.2f} / {statistics.median(mttr):.2f} / {max(mttr):.2f}" if mttr else "n/a"
        rows.append(f"| {name} | {len(runs)} | {len(ok)} | {rc}/{len(runs)} | {d} | {m} |")
    return "\n".join(rows) + "\n"
