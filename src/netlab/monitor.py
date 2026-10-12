from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from netlab.checks import Finding, Intent, evaluate, runnable_pings
from netlab.collect import PingResult, collect_all, ping
from netlab.lab import Capabilities, Lab
from netlab.metrics import Metrics
from netlab.parsers import RouterSnapshot
from netlab.remediation import Plan, Remediator, Topology, plan_remediation

log = logging.getLogger("netlab.monitor")


def _finding_doc(f: Finding) -> dict[str, str]:
    return {"router": f.router, "kind": f.kind.value, "target": f.target, "detail": f.detail}


@dataclass
class Incident:
    id: str
    opened_at: float
    actions: list[str] = field(default_factory=list)
    root_causes: list[str] = field(default_factory=list)


@dataclass
class PollResult:
    findings: list[Finding]
    plans: list[Plan]
    duration_s: float


class Monitor:
    def __init__(
        self,
        lab: Lab,
        intent: Intent,
        caps: Capabilities,
        metrics: Metrics,
        remediator: Remediator,
        status_file: Path,
        interval_s: float = 2.0,
        confirm_polls: int = 1,
        remediate: bool = True,
        collector: Callable[[], tuple[dict[str, RouterSnapshot], list[PingResult]]] | None = None,
    ) -> None:
        self.lab = lab
        self.net = lab.net
        self.intent = intent
        self.caps = caps
        self.metrics = metrics
        self.remediator = remediator
        self.status_file = status_file
        self.interval_s = interval_s
        self.confirm_polls = confirm_polls
        self.remediate = remediate
        self.topo = Topology(self.net)
        self.collector = collector or self._collect
        self.pings = runnable_pings(intent, self.net, caps)
        self._seen: dict[str, tuple[Finding, float, int]] = {}
        self.incident: Incident | None = None
        metrics.set_capabilities(caps)

    def _collect(self) -> tuple[dict[str, RouterSnapshot], list[PingResult]]:
        with ThreadPoolExecutor(max_workers=4) as pool:
            futs = [pool.submit(ping, self.lab.shell, p.name, p.router, p.destination, p.source) for p in self.pings]
            snaps = collect_all(self.lab.shell, self.net)
            return snaps, [f.result() for f in futs]

    def _track(self, findings: list[Finding], now: float) -> list[Finding]:
        current = {f.key: f for f in findings}
        for key, f in current.items():
            if key in self._seen:
                _, since, n = self._seen[key]
                self._seen[key] = (f, since, n + 1)
                continue
            self._seen[key] = (f, now, 1)
            if self.incident is None:
                self.incident = Incident(id=uuid.uuid4().hex[:8], opened_at=now)
                self.metrics.incidents.inc()
                log.warning("incident_opened", extra={"incident": self.incident.id})
            self.metrics.detections.labels(f.kind.value).inc()
            log.warning("finding_detected", extra={"incident": self.incident.id, **_finding_doc(f)})
        for key in [k for k in self._seen if k not in current]:
            f, since, _ = self._seen.pop(key)
            log.info(
                "finding_cleared",
                extra={
                    "incident": self.incident.id if self.incident else None,
                    "duration_s": round(now - since, 3),
                    **_finding_doc(f),
                },
            )
        if not current and self.incident is not None:
            inc = self.incident
            duration = now - inc.opened_at
            self.metrics.last_ttr.set(duration)
            log.info(
                "incident_resolved",
                extra={
                    "incident": inc.id,
                    "duration_s": round(duration, 3),
                    "actions": inc.actions,
                    "root_causes": inc.root_causes,
                },
            )
            self.incident = None
            self.remediator.reset()
        return [f for k, f in current.items() if self._seen[k][2] >= self.confirm_polls]

    def _act(self, plans: list[Plan]) -> None:
        for plan in plans:
            ok, why = self.remediator.allowed(plan)
            if not ok:
                log.debug("remediation_skipped", extra={"plan": plan.key, "reason": why})
                continue
            inc = self.incident.id if self.incident else None
            log.warning(
                "diagnosis",
                extra={
                    "incident": inc,
                    "root_cause": plan.root_cause,
                    "cause": [_finding_doc(f) for f in plan.cause],
                    "symptoms": [_finding_doc(f) for f in plan.symptoms],
                    "evidence": plan.evidence[:20],
                    "steps": [f"{s.action.value}:{s.router}:{s.target}".rstrip(":") for s in plan.steps],
                    "will_execute": self.remediate and not plan.escalation,
                },
            )
            if plan.escalation or not self.remediate:
                self.remediator.mark(plan)
                if plan.escalation:
                    log.error(
                        "escalation",
                        extra={"incident": inc, "root_cause": plan.root_cause, "plan": plan.key},
                    )
                continue
            t0 = time.time()
            results = self.remediator.execute(plan)
            for r in results:
                self.metrics.remediations.labels(r.step.action.value, "ok" if r.ok else "error").inc()
            if self.incident:
                self.incident.actions += [plan.key]
                self.incident.root_causes.append(plan.root_cause)
            log.warning(
                "remediation_applied",
                extra={
                    "incident": inc,
                    "plan": plan.key,
                    "ok": all(r.ok for r in results),
                    "results": [
                        {
                            "action": r.step.action.value,
                            "router": r.step.router,
                            "target": r.step.target,
                            "ok": r.ok,
                            "detail": r.detail,
                        }
                        for r in results
                    ],
                    "elapsed_s": round(time.time() - t0, 3),
                },
            )

    def poll_once(self) -> PollResult:
        t0 = time.time()
        snaps, pings = self.collector()
        findings = evaluate(self.intent, self.net, self.caps, snaps, pings)
        self.metrics.observe(snaps, pings, findings)
        confirmed = self._track(findings, t0)
        plans: list[Plan] = []
        if confirmed and self.remediator.settling():
            log.debug("planning_deferred", extra={"reason": "settling after remediation", "findings": len(confirmed)})
        elif confirmed:
            plans = plan_remediation(confirmed, self.topo, self.lab.config_drift)
            self._act(plans)
        duration = time.time() - t0
        self.metrics.poll_seconds.observe(duration)
        self._write_status(t0, findings, duration)
        return PollResult(findings, plans, duration)

    def _write_status(self, ts: float, findings: list[Finding], duration: float) -> None:
        doc = {
            "epoch": round(ts, 3),
            "healthy": not findings,
            "incident": self.incident.id if self.incident else None,
            "poll_duration_s": round(duration, 3),
            "interval_s": self.interval_s,
            "findings": [_finding_doc(f) for f in findings],
            "capabilities": asdict(self.caps),
        }
        self.status_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.status_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, indent=2))
        tmp.replace(self.status_file)

    def run(self, stop: threading.Event) -> None:
        log.info(
            "monitor_started",
            extra={
                "routers": list(self.net.routers),
                "interval_s": self.interval_s,
                "remediate": self.remediate,
                "capabilities": asdict(self.caps),
                "pings": [p.name for p in self.pings],
            },
        )
        while not stop.is_set():
            start = time.time()
            try:
                self.poll_once()
            except Exception:
                log.exception("poll_failed")
            stop.wait(max(0.0, self.interval_s - (time.time() - start)))
        log.info("monitor_stopped")
