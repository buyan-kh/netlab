from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

from netlab.checks import Finding, Kind
from netlab.collect import PingResult
from netlab.lab import Capabilities
from netlab.parsers import RouterSnapshot


class Metrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        r = self.registry
        self.router_up = Gauge("netlab_router_scrape_ok", "1 if every vtysh query succeeded", ["router"], registry=r)
        self.interface_up = Gauge(
            "netlab_interface_oper_up", "Interface operational state", ["router", "interface"], registry=r
        )
        self.bgp_established = Gauge(
            "netlab_bgp_peer_established", "1 if the BGP session is Established", ["router", "peer"], registry=r
        )
        self.bgp_prefixes = Gauge(
            "netlab_bgp_peer_prefixes_received", "Prefixes accepted from peer", ["router", "peer"], registry=r
        )
        self.igp_adjacency = Gauge(
            "netlab_igp_adjacency_up", "IGP/LDP adjacency state", ["router", "protocol", "neighbor"], registry=r
        )
        self.routes = Gauge("netlab_routes_selected", "Selected IPv4 routes in the RIB", ["router"], registry=r)
        self.ping_ok = Gauge("netlab_ping_success", "1 if the reachability probe got a reply", ["name"], registry=r)
        self.ping_rtt = Gauge("netlab_ping_rtt_ms", "Reachability probe round-trip time", ["name"], registry=r)
        self.findings = Gauge("netlab_findings_active", "Active findings by kind", ["kind"], registry=r)
        self.detections = Counter("netlab_findings_detected", "Findings detected", ["kind"], registry=r)
        self.remediations = Counter(
            "netlab_remediations", "Remediation steps executed", ["action", "result"], registry=r
        )
        self.incidents = Counter("netlab_incidents", "Incidents opened", registry=r)
        self.last_ttr = Gauge(
            "netlab_last_incident_duration_seconds", "Duration of the last resolved incident", registry=r
        )
        self.healthy = Gauge("netlab_healthy", "1 when no findings are active", registry=r)
        self.capability = Gauge("netlab_kernel_capability", "Host kernel feature support", ["feature"], registry=r)
        self.poll_seconds = Histogram(
            "netlab_poll_duration_seconds",
            "Time to collect and evaluate one poll",
            buckets=(0.25, 0.5, 1, 2, 4, 8),
            registry=r,
        )

    def set_capabilities(self, caps: Capabilities) -> None:
        for feature in ("gre", "ipip", "mpls_forwarding"):
            self.capability.labels(feature).set(1 if getattr(caps, feature) else 0)

    def observe(self, snaps: dict[str, RouterSnapshot], pings: list[PingResult], findings: list[Finding]) -> None:
        for g in (self.interface_up, self.bgp_established, self.bgp_prefixes, self.igp_adjacency):
            g.clear()
        for name, s in snaps.items():
            self.router_up.labels(name).set(0 if s.errors else 1)
            for i in s.interfaces.values():
                self.interface_up.labels(name, i.name).set(1 if i.oper_up else 0)
            for p in s.bgp_peers.values():
                self.bgp_established.labels(name, p.address).set(1 if p.established else 0)
                self.bgp_prefixes.labels(name, p.address).set(p.prefixes_received)
            for o in s.ospf_neighbors.values():
                self.igp_adjacency.labels(name, "ospf", o.router_id).set(1 if o.full else 0)
            for a in s.isis_adjacencies:
                self.igp_adjacency.labels(name, "isis", a.system).set(1 if a.up else 0)
            for ld in s.ldp_neighbors.values():
                self.igp_adjacency.labels(name, "ldp", ld.neighbor_id).set(1 if ld.operational else 0)
            self.routes.labels(name).set(len(s.routes))
        for pr in pings:
            self.ping_ok.labels(pr.name).set(1 if pr.success else 0)
            if pr.rtt_ms is not None:
                self.ping_rtt.labels(pr.name).set(pr.rtt_ms)
        counts = {k: 0 for k in Kind}
        for f in findings:
            counts[f.kind] += 1
        for k, n in counts.items():
            self.findings.labels(k.value).set(n)
        self.healthy.set(0 if findings else 1)
