from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from pathlib import Path

from netlab.lab import Capabilities, Lab
from netlab.model import load_network
from netlab.runner import SubprocessRunner


def _lab(args: argparse.Namespace) -> Lab:
    return Lab(load_network(args.network), SubprocessRunner(), args.build_dir)


def cmd_render(args: argparse.Namespace) -> int:
    for path in _lab(args).render():
        print(path)
    return 0


def cmd_up(args: argparse.Namespace) -> int:
    lab = _lab(args)
    print(lab.deploy(), flush=True)
    caps = lab.post_deploy()
    print(f"lab up; kernel capabilities: gre={caps.gre} ipip={caps.ipip} mpls_forwarding={caps.mpls_forwarding}")
    return 0


def cmd_down(args: argparse.Namespace) -> int:
    _lab(args).down()
    print("lab destroyed")
    return 0


def cmd_push(args: argparse.Namespace) -> int:
    lab = _lab(args)
    rc = 0
    for router in args.routers or list(lab.net.routers):
        res = lab.push(router)
        print(f"{router}: {'ok' if res.ok else 'FAILED'}")
        if not res.ok:
            print(res.stderr.strip(), file=sys.stderr)
            rc = 1
    return rc


def cmd_drift(args: argparse.Namespace) -> int:
    lab = _lab(args)
    drifted = False
    for router in args.routers or list(lab.net.routers):
        changes = lab.config_drift(router)
        print(f"{router}: {'in sync' if not changes else f'{len(changes)} line(s) drifted'}")
        for line in changes:
            print(f"    {line}")
        drifted = drifted or bool(changes)
    return 1 if drifted else 0


def cmd_check(args: argparse.Namespace) -> int:
    from netlab.checks import evaluate, load_intent, runnable_pings
    from netlab.collect import collect_all, ping

    lab = _lab(args)
    intent = load_intent(args.intent)
    caps = Capabilities.load(lab.capabilities_file)
    snaps = collect_all(lab.shell, lab.net)
    pings = [ping(lab.shell, p.name, p.router, p.destination, p.source) for p in runnable_pings(intent, lab.net, caps)]
    findings = evaluate(intent, lab.net, caps, snaps, pings)
    for p in pings:
        rtt = f"{p.rtt_ms:.3f} ms" if p.rtt_ms is not None else "-"
        print(f"ping {p.name:<20} {p.router} -> {p.destination:<15} {'ok' if p.success else 'FAIL'} {rtt}")
    for name, s in snaps.items():
        peers = sum(1 for p in s.bgp_peers.values() if p.established)
        print(
            f"{name:<9} bgp {peers}/{len(s.bgp_peers)} established  ospf {len(s.ospf_neighbors)}  "
            f"isis {sum(a.up for a in s.isis_adjacencies)}  ldp {len(s.ldp_neighbors)}  routes {len(s.routes)}"
        )
    for t in lab.net.tunnels:
        if not caps.supports(t.type):
            print(f"tunnel {t.name} ({t.type}): not checked, host kernel has no {t.type} support")
    if findings:
        print(f"\n{len(findings)} finding(s):")
        for f in findings:
            print(f"  {f.router:<9} {f.kind.value:<22} {f.target:<15} {f.detail}")
        return 1
    print("\nall checks pass: live state matches intended state")
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    from prometheus_client import start_http_server

    from netlab.actuator import LabActuator
    from netlab.checks import load_intent
    from netlab.jsonlog import setup_json_logging
    from netlab.metrics import Metrics
    from netlab.monitor import Monitor
    from netlab.remediation import Remediator

    setup_json_logging(args.state_dir / "monitor.jsonl", logging.DEBUG if args.verbose else logging.INFO)
    lab = _lab(args)
    metrics = Metrics()
    caps = Capabilities.load(lab.capabilities_file)
    monitor = Monitor(
        lab,
        load_intent(args.intent),
        caps,
        metrics,
        Remediator(LabActuator(lab), cooldown_s=args.cooldown, settle_s=args.settle),
        status_file=args.state_dir / "status.json",
        interval_s=args.interval,
        confirm_polls=args.confirm_polls,
        session_confirm_polls=args.session_confirm_polls,
        remediate=not args.no_remediate,
    )
    start_http_server(args.metrics_port, addr=args.metrics_addr, registry=metrics.registry)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    monitor.run(stop)
    return 0


def cmd_chaos(args: argparse.Namespace) -> int:
    from netlab.chaos import SCENARIOS, append_result, restore, run_scenario, wait_healthy
    from netlab.checks import load_intent

    lab = _lab(args)
    intent = load_intent(args.intent)
    caps = Capabilities.load(lab.capabilities_file)
    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    log_file, status_file = args.state_dir / "monitor.jsonl", args.state_dir / "status.json"
    rc = 0
    for i in range(args.repeat):
        for name in names:
            sc = SCENARIOS[name]
            if not wait_healthy(status_file):
                print("monitor does not report a healthy, fresh state; is `netlab monitor` running?", file=sys.stderr)
                return 2
            print(f"[{i + 1}/{args.repeat}] {name}: {sc.description}")
            res = run_scenario(lab, intent, caps, sc, log_file, status_file, timeout=args.timeout)
            append_result(args.results, res)
            if res.success:
                print(
                    f"    detected {res.mttd_s:.2f}s  diagnosed {res.time_to_diagnose_s:.2f}s  "
                    f"remediated {res.time_to_remediate_s:.2f}s  recovered (MTTR) {res.mttr_s:.2f}s"
                )
                print(f"    root cause: {res.root_cause}")
            else:
                rc = 1
                print(f"    FAILED: {res.error or 'wrong diagnosis or not healthy after recovery'}")
                restore(lab)
    print(f"results appended to {args.results}")
    return rc


def cmd_report(args: argparse.Namespace) -> int:
    from netlab.chaos import load_results, summarize

    results = load_results(args.results)
    if not results:
        print(f"no results in {args.results}", file=sys.stderr)
        return 1
    print(summarize(results), end="")
    return 0


def build_parser() -> argparse.ArgumentParser:
    from netlab.chaos import SCENARIOS

    p = argparse.ArgumentParser(prog="netlab", description="FRR/containerlab network lab automation")
    p.add_argument("--network", type=Path, default=Path("lab/network.yml"), help="lab definition YAML")
    p.add_argument("--intent", type=Path, default=Path("lab/intended_state.yml"), help="intended-state YAML")
    p.add_argument("--build-dir", type=Path, default=Path("build"), help="rendered output directory")
    p.add_argument("--state-dir", type=Path, default=Path("var"), help="monitor logs and status")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("render", help="render FRR configs and the containerlab topology").set_defaults(func=cmd_render)
    sub.add_parser("up", help="render, deploy the lab and create tunnels").set_defaults(func=cmd_up)
    sub.add_parser("down", help="destroy the lab").set_defaults(func=cmd_down)

    push = sub.add_parser("push", help="push intended config to running routers (frr-reload)")
    push.add_argument("routers", nargs="*")
    push.set_defaults(func=cmd_push)

    drift = sub.add_parser("drift", help="diff running config against intended config")
    drift.add_argument("routers", nargs="*")
    drift.set_defaults(func=cmd_drift)

    sub.add_parser("check", help="one-shot comparison of live state against intent").set_defaults(func=cmd_check)

    mon = sub.add_parser("monitor", help="run the monitoring and auto-remediation daemon")
    mon.add_argument("--interval", type=float, default=2.0, help="poll interval in seconds")
    mon.add_argument("--confirm-polls", type=int, default=1, help="polls a finding must persist before acting")
    mon.add_argument(
        "--session-confirm-polls",
        type=int,
        default=2,
        help="polls a session/reachability finding must persist before acting",
    )
    mon.add_argument("--cooldown", type=float, default=30.0, help="seconds before repeating the same fix")
    mon.add_argument("--settle", type=float, default=12.0, help="seconds to let the network reconverge after a fix")
    mon.add_argument("--no-remediate", action="store_true", help="diagnose only")
    mon.add_argument("--metrics-port", type=int, default=9469)
    mon.add_argument("--metrics-addr", default="0.0.0.0")
    mon.set_defaults(func=cmd_monitor)

    chaos = sub.add_parser("chaos", help="inject failures and measure MTTD/MTTR against the running daemon")
    chaos.add_argument("scenario", choices=[*SCENARIOS, "all"])
    chaos.add_argument("--repeat", type=int, default=1)
    chaos.add_argument("--timeout", type=float, default=120.0)
    chaos.add_argument("--results", type=Path, default=Path("results/chaos-results.jsonl"))
    chaos.set_defaults(func=cmd_chaos)

    rep = sub.add_parser("report", help="summarize recorded chaos runs")
    rep.add_argument("--results", type=Path, default=Path("results/chaos-results.jsonl"))
    rep.set_defaults(func=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "monitor":
        logging.basicConfig(
            level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(name)s: %(message)s"
        )
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
