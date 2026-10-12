from __future__ import annotations

from pathlib import Path

from netlab.lab import Capabilities, Lab, parse_reload_test, tunnel_commands
from netlab.model import Network

from .conftest import FakeRunner, fail, fixture_text, ok


def test_parse_reload_test_from_real_output() -> None:
    lines = parse_reload_test(fixture_text("config_delete", "bb2_frr_reload_test.txt"))
    assert "+ neighbor 172.16.20.0 remote-as 65002" in lines
    assert "+ neighbor 172.16.20.0 route-map RM-EBGP-IN in" in lines
    assert not any("frr version" in line or "ipv6 forwarding" in line for line in lines)
    assert not any(line.startswith(("+ =", "- =")) for line in lines)
    assert not any("INFO" in line for line in lines)


def test_parse_reload_test_in_sync() -> None:
    assert (
        parse_reload_test("Lines To Delete\n===============\n\nLines To Add\n============\nfrr version 10.2.1\n") == []
    )


def test_tunnel_commands(net: Network) -> None:
    gre = net.tunnels[0]
    cmds = tunnel_commands(gre, gre.a, gre.b)
    assert cmds[0] == [
        "ip",
        "link",
        "add",
        "gre-ab",
        "type",
        "gre",
        "local",
        "10.0.1.2",
        "remote",
        "10.0.2.2",
        "ttl",
        "64",
    ]
    assert cmds[1] == ["ip", "addr", "add", "192.168.100.1/30", "dev", "gre-ab"]
    ipip = net.tunnels[1]
    assert tunnel_commands(ipip, ipip.b, ipip.a)[0][5:10] == ["ipip", "local", "10.0.2.1", "remote", "10.0.1.1"]


def test_push_streams_rendered_config_then_reloads(net: Network, tmp_path: Path) -> None:
    runner = FakeRunner()
    Lab(net, runner, tmp_path).push("bb1")
    (copy, stdin), (reload, _) = runner.calls
    assert copy[:4] == ["docker", "exec", "-i", "clab-netlab-bb1"]
    assert stdin is not None and "hostname bb1" in stdin
    assert reload[-3:] == ["/usr/lib/frr/frr-reload.py", "--reload", "/tmp/netlab-intended.conf"]


def test_probe_capabilities(net: Network, tmp_path: Path) -> None:
    runner = FakeRunner(
        [
            ("type gre", fail("Error: Unknown device type.")),
            ("type ipip", ok()),
            ("/proc/sys/net/mpls", fail("")),
        ]
    )
    caps = Lab(net, runner, tmp_path).probe_capabilities()
    assert caps == Capabilities(gre=False, ipip=True, mpls_forwarding=False)


def test_create_tunnels_skips_unsupported(net: Network, tmp_path: Path) -> None:
    runner = FakeRunner()
    Lab(net, runner, tmp_path).create_tunnels(Capabilities(gre=False, ipip=True, mpls_forwarding=False))
    joined = [" ".join(argv) for argv, _ in runner.calls]
    assert not any("gre" in j for j in joined)
    assert sum("type ipip" in j for j in joined) == 2
