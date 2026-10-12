from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandError(RuntimeError):
    def __init__(self, result: CommandResult) -> None:
        super().__init__(f"command failed ({result.returncode}): {' '.join(result.argv)}: {result.stderr.strip()}")
        self.result = result


class Runner(Protocol):
    def run(self, argv: Sequence[str], *, stdin: str | None = None, timeout: float = 15.0) -> CommandResult: ...


class SubprocessRunner:
    def run(self, argv: Sequence[str], *, stdin: str | None = None, timeout: float = 15.0) -> CommandResult:
        try:
            proc = subprocess.run(list(argv), input=stdin, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            return CommandResult(tuple(argv), 124, "", f"timeout after {exc.timeout}s")
        return CommandResult(tuple(argv), proc.returncode, proc.stdout, proc.stderr)


def privileged(argv: Sequence[str]) -> list[str]:
    if os.geteuid() == 0:
        return list(argv)
    return ["sudo", "-n", *argv]


class RouterShell:
    """Runs commands inside router containers via `docker exec`."""

    def __init__(self, runner: Runner, container_of: dict[str, str], docker: str = "docker") -> None:
        self.runner = runner
        self.container_of = container_of
        self.docker = docker

    def exec(
        self, router: str, argv: Sequence[str], *, stdin: str | None = None, timeout: float = 15.0
    ) -> CommandResult:
        cmd = [self.docker, "exec"]
        if stdin is not None:
            cmd.append("-i")
        cmd += [self.container_of[router], *argv]
        return self.runner.run(cmd, stdin=stdin, timeout=timeout)

    def vtysh(self, router: str, *commands: str, timeout: float = 15.0) -> CommandResult:
        argv = ["vtysh"]
        for c in commands:
            argv += ["-c", c]
        return self.exec(router, argv, timeout=timeout)

    def vtysh_json(self, router: str, command: str) -> Any:
        res = self.vtysh(router, command)
        if not res.ok:
            raise CommandError(res)
        text = res.stdout.strip()
        return json.loads(text) if text else {}

    def ip_json(self, router: str, *args: str) -> Any:
        res = self.exec(router, ["ip", "-j", *args])
        if not res.ok:
            raise CommandError(res)
        text = res.stdout.strip()
        return json.loads(text) if text else []
