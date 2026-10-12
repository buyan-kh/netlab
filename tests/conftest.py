from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from netlab.checks import Intent, load_intent
from netlab.model import Network, load_network
from netlab.runner import CommandResult

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture_json(scenario: str, name: str) -> Any:
    return json.loads((FIXTURES / scenario / f"{name}.json").read_text())


def fixture_text(scenario: str, name: str) -> str:
    return (FIXTURES / scenario / name).read_text()


@pytest.fixture(scope="session")
def net() -> Network:
    return load_network(ROOT / "lab" / "network.yml")


@pytest.fixture(scope="session")
def intent() -> Intent:
    return load_intent(ROOT / "lab" / "intended_state.yml")


class FakeRunner:
    """Records argv and replies from a list of (predicate substring, result) rules."""

    def __init__(self, rules: list[tuple[str, CommandResult]] | None = None) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.rules = rules or []

    def run(self, argv: Sequence[str], *, stdin: str | None = None, timeout: float = 15.0) -> CommandResult:
        self.calls.append((list(argv), stdin))
        joined = " ".join(argv)
        for needle, result in self.rules:
            if needle in joined:
                return result
        return CommandResult(tuple(argv), 0, "", "")


def ok(stdout: str = "") -> CommandResult:
    return CommandResult((), 0, stdout, "")


def fail(stderr: str) -> CommandResult:
    return CommandResult((), 1, "", stderr)
