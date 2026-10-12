from __future__ import annotations

import json
import logging
from pathlib import Path

from netlab.chaos import SCENARIOS, EventTail, summarize
from netlab.checks import Kind
from netlab.jsonlog import JsonFormatter, read_events
from netlab.remediation import Action


def test_scenarios_cover_required_failures() -> None:
    assert set(SCENARIOS) == {"link-down", "config-delete", "bad-route-map"}
    assert SCENARIOS["link-down"].expect_action is Action.INTERFACE_UP
    assert SCENARIOS["config-delete"].expect_kind is Kind.BGP_PEER_MISSING
    assert SCENARIOS["bad-route-map"].expect_kind is Kind.BGP_POLICY_MISMATCH


def test_event_tail_only_returns_new_complete_lines(tmp_path: Path) -> None:
    p = tmp_path / "log.jsonl"
    p.write_text(json.dumps({"event": "old"}) + "\n")
    tail = EventTail(p)
    with p.open("a") as fh:
        fh.write(json.dumps({"event": "new"}) + "\n" + '{"event": "par')
    assert [e["event"] for e in tail.read()] == ["new"]
    with p.open("a") as fh:
        fh.write('tial"}\n')
    assert [e["event"] for e in tail.read()] == ["partial"]


def test_json_formatter_and_reader(tmp_path: Path) -> None:
    rec = logging.LogRecord("netlab.monitor", logging.WARNING, __file__, 1, "finding_detected", (), None)
    rec.router = "bb1"
    doc = json.loads(JsonFormatter().format(rec))
    assert doc["event"] == "finding_detected" and doc["router"] == "bb1" and doc["level"] == "warning"
    p = tmp_path / "m.jsonl"
    p.write_text(json.dumps({**doc, "epoch": 10}) + "\nnot json\n" + json.dumps({**doc, "epoch": 20}) + "\n")
    assert len(read_events(p, since=15)) == 1


def test_summarize() -> None:
    base = {"correct_root_cause": True, "mttd_s": 1.0, "mttr_s": 4.0, "success": True}
    rows = [
        {"scenario": "link-down", **base},
        {"scenario": "link-down", **base, "mttd_s": 2.0, "mttr_s": 6.0},
        {"scenario": "bad-route-map", **base, "success": False, "correct_root_cause": False, "mttr_s": None},
    ]
    table = summarize(rows)
    assert "| link-down | 2 | 2 | 2/2 | 1.50 / 2.00 | 5.00 / 5.00 / 6.00 |" in table
    assert "| bad-route-map | 1 | 0 | 0/1 | n/a | n/a |" in table
