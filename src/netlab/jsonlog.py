from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        doc: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "epoch": round(record.created, 3),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k not in _RESERVED and not k.startswith("_"):
                doc[k] = v
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc, default=str, sort_keys=False)


def setup_json_logging(log_file: Path | None, level: int = logging.INFO, stream: bool = True) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)
    fmt = JsonFormatter()
    if stream:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(fmt)
        root.addHandler(h)
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file)
        fh.setFormatter(fmt)
        root.addHandler(fh)


def read_events(path: Path, since: float = 0.0) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events = []
    with path.open() as fh:
        for line in fh:
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            if doc.get("epoch", 0) >= since:
                events.append(doc)
    return events
