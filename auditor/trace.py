"""JSONL trace of the agent's reasoning and tool calls (redacted), so evaluators can verify agent behaviour."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from auditor.redact import redact_obj

PREVIEW_CHARS = 2000


class Tracer:
    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None
        self._fh = None
        self.events: list[dict[str, Any]] = []

    def log(self, event: str, **data: Any) -> None:
        record = redact_obj({"ts": round(time.time(), 3), "event": event, **data})
        for key in ("result", "content"):
            if isinstance(record.get(key), str) and len(record[key]) > PREVIEW_CHARS:
                record[key] = record[key][:PREVIEW_CHARS] + f"…[{len(record[key]) - PREVIEW_CHARS} chars omitted]"
        self.events.append(record)
        if self.path and self._fh is None:  # opened lazily: no empty trace file when the run fails early
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.open("w", encoding="utf-8")
        if self._fh:
            self._fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._fh.flush()

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
