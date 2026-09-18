"""Small JSONL audit logger with no credential or frame contents."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: str | None = None) -> None:
        self.path = Path(path) if path else None

    def event(self, name: str, **fields: Any) -> None:
        record = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": name}
        record.update(fields)
        encoded = json.dumps(record, sort_keys=True)
        print(encoded, file=sys.stderr, flush=True)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(encoded + "\n")
