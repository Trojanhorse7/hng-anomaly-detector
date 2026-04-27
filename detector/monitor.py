
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)


REQUIRED_FIELDS = (
    "source_ip",
    "timestamp",
    "method",
    "path",
    "status",
    "response_size",
)


class AccessLogMonitor:
    def __init__(
        self,
        path: str | Path,
        on_event: Callable[[dict[str, Any]], None],
        *,
        start_at_end: bool = True,
        poll_interval: float = 0.1,
    ) -> None:
        self.path = Path(path)
        self.on_event = on_event
        self.start_at_end = start_at_end
        self.poll_interval = poll_interval
        self._lines_ok = 0
        self._lines_bad = 0

    @property
    def lines_ok(self) -> int:
        return self._lines_ok

    @property
    def lines_bad(self) -> int:
        return self._lines_bad

    def run_forever(self) -> None:
        f = self._open_when_ready()
        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(self.poll_interval)
                    continue
                line = line.strip()
                if not line:
                    continue
                self._process_line(line)
        finally:
            f.close()

    def _open_when_ready(self) -> object:
        while not self.path.exists():
            log.warning("log file not there yet, waiting: %s", self.path)
            time.sleep(1.0)
        f = open(self.path, "r", encoding="utf-8", errors="replace")
        if self.start_at_end:
            f.seek(0, 2)
        log.info("tailing %s (start_at_end=%s)", self.path, self.start_at_end)
        return f

    def _process_line(self, line: str) -> None:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            self._lines_bad += 1
            log.debug("skip bad json: %s", e)
            return
        if not isinstance(obj, dict) or not _has_fields(obj, REQUIRED_FIELDS):
            self._lines_bad += 1
            log.debug("skip missing fields: %r", line[:200])
            return
        self._lines_ok += 1
        self.on_event(_normalize_event(obj))

def _has_fields(obj: dict[str, Any], fields: tuple[str, ...]) -> bool:
    return all(k in obj for k in fields)


def _normalize_event(obj: dict[str, Any]) -> dict[str, Any]:
    # keep a stable dict the rest of the app can rely on
    return {k: obj[k] for k in REQUIRED_FIELDS}
