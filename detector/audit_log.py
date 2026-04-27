"""Structured audit: [ts] ACTION ip | condition | rate | baseline | duration"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


def _ts() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_audit(
    path: str | None,
    action: str,
    ip: str,
    condition: str,
    rate: str,
    baseline: str,
    duration: str,
) -> None:
    if not path:
        return
    line = f"[{_ts()}] {action} {ip} | {condition} | {rate} | {baseline} | {duration}\n"
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(line)
