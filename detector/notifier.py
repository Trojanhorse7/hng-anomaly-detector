"""Slack incoming webhooks (JSON). Webhook from config or SLACK_WEBHOOK_URL env."""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class NotifierConfig:
    webhook_url: str


def load_notifier_config(cfg: dict) -> NotifierConfig:
    url = (os.environ.get("SLACK_WEBHOOK_URL") or "").strip() or (
        (cfg.get("slack") or {}).get("webhook_url") or ""
    ).strip()
    return NotifierConfig(webhook_url=url)


def send_text(webhook_url: str, text: str, timeout: float = 5.0) -> bool:
    if not webhook_url:
        return False
    body = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return 200 <= r.status < 300
    except (urllib.error.URLError, OSError) as e:
        log.warning("slack: %s", e)
        return False


def _ts() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def notify_global_anomaly(
    url: str,
    *,
    condition: str,
    rate: float,
    mean: float,
    std: float,
) -> bool:
    t = _ts()
    return send_text(
        url,
        f"*[HNG] Global anomaly* `{t}`\n"
        f"• *condition* `{condition}`\n"
        f"• *current rate* `{rate:.4f}` req/s (60s win)\n"
        f"• *baseline* mean `{mean:.6f}` std `{std:.6f}` (30m)\n"
        f"(iptables not applied for global — Slack only)\n",
    )


def notify_ip_ban(
    url: str,
    *,
    ip: str,
    condition: str,
    rate: float,
    mean: float,
    std: float,
    duration_s: int | None,
) -> bool:
    t = _ts()
    dur = "permanent" if duration_s is None else f"{duration_s}s"
    return send_text(
        url,
        f"*[HNG] IP BAN* `{t}`\n"
        f"• *ip* `{ip}`\n"
        f"• *condition* `{condition}`\n"
        f"• *current rate* `{rate:.4f}` req/s (60s)\n"
        f"• *baseline* mean `{mean:.6f}` | std `{std:.6f}`\n"
        f"• *ban duration* `{dur}`\n"
        f"`iptables DROP` applied\n",
    )


def notify_unban(
    url: str,
    *,
    ip: str,
    reason: str,
    next_stage_note: str,
) -> bool:
    t = _ts()
    return send_text(
        url,
        f"*[HNG] IP UNBAN* `{t}`\n"
        f"• *ip* `{ip}`\n"
        f"• *reason* `{reason}`\n"
        f"• {next_stage_note}\n"
        f"`iptables` rule removed\n",
    )
