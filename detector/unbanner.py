"""
Ban / unban with persisted state. Backoff: 10m, 30m, 2h, then permanent (no auto-unban).
Background thread processes due unbans.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

import blocker
import notifier
from audit_log import append_audit

log = logging.getLogger(__name__)

BACKOFF_SECONDS = (600, 1800, 7200)


class BanManager:
    def __init__(
        self,
        state_path: str,
        audit_path: str | None,
        webhook_url: str,
        tick_interval: float = 3.0,
    ) -> None:
        self._path = Path(state_path)
        self._audit = audit_path
        self._webhook = webhook_url
        self._tick = tick_interval
        self._lock = threading.Lock()
        self._state: dict[str, dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.is_file():
            self._state = {}
            return
        try:
            self._state = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            log.warning("ban state load: %s", e)
            self._state = {}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(self._state, indent=1, sort_keys=True),
            encoding="utf-8",
        )

    def list_for_dashboard(self) -> list[dict[str, Any]]:
        with self._lock:
            self._load()
            out: list[dict[str, Any]] = []
            for ip, rec in self._state.items():
                if rec.get("active"):
                    out.append(
                        {
                            "ip": ip,
                            "permanent": bool(rec.get("permanent")),
                            "unban_at": rec.get("unban_at"),
                            "bans_total": int(rec.get("bans_total", 0)),
                        }
                    )
            return sorted(out, key=lambda x: str(x.get("ip")))

    def try_ban_from_anomaly(
        self,
        ip: str,
        *,
        condition: str,
        rate: float,
        mean: float,
        std: float,
    ) -> None:
        """Apply DROP + notify once per strike. If schedule is overdue before the tick fires, unban synchronously."""
        now = time.time()
        overdue_unban = False
        with self._lock:
            self._load()
            rec = self._state.get(ip, {})
            if rec.get("permanent") and rec.get("active"):
                return
            if rec.get("active") and not rec.get("permanent"):
                uat = float(rec.get("unban_at") or 0.0)
                if now < uat:
                    return
                if now >= uat:
                    overdue_unban = True

        if overdue_unban:
            self._unban_one(ip)

        now = time.time()
        with self._lock:
            self._load()
            rec = self._state.get(ip, {})
            if rec.get("permanent") and rec.get("active"):
                return
            if rec.get("active") and not rec.get("permanent"):
                uat = float(rec.get("unban_at") or 0.0)
                if now < uat:
                    return
            n = int(rec.get("bans_total", 0)) + 1
            perm = n >= 4
            if perm:
                self._state[ip] = {
                    "bans_total": n,
                    "active": True,
                    "permanent": True,
                    "unban_at": None,
                }
            else:
                dur = BACKOFF_SECONDS[n - 1]
                self._state[ip] = {
                    "bans_total": n,
                    "active": True,
                    "permanent": False,
                    "unban_at": now + float(dur),
                }
            self._save()
            duration_for_notify: int | None = None if perm else BACKOFF_SECONDS[n - 1]
            n_final = n
        blocker.drop_ip(ip)
        notifier.notify_ip_ban(
            self._webhook,
            ip=ip,
            condition=condition,
            rate=rate,
            mean=mean,
            std=std,
            duration_s=duration_for_notify,
        )
        bl = f"{mean:.6f}|{std:.6f}"
        rate_s = f"{rate:.6f}"
        dur_txt = "permanent" if n_final >= 4 else f"{BACKOFF_SECONDS[n_final - 1]}s"
        append_audit(
            self._audit,
            "BAN",
            ip,
            condition,
            rate_s,
            bl,
            dur_txt,
        )

    def _process_due_unbans(self) -> None:
        now = time.time()
        with self._lock:
            self._load()
            due: list[str] = []
            for ip, rec in self._state.items():
                if not rec.get("active") or rec.get("permanent"):
                    continue
                uat = rec.get("unban_at")
                if uat is None:
                    continue
                if float(uat) <= now:
                    due.append(ip)
        for ip in due:
            self._unban_one(ip)

    def _unban_one(self, ip: str) -> None:
        with self._lock:
            self._load()
            rec = self._state.get(ip, {})
            bt = int(rec.get("bans_total", 0))
            if not rec.get("active"):
                return
            if rec.get("permanent"):
                return

        blocker.undrop_ip(ip)
        with self._lock:
            self._load()
            rec = self._state.get(ip, {})
            bt = int(rec.get("bans_total", 0))
            if not rec.get("active"):
                return
            if rec.get("permanent"):
                return
            rec["active"] = False
            self._state[ip] = rec
            self._save()
        notifier.notify_unban(
            self._webhook,
            ip=ip,
            reason="auto_backoff",
            next_stage_note=f"historical_bans={bt} (next strike escalates or perm at 4)",
        )
        append_audit(
            self._audit,
            "UNBAN",
            ip,
            "auto_backoff",
            "0",
            f"bans={bt}",
            "0s",
        )

    def start_thread(self, stop: threading.Event) -> None:
        def _run() -> None:
            while not stop.wait(timeout=self._tick):
                try:
                    self._process_due_unbans()
                except Exception:  # noqa: BLE001
                    log.exception("unbanner tick")

        threading.Thread(target=_run, name="unbanner", daemon=True).start()
