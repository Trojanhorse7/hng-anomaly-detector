"""HNG anomaly detector — entrypoint (tail logs, sliding windows, rolling baseline)."""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from pathlib import Path

import yaml

from baseline import RollingBaseline, start_baseline_recompute_thread
from monitor import AccessLogMonitor
from windows import SlidingWindows


_stop = threading.Event()


def _handle_sig(_sig: int, _frame: object) -> None:
    _stop.set()
    logging.info("signal — stopping")
    sys.exit(0)


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def load_config() -> dict:
    cfg_path = Path(os.environ.get("HNG_CONFIG", "config.yaml"))
    if not cfg_path.is_file():
        print(f"config not found: {cfg_path}", file=sys.stderr)
        sys.exit(1)
    with cfg_path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def main() -> None:
    signal.signal(signal.SIGINT, _handle_sig)
    signal.signal(signal.SIGTERM, _handle_sig)
    setup_logging()
    cfg = load_config() or {}
    log_path = cfg.get("log_path", "/var/log/nginx/hng-access.log")
    start_at_end = bool(cfg.get("start_at_end", True))
    window_s = float(cfg.get("window_seconds", 60.0))
    sweep_s = float(cfg.get("sweep_interval_seconds", 1.0))
    win = SlidingWindows(window_seconds=window_s, sweep_interval_seconds=sweep_s)
    bl = RollingBaseline(cfg)
    start_baseline_recompute_thread(bl, _stop)

    def on_event(ev: dict) -> None:
        bl.record()
        win.record(ev["source_ip"])
        g = win.global_count()
        ig = win.ip_count(ev["source_ip"])
        g_rps = g / window_s
        i_rps = ig / window_s
        # one line per request + sliding-window stats for the configured window
        print(
            f"event: ip={ev['source_ip']} {ev['method']} {ev['path']} -> "
            f"{ev['status']} size={ev['response_size']}"
            f" | w{int(window_s)}s: global={g}({g_rps:.2f}/s) this_ip={ig}({i_rps:.2f}/s)",
            flush=True,
        )

    m = AccessLogMonitor(
        log_path,
        on_event=on_event,
        start_at_end=start_at_end,
    )
    
    logging.info("daemon up — tailing %s", log_path)
    m.run_forever()


if __name__ == "__main__":
    main()
