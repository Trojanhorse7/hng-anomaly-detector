"""
HNG anomaly detector — entrypoint. Phase 2: tail + parse + print/log lines.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
from pathlib import Path

import yaml

from monitor import AccessLogMonitor


def _handle_sig(_sig: int, _frame: object) -> None:
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

    def on_event(ev: dict) -> None:
        # one line per request
        print(
            f"event: ip={ev['source_ip']} {ev['method']} {ev['path']} -> "
            f"{ev['status']} size={ev['response_size']}",
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
