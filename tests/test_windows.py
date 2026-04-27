"""Run from project root: PYTHONPATH=detector python -m unittest discover -s tests -p 'test_*.py'"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detector"))

from windows import SlidingWindows  # noqa: E402


class TestSlidingWindows(unittest.TestCase):
    def test_eviction_leaves_only_recent(self) -> None:
        w = SlidingWindows(window_seconds=10.0, sweep_interval_seconds=0.0)
        w.record("a", now=1000.0)
        w.record("a", now=1001.0)
        s = w.snapshot(now=1011.0)
        self.assertEqual(s["global_count"], 1)
        s_ip = w.snapshot("a", now=1011.0)
        self.assertEqual(s_ip["ip_count"], 1)

    def test_global_and_per_ip(self) -> None:
        w = SlidingWindows(window_seconds=60.0, sweep_interval_seconds=0.0)
        base = 10_000.0
        w.record("a", now=base)
        w.record("b", now=base)
        w.record("a", now=base + 1)
        self.assertEqual(w.global_count(now=base + 2), 3)
        self.assertEqual(w.ip_count("a", now=base + 2), 2)
        self.assertEqual(w.ip_count("b", now=base + 2), 1)

    def test_sweep_removes_stale_ip(self) -> None:
        w = SlidingWindows(window_seconds=5.0, sweep_interval_seconds=1.0)
        w.record("x", now=0.0)
        w.record("y", now=10.0)
        self.assertEqual(w.ip_count("x", now=10.0), 0)
        self.assertEqual(w.ip_count("y", now=10.0), 1)


if __name__ == "__main__":
    unittest.main()
