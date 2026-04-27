"""PYTHONPATH=detector python -m unittest discover -s tests -p 'test_*.py'"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detector"))

from baseline import BaselineResult, RollingBaseline  # noqa: E402


class TestRollingBaseline(unittest.TestCase):
    def test_zero_traffic(self) -> None:
        cfg: dict = {
            "baseline_window_seconds": 60,
            "baseline_recompute_interval_seconds": 10,
            "baseline_min_std": 0.01,
            "baseline_floor_rps": 0.0,
            "baseline_min_samples_current_hour": 10,
        }
        b = RollingBaseline(cfg)
        r = b.recompute(now=1_000_000.0)
        self.assertIsInstance(r, BaselineResult)
        self.assertEqual(r.n_samples, 60)
        self.assertEqual(r.total_requests_in_window, 0)
        self.assertEqual(r.total_errors_in_window, 0)
        # floor std
        self.assertGreaterEqual(r.effective_std, 0.01)

    def test_constant_rate_per_second(self) -> None:
        cfg: dict = {
            "baseline_window_seconds": 10,
            "baseline_recompute_interval_seconds": 1,
            "baseline_min_std": 0.0,
            "baseline_floor_rps": 0.0,
            "baseline_min_samples_current_hour": 2,
        }
        b = RollingBaseline(cfg)
        base = 2_000_000
        for s in range(base, base + 10):
            for _ in range(3):
                b.record(float(s))
        r = b.recompute(now=float(base + 10))
        self.assertAlmostEqual(r.effective_mean, 3.0, places=4)


if __name__ == "__main__":
    unittest.main()
