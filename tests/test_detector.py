"""PYTHONPATH=detector python -m unittest discover -s tests -p 'test_*.py'"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detector"))

from baseline import BaselineResult  # noqa: E402
import detector as det  # noqa: E402


class TestZScore(unittest.TestCase):
    def test_z(self) -> None:
        self.assertAlmostEqual(det.z_score(6.0, 1.0, 1.0), 5.0)


class TestEvaluate(unittest.TestCase):
    def _b(self) -> BaselineResult:
        return BaselineResult(
            effective_mean=1.0,
            effective_std=0.5,
            error_effective_mean=0.05,
            error_effective_std=0.01,
            source="full_window",
            n_samples=100,
            total_requests_in_window=100,
            total_errors_in_window=5,
        )

    def test_no_baseline(self) -> None:
        w = __import__("windows", fromlist=["*"]).SlidingWindows(60.0, 0.0)
        d = det.DetectionConfig(3, 2, 5, 3, 3, 0.0001)
        s = det.evaluate(None, w, "1.1.1.1", 60.0, d)
        self.assertFalse(s.global_anomaly)

    def test_high_rps_triggers(self) -> None:
        from windows import SlidingWindows

        w = SlidingWindows(window_seconds=10.0, sweep_interval_seconds=0.0)
        t = 1000.0
        for _ in range(51):
            w.record("a", status=200, now=t)
            t += 0.01
        b = BaselineResult(
            effective_mean=1.0,
            effective_std=10.0,
            error_effective_mean=0.0,
            error_effective_std=0.01,
            source="full_window",
            n_samples=1800,
            total_requests_in_window=1800,
            total_errors_in_window=0,
        )
        d = det.DetectionConfig(3.0, 2.0, 5.0, 3.0, 3.0, 0.0001)
        s = det.evaluate(b, w, "a", 10.0, d)
        self.assertTrue(s.ip_rps > 1.0)
        self.assertTrue(s.ip_anomaly or s.global_anomaly)


if __name__ == "__main__":
    unittest.main()
