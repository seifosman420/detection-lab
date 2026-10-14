#!/usr/bin/env python3
"""Tests: run the reference detection against the synthetic CSV and check labels."""
import csv
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).parent
DATA = HERE.parent / "test_data"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(DATA))

import reference  # noqa: E402
import generate_logs  # noqa: E402


def load_events():
    events = []
    with open(DATA / "vpn_logs.csv") as f:
        for row in csv.DictReader(f):
            row["time"] = datetime.strptime(row.pop("_time"), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            events.append(row)
    return events


def load_expected():
    with open(DATA / "expected.json") as f:
        d = json.load(f)
    return datetime.strptime(d["test_date"], "%Y-%m-%d").date(), d["cases"]


def key(user, hour):
    return (user, round(hour, 1))


class TestDetection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = load_events()
        cls.test_date, cls.cases = load_expected()

    def test_dataset_is_reproducible(self):
        regenerated, _ = generate_logs.build_events()
        self.assertEqual(len(regenerated), len(self.events), "CSV is stale: rerun generate_logs.py")

    def test_improved_detection_matches_labels(self):
        alerts = reference.detect(self.events, self.test_date)
        fired = {key(a["user"], a["hour"]) for a in alerts}
        for c in self.cases:
            k = key(c["user"], c["hour"])
            self.assertEqual(k in fired, c["should_alert"], f"{c['user']}@{c['hour']}: {c['reason']}")

    def test_naive_misses_midnight_wrap_anomaly(self):
        fired = {key(a["user"], a["hour"]) for a in reference.detect_naive(self.events, self.test_date)}
        self.assertNotIn(("carol", 12.0), fired, "naive was expected to miss this (false negative)")

    def test_naive_false_positive_without_floor(self):
        fired = {key(a["user"], a["hour"]) for a in reference.detect_naive(self.events, self.test_date)}
        self.assertIn(("dave", 8.6), fired, "naive was expected to flag this (false positive)")

    def test_circular_mean_wraps_midnight(self):
        typical, _ = reference.circular_baseline([23.0, 23.5, 0.0, 0.5, 1.0])
        self.assertTrue(typical > 23.0 or typical < 1.5, f"got {typical}")

    def test_circular_diff(self):
        self.assertAlmostEqual(reference.circular_diff(23.5, 0.5), 1.0)
        self.assertAlmostEqual(reference.circular_diff(12.0, 0.0), 12.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
