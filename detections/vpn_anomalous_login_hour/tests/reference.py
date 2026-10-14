"""Reference implementation of the detection logic in Python.

Mirrors baseline.spl / detection.spl so the logic can be unit tested without
Splunk, and includes the naive version for before/after comparison.
"""
import math
import statistics
from collections import defaultdict

MIN_SAMPLES = 10
STDEV_FLOOR = 0.5
ZSCORE_THRESHOLD = 3.0


def hour_of(dt):
    return dt.hour + dt.minute / 60.0


def circular_baseline(hours):
    """Circular mean and stdev of hour-of-day values (0-24)."""
    angles = [h * 2 * math.pi / 24 for h in hours]
    ms = sum(math.sin(a) for a in angles) / len(angles)
    mc = sum(math.cos(a) for a in angles) / len(angles)
    r = math.sqrt(ms * ms + mc * mc)
    typical = (math.atan2(ms, mc) * 24 / (2 * math.pi)) % 24
    circ_sd = 12.0 if r < 1e-4 else math.sqrt(-2 * math.log(r)) * 24 / (2 * math.pi)
    return typical, max(circ_sd, STDEV_FLOOR)


def circular_diff(a, b):
    d = abs(a - b)
    return 24 - d if d > 12 else d


def detect(events, test_date):
    """Improved: baseline from prior days only, circular stats, floor, min samples."""
    base = defaultdict(list)
    for e in events:
        if e["action"] == "success" and e["time"].date() < test_date:
            base[e["user"]].append(hour_of(e["time"]))
    baselines = {u: circular_baseline(h) for u, h in base.items() if len(h) >= MIN_SAMPLES}

    alerts = []
    for e in events:
        if e["action"] != "success" or e["time"].date() != test_date:
            continue
        if e["user"] not in baselines:
            continue
        typical, sd = baselines[e["user"]]
        h = hour_of(e["time"])
        z = circular_diff(h, typical) / sd
        if z > ZSCORE_THRESHOLD:
            alerts.append({"user": e["user"], "hour": h, "typical_hour": round(typical, 2),
                           "stdev_hour": round(sd, 2), "zscore": round(z, 2),
                           "src_country": e["src_country"]})
    return sorted(alerts, key=lambda a: -a["zscore"])


def detect_naive(events, test_date):
    """The textbook version: linear hours, same-window baseline, no floor, no minimum."""
    by_user = defaultdict(list)
    for e in events:
        by_user[e["user"]].append(e)
    alerts = []
    for user, evs in by_user.items():
        hours = [hour_of(e["time"]) for e in evs]
        if len(hours) < 2:
            continue
        mean, sd = statistics.mean(hours), statistics.stdev(hours)
        if sd == 0:
            continue
        for e in evs:
            if e["time"].date() != test_date:
                continue
            h = hour_of(e["time"])
            z = abs(h - mean) / sd
            if z > ZSCORE_THRESHOLD:
                alerts.append({"user": user, "hour": h, "zscore": round(z, 2)})
    return sorted(alerts, key=lambda a: -a["zscore"])
