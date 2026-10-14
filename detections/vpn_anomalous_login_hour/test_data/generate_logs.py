#!/usr/bin/env python3
"""Generate synthetic VPN logs with labelled anomalies.

Output (next to this file):
  vpn_logs.csv   - 30 days of baseline + 1 scoring day (2025-01-15, UTC)
  expected.json  - ground truth for the scoring day

Each user is built to exercise one specific behaviour of the detection.
All IPs are RFC 5737 documentation ranges. Deterministic (seeded).
"""
import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).parent
SEED = 1337
TEST_DATE = datetime(2025, 1, 15, tzinfo=timezone.utc)  # the day being scored
BASELINE_DAYS = 30

# typical/sd are hours (UTC). `net` is a documentation /24.
USERS = {
    "alice": dict(typical=13.5, sd=0.7, country="US", net="203.0.113"),   # tight day worker
    "bob":   dict(typical=9.0,  sd=1.5, country="US", net="198.51.100"),  # normal day worker
    "carol": dict(typical=0.0,  sd=1.0, country="IN", net="192.0.2"),     # night shift, wraps midnight
    "dave":  dict(typical=8.0,  sd=0.1, country="DE", net="203.0.113"),   # extremely consistent
    "erin":  dict(typical=10.0, sd=1.0, country="GB", net="198.51.100"),  # new user, tiny baseline
    "frank": dict(typical=14.0, sd=3.0, country="US", net="192.0.2"),     # flexible schedule
}
NEW_USER_BASELINE_DAYS = 4


def _event(rng, user, dt, country=None, ip=None, action="success"):
    cfg = USERS[user]
    return {
        "time": dt,
        "user": user,
        "src_ip": ip or f"{cfg['net']}.{rng.randint(10, 250)}",
        "src_country": country or cfg["country"],
        "action": action,
    }


def _at(hour):
    return TEST_DATE + timedelta(hours=hour)


def build_events():
    rng = random.Random(SEED)
    events = []

    for d in range(1, BASELINE_DAYS + 1):
        day = TEST_DATE - timedelta(days=d)
        for user, cfg in USERS.items():
            if user == "erin" and d > NEW_USER_BASELINE_DAYS:
                continue
            for _ in range(1 + (rng.random() < 0.2)):
                dt = day + timedelta(hours=rng.gauss(cfg["typical"], cfg["sd"]))
                events.append(_event(rng, user, dt))

    # Scoring day. (hour, should_alert, reason)
    scoring = [
        ("alice", 18.5, True,  "5h off a very tight baseline, new country", "RO", "198.51.100.23"),
        ("bob",    9.3, False, "ordinary variation", None, None),
        ("carol", 23.5, False, "normal for a night-shift user; naive method mishandles midnight wrap", None, None),
        ("carol", 12.0, True,  "noon login for a night-shift user; naive method misses it", "BR", "203.0.113.77"),
        ("dave",   8.6, False, "tiny deviation; z-score explodes without a stdev floor", None, None),
        ("erin",   3.0, False, "insufficient baseline (<10 logins): not scored by design", None, None),
        ("frank", 14.0, False, "ordinary variation", None, None),
    ]
    expected = []
    for user, hour, should, reason, country, ip in scoring:
        events.append(_event(rng, user, _at(hour), country=country, ip=ip))
        expected.append({"user": user, "hour": hour, "should_alert": should, "reason": reason})

    # A failed login at 03:00 - out of scope (success-only detection).
    events.append(_event(rng, "bob", _at(3.0), action="failure"))
    expected.append({"user": "bob", "hour": 3.0, "should_alert": False,
                     "reason": "failed login: out of scope, belongs to a brute-force detection"})

    events.sort(key=lambda e: e["time"])
    return events, expected


def write_files():
    events, expected = build_events()
    with open(HERE / "vpn_logs.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["_time", "user", "src_ip", "src_country", "action"])
        for e in events:
            w.writerow([e["time"].strftime("%Y-%m-%dT%H:%M:%SZ"), e["user"],
                        e["src_ip"], e["src_country"], e["action"]])
    with open(HERE / "expected.json", "w") as f:
        json.dump({"test_date": TEST_DATE.strftime("%Y-%m-%d"), "cases": expected}, f, indent=2)
        f.write("\n")
    print(f"wrote {len(events)} events")


if __name__ == "__main__":
    write_files()
