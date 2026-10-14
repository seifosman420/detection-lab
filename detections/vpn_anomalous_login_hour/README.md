# DET-0001: VPN login at anomalous hour

**ATT&CK:** T1078 Valid Accounts · **Platform:** Splunk · **Status:** experimental

## Goal

Surface successful VPN logins that deviate sharply from that user's own
time-of-day pattern, as a weak signal of credential misuse.

## Hypothesis

Stolen credentials are often used outside the owner's usual hours (different
time zone, automated access, attacker working hours). A per-user baseline
catches this without hard-coding "business hours", which break for shift
workers and global teams.

## How it works

1. `baseline.spl` (daily): from the previous 30 days of successful logins,
   compute each user's **circular** mean hour and circular stdev. Skip users
   with fewer than 10 logins. Floor the stdev at 0.5 h. Save to a lookup.
2. `detection.spl` (hourly): score new logins against the lookup using the
   shortest distance around the 24h clock. Alert at z > 3.

## Why not the textbook version?

The common approach (`eventstats avg/stdev` over raw hours, `naive.spl`) has
four problems. Results on the synthetic data in `test_data/`:

| Issue | Example in data | Naive | This detection |
|---|---|---|---|
| Hours are circular, not linear (23:30 and 00:30 average to noon) | `carol` (night shift) logs in at noon | **Missed** (naive mean 13.9, stdev 11.0, so z is about 0) | Caught, z = 11.6 |
| Tiny stdev makes z explode | `dave` logs in 36 min off a very consistent pattern | **False positive**, z = 4.55 | Suppressed by stdev floor |
| Baseline includes the day being scored | `alice` anomaly inflates her own stdev | Caught but z deflated to 4.26 | z = 6.52 |
| No scoping to successful logins | `bob` failed login at 03:00 | **False positive**, z = 3.2 | Out of scope by design |

| | True positives | False positives | Missed |
|---|---|---|---|
| Naive | 1 / 2 | 2 | 1 |
| This detection | 2 / 2 | 0 | 0 |

These are synthetic results that demonstrate the logic. They are **not** a
claim about real-world precision.

## Known gaps and false positives

See `detection.yml`. Biggest ones: an attacker who matches the victim's usual
hours is invisible, and travel/on-call work will fire.

## Making it useful in production

A time-of-day outlier alone is a weak signal. Treat it as a risk signal and
combine with enrichment before paging anyone:

- New country or ASN for the user (`alice`'s alert in the test data has `RO`)
- MFA method changed or MFA fatigue pattern before the login
- Impossible travel, or a new device
- Sensitive access shortly after login (admin portals, bulk downloads)

Suggested triage: low severity alone; medium with new geo; high with new geo
and sensitive follow-on activity.

## Analyst response

1. Check the user's ticket/calendar for travel or on-call.
2. Compare src_ip/ASN/geo with history. Confirm with the user out-of-band.
3. If not confirmed: revoke sessions, reset credentials, review post-login activity.

## Validation

```bash
python test_data/generate_logs.py      # regenerate synthetic data (deterministic)
python tests/test_detection.py         # 6 tests
```

The tests run a Python reference implementation that mirrors the SPL. The SPL
itself is not executed in CI; validate it in a Splunk instance against
`test_data/vpn_logs.csv` (index it as `vpnlogs`, set `_time` from the `_time` column).

## Changelog

- 2026-10-14: initial version
