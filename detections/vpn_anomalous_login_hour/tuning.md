# Tuning log

Record every threshold change and why. Future you will not remember.

| Date | Parameter | From | To | Reason | Evidence |
|------|-----------|------|----|--------|----------|
| 2026-10-14 | stdev_floor_hours | none | 0.5 | Very consistent users produced z > 4 for a 36 min deviation | `dave` case in test data |
| 2026-10-14 | min_baseline_logins | none | 10 | New users produce unstable baselines | `erin` case in test data |
| 2026-10-14 | baseline window | same-window | prior 30d | Anomalies were deflating their own z-score | `alice` case, z 4.26 vs 6.52 |

## Knobs to try on real data

- `zscore_threshold`: start at 3, check alerts/day, move to 4 if noisy.
- `baseline_window_days`: shorter adapts faster to schedule changes, longer is more stable.
- Separate weekday/weekend baselines if weekend logins dominate false positives.
- Allowlist: service accounts, on-call rotations (maintain in a lookup, review quarterly).

## Before going live

1. Run `detection.spl` over the last 30 days in **silent** mode (no alerts, just count).
2. Review the top 20 hits manually and record TP/FP.
3. Adjust, then enable as low severity for two weeks before relying on it.
