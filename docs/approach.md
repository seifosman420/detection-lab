# How I approach detection engineering

## The loop

```
Prioritize → Hypothesize → Check data → Build → Test → Baseline on real data
     ↑                                                          ↓
  Retire / Improve  ←  Measure  ←  Deploy (staged)  ←  Tune & document
```

1. **Prioritize by threat, not by availability.** Pick what to cover using
   ATT&CK techniques relevant to your sector, recent incidents, threat intel,
   red/purple team findings, and what your crown jewels are. "I found a cool
   query" is not a reason to build a detection.
2. **Write the hypothesis first.** One sentence: *"If an attacker does X, we
   will see Y in log source Z."* If you cannot write it, you are not ready.
3. **Check the data exists.** Is the log source onboarded, parsed, complete,
   timely? Many "missing detections" are really missing telemetry.
4. **Build the simplest thing that could work.** Start with a precise,
   boring rule. Add statistics or ML only when rules cannot express the behavior.
5. **Test it.** Generate the behavior (Atomic Red Team, Caldera, hand-crafted
   events, synthetic logs) and prove the detection fires. Also test that it
   stays quiet on benign look-alikes.
6. **Baseline on real data silently.** Run over 30-90 days of history with no
   alerting. Review hits. Measure volume and precision before anyone gets paged.
7. **Tune, then document.** Record thresholds, exclusions, and *why*.
8. **Deploy in stages.** Silent → low severity → production. Give the SOC a
   runbook before the first alert, not after.
9. **Measure and maintain.** Track alert volume, true-positive rate, time to
   triage, and analyst feedback. Fix or delete detections that do not earn
   their keep.

## Principles

- **Detections are code.** Version control, peer review, tests, CI, changelog.
- **Every alert needs an action.** If no analyst can do anything with it, it
  is a dashboard or a hunting query, not an alert.
- **Know your Pyramid of Pain.** Hashes and IPs are cheap to evade. Prefer
  behaviors and techniques, and keep IOC matching as a fast, disposable layer.
- **Behavior over tooling.** Detect the technique (e.g. LSASS access) rather
  than one tool's name.
- **Document what you miss.** Blind spots written down are a roadmap.
  Blind spots unwritten are an incident.
- **Coverage is not quality.** A green ATT&CK heatmap of noisy, untested rules
  is worse than a small map of detections you trust.
- **Signals vs alerts.** Weak signals (like anomalous hour) are better scored
  and combined than paged individually.
- **Analysts are your customers.** Their feedback is your best test data.

## Anti-patterns

- Copying rules from the internet and enabling them unreviewed
- Thresholds with no recorded justification
- Alerting on a single weak signal at high severity
- No exclusions process, so noise piles up until the rule is disabled
- Building only what is easy to detect (the "streetlight effect")
- Never retiring detections

## Metrics worth tracking

| Metric | Why |
|---|---|
| Alerts per detection per week | Finds noisy rules |
| True-positive rate / analyst verdicts | Quality, not just volume |
| Mean time to triage | Whether alerts are understandable |
| % of priority techniques with tested coverage | Real coverage |
| Detections with a passing automated test | Engineering hygiene |
| Time from new threat to deployed detection | Responsiveness |

## Starting points

- MITRE ATT&CK and the Sigma rule format/repository
- Atomic Red Team, for generating test behavior
- Palantir's Alerting and Detection Strategy (ADS) framework, which `detection-template.md` is based on
- The "Pyramid of Pain" (David Bianco)
- Detection Engineering Maturity Matrix (Kyle Bailey)
