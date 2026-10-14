# detections-as-code

A personal detection engineering portfolio. Every detection here ships with a
hypothesis, ATT&CK mapping, synthetic test data, automated tests, and an honest
list of blind spots and false positives.

> All data is synthetic. IPs use RFC 5737 documentation ranges. No real
> company logs are used anywhere in this repo.

## Detections

| ID | Detection | ATT&CK | Platform | Status |
|----|-----------|--------|----------|--------|
| DET-0001 | [VPN login at anomalous hour (circular z-score)](detections/vpn_anomalous_login_hour/) | T1078 | Splunk | experimental |

## Repo layout

```
detections/<name>/
├── README.md        # hypothesis, logic, limitations (ADS-style)
├── detection.yml    # metadata: ATT&CK, severity, tuning knobs, FP notes
├── *.spl            # the queries
├── tuning.md        # what was changed and why
├── test_data/       # synthetic logs + ground-truth labels
└── tests/           # reference implementation + unit tests
docs/
├── approach.md            # how I approach detection engineering
└── detection-template.md  # template for new detections
```

## Run the tests

```bash
python detections/vpn_anomalous_login_hour/tests/test_detection.py
```

No dependencies beyond Python 3.9+.

## Principles

1. Start from a threat and a hypothesis, not from a query.
2. If I cannot test it, I do not ship it.
3. Every alert needs an owner action. If there is none, it is a dashboard.
4. Document what the detection does **not** catch.

See [docs/approach.md](docs/approach.md).
