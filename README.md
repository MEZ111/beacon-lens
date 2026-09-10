# BeaconLens

Explainable statistical triage for Zeek JSON logs. BeaconLens highlights two
behaviors that are difficult to spot in raw telemetry: low-variance recurring
connections and high-entropy DNS prefixes that may carry encoded data.

## Detection model

### Periodic connections

Flows are grouped by origin, destination, port, and protocol. The score combines
interval regularity, outbound-size stability, and observation volume. The report
includes each component so an analyst can challenge the result.

### DNS encoding candidates

Queries are grouped by origin and base domain. Candidates must meet minimum
entropy, label length, uniqueness, and observation-count gates before scoring.

## Install

```bash
git clone https://github.com/MEZ111/beacon-lens.git
cd beacon-lens
python3 -m pip install .
```

## Run

```bash
beacon-lens zeek.jsonl -o signals.md
beacon-lens zeek.jsonl --json
beacon-lens zeek.jsonl --fail-score 80
```

The input is Zeek JSON output containing `conn.log`-style connection fields,
`dns.log`-style query fields, or both.

## Why the result is reviewable

Each periodic signal includes mean interval, interval coefficient of variation,
mean outbound bytes, and byte-size coefficient of variation. Each DNS signal
includes average prefix entropy, length, and uniqueness ratio.

## Verification

```bash
PYTHONPATH=src python3 -m unittest -v tests/test_beacon_lens.py
```

Tests use synthetic periodic, jittered, high-entropy, and repetitive traffic.

## Boundaries

Regular software updates and telemetry can look periodic. Legitimate randomized
subdomains can have high entropy. BeaconLens produces triage signals, not malware
verdicts; validate them with endpoint, domain, and threat-intelligence context.

## License

MIT
