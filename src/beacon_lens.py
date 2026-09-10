#!/usr/bin/env python3
"""Explainable beacon and DNS-tunnel triage for Zeek JSON logs."""

from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Signal:
    kind: str
    score: int
    origin: str
    destination: str
    observations: int
    evidence: dict


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def read_jsonl(path: Path) -> tuple[list[dict], list[str]]:
    records, errors = [], []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("expected object")
            records.append(value)
        except (json.JSONDecodeError, ValueError) as exc:
            errors.append(f"line {number}: {exc}")
    return records, errors


def beacon_signals(records: list[dict], minimum: int = 6) -> list[Signal]:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for item in records:
        if "ts" not in item or "id.orig_h" not in item or "id.resp_h" not in item:
            continue
        key = (str(item["id.orig_h"]), str(item["id.resp_h"]), int(item.get("id.resp_p", 0)), str(item.get("proto", "unknown")))
        groups[key].append(item)
    signals = []
    for (origin, destination, port, proto), events in groups.items():
        if len(events) < minimum:
            continue
        times = sorted(float(event["ts"]) for event in events)
        intervals = [right - left for left, right in zip(times, times[1:]) if right > left]
        if len(intervals) < minimum - 1:
            continue
        mean = statistics.fmean(intervals)
        cv = statistics.pstdev(intervals) / mean if mean else 1.0
        bytes_out = [int(event.get("orig_bytes", 0) or 0) for event in events]
        byte_mean = statistics.fmean(bytes_out) if bytes_out else 0
        byte_cv = statistics.pstdev(bytes_out) / byte_mean if byte_mean else 1.0
        periodicity = max(0.0, 1.0 - min(cv, 1.0))
        size_stability = max(0.0, 1.0 - min(byte_cv, 1.0))
        volume = min(1.0, len(events) / 20)
        score = round(100 * (0.60 * periodicity + 0.25 * size_stability + 0.15 * volume))
        if score >= 55:
            signals.append(Signal("periodic-connection", score, origin, f"{destination}:{port}/{proto}", len(events), {
                "mean_interval_seconds": round(mean, 3), "interval_cv": round(cv, 4),
                "mean_origin_bytes": round(byte_mean, 2), "origin_bytes_cv": round(byte_cv, 4),
            }))
    return signals


def dns_signals(records: list[dict], minimum: int = 5) -> list[Signal]:
    groups: dict[tuple[str, str], list[tuple[str, float]]] = defaultdict(list)
    for item in records:
        query = str(item.get("query") or "").lower().rstrip(".")
        origin = str(item.get("id.orig_h") or "unknown")
        labels = query.split(".")
        if len(labels) < 3:
            continue
        base = ".".join(labels[-2:])
        prefix = ".".join(labels[:-2])
        groups[(origin, base)].append((prefix, entropy(prefix.replace(".", ""))))
    signals = []
    for (origin, base), values in groups.items():
        if len(values) < minimum:
            continue
        prefixes = [value[0] for value in values]
        average_entropy = statistics.fmean(value[1] for value in values)
        average_length = statistics.fmean(len(value) for value in prefixes)
        unique_ratio = len(set(prefixes)) / len(prefixes)
        score = round(min(100, average_entropy * 12 + min(30, average_length) + unique_ratio * 25))
        if average_entropy >= 3.2 and average_length >= 12 and unique_ratio >= 0.8:
            signals.append(Signal("dns-encoding-candidate", score, origin, base, len(values), {
                "average_prefix_entropy": round(average_entropy, 3),
                "average_prefix_length": round(average_length, 2), "unique_ratio": round(unique_ratio, 3),
            }))
    return signals


def analyze(records: list[dict]) -> list[Signal]:
    values = beacon_signals(records) + dns_signals(records)
    return sorted(values, key=lambda item: (-item.score, item.origin, item.destination))


def markdown(signals: list[Signal], errors: list[str]) -> str:
    lines = ["# Beacon Lens", "", f"**Signals:** {len(signals)} · **Rejected records:** {len(errors)}", "",
             "| Score | Signal | Origin | Destination | Observations |", "| ---: | --- | --- | --- | ---: |"]
    for item in signals:
        lines.append(f"| {item.score} | {item.kind} | {item.origin} | {item.destination} | {item.observations} |")
    lines += ["", "> Statistical signals require analyst validation and endpoint context.", ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--fail-score", type=int, default=101)
    args = parser.parse_args()
    records, errors = read_jsonl(args.input)
    signals = analyze(records)
    output = json.dumps({"signals": [asdict(item) for item in signals], "errors": errors}, indent=2) if args.json else markdown(signals, errors)
    args.output.write_text(output, encoding="utf-8") if args.output else print(output)
    return 1 if any(item.score >= args.fail_score for item in signals) else 0


if __name__ == "__main__":
    raise SystemExit(main())
