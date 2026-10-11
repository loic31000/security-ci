#!/usr/bin/env python3
"""Fail-closed validation of a *synthetic* Java/Gradle Trivy coverage probe.

A scan of gradle.lockfile is narrower than general Java/Kotlin coverage.
Only use real, scanner-generated Trivy JSON; ignore no missing targets.
"""
import argparse
import json
from pathlib import Path

POSITIVE_VERSION = "2.14.1"
LOG4J_NAMES = frozenset((
    "org.apache.logging.log4j:log4j-core",
    "log4j-core",
))


class ProbeError(ValueError):
    pass


def _recognized(report, label):
    if not isinstance(report, dict) or type(report.get("SchemaVersion")) is not int:
        raise ProbeError(label + ": missing Trivy JSON schema")
    rows = report.get("Results")
    if not isinstance(rows, list) or not rows:
        raise ProbeError(label + ": empty or absent target inventory")
    targets = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("Target"), str):
            raise ProbeError(label + ": invalid inventory record")
        # The scan directory contains one known fixture only; a partial or
        # invented target name must never count as Gradle dependency coverage.
        target = row["Target"].replace("\\", "/").removeprefix("./")
        if target != "gradle.lockfile":
            raise ProbeError(label + ": unexpected target (not Gradle lock)")
        if not isinstance(row.get("Type"), str) or not row["Type"]:
            raise ProbeError(label + ": recognized target has no analyzer type")
        if row.get("Class") not in ("lang-pkgs", None):
            raise ProbeError(label + ": Gradle lock is not a dependency target")
        vulnerabilities = row.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ProbeError(label + ": malformed vulnerability list")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ProbeError(label + ": malformed vulnerability entry")
        targets.append((row["Type"], vulnerabilities))
    if len(targets) != 1:
        raise ProbeError(label + ": duplicate or unexpected inventory records")
    return targets[0]


def probe(positive, negative):
    positive_type, positives = _recognized(positive, "positive")
    negative_type, negatives = _recognized(negative, "negative")
    if positive_type != negative_type:
        raise ProbeError("positive/negative Gradle analyzers disagree")
    observed = [
        item for item in positives
        if item.get("PkgName") in LOG4J_NAMES
        and item.get("InstalledVersion") == POSITIVE_VERSION
        and item.get("Severity") in ("HIGH", "CRITICAL")
        and isinstance(item.get("VulnerabilityID"), str)
        and item["VulnerabilityID"]
    ]
    if not observed:
        raise ProbeError("Trivy did not identify known vulnerable log4j-core 2.14.1")
    if negatives:
        raise ProbeError("benign Gradle fixture produced advisory candidates")
    return {
        "schema": 1,
        "status": "PASS",
        "ecosystem": "java-gradle-lockfile",
        "target_type": positive_type,
        "recognized_positive_targets": 1,
        "recognized_negative_targets": 1,
        "positive_advisory_candidates": len(observed),
        "negative_advisory_candidates": 0,
        "limitations": (
            "Synthetic Gradle lockfile only; does not certify Maven, "
            "Java/Kotlin source code, transitives, exploitability, or general recall"
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--positive", required=True, type=Path)
    parser.add_argument("--negative", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = probe(
            json.loads(args.positive.read_text(encoding="utf-8")),
            json.loads(args.negative.read_text(encoding="utf-8")),
        )
    except (OSError, ValueError, TypeError) as exc:
        result = {"schema": 1, "status": "ERROR", "reason": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
