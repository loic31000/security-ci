#!/usr/bin/env python3
"""Verify real, narrow Maven POM dependency scan evidence, never claim Java coverage."""
import argparse
import json
from pathlib import Path


class MavenEvidenceError(ValueError):
    pass


def extract(report, label):
    if not isinstance(report, dict) or type(report.get("SchemaVersion")) is not int:
        raise MavenEvidenceError(label + ": invalid Trivy JSON schema")
    rows = report.get("Results")
    if not isinstance(rows, list) or len(rows) != 1:
        raise MavenEvidenceError(label + ": expected exactly one Maven target")
    row = rows[0]
    if not isinstance(row, dict) or row.get("Target") not in ("pom.xml", "./pom.xml"):
        raise MavenEvidenceError(label + ": missing or unexpected pom.xml target")
    if row.get("Type") != "pom" or row.get("Class") != "lang-pkgs":
        raise MavenEvidenceError(label + ": dependency analyzer is not Maven POM")
    vulnerabilities = row.get("Vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise MavenEvidenceError(label + ": malformed advisories")
    if any(not isinstance(x, dict) for x in vulnerabilities):
        raise MavenEvidenceError(label + ": malformed advisory entry")
    return vulnerabilities


def verify(positive, negative):
    vulnerabilities = extract(positive, "positive")
    benign = extract(negative, "negative")
    log4j = [
        v for v in vulnerabilities
        if v.get("PkgName") in ("org.apache.logging.log4j:log4j-core", "log4j-core")
        and v.get("InstalledVersion") == "2.14.1"
        and v.get("Severity") in ("HIGH", "CRITICAL")
        and isinstance(v.get("VulnerabilityID"), str) and v["VulnerabilityID"]
    ]
    if not log4j:
        raise MavenEvidenceError("positive Maven POM missed pinned log4j-core 2.14.1")
    if benign:
        raise MavenEvidenceError("benign Maven POM produced candidate advisories")
    return {
        "schema": 1, "status": "PASS", "ecosystem": "java-maven-pom",
        "positive_recognized_targets": 1, "negative_recognized_targets": 1,
        "positive_advisory_candidates": len(log4j),
        "negative_advisory_candidates": 0,
        "limitations": "isolated direct Maven POM dependency fixtures only; no transitive, source, or overall Java coverage",
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--positive", type=Path, required=True)
    p.add_argument("--negative", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        evidence = verify(json.loads(args.positive.read_text(encoding="utf-8")),
                          json.loads(args.negative.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError) as exc:
        evidence = {"schema": 1, "status": "ERROR", "reason": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps(evidence, sort_keys=True))
    return 0 if evidence["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
