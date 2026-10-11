#!/usr/bin/env python3
"""Interpret generated engine dependency manifests and Trivy JSON without false 'clean' claims."""
import argparse
import json
from pathlib import Path

MANIFESTS = ("python/requirements.txt", "node/package-lock.json", "go/go.mod")


def summarize(directory, report):
    root = Path(directory)
    missing = [p for p in MANIFESTS if not (root / p).is_file() or (root / p).stat().st_size == 0]
    if missing:
        raise ValueError("Engine dependency manifests missing: " + ", ".join(missing))
    data = json.loads(Path(report).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("SchemaVersion"), int):
        raise ValueError("Invalid Trivy JSON response")
    rows = data.get("Results", [])
    if not isinstance(rows, list) or not rows:
        raise ValueError("No engine dependency targets recognized by Trivy")
    targets = []
    findings = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("Target"), str):
            raise ValueError("Malformed Trivy target record")
        targets.append(row["Target"])
        for vuln in row.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict) or not isinstance(vuln.get("VulnerabilityID"), str):
                raise ValueError("Malformed Trivy vulnerability result")
            findings.append((vuln["VulnerabilityID"], vuln.get("PkgName", "?"),
                             vuln.get("Severity", "UNKNOWN"), row["Target"]))
    found = {name: any(name.split("/")[-1] in t for t in targets) for name in MANIFESTS}
    missing_coverage = [name for name, matched in found.items() if not matched]
    return {
        "targets": len(set(targets)),
        "vulnerabilities": findings,
        "missing_coverage": missing_coverage,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("manifest_dir")
    p.add_argument("trivy_json")
    args = p.parse_args()
    try:
        result = summarize(args.manifest_dir, args.trivy_json)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"::error::Engine dependency scan invalid: {exc}")
        return 1
    print(f"Engine dependency audit: {result['targets']} target(s) detected")
    print(f"Potential HIGH/CRITICAL findings: {len(result['vulnerabilities'])}")
    print("Coverage not confirmed: " + (", ".join(result["missing_coverage"]) or "none"))
    if result["vulnerabilities"]:
        for vuln_id, package, severity, target in result["vulnerabilities"][:30]:
            print(f"Potential finding (not confirmed exploited): {vuln_id} / {package} / {severity} / {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
