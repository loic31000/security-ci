#!/usr/bin/env python3
"""Verify *limited* positive/negative scanner control pairs from actual SARIF.

This calibration is per labeled fixture, NOT real-world precision or recall.
Output deliberately omits messages, matches and potential credential values.
"""
import argparse
import json
from pathlib import Path
from urllib.parse import unquote, urlsplit

SCANNERS = frozenset(("semgrep", "gitleaks", "zizmor"))


class InvalidEvidence(ValueError):
    pass


def _reported_paths(result):
    paths = []
    for location in result.get("locations", []):
        if not isinstance(location, dict):
            raise InvalidEvidence("malformed SARIF location")
        uri = (((location.get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri"))
        if not isinstance(uri, str) or not uri:
            continue
        parsed = urlsplit(uri)
        # Different scanners emit relative or absolute local paths. We compare
        # basenames only; do not leak target paths or accept cross-file findings.
        raw_path = unquote(parsed.path).replace("\\", "/")
        if parsed.scheme not in ("", "file") or ".." in raw_path.split("/"):
            raise InvalidEvidence("unsafe SARIF location")
        paths.append(raw_path.rsplit("/", 1)[-1])
    return paths


def _active_results(report):
    if not isinstance(report, dict) or report.get("version") != "2.1.0":
        raise InvalidEvidence("invalid SARIF version")
    runs = report.get("runs")
    if not isinstance(runs, list) or not runs:
        raise InvalidEvidence("missing SARIF runs")
    candidates = []
    all_results = 0
    for run in runs:
        if not isinstance(run, dict):
            raise InvalidEvidence("malformed SARIF run")
        driver = (run.get("tool") or {}).get("driver")
        if not isinstance(driver, dict) or not driver.get("name"):
            raise InvalidEvidence("missing scanner identity")
        rules = {item.get("id"): item for item in driver.get("rules", [])
                 if isinstance(item, dict)}
        for invocation in run.get("invocations", []):
            if not isinstance(invocation, dict) or invocation.get("executionSuccessful") is not True:
                raise InvalidEvidence("unsuccessful scanner invocation")
            for field in ("toolConfigurationNotifications", "toolExecutionNotifications"):
                notifications = invocation.get(field, [])
                if not isinstance(notifications, list):
                    raise InvalidEvidence("malformed scanner notifications")
                if any(not isinstance(item, dict) or item.get("level") == "error"
                       for item in notifications):
                    raise InvalidEvidence("scanner configuration or execution error")
        results = run.get("results")
        if not isinstance(results, list):
            raise InvalidEvidence("missing SARIF results")
        all_results += len(results)
        for result in results:
            if not isinstance(result, dict):
                raise InvalidEvidence("malformed SARIF result")
            kind = result.get("kind", "fail")
            if kind not in ("fail", "pass", "review", "open", "informational", "notApplicable"):
                raise InvalidEvidence("unknown SARIF kind")
            rule = rules.get(result.get("ruleId")) or {}
            level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
            if level not in ("error", "warning", "note", "none"):
                raise InvalidEvidence("unknown SARIF level")
            suppressions = result.get("suppressions") or []
            if not isinstance(suppressions, list) or any(
                    not isinstance(item, dict) for item in suppressions):
                raise InvalidEvidence("malformed suppressions")
            active = (kind == "fail" and level in ("warning", "error")
                      and not any(s.get("status") == "accepted" for s in suppressions))
            if active:
                candidates.append(_reported_paths(result))
    return candidates, all_results


def _read(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InvalidEvidence("SARIF unreadable or malformed") from exc


def calibrate(scanner, positive, negative, positive_file):
    if scanner not in SCANNERS:
        raise InvalidEvidence("unsupported scanner")
    if (not isinstance(positive_file, str) or not positive_file
            or "/" in positive_file or "\\" in positive_file
            or positive_file in (".", "..")):
        raise InvalidEvidence("invalid expected positive filename")
    positive_candidates, positive_total = _active_results(positive)
    negative_candidates, negative_total = _active_results(negative)
    matching = sum(positive_file in locations for locations in positive_candidates)
    unexpected = sum(positive_file not in locations for locations in positive_candidates)
    evidence = {
        "schema": 1,
        "scanner": scanner,
        "labeled_positive_fixtures": 1,
        "labeled_negative_fixtures": 1,
        "positive_active_results": len(positive_candidates),
        "negative_raw_results": negative_total,
        "true_positive_fixtures": int(matching > 0),
        "false_negative_fixtures": int(matching == 0),
        "true_negative_fixtures": int(negative_total == 0),
        "false_positive_fixtures": int(negative_total > 0),
        "unexpected_positive_locations": unexpected,
        "status": "PASS" if matching > 0 and unexpected == 0 and negative_total == 0 else "FAIL",
        "limitations": "fixture-level calibration only; no real-project FP/FN rate inferred",
    }
    return evidence


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--scanner", choices=sorted(SCANNERS), required=True)
    p.add_argument("--positive", type=Path, required=True)
    p.add_argument("--negative", type=Path, required=True)
    p.add_argument("--positive-file", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        data = calibrate(args.scanner, _read(args.positive), _read(args.negative),
                         args.positive_file)
    except (InvalidEvidence, TypeError, KeyError, AttributeError) as exc:
        data = {"schema": 1, "scanner": args.scanner, "status": "ERROR",
                "error": str(exc)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(data, sort_keys=True))
    return 0 if data["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
