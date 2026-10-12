#!/usr/bin/env python3
"""One-shot, read-only comparison of exact approved Semgrep rules and candidate metadata.

Never execute unknown rules. Never store or publish Semgrep rule bodies, IDs, or
rule files. If the registry returns drift, baseline is UNAVAILABLE.
"""
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

from ruamel.yaml import YAML

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from verify_semgrep_bundle import validate_bundle, RuleBundleError

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(os.environ["RUNNER_TEMP"]) / "approved-profile-metadata.json"
REVIEW = json.loads((ROOT / "locks" / "semgrep-security-audit.json").read_text())
CWE = re.compile(r"(?i)\bCWE[-_\s:]*(\d{1,4})\b")
PARSER = YAML(typ="safe")


def inventory(rules):
    counts = collections.Counter()
    by_lang = collections.defaultdict(set)
    no_cwe = 0
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("invalid Semgrep rule")
        meta = rule.get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {}
        labels = meta.get("cwe", [])
        if isinstance(labels, str):
            labels = [labels]
        if not isinstance(labels, (list, tuple)):
            labels = []
        cwe = set()
        for item in labels:
            cwe.update(CWE.findall(str(item)))
        if not cwe:
            no_cwe += 1
        langs = rule.get("languages") or []
        if not isinstance(langs, list) or not langs:
            raise ValueError("invalid Semgrep rule language metadata")
        for lang in langs:
            counts[str(lang)] += 1
            by_lang[str(lang)].update(cwe)
    return {
        "rules": len(rules),
        "by_language": dict(sorted(counts.items())),
        "cwe_labels_by_language": {
            lang: sorted(values, key=int) for lang, values in sorted(by_lang.items())
        },
        "rule_records_without_cwe_metadata": no_cwe,
    }


def probe():
    candidate = json.loads(
        (Path(os.environ["RUNNER_TEMP"]) / "candidate-coverage-matrix.json").read_text()
    )["expanded_candidate"]
    req = urllib.request.Request(
        REVIEW["source"], headers={"Accept": "text/yaml", "User-Agent": "security-ci-experimental-provenance"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            bundle = response.read(5_000_001)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"status": "SOURCE_UNAVAILABLE", "error_type": type(exc).__name__,
                "baseline_authorized": False}

    observed = hashlib.sha256(bundle).hexdigest()
    if observed != REVIEW["sha256"]:
        return {
            "status": "UNAPPROVED_REGISTRY_RESPONSE",
            "baseline_authorized": False,
            "approved_sha256": REVIEW["sha256"],
            "observed_sha256": observed,
            "notice": "Unknown data rejected without rule parsing or execution.",
        }
    try:
        validate_bundle(bundle, REVIEW)
        obj = PARSER.load(bundle.decode("utf-8"))
        if not isinstance(obj, dict) or not isinstance(obj.get("rules"), list):
            raise ValueError("malformed approved configuration")
        baseline = inventory(obj["rules"])
    except (UnicodeError, ValueError, RuleBundleError) as exc:
        return {
            "status": "APPROVED_BUT_UNPARSEABLE",
            "baseline_authorized": False,
            "error_type": type(exc).__name__,
        }

    candidate_map = {
        language: set(str(x) for x in cwes)
        for language, cwes in candidate["cwe_ids_by_language"].items()
    }
    absent_language = sorted(set(baseline["by_language"]) - set(candidate_map))
    missing_cwe = {
        lang: sorted(labels - candidate_map.get(lang, set()), key=int)
        for lang, labels in ((name, set(values)) for name, values in
                             baseline["cwe_labels_by_language"].items())
        if labels - candidate_map.get(lang, set())
    }
    return {
        "status": "APPROVED_BUNDLE_COMPARED",
        "baseline_authorized": True,
        "approved_sha256": REVIEW["sha256"],
        "baseline_rules": baseline["rules"],
        "baseline_by_language": baseline["by_language"],
        "baseline_cwe_label_counts_by_language": {
            name: len(values) for name, values in baseline["cwe_labels_by_language"].items()
        },
        "baseline_rules_missing_cwe_metadata": baseline["rule_records_without_cwe_metadata"],
        "expanded_candidate_by_language": candidate["rules_by_language"],
        "expanded_candidate_distinct_cwe": candidate["total_distinct_cwe"],
        "baseline_languages_missing_from_candidate": absent_language,
        "baseline_cwe_labels_missing_from_candidate": missing_cwe,
        "disclaimer": "Metadata-only structural comparison. No proof of equivalent detection, precision or recall. Semgrep rule data was never persisted.",
    }


def main():
    try:
        result = probe()
    except Exception as exc:
        result = {"status": "ERROR", "error_type": type(exc).__name__,
                  "baseline_authorized": False}
    OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
        f.write("\n### Current 225-rule Semgrep provenance-only baseline probe\n\n")
        f.write("- Outcome: **" + result["status"] + "**\n")
        if result.get("baseline_authorized"):
            f.write(f"- Baseline unique rule objects: {result['baseline_rules']}\n")
            f.write(f"- Missing candidate languages: {result['baseline_languages_missing_from_candidate']}\n")
            f.write("- This is a metadata-only comparison, not detection parity.\n")
        else:
            f.write("- No comparison authorized: the exact approved Semgrep YAML was unavailable.\n")
            f.write("- Unapproved rule data was not parsed, stored or executed.\n")
    return 0 if result.get("baseline_authorized") else 1


if __name__ == "__main__":
    sys.exit(main())
