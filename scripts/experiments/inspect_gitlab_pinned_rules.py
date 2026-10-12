#!/usr/bin/env python3
"""Compare rule metadata of a source-pinned GitLab OCI image to an approved baseline.

Only metadata are written; no third-party rule IDs, YAML, code, or rule bodies
are included in logs, artifacts, or commits.
"""
import collections
import json
import os
from pathlib import Path
import re
import sys

from ruamel.yaml import YAML

ROOT = Path("/rules")
BASELINE = Path("/approved/rules.yaml")
OUT = Path("/reports/image-coverage-metadata.json")
CWE = re.compile(r"(?i)\bCWE[-_:\s]*(\d{1,4})\b")
MIT = re.compile(r"(?im)^#\s*License:\s*(MIT|Apache 2\.0|GPL[^;\n]*|LGPL[^;\n]*|.+)$")
parser = YAML(typ="safe")


def inventory(rules):
    langs = collections.Counter()
    cwes = collections.defaultdict(set)
    severities = collections.Counter()
    no_cwe = 0
    no_language = 0
    for item in rules:
        if not isinstance(item, dict):
            raise ValueError("rule is not mapping")
        languages = item.get("languages")
        if not isinstance(languages, list) or not languages:
            no_language += 1
            continue
        meta = item.get("metadata") or {}
        if not isinstance(meta, dict):
            meta = {}
        declared = meta.get("cwe", [])
        if isinstance(declared, str):
            declared = [declared]
        if not isinstance(declared, (tuple, list)):
            declared = []
        cwe = set()
        for candidate in declared:
            cwe.update(CWE.findall(str(candidate)))
        if not cwe:
            no_cwe += 1
        for language in set(map(str, languages)):
            langs[language] += 1
            cwes[language].update(cwe)
        sev = item.get("severity")
        if isinstance(sev, str):
            severities[sev] += 1
    return {
        "rule_objects": len(rules),
        "languages": dict(sorted(langs.items())),
        "cwe_metadata_missing_rules": no_cwe,
        "language_metadata_missing_rules": no_language,
        "cwe_labels_by_language": {name: sorted(ids, key=int) for name, ids in sorted(cwes.items())},
        "cwe_label_counts_by_language": {name: len(ids) for name, ids in sorted(cwes.items())},
        "severity": dict(sorted(severities.items())),
    }


def collect_rules():
    files = sorted(list(ROOT.rglob("*.yml")) + list(ROOT.rglob("*.yaml")))
    if not files:
        raise ValueError("GitLab image contains no YAML rules")
    all_rules = []
    license_headers = collections.Counter()
    rule_metadata_licenses = collections.Counter()
    parse_errors = []
    for path in files:
        try:
            data = path.read_text(encoding="utf-8")
            header = "\n".join(data.splitlines()[:14])
            match = MIT.search(header)
            if not match:
                license_headers["UNDECLARED"] += 1
            else:
                license_headers[match.group(1).strip()[:80]] += 1
            doc = parser.load(data)
            if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
                raise ValueError("not a Semgrep rules mapping")
            for rule in doc["rules"]:
                if isinstance(rule, dict):
                    meta = rule.get("metadata") or {}
                    if isinstance(meta, dict):
                        license_value = meta.get("license")
                        if license_value:
                            rule_metadata_licenses[str(license_value)[:50]] += 1
                all_rules.append(rule)
        except Exception as exc:
            parse_errors.append(type(exc).__name__)
    return files, all_rules, dict(license_headers), dict(rule_metadata_licenses), parse_errors


def main():
    files, rules, licenses, per_rule_licenses, parse_errors = collect_rules()
    image = inventory(rules)
    result = {
        "status": "IMAGE_METADATA_MEASURED",
        "source": "GitLab image pinned at OCI digest in experimental harness",
        "image_config_yaml_files": len(files),
        "image_rule_stats": image,
        "file_header_licenses": licenses,
        "rule_metadata_license_declarations": per_rule_licenses,
        "files_with_parse_errors": len(parse_errors),
        "parse_error_types": dict(collections.Counter(parse_errors)),
        "license_disclaimer": "An image or file header is not proof of legal redistribution rights. No rules or source content is exported.",
        "coverage_disclaimer": "Rule counts/CWE labels do not establish quality of findings or equivalence.",
    }
    if BASELINE.exists():
        baseline_obj = parser.load(BASELINE.read_text(encoding="utf-8"))
        if not isinstance(baseline_obj, dict) or not isinstance(baseline_obj.get("rules"), list):
            raise ValueError("verified baseline is not a Semgrep rule bundle")
        approved = inventory(baseline_obj["rules"])
        if approved["rule_objects"] != 225:
            raise ValueError("verified Semgrep baseline count is not 225")
        missing_languages = sorted(set(approved["languages"]) - set(image["languages"]))
        missing_labels = {
            lang: sorted(set(values) - set(image["cwe_labels_by_language"].get(lang, [])), key=int)
            for lang, values in approved["cwe_labels_by_language"].items()
            if set(values) - set(image["cwe_labels_by_language"].get(lang, []))
        }
        result["approved_reference"] = {
            "verified": True,
            "rules": approved["rule_objects"],
            "languages": approved["languages"],
            "cwe_label_counts_by_language": approved["cwe_label_counts_by_language"],
        }
        result["comparison"] = {
            "missing_languages": missing_languages,
            "baseline_cwe_labels_missing_for_same_language": missing_labels,
            "no_equivalence_claim": True,
        }
        result["status"] = "COMPARED_WITH_APPROVED_BASELINE"
    else:
        result["approved_reference"] = {"verified": False, "reason": "exact reviewed SHA not served"}
    OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    if parse_errors or not rules:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
