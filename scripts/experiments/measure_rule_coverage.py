#!/usr/bin/env python3
"""Measure language/CWE inventory of pinned candidate rules without publishing rule content.

Descriptive metadata audit, not an assertion of true detection coverage.
"""
import collections
import json
import os
from pathlib import Path
import re
import tarfile

from ruamel.yaml import YAML

TEMP = Path(os.environ["RUNNER_TEMP"])
OFFICIAL_SHA = "39fc7de205d447c70e75a1fdabdcf4588733adc8"
MIRROR_SHA = "19af7ed20926ed0b1666e5f78722d4c0824ba99a"
EXTERNAL_SHA = "dae50da6e6e629750f1daec73a01ef9206a372ab"
YAML_PARSER = YAML(typ="safe")
PERMISSIVE = re.compile(r"(?im)^#\s*License:\s*(MIT|Apache 2\.0)\b")
CWE = re.compile(r"(?i)\bCWE[-_\s:]*(\d{1,4})\b")


def official_files():
    files = {}
    with tarfile.open(TEMP / "gitlab-official.tar.gz", "r:gz") as bundle:
        for member in bundle:
            if not member.isfile() or member.size > 1_000_000:
                continue
            parts = member.name.split("/", 1)
            if len(parts) != 2 or ".." in Path(parts[1]).parts:
                continue
            if not parts[1].endswith((".yml", ".yaml")):
                continue
            stream = bundle.extractfile(member)
            if stream:
                files[parts[1]] = stream.read().decode("utf-8")
    return files


def permissive_header(source):
    match = PERMISSIVE.search("\n".join(source.splitlines()[:12]))
    return match.group(1) if match else None


def parse_rules(source):
    obj = YAML_PARSER.load(source)
    if not isinstance(obj, dict) or not isinstance(obj.get("rules"), list):
        raise ValueError("not a Semgrep rules list")
    return obj["rules"]


def rules_inventory(rules):
    languages = collections.Counter()
    weak_count = collections.Counter()
    annotated = collections.Counter()
    per_language_cwe = collections.defaultdict(set)
    unique_ids = set()
    duplicated = 0
    total_no_cwe = 0
    total_no_language = 0
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            raise ValueError("bad rule mapping")
        rid = rule["id"]
        if rid in unique_ids:
            duplicated += 1
        unique_ids.add(rid)
        langs = set(rule.get("languages", []))
        metadata = rule.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {}
        raw_cwe = metadata.get("cwe", [])
        if isinstance(raw_cwe, str):
            raw_cwe = [raw_cwe]
        if not isinstance(raw_cwe, (list, tuple)):
            raw_cwe = []
        identifiers = set()
        for value in raw_cwe:
            identifiers.update(CWE.findall(str(value)))
        if not identifiers:
            total_no_cwe += 1
        if not langs:
            total_no_language += 1
        for lang in langs:
            languages[lang] += 1
            per_language_cwe[lang].update(identifiers)
        for n in identifiers:
            weak_count["CWE-" + n] += 1
        severity = str(metadata.get("security-severity", "")).lower()
        if severity:
            annotated[severity] += 1

    return {
        "rules": len(rules),
        "unique_rule_ids": len(unique_ids),
        "duplicate_ids": duplicated,
        "rules_without_cwe_metadata": total_no_cwe,
        "rules_without_language": total_no_language,
        "rules_by_language": dict(sorted(languages.items())),
        "distinct_cwe_per_language": {k: len(v) for k, v in sorted(per_language_cwe.items())},
        "total_distinct_cwe": len(weak_count),
        "top_cwe_by_rule_count": dict(weak_count.most_common(12)),
        "metadata_severity": dict(annotated),
    }


def main():
    upstream = official_files()
    mirror = TEMP / "candidate-qodana"
    external = TEMP / "candidate-0xdea"
    upstream_permissive = {
        name: source for name, source in upstream.items()
        if name.startswith(tuple(lang + "/" for lang in ("c", "csharp", "go", "java", "javascript", "python", "scala", "php", "ruby", "rust", "swift", "kotlin", "typescript")))
        and permissive_header(source)
    }
    # The experimental evaluator uses precisely 210 paths selected via pinned
    # Qodana and replaces their bytes with those from the official GitLab archive.
    selected_paths = set()
    for file in mirror.rglob("*.yml"):
        rel = file.relative_to(mirror).as_posix()
        if rel.startswith(("rules/", "jetbrains/")):
            continue
        if permissive_header(file.read_text(encoding="utf-8")):
            selected_paths.add(rel)

    missing = selected_paths - set(upstream_permissive)
    if missing:
        raise ValueError("missing official allowed rules: " + str(len(missing)))
    gitlab_rules = [rule for p in sorted(selected_paths) for rule in parse_rules(upstream_permissive[p])]

    extra_dirs = collections.Counter()
    extra_license = collections.Counter()
    for p, source in upstream_permissive.items():
        if p not in selected_paths:
            extra_dirs[p.split("/", 1)[0]] += 1
            extra_license[permissive_header(source)] += 1

    external_rules = []
    for file in sorted((external / "rules" / "c").glob("*.yaml")):
        for rule in parse_rules(file.read_text(encoding="utf-8")):
            if "vuln" in ((rule.get("metadata") or {}).get("subcategory") or []):
                external_rules.append(rule)
    profile = rules_inventory(gitlab_rules + external_rules)
    gitlab = rules_inventory(gitlab_rules)
    independent = rules_inventory(external_rules)

    assert profile["rules"] == 238 and profile["duplicate_ids"] == 0, "profile drift"
    assert gitlab["rules"] == 210 and independent["rules"] == 28, "unexpected source split"

    output = {
        "upstream_commit": OFFICIAL_SHA,
        "mirror_commit": MIRROR_SHA,
        "external_commit": EXTERNAL_SHA,
        "candidate": profile,
        "gitlab": gitlab,
        "0xdea": independent,
        "potentially_permissive_official_rules_not_in_candidate": {
            "file_count": sum(extra_dirs.values()),
            "by_language_directory": dict(sorted(extra_dirs.items())),
            "by_license_claim": dict(extra_license),
        },
        "disclaimer": "Rule metadata and count are NOT evidence of CWE detection coverage, precision, recall, or license clearance. No original Semgrep profile inventory is available for parity.",
    }
    (TEMP / "candidate-coverage-matrix.json").write_text(json.dumps(output, indent=2))
    print(json.dumps(output, indent=2))
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
        f.write("\n### Original GitLab candidate: language/CWE metadata inventory\n\n")
        f.write(f"- Selected original GitLab rules: {gitlab['rules']}\n")
        f.write(f"- Selected 0xdea C/C++ rules: {independent['rules']}\n")
        f.write(f"- Rule records without CWE metadata: {profile['rules_without_cwe_metadata']}\n")
        f.write(f"- Distinct claimed CWEs: {profile['total_distinct_cwe']}\n")
        for lang, count in profile["rules_by_language"].items():
            f.write(f"- {lang}: {count} rules, {profile['distinct_cwe_per_language'].get(lang, 0)} CWEs mentioned\n")
        f.write("The source Semgrep Registry 225-rule inventory is not available for a defensible parity claim.\n")


if __name__ == "__main__":
    main()
