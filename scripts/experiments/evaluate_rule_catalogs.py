#!/usr/bin/env python3
"""Isolated Semgrep ruleset qualification. Never downloads or republishes rule content.

This experiment is NOT an approval to migrate production scanners.
"""
import collections
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from ruamel.yaml import YAML

YAML_PARSER = YAML(typ="safe")
SOURCES = (
    ("qodana", Path(os.environ["RUNNER_TEMP"]) / "candidate-qodana"),
    ("0xdea", Path(os.environ["RUNNER_TEMP"]) / "candidate-0xdea"),
)
EXPECTED_SHA = {
    "qodana": "19af7ed20926ed0b1666e5f78722d4c0824ba99a",
    "0xdea": "dae50da6e6e629750f1daec73a01ef9206a372ab",
}
FIXTURES = (
    ("qodana", "python/eval/rule-eval.yml", "python_eval_rule-eval", "py",
     "def unsafe(user):\n    return eval(user)\n",
     "def safe(user):\n    return sum([1, 2])\n"),
    ("qodana", "python/exec/rule-exec-used.yml", "python_exec_rule-exec-used", "py",
     "def unsafe(user):\n    exec(user)\n",
     "def safe(user):\n    print(user)\n"),
    ("qodana", "javascript/eval/rule-eval-with-expression.yml",
     "javascript_eval_rule-eval-with-expression", "js",
     "function unsafe(user) { return eval(user); }\n",
     "function safe(user) { return JSON.parse(user); }\n"),
    ("qodana", "go/subproc/rule-subproc.yml", "go_subproc_rule-subproc", "go",
     'package main\nimport "os/exec"\nfunc unsafe(user string) { exec.Command(user, "-v") }\n',
     'package main\nimport "os/exec"\nfunc safe() { exec.Command("echo", "hello") }\n'),
    ("0xdea", "rules/c/insecure-api-gets.yaml", "raptor-insecure-api-gets", "c",
     "#include <stdio.h>\nvoid unsafe(void) { char buf[128]; gets(buf); }\n",
     "#include <stdio.h>\nvoid safe(void) { char buf[128]; fgets(buf, sizeof(buf), stdin); }\n"),
)

def audit(source, root):
    observed = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if observed != EXPECTED_SHA[source]:
        raise RuntimeError("unapproved git revision: " + source + " " + observed)
    counts = collections.Counter()
    ids = collections.Counter()
    errors = []
    parsed = 0
    files = list(root.rglob("*.yml")) + list(root.rglob("*.yaml"))
    for file in files:
        if "/.github/" in str(file):
            continue
        relative = file.relative_to(root).as_posix()
        if source == "qodana" and (relative.startswith("rules/lgpl/") or relative.startswith("jetbrains/")):
            counts["excluded_nested_licences"] += 1
            continue
        head = "\n".join(file.read_text(errors="replace").splitlines()[:12])
        match = re.search(r"(?im)^#\s*License:\s*(.+)$", head)
        declaration = match.group(1).strip() if match else "UNDECLARED"
        if source == "qodana":
            if declaration.startswith("MIT"):
                bucket = "MIT_declared"
            elif declaration.startswith("Apache 2.0"):
                bucket = "APACHE_declared"
            elif declaration.startswith("GPL") or declaration.startswith("GNU"):
                bucket = "GPL_declared"
            else:
                bucket = "OTHER_or_undeclared"
        else:
            bucket = "MIT_root_repository" if relative.startswith("rules/") else "other"
        counts[bucket] += 1
        if "rule-" not in file.name and source == "qodana":
            continue
        try:
            doc = YAML_PARSER.load(file.read_text())
            rules = doc.get("rules") if isinstance(doc, dict) else None
            if not isinstance(rules, list) or not rules:
                raise ValueError("not a nonempty Semgrep rules mapping")
            for rule in rules:
                rid = rule.get("id") if isinstance(rule, dict) else None
                if not isinstance(rid, str) or not rid:
                    raise ValueError("missing rule ID")
                ids[rid] += 1
            parsed += 1
        except Exception as exc:
            errors.append(relative + ": " + type(exc).__name__)
    duplicates = sum(count > 1 for count in ids.values())
    return {
        "git_sha": observed, "yaml_files": len(files), "license_file_counts": dict(counts),
        "parseable_rule_files": parsed, "unique_rule_ids": len(ids),
        "duplicate_ids": duplicates, "malformed_rule_files": len(errors),
        "sample_parse_errors": errors[:5],
    }

def run_fixture(name, rule_file, expected_id, ext, positive, negative, tmp):
    outcomes = {}
    for kind, code in (("positive", positive), ("negative", negative)):
        dest = tmp / (name + "-" + kind + "." + ext)
        result_path = tmp / (name + "-" + kind + ".json")
        dest.write_text(code, encoding="utf-8")
        command = [
            "semgrep", "scan", "--config", str(rule_file),
            "--disable-version-check", "--metrics", "off",
            "--json", "--output", str(result_path), str(dest),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=80)
        if completed.returncode != 0 or not result_path.is_file():
            outcomes[kind] = {"error": "scan_failed", "exit_code": completed.returncode,
                              "stderr_tail": completed.stderr[-240:]}
            continue
        report = json.loads(result_path.read_text())
        results = report.get("results")
        failures = report.get("errors", [])
        if not isinstance(results, list) or failures:
            outcomes[kind] = {"error": "invalid_or_error_report", "error_count": len(failures)}
            continue
        matches = [x for x in results if x.get("check_id", "").endswith(expected_id)]
        outcomes[kind] = {"findings": len(results), "target_rule_findings": len(matches),
                          "valid": bool(matches) if kind == "positive" else len(results) == 0}
    return outcomes

def main():
    problems = []
    report = {"engine": "semgrep==1.179.0", "sources": {}, "fixture_results": {}}
    for name, root in SOURCES:
        try:
            report["sources"][name] = audit(name, root)
        except Exception as exc:
            problems.append(name + ": unable to audit source: " + str(exc))
    with tempfile.TemporaryDirectory() as path:
        temp = Path(path)
        for i, (source, relative, rid, ext, positive, negative) in enumerate(FIXTURES):
            rule = dict(SOURCES)[source] / relative
            label = source + "/" + rid
            if not rule.is_file():
                problems.append("missing selected rule " + label)
                continue
            # Root MIT is NOT sufficient for derived GitLab rules: a per-file declaration is required.
            if source == "qodana":
                license_header = "\n".join(rule.read_text().splitlines()[:12])
                if not re.search(r"(?im)^#\s*License:\s*(MIT|Apache 2\.0)\b", license_header):
                    problems.append("review licence before using " + label)
                    continue
            outcomes = run_fixture("fixture" + str(i), rule, rid, ext, positive, negative, temp)
            report["fixture_results"][label] = outcomes
            if not all(outcomes.get(k, {}).get("valid") is True for k in ("positive", "negative")):
                problems.append("canary failure: " + label)
    for name, source in report["sources"].items():
        if source["duplicate_ids"] or source["malformed_rule_files"]:
            problems.append(name + " has duplicate IDs or malformed YAML")
    report["status"] = "SMOKE_PASS" if not problems else "QUALIFICATION_FAILED"
    report["problems"] = problems
    print(json.dumps(report, indent=2))
    summary = [
        "### Étude expérimentale de catalogues Semgrep", "",
        "**Pas de décision de migration ni d'autorisation de redistribution.**", "",
        "Semgrep 1.179.0, dépôts Git épinglés à un commit exact.", "",
    ]
    for name, source in report["sources"].items():
        summary.append("- " + name + ": " + str(source["unique_rule_ids"]) +
                       " identifiants uniques, " + str(source["malformed_rule_files"]) +
                       " fichiers invalides, licences déclarées " +
                       str(source["license_file_counts"]))
    for name, outcomes in report["fixture_results"].items():
        summary.append("- " + name + ": " +
                       ("PASS" if all(item.get("valid") for item in outcomes.values()) else "FAIL") +
                       " (positif " + str(outcomes.get("positive", {}).get("findings", "ERREUR")) +
                       ", bénin " + str(outcomes.get("negative", {}).get("findings", "ERREUR")) + ")")
    summary.extend(["", "**État : " + report["status"] + "**",
                    "Ces tests limités ne prouvent pas l'équivalence aux 225 règles Semgrep officielles.",
                    "Aucun catalogue de règles n'est archivé ni publié."])
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as target:
        target.write("\n".join(summary) + "\n")
    Path(os.environ["RUNNER_TEMP"], "catalog-qualification.json").write_text(json.dumps(report, indent=2))
    return 1 if problems else 0

if __name__ == "__main__":
    sys.exit(main())
