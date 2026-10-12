#!/usr/bin/env python3
"""Reproduce GitLab-authored Semgrep rule tests using the pinned source archive.

This never runs program fixtures, republishes third-party rule contents,
or modifies the production Security Audit workflow.
"""
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

from ruamel.yaml import YAML

ROOT = Path(os.environ["RUNNER_TEMP"])
ARCHIVE = ROOT / "gitlab-official.tar.gz"
EXPECTED_ARCHIVE_SHA = "39fc7de205d447c70e75a1fdabdcf4588733adc8"
LANGUAGES = {
    "python": (".py",),
    "go": (".go",),
    "javascript": (".js", ".ts"),
    "csharp": (".cs",),
    "scala": (".scala",),
}
PER_LANGUAGE = 5
SAFE_LICENSE = re.compile(rb"(?im)^#\s*License:\s*(MIT|Apache 2\.0)\b")
RULE_ANN = re.compile(r"(?m)^\s*(?:#|//)\s*ruleid:\s*([a-zA-Z0-9_.-]+)")
OK_ANN = re.compile(r"(?m)^\s*(?:#|//)\s*ok:\s*([a-zA-Z0-9_.-]+)")
PARSER = YAML(typ="safe")


def upstream_files():
    result = {}
    with tarfile.open(ARCHIVE, "r:gz") as archive:
        for member in archive:
            if not member.isfile() or member.size > 2_000_000:
                continue
            parts = member.name.split("/", 1)
            if len(parts) != 2:
                continue
            name = parts[1]
            if name.startswith("/") or ".." in Path(name).parts:
                continue
            if name.endswith((".yml", ".yaml", ".py", ".go", ".js", ".ts", ".cs", ".scala")):
                stream = archive.extractfile(member)
                if stream:
                    result[name] = stream.read()
    return result


def select(files):
    by_lang = collections.Counter()
    selected = []
    counts = {"no_positive_and_negative": 0, "not_clearly_permissive": 0,
              "no_paired_test_file": 0, "invalid_rule_document": 0}
    for name in sorted(files):
        if not (name.endswith((".yaml", ".yml")) and Path(name).name.startswith("rule-")):
            continue
        language = name.split("/", 1)[0]
        if language not in LANGUAGES or by_lang[language] >= PER_LANGUAGE:
            continue
        data = files[name]
        if not SAFE_LICENSE.search(b"\n".join(data.splitlines()[:12])):
            counts["not_clearly_permissive"] += 1
            continue
        try:
            doc = PARSER.load(data.decode("utf-8"))
            rule_list = doc["rules"]
            if len(rule_list) != 1:
                raise ValueError("not one rule")
            rule_id = rule_list[0]["id"]
            if not isinstance(rule_id, str) or not rule_id:
                raise ValueError("missing ID")
        except Exception:
            counts["invalid_rule_document"] += 1
            continue
        stem = str(Path(name).with_suffix(""))
        sibling = None
        for ext in LANGUAGES[language]:
            for candidate in (stem + ext,
                              str(Path(name).with_name(Path(name).name.replace("rule-", "test-", 1))).rsplit(".", 1)[0] + ext):
                if candidate in files:
                    sibling = candidate
                    break
            if sibling:
                break
        if sibling is None:
            counts["no_paired_test_file"] += 1
            continue
        code = files[sibling].decode("utf-8", errors="replace")
        positives = [x for x in RULE_ANN.findall(code) if x == rule_id]
        negatives = [x for x in OK_ANN.findall(code) if x == rule_id]
        if not positives or not negatives:
            counts["no_positive_and_negative"] += 1
            continue
        selected.append((name, sibling, rule_id, len(positives), len(negatives)))
        by_lang[language] += 1
    return selected, counts


def test():
    files = upstream_files()
    picked, skipped = select(files)
    langs = collections.Counter(x[0].split("/", 1)[0] for x in picked)
    result = {
        "source_commit": EXPECTED_ARCHIVE_SHA,
        "engine": "semgrep 1.179.0",
        "upstream_files_indexed": len(files),
        "selected_rule_pairs": len(picked),
        "languages": dict(langs),
        "positive_annotations": sum(x[3] for x in picked),
        "negative_annotations": sum(x[4] for x in picked),
        "skipped": skipped,
        "individual_rules_tested": False,
    }
    if len(picked) < 12 or len(langs) < 4:
        result["status"] = "INSUFFICIENT_TEST_FIXTURES"
        return result

    with tempfile.TemporaryDirectory() as location:
        target = Path(location) / "test-cases"
        for name, sibling, _, _, _ in picked:
            basename = Path(name).stem
            suffix = Path(sibling).suffix
            rule_target = target / name
            rule_target.parent.mkdir(parents=True, exist_ok=True)
            rule_target.write_bytes(files[name])
            # Semgrep test runner pairs files sharing the rule basename.
            (rule_target.parent / (basename + suffix)).write_bytes(files[sibling])
        command = ["semgrep", "--metrics=off", "--test", str(target)]
        try:
            done = subprocess.run(command, capture_output=True, text=True, timeout=240)
            result["exit_code"] = done.returncode
            result["stdout_sha256"] = hashlib.sha256(done.stdout.encode()).hexdigest()
            result["stderr_sha256"] = hashlib.sha256(done.stderr.encode()).hexdigest()
            result["status"] = "PASS" if done.returncode == 0 else "UPSTREAM_FIXTURE_FAILURE"
            # No code, rule text, or third-party findings in logs/artifacts.
        except subprocess.TimeoutExpired:
            result["status"] = "TIMEOUT"
    return result


if __name__ == "__main__":
    try:
        report = test()
    except Exception as exc:
        report = {"status": "ERROR", "error_type": type(exc).__name__}
    target = ROOT / "official-author-fixtures.json"
    target.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
        f.write("\n### Pinned upstream annotated rule tests\n\n")
        f.write(f"- Pairs: {report.get('selected_rule_pairs', 'unknown')}\n")
        f.write(f"- Positive annotated examples: {report.get('positive_annotations', 'unknown')}\n")
        f.write(f"- Negative annotated examples: {report.get('negative_annotations', 'unknown')}\n")
        f.write(f"- Outcome: **{report['status']}**\n")
        f.write("No fixture code or third-party rule text is published.\n")
    sys.exit(0 if report["status"] == "PASS" else 1)
