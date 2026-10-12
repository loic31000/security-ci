#!/usr/bin/env python3
"""Compare pinned GitLab source bytes with a pinned derived mirror.

Does not extract an untrusted tarball, archive rule content, or approve licenses.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tarfile

from ruamel.yaml import YAML

PARSER = YAML(typ="safe")

GITLAB_SHA = "39fc7de205d447c70e75a1fdabdcf4588733adc8"
MIRROR_SHA = "19af7ed20926ed0b1666e5f78722d4c0824ba99a"
ROOT = Path(os.environ["RUNNER_TEMP"])
ARCHIVE = ROOT / "gitlab-official.tar.gz"
MIRROR = ROOT / "candidate-qodana"

def declared_license(data):
    head = "\n".join(data.decode("utf-8", errors="replace").splitlines()[:12])
    found = re.search(r"(?im)^#\s*License:\s*(.+)$", head)
    return found.group(1).strip() if found else "UNDECLARED"

def sha(data):
    return hashlib.sha256(data).hexdigest()

def changed_fields(left, right, prefix="root", limit=20):
    """Only structural key paths, never rule text or IDs."""
    if type(left) is not type(right):
        return [prefix + ":type"]
    if isinstance(left, dict):
        changes = []
        for key in set(left) | set(right):
            if key not in left or key not in right:
                changes.append(prefix + "." + str(key) + ":presence")
            else:
                changes.extend(changed_fields(left[key], right[key], prefix + "." + str(key)))
            if len(changes) >= limit:
                break
        return changes[:limit]
    if isinstance(left, list):
        if len(left) != len(right):
            return [prefix + ":length"]
        changes = []
        for i, (a, b) in enumerate(zip(left, right)):
            changes.extend(changed_fields(a, b, prefix + "[" + str(i) + "]"))
            if len(changes) >= limit:
                break
        return changes[:limit]
    return [prefix] if left != right else []


def compare():
    index = {}
    with tarfile.open(ARCHIVE, "r:gz") as bundle:
        for member in bundle:
            if not member.isfile() or member.size > 1024 * 1024:
                continue
            name = member.name.split("/", 1)
            if len(name) != 2:
                continue
            rel = name[1]
            if rel.startswith("/") or ".." in Path(rel).parts or not rel.endswith((".yml", ".yaml")):
                continue
            stream = bundle.extractfile(member)
            if stream is None:
                continue
            index[rel] = stream.read()
    statuses = {"exact": 0, "modified": 0, "missing": 0}
    examples = {"modified": [], "missing": []}
    by_license = {}
    mismatches = []
    upstream_license_mismatches = 0
    for file in sorted(MIRROR.rglob("*.yml")) + sorted(MIRROR.rglob("*.yaml")):
        rel = file.relative_to(MIRROR).as_posix()
        if rel.startswith(("rules/", "jetbrains/", ".github/")):
            continue
        local = file.read_bytes()
        licence = declared_license(local)
        if not (licence.startswith("MIT") or licence.startswith("Apache 2.0")):
            continue
        category = "MIT" if licence.startswith("MIT") else "Apache-2.0"
        if rel not in index:
            status = "missing"
        elif sha(local) == sha(index[rel]):
            status = "exact"
        else:
            status = "modified"
        if rel in index and declared_license(index[rel]) != licence:
            upstream_license_mismatches += 1
        if status == "modified":
            try:
                left_doc = PARSER.load(local.decode("utf-8"))
                right_doc = PARSER.load(index[rel].decode("utf-8"))
                mismatches.append({
                    "path": rel, "semantically_identical": left_doc == right_doc,
                    "changed_field_paths": changed_fields(left_doc, right_doc),
                })
            except Exception as e:
                mismatches.append({"path": rel, "cannot_parse": type(e).__name__})
        statuses[status] += 1
        by_license.setdefault(category, {"exact": 0, "modified": 0, "missing": 0})[status] += 1
        if status in examples and len(examples[status]) < 8:
            examples[status].append(rel)
    total = sum(statuses.values())
    return {
        "gitlab_upstream_commit": GITLAB_SHA,
        "qodana_mirror_commit": MIRROR_SHA,
        "upstream_rule_yaml_files": len(index),
        "qodana_mit_apache_candidates": total,
        "byte_comparison": statuses,
        "by_declared_license": by_license,
        "sample_paths": examples,
        "mismatch_diagnostics": mismatches,
        "upstream_license_header_mismatches": upstream_license_mismatches,
        "all_bytes_equal_to_upstream": total > 0 and statuses["exact"] == total,
        "limits": "Exact paths and byte hashes only; no legal determination or equality to Semgrep Registry's 225-rule bundle.",
    }

if __name__ == "__main__":
    try:
        output = compare()
        report = ROOT / "catalog-provenance.json"
        report.write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(json.dumps(output, indent=2))
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write("### Provenance of MIT/Apache candidate rules\n\n")
            f.write(f"Official pinned GitLab revision: {GITLAB_SHA}\n\n")
            for status, count in output["byte_comparison"].items():
                f.write(f"- {status}: {count}\n")
            f.write("\n**Not a copyright clearance or proof of equivalent security coverage.**\n")
    except Exception as exc:
        print("Cannot verify pinned GitLab provenance: " + type(exc).__name__ + ": " + str(exc))
        sys.exit(1)
