#!/usr/bin/env python3
"""Ephemeral GitLab analyzer image test; no third-party rules are redistributed."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

TAG = "registry.gitlab.com/security-products/semgrep:6"
PREFIX = "registry.gitlab.com/security-products/semgrep@sha256:"
ROOT = Path(os.environ["RUNNER_TEMP"]) / "gitlab-oci-test"
ROOT.mkdir(parents=True, exist_ok=True)
EVIDENCE = ROOT / "evidence.json"


def run(cmd, timeout=300):
    start = time.monotonic()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("command failed: " + str(cmd[0]) + " exit=" +
                           str(result.returncode) + " stderr_tail=" +
                           result.stderr[-500:].replace("\n", " "))
    return result.stdout.strip(), round(time.monotonic() - start, 1)


def container(ref, entry, args, mounts=(), timeout=300):
    cmd = ["docker", "run", "--rm", "--pull", "never",
           "--user", str(os.getuid()) + ":" + str(os.getgid()),
           "--network", "none", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges",
           "--pids-limit", "256", "--memory", "4g", "--cpus", "2",
           "--tmpfs", "/tmp:rw,nosuid,size=1g",
           "--tmpfs", "/root/.cache:rw,nosuid,size=256m",
           "--tmpfs", "/.cache:rw,nosuid,size=256m",
           "-e", "SEMGREP_SEND_METRICS=off", "-e", "HOME=/tmp"]
    for src, dst, mode in mounts:
        mount = "type=bind,src=" + str(src) + ",dst=" + dst
        if mode == "readonly":
            mount += ",readonly"
        cmd += ["--mount", mount]
    return run(cmd + ["--entrypoint", entry, ref] + args, timeout)


def count_json(path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc.get("results"), list) or doc.get("errors"):
        raise RuntimeError("invalid or error-filled JSON scan report")
    return len(doc["results"])


def count_sarif(path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    runs = doc.get("runs")
    if doc.get("version") != "2.1.0" or not isinstance(runs, list) or not runs:
        raise RuntimeError("missing SARIF 2.1.0 runs")
    if any(not isinstance(r.get("results"), list) or
           not isinstance(r.get("tool", {}).get("driver", {}).get("name"), str)
           for r in runs):
        raise RuntimeError("incomplete SARIF result or scanner identity")
    return sum(len(r["results"]) for r in runs)


def smoke():
    positive, benign, reports = (ROOT / "positive", ROOT / "benign", ROOT / "reports")
    for folder in (positive, benign, reports):
        folder.mkdir(exist_ok=True)
    output = {"status": "NOT_TESTED", "image_discovery_tag": TAG,
              "approved_for_release": False, "scan_network": "none"}
    try:
        _, seconds = run(["docker", "pull", TAG], timeout=900)
        output["anonymous_pull"] = True
        output["pull_seconds"] = seconds
        raw, _ = run(["docker", "image", "inspect", TAG, "--format", "{{json .RepoDigests}}"])
        refs = [ref for ref in json.loads(raw) if ref.startswith(PREFIX)
                and re.fullmatch("[a-f0-9]{64}", ref[len(PREFIX):])]
        if len(refs) != 1:
            raise RuntimeError("no unique OCI digest for the official image")
        ref = refs[0]
        output["resolved_digest"] = ref.split("@", 1)[1]
        nbytes, _ = run(["docker", "image", "inspect", TAG, "--format", "{{.Size}}"])
        output["image_size_bytes"] = int(nbytes)
        shell = ('test -d /rules && '
                 'echo files=$(find /rules -type f | wc -l) && '
                 'echo yamls=$(find /rules -type f \\( -name "*.yaml" -o -name "*.yml" \\) | wc -l) && '
                 'echo version=$SAST_RULES_VERSION && semgrep --version')
        probe, _ = container(ref, "sh", ["-ec", shell], timeout=120)
        pairs = dict(line.split("=", 1) for line in probe.splitlines()
                     if line.count("=") == 1)
        output["rule_files"] = int(pairs["files"])
        output["yaml_files"] = int(pairs["yamls"])
        output["packaged_rules_version"] = pairs.get("version")
        output["semgrep_version"] = probe.splitlines()[-1]
        if output["yaml_files"] < 1:
            raise RuntimeError("no local YAML rules")
        (positive / "unsafe.py").write_text(
            "def unsafe(user_input):\n    return eval(user_input)\n", encoding="utf-8")
        (positive / "unsafe.js").write_text(
            "function unsafe(user) { return eval(user); }\n", encoding="utf-8")
        (benign / "safe.py").write_text(
            "def total(values):\n    return sum(values)\n", encoding="utf-8")
        (benign / "safe.js").write_text(
            "function safe(text) { return JSON.parse(text); }\n", encoding="utf-8")
        def scan(folder, fmt, name):
            args = ["scan", "--config", "/rules", "--metrics", "off",
                    "--disable-version-check", "--jobs", "1", "--timeout", "15",
                    "--" + fmt, "--output", "/reports/" + name, "/scan"]
            _, duration = container(ref, "semgrep", args, mounts=(
                (folder, "/scan", "readonly"), (reports, "/reports", "rw")),
                timeout=360)
            output[name + "_seconds"] = duration
            file = reports / name
            if not file.is_file():
                raise RuntimeError("scan did not produce " + name)
            return file
        positives = count_json(scan(positive, "json", "positives.json"))
        negatives = count_json(scan(benign, "json", "benign.json"))
        sarif = count_sarif(scan(positive, "sarif", "positives.sarif"))
        output.update({"positive_findings": positives, "benign_findings": negatives,
                       "sarif_findings": sarif, "sarif_valid": True,
                       "json_sarif_parity": positives == sarif})
        output["status"] = (
            "SMOKE_PASS" if positives >= 2 and negatives == 0 and positives == sarif
            else "DETECTION_OR_FALSE_POSITIVE_GAP"
        )
    except Exception as exc:
        output["status"] = "TEST_FAILED"
        output["error"] = str(exc)[:950]
    finally:
        EVIDENCE.write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(json.dumps(output, indent=2))
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as dest:
                dest.write("\n### Experimental GitLab Semgrep container\n\n")
                dest.write("Not approved for production. All scans use network=none and the resolved OCI digest.\n\n")
                for key in ("status", "anonymous_pull", "resolved_digest",
                            "image_size_bytes", "rule_files", "yaml_files",
                            "packaged_rules_version", "semgrep_version",
                            "positive_findings", "benign_findings",
                            "sarif_findings", "json_sarif_parity"):
                    if key in output:
                        dest.write("- " + key + ": " + str(output[key]) + "\n")
                dest.write("\nThe digest is discovered during this test, not yet source-pinned or reviewed.\n")
                dest.write("No parity with 225 Semgrep rules or redistribution rights has been shown.\n")
    return 0 if output["status"] == "SMOKE_PASS" else 1


if __name__ == "__main__":
    sys.exit(smoke())
