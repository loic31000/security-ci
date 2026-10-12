#!/usr/bin/env python3
"""Validate *claimed* release-readiness evidence, never create tags or releases.

Evidence must be collected from actual GitHub run URLs, not fabricated. This
validator checks completeness/consistency, not the authenticity of API data.
"""
import argparse
import json
import re
import sys
from pathlib import Path

EXPECTED_CHECKS = frozenset((
    "Audit - semgrep", "Audit - trivy", "Audit - gitleaks", "Audit - zizmor",
    "ShellCheck - Bash scripts", "actionlint - GitHub Actions syntax and expressions",
    "Maintainability - duplication and Python metrics", "Tests du projet et couverture",
    "reports", "Resolved dependencies - Python, Node and Go",
))
SCANNERS = frozenset(("semgrep", "gitleaks", "zizmor", "jscpd", "trivy"))
BENIGN = frozenset(("semgrep", "gitleaks", "zizmor", "jscpd"))
EXTERNAL_JOBS = frozenset(("semgrep", "trivy", "gitleaks", "zizmor", "go_tests"))
EXTERNAL_REPORTS = frozenset(("semgrep", "trivy", "gitleaks", "zizmor"))
SHA_RE = re.compile(r"^[a-f0-9]{40}$")
STABILITY_RUN_PREFIX = "https://github.com/loic31000/security-ci/actions/runs/"


def stability_issues(runs, commit):
    """Require independently executed, first-attempt audit runs on this commit."""
    if not isinstance(runs, list) or len(runs) < 3:
        return ["at least three independent first-attempt Security Audit runs are required"]
    issues = []
    urls = set()
    for run in runs:
        if not isinstance(run, dict):
            issues.append("malformed Security Audit stability evidence")
            continue
        url = run.get("url")
        if (not isinstance(url, str)
                or not url.startswith(STABILITY_RUN_PREFIX)
                or not url[len(STABILITY_RUN_PREFIX):].isdigit()):
            issues.append("invalid Security Audit stability run URL")
        elif url in urls:
            issues.append("duplicate Security Audit stability run")
        else:
            urls.add(url)
        if run.get("commit") != commit:
            issues.append("stability run does not match release candidate commit")
        if type(run.get("attempt")) is not int or run["attempt"] != 1:
            issues.append("stability run required a retry")
        if run.get("conclusion") != "success" or run.get("semgrep") != "success":
            issues.append("Security Audit or Semgrep was not successful")
    return issues


def validate(evidence):
    if not isinstance(evidence, dict):
        raise ValueError("release evidence must be an object")
    issues = []
    ref = evidence.get("security_ci_commit")
    issues.extend(stability_issues(evidence.get("stability_runs"), ref))
    if not isinstance(ref, str) or not SHA_RE.fullmatch(ref):
        issues.append("missing reviewed 40-character security-ci commit SHA")
    checks = evidence.get("checks")
    if not isinstance(checks, dict) or not EXPECTED_CHECKS.issubset(checks):
        issues.append("some of the ten required GitHub checks are absent")
    elif any(checks[name] != "success" for name in EXPECTED_CHECKS):
        issues.append("at least one GitHub check is not successful")
    if type(evidence.get("junit_cases")) is not int or evidence["junit_cases"] < 58:
        issues.append("fewer than 58 freshly validated JUnit cases")
    coverage = evidence.get("engine_coverage")
    if not isinstance(coverage, dict) or (
        not isinstance(coverage.get("targets"), list)
        or set(coverage["targets"]) != {"python", "node", "go"}
        or coverage.get("state") != "SCANNED"
    ):
        issues.append("incomplete Python/Node/Go dependency scanner coverage")
    if type(evidence.get("sbom_components")) is not int or evidence["sbom_components"] < 1:
        issues.append("no validated nonempty CycloneDX SBOM")
    positive = evidence.get("positive_controls")
    if not isinstance(positive, dict) or any(positive.get(name) is not True for name in SCANNERS):
        issues.append("positive detection control missing")
    negative = evidence.get("benign_controls")
    if not isinstance(negative, dict) or any(negative.get(name) is not True for name in BENIGN):
        issues.append("benign negative control missing")
    trial = evidence.get("external_trial")
    if not isinstance(trial, dict) or (
        trial.get("repo") != "loic31000/local-agents"
        or trial.get("branch") in (None, "", "main", "master")
        or not str(trial.get("branch", "")).startswith("audit/security-ci-")
        or trial.get("status") != "success"
        or trial.get("merged") is not False
        or not isinstance(trial.get("commit"), str)
        or not SHA_RE.fullmatch(trial["commit"])
    ):
        issues.append("successful unmerged isolated local-agents trial not evidenced")
    # A green string is insufficient: GitHub can fail before assigning a runner.
    # These fields must be copied from job metadata and reviewed artifacts.
    if isinstance(trial, dict):
        if trial.get("security_ci_ref") != ref:
            issues.append("external trial does not pin the reviewed security-ci commit")
        jobs = trial.get("executed_jobs")
        if not isinstance(jobs, dict):
            issues.append("missing external GitHub jobs execution evidence")
        else:
            for name in EXTERNAL_JOBS:
                job = jobs.get(name)
                if not isinstance(job, dict) or (
                    job.get("conclusion") != "success"
                    or not isinstance(job.get("runner_name"), str)
                    or not job["runner_name"].strip()
                    or type(job.get("steps_executed")) is not int
                    or job["steps_executed"] < 1
                ):
                    issues.append(f"external {name} job lacks executed steps and an assigned runner")
        for name in ("go_tests_passed", "trivy_targets"):
            value = trial.get(name)
            if type(value) is not int or value < 1:
                issues.append(f"external trial missing real nonzero {name}")
        reports = trial.get("reports_verified")
        if not isinstance(reports, dict) or any(
            reports.get(name) is not True for name in EXTERNAL_REPORTS
        ):
            issues.append("external scanner reports missing or not reviewed")

    for name in ("security_ci_run_url", "tests_run_url", "engine_run_url", "external_run_url"):
        repo = "local-agents" if name == "external_run_url" else "security-ci"
        prefix = f"https://github.com/loic31000/{repo}/actions/runs/"
        url = evidence.get(name, "")
        if not isinstance(url, str) or not url.startswith(prefix) or not url[len(prefix):].isdigit():
            issues.append(f"missing valid {repo} GitHub evidence URL: {name}")
    if evidence.get("human_cve_reviewed") is not True:
        issues.append("open CVE candidates have not been triaged by a human")
    return issues


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    try:
        data = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
        issues = validate(data)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"Release candidate evidence unavailable: {exc}")
        return 1
    if issues:
        for issue in issues:
            print(f"NOT READY: {issue}")
        return 1
    print("Release readiness evidence is complete; confirm GitHub URLs and artifact authenticity manually before tagging.")
    print("This script never publishes, tags, or changes any repository.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
