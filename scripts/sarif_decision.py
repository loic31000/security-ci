#!/usr/bin/env python3
"""Fail-closed SARIF accounting: candidates are not confirmed vulnerabilities."""
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path


class InvalidSarif(ValueError):
    """Technical/reporting failure, never interpreted as a clean scan."""


@dataclass(frozen=True)
class Counts:
    candidate: int = 0
    suppressed: int = 0
    other: int = 0


def _obj(value, label):
    if not isinstance(value, dict):
        raise InvalidSarif(f"{label} must be an object")
    return value


def _list(value, label):
    if not isinstance(value, list):
        raise InvalidSarif(f"{label} must be an array")
    return value


def assess(document):
    """Count actionable scanner candidates without claiming to prove exploitation."""
    document = _obj(document, "SARIF document")
    if document.get("version") != "2.1.0":
        raise InvalidSarif("unsupported or missing SARIF version")
    runs = _list(document.get("runs"), "runs")
    if not runs:
        raise InvalidSarif("missing SARIF runs")
    candidate = suppressed = other = 0
    for run in runs:
        run = _obj(run, "run")
        driver = _obj(_obj(run.get("tool"), "tool").get("driver"), "driver")
        if not isinstance(driver.get("name"), str) or not driver["name"].strip():
            raise InvalidSarif("missing scanner identity")
        for invocation in _list(run.get("invocations", []), "invocations"):
            invocation = _obj(invocation, "invocation")
            # SARIF 2.1.0 requires this boolean for every provided invocation.
            # No invocations is still valid (e.g. Trivy and Gitleaks output).
            if invocation.get("executionSuccessful") is not True:
                raise InvalidSarif("scanner did not confirm successful execution")
            for name in ("toolExecutionNotifications", "toolConfigurationNotifications"):
                for note in _list(invocation.get(name, []), name):
                    if _obj(note, name + " entry").get("level") == "error":
                        raise InvalidSarif("scanner reported an execution or configuration error")
        results = _list(run.get("results"), "results")
        rules = _list(driver.get("rules", []), "rules")
        levels = {}
        for rule in rules:
            rule = _obj(rule, "rule")
            if isinstance(rule.get("id"), str):
                levels[rule["id"]] = _obj(rule.get("defaultConfiguration", {}), "defaultConfiguration").get("level")
        for result in results:
            result = _obj(result, "result")
            kind = result.get("kind", "fail")
            if kind not in ("fail", "pass", "review", "open", "informational", "notApplicable"):
                raise InvalidSarif("unknown result kind")
            level = result.get("level", levels.get(result.get("ruleId")) or "warning")
            if level not in ("error", "warning", "note", "none"):
                raise InvalidSarif("unknown result level")
            suppressions = result.get("suppressions")
            if suppressions is not None:
                _list(suppressions, "suppressions")
                for item in suppressions:
                    status = _obj(item, "suppression").get("status")
                    if status not in (None, "accepted", "underReview", "rejected"):
                        raise InvalidSarif("unknown suppression status")
            if kind != "fail" or level in ("note", "none"):
                other += 1
            elif suppressions and any(s.get("status") == "accepted" for s in suppressions):
                suppressed += 1
            else:
                candidate += 1
    return Counts(candidate=candidate, suppressed=suppressed, other=other)


def decide(path, outcome, enforce):
    if outcome != "success":
        raise InvalidSarif("scanner step did not succeed")
    with open(path, encoding="utf-8") as source:
        counts = assess(json.load(source))
    return counts, bool(enforce and counts.candidate)


def main():
    scanner = os.environ["SCANNER"]
    outcome = os.environ["TRIVY_OUTCOME" if scanner == "trivy" else "SCAN_OUTCOME"]
    enforce = os.environ.get("ENFORCE", "false").lower() == "true"
    report = Path(os.environ["REPORT_DIR"]) / f"{scanner}.sarif"
    counts = None
    trivy_coverage = None
    failed = False
    try:
        counts, failed = decide(report, outcome, enforce)
        if scanner == "trivy":
            if os.environ.get("TRIVY_INVENTORY_OUTCOME") != "success":
                raise InvalidSarif("Trivy target discovery did not succeed")
            from trivy_coverage import read_inventory
            trivy_coverage = read_inventory(Path(os.environ["REPORT_DIR"]) / "trivy-targets.json")
    except (InvalidSarif, OSError, ValueError, TypeError, KeyError):
        counts = None
        failed = True
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        summary.write(f"### Audit : {scanner}\n\n")
        summary.write("**Attention :** les détections automatiques sont des pistes à vérifier, pas des failles confirmées.\n\n")
        if counts is None:
            summary.write("**Erreur technique :** rapport absent, invalide ou analyse non terminée. Impossible de conclure.\n")
        else:
            summary.write("| Signalements à vérifier | Suppressions acceptées | Résultats non bloquants | Mode |\n")
            summary.write("|---:|---:|---:|---|\n")
            summary.write(f"| {counts.candidate} | {counts.suppressed} | {counts.other} | {'strict' if enforce else 'rapport'} |\n\n")
            summary.write("Seules les suppressions acceptées sont exclues ; une revue en cours reste active.\n")

            if scanner == "trivy" and trivy_coverage:
                state, targets = trivy_coverage
                if state == "NOT_APPLICABLE":
                    summary.write("**AUCUNE CIBLE RECONNUE PAR TRIVY : couverture non établie.** "
                                  "Un résultat sans alerte ne prouve pas que les dépendances sont sûres.\\n")
                else:
                    summary.write(f"**Cibles reconnues par Trivy : {targets}.** "
                                  "Les résultats ne couvrent que ces cibles et filtres.\\n")
        summary.write("\nConsulter le SARIF, confirmer le contexte et la pertinence avant toute correction.\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
