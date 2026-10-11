#!/usr/bin/env python3
"""Anonymous, non-authorizing rule-object fingerprint for cross-run Semgrep triage.

A fingerprint may be compared across runners; it NEVER grants permission to
execute a new payload, even when two fingerprints happen to be identical.
Raw vendor rules and individual rule IDs are neither logged nor archived.
"""
import argparse
import hashlib
import json
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from semgrep_ruleset_compare import ComparisonError, hashes
from verify_semgrep_bundle import RuleBundleError, validate_bundle

MAX_BYTES = 5_000_000


class FingerprintError(ValueError):
    pass


def fingerprint(payload, lock, mode):
    if mode not in ("approved", "observed"):
        raise FingerprintError("unsupported analysis mode")
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_BYTES:
        raise FingerprintError("invalid payload")
    if not isinstance(lock, dict):
        raise FingerprintError("invalid review metadata")
    approved = mode == "approved"
    if approved:
        try:
            validate_bundle(payload, lock)
        except (RuleBundleError, TypeError, KeyError) as exc:
            raise FingerprintError("approval prerequisite failed") from exc
    try:
        if payload.startswith(b"rules:\n"):
            kind = "yaml"
            obj = YAML(typ="safe").load(payload.decode("utf-8"))
        elif payload.lstrip().startswith(b"{"):
            kind = "json"
            obj = json.loads(payload)
        else:
            raise FingerprintError("unrecognized response type")
        rule_hashes = hashes(obj)
    except (YAMLError, ComparisonError, ValueError, UnicodeError, TypeError,
            RecursionError) as exc:
        raise FingerprintError("rule objects cannot be parsed") from exc
    # Rule objects are reduced to SHA-256 and sorted by identifier internally.
    # Neither the identifiers nor the per-rule hashes leave this process.
    stable = json.dumps(
        [[rid, rule_hashes[rid]] for rid in sorted(rule_hashes)],
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(stable).hexdigest()
    reviewed_count = lock.get("rule_count")
    return {
        "schema": 1,
        "status": "FINGERPRINTED",
        "response_format": kind,
        "provenance": "APPROVED_YAML" if approved else "UNAPPROVED_OBSERVATION",
        "parsed_rule_count": len(rule_hashes),
        "reviewed_rule_count": reviewed_count if type(reviewed_count) is int else None,
        "reviewed_count_matches": (
            len(rule_hashes) == reviewed_count
            if type(reviewed_count) is int else False
        ),
        "canonical_rule_objects_sha256": digest,
        "comparison_scope": (
            "canonical parsed rule objects only, not top-level configuration,"
            " rule evaluation or scanner behavior"
        ),
        "authorization": "NEVER: anonymous fingerprints cannot approve scanner rules",
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--lock", type=Path, required=True)
    p.add_argument("--mode", choices=("approved", "observed"), required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        report = fingerprint(
            args.source.read_bytes(),
            json.loads(args.lock.read_text(encoding="utf-8")),
            args.mode,
        )
    except (OSError, ValueError, TypeError, KeyError, YAMLError, RecursionError):
        report = {
            "schema": 1,
            "status": "INCOMPARABLE",
            "authorization": "NEVER: unavailable evidence cannot approve scanner rules",
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    print("Semgrep anonymous rule-object fingerprint recorded (no rule data)")
    return 0  # Diagnostic data may NEVER change the scan decision.


if __name__ == "__main__":
    raise SystemExit(main())
