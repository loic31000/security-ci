#!/usr/bin/env python3
"""Emit non-sensitive metadata about a changed Semgrep Registry response.

Never saves rule bodies, messages, rule identifiers, or source text. This
diagnostic cannot authorize new rules or override verify_semgrep_bundle.py.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

RULE = re.compile(rb"^- id: ([a-zA-Z0-9_.-]+)\s*$", re.MULTILINE)


def inspect_payload(payload, approved):
    if not isinstance(payload, bytes):
        raise ValueError("invalid input bytes")
    if not isinstance(approved, dict) or not re.fullmatch(
        "[0-9a-f]{64}", str(approved.get("sha256", ""))
    ):
        raise ValueError("approved metadata invalid")
    expected_count = approved.get("rule_count")
    if type(expected_count) is not int or expected_count < 1:
        raise ValueError("approved rule count invalid")
    if not payload or len(payload) > 5_000_000:
        raise ValueError("registry payload missing or unreasonably large")
    rule_ids = RULE.findall(payload) if payload.startswith(b"rules:\n") else []
    actual_sha = hashlib.sha256(payload).hexdigest()
    unique = set(rule_ids)
    # Only a digest of sorted identifiers, never identifiers themselves.
    ids_sha = hashlib.sha256(b"\n".join(sorted(unique))).hexdigest()
    valid_shape = (payload.startswith(b"rules:\n") and
                   len(rule_ids) == len(unique) and bool(rule_ids))
    matched = actual_sha == approved["sha256"]
    return {
        "schema": 1,
        "status": "APPROVED" if matched and valid_shape and len(rule_ids) == expected_count
                  else "UNAPPROVED",
        "approved_sha256": approved["sha256"],
        "observed_sha256": actual_sha,
        "payload_bytes": len(payload),
        "parsed_rule_count": len(rule_ids),
        "distinct_rule_count": len(unique),
        "rule_ids_sha256": ids_sha,
        "matches_approved_sha256": matched,
        "yaml_shape_recognized": valid_shape,
        "authorization": "NEVER: diagnostics do not approve rules",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("payload", type=Path)
    parser.add_argument("approved_metadata", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    # An error in diagnostics must never convert a failed scan into a pass.
    try:
        report = inspect_payload(
            args.payload.read_bytes(),
            json.loads(args.approved_metadata.read_text(encoding="utf-8")),
        )
    except (OSError, ValueError, TypeError):
        report = {
            "schema": 1, "status": "UNAVAILABLE",
            "authorization": "NEVER: diagnostics do not approve rules",
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print("Semgrep registry diagnostic metadata recorded (no rule text exported)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
