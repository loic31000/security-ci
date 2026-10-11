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
    # The public Registry sometimes serves JSON although the reviewed
    # bytes are YAML. Inspect JSON *only* for comparison metadata. Never
    # accept or execute it using the YAML SHA-256 approval.
    format_name = "unrecognized"
    rule_ids = []
    if payload.startswith(b"rules:\n"):
        format_name = "yaml"
        rule_ids = RULE.findall(payload)
    elif payload.lstrip().startswith(b"{"):
        try:
            obj = json.loads(payload)
            if isinstance(obj, dict) and isinstance(obj.get("rules"), list):
                items = obj["rules"]
                if all(isinstance(item, dict) and
                       isinstance(item.get("id"), str) for item in items):
                    rule_ids = [item["id"].encode("utf-8") for item in items]
                    format_name = "json"
        except (ValueError, UnicodeError, TypeError):
            pass
    actual_sha = hashlib.sha256(payload).hexdigest()
    unique = set(rule_ids)
    # Only a digest of sorted identifiers, never identifiers themselves.
    ids_sha = hashlib.sha256(b"\n".join(sorted(unique))).hexdigest()
    valid_shape = (format_name != "unrecognized" and
                   len(rule_ids) == len(unique) and bool(rule_ids))
    matched = actual_sha == approved["sha256"]
    approved_bundle = (matched and format_name == "yaml" and valid_shape
                       and len(rule_ids) == expected_count)
    # Classify the *shape of evidence*, not whether new rules are equivalent.
    # The accepted payload is still solely the exact reviewed YAML bytes.
    if approved_bundle:
        category = "APPROVED"
    elif format_name == "unrecognized":
        category = "UNRECOGNIZED_RESPONSE"
    elif not valid_shape or len(rule_ids) != expected_count:
        category = "RULE_INVENTORY_MISMATCH"
    elif format_name == "json":
        category = "JSON_FORMAT_UNAPPROVED"
    else:
        category = "YAML_DIGEST_MISMATCH"
    return {
        "schema": 1,
        "status": "APPROVED" if approved_bundle else "UNAPPROVED",
        "diagnostic_category": category,
        "approved_sha256": approved["sha256"],
        "observed_sha256": actual_sha,
        "payload_bytes": len(payload),
        "parsed_rule_count": len(rule_ids),
        "distinct_rule_count": len(unique),
        "rule_ids_sha256": ids_sha,
        "matches_approved_sha256": matched,
        "response_format": format_name,
        "structure_recognized": valid_shape,
        "yaml_shape_recognized": format_name == "yaml" and valid_shape,
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
