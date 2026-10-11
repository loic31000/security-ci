#!/usr/bin/env python3
"""Verify the *exact* trusted Semgrep Registry YAML before executing scanner rules.

This checksum control is about integrity and drift, not exploitability.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

EXPECTED_RULE_LINE = re.compile(rb"^- id: ([a-zA-Z0-9_.-]+)\s*$", re.MULTILINE)
SHA = re.compile(r"^[0-9a-f]{64}$")


class RuleBundleError(ValueError):
    pass


def validate_bundle(data, metadata):
    if not isinstance(metadata, dict) or metadata.get("format") != "yaml":
        raise RuleBundleError("invalid reviewed Semgrep format")
    expected_hash = metadata.get("sha256")
    if not isinstance(expected_hash, str) or not SHA.fullmatch(expected_hash):
        raise RuleBundleError("missing or malformed reviewed ruleset digest")
    expected_count = metadata.get("rule_count")
    if not isinstance(expected_count, int) or isinstance(expected_count, bool) or expected_count < 1:
        raise RuleBundleError("invalid reviewed ruleset count")
    if not isinstance(data, bytes) or len(data) < 1000 or len(data) > 5_000_000:
        raise RuleBundleError("unexpected Semgrep configuration size")
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected_hash:
        raise RuleBundleError(
            "Semgrep Registry rules have changed since review. "
            "Do NOT report this as a vulnerability or use rules before approval. "
            f"Approved SHA256={expected_hash}, received SHA256={digest}"
        )
    if not data.startswith(b"rules:\n"):
        raise RuleBundleError("Semgrep config missing YAML root")
    names = EXPECTED_RULE_LINE.findall(data)
    if len(names) != expected_count or len(set(names)) != expected_count:
        raise RuleBundleError(
            "Semgrep rules count/identities differ from reviewed metadata"
        )
    return len(names)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("downloaded_file")
    parser.add_argument("reviewed_metadata")
    args = parser.parse_args()
    try:
        payload = Path(args.downloaded_file).read_bytes()
        metadata = json.loads(Path(args.reviewed_metadata).read_text())
        count = validate_bundle(payload, metadata)
    except (OSError, ValueError, TypeError) as exc:
        print(f"::error::Semgrep Registry verification failed: {exc}")
        return 1
    print(f"Verified Semgrep Registry bundle with {count} approved rules and exact SHA-256")
    return 0


if __name__ == "__main__":
    sys.exit(main())
