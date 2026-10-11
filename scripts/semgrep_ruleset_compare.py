#!/usr/bin/env python3
"""Compare an approved YAML Semgrep bundle to JSON without exporting rule content.

The result is diagnostic only and is NEVER used to authorize scanner rules.
"""
import argparse
import hashlib
import json
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from verify_semgrep_bundle import RuleBundleError, validate_bundle

MAX_BYTES = 5_000_000


class ComparisonError(ValueError):
    pass


def canonical(value):
    """Allow only deterministic, JSON-compatible rule data."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        raise ComparisonError("noncanonical number in rule")
    if isinstance(value, list):
        return [canonical(item) for item in value]
    if isinstance(value, dict):
        if any(not isinstance(k, str) for k in value):
            raise ComparisonError("non-string rule key")
        return {k: canonical(v) for k, v in value.items()}
    raise ComparisonError("unsupported rule value")


def hashes(document):
    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        raise ComparisonError("rule list absent")
    result = {}
    for rule in document["rules"]:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            raise ComparisonError("invalid rule identity")
        rid = rule["id"]
        if not rid or rid in result:
            raise ComparisonError("duplicate or empty rule identity")
        content = canonical(rule)
        stable = json.dumps(content, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False, allow_nan=False)
        result[rid] = hashlib.sha256(stable.encode("utf-8")).hexdigest()
    if not result:
        raise ComparisonError("no rule objects")
    return result


def compare(approved_yaml, observed_json, lock):
    if not isinstance(approved_yaml, bytes) or not isinstance(observed_json, bytes):
        raise ComparisonError("invalid byte inputs")
    if not isinstance(lock, dict):
        raise ComparisonError("invalid approved metadata")
    if not observed_json or len(observed_json) > MAX_BYTES:
        raise ComparisonError("invalid observed response size")
    try:
        validate_bundle(approved_yaml, lock)
    except (RuleBundleError, TypeError, KeyError) as exc:
        raise ComparisonError("approved YAML did not pass original integrity guard") from exc
    try:
        yaml = YAML(typ="safe")
        approved = hashes(yaml.load(approved_yaml.decode("utf-8")))
        observed = hashes(json.loads(observed_json))
    except (YAMLError, ValueError, TypeError, UnicodeError) as exc:
        raise ComparisonError("could not parse and compare rule objects") from exc
    trusted_ids, observed_ids = set(approved), set(observed)
    common = trusted_ids & observed_ids
    changed = sum(approved[key] != observed[key] for key in common)
    missing = len(trusted_ids - observed_ids)
    added = len(observed_ids - trusted_ids)
    return {
        "schema": 1,
        "status": "COMPARED",
        "outcome": "SAME_RULE_OBJECTS" if not (changed or missing or added)
                   else "RULE_OBJECT_DIFFERENCES",
        "scope": "parsed rule objects only; not top-level config or scanner behavior",
        "approved_rule_count": len(approved),
        "observed_rule_count": len(observed),
        "common_rule_count": len(common),
        "changed_rule_objects": changed,
        "missing_rule_ids": missing,
        "added_rule_ids": added,
        "authorization": "NEVER: semantic comparison does not approve observed bytes",
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--approved-yaml", type=Path, required=True)
    p.add_argument("--observed-json", type=Path, required=True)
    p.add_argument("--lock", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        proof = compare(args.approved_yaml.read_bytes(), args.observed_json.read_bytes(),
                        json.loads(args.lock.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, KeyError):
        proof = {
            "schema": 1, "status": "INCOMPARABLE",
            "authorization": "NEVER: unavailable evidence does not approve rules",
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print("Sanitized Semgrep rule comparison completed (no rule data exported)")
    return 0  # Informational only. Never used by the scanner integrity check.


if __name__ == "__main__":
    raise SystemExit(main())
