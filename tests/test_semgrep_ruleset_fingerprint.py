"""Cross-run equality proof is anonymous, and never an authorization decision."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import semgrep_ruleset_fingerprint as fp  # noqa: E402


RULES = [
    {"id": "rule.test.eval", "message": "PRIVATE_RULE_MESSAGE", "languages": ["python"],
     "severity": "WARNING", "pattern": "eval(...)"},
    {"id": "rule.test.exec", "message": "SECRET_PATTERN_TEXT", "languages": ["python"],
     "severity": "ERROR", "pattern": "exec(...)"},
]


def approved_fixture():
    text = (
        "rules:\n"
        "- id: rule.test.eval\n"
        "  message: PRIVATE_RULE_MESSAGE\n"
        "  languages: [python]\n"
        "  severity: WARNING\n"
        "  pattern: eval(...)\n"
        "- id: rule.test.exec\n"
        "  message: SECRET_PATTERN_TEXT\n"
        "  languages: [python]\n"
        "  severity: ERROR\n"
        "  pattern: exec(...)\n"
    )
    raw = (text + "# test-only-padding-" + "x" * 1100 + "\n").encode()
    return raw, {"format": "yaml", "rule_count": 2,
                 "sha256": hashlib.sha256(raw).hexdigest()}


class RuleFingerprintTest(unittest.TestCase):
    def setUp(self):
        self.raw, self.lock = approved_fixture()

    def test_approved_yaml_matches_equivalent_json_across_independent_inputs(self):
        trusted = fp.fingerprint(self.raw, self.lock, "approved")
        untrusted = fp.fingerprint(
            json.dumps({"rules": list(reversed(RULES))}).encode(),
            self.lock, "observed",
        )
        self.assertEqual(trusted["canonical_rule_objects_sha256"],
                         untrusted["canonical_rule_objects_sha256"])
        self.assertEqual(trusted["provenance"], "APPROVED_YAML")
        self.assertEqual(untrusted["provenance"], "UNAPPROVED_OBSERVATION")
        self.assertIn("NEVER", untrusted["authorization"])
        for raw_string in ("rule.test.eval", "PRIVATE_RULE_MESSAGE", "SECRET_PATTERN_TEXT"):
            self.assertNotIn(raw_string, json.dumps(untrusted))
            self.assertNotIn(raw_string, json.dumps(trusted))

    def test_changed_pattern_with_same_ids_changes_fingerprint(self):
        changed = [dict(RULES[0], pattern="safe(...)"), RULES[1]]
        original = fp.fingerprint(self.raw, self.lock, "approved")
        other = fp.fingerprint(json.dumps({"rules": changed}).encode(),
                               self.lock, "observed")
        self.assertNotEqual(original["canonical_rule_objects_sha256"],
                            other["canonical_rule_objects_sha256"])
        self.assertEqual(other["parsed_rule_count"], 2)
        self.assertTrue(other["reviewed_count_matches"])

    def test_replaced_rule_identity_same_count_changes_fingerprint(self):
        different = [RULES[0], dict(RULES[1], id="rule.different")]
        original = fp.fingerprint(self.raw, self.lock, "approved")
        other = fp.fingerprint(json.dumps({"rules": different}).encode(),
                               self.lock, "observed")
        self.assertNotEqual(original["canonical_rule_objects_sha256"],
                            other["canonical_rule_objects_sha256"])

    def test_approved_mode_requires_original_exact_sha_verification(self):
        with self.assertRaises(fp.FingerprintError):
            fp.fingerprint(self.raw.replace(b"eval(...)", b"safe(...)"),
                           self.lock, "approved")
        with self.assertRaises(fp.FingerprintError):
            fp.fingerprint(json.dumps({"rules": RULES}).encode(),
                           self.lock, "approved")

    def test_unapproved_yaml_is_never_upgraded_to_approved_provenance(self):
        altered = self.raw.replace(b"eval(...)", b"safe(...)")
        data = fp.fingerprint(altered, self.lock, "observed")
        self.assertEqual(data["provenance"], "UNAPPROVED_OBSERVATION")
        self.assertEqual(data["status"], "FINGERPRINTED")
        self.assertIn("NEVER", data["authorization"])

    def test_invalid_malformed_duplicate_and_excessive_responses(self):
        for bad in (b'{"rules":', b'{"rules":"not-an-array"}',
                    json.dumps({"rules": [RULES[0], RULES[0]]}).encode(),
                    b"x" * 5_000_001):
            with self.subTest(sample=bad[:16]):
                with self.assertRaises(fp.FingerprintError):
                    fp.fingerprint(bad, self.lock, "observed")

    def test_cli_handles_missing_and_corrupted_input_without_exposing_details(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "lock.json").write_text(json.dumps(self.lock))
            original = sys.argv
            sys.argv = ["fp", "--source", str(root / "nonexistent"),
                        "--lock", str(root / "lock.json"),
                        "--mode", "observed",
                        "--output", str(root / "summary.json")]
            try:
                self.assertEqual(fp.main(), 0)
            finally:
                sys.argv = original
            data = (root / "summary.json").read_text()
            self.assertIn('"status": "INCOMPARABLE"', data)
            self.assertNotIn("nonexistent", data)

    def test_nonmatching_expected_rule_count_is_not_approval(self):
        other = fp.fingerprint(json.dumps({"rules": [RULES[0]]}).encode(),
                               self.lock, "observed")
        self.assertFalse(other["reviewed_count_matches"])
        self.assertEqual(other["provenance"], "UNAPPROVED_OBSERVATION")


if __name__ == "__main__":
    unittest.main()
