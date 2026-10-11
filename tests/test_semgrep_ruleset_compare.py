"""Rule-object comparison is diagnostic only; any uncertainty is incomparable."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import semgrep_ruleset_compare as comparator  # noqa: E402


RULES = [
    {"id": "test.eval", "message": "NEVER_SHARE_CONTENT", "languages": ["python"],
     "severity": "WARNING", "pattern": "eval(...)"},
    {"id": "test.exec", "message": "SENSITIVE_DETECTION_TEXT", "languages": ["python"],
     "severity": "ERROR", "pattern": "exec(...)"},
]


def fixture():
    yaml = (
        "rules:\n"
        "- id: test.eval\n"
        "  message: NEVER_SHARE_CONTENT\n"
        "  languages: [python]\n"
        "  severity: WARNING\n"
        "  pattern: eval(...)\n"
        "- id: test.exec\n"
        "  message: SENSITIVE_DETECTION_TEXT\n"
        "  languages: [python]\n"
        "  severity: ERROR\n"
        "  pattern: exec(...)\n"
    )
    # verify_semgrep_bundle has a minimum reviewed YAML length.
    data = (yaml + ("# reviewed-sample-padding-" + "z" * 1050 + "\n")).encode()
    return data, {"format": "yaml", "rule_count": 2,
                  "sha256": hashlib.sha256(data).hexdigest()}


class SemgrepComparisonTest(unittest.TestCase):
    def setUp(self):
        self.approved, self.lock = fixture()

    def compare(self, rules):
        return comparator.compare(self.approved, json.dumps({"rules": rules}).encode(),
                                  self.lock)

    def test_equivalent_rule_objects_have_no_new_authority(self):
        outcome = self.compare(list(reversed(RULES)))
        self.assertEqual(outcome["outcome"], "SAME_RULE_OBJECTS")
        self.assertEqual(outcome["changed_rule_objects"], 0)
        self.assertEqual(outcome["status"], "COMPARED")
        self.assertIn("NEVER", outcome["authorization"])
        for secret in ("NEVER_SHARE_CONTENT", "test.eval", "SENSITIVE_DETECTION_TEXT"):
            self.assertNotIn(secret, json.dumps(outcome))

    def test_same_ids_with_changed_rule_pattern_are_detected(self):
        alternate = [{**RULES[0], "pattern": "allow(...)"}, RULES[1]]
        outcome = self.compare(alternate)
        self.assertEqual(outcome["outcome"], "RULE_OBJECT_DIFFERENCES")
        self.assertEqual(outcome["changed_rule_objects"], 1)
        self.assertEqual((outcome["added_rule_ids"], outcome["missing_rule_ids"]), (0, 0))

    def test_replaced_id_is_not_hidden_by_same_count(self):
        alternate = [RULES[0], {**RULES[1], "id": "test.other"}]
        outcome = self.compare(alternate)
        self.assertEqual(outcome["outcome"], "RULE_OBJECT_DIFFERENCES")
        self.assertEqual((outcome["added_rule_ids"], outcome["missing_rule_ids"]), (1, 1))

    def test_modified_approved_yaml_cannot_be_used_to_compare(self):
        broken = self.approved.replace(b"eval(...)", b"safe(...)")
        with self.assertRaisesRegex(comparator.ComparisonError, "integrity"):
            comparator.compare(broken, json.dumps({"rules": RULES}).encode(), self.lock)

    def test_unapproved_yaml_digest_metadata_rejected(self):
        with self.assertRaises(comparator.ComparisonError):
            comparator.compare(self.approved, json.dumps({"rules": RULES}).encode(),
                               {**self.lock, "sha256": "0" * 64})

    def test_malformed_json_and_duplicate_ids_are_not_comparable(self):
        bad = [b'{"rules":', b'{"rules":"no"}',
               json.dumps({"rules": [RULES[0], RULES[0]]}).encode()]
        for payload in bad:
            with self.subTest(payload=payload[:15]):
                with self.assertRaises(comparator.ComparisonError):
                    comparator.compare(self.approved, payload, self.lock)

    def test_cli_never_prints_raw_rules_even_on_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            (p / "approved.yaml").write_bytes(self.approved)
            (p / "response.json").write_bytes(json.dumps({"rules": RULES}).encode())
            (p / "approved.json").write_text(json.dumps(self.lock))
            original = sys.argv
            sys.argv = [
                "compare", "--approved-yaml", str(p / "approved.yaml"),
                "--observed-json", str(p / "response.json"),
                "--lock", str(p / "approved.json"), "--output", str(p / "summary.json")
            ]
            try:
                self.assertEqual(comparator.main(), 0)
            finally:
                sys.argv = original
            output = (p / "summary.json").read_text()
            self.assertIn('"SAME_RULE_OBJECTS"', output)
            self.assertNotIn("SENSITIVE_DETECTION_TEXT", output)
            self.assertNotIn("test.eval", output)


if __name__ == "__main__":
    unittest.main()
