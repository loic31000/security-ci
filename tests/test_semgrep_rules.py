"""Regression tests: registry rule drift is an audit-configuration error, not a clean scan."""
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "verify_semgrep_bundle", ROOT / "scripts/verify_semgrep_bundle.py"
)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class SemgrepRuleIntegrityTest(unittest.TestCase):
    @staticmethod
    def fixture():
        data = b"rules:\n" + b"".join(
            ("- id: example.rule%03d\n  pattern: dangerous_call(...)\n"
             "  message: controlled example\n  severity: WARNING\n"
             "  languages: [python]\n" % i).encode()
            for i in range(15)
        )
        metadata = {
            "format": "yaml",
            "rule_count": 15,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        return data, metadata

    def test_exact_approved_bundle_passes(self):
        data, metadata = self.fixture()
        self.assertEqual(validator.validate_bundle(data, metadata), 15)

    def test_changed_rule_with_same_ids_fails_closed(self):
        data, metadata = self.fixture()
        changed = data.replace(b"dangerous_call", b"apparently_safe", 1)
        with self.assertRaisesRegex(validator.RuleBundleError, "have changed"):
            validator.validate_bundle(changed, metadata)

    def test_reordered_rules_trigger_review(self):
        data, metadata = self.fixture()
        moved = data.replace(b"- id: example.rule000", b"- id: example.rule999", 1)
        with self.assertRaises(validator.RuleBundleError):
            validator.validate_bundle(moved, metadata)

    def test_duplicate_or_missing_ids_cannot_claim_coverage(self):
        data, metadata = self.fixture()
        invalid = dict(metadata, rule_count=16)
        with self.assertRaisesRegex(validator.RuleBundleError, "count"):
            validator.validate_bundle(data, invalid)
        bad = data.replace(b"- id: example.rule001", b"- id: example.rule000")
        bad_meta = dict(metadata, sha256=hashlib.sha256(bad).hexdigest())
        with self.assertRaisesRegex(validator.RuleBundleError, "identities"):
            validator.validate_bundle(bad, bad_meta)

    def test_invalid_digests_refused(self):
        data, metadata = self.fixture()
        for value in ("", "deadbeef", "Z" * 64, None):
            with self.subTest(value=value), self.assertRaises(validator.RuleBundleError):
                validator.validate_bundle(data, dict(metadata, sha256=value))

    def test_truncated_download_does_not_pass(self):
        data, metadata = self.fixture()
        with self.assertRaises(validator.RuleBundleError):
            validator.validate_bundle(data[:8], metadata)

    def test_real_review_metadata_format_and_nonzero_digest(self):
        info = json.loads((ROOT / "locks/semgrep-security-audit.json").read_text())
        self.assertEqual(info["rule_count"], 225)
        self.assertTrue(info["source"].startswith("https://semgrep.dev/c/p/security-audit"))
        self.assertEqual(len(info["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
