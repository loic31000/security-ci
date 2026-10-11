"""Ensure Semgrep drift triage cannot leak or approve unreviewed rule content."""
import importlib.util
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "semgrep_drift_metadata", HERE / "scripts" / "semgrep_drift_metadata.py")
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


class RegistryDriftTest(unittest.TestCase):
    def setUp(self):
        self.raw = b"rules:\n- id: p0\n  message: DO_NOT_PUBLISH_RULE_CONTENT\n- id: p1\n"
        self.lock = {"sha256": hashlib.sha256(self.raw).hexdigest(), "rule_count": 2}

    def test_approved_payload_is_not_self_authorizing(self):
        data = subject.inspect_payload(self.raw, self.lock)
        self.assertEqual(data["status"], "APPROVED")
        self.assertFalse("DO_NOT_PUBLISH_RULE_CONTENT" in json.dumps(data))
        self.assertFalse('"p0"' in json.dumps(data))
        self.assertEqual(data["authorization"], "NEVER: diagnostics do not approve rules")

    def test_changed_payload_fails_to_match_and_exposes_no_rule_text(self):
        raw = self.raw.replace(b"p1", b"p2")
        data = subject.inspect_payload(raw, self.lock)
        self.assertEqual(data["status"], "UNAPPROVED")
        self.assertEqual(data["parsed_rule_count"], 2)
        self.assertFalse(data["matches_approved_sha256"])
        for value in ("p0", "p2", "DO_NOT_PUBLISH_RULE_CONTENT"):
            self.assertNotIn('"'+value+'"', json.dumps(data))

    def test_json_registry_response_is_diagnosed_but_never_approved(self):
        source = {
            "rules": [
                {"id": "p0", "message": "DO_NOT_EXPORT"},
                {"id": "p1", "patterns": [{"pattern": "any"}]},
            ],
        }
        data = subject.inspect_payload(json.dumps(source).encode(), self.lock)
        self.assertEqual(data["status"], "UNAPPROVED")
        self.assertEqual(data["response_format"], "json")
        self.assertEqual(data["parsed_rule_count"], 2)
        self.assertEqual(data["distinct_rule_count"], 2)
        self.assertFalse(data["matches_approved_sha256"])
        self.assertFalse(data["yaml_shape_recognized"])
        self.assertNotIn("DO_NOT_EXPORT", json.dumps(data))
        self.assertNotIn('"p0"', json.dumps(data))
        self.assertNotIn('"p1"', json.dumps(data))

    def test_invalid_json_and_duplicate_identifiers_never_approved(self):
        for raw in (b'{"rules": [', b'{"rules": "not-list"}',
                    b'{"rules":[{"id":"same"},{"id":"same"}]}'):
            with self.subTest(raw=raw):
                self.assertNotEqual(
                    subject.inspect_payload(raw, self.lock)["status"], "APPROVED")

    def test_bad_count_duplicate_and_root_never_pass(self):
        for value in (self.raw.replace(b"- id: p1", b"- id: p0"),
                      b"error: opaque", self.raw + b"- id: p2\n"):
            with self.subTest(sample=value[:16]):
                data = subject.inspect_payload(value, self.lock)
                self.assertNotEqual(data["status"], "APPROVED")
        mismatch = dict(self.lock, rule_count=5)
        self.assertEqual(subject.inspect_payload(self.raw, mismatch)["status"], "UNAPPROVED")

    def test_rejects_oversized_payload_or_invalid_lock(self):
        with self.assertRaises(ValueError):
            subject.inspect_payload(b"x"*5_000_001, self.lock)
        with self.assertRaises(ValueError):
            subject.inspect_payload(self.raw, {"sha256": "bad", "rule_count": 2})

    def test_cli_writes_sanitized_artifact(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "response.yaml").write_bytes(self.raw)
            (root / "lock.json").write_text(json.dumps(self.lock))
            import sys
            original = sys.argv
            sys.argv = ["tool", str(root / "response.yaml"),
                        str(root / "lock.json"), str(root / "evidence.json")]
            try:
                self.assertEqual(subject.main(), 0)
            finally:
                sys.argv = original
            result = (root / "evidence.json").read_text()
            self.assertNotIn("DO_NOT_PUBLISH_RULE_CONTENT", result)
            self.assertIn('"status": "APPROVED"', result)


if __name__ == "__main__":
    unittest.main()
