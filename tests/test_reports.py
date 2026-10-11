"""Regression tests for public Markdown reports."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReportsTest(unittest.TestCase):
    def test_sarif_location_and_message(self):
        module = load("sarif_to_markdown")
        data = {"runs": [{"tool": {"driver": {"rules": []}}, "results": [{
            "ruleId": "test-rule", "level": "warning", "message": {"text": "Possible injection"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/db.go"},
                                               "region": {"startLine": 97}}}]
        }]}]}
        result = module.render(data, "semgrep", "example/project", "123abc")
        self.assertIn("src/db.go", result)
        self.assertIn("97", result)
        self.assertIn("Possible injection", result)
        self.assertIn("blob/123abc/src/db.go#L97", result)

    def test_secret_message_not_leaked(self):
        module = load("sarif_to_markdown")
        result = module.render({"runs": [{"results": [{
            "ruleId": "generic-api-key", "message": {"text": "TOKEN_SECRET_SHOULD_NOT_APPEAR"}}]}]},
            "gitleaks")
        self.assertNotIn("TOKEN_SECRET_SHOULD_NOT_APPEAR", result)

    def test_empty_and_malformed_sarif(self):
        module = load("sarif_to_markdown")
        self.assertIn("Aucune alerte", module.render({"runs": [{"results": []}]}, "trivy"))
        with self.assertRaises(ValueError):
            module.render({"runs": []}, "trivy")

    def test_reject_url_and_traversal_locations(self):
        module = load("sarif_to_markdown")
        for path in ("../../private", "https://bad.example/path"):
            row = {"locations": [{"physicalLocation": {"artifactLocation": {"uri": path}}}]}
            self.assertEqual(module.location_for(row, "a/b", "123")[2], "")

    def test_maintainability_location_and_counts(self):
        module = load("maintainability_to_markdown")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "jscpd-report.json").write_text(json.dumps({"duplicates": [{
                "firstFile": {"name": "src/a.go", "start": 12},
                "secondFile": {"name": "src/b.go", "start": 42}}]}))
            (root / "python-complexity.json").write_text(json.dumps({
                "src/x.py": [{"name": "complex", "lineno": 8, "complexity": 15}]}))
            (root / "python-maintainability.json").write_text(json.dumps({
                "src/x.py": {"mi": 12.2}}))
            (root / "lizard.xml").write_text("<root><measure type='Function'><value value='17'/></measure></root>")
            report = module.render(root)
            for needle in ("src/a.go", "12", "src/b.go", "42", "src/x.py", "complex", "15", "12.2"):
                self.assertIn(needle, report)


    def test_sarif_suppressed_and_informational_not_labeled_confirmed(self):
        module = load("sarif_to_markdown")
        data = {"runs": [{"results": [
            {"ruleId": "A", "level": "error", "suppressions": [{"status": "accepted"}]},
            {"ruleId": "B", "kind": "pass"},
            {"ruleId": "C", "level": "warning"}
        ]}]}
        markdown = module.render(data, "semgrep")
        self.assertIn("Entrées SARIF brutes : 3", markdown)
        self.assertIn("Exclu : suppression acceptée", markdown)
        self.assertIn("Non bloquant", markdown)
        self.assertIn("À vérifier", markdown)
        self.assertNotIn("faille confirmée", markdown)

    def test_malicious_lizard_xml_entities_rejected(self):
        from defusedxml.common import DefusedXmlException

        module = load("maintainability_to_markdown")
        malicious = '<!DOCTYPE root [<!ENTITY leak "unexpected expansion">]><root>&leak;</root>'
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "lizard.xml").write_text(malicious, encoding="utf-8")
            with self.assertRaises(DefusedXmlException):
                module.render(root)


if __name__ == "__main__":
    unittest.main()
