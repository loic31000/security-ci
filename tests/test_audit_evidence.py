"""Real scanner shapes, certified JUnit and Trivy coverage regression tests."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class AuditEvidenceTest(unittest.TestCase):
    def test_four_real_sarif_shapes(self):
        decision = load("sarif_decision")
        fixtures = json.loads((ROOT / "tests/fixtures/real-sarif-shapes.json").read_text())
        self.assertEqual(set(fixtures["scanners"]), {"semgrep", "trivy", "gitleaks", "zizmor"})
        for name, data in fixtures["scanners"].items():
            with self.subTest(scanner=name):
                c = decision.assess(data)
                self.assertEqual((c.candidate, c.other), (0, 0))

    def test_scanner_config_error_in_semgrep_shape(self):
        decision = load("sarif_decision")
        fixture = json.loads((ROOT / "tests/fixtures/real-sarif-shapes.json").read_text())
        report = fixture["scanners"]["semgrep"]
        report["runs"][0]["invocations"][0]["toolConfigurationNotifications"] = [{"level": "error"}]
        with self.assertRaises(decision.InvalidSarif):
            decision.assess(report)

    def test_trivy_no_targets_is_not_clean(self):
        cov = load("trivy_coverage")
        self.assertEqual(cov.assess_inventory({"SchemaVersion": 2, "Results": []}), ("NOT_APPLICABLE", 0))
        self.assertEqual(cov.assess_inventory({"SchemaVersion": 2}), ("NOT_APPLICABLE", 0))

    def test_trivy_recognized_targets_and_bad_json(self):
        cov = load("trivy_coverage")
        data = {"SchemaVersion": 2, "Results": [
            {"Target": "requirements.txt", "Type": "pip", "Vulnerabilities": []},
            {"Target": "package-lock.json", "Type": "npm", "Vulnerabilities": []}]}
        self.assertEqual(cov.assess_inventory(data), ("SCANNED", 2))
        for invalid in ([], {"Results": []}, {"SchemaVersion": 2, "Results": "bad"},
                        {"SchemaVersion": 2, "Results": [{}]}):
            with self.assertRaises(cov.InventoryError):
                cov.assess_inventory(invalid)

    def test_junit_requires_fresh_nonempty_passing_cases(self):
        v = load("test_report_validator")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            xml = root / "results.xml"
            xml.write_text('<testsuite tests="1"><testcase name="works"/></testsuite>')
            self.assertEqual(v.validate("results.xml", root, xml.stat().st_mtime_ns), 1)
            with self.assertRaises(ValueError):
                v.validate("results.xml", root, xml.stat().st_mtime_ns + 1)
            with self.assertRaises(ValueError):
                v.validate("../results.xml", root, 0)

    def test_junit_rejects_zero_failed_skipped_and_malformed(self):
        v = load("test_report_validator")
        cases = ('<testsuite tests="0"/>',
                 '<testsuite><testcase name="x"><failure/></testcase></testsuite>',
                 '<testsuite><testcase name="x"><skipped/></testcase></testsuite>',
                 '<testsuite errors="1"><testcase name="x"/></testsuite>',
                 '<root><testcase name="x"/></root>')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.xml"
            for data in cases:
                with self.subTest(data=data):
                    p.write_text(data)
                    with self.assertRaises(ValueError):
                        v.validate("test.xml", d, 0)

    def test_junit_supports_multiple_suites(self):
        v = load("test_report_validator")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.xml"
            p.write_text('<testsuites><testsuite><testcase name="one"/></testsuite>'
                         '<testsuite><testcase name="two"/></testsuite></testsuites>')
            self.assertEqual(v.validate("test.xml", d, 0), 2)

    def test_junit_xml_entity_expansion_blocked(self):
        v = load("test_report_validator")
        from defusedxml.common import DefusedXmlException
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.xml"
            p.write_text('<!DOCTYPE testsuite [<!ENTITY x "hi">]><testsuite>'
                         '<testcase name="&x;"/></testsuite>')
            with self.assertRaises(DefusedXmlException):
                v.validate("test.xml", d, 0)


if __name__ == "__main__":
    unittest.main()
