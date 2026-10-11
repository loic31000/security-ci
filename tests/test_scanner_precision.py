"""Calibration controls: fail closed for missing, mislabeled or ignored detections."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "scanner_precision.py"
spec = importlib.util.spec_from_file_location("scanner_precision", MODULE_PATH)
precision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(precision)


def sarif(*results, successful=True, notifications=None, scanner="Semgrep"):
    """Synthetic report with explicit scanner identity."""
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": scanner, "rules": []}},
            "invocations": [{
                "executionSuccessful": successful,
                "toolConfigurationNotifications": notifications or [],
            }],
            "results": list(results),
        }],
    }


def finding(filename="unsafe.py", **extras):
    return {
        "ruleId": "synthetic-detection",
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": filename},
            },
        }],
        **extras,
    }


class ScannerCalibrationTest(unittest.TestCase):
    def test_labeled_true_positive_and_negative(self):
        result = precision.calibrate("semgrep", sarif(finding()), sarif(), "unsafe.py")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual((result["true_positive_fixtures"], result["true_negative_fixtures"]), (1, 1))
        self.assertEqual((result["false_positive_fixtures"], result["false_negative_fixtures"]), (0, 0))

    def test_wrong_path_is_false_negative_not_success(self):
        result = precision.calibrate("semgrep", sarif(finding("other.py")), sarif(), "unsafe.py")
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["false_negative_fixtures"], 1)
        self.assertEqual(result["unexpected_positive_locations"], 1)

    def test_benign_result_is_false_positive_even_if_suppressed(self):
        result = precision.calibrate("gitleaks", sarif(finding("canary.txt"), scanner="gitleaks"),
                                     sarif(finding("placeholder.txt", suppressions=[{"status": "accepted"}]), scanner="gitleaks"),
                                     "canary.txt")
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["false_positive_fixtures"], 1)

    def test_ignored_positive_is_false_negative(self):
        for options in ({"kind": "pass"}, {"level": "note"},
                        {"suppressions": [{"status": "accepted"}]}):
            with self.subTest(options=options):
                result = precision.calibrate("semgrep", sarif(finding(**options)), sarif(), "unsafe.py")
                self.assertEqual(result["status"], "FAIL")
                self.assertEqual(result["false_negative_fixtures"], 1)

    def test_fails_on_scanner_configuration_error_and_incomplete_report(self):
        for source in (sarif(successful=False),
                       sarif(notifications=[{"level": "error"}]),
                       {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Tool"}}}]}):
            with self.subTest(source=source):
                with self.assertRaises(precision.InvalidEvidence):
                    precision.calibrate("semgrep", source, sarif(), "unsafe.py")

    def test_rejects_missing_scanner_and_path(self):
        with self.assertRaises(precision.InvalidEvidence):
            precision.calibrate("unknown", sarif(finding()), sarif(), "unsafe.py")
        with self.assertRaises(precision.InvalidEvidence):
            precision.calibrate("semgrep", sarif(finding()), sarif(), "../unsafe.py")

    def test_cannot_use_path_traversal_or_remote_url(self):
        for uri in ("../../unsafe.py", "https://example.com/unsafe.py"):
            with self.subTest(uri=uri):
                with self.assertRaises(precision.InvalidEvidence):
                    precision.calibrate("semgrep", sarif(finding(uri)), sarif(), "unsafe.py")

    def test_raw_secret_is_not_in_sanitized_metrics(self):
        sensitive_value = "ONLY_FOR_UNIT_TESTS_NEVER_REAL_SECRET"
        result = precision.calibrate(
            "gitleaks",
            sarif(finding("canary.txt", message={"text": sensitive_value}), scanner="gitleaks"),
            sarif(scanner="gitleaks"),
            "canary.txt",
        )
        self.assertNotIn(sensitive_value, json.dumps(result))

    def test_wrong_scanner_identity_rejected_for_both_fixtures(self):
        good = sarif(finding())
        wrong = sarif(finding(), scanner="gitleaks")
        for p, n in ((wrong, sarif()), (good, sarif(scanner="zizmor"))):
            with self.subTest(name=(p["runs"][0]["tool"]["driver"]["name"],
                                    n["runs"][0]["tool"]["driver"]["name"])):
                with self.assertRaisesRegex(precision.InvalidEvidence,
                                            "unexpected scanner identity"):
                    precision.calibrate("semgrep", p, n, "unsafe.py")

    def test_missing_and_invalid_suppression_status_rejected(self):
        for status in ("masked", False, [], {}):
            item = finding(suppressions=[{"status": status}])
            with self.subTest(status=status):
                with self.assertRaisesRegex(precision.InvalidEvidence,
                                            "malformed suppressions"):
                    precision.calibrate("semgrep", sarif(item), sarif(), "unsafe.py")

    def test_file_uri_host_is_not_accepted(self):
        with self.assertRaisesRegex(precision.InvalidEvidence, "unsafe SARIF"):
            precision.calibrate("semgrep",
                                sarif(finding("file://remote-host/tmp/unsafe.py")),
                                sarif(), "unsafe.py")

    def test_missing_and_corrupt_sarif_fail_before_reporting_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "report.sarif"
            with self.assertRaises(precision.InvalidEvidence):
                precision._read(file)
            file.write_text("{")
            with self.assertRaises(precision.InvalidEvidence):
                precision._read(file)


if __name__ == "__main__":
    unittest.main()
