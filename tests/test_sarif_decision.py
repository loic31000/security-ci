"""Regression tests for strict, suppression-aware SARIF decisions."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sarif_decision.py"
spec = importlib.util.spec_from_file_location("sarif_decision", SCRIPT)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def report(results=(), *, extra=None, version="2.1.0"):
    run = {"tool": {"driver": {
        "name": "mock",
        "rules": [{"id": "test", "defaultConfiguration": {"level": "error"}}],
    }}, "results": list(results)}
    if extra:
        run.update(extra)
    return {"version": version, "runs": [run]}


class SarifDecisionTest(unittest.TestCase):
    def test_empty_valid_report_clean(self):
        self.assertEqual(module.assess(report()).candidate, 0)

    def test_warning_and_error_are_candidates(self):
        self.assertEqual(module.assess(report([{"level": "warning"}, {"level": "error"}])).candidate, 2)

    def test_kind_and_level_without_failure_not_blocked(self):
        rows = [{"kind": k} for k in ("pass", "review", "open", "informational", "notApplicable")]
        rows += [{"level": "note"}, {"level": "none"}]
        counts = module.assess(report(rows))
        self.assertEqual((counts.candidate, counts.other), (0, 7))

    def test_accepted_suppressions_only(self):
        rows = [
            {"suppressions": [{"kind": "inSource", "status": "accepted"}]},
            {"suppressions": [{"kind": "inSource", "status": "underReview"}]},
            {"suppressions": [{"kind": "external", "status": "rejected"}]},
        ]
        c = module.assess(report(rows))
        self.assertEqual((c.candidate, c.suppressed), (2, 1))

    def test_invalid_and_partial_reports_fail_closed(self):
        cases = [
            None, {}, {"version": "2.1.0", "runs": []},
            {"version": "2.1.0", "runs": [{}]},
            {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}}]},
            report([None]), report([{"kind": "unknown"}]), report([], version="2.0.0"),
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(module.InvalidSarif):
                module.assess(case)

    def test_scanner_internal_failure_is_not_clean(self):
        for extra in (
            {"invocations": [{"executionSuccessful": False}]},
            {"invocations": [{"toolExecutionNotifications": [{"level": "error"}]}]},
        ):
            with self.assertRaises(module.InvalidSarif):
                module.assess(report([], extra=extra))

    def test_configuration_error_must_fail_even_when_results_are_empty(self):
        # OASIS SARIF 2.1.0 3.20.22: configuration error means the run failed.
        data = report([], extra={"invocations": [{
            "executionSuccessful": True,
            "toolConfigurationNotifications": [{
                "level": "error", "message": {"text": "Rules were not loaded"}
            }]
        }]})
        with self.assertRaises(module.InvalidSarif):
            module.assess(data)

    def test_configuration_warning_is_not_a_failure(self):
        data = report([], extra={"invocations": [{
            "executionSuccessful": True,
            "toolConfigurationNotifications": [{"level": "warning"}]
        }]})
        self.assertEqual(module.assess(data).candidate, 0)

    def test_invocation_without_boolean_success_is_incomplete(self):
        for bad in ({}, {"executionSuccessful": "true"}, {"executionSuccessful": False}):
            with self.subTest(invocation=bad), self.assertRaises(module.InvalidSarif):
                module.assess(report([], extra={"invocations": [bad]}))

    def test_missing_report_and_scanner_failure_not_clean(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "scan.sarif"
            with self.assertRaises(OSError):
                module.decide(f, "success", False)
            f.write_text(json.dumps(report()))
            with self.assertRaises(module.InvalidSarif):
                module.decide(f, "failure", False)

    def test_report_mode_strict_mode_and_accepted_suppression(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "scan.sarif"
            f.write_text(json.dumps(report([{"level": "error"}])))
            self.assertTrue(module.decide(f, "success", True)[1])
            self.assertFalse(module.decide(f, "success", False)[1])
            f.write_text(json.dumps(report([{"suppressions": [{"status": "accepted"}]}])))
            self.assertFalse(module.decide(f, "success", True)[1])

    def test_multiple_runs_counted(self):
        r = report([{"level": "warning"}])
        r["runs"].append(report([{"level": "error"}])["runs"][0])
        self.assertEqual(module.assess(r).candidate, 2)


if __name__ == "__main__":
    unittest.main()
