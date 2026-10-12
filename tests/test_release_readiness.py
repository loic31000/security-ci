"""Fail-closed release checks: never conflate successful CI with proof of safety."""
import importlib.util
import unittest
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "scripts/release_readiness.py"
spec = importlib.util.spec_from_file_location("readiness", FILE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

SHA = "a" * 40
RUN = "https://github.com/loic31000/security-ci/actions/runs/38128635719"
LOCAL_RUN = "https://github.com/loic31000/local-agents/actions/runs/12345"


def evidence():
    return {
        "security_ci_commit": SHA,
        "stability_runs": [
            {
                "url": f"https://github.com/loic31000/security-ci/actions/runs/{1000 + index}",
                "commit": SHA,
                "attempt": 1,
                "conclusion": "success",
                "semgrep": "success",
            }
            for index in range(3)
        ],
        "checks": {name: "success" for name in module.EXPECTED_CHECKS},
        "junit_cases": 58,
        "engine_coverage": {"state": "SCANNED", "targets": ["python", "node", "go"]},
        "sbom_components": 1,
        "positive_controls": {name: True for name in module.SCANNERS},
        "benign_controls": {name: True for name in module.BENIGN},
        "external_trial": {
            "repo": "loic31000/local-agents",
            "branch": "audit/security-ci-fp-validation",
            "status": "success", "merged": False, "commit": SHA,
            "security_ci_ref": SHA,
            "executed_jobs": {
                name: {"conclusion": "success", "runner_name": "Hosted Runner",
                       "steps_executed": 4}
                for name in module.EXTERNAL_JOBS
            },
            "go_tests_passed": 3,
            "trivy_targets": 2,
            "reports_verified": {name: True for name in module.EXTERNAL_REPORTS},
        },
        "security_ci_run_url": RUN,
        "tests_run_url": RUN,
        "engine_run_url": RUN,
        "external_run_url": LOCAL_RUN,
        "human_cve_reviewed": True,
    }


class ReleaseReadinessTest(unittest.TestCase):
    def test_complete_consistent_evidence_can_qualify(self):
        self.assertEqual(module.validate(evidence()), [])

    def test_stability_requires_three_distinct_successes_on_first_attempt(self):
        for mutation in ("missing", "two", "duplicate", "retried", "wrong_commit",
                         "semgrep_failed", "bad_url"):
            record = evidence()
            runs = record["stability_runs"]
            if mutation == "missing":
                del record["stability_runs"]
            elif mutation == "two":
                runs.pop()
            elif mutation == "duplicate":
                runs[2]["url"] = runs[0]["url"]
            elif mutation == "retried":
                runs[1]["attempt"] = 2
            elif mutation == "wrong_commit":
                runs[1]["commit"] = "b" * 40
            elif mutation == "semgrep_failed":
                runs[1]["semgrep"] = "failure"
            else:
                runs[1]["url"] = "https://example.org/actions/runs/123"
            with self.subTest(mutation=mutation):
                self.assertTrue(module.validate(record))

    def test_bool_attempt_cannot_masquer_retry(self):
        record = evidence()
        record["stability_runs"][0]["attempt"] = True
        self.assertTrue(module.validate(record))

    def test_missing_external_trial_cannot_be_overridden_by_ci(self):
        record = evidence()
        del record["external_trial"]
        self.assertTrue(any("local-agents" in x for x in module.validate(record)))

    def test_merged_external_branch_is_never_acceptable(self):
        record = evidence()
        record["external_trial"]["merged"] = True
        self.assertTrue(module.validate(record))
        record = evidence()
        record["external_trial"]["branch"] = "main"
        self.assertTrue(module.validate(record))

    def test_failed_allocation_is_never_a_successful_external_trial(self):
        for scanner in module.EXTERNAL_JOBS:
            record = evidence()
            record["external_trial"]["executed_jobs"][scanner]["steps_executed"] = 0
            with self.subTest(scanner=scanner):
                self.assertTrue(any("runner" in x for x in module.validate(record)))
            record = evidence()
            record["external_trial"]["executed_jobs"][scanner]["runner_name"] = ""
            with self.subTest(scanner=scanner, case="no runner"):
                self.assertTrue(any("runner" in x for x in module.validate(record)))

    def test_all_external_jobs_must_have_succeeded(self):
        record = evidence()
        record["external_trial"]["executed_jobs"].pop("trivy")
        self.assertTrue(any("trivy job" in x for x in module.validate(record)))
        record = evidence()
        record["external_trial"]["executed_jobs"]["go_tests"]["conclusion"] = "failure"
        self.assertTrue(any("go_tests job" in x for x in module.validate(record)))

    def test_real_go_tests_and_trivy_targets_required(self):
        for field in ("go_tests_passed", "trivy_targets"):
            for count in (0, -1, True, "1", None):
                record = evidence()
                record["external_trial"][field] = count
                with self.subTest(field=field, count=count):
                    self.assertTrue(any(field in x for x in module.validate(record)))

    def test_external_scan_reports_and_pinned_engine_required(self):
        record = evidence()
        record["external_trial"]["security_ci_ref"] = "b" * 40
        self.assertTrue(any("pin" in x for x in module.validate(record)))
        for scanner in module.EXTERNAL_REPORTS:
            record = evidence()
            record["external_trial"]["reports_verified"][scanner] = False
            with self.subTest(scanner=scanner):
                self.assertTrue(any("reports" in x for x in module.validate(record)))

    def test_nonzero_alerts_dont_replace_manual_cve_review(self):
        record = evidence()
        record["human_cve_reviewed"] = False
        self.assertTrue(any("CVE" in x for x in module.validate(record)))

    def test_each_missing_control_or_failed_check_fails(self):
        for scanner in module.BENIGN:
            record = evidence()
            record["benign_controls"][scanner] = False
            with self.subTest(scanner=scanner):
                self.assertTrue(any("benign" in x for x in module.validate(record)))
        for check in module.EXPECTED_CHECKS:
            record = evidence()
            record["checks"][check] = "failure"
            with self.subTest(check=check):
                self.assertTrue(any("check" in x for x in module.validate(record)))

    def test_no_unexecuted_tests_or_unscanned_dependencies(self):
        record = evidence()
        record["junit_cases"] = 0
        record["engine_coverage"]["state"] = "NOT_APPLICABLE"
        record["engine_coverage"]["targets"] = []
        record["sbom_components"] = 0
        self.assertGreaterEqual(len(module.validate(record)), 3)

    def test_fake_unsupported_provenance_is_rejected(self):
        record = evidence()
        record["security_ci_commit"] = "not-a-sha"
        record["external_run_url"] = "https://example.org/fake"
        self.assertGreaterEqual(len(module.validate(record)), 2)


if __name__ == "__main__":
    unittest.main()
