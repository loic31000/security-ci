"""Regression guard: retries must never authorize unreviewed Semgrep rules."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SemgrepRegistryRetryTest(unittest.TestCase):
    def test_bounded_retry_always_checks_approved_bundle_before_use(self):
        workflow = (ROOT / ".github/workflows/security-audit.yml").read_text(
            encoding="utf-8"
        )
        anchor = "      - name: Verify exact reviewed Semgrep rules before use"
        part = workflow.split(anchor, 1)[1].split(
            "      - name: Installer zizmor avec hachages vérifiés", 1
        )[0]
        self.assertIn("for attempt in 1 2 3; do", part)
        self.assertIn("if curl --fail --silent", part)
        self.assertIn("&&\n                python3 .audit-python-lock/scripts/verify_semgrep_bundle.py", part)
        self.assertIn(".audit-python-lock/locks/semgrep-security-audit.json", part)
        self.assertRegex(part, r'if \[\[ "\$verified" != "true" \]\]; then\s+echo .*\s+exit 1')
        self.assertGreater(
            part.index('echo "SEMGREP_CONFIG_PATH='),
            part.index('if [[ "$verified" != "true" ]]'),
        )
        self.assertNotIn("sha256sum --ignore-missing", part)
        self.assertNotIn("|| true", part)


if __name__ == "__main__":
    unittest.main()
