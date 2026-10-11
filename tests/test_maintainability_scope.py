"""Regressions for maintainability metrics and user-facing typography."""
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENERATED = (".git", ".audit-python-lock", ".audit-jscpd-tools",
             ".audit-report-tools")


class MaintainabilityScopeTest(unittest.TestCase):
    def test_jscpd_excludes_engine_checkouts_but_keeps_project_sources(self):
        source = (ROOT / ".github/workflows/security-audit.yml").read_text(
            encoding="utf-8"
        )
        step = source.split("      - name: Measure duplication", 1)[1].split(
            "      - name: Reject duplication reports", 1
        )[0]
        self.assertIn(" --mode strict --min-tokens 100 --min-lines 10 ", step)
        self.assertIn("--threshold 100", step)
        self.assertTrue(step.rstrip().endswith("' ."))
        for folder in GENERATED:
            self.assertIn(f"**/{folder}/**", step)
        self.assertIn("**/node_modules/**", step)
        self.assertIn("jscpd-report.json", source)
        self.assertIn("generated checkout included in report", source)

    def test_lizard_excludes_engine_checkouts_without_changing_radon(self):
        source = (ROOT / ".github/workflows/security-audit.yml").read_text(
            encoding="utf-8"
        )
        step = source.split("      - name: Measure multi-language complexity", 1)[1].split(
            "      - name: Reject complexity metrics", 1
        )[0]
        self.assertIn("lizard --xml .", step)
        for folder in GENERATED:
            self.assertIn(f"-x './{folder}/*'", step)
        self.assertIn("Lizard: generated checkout included in metrics", source)
        self.assertIn("radon cc . -j", source)
        self.assertIn("radon mi . -j", source)

    def test_no_decoration_em_dash_or_encoded_whitespace_in_user_docs(self):
        docs = [ROOT / "README.md"]
        docs.extend((ROOT / "docs").glob("*.md"))
        for file in docs:
            with self.subTest(file=file.name):
                content = file.read_text(encoding="utf-8")
                self.assertNotIn("\u2014", content)
                self.assertNotIn("\u00a0", content)
                self.assertIsNone(
                    re.search(r"&#(?:x20|xA0|32|160);", content, re.IGNORECASE)
                )


if __name__ == "__main__":
    unittest.main()
