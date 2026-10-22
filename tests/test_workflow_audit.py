import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from src.auditor import audit_file


FIXTURES = (
    Path(__file__).resolve().parent.parent
    / "fixtures"
    / "workflows"
)


class TestWorkflowAudit(unittest.TestCase):
    def scan_fixture(self, filename):
        output = io.StringIO()

        with redirect_stdout(output):
            findings = audit_file(FIXTURES / filename)

        return findings, output.getvalue()

    def test_inline_workflow_reports_both_rules(self):
        findings, output = self.scan_fixture("insecure-example.yml")

        self.assertEqual(findings, 2)
        self.assertIn("action actions/checkout@v4", output)
        self.assertIn("data PR dipakai langsung", output)
        self.assertIn("WARNING [GHA001]:", output)
        self.assertIn("WARNING [GHA002]:", output)

    def test_multiline_run_reports_pr_data(self):
            findings, output = self.scan_fixture("multiline-example.yml")

            self.assertEqual(findings, 1)
            self.assertIn("data PR dipakai langsung", output)
            self.assertIn("job=example, langkah=1", output)
            self.assertIn("WARNING [GHA002]:", output)
            self.assertNotIn("WARNING [GHA001]:", output)

    def test_clean_workflow_has_no_findings(self):
        findings, output = self.scan_fixture("clean-example.yml")

        self.assertEqual(findings, 0)
        self.assertEqual(output, "")
