import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from src.auditor import audit_file


class TestPermissions(unittest.TestCase):
    def scan_permissions(self, workflow_permissions=None, job_permissions=None):
        workflow = {
            "name": "Permissions Test",
            "on": "push",
            "jobs": {
                "example": {
                    "runs-on": "ubuntu-latest",
                    "steps": [{"run": "echo test"}],
                }
            },
        }

        if workflow_permissions is not None:
            workflow["permissions"] = workflow_permissions

        if job_permissions is not None:
            workflow["jobs"]["example"]["permissions"] = job_permissions

        output = io.StringIO()

        with TemporaryDirectory() as folder:
            path = Path(folder) / "workflow.yml"
            path.write_text(yaml.safe_dump(workflow), encoding="utf-8")

            with redirect_stdout(output):
                findings = audit_file(path)

        return findings, output.getvalue()

    def test_workflow_write_all_is_reported(self):
        findings, output = self.scan_permissions(
            workflow_permissions="write-all"
        )

        self.assertEqual(findings, 1)
        self.assertIn("WARNING [CHA003]:", output)
        self.assertIn("level=workflow", output)
        self.assertNotIn("job=example", output)

    def test_job_write_all_is_reported(self):
        findings, output = self.scan_permissions(
            job_permissions="write-all"
        )

        self.assertEqual(findings, 1)
        self.assertIn("WARNING [CHA003]:", output)
        self.assertIn("job=example", output)
        self.assertNotIn("level=workflow", output)

    def test_both_declarations_are_reported(self):
        findings, output = self.scan_permissions(
            workflow_permissions="write-all",
            job_permissions="write-all",
        )

        self.assertEqual(findings, 2)
        self.assertEqual(output.count("[CHA003]"), 2)
        self.assertIn("level=workflow", output)
        self.assertIn("job=example", output)

    def test_other_settings_are_not_flagged_by_this_rule(self):
        cases = [
            (None, None),
            ("read-all", None),
            ({}, None),
            ({"contents": "read"}, None),
            ({"contents": "write"}, None),
            (None, "read-all"),
            (None, {}),
            (None, {"contents": "read"}),
            (None, {"contents": "write"}),
        ]

        for workflow_permissions, job_permissions in cases:
            with self.subTest(
                workflow=workflow_permissions,
                job=job_permissions,
            ):
                findings, output = self.scan_permissions(
                    workflow_permissions,
                    job_permissions,
                )

                self.assertEqual(findings, 0)
                self.assertEqual(output, "")
