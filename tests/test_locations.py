# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 nomatterwhathappns
"""Source scopes, parser preservation, and implicitly pinned self references."""

from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import yaml

from src.engine import (
    AuditError,
    action_is_unpinned,
    collect_findings,
    load_workflow,
    print_text_findings,
)
from src.rules.common import RuleContext


ROOT = Path(__file__).resolve().parent.parent


class TestSourceLocations(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "workflow.yml"

    def write(self, text):
        self.path.write_text(text, encoding="utf-8")
        return self.path

    def test_findings_point_to_the_enclosing_workflow_job_and_step(self):
        path = self.write(
            "name: Scope locations\n"
            "on: push\n"
            "permissions: write-all\n"
            "jobs:\n"
            "  build:\n"
            "    permissions: write-all\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - name: Checkout\n"
            "        uses: actions/checkout@v4\n"
        )
        findings = collect_findings(path)
        self.assertEqual(
            [(f["rule_id"], f["line"], f["column"], f["location_scope"])
             for f in findings],
            [("CHA003", 1, 1, "workflow"),
             ("CHA003", 6, 5, "job"),
             ("CHA001", 9, 9, "step")],
        )

    def test_multiline_command_uses_step_start_and_does_not_disclose_source(self):
        marker = "DEMO_NOT_A_REAL_SECRET_VALUE"
        path = self.write(
            "# A leading comment\n"
            "on: pull_request\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - name: Check title\n"
            "        run: |\n"
            f"          echo {marker}\n"
            '          echo "${{ github.event.pull_request.title }}"\n'
        )
        finding, = collect_findings(path)
        self.assertEqual((finding["line"], finding["column"]), (7, 9))
        self.assertEqual(finding["location_scope"], "step")
        self.assertNotIn(marker, json.dumps(finding))

    def test_alias_findings_point_to_the_original_anchor_definition(self):
        path = self.write(
            "on: push\n"
            "jobs:\n"
            "  first:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps: &shared\n"
            "      - uses: owner/action@v1\n"
            "  second:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps: *shared\n"
        )
        findings = collect_findings(path)
        self.assertEqual([f["job"] for f in findings], ["first", "second"])
        self.assertEqual([(f["line"], f["column"]) for f in findings], [(6, 9)] * 2)

    def test_metadata_is_not_inserted_into_workflow_data_or_global_loader(self):
        path = self.write(
            "on: push\n"
            "jobs: {build: {steps: [{uses: owner/action@v1}]}}\n"
        )
        before = path.read_bytes()
        workflow = load_workflow(path)
        self.assertEqual(set(workflow), {"on", "jobs"})
        self.assertNotIn("source_line", json.dumps(workflow))
        self.assertNotIn("source_digest", json.dumps(workflow))
        self.assertEqual(type(yaml.safe_load("key: value")), dict)
        self.assertEqual(path.read_bytes(), before)

    def test_digest_binds_to_the_exact_bytes_that_were_parsed(self):
        path = self.write(
            "on: push\n"
            "jobs: {build: {steps: [{uses: owner/action@v1}]}}\n"
        )
        original_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        original, = collect_findings(path)
        self.assertEqual(original["source_digest"], original_digest)
        self.write(path.read_text(encoding="utf-8") + "# A changed input\n")
        updated, = collect_findings(path)
        self.assertNotEqual(updated["source_digest"], original_digest)

    def test_text_report_includes_the_source_coordinates(self):
        path = self.write(
            "on: push\n"
            "jobs: {build: {steps: [{uses: owner/action@v1}]}}\n"
        )
        finding, = collect_findings(path)
        output = io.StringIO()
        with redirect_stdout(output):
            print_text_findings([finding])
        self.assertIn(f"{path}:{finding['line']}:{finding['column']}:", output.getvalue())

    def test_all_existing_bad_fixture_findings_have_valid_scope_coordinates(self):
        for path in sorted((ROOT / "fixtures" / "rules").glob("CHA*-bad.yml")):
            source_lines = path.read_text(encoding="utf-8").splitlines()
            for finding in collect_findings(path):
                with self.subTest(file=path.name, rule=finding["rule_id"]):
                    self.assertGreaterEqual(finding["line"], 1)
                    self.assertLessEqual(finding["line"], len(source_lines))
                    self.assertGreaterEqual(finding["column"], 1)
                    self.assertLessEqual(finding["column"], len(source_lines[finding["line"] - 1]) + 1)
                    self.assertRegex(finding["source_digest"], r"^[a-f0-9]{64}$")

    def test_source_marks_do_not_bypass_duplicate_or_merge_key_rejection(self):
        for text in (
            "on: push\non: pull_request\njobs: {}\n",
            "base: &base {run: echo ok}\njobs: {build: {steps: [{<<: *base}]}}\n",
        ):
            with self.subTest(text=text), self.assertRaises(AuditError):
                load_workflow(self.write(text))

    def test_synthetic_rule_context_has_a_documented_location_fallback(self):
        context = RuleContext(Path("synthetic.yml"), {"jobs": {"build": {"steps": [{}]}}})
        context.emit("CHA001", "Synthetic case", job="build", step=1)
        finding, = context.findings
        self.assertEqual((finding["line"], finding["column"], finding["location_scope"]), (1, 1, "step"))


class TestSelfRepositoryReferences(unittest.TestCase):
    def test_self_repository_paths_are_implicitly_pinned(self):
        for reference in (
            "$/actions/local-action",
            "$/nested/action/path",
            "$/.github/workflows/reusable.yml",
        ):
            with self.subTest(reference=reference):
                self.assertFalse(action_is_unpinned(reference))

    def test_remote_references_still_require_a_complete_sha(self):
        for reference in ("owner/action@v1", "owner/action@main", "owner/action", "owner/action@" + "a" * 39):
            with self.subTest(reference=reference):
                self.assertTrue(action_is_unpinned(reference))
        self.assertFalse(action_is_unpinned("owner/action@" + "a" * 40))

    def test_workflow_supports_both_self_repository_actions_and_reusable_jobs(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "workflow.yml"
            path.write_text(
                "on: push\n"
                "jobs:\n"
                "  local-action:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps: [{uses: '$/actions/local-action'}]\n"
                "  local-workflow:\n"
                "    uses: '$/.github/workflows/reusable.yml'\n",
                encoding="utf-8",
            )
            self.assertEqual(collect_findings(path), [])


if __name__ == "__main__":
    unittest.main()
