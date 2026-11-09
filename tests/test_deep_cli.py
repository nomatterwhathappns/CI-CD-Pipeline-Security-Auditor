# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 nomatterwhathappns
"""Exercise report integration, gates, policies, and deep source identities."""

from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from src.auditor import main


class TestDeepCLI(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workflow = self.root / ".github/workflows/ci.yml"
        self.action = self.root / ".github/actions/check/action.yml"
        self.workflow.parent.mkdir(parents=True)
        self.action.parent.mkdir(parents=True)
        self.workflow.write_text("on: pull_request\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/check\n        with:\n          title: ${{ github.event.pull_request.title }}\n", encoding="utf-8")
        self.action.write_text("name: Check\ninputs:\n  title: {}\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo \"${{ inputs.title }}\"\n", encoding="utf-8")

    def cli(self, *args, output_format="json"):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = main([str(self.workflow), "--format", output_format, *map(str, args)])
        return status, json.loads(stdout.getvalue())

    def deep(self, *args, **kwargs):
        return self.cli("--deep", "--repo-root", self.root, *args, **kwargs)

    def test_deep_reaches_local_source_and_reports_trace(self):
        status, report = self.deep("--fail-on-findings")
        self.assertEqual(status, 1)
        self.assertEqual(report["schema_version"], "1.3")
        self.assertEqual(report["files_scanned"], 2)
        self.assertEqual(report["analysis"]["mode"], "deep")
        self.assertEqual(len(report["analysis"]["edges"]), 1)
        self.assertEqual(report["analysis"]["unresolved_references"], [])
        self.assertEqual({f["rule_id"] for f in report["findings"]}, {"CHA023"})
        finding = report["findings"][0]
        self.assertEqual(finding["file"], str(self.action))
        self.assertTrue(finding["dataflow_trace"])
        self.assertTrue(finding["analysis_digest"])

    def test_regular_mode_does_not_read_local_action_body(self):
        status, report = self.cli("--fail-on-findings")
        self.assertEqual(status, 0)
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(report["findings"], [])

    def test_unresolved_remote_is_visible_and_can_be_a_strict_error(self):
        self.workflow.write_text("on: push\njobs:\n  check:\n    steps:\n      - uses: owner/action@" + "a" * 40 + "\n", encoding="utf-8")
        status, report = self.deep("--fail-on-findings")
        self.assertEqual(status, 0)
        self.assertEqual(report["findings_count"], 0)
        self.assertEqual(len(report["analysis"]["unresolved_references"]), 1)
        status, report = self.deep("--fail-on-unresolved")
        self.assertEqual(status, 2)
        self.assertTrue(report["errors"])

    def test_deep_options_require_explicit_deep_mode(self):
        for option in (["--repo-root", str(self.root)], ["--fail-on-unresolved"]):
            with self.subTest(option=option), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    main([str(self.workflow), *option])
                self.assertEqual(caught.exception.code, 2)

    def test_baseline_rechecks_callee_when_caller_changes(self):
        baseline = self.root / "baseline.json"
        self.deep("--write-baseline", baseline)
        status, report = self.deep("--baseline", baseline, "--fail-on-findings")
        self.assertEqual(status, 0)
        self.assertEqual(report["existing_findings_count"], 1)
        self.workflow.write_text(self.workflow.read_text() + "# caller changed\n", encoding="utf-8")
        status, report = self.deep("--baseline", baseline, "--fail-on-findings")
        self.assertEqual(status, 1)
        self.assertEqual(report["new_findings_count"], 1)

    def test_scoped_exception_uses_the_actual_callee_file(self):
        config = self.root / "policy.json"
        config.write_text(json.dumps({"version": 1, "suppressions": [{
            "rule_id": "CHA023", "file": ".github/actions/check/action.yml", "job": "composite", "step": 1,
            "reason": "Temporary reviewed example exception", "expires": "2099-12-31"}]}), encoding="utf-8")
        status, report = self.deep("--config", config, "--fail-on-findings")
        self.assertEqual(status, 0)
        self.assertEqual(report["findings_count"], 0)
        self.assertEqual(report["suppressed_findings_count"], 1)

    def test_deep_flow_reaches_sarif_codeflow(self):
        status, sarif = self.deep("--fail-on-findings", output_format="sarif")
        self.assertEqual(status, 1)
        run = sarif["runs"][0]
        self.assertEqual(run["properties"]["analysis"]["mode"], "deep")
        self.assertTrue(run["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"])
        self.assertTrue(run["invocations"][0]["executionSuccessful"])

    def test_no_source_values_in_trace_or_parser_error(self):
        marker = "DEMO_PRIVATE_LITERAL_DO_NOT_REPORT"
        self.action.write_text(self.action.read_text() + "env:\n  TOKEN: " + marker + "\n", encoding="utf-8")
        _, report = self.deep()
        self.assertNotIn(marker, json.dumps(report))
        self.action.write_text('runs: "' + marker, encoding="utf-8")
        status, report = self.deep()
        self.assertEqual(status, 2)
        self.assertNotIn(marker, json.dumps(report))


class TestDeepExamples(unittest.TestCase):
    def test_three_file_examples_distinguish_script_source_from_data(self):
        root = Path(__file__).resolve().parents[1] / "fixtures/deep/demo"
        for variant, expected_status in (("bad", 1), ("good", 0)):
            with self.subTest(variant=variant):
                stdout = io.StringIO()
                entry = root / ".github/workflows" / f"entry-{variant}.yml"
                with redirect_stdout(stdout):
                    status = main([str(entry), "--deep", "--repo-root", str(root),
                                   "--format", "json", "--fail-on-findings"])
                report = json.loads(stdout.getvalue())
                self.assertEqual(status, expected_status)
                self.assertEqual(report["files_scanned"], 3)
                self.assertEqual(report["errors"], [])
                self.assertEqual(report["analysis"]["unresolved_references"], [])
                self.assertEqual({finding["rule_id"] for finding in report["findings"]},
                                 {"CHA023"} if variant == "bad" else set())
