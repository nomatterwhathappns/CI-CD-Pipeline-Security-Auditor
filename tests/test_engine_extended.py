"""Regression tests for parser safety, CLI policy and stable reports."""

import io
import json
import os
from pathlib import Path
import subprocess
import sys
from contextlib import redirect_stdout, redirect_stderr
from tempfile import TemporaryDirectory
import unittest

import yaml

from src.auditor import main, make_report
from src.engine import AuditError, collect_findings, load_workflow
from src.registry import RULES


ROOT = Path(__file__).resolve().parent.parent


class TestExtendedEngine(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def write(self, text, name="workflow.yml"):
        path = self.folder / name
        path.write_text(text, encoding="utf-8")
        return path

    def workflow(self, **changes):
        data = {
            "name": "Regression",
            "on": "push",
            "jobs": {"test": {
                "runs-on": "ubuntu-latest",
                "steps": [{"run": "echo ok"}],
            }},
        }
        data.update(changes)
        return data

    def write_data(self, data):
        return self.write(yaml.safe_dump(data))

    def cli(self, *args):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = main([str(arg) for arg in args])
        return status, json.loads(stdout.getvalue())

    def test_on_off_yes_remain_strings_and_true_is_boolean(self):
        path = self.write(
            "on: pull_request\n"
            "env: {MODE: off, ANSWER: yes, ENABLED: true}\n"
            "jobs: {test: {runs-on: ubuntu-latest, steps: [{run: echo ok}]}}\n"
        )
        data = load_workflow(path)
        self.assertEqual(data["on"], "pull_request")
        self.assertEqual(data["env"]["MODE"], "off")
        self.assertEqual(data["env"]["ANSWER"], "yes")
        self.assertIs(data["env"]["ENABLED"], True)

    def test_duplicate_keys_are_rejected_without_value_disclosure(self):
        marker = "DEMO_DUPLICATE_SECRET_VALUE"
        path = self.write("on: push\non: " + marker + "\n")
        with self.assertRaises(AuditError) as caught:
            load_workflow(path)
        self.assertNotIn(marker, str(caught.exception))

    def test_merge_alias_expansion_is_rejected_before_expansion(self):
        lines = ["a0: &a0 {x: value}"]
        lines += [f"a{i}: &a{i} {{<<: [*a{i-1}, *a{i-1}]}}" for i in range(1, 23)]
        lines += ["<<: *a22", "jobs: {test: {steps: [{run: echo ok}]}}"]
        path = self.write("\n".join(lines))
        with self.assertRaisesRegex(AuditError, "merge keys"):
            load_workflow(path)

    def test_regular_anchors_are_supported(self):
        path = self.write(
            "on: push\n"
            "jobs:\n"
            "  first:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps: &steps\n"
            "      - run: echo ok\n"
            "  second:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps: *steps\n"
        )
        self.assertEqual(collect_findings(path), [])

    def test_excessive_nesting_and_alias_count_are_rejected(self):
        path = self.write("extra: " + "[" * 60 + "0" + "]" * 60)
        with self.assertRaises(AuditError):
            load_workflow(path)
        path = self.write("a: &a value\nb: [" + ",".join(["*a"] * 51) + "]")
        with self.assertRaises(AuditError):
            load_workflow(path)

    def test_non_utf8_and_oversized_workflows_are_input_errors(self):
        path = self.folder / "bad.yml"
        path.write_bytes(b"\xff\xfe")
        with self.assertRaises(AuditError):
            load_workflow(path)
        path.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
        with self.assertRaises(AuditError):
            load_workflow(path)

    def test_yaml_error_does_not_echo_candidate_secret_in_json_or_text(self):
        marker = "DEMO_PRIVATE_PAYLOAD_DO_NOT_LOG"
        path = self.write('env:\n  PASSWORD: "' + marker + '\njobs: [\n')
        status, report = self.cli(path, "--format", "json")
        self.assertEqual(status, 2)
        self.assertNotIn(marker, json.dumps(report))
        output = io.StringIO()
        with redirect_stdout(output):
            status = main([str(path)])
        self.assertEqual(status, 2)
        self.assertNotIn(marker, output.getvalue())

    def test_malformed_job_uses_cannot_crash_json_output(self):
        for value in (123, True, [], {}):
            with self.subTest(value=value):
                data = self.workflow()
                data["jobs"]["test"]["uses"] = value
                status, report = self.cli(self.write_data(data), "--format", "json")
                self.assertEqual(status, 2)
                self.assertEqual(report["files_scanned"], 0)

    def test_job_uses_and_steps_are_not_combined(self):
        data = self.workflow()
        data["jobs"]["test"]["uses"] = "owner/repo/.github/workflows/test.yml@v1"
        self.assertTrue(make_report(self.write_data(data))["errors"])

    def test_binary_service_ids_and_surrogate_env_names_are_rejected(self):
        path = self.write(
            "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
            "    services:\n      !!binary ZGI=:\n        image: postgres:17\n"
            "    steps: [{run: echo ok}]\n"
        )
        status, report = self.cli(path, "--format", "json")
        self.assertEqual(status, 2)
        path = self.write(
            'env: {"PASSWORD_\\uD800": literal}\n'
            "jobs: {test: {steps: [{run: echo ok}]}}\n"
        )
        status, report = self.cli(path, "--format", "json")
        self.assertEqual(status, 2)

    def test_invalid_env_and_with_types_are_input_errors(self):
        for bad_env in ([], "not-an-expression", {"TOKEN": {}}):
            with self.subTest(env=bad_env):
                data = self.workflow(env=bad_env)
                self.assertTrue(make_report(self.write_data(data))["errors"])
        data = self.workflow()
        data["jobs"]["test"]["steps"][0]["with"] = []
        self.assertTrue(make_report(self.write_data(data))["errors"])

    def test_quoted_source_name_is_not_an_untrusted_expression(self):
        data = self.workflow()
        data["jobs"]["test"]["steps"][0]["run"] = "echo \"${{ 'github.event.pull_request.title' }}\""
        findings = collect_findings(self.write_data(data))
        self.assertNotIn("CHA002", {finding["rule_id"] for finding in findings})

    def test_quoted_closing_braces_do_not_hide_real_source(self):
        data = self.workflow()
        data["jobs"]["test"]["steps"][0]["run"] = "echo \"${{ format('}}{0}', github.event.pull_request.title) }}\""
        findings = collect_findings(self.write_data(data))
        self.assertIn("CHA002", {finding["rule_id"] for finding in findings})

    def test_input_scripts_are_never_executed(self):
        marker = self.folder / "must-not-exist"
        data = self.workflow()
        data["jobs"]["test"]["steps"][0]["run"] = f"touch {marker}"
        collect_findings(self.write_data(data))
        self.assertFalse(marker.exists())

    def test_python_yaml_tags_are_rejected_without_execution(self):
        marker = self.folder / "yaml-must-not-execute"
        path = self.write(f"!!python/object/apply:os.system ['touch {marker}']")
        status, report = self.cli(path, "--format", "json")
        self.assertEqual(status, 2)
        self.assertFalse(marker.exists())
        self.assertNotIn("object/apply", json.dumps(report))

    def test_collection_is_silent_and_contains_rule_metadata(self):
        data = self.workflow(permissions="write-all")
        output = io.StringIO()
        with redirect_stdout(output):
            findings = collect_findings(self.write_data(data))
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertIn("confidence", findings[0])
        self.assertIn("remediation", findings[0])

    def test_ignore_policy_is_reported_and_does_not_mutate_input(self):
        path = self.write_data(self.workflow(permissions="write-all"))
        before = path.read_bytes()
        status, report = self.cli(path, "--format", "json", "--fail-on-findings", "--ignore", "cha003")
        self.assertEqual(status, 0)
        self.assertEqual(report["findings_count"], 0)
        self.assertEqual(report["rules_ignored"], ["CHA003"])
        self.assertNotIn("CHA003", report["rules_enabled"])
        self.assertEqual(path.read_bytes(), before)

    def test_severity_threshold_only_changes_failure_policy(self):
        path = self.write_data(self.workflow(permissions="write-all"))
        status, report = self.cli(path, "--format", "json", "--fail-on-findings", "--fail-on-severity", "high")
        self.assertEqual(status, 0)
        self.assertEqual(report["findings_count"], 1)
        status, _ = self.cli(path, "--format", "json", "--fail-on-findings", "--fail-on-severity", "medium")
        self.assertEqual(status, 1)

    def test_unknown_rule_is_an_argument_error(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                main(["--ignore", "CHA999"])
        self.assertEqual(caught.exception.code, 2)

    def test_rule_listing_has_all_unique_ids(self):
        status, report = self.cli("--list-rules", "--format", "json")
        self.assertEqual(status, 0)
        self.assertEqual({rule["rule_id"] for rule in report["rules"]}, set(RULES))
        self.assertEqual(len(report["rules"]), len(RULES))

    def test_empty_directory_and_wrong_extension_fail_closed(self):
        status, report = self.cli(self.folder, "--format", "json")
        self.assertEqual(status, 2)
        self.assertEqual(report["files_scanned"], 0)
        status, report = self.cli(self.write("hello", "notes.txt"), "--format", "json")
        self.assertEqual(status, 2)

    def test_symlinks_and_dependency_folders_are_not_scanned(self):
        path = self.write_data(self.workflow())
        link = self.folder / "linked.yml"
        link.symlink_to(path)
        status, report = self.cli(link, "--format", "json")
        self.assertEqual(status, 2)
        ignored = self.folder / ".venv"
        ignored.mkdir()
        (ignored / "broken.yml").write_text("jobs: [", encoding="utf-8")
        status, report = self.cli(self.folder, "--format", "json")
        self.assertEqual(status, 0)
        self.assertEqual(report["files_scanned"], 1)

    def test_custom_advisory_errors_do_not_disclose_payload(self):
        path = self.write_data(self.workflow())
        marker = "DEMO_UNTRUSTED_ADVISORY"
        advisory = self.write("[" + marker, "advisories.json")
        status, report = self.cli(path, "--format", "json", "--advisory-file", advisory)
        self.assertEqual(status, 2)
        self.assertNotIn(marker, json.dumps(report))

    def test_advisory_size_and_duplicate_keys_are_rejected(self):
        from src.rules.guards import load_advisory_data, MAX_ADVISORY_BYTES
        path = self.folder / "advisories.json"
        path.write_bytes(b"x" * (MAX_ADVISORY_BYTES + 1))
        with self.assertRaises(ValueError):
            load_advisory_data(path)
        path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            load_advisory_data(path)

    def test_module_entry_point_supports_the_same_cli(self):
        result = subprocess.run(
            [sys.executable, "-m", "src.auditor", "--list-rules", "--format", "json"],
            cwd=ROOT, capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)["rules"]), len(RULES))

    @unittest.skipUnless(os.name == "posix", "Non-UTF8 filesystem names are POSIX-specific")
    def test_non_utf8_filename_does_not_break_json_or_text(self):
        path = self.folder / os.fsdecode(b"workflow-\xff.yml")
        data = self.workflow(permissions="write-all")
        path.write_text(yaml.safe_dump(data), encoding="utf-8")
        status, report = self.cli(path, "--format", "json")
        self.assertEqual(status, 0)
        self.assertEqual(report["findings_count"], 1)
        output = io.StringIO()
        with redirect_stdout(output):
            status = main([str(path)])
        self.assertEqual(status, 0)
        self.assertIn("CHA003", output.getvalue())

