"""Independent review of caller boundaries, baselines and unresolved scope."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import yaml

from src.auditor import make_report
from src.policy import write_baseline


class TestIndependentDeepIntegrationReview(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def document(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(content, sort_keys=False), encoding="utf-8")
        return path

    def reusable(self, script='echo "${{ inputs.title }}"'):
        return self.document(".github/workflows/reusable.yml", {
            "on": {"workflow_call": {"inputs": {"title": {"type": "string"}}}},
            "jobs": {"consume": {"runs-on": "ubuntu-latest", "steps": [{"run": script}]}},
        })

    def caller(self, field="title", **extra):
        return self.document(".github/workflows/caller.yml", {
            "on": "pull_request",
            "jobs": {"call": {"uses": "./.github/workflows/reusable.yml",
                               "with": {"title": "${{ github.event.pull_request." + field + " }}"}}},
            **extra,
        })

    def deep(self, target, **kwargs):
        return make_report(target, deep=True, repo_root=self.root, **kwargs)

    def test_default_direct_bracket_context_is_detected_as_source(self):
        target = self.document(".github/workflows/direct.yml", {
            "on": "pull_request",
            "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{
                "run": 'echo "${{ github[\'event\'][\'pull_request\'][\'title\'] }}"',
            }]}},
        })
        report = make_report(target)
        self.assertEqual(report["errors"], [])
        self.assertIn("CHA002", {finding["rule_id"] for finding in report["findings"]})
        self.assertNotIn("CHA023", {finding["rule_id"] for finding in report["findings"]})

    def test_finite_predicates_and_unused_format_arguments_do_not_generate_source(self):
        for expression in ("contains(github.event.pull_request.title, 'ok')",
                           "format('fixed', github.event.pull_request.title)",
                           "format('{1}', github.event.pull_request.title, 'safe')"):
            with self.subTest(expression=expression):
                target = self.document(".github/workflows/direct.yml", {
                    "on": "pull_request",
                    "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{
                        "run": 'echo "${{ ' + expression + ' }}"',
                    }]}},
                })
                report = make_report(target)
                self.assertEqual(report["errors"], [])
                self.assertFalse({finding["rule_id"] for finding in report["findings"]} & {"CHA002", "CHA023"})

    def test_caller_edit_invalidates_unchanged_callee_baseline(self):
        callee = self.reusable()
        before_bytes = callee.read_bytes()
        caller = self.caller()
        report = self.deep(caller)
        self.assertFalse(report["errors"])
        self.assertTrue(any(f["rule_id"] == "CHA023" for f in report["findings"]))
        baseline = self.root / "baseline.json"
        write_baseline(baseline, report)
        existing = self.deep(caller, baseline_file=baseline)
        self.assertGreater(existing["existing_findings_count"], 0)
        self.caller(field="body")
        changed = self.deep(caller, baseline_file=baseline)
        self.assertEqual(callee.read_bytes(), before_bytes)
        self.assertNotEqual(report["analysis"]["source_digest"], changed["analysis"]["source_digest"])
        self.assertGreater(changed["new_findings_count"], 0)
        self.assertEqual(changed["existing_findings_count"], 0)

    def test_caller_workflow_env_does_not_leak_into_reusable_workflow(self):
        self.reusable(script='echo "${{ env.TITLE }}"')
        caller = self.caller(env={"TITLE": "${{ github.event.pull_request.title }}"})
        report = self.deep(caller)
        self.assertEqual(report["errors"], [])
        self.assertFalse(any(f["rule_id"] == "CHA023" for f in report["findings"]))

    def test_composite_does_not_invent_input_environment_variables(self):
        self.document(".github/actions/example/action.yml", {
            "name": "No implicit input env",
            "inputs": {"title": {}},
            "runs": {"using": "composite", "steps": [{"shell": "bash", "run": 'echo "${{ env.INPUT_TITLE }}"'}]},
        })
        caller = self.document(".github/workflows/caller.yml", {
            "on": "pull_request",
            "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{
                "uses": "./.github/actions/example",
                "with": {"title": "${{ github.event.pull_request.title }}"},
            }]}},
        })
        report = self.deep(caller)
        self.assertFalse(report["errors"])
        self.assertEqual(report["files_scanned"], 2)
        self.assertFalse(any(f["rule_id"] == "CHA023" for f in report["findings"]))

    def test_unknown_remote_reference_is_retained_without_network_execution(self):
        caller = self.document(".github/workflows/caller.yml", {
            "on": "push",
            "jobs": {"build": {"runs-on": "ubuntu-latest", "steps": [{
                "uses": "example/action@" + "a" * 40,
            }]}},
        })
        relaxed = self.deep(caller)
        self.assertEqual(relaxed["errors"], [])
        self.assertEqual(relaxed["findings_count"], 0)
        self.assertTrue(relaxed["analysis"]["unresolved_references"])
        strict = self.deep(caller, fail_on_unresolved=True)
        self.assertTrue(strict["errors"])
        self.assertEqual(strict["findings_count"], 0)

    def test_trace_does_not_disclose_unrelated_literal_environment_value(self):
        self.reusable()
        marker = "DEMO_UNRELATED_LITERAL_MUST_NOT_APPEAR"
        caller = self.caller(env={"APP_LABEL": marker})
        report = self.deep(caller)
        self.assertFalse(report["errors"])
        self.assertTrue(any(f["rule_id"] == "CHA023" for f in report["findings"]))
        self.assertNotIn(marker, json.dumps(report))
