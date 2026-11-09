# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 nomatterwhathappns
"""Static cross-file integration cases with bounded input and output flow."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import yaml

from src.analysis.graph import analyze_graph


SOURCE = "${{ github.event.pull_request.title }}"


def workflow(steps=None, **extra):
    return {"on": "pull_request", "jobs": {"build": {
        "runs-on": "ubuntu-latest", "steps": steps or [{"run": "echo ok"}], **extra,
    }}}


def action(steps=None, outputs=None):
    result = {"name": "Local", "inputs": {"title": {"description": "Data"}},
              "runs": {"using": "composite", "steps": steps or [
                  {"shell": "bash", "run": 'echo "${{ inputs.title }}"'},
              ]}}
    if outputs is not None:
        result["outputs"] = outputs
    return result


def reusable(output=False):
    result = {"on": {"workflow_call": {"inputs": {"title": {"type": "string"}}}},
              "jobs": {"inner": {"runs-on": "ubuntu-latest", "steps": [
                  {"run": 'echo "${{ inputs.title }}"'},
              ]}}}
    if output:
        result["on"]["workflow_call"]["outputs"] = {"title": {"value": "${{ jobs.inner.outputs.title }}"}}
        result["jobs"]["inner"]["outputs"] = {"title": "${{ steps.emit.outputs.title }}"}
        result["jobs"]["inner"]["steps"] = [{"id": "emit", "shell": "bash",
                                                "env": {"TITLE": "${{ inputs.title }}"},
                                                "run": 'echo "title=$TITLE" >> "$GITHUB_OUTPUT"'}]
    return result


class TestDeepGraph(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.entry = self.write(".github/workflows/ci.yml", workflow())

    def write(self, name, document):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        return path

    def audit(self, *entries):
        return analyze_graph(entries or [self.entry], self.root)

    @staticmethod
    def indirect(report):
        return [finding for finding in report["findings"] if finding["rule_id"] == "CHA023"]

    def test_composite_input_reaches_script_with_original_source_locations(self):
        self.write(".github/workflows/ci.yml", workflow([
            {"uses": "./.github/actions/title", "with": {"title": SOURCE}},
        ]))
        target = self.write(".github/actions/title/action.yml", action())
        result = self.audit()
        self.assertEqual(result["errors"], [])
        findings = self.indirect(result)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["file"], str(target))
        self.assertGreater(findings[0]["line"], 1)
        self.assertEqual(findings[0]["analysis_call_path"], [str(self.entry), str(target)])
        self.assertEqual(set(result["source_digests"]), {str(self.entry), str(target)})

    def test_safe_and_untrusted_calls_to_same_file_do_not_share_input_state(self):
        self.write(".github/workflows/ci.yml", workflow([
            {"uses": "./.github/actions/title", "with": {"title": "constant"}},
            {"uses": "./.github/actions/title", "with": {"title": SOURCE}},
        ]))
        self.write(".github/actions/title/action.yml", action())
        result = self.audit()
        self.assertEqual(result["errors"], [])
        self.assertEqual(len(self.indirect(result)), 1)
        self.assertEqual(len(result["files_analyzed"]), 2)
        self.assertGreaterEqual(result["contexts_analyzed"], 3)

    def test_composite_input_is_not_an_automatic_input_environment_variable(self):
        self.write(".github/workflows/ci.yml", workflow([
            {"uses": "./.github/actions/title", "with": {"title": SOURCE}},
        ]))
        self.write(".github/actions/title/action.yml", action([
            {"shell": "bash", "run": 'echo "${{ env.INPUT_TITLE }}"'},
        ]))
        self.assertEqual(self.indirect(self.audit()), [])

    def test_composite_inherits_explicit_caller_environment_taint(self):
        self.write(".github/workflows/ci.yml", workflow([
            {"uses": "./.github/actions/title", "env": {"TITLE": SOURCE}},
        ]))
        self.write(".github/actions/title/action.yml", action([
            {"shell": "bash", "run": 'echo "${{ env.TITLE }}"'},
        ]))
        self.assertEqual(len(self.indirect(self.audit())), 1)

    def test_definitely_disabled_calls_are_not_followed(self):
        self.write(".github/workflows/ci.yml", workflow([
            {"uses": "./missing", "if": False, "with": {"title": SOURCE}},
            {"uses": "./also-missing", "if": "${{ false }}", "with": {"title": SOURCE}},
        ]))
        result = self.audit()
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["edges"], [])
        self.assertEqual(self.indirect(result), [])

    def test_reusable_workflow_receives_only_explicit_input_taint(self):
        self.write(".github/workflows/ci.yml", {"on": "pull_request", "env": {"TITLE": SOURCE},
                                                "jobs": {"call": {"uses": "./.github/workflows/reusable.yml"}}})
        self.write(".github/workflows/reusable.yml", {"on": {"workflow_call": {}}, "jobs": {
            "inner": {"runs-on": "ubuntu-latest", "steps": [{"run": 'echo "${{ env.TITLE }}"'}]},
        }})
        self.assertEqual(self.indirect(self.audit()), [])
        self.write(".github/workflows/ci.yml", {"on": "pull_request", "jobs": {
            "call": {"uses": "./.github/workflows/reusable.yml", "with": {"title": SOURCE}},
        }})
        self.write(".github/workflows/reusable.yml", reusable())
        self.assertEqual(len(self.indirect(self.audit())), 1)

    def test_reusable_output_returns_to_caller_needs_sink(self):
        self.write(".github/workflows/reusable.yml", reusable(output=True))
        self.write(".github/workflows/ci.yml", {"on": "pull_request", "jobs": {
            "call": {"uses": "./.github/workflows/reusable.yml", "with": {"title": SOURCE}},
            "consume": {"runs-on": "ubuntu-latest", "needs": "call", "steps": [
                {"run": 'echo "${{ needs.call.outputs.title }}"'},
            ]},
        }})
        result = self.audit()
        self.assertEqual(result["errors"], [])
        findings = self.indirect(result)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["job"], "consume")
        self.assertTrue(any(node["kind"] == "workflow-output" for node in findings[0]["dataflow_trace"]))

    def test_called_workflow_must_declare_workflow_call(self):
        self.write(".github/workflows/reusable.yml", workflow())
        self.write(".github/workflows/ci.yml", {"on": "pull_request", "jobs": {
            "call": {"uses": "./.github/workflows/reusable.yml", "with": {"title": SOURCE}},
        }})
        result = self.audit()
        self.assertTrue(any("workflow_call" in error["message"] for error in result["errors"]))

    def test_composite_output_returns_to_caller_step_sink(self):
        self.write(".github/actions/title/action.yml", action([
            {"id": "emit", "shell": "bash", "env": {"TITLE": "${{ inputs.title }}"},
             "run": 'echo "title=$TITLE" >> "$GITHUB_OUTPUT"'},
        ], outputs={"title": {"value": "${{ steps.emit.outputs.title }}"}}))
        self.write(".github/workflows/ci.yml", workflow([
            {"id": "wrapped", "uses": "./.github/actions/title", "with": {"title": SOURCE}},
            {"run": 'echo "${{ steps.wrapped.outputs.title }}"'},
        ]))
        result = self.audit()
        self.assertEqual(result["errors"], [])
        self.assertEqual([(f["file"], f["step"]) for f in self.indirect(result)], [(str(self.entry), 2)])

    def test_returned_output_can_flow_through_a_later_local_call(self):
        forwarding = action([
            {"id": "emit", "shell": "bash", "env": {"TITLE": "${{ inputs.title }}"},
             "run": 'echo "title=$TITLE" >> "$GITHUB_OUTPUT"'},
        ], outputs={"title": {"value": "${{ steps.emit.outputs.title }}"}})
        self.write(".github/actions/title/action.yml", forwarding)
        self.write(".github/workflows/ci.yml", workflow([
            {"id": "first", "uses": "./.github/actions/title", "with": {"title": SOURCE}},
            {"id": "second", "uses": "./.github/actions/title", "with": {"title": "${{ steps.first.outputs.title }}"}},
            {"run": 'echo "${{ steps.second.outputs.title }}"'},
        ]))
        result = self.audit()
        self.assertEqual(result["errors"], [])
        self.assertEqual([f["step"] for f in self.indirect(result)], [3])

    def test_self_cycle_does_not_pop_parent_or_hide_other_callers(self):
        looping = action([{"uses": "./.github/actions/loop"}])
        self.write(".github/actions/loop/action.yml", looping)
        self.write(".github/actions/title/action.yml", action())
        self.write(".github/workflows/ci.yml", workflow([
            {"uses": "./.github/actions/loop"},
            {"uses": "./.github/actions/title", "with": {"title": SOURCE}},
        ]))
        result = self.audit()
        self.assertEqual(result["errors"], [])
        self.assertTrue(any(issue["kind"] == "cycle" for issue in result["unresolved"]))
        self.assertEqual(len(self.indirect(result)), 1)

    def test_repeated_cached_reusable_output_is_still_available(self):
        self.write(".github/workflows/reusable.yml", reusable(output=True))
        self.write(".github/workflows/ci.yml", {"on": "pull_request", "jobs": {
            "call": {"uses": "./.github/workflows/reusable.yml", "with": {"title": SOURCE}},
            "consume": {"runs-on": "ubuntu-latest", "needs": "call", "steps": [
                {"run": 'echo "${{ needs.call.outputs.title }}"'},
            ]},
        }})
        result = self.audit(self.entry, self.entry)
        self.assertEqual(len(self.indirect(result)), 1)

    def test_existing_static_rules_apply_inside_local_composite(self):
        self.write(".github/workflows/ci.yml", workflow([{"uses": "./.github/actions/title"}]))
        target = self.write(".github/actions/title/action.yml", action([{"uses": "actions/checkout@v4"}]))
        result = self.audit()
        self.assertEqual([(f["rule_id"], f["file"]) for f in result["findings"]], [("CHA001", str(target))])
        self.assertTrue(any(issue["kind"] == "remote_reference" for issue in result["unresolved"]))

    def test_self_repository_reference_uses_action_yaml_fallback(self):
        self.write(".github/workflows/ci.yml", workflow([{"uses": "$/actions/title", "with": {"title": SOURCE}}]))
        self.write("actions/title/action.yaml", action())
        self.assertEqual(len(self.indirect(self.audit())), 1)

    def test_remote_and_non_composite_implementations_are_unknown_not_safe(self):
        self.write(".github/workflows/ci.yml", workflow([
            {"uses": "org/action@" + "a" * 40}, {"uses": "./actions/js"},
        ]))
        self.write("actions/js/action.yml", {"name": "JS", "runs": {"using": "node24", "main": "index.js"}})
        result = self.audit()
        self.assertEqual(result["errors"], [])
        self.assertEqual({issue["kind"] for issue in result["unresolved"]}, {"remote_reference", "action_implementation"})

    def test_missing_or_outside_reference_and_symlink_are_not_opened(self):
        for ref in ("./missing", "./../outside", "./linked"):
            with self.subTest(ref=ref):
                link = self.root / "linked"
                if not link.exists():
                    link.symlink_to(self.root, target_is_directory=True)
                self.write(".github/workflows/ci.yml", workflow([{"uses": ref}]))
                result = self.audit()
                self.assertTrue(result["errors"])
                self.assertEqual(result["files_analyzed"], [str(self.entry)])

    def test_root_and_target_boundaries_reject_external_entries(self):
        with TemporaryDirectory() as elsewhere:
            result = analyze_graph([self.entry], Path(elsewhere))
            self.assertTrue(result["errors"])
            self.assertEqual(result["source_digests"], {})
        result = analyze_graph([self.entry], self.root / "absent")
        self.assertTrue(result["errors"])

    def test_file_context_and_byte_budgets_are_explicit_errors(self):
        self.write(".github/workflows/ci.yml", workflow([{"uses": "./actions/title", "with": {"title": SOURCE}}]))
        self.write("actions/title/action.yml", action())
        for constant in ("MAX_FILES", "MAX_CONTEXTS", "MAX_TOTAL_BYTES"):
            with self.subTest(limit=constant), patch("src.analysis.graph." + constant, 1):
                result = self.audit()
                self.assertTrue(result["errors"])

    def test_depth_limit_is_visible(self):
        self.write(".github/workflows/ci.yml", workflow([{"uses": "./actions/title", "with": {"title": SOURCE}}]))
        self.write("actions/title/action.yml", action([{"uses": "./actions/inner"}]))
        self.write("actions/inner/action.yml", action())
        with patch("src.analysis.graph.MAX_DEPTH", 0):
            result = self.audit()
            self.assertTrue(result["errors"])

    def test_flow_pass_limit_is_reported_instead_of_claiming_resolution(self):
        self.write("actions/title/action.yml", action([
            {"id": "emit", "shell": "bash", "env": {"TITLE": "${{ inputs.title }}"},
             "run": 'echo "title=$TITLE" >> "$GITHUB_OUTPUT"'},
        ], outputs={"title": {"value": "${{ steps.emit.outputs.title }}"}}))
        self.write(".github/workflows/ci.yml", workflow([
            {"id": "wrapped", "uses": "./actions/title", "with": {"title": SOURCE}},
            {"run": 'echo "${{ steps.wrapped.outputs.title }}"'},
        ]))
        with patch("src.analysis.graph.MAX_FLOW_PASSES", 1):
            result = self.audit()
        self.assertTrue(any(issue["kind"] == "flow_pass_limit" for issue in result["unresolved"]))

    def test_scripts_and_candidate_values_are_not_executed_or_returned(self):
        marker = self.root / "never-executed"
        self.write(".github/workflows/ci.yml", workflow([{"uses": "./actions/title", "with": {"title": SOURCE}}]))
        self.write("actions/title/action.yml", action([
            {"shell": "bash", "env": {"PASSWORD": "DEMO_PRIVATE_VALUE"}, "run": f"touch {marker}"},
            {"shell": "bash", "run": 'echo "${{ inputs.title }}"'},
        ]))
        result = self.audit()
        self.assertFalse(marker.exists())
        self.assertNotIn("DEMO_PRIVATE_VALUE", json.dumps(result))
