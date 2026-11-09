# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 nomatterwhathappns
"""Independent precision cases for bounded expression/dataflow analysis.

These tests exercise data as data, lexical scope, and runtime availability;
they never execute source workflow scripts.
"""

from pathlib import Path
import unittest

from src.analysis.dataflow import check
from src.rules.common import RuleContext


class RecordingContext(RuleContext):
    def emit(self, rule_id, message, **metadata):
        if rule_id not in self.ignored:
            self.findings.append({"rule_id": rule_id, "message": message, **metadata})


def review(workflow, **bindings):
    context = RecordingContext(Path("workflow.yml"), workflow)
    summary = check(context, **bindings)
    return context.findings, summary


def one_job(steps, **extra):
    return {"on": "pull_request", "jobs": {"build": {
        "runs-on": "ubuntu-latest", "steps": steps, **extra,
    }}}


class TestIndependentDataflowReview(unittest.TestCase):
    def test_quoted_shell_variable_is_data_without_generated_source(self):
        workflow = one_job([{"run": 'printf "%s\\n" "$TITLE"'}],
                           env={"TITLE": "${{ github.event.pull_request.title }}"})
        findings, _ = review(workflow)
        self.assertEqual(findings, [])

    def test_context_name_inside_expression_string_is_not_a_source(self):
        workflow = one_job([{"run": 'echo "${{ env.TITLE }}"'}],
                           env={"TITLE": "${{ 'github.event.pull_request.title' }}"})
        findings, _ = review(workflow)
        self.assertEqual(findings, [])

    def test_boolean_predicate_results_do_not_carry_attacker_script_text(self):
        for expression in (
            "contains(github.event.pull_request.title, 'ok')",
            "startsWith(github.event.pull_request.title, 'ok')",
            "github.event.pull_request.title == 'ok'",
            "contains(github.event.pull_request.title, 'ok') && 'yes' || 'no'",
        ):
            with self.subTest(expression=expression):
                workflow = one_job([{"run": 'echo "${{ env.FLAG }}"'}],
                                   env={"FLAG": "${{ " + expression + " }}"})
                findings, _ = review(workflow)
                self.assertEqual(findings, [])

    def test_more_specific_environment_overrides_root_source(self):
        workflow = one_job([{"run": 'echo "${{ env.TITLE }}"'}], env={"TITLE": "safe"})
        workflow["env"] = {"TITLE": "${{ github.event.pull_request.title }}"}
        findings, _ = review(workflow)
        self.assertEqual(findings, [])
        workflow["jobs"]["build"]["steps"][0]["env"] = {
            "TITLE": "${{ github.event.pull_request.body }}",
        }
        findings, _ = review(workflow)
        self.assertEqual({finding["rule_id"] for finding in findings}, {"CHA023"})

    def test_future_step_output_is_not_available_to_previous_step(self):
        workflow = one_job([
            {"run": 'echo "${{ steps.future.outputs.title }}"'},
            {"id": "future", "env": {"TITLE": "${{ github.event.pull_request.title }}"},
             "run": 'echo "title=$TITLE" >> "$GITHUB_OUTPUT"'},
        ])
        findings, _ = review(workflow)
        self.assertEqual(findings, [])

    def test_needs_does_not_include_implicit_transitive_dependencies(self):
        workflow = {"on": "pull_request", "jobs": {
            "source": {"runs-on": "ubuntu-latest",
                       "outputs": {"title": "${{ steps.emit.outputs.title }}"},
                       "steps": [{"id": "emit", "env": {"TITLE": "${{ github.event.pull_request.title }}"},
                                  "run": 'echo "title=$TITLE" >> "$GITHUB_OUTPUT"'}]},
            "middle": {"runs-on": "ubuntu-latest", "needs": "source", "steps": [{"run": "echo ok"}]},
            "sink": {"runs-on": "ubuntu-latest", "needs": "middle",
                     "steps": [{"run": 'echo "${{ needs.source.outputs.title }}"'}]},
        }}
        findings, _ = review(workflow)
        self.assertEqual(findings, [])
        workflow["jobs"]["sink"]["needs"] = ["source", "middle"]
        findings, _ = review(workflow)
        self.assertEqual({finding["rule_id"] for finding in findings}, {"CHA023"})

    def test_single_quoted_shell_reference_is_not_an_expanded_output(self):
        workflow = one_job([
            {"id": "emit", "run": "echo 'title=$TITLE' >> \"$GITHUB_OUTPUT\""},
            {"run": 'echo "${{ steps.emit.outputs.title }}"'},
        ], env={"TITLE": "${{ github.event.pull_request.title }}"})
        findings, _ = review(workflow)
        self.assertEqual(findings, [])

    def test_posix_shell_variable_names_are_case_sensitive(self):
        workflow = one_job([
            {"id": "emit", "run": 'echo "title=$title" >> "$GITHUB_OUTPUT"'},
            {"run": 'echo "${{ steps.emit.outputs.title }}"'},
        ], env={"TITLE": "${{ github.event.pull_request.title }}"})
        findings, _ = review(workflow)
        self.assertEqual(findings, [])

    def test_quoted_literal_output_filename_is_not_the_output_file(self):
        workflow = one_job([
            {"id": "emit", "run": 'echo "title=$TITLE" >> \'$GITHUB_OUTPUT\''},
            {"run": 'echo "${{ steps.emit.outputs.title }}"'},
        ], env={"TITLE": "${{ github.event.pull_request.title }}"})
        findings, _ = review(workflow)
        self.assertEqual(findings, [])

    def test_constant_format_template_does_not_use_extra_untrusted_arguments(self):
        for expression in (
            "format('fixed', github.event.pull_request.title)",
            "format('{1}', github.event.pull_request.title, 'safe')",
        ):
            with self.subTest(expression=expression):
                workflow = one_job([{"run": 'echo "${{ env.TITLE }}"'}],
                                   env={"TITLE": "${{ " + expression + " }}"})
                findings, _ = review(workflow)
                self.assertEqual(findings, [])

    def test_escaped_format_braces_do_not_silently_hide_a_real_placeholder(self):
        workflow = one_job([{"run": 'echo "${{ env.TITLE }}"'}],
                           env={"TITLE": "${{ format('{{{0}}}', github.event.pull_request.title) }}"})
        findings, summary = review(workflow)
        self.assertTrue(any(finding["rule_id"] == "CHA023" for finding in findings)
                        or summary.get("unresolved"),
                        "Recognize the payload or explicitly report unsupported formatting, never silently drop it.")
