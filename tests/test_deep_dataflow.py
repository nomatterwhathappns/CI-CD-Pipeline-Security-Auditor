"""Source-to-sink behavior and precision boundaries of the static flow model."""

import json
from pathlib import Path
import unittest
from unittest.mock import patch

from src.analysis.dataflow import check, direct_script_source
from src.engine import SourceMapping
from src.rules.common import RuleContext


EVENT = "${{ github.event.pull_request.title }}"


def workflow(steps, env=None):
    return {"on": "pull_request", "jobs": {"build": {
        "runs-on": "ubuntu-latest", "env": env or {}, "steps": steps,
    }}}


def analyze(document, **bindings):
    ctx = RuleContext(Path("workflow.yml"), document)
    summary = check(ctx, **bindings)
    return ctx.findings, summary


def external_source():
    return [{"file": "caller.yml", "job": "source", "step": 1,
             "kind": "event", "name": "github.event.pull_request.title"}]


class TestDeepDataflow(unittest.TestCase):
    def test_env_indirection_reports_a_safe_identifier_trace(self):
        findings, _ = analyze(workflow([{"run": 'echo "${{ env.TITLE }}"'}], {"TITLE": EVENT}))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "CHA023")
        self.assertEqual([node["kind"] for node in findings[0]["dataflow_trace"]], ["event", "env", "script"])

    def test_expression_environment_casing_follows_known_runner_os(self):
        for runner, expected in (("ubuntu-latest", 0), ("macos-latest", 0), ("windows-latest", 1)):
            with self.subTest(runner=runner):
                document = workflow([{"run": 'echo "${{ env.title }}"'}], {"TITLE": EVENT})
                document["jobs"]["build"]["runs-on"] = runner
                self.assertEqual(len(analyze(document)[0]), expected)

    def test_unknown_runner_case_mismatch_is_recorded_without_inventing_flow(self):
        document = workflow([{"run": 'echo "${{ env.title }}"'}], {"TITLE": EVENT})
        document["jobs"]["build"]["runs-on"] = "${{ matrix.runner }}"
        findings, summary = analyze(document)
        self.assertEqual(findings, [])
        self.assertIn("env-case-unknown", {item["kind"] for item in summary["unresolved"]})
        document["jobs"]["build"]["steps"][0]["run"] = 'echo "${{ env.TITLE }}"'
        self.assertEqual(len(analyze(document)[0]), 1)

    def test_step_outputs_follow_recognized_posix_writes(self):
        findings, summary = analyze(workflow([
            {"id": "emit", "run": 'echo "title=$TITLE" >> "$GITHUB_OUTPUT"'},
            {"run": 'echo "${{ steps.emit.outputs.title }}"'},
        ], {"TITLE": EVENT}))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["step"], 2)
        self.assertIn("title", summary["step_outputs"]["build"]["emit"])
        self.assertIn("step-output", {n["kind"] for n in findings[0]["dataflow_trace"]})

    def test_env_file_updates_apply_only_to_later_steps(self):
        findings, _ = analyze(workflow([
            {"run": 'echo "TITLE=$VALUE" >> "$GITHUB_ENV"\necho "${{ env.TITLE }}"'},
            {"run": 'echo "${{ env.TITLE }}"'},
        ], {"VALUE": EVENT}))
        self.assertEqual([f["step"] for f in findings], [2])
        self.assertIn("env-file", {n["kind"] for n in findings[0]["dataflow_trace"]})

    def test_job_outputs_are_available_after_direct_dependency_even_if_declared_later(self):
        source = {"runs-on": "ubuntu-latest", "env": {"TITLE": EVENT},
                  "outputs": {"title": "${{ steps.emit.outputs.title }}"},
                  "steps": [{"id": "emit", "run": 'echo "title=$TITLE" >> "$GITHUB_OUTPUT"'}]}
        document = {"on": "pull_request", "jobs": {
            "sink": {"runs-on": "ubuntu-latest", "needs": "source",
                     "steps": [{"run": 'echo "${{ needs.source.outputs.title }}"'}]},
            "source": source,
        }}
        findings, _ = analyze(document)
        self.assertEqual([(f["job"], f["step"]) for f in findings], [("sink", 1)])
        self.assertIn("job-output", {n["kind"] for n in findings[0]["dataflow_trace"]})

    def test_explicit_inputs_are_traced_without_assuming_unknown_inputs_unsafe(self):
        document = workflow([{"run": 'echo "${{ inputs.title }}"'}])
        self.assertEqual(analyze(document)[0], [])
        findings, _ = analyze(document, input_sources={"title": external_source()})
        self.assertEqual(len(findings), 1)
        self.assertIn("input", {n["kind"] for n in findings[0]["dataflow_trace"]})

    def test_caller_bindings_include_only_taint_and_no_literal_payload(self):
        marker = "DEMO_LITERAL_NEVER_SERIALIZE_AS_PROVENANCE"
        document = workflow([{"uses": "./action", "with": {"title": "${{ env.TITLE }}", "secret": marker}}], {"TITLE": EVENT})
        _, summary = analyze(document)
        self.assertEqual(set(summary["calls"][0]["inputs"]), {"title"})
        self.assertIn("TITLE", summary["calls"][0]["env_sources"])
        self.assertNotIn(marker, json.dumps(summary))

    def test_external_step_outputs_and_reusable_job_outputs_return_to_callers(self):
        document = workflow([
            {"id": "child", "uses": "./action"},
            {"run": 'echo "${{ steps.child.outputs.title }}"'},
        ])
        findings, _ = analyze(document, call_output_sources={("build", 1): {"title": external_source()}})
        self.assertEqual([f["step"] for f in findings], [2])
        document = {"jobs": {
            "child": {"uses": "./.github/workflows/child.yml"},
            "sink": {"runs-on": "ubuntu-latest", "needs": "child",
                     "steps": [{"run": 'echo "${{ needs.child.outputs.title }}"'}]},
        }}
        findings, _ = analyze(document, call_output_sources={("child", None): {"title": external_source()}})
        self.assertEqual([f["job"] for f in findings], ["sink"])

    def test_workflow_output_contract_survives_trigger_context_override(self):
        document = SourceMapping(1, 1)
        document.update(workflow([
            {"id": "emit", "run": 'echo "title=$TITLE" >> "$GITHUB_OUTPUT"'},
        ], {"TITLE": EVENT}))
        document["jobs"]["build"]["outputs"] = {"title": "${{ steps.emit.outputs.title }}"}
        document.analysis_workflow_call = {"outputs": {"title": {"value": "${{ jobs.build.outputs.title }}"}}}
        _, summary = analyze(document)
        self.assertIn("title", summary["workflow_outputs"])

    def test_composite_outputs_export_recognized_step_values(self):
        document = SourceMapping(1, 1)
        document.update({"jobs": {"composite": {
            "steps": [{"id": "emit", "shell": "bash", "env": {"TITLE": "${{ inputs.title }}"},
                       "run": 'echo "title=$TITLE" >> "$GITHUB_OUTPUT"'}],
        }}, "outputs": {"result": {"value": "${{ steps.emit.outputs.title }}"}}})
        document.analysis_kind = "composite"
        _, summary = analyze(document, input_sources={"title": external_source()})
        self.assertIn("result", summary["workflow_outputs"])

    def test_known_environment_literals_control_expression_branches(self):
        for literal, count in (("constant", 0), ("", 1)):
            with self.subTest(literal=literal):
                document = workflow([{"run": 'echo "${{ env.CHOSEN }}"'}], {"FLAG": literal})
                document["jobs"]["build"]["steps"][0]["env"] = {
                    "CHOSEN": "${{ env.FLAG || github.event.pull_request.title }}",
                }
                self.assertEqual(len(analyze(document)[0]), count)

    def test_yaml_false_environment_is_the_truthy_string_false(self):
        document = workflow([{"env": {"VALUE": "${{ env.FLAG && github.event.pull_request.title }}"},
                              "run": 'echo "${{ env.VALUE }}"'}], {"FLAG": False})
        self.assertEqual(len(analyze(document)[0]), 1)

    def test_known_false_expression_cannot_return_untrusted_branch(self):
        document = workflow([{"run": 'echo "${{ env.VALUE }}"'}], {
            "VALUE": "${{ fromJSON('false') && github.event.pull_request.title }}",
        })
        self.assertEqual(analyze(document)[0], [])

    def test_formatted_selection_uses_only_referenced_arguments(self):
        for template, expected in (("{{{0}}}", 1), ("{{0}}", 0), ("{1}", 0)):
            with self.subTest(template=template):
                document = workflow([{"run": 'echo "${{ env.TITLE }}"'}], {
                    "TITLE": "${{ format('" + template + "', github.event.pull_request.title, 'safe') }}",
                })
                self.assertEqual(len(analyze(document)[0]), expected)

    def test_shell_locals_and_output_names_remain_case_precise(self):
        for reference, expected in (("$LOCAL", 1), ("$local", 0)):
            with self.subTest(reference=reference):
                document = workflow([
                    {"id": "emit", "run": 'LOCAL="$TITLE"\necho "title=' + reference + '" >> "$GITHUB_OUTPUT"'},
                    {"run": 'echo "${{ steps.emit.outputs.title }}"'},
                ], {"TITLE": EVENT})
                self.assertEqual(len(analyze(document)[0]), expected)

    def test_single_quoted_output_payload_is_literal_shell_data(self):
        document = workflow([
            {"id": "emit", "run": "echo 'title=$TITLE' >> \"$GITHUB_OUTPUT\""},
            {"run": 'echo "${{ steps.emit.outputs.title }}"'},
        ], {"TITLE": EVENT})
        self.assertEqual(analyze(document)[0], [])

    def test_even_backslashes_allow_expansion_and_odd_backslashes_escape_it(self):
        for slashes, expected in ((1, 0), (2, 1), (3, 0), (4, 1)):
            with self.subTest(slashes=slashes):
                document = workflow([
                    {"id": "emit", "run": 'echo "title=' + '\\' * slashes + '$TITLE" >> "$GITHUB_OUTPUT"'},
                    {"run": 'echo "${{ steps.emit.outputs.title }}"'},
                ], {"TITLE": EVENT})
                self.assertEqual(len(analyze(document)[0]), expected)

    def test_dashed_output_names_work_with_bracket_property_access(self):
        document = workflow([
            {"id": "emit", "run": 'echo "pr-title=$TITLE" >> "$GITHUB_OUTPUT"'},
            {"run": "echo \"${{ steps['emit']['outputs']['pr-title'] }}\""},
        ], {"TITLE": EVENT})
        self.assertEqual(len(analyze(document)[0]), 1)

    def test_braced_output_target_is_supported(self):
        document = workflow([
            {"id": "emit", "run": 'echo "title=$TITLE" >> ${GITHUB_OUTPUT}'},
            {"run": 'echo "${{ steps.emit.outputs.title }}"'},
        ], {"TITLE": EVENT})
        self.assertEqual(len(analyze(document)[0]), 1)

    def test_pwsh_output_commands_are_left_outside_posix_model(self):
        document = workflow([
            {"id": "emit", "shell": "pwsh", "run": 'echo "title=$TITLE" >> "$GITHUB_OUTPUT"'},
            {"run": 'echo "${{ steps.emit.outputs.title }}"'},
        ], {"TITLE": EVENT})
        self.assertEqual(analyze(document)[0], [])

    def test_control_flow_and_multiline_examples_do_not_invent_outputs(self):
        examples = (
            'if condition; then\necho "title=$TITLE" >> "$GITHUB_OUTPUT"\nfi',
            'emit() {\necho "title=$TITLE" >> "$GITHUB_OUTPUT"\n}',
            'echo \'example\necho "title=$TITLE" >> "$GITHUB_OUTPUT"\n\'',
            'cat <<EOF\necho "title=$TITLE" >> "$GITHUB_OUTPUT"\nEOF',
        )
        for script in examples:
            with self.subTest(script=script):
                findings, summary = analyze(workflow([
                    {"id": "emit", "run": script},
                    {"run": 'echo "${{ steps.emit.outputs.title }}"'},
                ], {"TITLE": EVENT}))
                self.assertEqual(findings, [])
                self.assertIn("unsupported-output-control-flow", {item["kind"] for item in summary["unresolved"]})

    def test_disabled_steps_jobs_do_not_generate_or_forward_taint(self):
        document = workflow([
            {"if": False, "id": "emit", "run": 'echo "title=$TITLE" >> "$GITHUB_OUTPUT"'},
            {"run": 'echo "${{ steps.emit.outputs.title }}"'},
            {"if": "${{ false }}", "run": 'echo "${{ env.TITLE }}"'},
        ], {"TITLE": EVENT})
        self.assertEqual(analyze(document)[0], [])
        document["jobs"]["build"]["if"] = False
        document["jobs"]["build"]["steps"] = [{"run": 'echo "${{ env.TITLE }}"'}]
        self.assertEqual(analyze(document)[0], [])

    def test_direct_sources_are_not_duplicated_as_indirect_findings(self):
        self.assertEqual(analyze(workflow([{"run": 'echo "' + EVENT + '"'}]))[0], [])

    def test_unknown_expressions_and_dynamic_env_report_coverage(self):
        document = workflow([{"run": 'echo "${{ env.TITLE }}"'}], {"TITLE": "${{ unknownFunction(github.event.pull_request.title) }}"})
        findings, summary = analyze(document)
        self.assertEqual(findings, [])
        self.assertIn("unsupported-expression", {item["kind"] for item in summary["unresolved"]})
        document["jobs"]["build"]["env"] = "${{ fromJSON(inputs.env) }}"
        self.assertIn("dynamic-env", {item["kind"] for item in analyze(document)[1]["unresolved"]})

    def test_limits_and_cycles_are_visible_in_summary(self):
        document = workflow([{"run": "echo ok"}])
        document["jobs"]["build"]["needs"] = "build"
        _, summary = analyze(document)
        self.assertIn("cyclic-job-dependencies", {item["kind"] for item in summary["unresolved"]})
        self.assertEqual(summary["limits"]["max_jobs"], 100)
        document["jobs"]["other"] = {"steps": [{"run": "echo ok"}]}
        with patch("src.analysis.dataflow.MAX_JOBS", 1):
            self.assertIn("job-limit", {item["kind"] for item in analyze(document)[1]["unresolved"]})

    def test_long_traces_are_clamped_and_reported(self):
        source = [{"file": "caller.yml", "job": "j", "step": 1,
                   "kind": "event" if i == 0 else "call-input", "name": f"hop{i}"} for i in range(40)]
        findings, summary = analyze(workflow([{"run": 'echo "${{ inputs.title }}"'}]), input_sources={"title": source})
        self.assertEqual(len(findings), 1)
        self.assertLessEqual(len(findings[0]["dataflow_trace"]), 32)
        self.assertIn("trace-limit", {item["kind"] for item in summary["unresolved"]})

    def test_trace_cap_does_not_erase_the_indirection_or_sink(self):
        source = [{"file": "caller.yml", "job": "j", "step": i,
                   "kind": "event", "name": f"origin{i}"} for i in range(32)]
        findings, summary = analyze(workflow([{"run": 'echo "${{ inputs.title }}"'}]), input_sources={"title": source})
        self.assertEqual(len(findings), 1)
        trace = findings[0]["dataflow_trace"]
        self.assertEqual(trace[0]["kind"], "event")
        self.assertEqual(trace[-1]["kind"], "script")
        self.assertIn("trace-limit", {item["kind"] for item in summary["unresolved"]})

    def test_ignored_rule_still_returns_callee_bindings(self):
        ctx = RuleContext(Path("workflow.yml"), workflow([{"uses": "./child", "with": {"title": EVENT}}]), ignored={"CHA023"})
        summary = check(ctx)
        self.assertEqual(ctx.findings, [])
        self.assertIn("title", summary["calls"][0]["inputs"])


class TestDirectScriptSource(unittest.TestCase):
    def test_brackets_format_and_boolean_results_are_distinguished(self):
        self.assertIs(direct_script_source("echo ${{ github['event']['pull_request']['title'] }}"), True)
        self.assertIs(direct_script_source("echo ${{ github['event.pull_request.title'] }}"), False)
        self.assertIs(direct_script_source("echo ${{ contains(github.event.pull_request.title, 'x') }}"), False)
        self.assertIs(direct_script_source("echo ${{ format('{{{0}}}', github.event.pull_request.title) }}"), True)
        self.assertIs(direct_script_source("echo ${{ format('{{0}}', github.event.pull_request.title) }}"), False)

    def test_unknown_syntax_requests_fallback_without_executing_anything(self):
        self.assertIsNone(direct_script_source("echo ${{ unknownFunction(github.event.pull_request.title) }}"))
        self.assertIsNone(direct_script_source("echo ${{ 'safe' }} ${{ broken"))
        self.assertIs(direct_script_source("echo '${{ 'github.event.pull_request.title' }}'"), False)
