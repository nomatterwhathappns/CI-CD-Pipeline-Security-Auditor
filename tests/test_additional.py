# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 nomatterwhathappns
"""Focused checks for additional rules, with no workflow execution."""

from copy import deepcopy
from pathlib import Path
import unittest

from src.rules.additional import check
from src.rules.common import RuleContext


def workflow():
    return {"on": "push", "jobs": {"build": {
        "runs-on": "ubuntu-latest", "steps": [{"run": "echo example"}]
    }}}


def scan(document, rule):
    ctx = RuleContext(Path("workflow.yml"), document)
    check(ctx)
    return [finding for finding in ctx.findings if finding["rule_id"] == rule]


class UnsafeWorkflowCommandTests(unittest.TestCase):
    def test_literal_true_forms_enable_opt_in(self):
        for value in (True, "true", "TRUE", " TrUe ", "${{ true }}",
                      "${{ 'true' }}", "${{ 'TRUE' }}", "  ${{ true }}  "):
            with self.subTest(value=value):
                document = workflow()
                document["env"] = {"ACTIONS_ALLOW_UNSECURE_COMMANDS": value}
                findings = scan(document, "CHA021")
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["level"], "workflow")
                self.assertIsNone(findings[0]["job"])

    def test_only_runner_boolean_true_enables(self):
        for value in (False, "false", "", None, "1", 1, "yes", "on", "truthy",
                      "${{ false }}", "${{ 1 }}", "${{ vars.OPT_IN }}",
                      "prefix${{ true }}", "${{ 'tr''ue' }}"):
            with self.subTest(value=value):
                document = workflow()
                document["env"] = {"ACTIONS_ALLOW_UNSECURE_COMMANDS": value}
                self.assertEqual(scan(document, "CHA021"), [])

    def test_similarly_named_variables_are_not_reported(self):
        for name in ("ACTIONS_ALLOW_UNSECURE_COMMANDS_EXTRA", "UNSECURE_COMMANDS",
                     "actions_allow_unsecure_commands"):
            document = workflow()
            document["env"] = {name: True}
            self.assertEqual(scan(document, "CHA021"), [])

    def test_job_and_step_locations(self):
        document = workflow()
        job = document["jobs"]["build"]
        job["env"] = {"ACTIONS_ALLOW_UNSECURE_COMMANDS": "true"}
        findings = scan(document, "CHA021")
        self.assertEqual((findings[0]["job"], findings[0]["step"]), ("build", None))
        job.pop("env")
        job["steps"][0]["env"] = {"ACTIONS_ALLOW_UNSECURE_COMMANDS": True}
        findings = scan(document, "CHA021")
        self.assertEqual((findings[0]["job"], findings[0]["step"]), ("build", 1))

    def test_job_false_overrides_root_true(self):
        document = workflow()
        document["env"] = {"ACTIONS_ALLOW_UNSECURE_COMMANDS": True}
        document["jobs"]["build"]["env"] = {"ACTIONS_ALLOW_UNSECURE_COMMANDS": "false"}
        self.assertEqual(scan(document, "CHA021"), [])

    def test_step_false_overrides_job_true(self):
        document = workflow()
        job = document["jobs"]["build"]
        job["env"] = {"ACTIONS_ALLOW_UNSECURE_COMMANDS": True}
        job["steps"][0]["env"] = {"ACTIONS_ALLOW_UNSECURE_COMMANDS": False}
        self.assertEqual(scan(document, "CHA021"), [])

    def test_unknown_env_or_opt_in_overrides_known_inherited_true(self):
        for override in ("${{ fromJSON(vars.STEP_ENV) }}",
                         {"ACTIONS_ALLOW_UNSECURE_COMMANDS": "${{ vars.OPT_IN }}"}):
            document = workflow()
            document["env"] = {"ACTIONS_ALLOW_UNSECURE_COMMANDS": True}
            document["jobs"]["build"]["steps"][0]["env"] = override
            self.assertEqual(scan(document, "CHA021"), [])

    def test_known_step_overrides_unknown_job_env(self):
        document = workflow()
        job = document["jobs"]["build"]
        job["env"] = "${{ fromJSON(vars.JOB_ENV) }}"
        job["steps"][0]["env"] = {"ACTIONS_ALLOW_UNSECURE_COMMANDS": True}
        findings = scan(document, "CHA021")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["level"], "step")

    def test_inherited_declaration_is_reported_once_across_steps_and_jobs(self):
        document = workflow()
        document["env"] = {"ACTIONS_ALLOW_UNSECURE_COMMANDS": True}
        document["jobs"]["build"]["steps"].append({"run": "echo second"})
        document["jobs"]["second"] = deepcopy(document["jobs"]["build"])
        self.assertEqual(len(scan(document, "CHA021")), 1)

    def test_nonexecuting_and_definitely_disabled_scopes_are_skipped(self):
        for condition in (False, "false", "${{ false }}"):
            document = workflow()
            document["env"] = {"ACTIONS_ALLOW_UNSECURE_COMMANDS": True}
            document["jobs"]["build"]["steps"][0]["if"] = condition
            self.assertEqual(scan(document, "CHA021"), [])
            document["jobs"]["build"]["steps"][0].pop("if")
            document["jobs"]["build"]["if"] = condition
            self.assertEqual(scan(document, "CHA021"), [])
        document = {"env": {"ACTIONS_ALLOW_UNSECURE_COMMANDS": True}, "jobs": {
            "call": {"uses": "./.github/workflows/build.yml"}
        }}
        self.assertEqual(scan(document, "CHA021"), [])

    def test_whitespace_around_false_expression_is_not_assumed_disabled(self):
        document = workflow()
        step = document["jobs"]["build"]["steps"][0]
        step["env"] = {"ACTIONS_ALLOW_UNSECURE_COMMANDS": True}
        step["if"] = " ${{ false }}"
        self.assertEqual(len(scan(document, "CHA021")), 1)

    def test_rule_can_be_ignored(self):
        document = workflow()
        document["env"] = {"ACTIONS_ALLOW_UNSECURE_COMMANDS": True}
        ctx = RuleContext(Path("workflow.yml"), document, ignored={"CHA021"})
        check(ctx)
        self.assertEqual(ctx.findings, [])


class PrivilegedContainerTests(unittest.TestCase):
    def with_options(self, options):
        document = workflow()
        document["jobs"]["build"]["container"] = {
            "image": "example/image@sha256:" + "a" * 64, "options": options,
        }
        return document

    def test_literal_privileged_flags(self):
        for options in ("--privileged", "--privileged=true", "--privileged=True",
                        "--privileged=1", "--cpus 2 --privileged --memory 1g",
                        "-it --privileged", "'--privileged'"):
            with self.subTest(options=options):
                findings = scan(self.with_options(options), "CHA022")
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["container_type"], "job")
                self.assertEqual(findings[0]["confidence"], "high")

    def test_disabled_flags_and_last_override(self):
        for options in ("--privileged=false", "--privileged=0", "--privileged=F",
                        "--privileged --privileged=false"):
            with self.subTest(options=options):
                self.assertEqual(scan(self.with_options(options), "CHA022"), [])
        self.assertEqual(len(scan(self.with_options("--privileged=false --privileged"),
                                  "CHA022")), 1)

    def test_option_values_are_not_treated_as_flags(self):
        for options in ('--label "--privileged"', "--label=--privileged",
                        "--env FLAG=--privileged", "-l--privileged",
                        '--health-cmd "echo --privileged"',
                        '--label "text with --privileged" --cpus 2'):
            with self.subTest(options=options):
                self.assertEqual(scan(self.with_options(options), "CHA022"), [])

    def test_service_container_location(self):
        document = workflow()
        document["jobs"]["build"]["services"] = {
            "docker": {"image": "docker", "options": "--privileged"}
        }
        findings = scan(document, "CHA022")
        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0]["job"], findings[0]["service"]), ("build", "docker"))
        self.assertEqual(findings[0]["container_type"], "service")

    def test_job_and_service_each_reported(self):
        document = self.with_options("--privileged")
        document["jobs"]["build"]["services"] = {
            "docker": {"image": "docker", "options": "--privileged=true"}
        }
        self.assertEqual(len(scan(document, "CHA022")), 2)

    def test_dynamic_malformed_unknown_and_absent_options_remain_unresolved(self):
        for options in (None, [], {}, "", "--privileged=invalid", '"--privileged',
                        "${{ vars.CONTAINER_OPTIONS }}", "--privileged ${{ vars.OTHER }}",
                        "--unknown --privileged", "--label", "--privilegedly",
                        "echo --privileged"):
            with self.subTest(options=options):
                self.assertEqual(scan(self.with_options(options), "CHA022"), [])

    def test_privileged_text_in_steps_or_labels_is_not_container_option(self):
        document = workflow()
        document["jobs"]["build"]["steps"][0]["run"] = "echo --privileged"
        document["jobs"]["build"]["steps"][0]["options"] = "--privileged"
        self.assertEqual(scan(document, "CHA022"), [])

    def test_explicitly_disabled_job_does_not_start_container(self):
        document = self.with_options("--privileged")
        document["jobs"]["build"]["if"] = False
        self.assertEqual(scan(document, "CHA022"), [])

    def test_rule_can_be_ignored(self):
        ctx = RuleContext(Path("workflow.yml"), self.with_options("--privileged"),
                          ignored={"CHA022"})
        check(ctx)
        self.assertEqual(ctx.findings, [])


if __name__ == "__main__":
    unittest.main()
