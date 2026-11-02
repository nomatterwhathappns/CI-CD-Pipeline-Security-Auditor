"""Positive/negative behavior at the seven bounded trust rules' boundaries."""

import unittest
from pathlib import Path

import yaml

from src.rules.common import RuleContext
from src.rules.trust import check


CHECKOUT_V7_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
UPLOAD_V7_SHA = "cf430e030ddbb5b0abf93d22962f4752f3646cd9"
PR_SHA = "${{ github.event.pull_request.head.sha }}"
RUN_ID = "${{ github.event.workflow_run.id }}"
COMMENT = "${{ github.event.comment.body }}"


def action(name, action_ref="v6", **options):
    step = {"uses": f"{name}@{action_ref}"}
    if options:
        step["with"] = options
    return step


class TestTrustRules(unittest.TestCase):
    def scan(self, steps, event="push", job=None, workflow=None):
        definition = {"on": event, "jobs": {"example": {"runs-on": "ubuntu-latest", "steps": steps}}}
        definition["jobs"]["example"].update(job or {})
        definition.update(workflow or {})
        context = RuleContext(Path("workflow.yml"), definition)
        check(context)
        return context.findings

    def rule(self, rule_id, steps, **kwargs):
        return [finding for finding in self.scan(steps, **kwargs) if finding["rule_id"] == rule_id]

    def checkout(self, action_ref="v6", **options):
        return action("actions/checkout", action_ref, **{"ref": PR_SHA, **options})

    def download(self, **options):
        return action("actions/download-artifact", "v7", **{"run-id": RUN_ID, "github-token": "${{ github.token }}", **options})

    def test_011_self_hosted_pr_is_review_finding(self):
        findings = self.rule("CHA011", [], event="pull_request", job={"runs-on": ["self-hosted", "linux"]})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["confidence"], "medium")
        self.assertEqual(findings[0]["job"], "example")

    def test_011_runner_label_mapping_is_supported(self):
        self.assertEqual(len(self.rule("CHA011", [], event="pull_request", job={"runs-on": {"group": "ci", "labels": ["self-hosted"]}})), 1)

    def test_011_hosted_push_and_disabled_jobs_do_not_warn(self):
        cases = [
            ("push", {"runs-on": "self-hosted"}),
            ("pull_request", {"runs-on": "ubuntu-latest"}),
            ("pull_request", {"runs-on": "self-hosted", "if": False}),
            (["push", "pull_request"], {"runs-on": "self-hosted", "if": "${{ github.event_name == 'push' }}"}),
        ]
        for event, job in cases:
            with self.subTest(event=event, job=job):
                self.assertFalse(self.rule("CHA011", [], event=event, job=job))

    def test_012_pr_head_checkout_then_execution(self):
        for command in ("npm ci", "npm test", "make test", "python -m unittest discover", "bash scripts/test.sh", "./ci.sh"):
            with self.subTest(command=command):
                found = self.rule("CHA012", [self.checkout(), {"run": command}], event="pull_request_target")
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0]["step"], 1)

    def test_012_fork_repository_and_merge_ref(self):
        for options in ({"repository": "${{ github.event.pull_request.head.repo.full_name }}", "ref": "main"}, {"ref": "refs/pull/${{ github.event.pull_request.number }}/merge"}):
            with self.subTest(options=options):
                steps = [self.checkout(**options), {"run": "npm test"}]
                self.assertTrue(self.rule("CHA012", steps, event="pull_request_target"))

    def test_012_v7_default_protection_and_explicit_opt_in(self):
        for ref in ("v7", "v7.0.1", CHECKOUT_V7_SHA):
            with self.subTest(ref=ref):
                self.assertFalse(self.rule("CHA012", [self.checkout(ref), {"run": "npm test"}], event="pull_request_target"))
                unsafe = self.checkout(ref, **{"allow-unsafe-pr-checkout": True})
                self.assertTrue(self.rule("CHA012", [unsafe, {"run": "npm test"}], event="pull_request_target"))

    def test_012_unknown_sha_does_not_claim_known_version(self):
        found = self.rule("CHA012", [self.checkout("a" * 40), {"run": "npm test"}], event="pull_request_target")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["confidence"], "medium")

    def test_012_v7_expression_optins_are_not_assumed_false(self):
        for opt_in in ("${{ true }}", "${{ inputs.allow_unsafe }}"):
            with self.subTest(opt_in=opt_in):
                checkout = self.checkout("v7", **{"allow-unsafe-pr-checkout": opt_in})
                self.assertTrue(self.rule("CHA012", [checkout, {"run": "npm test"}], event="pull_request_target"))

    def test_012_014_oversized_version_components_remain_unresolved(self):
        for version in ("v" + "9" * 5000, "v4." + "9" * 5000, "v7.0." + "9" * 5000):
            with self.subTest(component_length=len(version)):
                found = self.rule("CHA012", [self.checkout(version), {"run": "npm test"}], event="pull_request_target")
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0]["confidence"], "medium")
                upload = action("actions/upload-artifact", version, path=".env")
                self.assertFalse(self.rule("CHA014", [upload]))
                upload["with"]["include-hidden-files"] = True
                self.assertTrue(self.rule("CHA014", [upload]))

    def test_012_trigger_alone_inspection_and_trusted_checkout_are_clear(self):
        cases = [
            [{"run": "npm test"}],
            [self.checkout(), {"run": "git diff --stat\ncat package.json\necho 'npm test'"}],
            [self.checkout(), {"run": "make --version\npython --version"}],
            [action("actions/checkout", "v6"), {"run": "npm test"}],
            [self.checkout(), action("actions/checkout", "v6"), {"run": "npm test"}],
            [self.checkout(), {"run": "npm test", "if": "${{ false }}"}],
        ]
        for steps in cases:
            with self.subTest(steps=steps):
                self.assertFalse(self.rule("CHA012", steps, event="pull_request_target"))
        self.assertFalse(self.rule("CHA012", [self.checkout(), {"run": "npm test"}], event="pull_request"))

    def test_011_012_outside_expression_literals_do_not_prove_disabled(self):
        for condition in (" ${{ false }}", "${{ false }} ", "${{ false }}\n", "${{ false }}${{ false }}", "${{ false"):
            with self.subTest(condition=condition):
                steps = [self.checkout(), {"run": "npm test"}]
                self.assertTrue(self.rule("CHA012", steps, event="pull_request_target", job={"if": condition}))
                self.assertTrue(self.rule("CHA011", [], event="pull_request", job={"if": condition, "runs-on": "self-hosted"}))
        for condition in ("${{ false }}", False, " false "):
            with self.subTest(disabled=condition):
                self.assertFalse(self.rule("CHA012", [self.checkout(), {"run": "npm test"}], event="pull_request_target", job={"if": condition}))

    def test_012_quoted_operators_are_arguments_not_execution_boundaries(self):
        scripts = [
            'echo "|" ./build.sh',
            "echo ';' ./build.sh",
            'echo "&&" ./build.sh',
            'echo "first line\n| ./build.sh\n; npm test"',
        ]
        for script in scripts:
            with self.subTest(script=script):
                self.assertFalse(self.rule("CHA012", [self.checkout(), {"run": script}], event="pull_request_target"))

    def test_012_real_multiline_commands_still_execute_after_quoted_operators(self):
        scripts = [
            'echo "|" ./unused.sh\n./build.sh',
            "echo ';' ./unused.sh\nnpm test",
            'echo "first\nsecond"\npython scripts/test.py',
            'echo "|"; ./build.sh',
        ]
        for script in scripts:
            with self.subTest(script=script):
                self.assertTrue(self.rule("CHA012", [self.checkout(), {"run": script}], event="pull_request_target"))

    def test_012_execution_must_use_the_checked_out_directory(self):
        checkout = self.checkout(path="fork")
        self.assertFalse(self.rule("CHA012", [checkout, {"run": "npm test"}], event="pull_request_target"))
        self.assertTrue(self.rule("CHA012", [checkout, {"run": "npm test", "working-directory": "fork"}], event="pull_request_target"))
        self.assertTrue(self.rule("CHA012", [checkout, {"run": "cd fork && npm test"}], event="pull_request_target"))
        self.assertTrue(self.rule("CHA012", [checkout, {"uses": "./fork/.github/actions/test"}], event="pull_request_target"))

    def test_013_triggering_artifact_then_workspace_script(self):
        found = self.rule("CHA013", [self.download(), {"run": "sh cmd.sh"}], event="workflow_run")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["step"], 1)

    def test_013_recognizes_download_action_with_upstream_default(self):
        steps = [action("dawidd6/action-download-artifact", "v6"), {"run": "make release"}]
        self.assertTrue(self.rule("CHA013", steps, event="workflow_run"))

    def test_013_same_run_data_only_or_isolated_download_is_clear(self):
        cases = [
            [action("actions/download-artifact", "v7"), {"run": "sh cmd.sh"}],
            [self.download(), {"run": "cat report.json\necho 'sh cmd.sh'"}],
            [self.download(path="${{ runner.temp }}/artifacts"), {"run": "sh cmd.sh"}],
            [self.download(path="reports"), {"run": "npm test"}],
            [self.download(), action("actions/checkout", "v7"), {"run": "npm test"}],
        ]
        for steps in cases:
            with self.subTest(steps=steps):
                self.assertFalse(self.rule("CHA013", steps, event="workflow_run"))
        self.assertFalse(self.rule("CHA013", [self.download(), {"run": "sh cmd.sh"}], event="push"))

    def test_013_checkout_clears_nested_artifacts_only_when_cleaning(self):
        steps = [self.download(path="artifact"), action("actions/checkout", "v7"), {"run": "bash artifact/script.sh"}]
        self.assertFalse(self.rule("CHA013", steps, event="workflow_run"))
        steps[1]["with"] = {"clean": False}
        self.assertTrue(self.rule("CHA013", steps, event="workflow_run"))

    def test_014_explicit_sensitive_paths_respect_hidden_file_setting(self):
        for path in (".env", ".env.production", ".npmrc", ".aws/credentials", ".git/config", "id_rsa"):
            with self.subTest(path=path):
                upload = action("actions/upload-artifact", "v7", path=path, **{"include-hidden-files": True})
                self.assertTrue(self.rule("CHA014", [upload]))

    def test_014_broad_hidden_upload_warns(self):
        upload = action("actions/upload-artifact", "v7", path=".", **{"include-hidden-files": "true"})
        self.assertTrue(self.rule("CHA014", [upload]))

    def test_014_modern_default_and_old_version_are_distinguished(self):
        for ref in ("v4", "v4.4.0", "v7", UPLOAD_V7_SHA, "f" * 40):
            with self.subTest(ref=ref):
                self.assertFalse(self.rule("CHA014", [action("actions/upload-artifact", ref, path=".")]))
        for ref in ("v3", "v4.3.2", "1746f4ab65b179e0ea60a494b83293b640dd5bba"):
            with self.subTest(ref=ref):
                self.assertTrue(self.rule("CHA014", [action("actions/upload-artifact", ref, path=".")]))

    def test_014_exclusions_and_nonsecret_examples_are_clear(self):
        cases = [
            action("actions/upload-artifact", "v7", path="reports/audit-report.json"),
            action("actions/upload-artifact", "v7", path=".env.example", **{"include-hidden-files": True}),
            action("actions/upload-artifact", "v7", path=".env\n!.env", **{"include-hidden-files": True}),
            action("actions/upload-artifact", "v7", path=".aws/credentials\n!.aws/**", **{"include-hidden-files": True}),
            action("actions/upload-artifact", "v7", path=".env"),
        ]
        for step in cases:
            with self.subTest(step=step):
                self.assertFalse(self.rule("CHA014", [step]))

    def test_014_all_known_sensitive_paths_can_be_excluded(self):
        exclusions = "\n".join("!**/" + pattern for pattern in (".env*", ".git/**", ".npmrc", ".pypirc", ".netrc", ".aws/**", ".ssh/**", "id_rsa", "id_ed25519"))
        upload = action("actions/upload-artifact", "v7", path=".\n" + exclusions, **{"include-hidden-files": True})
        self.assertFalse(self.rule("CHA014", [upload]))

    def test_015_explicit_write_cache_plus_untrusted_execution(self):
        cache = action("actions/cache", "v4", path="~/.npm", key="dependencies")
        steps = [cache, self.checkout(), {"run": "npm ci"}]
        found = self.rule("CHA015", steps, event="pull_request_target", job={"cache-mode": "write"})
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["step"], 1)

    def test_015_untrusted_files_saved_without_execution(self):
        steps = [self.download(path="cache"), action("actions/cache/save", "v4", path="cache", key="build")]
        self.assertTrue(self.rule("CHA015", steps, event="workflow_run", workflow={"cache-mode": "write-only"}))

    def test_015_cleaned_artifact_files_are_not_attributed_to_later_cache(self):
        steps = [self.download(path="cache"), action("actions/checkout", "v7"), action("actions/cache/save", "v4", path="cache", key="build")]
        self.assertFalse(self.rule("CHA015", steps, event="workflow_run", job={"cache-mode": "write"}))

    def test_015_readonly_defaults_regular_pr_and_cache_alone_are_clear(self):
        cache = action("actions/cache", "v4", path="~/.npm", key="dependencies")
        steps = [cache, self.checkout(), {"run": "npm ci"}]
        for mode in (None, "read", "none"):
            with self.subTest(mode=mode):
                extra = {} if mode is None else {"cache-mode": mode}
                self.assertFalse(self.rule("CHA015", steps, event="pull_request_target", job=extra))
        self.assertFalse(self.rule("CHA015", steps, event="pull_request", job={"cache-mode": "write"}))
        self.assertFalse(self.rule("CHA015", [cache], event="pull_request_target", job={"cache-mode": "write"}))

    def test_015_restore_only_early_save_and_safe_optout_are_clear(self):
        code = [self.checkout(), {"run": "npm test"}]
        cases = [
            [action("actions/cache/restore", "v4", path="~/.npm", key="dependencies")] + code,
            [action("actions/cache/save", "v4", path="~/.npm", key="dependencies")] + code,
            [action("actions/cache", "v4", path="~/.npm", key="dependencies"), self.checkout("v7"), {"run": "npm test"}],
        ]
        for steps in cases:
            with self.subTest(steps=steps):
                self.assertFalse(self.rule("CHA015", steps, event="pull_request_target", job={"cache-mode": "write"}))
        self.assertFalse(self.rule("CHA015", [action("actions/cache", "v4", path="cache")] + code, event="pull_request_target", workflow={"cache-mode": "write"}, job={"cache-mode": "none"}))

    def test_015_untrusted_inline_script_with_write_capability(self):
        steps = [action("actions/cache", "v4", path="cache", key="build"), {"run": 'echo "${{ github.event.comment.body }}"'}]
        self.assertTrue(self.rule("CHA015", steps, event="issue_comment", job={"cache-mode": "write"}))

    def test_016_quoted_environment_variable_still_allows_newline_injection(self):
        for target in ("GITHUB_ENV", "GITHUB_OUTPUT", "{GITHUB_ENV}"):
            with self.subTest(target=target):
                step = {"env": {"BODY": COMMENT}, "run": f'echo "BODY=$BODY" >> "${target}"'}
                self.assertTrue(self.rule("CHA016", [step]))

    def test_016_direct_expression_and_shell_assignment_are_followed(self):
        cases = [
            {"run": 'echo "BODY=${{ github.event.comment.body }}" >> "$GITHUB_ENV"'},
            {"run": 'BODY="${{ github.event.comment.body }}"\nCOPY=$BODY\necho "BODY=$COPY" >> "$GITHUB_OUTPUT"'},
            {"env": {"BODY": COMMENT}, "run": 'VALUE=$(printf "%s" "$BODY")\necho "BODY=$VALUE" >> "$GITHUB_ENV"'},
        ]
        for step in cases:
            with self.subTest(step=step):
                self.assertTrue(self.rule("CHA016", [step]))

    def test_016_artifact_contents_are_untrusted_environment_source(self):
        steps = [self.download(path="artifact"), {"run": 'cat artifact/environment >> "$GITHUB_ENV"'}]
        self.assertTrue(self.rule("CHA016", steps, event="workflow_run"))

    def test_016_constants_logs_and_shell_single_quotes_are_clear(self):
        cases = [
            {"run": 'echo "MODE=production" >> "$GITHUB_ENV"'},
            {"env": {"BODY": COMMENT}, "run": 'echo "$BODY"\necho "MODE=production" >> "$GITHUB_ENV"'},
            {"env": {"BODY": COMMENT}, "run": "echo 'BODY=$BODY' >> \"$GITHUB_ENV\""},
            {"run": '# echo "BODY=${{ github.event.comment.body }}" >> "$GITHUB_ENV"'},
            {"env": {"BODY": COMMENT}, "run": 'BODY=constant\necho "BODY=$BODY" >> "$GITHUB_ENV"'},
        ]
        for step in cases:
            with self.subTest(step=step):
                self.assertFalse(self.rule("CHA016", [step]))

    def test_016_numeric_guards_and_explicit_crlf_removal_are_clear(self):
        cases = [
            '[[ "$BODY" =~ ^[0-9]+$ ]] || exit 1\necho "NUMBER=$BODY" >> "$GITHUB_ENV"',
            'if [[ "$BODY" =~ ^[0-9]+$ ]]; then\n echo "NUMBER=$BODY" >> "$GITHUB_ENV"\nfi',
            'CLEAN=$(printf "%s" "$BODY" | tr -d \'\\r\\n\')\necho "BODY=$CLEAN" >> "$GITHUB_ENV"',
            'printf "BODY=%s" "$BODY" | tr -d \'\\r\\n\' >> "$GITHUB_ENV"',
        ]
        for script in cases:
            with self.subTest(script=script):
                self.assertFalse(self.rule("CHA016", [{"env": {"BODY": COMMENT}, "run": script}]))

    def test_016_validation_does_not_leak_outside_guard(self):
        script = 'if [[ "$BODY" =~ ^[0-9]+$ ]]; then\n echo "NUMBER=$BODY" >> "$GITHUB_ENV"\nfi\necho "BODY=$BODY" >> "$GITHUB_ENV"'
        self.assertTrue(self.rule("CHA016", [{"env": {"BODY": COMMENT}, "run": script}]))

    def test_016_validation_does_not_leak_into_else_or_elif(self):
        scripts = [
            'if [[ "$BODY" =~ ^[0-9]+$ ]]; then\n echo numeric\nelse\n echo "VALUE=$BODY" >> "$GITHUB_ENV"\nfi',
            'if [[ "$BODY" =~ ^[0-9]+$ ]]; then\n echo numeric\nelif [[ "$FLAG" == yes ]]; then\n echo "VALUE=$BODY" >> "$GITHUB_OUTPUT"\nfi',
            'if [[ "$FLAG" == yes ]]; then\n BODY=constant\nelse\n echo "VALUE=$BODY" >> "$GITHUB_ENV"\nfi',
        ]
        for script in scripts:
            with self.subTest(script=script):
                self.assertTrue(self.rule("CHA016", [{"env": {"BODY": COMMENT}, "run": script}]))

    def test_016_nested_guards_preserve_only_their_own_validation(self):
        script = 'if [[ "$BODY" =~ ^[0-9]+$ ]]; then\n if [[ "$FLAG" == yes ]]; then\n  echo "VALUE=$BODY" >> "$GITHUB_ENV"\n else\n  echo "VALUE=$BODY" >> "$GITHUB_ENV"\n fi\n echo "VALUE=$BODY" >> "$GITHUB_ENV"\nfi'
        self.assertFalse(self.rule("CHA016", [{"env": {"BODY": COMMENT}, "run": script}]))
        script += '\necho "VALUE=$BODY" >> "$GITHUB_ENV"'
        self.assertTrue(self.rule("CHA016", [{"env": {"BODY": COMMENT}, "run": script}]))

    def test_016_branch_assignments_merge_conservatively_after_fi(self):
        script = 'if [[ "$FLAG" == yes ]]; then\n BODY=constant\nelse\n echo nochange\nfi\necho "VALUE=$BODY" >> "$GITHUB_ENV"'
        self.assertTrue(self.rule("CHA016", [{"env": {"BODY": COMMENT}, "run": script}]))
        script = 'if [[ "$FLAG" == yes ]]; then\n [[ "$BODY" =~ ^[0-9]+$ ]] || exit 1\nelse\n [[ "$BODY" =~ ^[0-9]+$ ]] || exit 1\nfi\necho "VALUE=$BODY" >> "$GITHUB_ENV"'
        self.assertFalse(self.rule("CHA016", [{"env": {"BODY": COMMENT}, "run": script}]))

    def test_017_path_allowlist_does_not_leak_into_else(self):
        script = 'if [[ "$DIR" == "/opt/trusted/bin" ]]; then\n echo known\nelse\n echo "$DIR" >> "$GITHUB_PATH"\nfi'
        self.assertTrue(self.rule("CHA017", [{"env": {"DIR": COMMENT}, "run": script}]))

    def test_016_printed_or_bypassed_guards_do_not_sanitize_values(self):
        guards = [
            "echo '[[ \"$BODY\" =~ ^[0-9]+$ ]] || exit 1'",
            '[[ "$BODY" =~ ^[0-9]+$ || 1 == 1 ]] || exit 1',
            '[[ "$BODY" =~ ^[0-9]+$ ]]',
        ]
        for guard in guards:
            with self.subTest(guard=guard):
                script = guard + '\necho "BODY=$BODY" >> "$GITHUB_ENV"'
                self.assertTrue(self.rule("CHA016", [{"env": {"BODY": COMMENT}, "run": script}]))

    def test_016_unrelated_sanitizer_does_not_hide_unsafe_source(self):
        scripts = [
            'CLEAN="$BODY$(printf "%s" "$BODY" | tr -d \'\\r\\n\')"\necho "BODY=$CLEAN" >> "$GITHUB_ENV"',
            '{\n echo "BODY=$BODY"\n printf "%s" "$BODY" | tr -d \'\\r\\n\'\n} >> "$GITHUB_ENV"',
            'DELIMITER=$(uuidgen)\n{\n echo "UNSAFE=$BODY"\n echo "BODY<<$DELIMITER"\n printf "%s\\n" "$BODY"\n echo "$DELIMITER"\n} >> "$GITHUB_ENV"',
        ]
        for script in scripts:
            with self.subTest(script=script):
                self.assertTrue(self.rule("CHA016", [{"env": {"BODY": COMMENT}, "run": script}]))

    def test_016_random_multiline_delimiter_is_distinguished_from_fixed(self):
        for delimiter, expected in (("EOF", True), ("$DELIMITER", False)):
            script = f'DELIMITER=$(uuidgen)\n{{\n echo "BODY<<{delimiter}"\n printf "%s\\n" "$BODY"\n echo "{delimiter}"\n}} >> "$GITHUB_OUTPUT"'
            with self.subTest(delimiter=delimiter):
                self.assertEqual(bool(self.rule("CHA016", [{"env": {"BODY": COMMENT}, "run": script}])), expected)

    def test_017_untrusted_path_is_not_made_safe_by_quotes_or_numeric_guard(self):
        for script in ('echo "$DIR" >> "$GITHUB_PATH"', '[[ "$DIR" =~ ^[0-9]+$ ]] || exit 1\necho "$DIR" >> "$GITHUB_PATH"'):
            with self.subTest(script=script):
                self.assertTrue(self.rule("CHA017", [{"env": {"DIR": COMMENT}, "run": script}]))

    def test_017_artifact_path_source_is_reported(self):
        steps = [self.download(path="artifact"), {"run": 'DIR=$(cat artifact/path)\necho "$DIR" >> "$GITHUB_PATH"'}]
        self.assertTrue(self.rule("CHA017", steps, event="workflow_run"))

    def test_017_constants_and_literal_path_allowlists_are_clear(self):
        self.assertFalse(self.rule("CHA017", [{"run": 'echo "$HOME/.local/bin" >> "$GITHUB_PATH"'}]))
        self.assertFalse(self.rule("CHA017", [{"env": {"DIR": COMMENT}, "run": '[[ "$DIR" == "/opt/trusted/bin" ]] || exit 1\necho "$DIR" >> "$GITHUB_PATH"'}]))

    def test_016_017_do_not_copy_candidate_values_into_findings(self):
        marker = "FAKE_PRIVATE_VALUE_DO_NOT_LOG"
        script = f'echo "BODY=${{{{ github.event.comment.body }}}}{marker}" >> "$GITHUB_ENV"\necho "${{{{ github.event.comment.body }}}}{marker}" >> "$GITHUB_PATH"'
        findings = self.scan([{"run": script}])
        self.assertEqual({finding["rule_id"] for finding in findings}, {"CHA016", "CHA017"})
        self.assertNotIn(marker, str(findings))

    def test_existing_repository_workflow_is_clear_for_trust_rules(self):
        workflow_path = Path(__file__).resolve().parents[1] / ".github/workflows/auditor-ci.yml"
        # BaseLoader retains the literal 'on' key; the application owns its
        # GitHub-compatible YAML loader and is covered by integration tests.
        workflow = yaml.load(workflow_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        context = RuleContext(workflow_path, workflow)
        check(context)
        self.assertEqual(context.findings, [])


if __name__ == "__main__":
    unittest.main()
