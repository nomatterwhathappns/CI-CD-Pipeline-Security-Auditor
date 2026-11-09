# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 nomatterwhathappns
"""Independent graph review: caller-specific sources and workflow boundaries."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from src.analysis.graph import analyze_graph


class TestIndependentGraphReview(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return target

    def test_safe_first_call_does_not_hide_later_untrusted_input(self):
        entry = self.write(".github/workflows/main.yml", """on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/title
        with:
          title: fixed
      - uses: ./.github/actions/title
        with:
          title: ${{ github.event.pull_request.title }}
""")
        callee = self.write(".github/actions/title/action.yml", """name: title
description: static example
inputs:
  title:
    description: title input
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "${{ inputs.title }}"
""")
        result = analyze_graph([entry], self.root)
        findings = [f for f in result["findings"] if f["rule_id"] == "CHA023"]
        self.assertTrue(findings)
        self.assertTrue(any(Path(f["file"]) == callee for f in findings))
        self.assertEqual(len(result["files_analyzed"]), 2)

    def test_caller_environment_does_not_leak_into_reusable_workflow(self):
        entry = self.write(".github/workflows/main.yml", """on: pull_request
env:
  TITLE: ${{ github.event.pull_request.title }}
jobs:
  call:
    uses: ./.github/workflows/reuse.yml
""")
        self.write(".github/workflows/reuse.yml", """on:
  workflow_call:
jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ env.TITLE }}"
""")
        result = analyze_graph([entry], self.root)
        self.assertNotIn("CHA023", {f["rule_id"] for f in result["findings"]})
        self.assertEqual(len(result["files_analyzed"]), 2)

    def test_remote_implementation_remains_unresolved_even_if_sha_pinned(self):
        entry = self.write(".github/workflows/main.yml", """on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: owner/action@1111111111111111111111111111111111111111
""")
        result = analyze_graph([entry], self.root)
        self.assertEqual(result["findings"], [])
        self.assertTrue(result["unresolved"])

    def test_recursive_local_action_is_reported_without_execution(self):
        entry = self.write(".github/workflows/main.yml", """on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/a
""")
        self.write(".github/actions/a/action.yml", """name: a
description: cycle
runs:
  using: composite
  steps:
    - uses: ./.github/actions/b
""")
        self.write(".github/actions/b/action.yml", """name: b
description: cycle
runs:
  using: composite
  steps:
    - uses: ./.github/actions/a
""")
        result = analyze_graph([entry], self.root)
        self.assertTrue(result["unresolved"] or result["errors"])
        self.assertLessEqual(len(result["files_analyzed"]), 3)
