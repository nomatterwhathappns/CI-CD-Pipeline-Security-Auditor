# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 nomatterwhathappns
"""Offline evaluation must verify data and never execute a workflow."""

import importlib.util
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/evaluate_corpus.py"
spec = importlib.util.spec_from_file_location("evaluate_corpus", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TestCorpusEvaluation(unittest.TestCase):
    def test_manifest_rejects_alias_paths_and_repo_traversal(self):
        with TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            base = {"repo": "owner/repo", "path": ".github/workflows/ci.yml", "sha": "a" * 40}
            for extra in ({"repo": "owner/.."}, {"repo": "./repo"},
                          {"path": ".github/workflows/./ci.yml"}, {"path": ".github/workflows//ci.yml"}):
                with self.subTest(extra=extra):
                    manifest.write_text(json.dumps({"schema_version": 1, "files": [{**base, **extra}]}), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        module.read_manifest(manifest)

    def test_download_verifies_hash_before_writing(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            entry = {"repo": "owner/repo", "path": ".github/workflows/ci.yml", "sha": "a" * 40}
            with patch.object(module, "urlopen", return_value=io.BytesIO(b"incorrect data")):
                summary = module.evaluate({"files": [entry]}, root, download=True)
            self.assertTrue(summary["errors"])
            self.assertFalse((root / "owner/repo/.github/workflows/ci.yml").exists())

    def test_verified_download_replaces_hardlink_without_modifying_its_target(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "original.yml"
            original = b"original data must survive"
            source.write_bytes(original)
            path = root / "owner/repo/.github/workflows/ci.yml"
            path.parent.mkdir(parents=True)
            os.link(source, path)
            content = b"on: push\njobs: {test: {steps: [{run: echo ok}]}}\n"
            entry = {"repo": "owner/repo", "path": ".github/workflows/ci.yml", "sha": module.git_blob_sha(content)}
            with patch.object(module, "urlopen", return_value=io.BytesIO(content)):
                summary = module.evaluate({"files": [entry]}, root, download=True)
            self.assertEqual(summary["errors"], [])
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(path.read_bytes(), content)
            self.assertEqual(list(path.parent.glob("tmp*")), [])

    def test_verified_workflow_is_counted_without_execution(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "must-not-exist"
            content = f"on: push\njobs: {{test: {{steps: [{{run: 'touch {marker}'}}]}}}}\n".encode()
            path = root / "owner/repo/.github/workflows/ci.yml"
            path.parent.mkdir(parents=True)
            path.write_bytes(content)
            manifest = {"files": [{"repo": "owner/repo", "path": ".github/workflows/ci.yml", "sha": module.git_blob_sha(content)}]}
            summary = module.evaluate(manifest, root)
            self.assertEqual(summary["files_verified"], 1)
            self.assertEqual(summary["files_scanned"], 1)
            self.assertEqual(summary["errors"], [])
            self.assertFalse(marker.exists())
            path.write_bytes(content + b"# different\n")
            summary = module.evaluate(manifest, root)
            self.assertEqual(summary["files_verified"], 0)
            self.assertTrue(summary["errors"])

    def test_symlink_is_not_accepted_as_verified_source(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "owner/repo/.github/workflows/ci.yml"
            path.parent.mkdir(parents=True)
            content = b"on: push\njobs: {test: {steps: [{run: echo ok}]}}\n"
            other = root / "other"
            other.write_bytes(content)
            path.symlink_to(other)
            summary = module.evaluate({"files": [{"repo": "owner/repo", "path": ".github/workflows/ci.yml", "sha": module.git_blob_sha(content)}]}, root)
            self.assertEqual(summary["files_verified"], 0)
            self.assertTrue(summary["errors"])
