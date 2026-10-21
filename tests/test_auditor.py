import unittest

from src.auditor import action_is_unpinned


class TestActionPinning(unittest.TestCase):
    def test_tag_branch_and_invalid_sha_are_flagged(self):
        references = [
            "actions/checkout@v4",
            "actions/checkout@main",
            "actions/checkout",
            "actions/checkout@" + "a" * 39,
            "actions/checkout@" + "a" * 41,
            "actions/checkout@" + "z" * 40,
        ]

        for reference in references:
            with self.subTest(reference=reference):
                self.assertTrue(action_is_unpinned(reference))

    def test_full_sha_is_not_flagged(self):
        reference = "actions/checkout@" + "a" * 40

        self.assertFalse(action_is_unpinned(reference))

    def test_local_and_docker_actions_are_skipped(self):
        references = [
            "./.github/actions/my-action",
            "docker://alpine:3",
        ]

        for reference in references:
            with self.subTest(reference=reference):
                self.assertFalse(action_is_unpinned(reference))
