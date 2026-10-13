"""Tests for --output name/extension resolution in portfilter.cli."""

from __future__ import annotations

import os
import tempfile
import time
import unittest

from portfilter.cli import _resolve_output


class ResolveOutputTest(unittest.TestCase):
    def test_none_means_no_export(self) -> None:
        self.assertIsNone(_resolve_output(None, loop_mode=False))
        self.assertIsNone(_resolve_output(None, loop_mode=True))

    def test_extension_is_added(self) -> None:
        self.assertEqual(_resolve_output("results", loop_mode=False), "results.json")
        self.assertEqual(_resolve_output("results", loop_mode=True), "results.jsonl")

    def test_existing_extension_is_kept(self) -> None:
        self.assertEqual(_resolve_output("results.txt", False), "results.txt")
        self.assertEqual(_resolve_output("log.jsonl", True), "log.jsonl")

    def test_empty_value_defaults_to_timestamped_name(self) -> None:
        name = _resolve_output("", False)
        self.assertRegex(name, r"^portfilter-\d{8}-\d{6}\.json$")

    def test_directory_gets_timestamped_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            name = _resolve_output(directory, False)
            self.assertTrue(name.startswith(directory + os.sep))
            self.assertRegex(name, r"portfilter-\d{8}-\d{6}\.json$")

    def test_trailing_slash_is_treated_as_directory(self) -> None:
        name = _resolve_output("out/", True)
        self.assertRegex(name, r"^out[\\/]portfilter-\d{8}-\d{6}\.jsonl$")

    def test_default_does_not_overwrite_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            first = os.path.join(directory, f"portfilter-{stamp}.json")
            with open(first, "w", encoding="utf-8") as fh:
                fh.write("x")
            name = _resolve_output(directory, False)
            self.assertEqual(name, os.path.join(directory, f"portfilter-{stamp}-1.json"))


if __name__ == "__main__":
    unittest.main()