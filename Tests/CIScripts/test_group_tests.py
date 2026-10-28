"""Keep CI test selection complete, disjoint, and strict about new suites."""

import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("groups", ROOT / "scripts/swift-test-groups.py")
groups = importlib.util.module_from_spec(spec)
spec.loader.exec_module(groups)


class SwiftTestGroupTests(unittest.TestCase):
    def setUp(self):
        self.config = {"core": ["Core.FormatTests"], "recovery": ["Core.RecoveryTests"]}
        self.discovery = "Core.FormatTests/roundTrip()\nCore.RecoveryTests/resume(phase:)\n"

    def test_partitions_every_test_once_and_filters_whole_suites(self):
        result = groups.partition(self.config, self.discovery)
        self.assertEqual(set(sum(result.values(), [])), set(self.discovery.splitlines()))
        for group, tests in result.items():
            selected = [test for test in self.discovery.splitlines()
                        if re.search(groups.test_filter(tests), test)]
            self.assertEqual(selected, tests)
        self.assertIsNone(re.search(groups.test_filter(result["core"]),
                                    "Core.FormatTestsExtra/roundTrip()"))

    def test_allows_suites_from_later_stack_layers_before_they_exist(self):
        self.config["core"].append("Core.FutureTests")
        self.assertEqual(len(groups.partition(self.config, self.discovery)["core"]), 1)

    def test_rejects_unassigned_and_duplicate_suite_ownership(self):
        with self.assertRaisesRegex(ValueError, "Unassigned"):
            groups.partition(self.config, self.discovery + "Core.NewTests/test()\n")
        self.config["recovery"].append("Core.FormatTests")
        with self.assertRaisesRegex(ValueError, "Duplicate.*assignment"):
            groups.partition(self.config, self.discovery)

    def test_rejects_missing_tests_and_empty_groups(self):
        for discovery in ("", "Core.FormatTests/test()\n"):
            with self.assertRaisesRegex(ValueError, "No .*Swift tests"):
                groups.partition(self.config, discovery)

    def test_rejects_corrupt_or_duplicate_discovery(self):
        for discovery in (self.discovery + "unexpected output\n",
                          self.discovery + self.discovery):
            with self.assertRaises(ValueError):
                groups.partition(self.config, discovery)

    def test_rejects_invalid_suite_names_and_empty_configuration(self):
        for config in ({}, ["invalid"], {"core": []}, {"core": ["invalid"]}):
            with self.assertRaises(ValueError):
                groups.partition(config, self.discovery)

    def test_workflow_runs_every_configured_group_exactly_once(self):
        config = json.loads(groups.CONFIG.read_text())
        workflow = (ROOT / ".github/workflows/verify.yml").read_text()
        job = workflow.split("  swift-test-suites:\n", 1)[1].split("  swift-tests:\n", 1)[0]
        matrix = re.findall(r"^          - group: ([\w-]+)$", job, re.MULTILINE)
        self.assertEqual(len(matrix), len(set(matrix)))
        self.assertEqual(set(matrix), set(config))


if __name__ == "__main__":
    unittest.main()
