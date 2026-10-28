"""Protect final-stack CI eligibility and the full-stack comparison boundary."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class StackVerificationPolicyTests(unittest.TestCase):
    def test_every_pr_job_requires_a_ready_standalone_pr_or_the_stack_top(self):
        workflow = (ROOT / ".github/workflows/verify.yml").read_text()
        jobs = workflow.split("jobs:\n", 1)[1]
        blocks = re.split(r"(?=^  [\w-]+:\n)", jobs, flags=re.MULTILINE)
        checked = []
        gate = (
            "github.event_name != 'pull_request' || "
            "(!github.event.pull_request.draft && "
            "(!github.event.pull_request.stack || "
            "github.event.pull_request.stack.position == "
            "github.event.pull_request.stack.size))"
        )
        for block in blocks:
            if not block.strip():
                continue
            name = block.split(":", 1)[0].strip()
            condition = re.search(r"^    if: (.+)$", block, re.MULTILINE)
            self.assertIsNotNone(condition, name)
            if name in {"migration-scale", "static-analysis", "extended-products"}:
                self.assertEqual(condition[1],
                                 "github.event_name == 'schedule' || "
                                 "github.event_name == 'workflow_dispatch'")
                continue
            self.assertIn(gate, condition[1], name)
            checked.append(name)
        self.assertTrue(checked)

    def test_patch_checks_and_dependency_review_use_the_stack_trunk(self):
        workflow = (ROOT / ".github/workflows/verify.yml").read_text()
        base = "${{ github.event.pull_request.stack.base.sha || github.event.pull_request.base.sha }}"
        self.assertEqual(workflow.count(f"PR_BASE: {base}"), 2)
        self.assertIn(f"base-ref: {base}", workflow)
        self.assertIn("head-ref: ${{ github.event.pull_request.head.sha }}", workflow)


if __name__ == "__main__":
    unittest.main()
