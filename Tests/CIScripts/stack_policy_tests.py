"""Protect final-stack CI eligibility and the full-stack comparison boundary."""

import json
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

    def test_required_merge_checks_have_stable_non_matrix_job_names(self):
        policy = json.loads((ROOT / ".github/main-ruleset.json").read_text())
        rule = next(rule for rule in policy["rules"]
                    if rule["type"] == "required_status_checks")
        checks = rule["parameters"]["required_status_checks"]
        self.assertTrue(checks)
        workflow = (ROOT / ".github/workflows/verify.yml").read_text()
        jobs = {}
        for block in re.split(r"(?=^  [\w-]+:\n)", workflow.split("jobs:\n", 1)[1],
                              flags=re.MULTILINE):
            name = re.search(r"^    name: (.+)$", block, re.MULTILINE)
            if name:
                jobs[name[1]] = block
        for check in checks:
            # Skipped matrices keep unresolved names; running matrices append
            # their values. Required gates need fixed, non-matrix job names.
            self.assertIn(check["context"], jobs)
            self.assertNotRegex(jobs[check["context"]], re.compile(r"^      matrix:", re.MULTILINE))
            self.assertEqual(check["integration_id"], 15368)

    def test_main_ruleset_requires_prs_and_limits_exception_scope(self):
        policy = json.loads((ROOT / ".github/main-ruleset.json").read_text())
        self.assertEqual(policy["enforcement"], "active")
        self.assertEqual(policy["conditions"]["ref_name"],
                         {"include": ["refs/heads/main"], "exclude": []})
        rules = {rule["type"]: rule for rule in policy["rules"]}
        self.assertTrue({"pull_request", "required_status_checks", "deletion",
                         "non_fast_forward"} <= rules.keys())
        self.assertEqual(rules["pull_request"]["parameters"]["allowed_merge_methods"],
                         ["squash"])
        self.assertEqual(rules["pull_request"]["parameters"]["required_approving_review_count"], 0)
        self.assertTrue(all(actor["bypass_mode"] == "pull_request"
                            for actor in policy["bypass_actors"]))

    def test_patch_checks_and_dependency_review_use_the_stack_trunk(self):
        workflow = (ROOT / ".github/workflows/verify.yml").read_text()
        base = "${{ github.event.pull_request.stack.base.sha || github.event.pull_request.base.sha }}"
        self.assertEqual(workflow.count(f"PR_BASE: {base}"), 2)
        self.assertIn(f"base-ref: {base}", workflow)
        self.assertIn("head-ref: ${{ github.event.pull_request.head.sha }}", workflow)


if __name__ == "__main__":
    unittest.main()
