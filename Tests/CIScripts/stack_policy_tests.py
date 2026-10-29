"""Protect final-stack CI eligibility and the full-stack comparison boundary."""

import json
from pathlib import Path
import re
import unittest
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]


class StackVerificationPolicyTests(unittest.TestCase):
    def jobs(self, filename="verify.yml"):
        workflow = (ROOT / ".github/workflows" / filename).read_text()
        blocks = re.split(r"(?=^  [\w-]+:\n)", workflow.split("jobs:\n", 1)[1],
                          flags=re.MULTILINE)
        return {block.split(":", 1)[0].strip(): block for block in blocks if block.strip()}

    def eligible(self, block, *, draft=False, position=None, event="pull_request"):
        condition = re.search(r"^    if: (.+)$", block, re.MULTILINE)
        self.assertIsNotNone(condition)
        stack = SimpleNamespace(position=position, size=3) if position else None
        github = SimpleNamespace(event_name=event, event=SimpleNamespace(
            pull_request=SimpleNamespace(draft=draft, stack=stack)))
        # These workflow conditions use only booleans, comparisons, and always().
        expression = condition[1].replace("&&", " and ").replace("||", " or ")
        expression = re.sub(r"!(?!=)", "not ", expression)
        return bool(eval(expression, {"__builtins__": {}},
                         {"github": github, "always": lambda: True}))

    def test_drafts_run_fast_checks_and_ready_candidates_run_all_merge_checks(self):
        jobs = self.jobs()
        fast = {"repository-checks", "workflows", "secrets"}
        full = fast | {"swift-test-suites", "swift-tests", "products"}
        self.assertEqual(set(jobs), full)
        for position in (None, 3):
            for draft, expected in ((True, fast), (False, full)):
                with self.subTest(position=position, draft=draft):
                    actual = {name for name, block in jobs.items()
                              if self.eligible(block, draft=draft, position=position)}
                    self.assertEqual(actual, expected)
        for draft in (False, True):
            for position in (1, 2):
                self.assertFalse(any(self.eligible(block, draft=draft, position=position)
                                     for block in jobs.values()))
        self.assertTrue(all(self.eligible(block, event="workflow_dispatch")
                            for block in jobs.values()))
        self.assertIn("if: always() &&", jobs["swift-tests"])
        self.assertIn('run: test "$GROUP_RESULT" = success', jobs["swift-tests"])

    def test_workflows_use_only_the_agreed_pr_and_manual_triggers(self):
        expected = {
            "verify.yml": {"pull_request", "workflow_dispatch"},
            "verify-qualification.yml": {"workflow_dispatch"},
            "verify-codeql.yml": {"workflow_dispatch", "workflow_call"},
        }
        for filename, events in expected.items():
            text = (ROOT / ".github/workflows" / filename).read_text()
            triggers = text.split("on:\n", 1)[1].split("\npermissions:", 1)[0]
            self.assertEqual(set(re.findall(r"^  ([\w_]+):", triggers, re.MULTILINE)), events)
        codeql = self.jobs("verify-codeql.yml")["static-analysis"]
        self.assertIn("    runs-on: macos-26-intel", codeql)
        self.assertIn("      security-events: write", codeql)
        self.assertIn("          queries: security-extended", codeql)
        qualification = self.jobs("verify-qualification.yml")
        self.assertIn("    if: inputs.migration_scale", qualification["migration-scale"])
        self.assertIn("    if: inputs.codeql", qualification["codeql"])
        self.assertIn("uses: ./.github/workflows/verify-codeql.yml", qualification["codeql"])
        self.assertIn("      security-events: write", qualification["codeql"])
        self.assertIn("VARIANT: ${{ inputs.product }}", qualification["products"])
        self.assertIn("            mode: debug", qualification["products"])
        self.assertIn("            mode: release", qualification["products"])

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
            for filename in ("verify-qualification.yml", "verify-codeql.yml"):
                for block in self.jobs(filename).values():
                    self.assertNotIn(f"    name: {check['context']}\n", block)

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
