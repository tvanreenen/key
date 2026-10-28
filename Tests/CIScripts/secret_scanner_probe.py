#!/usr/bin/env python3
"""Verify a narrow prose exception and redacted detection of removed secrets."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    with tempfile.TemporaryDirectory(prefix="key-secret-probe-") as directory:
        work = Path(directory)

        def git(*args):
            subprocess.run(["git", *args], cwd=work, check=True, capture_output=True)

        git("init", "--quiet")
        git("config", "user.name", "Key scanner verification")
        git("config", "user.email", "scanner@example.invalid")
        # Generate a deterministic non-credential, rather than embedding a
        # secret-shaped literal in this repository or contacting a provider.
        marker = hashlib.sha256(b"key scanner synthetic canary").hexdigest()
        sample = work / "Sample.swift"
        sample.write_text(f'let apiKey = "{marker}"\n')
        document = work / "docs/piv-recovery-plan.md"
        document.parent.mkdir()
        prose = "incorrect current keys,\nmissing/corrupt local records and entry bytes\n"
        document.write_text(prose + f'api_key = "{marker}"\n')
        git("add", "Sample.swift", "docs/piv-recovery-plan.md")
        git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Add synthetic canary")
        sample.unlink()
        document.write_text(prose)
        git("add", "-u")
        git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Remove synthetic canary")
        report = work / "report.json"
        result = subprocess.run([
            "python3", str(ROOT / "scripts/ci-tool.py"), "run", "gitleaks", "git",
            "--redact=100", "--no-banner", "--config", str(ROOT / ".gitleaks.toml"),
            "--log-opts=--all", "--report-format", "json", "--report-path", str(report), str(work),
        ], capture_output=True, text=True)
        if result.returncode != 1 or not report.exists():
            raise RuntimeError("Scanner did not reject the synthetic commit history")
        findings = json.loads(report.read_text())
        if len(findings) != 2 or {finding["File"] for finding in findings} != {
            "Sample.swift", "docs/piv-recovery-plan.md",
        }:
            raise RuntimeError("Scanner must allow reviewed prose and detect both removed canaries")
        if marker in report.read_text() or marker in result.stdout or marker in result.stderr:
            raise RuntimeError("Scanner exposed the synthetic secret despite redaction")
        print("Verified narrow prose exception, removed-secret detection, and redacted output.")


if __name__ == "__main__":
    main()
