#!/usr/bin/env python3
"""Prove the configured scanner catches a removed secret without disclosing it."""

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
        git("add", "Sample.swift")
        git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Add synthetic canary")
        sample.unlink()
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
        if not any(finding["File"] == "Sample.swift" for finding in findings):
            raise RuntimeError("Scanner failed to detect the removed Swift canary")
        if marker in report.read_text() or marker in result.stdout or marker in result.stderr:
            raise RuntimeError("Scanner exposed the synthetic secret despite redaction")
        print("Verified removed-secret detection and redacted report output.")


if __name__ == "__main__":
    main()
