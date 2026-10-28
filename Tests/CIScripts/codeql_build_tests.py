"""Exercise build failure, timeout, cancellation, and subprocess cleanup."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("codeql_build", ROOT / "scripts/verify-codeql-build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class CodeQLBuildTests(unittest.TestCase):
    def run_build(self, source, directory, **options):
        with contextlib.redirect_stdout(io.TextIOWrapper(io.BytesIO(), write_through=True)):
            return build.run_build([sys.executable, "-c", source], directory,
                                   progress_seconds=0.05, grace_seconds=0.1, **options)

    def test_retains_output_and_preserves_success_or_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            for code in (0, 7):
                output = Path(directory) / str(code)
                result = self.run_build(
                    f"import sys; print('build stdout', flush=True); "
                    f"print('build stderr', file=sys.stderr, flush=True); sys.exit({code})",
                    output, timeout_seconds=5,
                )
                self.assertEqual(result["exit_code"], code)
                self.assertFalse(result["timed_out"])
                self.assertIn("build stdout", (output / "build.log").read_text())
                self.assertIn("build stderr", (output / "build.log").read_text())
                self.assertEqual(json.loads((output / "summary.json").read_text()), result)

    def test_timeout_terminates_a_term_resistant_process_and_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child_pid = root / "child.pid"
            source = (
                "import pathlib, signal, subprocess, sys, time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "signal.signal(signal.SIGINT, signal.SIG_IGN); "
                "child = subprocess.Popen([sys.executable, '-c', "
                "'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "signal.signal(signal.SIGINT, signal.SIG_IGN); time.sleep(60)']); "
                f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid)); "
                "print('compiler started', flush=True); time.sleep(60)"
            )
            result = self.run_build(source, root / "logs", timeout_seconds=0.6)
            self.assertEqual(result["exit_code"], 124)
            self.assertTrue(result["timed_out"])
            self.assertLess(result["elapsed_seconds"], 5)
            state = subprocess.run(["ps", "-p", child_pid.read_text(), "-o", "stat="],
                                   capture_output=True, text=True)
            self.assertEqual(state.stderr, "")
            self.assertTrue(not state.stdout.strip() or state.stdout.strip().startswith("Z"))
            progress = (root / "logs/progress.log").read_text()
            self.assertIn("output_age_seconds", progress)
            self.assertIn("RSS_KIB", progress)
            self.assertIn("compiler started", (root / "logs/build.log").read_text())

    def test_cancellation_preserves_diagnostics_and_signal_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_build("import time; time.sleep(60)", directory,
                                    timeout_seconds=5, cancelled=lambda: signal.SIGTERM)
            self.assertEqual(result["exit_code"], 143)
            self.assertFalse(result["timed_out"])
            self.assertEqual(result["cancelled_signal"], signal.SIGTERM)
            self.assertTrue((Path(directory) / "summary.json").is_file())

    def test_rejects_invalid_limits_before_starting_a_process(self):
        with tempfile.TemporaryDirectory() as directory:
            for limit in (0, -1, float("nan"), float("inf")):
                with self.subTest(limit=limit), self.assertRaises(ValueError):
                    self.run_build("raise RuntimeError('must not start')", directory, timeout_seconds=limit)


if __name__ == "__main__":
    unittest.main()
