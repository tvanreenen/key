"""Exercise dependency drift and missing/failed test-report boundaries."""

import copy
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dependencies = load_script("verify-dependencies")
reports = load_script("verify-test-results")


class DependencyVerificationTests(unittest.TestCase):
    def setUp(self):
        url = "https://github.com/example/package.git"
        self.manifest = {"dependencies": [{"sourceControl": [{
            "identity": "package", "location": {"remote": [{"urlString": url}]},
            "requirement": {"exact": ["1.2.3"]},
        }]}]}
        self.project = {"objects": {"package": {
            "isa": "XCRemoteSwiftPackageReference", "repositoryURL": url,
            "requirement": {"kind": "exactVersion", "version": "1.2.3"},
        }}}
        self.lock = {"version": 3, "originHash": "swiftpm-metadata", "pins": [{
            "identity": "package", "kind": "remoteSourceControl", "location": url,
            "state": {"version": "1.2.3", "revision": "a" * 40},
        }]}
        self.xcode_lock = copy.deepcopy(self.lock)
        self.xcode_lock["originHash"] = "different-xcode-metadata"

    def verify(self):
        return dependencies.verify(self.manifest, self.project, self.lock, self.xcode_lock)

    def test_accepts_equal_pins_with_different_resolution_metadata(self):
        self.assertEqual(len(self.verify()), 1)

    def test_rejects_project_version_drift(self):
        self.project["objects"]["package"]["requirement"]["version"] = "1.2.4"
        with self.assertRaisesRegex(ValueError, "declarations disagree"):
            self.verify()

    def test_rejects_same_version_with_different_commit(self):
        self.xcode_lock["pins"][0]["state"]["revision"] = "b" * 40
        with self.assertRaisesRegex(ValueError, "revisions disagree"):
            self.verify()

    def test_rejects_stale_locks_even_when_both_agree(self):
        for lock in (self.lock, self.xcode_lock):
            lock["pins"][0]["state"]["version"] = "1.2.2"
        with self.assertRaisesRegex(ValueError, "declared version"):
            self.verify()

    def test_rejects_missing_and_duplicate_pins(self):
        self.xcode_lock["pins"] = []
        with self.assertRaises(ValueError):
            self.verify()
        self.xcode_lock = copy.deepcopy(self.lock)
        self.lock["pins"].append(copy.deepcopy(self.lock["pins"][0]))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.verify()

    def test_rejects_unpinned_and_unsupported_dependencies(self):
        control = self.manifest["dependencies"][0]["sourceControl"][0]
        control["requirement"] = {"range": ["1.0.0", "2.0.0"]}
        with self.assertRaisesRegex(ValueError, "exactly pinned"):
            self.verify()
        self.manifest["dependencies"] = [{"fileSystem": [{"path": "/tmp/local"}]}]
        with self.assertRaises(ValueError):
            self.verify()


class TestReportVerificationTests(unittest.TestCase):
    def summarize(self, xml):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.xml"
            path.write_text(xml)
            return reports.summarize(path)

    def test_counts_failures_and_skips(self):
        summary, failures = self.summarize(
            '<testsuites><testsuite><testcase/><testcase><skipped/></testcase>'
            '<testcase><failure/></testcase></testsuite></testsuites>'
        )
        self.assertIn("3 reported, 1 skipped, 1 failed", summary)
        self.assertEqual(failures, 1)

    def test_rejects_empty_or_entirely_skipped_runs(self):
        for xml in ('<testsuites/>', '<testsuite><testcase><skipped/></testcase></testsuite>'):
            with self.assertRaises(ValueError):
                self.summarize(xml)

    def test_accepts_swiftpm_suffixed_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "results.xml"
            base.with_name("results-swift-testing.xml").write_text(
                '<testsuites><testsuite><testcase/></testsuite></testsuites>'
            )
            summary, failures = reports.summarize(base)
            self.assertIn("1 reported", summary)
            self.assertEqual(failures, 0)


class ProductBuildInvocationTests(unittest.TestCase):
    def test_codeql_disables_cached_and_integrated_compilation_only_for_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            capture = work / "arguments"
            compiler = work / "xcodebuild"
            compiler.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CI_TEST_BUILD_ARGS"\n')
            compiler.chmod(0o755)
            fixture_path = f"{work}:{os.environ['PATH']}"
            # Restore fixture commands after the runner's system Zsh startup.
            environment = dict(os.environ, PATH=fixture_path,
                               ZDOTDIR=str(ROOT / "Tests/ScriptFixtures"),
                               KEY_SCRIPT_TEST_PATH=fixture_path, CI_TEST_BUILD_ARGS=str(capture))
            for operation in ("build", "codeql"):
                command = [
                    str(ROOT / "scripts/verify-product.sh"), "stable", "release", operation,
                ]
                if operation == "codeql":
                    command = [sys.executable, str(ROOT / "scripts/verify-codeql-build.py"),
                               "--derived-data", str(work / "DerivedData"),
                               "--log-directory", str(work / "logs"), "--timeout-seconds", "5"]
                capture.unlink(missing_ok=True)
                subprocess.run(command, env=environment, check=True, stdout=subprocess.DEVNULL,
                               timeout=10)
                args = capture.read_text().splitlines()
                self.assertIn("CODE_SIGNING_ALLOWED=NO", args)
                self.assertIn("ARCHS=arm64", args)
                destination = args[args.index("-destination") + 1]
                self.assertEqual(
                    destination,
                    "generic/platform=macOS" if operation == "codeql" else "platform=macOS,arch=arm64",
                )
                for flag in (
                    "COMPILATION_CACHE_ENABLE_CACHING=NO",
                    "SWIFT_ENABLE_COMPILE_CACHE=NO",
                    "SWIFT_USE_INTEGRATED_DRIVER=NO",
                ):
                    self.assertEqual(flag in args, operation == "codeql")


if __name__ == "__main__":
    unittest.main()
