#!/usr/bin/env python3
"""Compare parsed SwiftPM/Xcode declarations and both committed lockfiles."""

import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def canonical_url(url):
    return url.removesuffix(".git").rstrip("/").lower()


def unique(items, label):
    result = {}
    for url, value in items:
        key = canonical_url(url)
        if key in result:
            raise ValueError(f"Duplicate dependency in {label}: {key}")
        result[key] = value
    return result


def manifest_dependencies(manifest):
    items = []
    for dependency in manifest["dependencies"]:
        controls = dependency.get("sourceControl", [])
        if len(controls) != 1:
            raise ValueError("CI requires explicit, exactly pinned Git dependencies")
        control = controls[0]
        exact = control["requirement"].get("exact", [])
        remote = control["location"].get("remote", [])
        if len(exact) != 1 or len(remote) != 1:
            raise ValueError("CI requires explicit, exactly pinned remote Git dependencies")
        items.append((remote[0]["urlString"], exact[0]))
    return unique(items, "Package.swift")


def project_dependencies(project):
    items = []
    for obj in project["objects"].values():
        if obj.get("isa") != "XCRemoteSwiftPackageReference":
            continue
        requirement = obj["requirement"]
        if requirement.get("kind") != "exactVersion":
            raise ValueError("Xcode dependencies must use exact versions")
        items.append((obj["repositoryURL"], requirement["version"]))
    return unique(items, "Xcode project")


def resolved_dependencies(lock):
    if lock.get("version") not in (2, 3):
        raise ValueError("Unsupported Package.resolved format")
    items = []
    for pin in lock["pins"]:
        if pin.get("kind") != "remoteSourceControl":
            raise ValueError("Unsupported dependency kind in Package.resolved")
        state = pin["state"]
        revision = state.get("revision", "")
        if len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision):
            raise ValueError("Resolved dependencies must pin a full Git revision")
        items.append((pin["location"], (pin["identity"], state["version"], revision)))
    return unique(items, "Package.resolved")


def verify(manifest, project, package_lock, xcode_lock):
    declared = manifest_dependencies(manifest)
    if declared != project_dependencies(project):
        raise ValueError("SwiftPM and Xcode dependency declarations disagree")
    resolved = resolved_dependencies(package_lock)
    if resolved != resolved_dependencies(xcode_lock):
        raise ValueError("SwiftPM and Xcode resolved identities, versions, or revisions disagree")
    for url, version in declared.items():
        if url not in resolved or resolved[url][1] != version:
            raise ValueError(f"Resolved dependency does not match declared version: {url}")
    return resolved


def main():
    manifest = json.loads(subprocess.check_output(["swift", "package", "dump-package"], cwd=ROOT))
    project = json.loads(subprocess.check_output([
        "plutil", "-convert", "json", "-o", "-", str(ROOT / "Key.xcodeproj/project.pbxproj")
    ]))
    locks = [json.loads(path.read_text()) for path in (
        ROOT / "Package.resolved",
        ROOT / "Key.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved",
    )]
    resolved = verify(manifest, project, *locks)
    lines = ["Verified SwiftPM/Xcode declarations and resolved pins:"]
    lines += [f"- {identity} {version} ({revision})" for identity, version, revision in resolved.values()]
    summary = "\n".join(lines) + "\n"
    print(summary, end="")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
            output.write(summary)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(f"Dependency verification failed: {error}")
