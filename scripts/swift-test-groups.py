#!/usr/bin/env python3
"""Assign every discovered Swift test to one explicitly owned CI group."""

import argparse
import json
import os
from pathlib import Path
import re
import sys


CONFIG = Path(__file__).with_name("swift-test-groups.json")


def partition(config, discovery):
    owners = {}
    if not isinstance(config, dict) or not config:
        raise ValueError("No Swift test groups configured")
    for group, suites in config.items():
        if not isinstance(suites, list) or not suites:
            raise ValueError(f"Empty or invalid Swift test group: {group}")
        for suite in suites:
            if not isinstance(suite, str) or not re.fullmatch(r"\w+(?:\.\w+)+", suite):
                raise ValueError(f"Invalid Swift test suite: {suite!r}")
            if suite in owners:
                raise ValueError(f"Duplicate Swift test suite assignment: {suite}")
            owners[suite] = group

    groups = {group: [] for group in config}
    seen = set()
    for line in discovery.splitlines():
        test = line.strip()
        if not test:
            continue
        if not re.fullmatch(r"\w+(?:\.\w+)+/[^\r\n]+", test):
            raise ValueError(f"Invalid Swift test discovery line: {test!r}")
        if test in seen:
            raise ValueError(f"Duplicate discovered Swift test: {test}")
        seen.add(test)
        suite = test.split("/", 1)[0]
        if suite not in owners:
            raise ValueError(f"Unassigned Swift test suite: {suite}; update {CONFIG.name}")
        groups[owners[suite]].append(test)

    if not seen:
        raise ValueError("No Swift tests discovered")
    for group, tests in groups.items():
        if not tests:
            raise ValueError(f"No discovered Swift tests in group: {group}")
    return groups


def test_filter(tests):
    suites = sorted({test.split("/", 1)[0] for test in tests})
    return "^(" + "|".join(re.escape(suite) for suite in suites) + ")/"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("discovery", type=Path)
    parser.add_argument("--group", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    groups = partition(json.loads(CONFIG.read_text()), args.discovery.read_text())
    if args.group not in groups:
        raise ValueError(f"Unknown Swift test group: {args.group}")
    args.report.write_text(json.dumps(groups, indent=2) + "\n")
    summary = "".join(
        f"{group}: {len(tests)} test declarations in "
        f"{len({test.split('/', 1)[0] for test in tests})} suites.\n"
        for group, tests in groups.items()
    )
    print(summary, file=sys.stderr, end="")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
            output.write(summary)
    print(f"filter={test_filter(groups[args.group])}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError) as error:
        sys.exit(f"Swift test grouping failed: {error}")
