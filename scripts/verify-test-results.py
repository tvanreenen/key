#!/usr/bin/env python3
"""Require executed tests and summarize the Swift Testing xUnit report."""

import os
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def summarize(path):
    path = Path(path)
    # SwiftPM may split XCTest and Swift Testing into suffixed reports.
    paths = sorted(path.parent.glob(f"{path.stem}*.xml"))
    if not paths:
        raise ValueError(f"Missing Swift test reports: {path}")
    cases = [case for report in paths for case in ET.parse(report).getroot().findall(".//testcase")]
    if not cases:
        raise ValueError("The Swift test report contains no test cases")
    skipped = sum(case.find("skipped") is not None for case in cases)
    failed = sum(case.find("failure") is not None or case.find("error") is not None for case in cases)
    if len(cases) == skipped:
        raise ValueError("Every reported Swift test was skipped")
    return f"Swift tests: {len(cases)} reported, {skipped} skipped, {failed} failed.\n", failed


if __name__ == "__main__":
    try:
        summary, failed = summarize(sys.argv[1])
        summary += "The 300-entry migration scale test is opt-in; it runs in Verify migration scale.\n"
        print(summary, end="")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
                output.write(summary)
        sys.exit(1 if failed else 0)
    except (OSError, ValueError, ET.ParseError) as error:
        sys.exit(f"Test-result verification failed: {error}")
