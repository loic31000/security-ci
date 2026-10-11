#!/usr/bin/env python3
"""Validate a fresh JUnit XML test report; exit nonzero on missing or zero tests."""
import argparse
import os
from pathlib import Path
from defusedxml import ElementTree as ET


def validate(xml_path, workspace, started_ns):
    base = Path(workspace).resolve(strict=True)
    path = Path(xml_path)
    if not xml_path.strip() or path.is_absolute() or any(p == ".." for p in path.parts):
        raise ValueError("Use one relative JUnit XML path inside the repository")
    target = (base / path).resolve(strict=True)
    if not target.is_relative_to(base) or not target.is_file():
        raise ValueError("JUnit report must be a regular file inside the repository")
    if target.stat().st_size > 10_000_000:
        raise ValueError("JUnit report is too large")
    if target.stat().st_mtime_ns < int(started_ns):
        raise ValueError("JUnit report was not freshly produced by this test run")
    root = ET.parse(target).getroot()
    if root.tag not in ("testsuite", "testsuites"):
        raise ValueError("Expected JUnit testsuite/testsuites XML root")
    cases = root.findall(".//testcase")
    # .//testcase includes the root suite's direct children.
    if not cases:
        raise ValueError("JUnit report has zero test cases")
    failed = sum(
        any(case.find(tag) is not None for tag in ("failure", "error", "skipped"))
        for case in cases
    )
    if failed:
        raise ValueError(f"JUnit report has {failed} failed, errored or skipped tests")
    suites = [root] if root.tag == "testsuite" else [root, *root.findall(".//testsuite")]
    for suite in suites:
        for attr in ("failures", "errors", "skipped"):
            value = suite.get(attr, "0")
            if not value.isdigit() or int(value) != 0:
                raise ValueError(f"JUnit suite contains nonzero {attr}")
        declared = suite.get("tests")
        if declared is not None and (not declared.isdigit() or int(declared) < 1):
            raise ValueError("JUnit suite claims no executed tests")
    return len(cases)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--start-ns", required=True)
    args = parser.parse_args()
    try:
        count = validate(args.path, args.workspace, args.start_ns)
    except (ValueError, OSError, ET.ParseError) as error:
        print(f"::error::JUnit certification failed: {error}")
        return 1
    print(f"Validated {count} freshly executed and passing JUnit test(s)")
    print(f"### JUnit certified: {count} passed tests" )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
