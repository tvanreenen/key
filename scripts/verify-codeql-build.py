#!/usr/bin/env python3
"""Bound the traced build and retain progress when the compiler is slow or stuck."""

import argparse
import datetime
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def process_snapshot():
    result = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,etime=,pcpu=,rss=,comm="],
        capture_output=True, text=True, timeout=5,
    )
    selected = []
    for line in result.stdout.splitlines():
        columns = line.split(None, 5)
        if len(columns) != 6:
            continue
        name = Path(columns[-1]).name.lower()
        if name in {"xcodebuild", "clang", "clang++", "java"} or name.endswith("buildservice") or any(
            term in name for term in ("swift", "codeql", "extractor")
        ):
            selected.append(line)
    return "PID PPID ELAPSED CPU_PERCENT RSS_KIB EXECUTABLE\n" + "\n".join(selected) + "\n"


def terminate(process, grace_seconds):
    # The build has its own process group, so cancellation includes its children.
    for number in (signal.SIGINT, signal.SIGTERM):
        try:
            os.killpg(process.pid, number)
        except ProcessLookupError:
            process.wait()
            return
        try:
            process.wait(timeout=grace_seconds)
            break
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run_build(command, log_directory, timeout_seconds, progress_seconds=30,
              grace_seconds=5, cancelled=lambda: 0):
    if any(not math.isfinite(limit) or limit <= 0
           for limit in (timeout_seconds, progress_seconds, grace_seconds)):
        raise ValueError("Timeout, progress interval, and termination grace must be finite and positive")
    log_directory = Path(log_directory)
    log_directory.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    timed_out = False
    cancelled_signal = 0
    output_path = log_directory / "build.log"
    with output_path.open("wb", buffering=0) as output, output_path.open("rb") as reader, \
            (log_directory / "progress.log").open("w", buffering=1) as progress:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        next_snapshot = 0.0
        try:
            while True:
                chunk = reader.read()
                if chunk:
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
                elapsed = time.monotonic() - start
                if elapsed >= next_snapshot:
                    stat = output_path.stat()
                    event = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                             "elapsed_seconds": round(elapsed, 1), "log_bytes": stat.st_size,
                             "output_age_seconds": round(max(0, time.time() - stat.st_mtime), 1)}
                    print("CODEQL_BUILD_PROGRESS " + json.dumps(event), flush=True)
                    progress.write(json.dumps(event) + "\n")
                    try:
                        progress.write(process_snapshot())
                    except (OSError, subprocess.TimeoutExpired) as error:
                        progress.write(f"Process snapshot unavailable: {type(error).__name__}\n")
                    next_snapshot = elapsed + progress_seconds
                if process.poll() is not None:
                    break
                cancelled_signal = cancelled()
                timed_out = elapsed >= timeout_seconds
                if timed_out or cancelled_signal:
                    terminate(process, grace_seconds)
                    break
                time.sleep(min(0.1, max(timeout_seconds - elapsed, 0.01)))
        finally:
            if process.poll() is None:
                terminate(process, grace_seconds)
        remainder = reader.read()
        if remainder:
            sys.stdout.buffer.write(remainder)
            sys.stdout.buffer.flush()
    return_code = 124 if timed_out else (128 + cancelled_signal if cancelled_signal else process.returncode)
    if return_code < 0:
        return_code = 128 - return_code
    summary = {"command": command, "elapsed_seconds": round(time.monotonic() - start, 2),
               "exit_code": return_code, "child_return_code": process.returncode,
               "timed_out": timed_out, "cancelled_signal": cancelled_signal,
               "timeout_seconds": timeout_seconds}
    (log_directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("CODEQL_BUILD_RESULT " + json.dumps(summary), flush=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--derived-data", required=True)
    parser.add_argument("--log-directory", default=".build/verification/codeql-build")
    parser.add_argument("--timeout-seconds", type=float, default=1800)
    parser.add_argument("--progress-seconds", type=float, default=30)
    args = parser.parse_args()
    received = 0

    def cancel(number, _frame):
        nonlocal received
        received = number

    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, cancel)
    command = ["/bin/zsh", str(ROOT / "scripts/verify-product.sh"),
               "stable", "release", "codeql", args.derived_data]
    result = run_build(command, args.log_directory, args.timeout_seconds,
                       args.progress_seconds, cancelled=lambda: received)
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
