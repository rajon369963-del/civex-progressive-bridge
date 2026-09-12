#!/usr/bin/env python3
"""
AIR10 Benchmark Execution Wrapper with Machine-Readable Tombstone
Enforces P0: Failure evidence must survive benchmark crash.
"""

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys


def get_git_output(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode("utf-8").strip()
    except Exception:
        return "UNKNOWN"

def compute_file_sha256(filepath):
    if not os.path.exists(filepath):
        return None
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def main():
    parser = argparse.ArgumentParser(description="AIR10 Benchmark Execution Wrapper with Tombstone")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "unknown/unknown"))
    parser.add_argument("--benchmark-cmd", required=True, help="Command to execute benchmark")
    parser.add_argument("--expected-output", required=True, help="Path to expected benchmark JSON")
    parser.add_argument("--status-output", default="/tmp/benchmark_execution_status.json")
    parser.add_argument("--stdout-log", default="/tmp/benchmark_stdout.log")
    parser.add_argument("--stderr-log", default="/tmp/benchmark_stderr.log")
    args = parser.parse_args()

    source_sha = os.environ.get("GITHUB_SHA") or get_git_output(["git", "rev-parse", "HEAD"])
    source_tree_sha = get_git_output(["git", "rev-parse", "HEAD^{tree}"])
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF") or os.environ.get("GITHUB_REF") or "local"
    workflow_sha = os.environ.get("GITHUB_SHA") or source_sha
    workflow_repo = os.environ.get("GITHUB_REPOSITORY") or args.repo
    workflow_file_path = os.environ.get("GITHUB_WORKFLOW") or "workflow"
    run_id = os.environ.get("GITHUB_RUN_ID") or "local"
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT") or "1"

    now_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # 1. Write initial tombstone BEFORE executing benchmark
    tombstone = {
        "schema_version": "1.0",
        "repo": args.repo,
        "source_sha": source_sha,
        "source_tree_sha": source_tree_sha,
        "workflow_ref": workflow_ref,
        "workflow_sha": workflow_sha,
        "workflow_repository": workflow_repo,
        "workflow_file_path": workflow_file_path,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "benchmark_status": "STARTED",
        "benchmark_exit_code": None,
        "expected_result_path": args.expected_output,
        "result_sha256": None,
        "verifier_status": "NOT_RUN",
        "verifier_exit_code": None,
        "started_at_utc": now_utc,
        "finished_at_utc": None
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.status_output)), exist_ok=True)
    with open(args.status_output, "w") as f:
        json.dump(tombstone, f, indent=2)

    # 2. Execute benchmark and capture stdout/stderr
    os.makedirs(os.path.dirname(os.path.abspath(args.stdout_log)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.stderr_log)), exist_ok=True)

    print(f"⚡ [tombstone-wrapper] Starting benchmark: {args.benchmark_cmd}")
    print(f"⚡ [tombstone-wrapper] Initial tombstone persisted: {args.status_output}")

    with open(args.stdout_log, "w") as out_f, open(args.stderr_log, "w") as err_f:
        proc = subprocess.Popen(
            args.benchmark_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        stdout_lines = []
        stderr_lines = []

        import selectors
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ, ("stdout", out_f, stdout_lines))
        sel.register(proc.stderr, selectors.EVENT_READ, ("stderr", err_f, stderr_lines))

        while sel.get_map():
            for key, events in sel.select():
                stream_type, stream_f, accum = key.data
                line = key.fileobj.readline()
                if not line:
                    sel.unregister(key.fileobj)
                    continue
                stream_f.write(line)
                stream_f.flush()
                accum.append(line)
                if stream_type == "stdout":
                    sys.stdout.write(line)
                    sys.stdout.flush()
                else:
                    sys.stderr.write(line)
                    sys.stderr.flush()

        proc.wait()
        exit_code = proc.returncode

    finished_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result_sha256 = compute_file_sha256(args.expected_output)

    # 3. Classify execution status
    if exit_code != 0:
        if result_sha256 is not None:
            status = "FAIL"
        else:
            status = "CRASH"
    else:
        if result_sha256 is not None:
            status = "PASS"
        else:
            status = "MISSING_OUTPUT"

    # 4. Update final tombstone
    tombstone["benchmark_status"] = status
    tombstone["benchmark_exit_code"] = exit_code
    tombstone["result_sha256"] = result_sha256
    tombstone["finished_at_utc"] = finished_utc

    with open(args.status_output, "w") as f:
        json.dump(tombstone, f, indent=2)

    print(f"\n⚡ [tombstone-wrapper] Benchmark finished with code: {exit_code}")
    print(f"⚡ [tombstone-wrapper] Status: {status} | Result SHA-256: {result_sha256}")
    print(f"⚡ [tombstone-wrapper] Final tombstone updated: {args.status_output}")

    if status != "PASS":
        print(f"❌ [tombstone-wrapper] Proof FAILED (Status: {status}). Exiting fail-hard.")
        sys.exit(exit_code if exit_code != 0 else 1)

    print("✅ [tombstone-wrapper] Proof PASSED.")
    sys.exit(0)

if __name__ == "__main__":
    main()
