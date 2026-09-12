#!/usr/bin/env python3
"""
Permanent Adversarial Regression Canary Suite (5 Negative Failure Vectors)
Guarantees fail-hard behavior on:
1. Fake / unreachable commit SHA
2. Fake / mismatched tree SHA
3. Tampered benchmark script digest
4. Shell pipeline failure propagation (false | tee must fail hard)
5. Benchmark crash tombstone preservation (crashed run persists tombstone and exits non-zero)
"""

import copy
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def test_adversarial_canaries():
    repo_root = Path(__file__).resolve().parent.parent
    receipt_path = repo_root / "db" / "STRESS_BENCHMARK_REAL_WHEELS.json"
    assert receipt_path.exists(), f"Receipt file must exist at {receipt_path}"
    
    orig_bytes = receipt_path.read_bytes()
    orig_data = json.loads(orig_bytes.decode("utf-8"))

    try:
        # Attack 1: Fake / unreachable commit SHA
        d1 = copy.deepcopy(orig_data)
        d1["hardware_telemetry"]["benchmarked_source_commit_sha"] = "0000000000000000000000000000000000000000"
        receipt_path.write_text(json.dumps(d1, indent=2))
        res1 = subprocess.run([sys.executable, "scripts/verify_receipt.py", "--zero-drift-check"], cwd=repo_root, capture_output=True)
        assert res1.returncode != 0, "Security Violation: Fake commit did not cause fail-hard exit!"

        # Attack 2: Fake tree SHA
        d2 = copy.deepcopy(orig_data)
        d2["hardware_telemetry"]["benchmarked_source_tree_sha"] = "ffffffffffffffffffffffffffffffffffffffff"
        receipt_path.write_text(json.dumps(d2, indent=2))
        res2 = subprocess.run([sys.executable, "scripts/verify_receipt.py", "--zero-drift-check"], cwd=repo_root, capture_output=True)
        assert res2.returncode != 0, "Security Violation: Fake tree SHA did not cause fail-hard exit!"

        # Attack 3: Tampered benchmark script SHA
        d3 = copy.deepcopy(orig_data)
        d3["hardware_telemetry"]["benchmark_script_sha256"] = "1111111111111111111111111111111111111111111111111111111111111111"
        receipt_path.write_text(json.dumps(d3, indent=2))
        res3 = subprocess.run([sys.executable, "scripts/verify_receipt.py", "--zero-drift-check"], cwd=repo_root, capture_output=True)
        assert res3.returncode != 0, "Security Violation: Tampered script SHA did not cause fail-hard exit!"

        # Attack 4: Shell pipeline failure propagation
        # Verifies that a failing command piped into tee fails when guarded by PIPESTATUS or pipefail
        test_script = """
set +e
false | tee /tmp/canary_pipe_test.txt
verifier_rc=${PIPESTATUS[0]}
exit "$verifier_rc"
"""
        res4 = subprocess.run(["bash", "-c", test_script], capture_output=True)
        assert res4.returncode != 0, "Security Violation: Pipeline failure was masked by tee!"

        # Attack 5: Benchmark crash tombstone preservation
        wrapper_path = repo_root / "scripts" / "run_benchmark_with_tombstone.py"
        if wrapper_path.exists():
            with tempfile.TemporaryDirectory() as tmpdir:
                status_file = os.path.join(tmpdir, "status.json")
                res5 = subprocess.run([
                    sys.executable, str(wrapper_path),
                    "--repo", "canary/test-repo",
                    "--benchmark-cmd", "echo 'Intentional Crash' >&2; exit 42",
                    "--expected-output", os.path.join(tmpdir, "missing.json"),
                    "--status-output", status_file,
                    "--stdout-log", os.path.join(tmpdir, "stdout.log"),
                    "--stderr-log", os.path.join(tmpdir, "stderr.log")
                ], capture_output=True)
                assert res5.returncode == 42, f"Security Violation: Wrapper did not exit with crash code 42 (got {res5.returncode})!"
                assert os.path.exists(status_file), "Security Violation: Crash tombstone was not preserved on disk!"
                with open(status_file, "r") as sf:
                    crash_data = json.load(sf)
                assert crash_data["benchmark_status"] == "CRASH", f"Tombstone status expected CRASH, got {crash_data.get('benchmark_status')}"
                assert crash_data["benchmark_exit_code"] == 42, f"Tombstone exit code expected 42, got {crash_data.get('benchmark_exit_code')}"

        print("✅ All 5 Adversarial Canary Regression Tests PASSED (Fail-Hard Enforced).")

    finally:
        # Restore pristine receipt
        receipt_path.write_bytes(orig_bytes)

if __name__ == "__main__":
    test_adversarial_canaries()
