#!/usr/bin/env python3
"""
Permanent Adversarial Regression Canary Suite
Guarantees that verify_receipt.py fails hard (exit code 1) on:
1. Fake / unreachable commit SHA
2. Fake / mismatched tree SHA
3. Tampered benchmark script digest
"""

import copy
import json
import subprocess
import sys
from pathlib import Path

def test_adversarial_canaries():
    repo_root = Path(__file__).resolve().parent.parent
    receipt_path = repo_root / "db" / "STRESS_BENCHMARK_REAL_WHEELS.json"
    assert receipt_path.exists(), "Receipt file must exist"
    
    orig_bytes = receipt_path.read_bytes()
    orig_data = json.loads(orig_bytes.decode("utf-8"))

    try:
        # Attack 1: Fake commit SHA
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

        # Attack 3: Tampered script SHA
        d3 = copy.deepcopy(orig_data)
        d3["hardware_telemetry"]["benchmark_script_sha256"] = "1111111111111111111111111111111111111111111111111111111111111111"
        receipt_path.write_text(json.dumps(d3, indent=2))
        res3 = subprocess.run([sys.executable, "scripts/verify_receipt.py", "--zero-drift-check"], cwd=repo_root, capture_output=True)
        assert res3.returncode != 0, "Security Violation: Tampered script SHA did not cause fail-hard exit!"

        print("✅ All 3 Adversarial Canary Regression Tests PASSED (Fail-Hard Enforced).")

    finally:
        # Restore pristine receipt
        receipt_path.write_bytes(orig_bytes)

if __name__ == "__main__":
    test_adversarial_canaries()
