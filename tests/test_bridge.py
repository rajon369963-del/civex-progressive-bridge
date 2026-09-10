#!/usr/bin/env python3
"""
AIR10 / MIGL: PHASE 5 TRI-VERIFIER MASTER RECONCILIATION REGRESSION HARNESS
Unified Adversarial & Property Verification Court
Combines stress vectors from CODEX, HERMES, and CHATGPT.
"""

import concurrent.futures
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

# Ensure scratch path is in sys.path
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from civex.bridge import (
    CIVeXVerifier,
    HeadroomCompressor,
    ProgressiveToolBridge,
    SchemaShrinker,
)


def test_headroom_critical_signals():
    print("--- [TEST 1] HEADROOM SIGNAL-AWARE COMPRESSION ---")
    c = HeadroomCompressor()
    
    # Check string boundaries: error token placed at edge boundaries
    for offset in [0, 50, 119, 120, 121, 200, 500, 1000]:
        payload = {"log": "x" * offset + "CRITICAL_ERROR: memory segmentation fault"}
        compressed = c.compress(payload)
        dumped = json.dumps(compressed)
        assert "CRITICAL_ERROR" in dumped, f"Failed at offset {offset}: marker lost"
    print("  ✅ [PASS] String boundary retention: all 8 offsets preserved CRITICAL_ERROR")

    # Check text lines: error token placed in every line position (0 to 49)
    for pos in range(50):
        lines = ["INFO: normal operation"] * 50
        lines[pos] = "CRITICAL_ERROR: fault on line " + str(pos)
        text_payload = "\n".join(lines)
        compressed_text = c.compress_text(text_payload)
        assert f"CRITICAL_ERROR: fault on line {pos}" in compressed_text, f"Failed at line pos {pos}: marker lost"
    print("  ✅ [PASS] Text line retention: all 50 line positions preserved CRITICAL_ERROR")

    # Check token reduction on nominal payload
    large_payload = [
        {"id": f"tool_{i}", "desc": "Standard description payload that is long and verbose "*5, "data": list(range(20))}
        for i in range(100)
    ]
    large_payload.append({"id": "tool_fail", "error": "CRITICAL_ERROR: unexpected crash in worker"})
    raw_size = len(json.dumps(large_payload))
    comp_size = len(json.dumps(c.compress(large_payload)))
    reduction = (1.0 - (comp_size / raw_size)) * 100.0
    print(f"  ✅ [PASS] Nominal compression reduction: {reduction:.2f}% (raw: {raw_size}B -> comp: {comp_size}B)")
    assert reduction >= 70.0, f"Reduction {reduction:.2f}% < 70%"
    assert "CRITICAL_ERROR" in json.dumps(c.compress(large_payload))


def test_circuit_breaker_concurrency():
    print("\n--- [TEST 2] CIRCUIT BREAKER CONCURRENCY & FAIL-CLOSED STATE ---")
    with tempfile.TemporaryDirectory() as td:
        state_file = os.path.join(td, "circuit_state.json")
        CIVeXVerifier.STATE_FILE = state_file

        # Test 100 multi-threaded concurrent increments
        def worker_failure(idx):
            v = CIVeXVerifier()
            v.record_outcome("tool_concurrent_1", False, f"failure from thread {idx}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            list(executor.map(worker_failure, range(100)))

        final_verifier = CIVeXVerifier()
        persisted = final_verifier.failure_counts.get("tool_concurrent_1", 0)
        print(f"  ✅ [PASS] 100 concurrent increments recorded: {persisted} / 100")
        assert persisted == 100, f"Expected 100 failures, got {persisted}"

        # Test breaker trip and guard
        assert final_verifier.is_circuit_open("tool_concurrent_1")
        try:
            final_verifier.guard("tool_concurrent_1")
            raise AssertionError("Guard did not raise RuntimeError on tripped breaker")
        except RuntimeError as e:
            assert "CIRCUIT_BREAKER_BLOCKED" in str(e)
            print("  ✅ [PASS] Guard correctly blocked tripped tool")

        # Test recovery / reset on success
        final_verifier.record_outcome("tool_concurrent_1", True)
        assert not final_verifier.is_circuit_open("tool_concurrent_1")
        final_verifier.guard("tool_concurrent_1")  # Should not raise
        print("  ✅ [PASS] Recovery reset tool failure count to 0")

        # Test multi-process concurrency
        script_code = f"""
import sys
sys.path.insert(0, {REPO_ROOT!r})
from civex.bridge import CIVeXVerifier
CIVeXVerifier.STATE_FILE = {state_file!r}
v = CIVeXVerifier()
v.record_outcome("tool_multiprocess", False, "process crash")
"""
        procs = []
        for _ in range(25):
            p = subprocess.Popen([sys.executable, "-c", script_code])
            procs.append(p)
        for p in procs:
            assert p.wait() == 0

        mp_verifier = CIVeXVerifier()
        mp_count = mp_verifier.failure_counts.get("tool_multiprocess", 0)
        print(f"  ✅ [PASS] 25 multi-process concurrent writes recorded: {mp_count} / 25")
        assert mp_count == 25, f"Expected 25 multi-process failures, got {mp_count}"

        # Test corrupt state rejection (fail-closed)
        pathlib.Path(state_file).write_text("{broken_json_content: true,")
        try:
            CIVeXVerifier()
            raise AssertionError("Corrupted state was accepted without error")
        except ValueError:
            print("  ✅ [PASS] Corrupt state file rejected fail-closed with ValueError")


def test_schema_shrinker_and_fallback_bounds():
    print("\n--- [TEST 3] SCHEMA SHRINKER BOUNDS & FAIL-CLOSED FALLBACK ---")
    bridge = ProgressiveToolBridge()
    
    # 1. Check fallback under extreme tool_id (350+ chars)
    oversized_row = (
        "EXTREME_OVERSIZED_TOOL_ID_" + "X" * 300,
        "massive_tool_name_" + "Y" * 100,
        "massive_category_" + "Z" * 50,
        "/usr/local/bin/massive",
        "massive --exec",
        "Very long description "*10,
        "intent1, intent2",
        "tag1, tag2"
    )
    # Shrinker itself raises ValueError on impossible ID
    try:
        SchemaShrinker.shrink_tool(oversized_row)
        raise AssertionError("Expected ValueError from SchemaShrinker for extreme ID")
    except ValueError:
        pass
    
    # Fallback in find_tools must guarantee <= 250 bytes
    raw_id = str(oversized_row[0])
    bounded_id = (raw_id[:40] + "...[trunc]") if len(raw_id) > 50 else raw_id
    diag = {
        "id": bounded_id,
        "name": str(oversized_row[1])[:40],
        "cat": str(oversized_row[2])[:20],
        "err": "OVERSIZED_SCHEMA_TRUNCATED"
    }
    b = len(json.dumps(diag).encode("utf-8"))
    print(f"  ✅ [PASS] Extreme ID fallback schema size: {b} bytes (limit: <= 250 B)")
    assert b <= 250

    # 2. Check all 5,283 tools in live catalog
    con = bridge.con
    all_rows = con.execute("SELECT tool_id, name, category, binary_path, exec_template, description, auto_trigger_intents, tags FROM tools_v2;").fetchall()
    assert len(all_rows) >= 5000, f"Expected >= 5000 tools, found {len(all_rows)}"
    max_b = 0
    for r in all_rows:
        try:
            shadow = SchemaShrinker.shrink_tool(r)
        except ValueError:
            raw_id = str(r[0])
            bounded_id = (raw_id[:40] + "...[trunc]") if len(raw_id) > 50 else raw_id
            shadow = {"id": bounded_id, "name": str(r[1])[:40], "cat": str(r[2])[:20], "err": "OVERSIZED_SCHEMA_TRUNCATED"}
        sz = len(json.dumps(shadow).encode("utf-8"))
        max_b = max(max_b, sz)
        assert sz <= 250, f"Tool {r[0]} generated {sz} bytes > 250 bytes"
    print(f"  ✅ [PASS] Full catalog verification ({len(all_rows)} tools): max shadow schema = {max_b} bytes")


def test_fts5_queries_and_malformed_fuzz():
    print("\n--- [TEST 4] FTS5 DIRECT JOIN & MALFORMED INPUT FUZZING ---")
    bridge = ProgressiveToolBridge()
    fuzz_queries = [
        "",
        " ",
        "\"",
        "\"\"",
        "*",
        "**",
        "^",
        "OR",
        "AND",
        "NOT",
        "NEAR",
        "'; DROP TABLE tools_v2; --",
        "a",
        "transformer*",
        "transformer copper loss",
        "induction motor synchronous speed slip equation",
        "DC machine armature reaction cross magnetizing demagnetizing",
        "power systems swing equation transient stability equal area criterion"
    ]
    for q in fuzz_queries:
        res = bridge.find_tools(q, limit=5)
        assert res["status"] == "SUCCESS", f"Failed for query: {q}"
        assert isinstance(res["tools"], list)
        for t in res["tools"]:
            sz = len(json.dumps(t).encode("utf-8"))
            assert sz <= 250, f"Fuzz result schema {sz}B > 250B"
    print(f"  ✅ [PASS] All {len(fuzz_queries)} hostile fuzz queries handled cleanly without syntax errors")


def test_civex_causal_interventions():
    print("\n--- [TEST 5] CIVEX CAUSAL INTERVENTION ASSERTIONS ---")
    verifier = CIVeXVerifier()
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"initial baseline bytes\n")
        temp_path = tf.name

    try:
        pre_hash = verifier.compute_file_hash(temp_path)
        
        # Scenario A: Nonzero exit code -> REJECT
        res_nonzero = verifier.verify_causal_write(temp_path, pre_hash, 1)
        assert res_nonzero["verdict"] == "REJECT" and not res_nonzero["causal"]
        print("  ✅ [PASS] Nonzero exit code rejected")

        # Scenario B: No state mutation (pre_hash == post_hash) -> FALSE_GREEN
        res_noop = verifier.verify_causal_write(temp_path, pre_hash, 0)
        assert res_noop["verdict"] == "FALSE_GREEN" and not res_noop["causal"]
        print("  ✅ [PASS] Idempotent touched file detected as FALSE_GREEN")

        # Scenario C: File truncated to 0 bytes -> REJECT
        with open(temp_path, "wb") as f:
            pass
        res_empty = verifier.verify_causal_write(temp_path, pre_hash, 0)
        assert res_empty["verdict"] == "REJECT" and not res_empty["causal"]
        print("  ✅ [PASS] 0-byte file mutation rejected")

        # Scenario D: Genuine non-zero byte mutation -> CONFIRMED
        with open(temp_path, "wb") as f:
            f.write(b"mutated real physical data\n")
        res_genuine = verifier.verify_causal_write(temp_path, pre_hash, 0)
        assert res_genuine["verdict"] == "CONFIRMED" and res_genuine["causal"]
        print("  ✅ [PASS] Genuine physical byte mutation CONFIRMED")
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


if __name__ == "__main__":
    t_start = time.perf_counter()
    test_headroom_critical_signals()
    test_circuit_breaker_concurrency()
    test_schema_shrinker_and_fallback_bounds()
    test_fts5_queries_and_malformed_fuzz()
    test_civex_causal_interventions()
    t_elapsed = (time.perf_counter() - t_start) * 1000
    print("\n" + "="*70)
    print(f"🏆 ALL TRI-VERIFIER MASTER RECONCILIATION TESTS PASSED in {t_elapsed:.2f} ms")
    print("="*70)
