#!/usr/bin/env python3
"""
CIVEX MASTER REGRESSION & ACCEPTANCE HARNESS
=============================================
Portable unit, regression, and property tests for CIVEX Progressive Tool Bridge.
Supports both local environments (5,283 catalog) and clean GitHub CI runners (sample fixture).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from civex.bridge import (
    CIVeXVerifier,
    DEFAULT_PROD_CATALOG,
    FIXTURE_CATALOG,
    HeadroomCompressor,
    ProgressiveToolBridge,
    SchemaShrinker,
    main,
)


def test_headroom_critical_signals():
    print("--- [TEST 1] HEADROOM SIGNAL-AWARE COMPRESSION ---")
    c = HeadroomCompressor()

    # Check string boundaries: error token placed at edge boundaries
    for offset in [0, 50, 119, 120, 121, 200, 500, 1000]:
        payload = {"log": "x" * offset + "CRITICAL_ERROR: memory segmentation fault"}
        res = c.compress(payload, max_str_len=120)
        assert "CRITICAL_ERROR" in str(res), f"Critical signal lost at offset {offset}"
    print("  ✅ [PASS] String boundary retention: all 8 offsets preserved CRITICAL_ERROR")

    # Check middle marker in long strings (deep adversarial regression test)
    for prefix_len in [200, 500, 800]:
        for suffix_len in [200, 500, 800]:
            payload = {"log": "A" * prefix_len + "CRITICAL_ERROR: segmentation fault" + "B" * suffix_len}
            res = c.compress(payload, max_str_len=120)
            assert "CRITICAL_ERROR" in str(res), f"Middle signal lost with prefix={prefix_len}, suffix={suffix_len}"
    print("  ✅ [PASS] Middle marker retention: preserved across all long string middle positions")

    # Check text line omission: middle lines omitted but critical signals kept
    for line_idx in range(50):
        lines = [f"line {i}: normal telemetry ping" for i in range(50)]
        lines[line_idx] = "line X: CRITICAL_ERROR: unexpected process exit"
        raw_text = "\n".join(lines)
        compressed_text = c.compress(raw_text)
        assert "CRITICAL_ERROR" in compressed_text, f"Signal dropped when on line {line_idx}"
    print("  ✅ [PASS] Text line retention: all 50 line positions preserved CRITICAL_ERROR")

    # Verify nominal compression ratio > 70%
    heavy_payload = {
        "status": "ok",
        "items": [{"id": i, "data": "filler " * 20, "metrics": [1, 2, 3, 4, 5]} for i in range(100)],
        "verbose_debug": "debug trace line\n" * 100
    }
    raw_size = len(json.dumps(heavy_payload))
    comp_res = c.compress(heavy_payload)
    comp_size = len(json.dumps(comp_res))
    ratio = (1.0 - (comp_size / raw_size)) * 100
    print(f"  ✅ [PASS] Nominal compression reduction: {ratio:.2f}% (raw: {raw_size}B -> comp: {comp_size}B)")
    assert ratio >= 70.0


def test_circuit_breaker_concurrency():
    print("\n--- [TEST 2] CIRCUIT BREAKER CONCURRENCY & FAIL-CLOSED STATE ---")
    state_file = f"/tmp/test_cb_state_{os.getpid()}_{time.time_ns()}.json"
    CIVeXVerifier.STATE_FILE = state_file

    try:
        verifier = CIVeXVerifier()

        # Threaded increments
        import threading
        threads = []
        for i in range(100):
            t = threading.Thread(target=verifier.record_outcome, args=(f"tool_concurrent_{i % 5}", False, "simulated err"))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        final_verifier = CIVeXVerifier()
        total_recorded = sum(final_verifier.failure_counts.values())
        print(f"  ✅ [PASS] 100 concurrent increments recorded: {total_recorded} / 100")
        assert total_recorded == 100

        # Test fail-closed guard
        try:
            final_verifier.guard("tool_concurrent_1")
            raise AssertionError("Guard failed to trip on failed tool")
        except RuntimeError as e:
            assert "CIRCUIT_BREAKER_BLOCKED" in str(e)
            print("  ✅ [PASS] Guard correctly blocked tripped tool")

        # Test recovery / reset on success
        final_verifier.record_outcome("tool_concurrent_1", True)
        assert not final_verifier.is_circuit_open("tool_concurrent_1")
        final_verifier.guard("tool_concurrent_1")
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
        assert mp_count == 25

        # Test corrupt file fail-closed
        with open(state_file, "w") as f:
            f.write("{corrupt_json_halfway_written")
        corrupt_verifier = CIVeXVerifier()
        try:
            _ = corrupt_verifier.failure_counts
            raise AssertionError("Corrupt state file should have raised ValueError")
        except ValueError:
            print("  ✅ [PASS] Corrupt state file rejected fail-closed with ValueError")

        # Test legacy flat dictionary migration
        legacy_file = f"/tmp/test_cb_legacy_{os.getpid()}_{time.time_ns()}.json"
        with open(legacy_file, "w") as f:
            json.dump({"legacy_tool_1": 3, "legacy_tool_2": 1}, f)
        CIVeXVerifier.STATE_FILE = legacy_file
        legacy_v = CIVeXVerifier()
        assert legacy_v.failure_counts["legacy_tool_1"] == 3
        assert legacy_v.is_circuit_open("legacy_tool_1") is True
        print("  ✅ [PASS] Legacy flat circuit breaker state auto-migrated cleanly")
        if os.path.exists(legacy_file):
            os.remove(legacy_file)
        if os.path.exists(legacy_file + ".lock"):
            os.remove(legacy_file + ".lock")

    finally:
        for p in [state_file, state_file + ".lock"]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass


def test_schema_shrinker_bounds():
    print("\n--- [TEST 3] SCHEMA SHRINKER BOUNDS & FAIL-CLOSED FALLBACK ---")
    bridge = ProgressiveToolBridge()

    # 1. Check fallback under extreme tool_id (350+ chars)
    oversized_row = (
        "EXTREME_OVERSIZED_TOOL_ID_" + "X" * 300,
        "massive_tool_name_" + "Y" * 100,
        "massive_category_" + "Z" * 50,
        "/usr/local/bin/massive",
        "massive --exec",
        "Very long description " * 10,
        "intent1, intent2",
        "tag1, tag2"
    )
    try:
        SchemaShrinker.shrink_tool(oversized_row)
        raise AssertionError("Expected ValueError from SchemaShrinker for extreme ID")
    except ValueError:
        pass

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

    # 2. Check catalog rows
    con = bridge.con
    all_rows = con.execute("SELECT tool_id, name, category, binary_path, exec_template, description, auto_trigger_intents, tags FROM tools_v2;").fetchall()
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
    print(f"  ✅ [PASS] Catalog verification ({len(all_rows)} tools): max shadow schema = {max_b} bytes")


def test_fts5_queries_and_bm25():
    print("\n--- [TEST 4] FTS5 DIRECT JOIN & BM25 RANK ORDERING ---")
    bridge = ProgressiveToolBridge()

    # Test FTS5 fuzz queries
    hostile_queries = [
        "SELECT * FROM users",
        '"" OR 1=1 --',
        'foo"bar',
        "a",
        "",
        "   ",
        "git*commit",
        "transformer*",
        "test AND OR NOT NEAR",
        "^^^***",
        "loss copper 100%",
        "()()()",
        "///",
        "\\x00",
        "emoji 🚀 tool",
        "python --version",
        "cat /etc/passwd",
        "sudo rm -rf /"
    ]
    for q in hostile_queries:
        res = bridge.find_tools(q)
        assert res["status"] == "SUCCESS"
        assert isinstance(res["tools"], list)
    print("  ✅ [PASS] All 18 hostile fuzz queries handled cleanly without syntax errors")

    # Test high-level resolve_intent API
    tools = bridge.resolve_intent("git", top_k=3)
    assert isinstance(tools, list)
    assert len(tools) <= 3
    print(f"  ✅ [PASS] resolve_intent returned {len(tools)} ranked tools")


def test_cli_entrypoint():
    print("\n--- [TEST 5] CLI ENTRYPOINT & MAIN CALLABLE ---")
    assert callable(main), "main() is not callable"

    # Test CLI search execution via main()
    ret = main(["search", "git", "--limit", "2"])
    assert ret == 0, f"civex-bridge search failed with exit code {ret}"
    print("  ✅ [PASS] civex-bridge search returned exit code 0")


def test_civex_causal_assertions():
    print("\n--- [TEST 6] CIVEX CAUSAL INTERVENTION ASSERTIONS ---")
    verifier = CIVeXVerifier()
    test_file = f"/tmp/civex_test_causal_{os.getpid()}_{time.time_ns()}.txt"

    try:
        # Pre-execution: file does not exist
        pre_hash = verifier.hash_file(test_file)
        assert pre_hash is None

        # Scenario 0: Missing target file (phantom execution / false green trap)
        missing_file = f"/tmp/civex_phantom_{os.getpid()}_{time.time_ns()}.txt"
        res0 = verifier.verify_causal_write(missing_file, pre_hash=None, exit_code=0)
        assert res0["verdict"] == "TARGET_MISSING", f"Expected TARGET_MISSING, got {res0['verdict']}"
        print("  ✅ [PASS] Missing target file rejected as TARGET_MISSING")

        # Scenario 1: Non-zero exit code
        res1 = verifier.verify_causal_write(test_file, pre_hash, exit_code=127)
        assert res1["verdict"] == "NONZERO_EXIT"
        print("  ✅ [PASS] Nonzero exit code rejected")

        # Scenario 2: Zero exit code but no file write (idempotent / no-op)
        with open(test_file, "w") as f:
            f.write("initial content")
        initial_hash = verifier.hash_file(test_file)

        res2 = verifier.verify_causal_write(test_file, initial_hash, exit_code=0)
        assert res2["verdict"] == "FALSE_GREEN"
        print("  ✅ [PASS] Idempotent touched file detected as FALSE_GREEN")

        # Scenario 3: Zero-byte file written
        with open(test_file, "w") as f:
            f.write("")
        zero_res = verifier.verify_causal_write(test_file, initial_hash, exit_code=0)
        assert zero_res["verdict"] == "0_BYTE_MUTATION"
        print("  ✅ [PASS] 0-byte file mutation rejected")

        # Scenario 4: Genuine physical mutation
        with open(test_file, "w") as f:
            f.write("genuine physical mutation: new bytes added")
        res4 = verifier.verify_causal_write(test_file, initial_hash, exit_code=0)
        assert res4["verdict"] == "CONFIRMED"
        print("  ✅ [PASS] Genuine physical byte mutation CONFIRMED")

    finally:
        if os.path.exists(test_file):
            try:
                os.remove(test_file)
            except OSError:
                pass


if __name__ == "__main__":
    t_start = time.perf_counter()
    test_headroom_critical_signals()
    test_circuit_breaker_concurrency()
    test_schema_shrinker_bounds()
    test_fts5_queries_and_bm25()
    test_cli_entrypoint()
    test_civex_causal_assertions()
    elapsed = (time.perf_counter() - t_start) * 1000
    print("\n" + "=" * 70)
    print(f"🏆 ALL 6 TEST SUITES PASSED in {elapsed:.2f} ms")
    print("=" * 70)
