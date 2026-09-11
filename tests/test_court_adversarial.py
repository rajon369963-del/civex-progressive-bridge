#!/usr/bin/env python3
"""
AIR10 Master Adversarial Court Regression Suite
===============================================
Enforces the 10-Gate Fail-Closed Invariants directly within pytest
for local execution and remote GitHub Actions CI matrix:
1. Pristine Baseline Contract Verification
2. Quarantined Contract Hard-Zero Score
3. Unverified Contract Fail-Closed Hold
4. Binary Tampering Cryptographic Digest Mismatch
5. Non-Executable Binary Rejection
6. Missing Audit DB Fail-Closed Hold
7. Authoritative Circuit Breaker Open via tool_id
8. Missing Verifier Unknown-State Circuit Hold
9. NDJSON Corrupted Stream Fail-Closed Proof
10. Bridge Zero-Score Hard Exclusion from Routable Output
11. Bridge Ranker Initialization Failure Hard Refusal
12. Layer 2 Router Fail-Closed Hold on Unverified Candidates
13. C11 Execution Boundary Physical Supervision Parity
"""

import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from civex.bridge import CIVeXVerifier, ProgressiveToolBridge
from civex.court_ranking import CourtAwareRanker
from civex.trace_plumbing import (
    air10_layer1_intent,
    air10_layer2_router,
    air10_layer3_shim,
    air10_layer4_executor,
    air10_layer5_verifier,
)


@pytest.fixture
def hermetic_audit_db(tmp_path):
    """Creates a hermetic, temporary SQLite audit DB with strict abort triggers and seed contracts."""
    db_path = str(tmp_path / "hermetic_audit.db")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE tool_contract_verdicts_v2 (
        tool_name TEXT NOT NULL,
        capability TEXT NOT NULL,
        input_format TEXT NOT NULL,
        contract_version TEXT NOT NULL,
        status TEXT NOT NULL,
        binary_path TEXT,
        binary_sha256 TEXT,
        reason TEXT NOT NULL,
        quarantined_at TEXT,
        superseded_by TEXT,
        verified_at TEXT NOT NULL,
        adversarial_evidence TEXT,
        PRIMARY KEY (tool_name, capability, input_format, contract_version)
    );
    """)

    cur.execute("""
    CREATE TABLE tool_traces_v2 (
        trace_id TEXT NOT NULL,
        attempt_no INTEGER NOT NULL DEFAULT 1,
        task_intent TEXT NOT NULL,
        traffic_class TEXT NOT NULL,
        router_candidates TEXT NOT NULL,
        chosen_tool TEXT NOT NULL,
        binary_path TEXT NOT NULL,
        binary_sha256 TEXT,
        input_path TEXT NOT NULL,
        input_sha256 TEXT,
        stdout_sha256 TEXT,
        actual_exit_code INTEGER NOT NULL,
        duration_ms REAL NOT NULL,
        semantic_equivalence TEXT NOT NULL,
        verification_status TEXT NOT NULL,
        failure_reason TEXT,
        created_at TEXT NOT NULL,
        PRIMARY KEY (trace_id, attempt_no)
    );
    """)

    cur.execute("""
    CREATE TABLE trace_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        trace_id TEXT NOT NULL,
        span_id TEXT NOT NULL,
        parent_span_id TEXT,
        stage TEXT NOT NULL,
        producer TEXT NOT NULL,
        timestamp_iso TEXT NOT NULL,
        payload_sha256 TEXT,
        status TEXT NOT NULL,
        details_json TEXT NOT NULL
    );
    """)

    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def mock_binaries(tmp_path):
    """Creates dummy executable and non-executable binaries for attestation testing."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()

    # Valid binary
    valid_bin = bin_dir / "valid_tool"
    valid_bin.write_bytes(b"#!/bin/sh\necho 'valid output'\n")
    valid_bin.chmod(0o755)
    valid_sha = hashlib.sha256(valid_bin.read_bytes()).hexdigest()

    # Tampered binary
    tampered_bin = bin_dir / "tampered_tool"
    tampered_bin.write_bytes(b"#!/bin/sh\necho 'tampered bytes'\n")
    tampered_bin.chmod(0o755)
    tampered_actual_sha = hashlib.sha256(tampered_bin.read_bytes()).hexdigest()

    # Non-executable binary
    non_exec_bin = bin_dir / "non_exec_tool"
    non_exec_bin.write_bytes(b"echo 'cannot execute'")
    non_exec_bin.chmod(0o644)

    return {
        "valid_path": str(valid_bin),
        "valid_sha": valid_sha,
        "tampered_path": str(tampered_bin),
        "tampered_actual_sha": tampered_actual_sha,
        "tampered_registered_sha": "0000000000000000000000000000000000000000000000000000000000000000",
        "non_exec_path": str(non_exec_bin)
    }


class MockVerifier:
    def __init__(self, open_tools=None):
        self.open_tools = set(open_tools or [])

    def is_circuit_open(self, tool_id: str) -> bool:
        return tool_id in self.open_tools


def test_gate1_pristine_baseline(hermetic_audit_db, mock_binaries):
    """Gate 1: Certified contract with matching physical digest must receive high utility score."""
    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO tool_contract_verdicts_v2 VALUES (
            'test-valid-tool', 'EXEC_VALID', 'FORMAT_A', 'v1.0', 'ALLOWED',
            ?, ?, 'Verified in court canary', NULL, NULL, '2026-09-11T00:00:00Z', 'CANARY_PASS'
        )
    """, (mock_binaries["valid_path"], mock_binaries["valid_sha"]))

    conn.execute("""
        INSERT INTO tool_traces_v2 (
            trace_id, task_intent, traffic_class, router_candidates,
            chosen_tool, binary_path, binary_sha256, input_path, input_sha256, stdout_sha256,
            actual_exit_code, duration_ms, semantic_equivalence, verification_status, failure_reason, created_at
        ) VALUES (
            'tr_gate1_pristine', 'CANONICAL_TEST', 'INTERACTIVE', '[]',
            'test-valid-tool', ?, ?, '/tmp/in', 'sha_in', 'sha_out',
            0, 4.5, 'EQUIVALENT', 'VERIFIED_PASS', NULL, '2026-09-11T00:00:00Z'
        )
    """, (mock_binaries["valid_path"], mock_binaries["valid_sha"]))

    conn.execute("""
        INSERT INTO trace_events VALUES (
            NULL, 'tr_gate1_pristine', 'span_01', 'span_root',
            'PROCESS_EXECUTION', 'air10_exec_boundary_c11', '2026-09-11T00:00:00Z',
            'sha_payload', 'COMPLETED', ?
        )
    """, (json.dumps({"tool_name": "test-valid-tool", "binary_path": mock_binaries["valid_path"], "supervisor": "air10_exec_boundary_c11"}),))
    conn.commit()
    conn.close()

    verifier = MockVerifier()
    ranker = CourtAwareRanker(audit_db_path=hermetic_audit_db, verifier=verifier)
    res = ranker.score_tool(
        tool_name="test-valid-tool",
        capability="EXEC_VALID",
        input_format="FORMAT_A",
        contract_version="v1.0",
        binary_path=mock_binaries["valid_path"]
    )
    assert res.status == "ELIGIBLE"
    assert res.final_score >= 0.4
    assert res.correctness_confidence == 1.0


def test_gate2_quarantined_contract_hard_zero(hermetic_audit_db, mock_binaries):
    """Gate 2: Quarantined contract must receive hard zero score and status QUARANTINED."""
    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO tool_contract_verdicts_v2 VALUES (
            'test-bad-tool', 'EXEC_BAD', 'FORMAT_A', 'v1.0', 'QUARANTINED',
            ?, ?, 'Fails on corrupted NDJSON lines', '2026-09-11T00:00:00Z', 'test-valid-tool', '2026-09-11T00:00:00Z', 'CORRUPT_LEAK'
        )
    """, (mock_binaries["valid_path"], mock_binaries["valid_sha"]))
    conn.commit()
    conn.close()

    verifier = MockVerifier()
    ranker = CourtAwareRanker(audit_db_path=hermetic_audit_db, verifier=verifier)
    res = ranker.score_tool(
        tool_name="test-bad-tool",
        capability="EXEC_BAD",
        input_format="FORMAT_A",
        contract_version="v1.0",
        binary_path=mock_binaries["valid_path"]
    )
    assert res.status == "QUARANTINED"
    assert res.final_score == 0.0


def test_gate3_unverified_contract_fail_closed(hermetic_audit_db, mock_binaries):
    """Gate 3: Any unknown or unregistered contract must fail-closed with score 0.0."""
    verifier = MockVerifier()
    ranker = CourtAwareRanker(audit_db_path=hermetic_audit_db, verifier=verifier)
    res = ranker.score_tool(
        tool_name="unknown-tool",
        capability="UNKNOWN_CAP",
        binary_path=mock_binaries["valid_path"]
    )
    assert res.status == "CONTRACT_UNVERIFIED"
    assert res.final_score == 0.0


def test_gate4_binary_tampering_digest_mismatch(hermetic_audit_db, mock_binaries):
    """Gate 4: Physical binary digest mismatch must trigger security alert and score 0.0."""
    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO tool_contract_verdicts_v2 VALUES (
            'test-tampered-tool', 'EXEC_TAMPER', 'FORMAT_A', 'v1.0', 'ALLOWED',
            ?, ?, 'Pre-certified digest', NULL, NULL, '2026-09-11T00:00:00Z', 'HASH_AUDIT'
        )
    """, (mock_binaries["tampered_path"], mock_binaries["tampered_registered_sha"]))
    conn.commit()
    conn.close()

    verifier = MockVerifier()
    ranker = CourtAwareRanker(audit_db_path=hermetic_audit_db, verifier=verifier)
    res = ranker.score_tool(
        tool_name="test-tampered-tool",
        capability="EXEC_TAMPER",
        input_format="FORMAT_A",
        contract_version="v1.0",
        binary_path=mock_binaries["tampered_path"]
    )
    assert res.status == "BINARY_HASH_MISMATCH"
    assert res.final_score == 0.0


def test_gate5_non_executable_binary_rejection(hermetic_audit_db, mock_binaries):
    """Gate 5: Binary missing execution permissions must fail-closed with score 0.0."""
    verifier = MockVerifier()
    ranker = CourtAwareRanker(audit_db_path=hermetic_audit_db, verifier=verifier)
    res = ranker.score_tool(
        tool_name="test-non-exec-tool",
        capability="EXEC_NON_EXEC",
        binary_path=mock_binaries["non_exec_path"]
    )
    assert res.status == "BINARY_NOT_EXECUTABLE"
    assert res.final_score == 0.0


def test_gate6_missing_audit_db_fail_closed():
    """Gate 6: Missing or corrupted audit database must strictly fail-closed."""
    verifier = MockVerifier()
    ranker = CourtAwareRanker(audit_db_path="/non/existent/audit.db", verifier=verifier)
    res = ranker.score_tool(
        tool_name="any-tool",
        capability="ANY_CAP"
    )
    assert res.status == "VERIFICATION_UNAVAILABLE_HOLD"
    assert res.final_score == 0.0


def test_gate7_circuit_breaker_open_via_tool_id(hermetic_audit_db, mock_binaries):
    """Gate 7: Authoritative circuit breaker open on tool_id must isolate candidate with score 0.0."""
    verifier = MockVerifier(open_tools=["tool_critical_failure"])
    ranker = CourtAwareRanker(audit_db_path=hermetic_audit_db, verifier=verifier)
    res = ranker.score_tool(
        tool_id="tool_critical_failure",
        tool_name="critical-failure-display-name",
        capability="ANY_CAP",
        binary_path=mock_binaries["valid_path"]
    )
    assert res.status == "CIRCUIT_OPEN"
    assert res.final_score == 0.0


def test_gate8_missing_verifier_unknown_state_hold(hermetic_audit_db, mock_binaries):
    """Gate 8: If no authoritative circuit verifier is provided, circuit state is UNKNOWN and must HOLD."""
    ranker = CourtAwareRanker(audit_db_path=hermetic_audit_db, verifier=None)
    res = ranker.score_tool(
        tool_name="any-tool",
        capability="ANY_CAP",
        binary_path=mock_binaries["valid_path"]
    )
    assert res.status == "CIRCUIT_STATE_UNKNOWN_HOLD"
    assert res.final_score == 0.0


def test_gate9_ndjson_adversarial_fail_closed(tmp_path):
    """Gate 9: Corrupted NDJSON stream with bad line 3 must fail-close with exit code 1."""
    corrupted_stream = '{"a":1}\n{"b":2}\nCORRUPTED_LINE\n{"c":3}\n'
    stream_file = tmp_path / "corrupted.ndjson"
    stream_file.write_text(corrupted_stream, encoding="utf-8")

    # Cross-platform hermetic verifier code mirroring air10-orjson-tool
    verifier_script = """
import sys, json
try:
    import orjson as json_engine
except ImportError:
    import json as json_engine

valid_count = 0
with open(sys.argv[1], "rb") as f:
    for line_no, raw_line in enumerate(f, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json_engine.loads(line)
            valid_count += 1
        except Exception as e:
            sys.stderr.write(f"NDJSON_DECODE_ERROR at line {line_no}: {e}\\n")
            sys.exit(1)
sys.stdout.write(f"NDJSON_VALID_STREAM: {valid_count} records\\n")
sys.exit(0)
"""
    script_file = tmp_path / "ndjson_verifier.py"
    script_file.write_text(verifier_script, encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(script_file), str(stream_file)],
        capture_output=True,
        text=True
    )
    assert proc.returncode == 1
    assert "NDJSON_DECODE_ERROR at line 3" in proc.stderr


def test_gate10_bridge_zero_score_hard_exclusion(tmp_path, hermetic_audit_db, mock_binaries):
    """Gate 10: In ProgressiveToolBridge, candidates with score 0.0 MUST NOT enter routable tools array."""
    # Build minimal test catalog
    catalog_path = str(tmp_path / "test_catalog.sqlite")
    conn = sqlite3.connect(catalog_path)
    conn.execute("""
    CREATE TABLE tools_v2 (
        tool_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        binary_path TEXT,
        exec_template TEXT,
        description TEXT,
        auto_trigger_intents TEXT,
        tags TEXT
    );
    """)
    conn.execute("""
    CREATE VIRTUAL TABLE tools_v2_fts USING fts5(
        tool_id, name, category, description, auto_trigger_intents, tags,
        tokenize="unicode61 remove_diacritics 2"
    );
    """)

    conn.execute("""
        INSERT INTO tools_v2 VALUES (
            'tool_unverified', 'unverified-tool', 'diagnostics', ?, 'cmd',
            'Unverified test tool', 'test query', 'test'
        )
    """, (mock_binaries["valid_path"],))
    conn.execute("""
        INSERT INTO tools_v2_fts VALUES (
            'tool_unverified', 'unverified-tool', 'diagnostics',
            'Unverified test tool', 'test query', 'test'
        )
    """)
    conn.commit()
    conn.close()

    bridge = ProgressiveToolBridge(db_path=catalog_path)
    # Inject ranker pointing to hermetic DB where 'unverified-tool' has NO contract
    bridge.ranker = CourtAwareRanker(audit_db_path=hermetic_audit_db, verifier=bridge.verifier)

    res = bridge.find_tools("test query", limit=5)
    # FAIL-CLOSED HARD EXCLUSION:
    # 1. Routable tools must be empty because score is 0.0 (CONTRACT_UNVERIFIED)
    assert res["tools"] == []
    assert res["status"] == "NO_VERIFIED_TOOL_AVAILABLE"
    # 2. Diagnostic audit must retain candidate in held_candidates
    assert len(res["held_candidates"]) == 1
    assert res["held_candidates"][0]["court_status"] == "CONTRACT_UNVERIFIED"
    assert res["held_candidates"][0]["court_score"] == 0.0

    # Convenience method resolve_intent MUST return empty list
    resolved = bridge.resolve_intent("test query")
    assert resolved == []


def test_gate11_bridge_ranker_init_failure(tmp_path):
    """Gate 11: If ranker fails initialization, bridge MUST refuse routing with hold."""
    catalog_path = str(tmp_path / "test_catalog2.sqlite")
    conn = sqlite3.connect(catalog_path)
    conn.execute("CREATE TABLE tools_v2 (tool_id TEXT PRIMARY KEY, name TEXT, category TEXT, binary_path TEXT, exec_template TEXT, description TEXT, auto_trigger_intents TEXT, tags TEXT);")
    conn.execute("CREATE VIRTUAL TABLE tools_v2_fts USING fts5(tool_id, name, category, description, auto_trigger_intents, tags);")
    conn.commit()
    conn.close()

    bridge = ProgressiveToolBridge(db_path=catalog_path)
    bridge.ranker = None
    bridge.ranker_init_error = "MockRankerUnavailableException"

    res = bridge.find_tools("test query")
    assert res["status"] == "VERIFICATION_UNAVAILABLE_HOLD"
    assert res["tools"] == []
    assert "FAIL-CLOSED" in res["error"]


def test_gate12_layer2_router_fail_closed(hermetic_audit_db, monkeypatch):
    """Gate 12: Layer 2 router MUST strictly fail-closed when candidates are unverified, returning None."""
    monkeypatch.setattr(air10_layer2_router, "DB_PATH", hermetic_audit_db)
    monkeypatch.setenv("AIR10_AUTO_TRIGGER_BIN", "/non/existent/trigger")

    chosen_tool, chosen_bin, span_id = air10_layer2_router.route_intent(
        trace_id="tr_gate12_router_fail",
        parent_span_id="span_root_gate12",
        intent_query="test parse json strict"
    )
    assert chosen_tool is None
    assert chosen_bin is None
    assert span_id.startswith("span_router_")

    conn = sqlite3.connect(hermetic_audit_db)
    cur = conn.cursor()
    cur.execute("SELECT stage, producer, status, details_json FROM trace_events WHERE trace_id = 'tr_gate12_router_fail'")
    row = cur.fetchone()
    conn.close()
    assert row is not None
    assert row[0] == "ROUTER_EVALUATION"
    assert row[1] == "civex-court-router"
    assert row[2] == "EVALUATED"
    details = json.loads(row[3])
    assert details["chosen_tool"] is None
    assert "NO_VERIFIED_TOOL_AVAILABLE" in details["selection_rationale"]


def test_gate13_c11_execution_boundary_integration(tmp_path):
    """Gate 13: Compile C11 execution boundary and verify physical process execution supervision."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    c_source = os.path.join(repo_root, "civex", "trace_plumbing", "air10_exec_boundary.c")
    assert os.path.isfile(c_source), f"C11 supervisor source missing at {c_source}"

    boundary_bin = str(tmp_path / "test_exec_boundary")
    compile_cmd = ["cc", "-O3", "-std=c11", c_source, "-o", boundary_bin]
    comp = subprocess.run(compile_cmd, capture_output=True, text=True)
    assert comp.returncode == 0, f"C11 compilation failed: {comp.stderr}"
    assert os.path.isfile(boundary_bin)

    input_file = str(tmp_path / "input.txt")
    with open(input_file, "w", encoding="utf-8") as f:
        f.write("test input content\n")

    # 1. Successful execution
    worker_script = str(tmp_path / "worker.sh")
    with open(worker_script, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\nprintf 'TEST_SUPERVISED_OUTPUT'\nexit 0\n")
    os.chmod(worker_script, 0o755)

    proc = subprocess.run(
        [boundary_bin, "tr_gate13_exec", "span_root", worker_script, input_file],
        capture_output=True,
        text=True
    )
    assert proc.returncode == 0
    telemetry = json.loads(proc.stdout)
    assert telemetry["trace_id"] == "tr_gate13_exec"
    assert telemetry["exit_code"] == 0
    assert telemetry["wall_duration_ms"] >= 0.0
    assert telemetry["supervisor"] == "air10_exec_boundary_c11"
    expected_sha = hashlib.sha256(b"TEST_SUPERVISED_OUTPUT").hexdigest()
    assert telemetry["stdout_sha256"] == expected_sha

    # 2. Failing execution with non-zero exit code
    failing_script = str(tmp_path / "failing_worker.sh")
    with open(failing_script, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\nprintf 'FAILURE_OUTPUT'\nexit 42\n")
    os.chmod(failing_script, 0o755)

    proc_fail = subprocess.run(
        [boundary_bin, "tr_gate13_fail", "span_root", failing_script, input_file],
        capture_output=True,
        text=True
    )
    assert proc_fail.returncode == 42
    fail_telemetry = json.loads(proc_fail.stdout)
    assert fail_telemetry["exit_code"] == 42
    assert fail_telemetry["stdout_sha256"] == hashlib.sha256(b"FAILURE_OUTPUT").hexdigest()


def test_gate14_circuit_breaker_feedback_loop(tmp_path):
    """Gate 14: Verify end-to-end circuit breaker trips after 3 failures and forces rerouting."""
    from civex.bridge import CIVeXVerifier
    state_file = str(tmp_path / "cb_state.json")

    orig_state_file = CIVeXVerifier.STATE_FILE
    CIVeXVerifier.STATE_FILE = state_file
    try:
        verifier = CIVeXVerifier()
        tool_id = "test_failing_tool"

        assert not verifier.is_circuit_open(tool_id)

        verifier.record_outcome(tool_id, success=False, error_msg="Error 1")
        verifier.record_outcome(tool_id, success=False, error_msg="Error 2")
        assert not verifier.is_circuit_open(tool_id)

        verifier.record_outcome(tool_id, success=False, error_msg="Error 3")
        assert verifier.is_circuit_open(tool_id)

        verifier.record_outcome(tool_id, success=True)
        assert not verifier.is_circuit_open(tool_id)
    finally:
        CIVeXVerifier.STATE_FILE = orig_state_file


def test_gate15_toctou_input_integrity_mismatch_fail_closed(hermetic_audit_db, tmp_path):
    """Gate 15: TOCTOU mutation between execution and verification triggers fail-closed violation."""
    from civex.trace_plumbing.air10_layer5_verifier import verify_trace

    input_file = str(tmp_path / "input.json")
    with open(input_file, "w", encoding="utf-8") as f:
        f.write('{"test": "original"}')
    orig_sha = hashlib.sha256(open(input_file, "rb").read()).hexdigest()

    bin_path = str(tmp_path / "echo_test.sh")
    with open(bin_path, "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(bin_path, 0o755)
    bin_sha = hashlib.sha256(open(bin_path, "rb").read()).hexdigest()
    out_sha = hashlib.sha256(b"mock_stdout").hexdigest()

    trace_id = "tr_gate15_toctou"
    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO trace_events 
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES (?, 'span_exec_01', 'span_root', 'PROCESS_EXECUTION', 'c11_supervisor', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (trace_id, json.dumps({
        "binary_path": bin_path,
        "binary_sha256": bin_sha,
        "input_file": input_file,
        "input_sha256": orig_sha,
        "actual_returncode": 0,
        "duration_ms": 1.0,
        "stdout_sha256": out_sha
    })))
    conn.commit()
    conn.close()

    # Mutate input file on disk before Layer 5 runs (TOCTOU mutation attack)
    with open(input_file, "w", encoding="utf-8") as f:
        f.write('{"test": "TAMPERED_CONTENT"}')

    os.environ["AIR10_AUDIT_DB"] = hermetic_audit_db
    verdict = verify_trace(trace_id, target_stdout_file=None, audit_db_path=hermetic_audit_db)
    assert verdict == "VERIFIED_FAIL_INVARIANT_VIOLATION"

    conn = sqlite3.connect(hermetic_audit_db)
    cur = conn.cursor()
    cur.execute("SELECT details_json FROM trace_events WHERE trace_id = ? AND stage = 'INDEPENDENT_VERIFICATION'", (trace_id,))
    row = cur.fetchone()
    conn.close()
    assert row is not None
    details = json.loads(row[0])
    assert details["semantic_result"] == "TOCTOU_INTEGRITY_VIOLATION"
    assert "TOCTOU_MUTATION_DETECTED" in details["failure_reason"]


def test_gate16_strict_rfc8259_number_constants_rejection():
    """Gate 16: Strict RFC 8259 Section 6 requires rejection of NaN, Infinity, -Infinity."""
    from civex.trace_plumbing.air10_layer5_verifier import inspect_strict_rfc8259

    # 1. NaN rejection
    valid, obj, trailing, sample = inspect_strict_rfc8259(b'{"key": NaN}')
    assert not valid
    assert "RFC 8259 Section 6 violation" in sample or "JSON_SYNTAX_ERROR" in sample

    # 2. Infinity rejection
    valid, obj, trailing, sample = inspect_strict_rfc8259(b'{"key": Infinity}')
    assert not valid
    assert "RFC 8259 Section 6 violation" in sample or "JSON_SYNTAX_ERROR" in sample

    # 3. -Infinity rejection
    valid, obj, trailing, sample = inspect_strict_rfc8259(b'{"key": -Infinity}')
    assert not valid
    assert "RFC 8259 Section 6 violation" in sample or "JSON_SYNTAX_ERROR" in sample

    # 4. Standard numbers must be accepted
    valid, obj, trailing, sample = inspect_strict_rfc8259(b'{"key": 42.125e-3}')
    assert valid
    assert obj == {"key": 0.042125}
    assert not trailing


def test_gate17_c11_stdout_preservation_and_arbitrary_argv(tmp_path):
    """Gate 17: C11 execution boundary persists stdout to file and supports arbitrary argv."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    c_source = os.path.join(repo_root, "civex", "trace_plumbing", "air10_exec_boundary.c")
    boundary_bin = str(tmp_path / "test_exec_boundary_v2")

    comp = subprocess.run(["cc", "-O3", "-std=c11", c_source, "-o", boundary_bin], capture_output=True, text=True)
    assert comp.returncode == 0

    # Create worker script that accepts 3 arbitrary arguments and prints them
    worker_script = str(tmp_path / "multi_arg_worker.sh")
    with open(worker_script, "w", encoding="utf-8") as f:
        f.write('#!/bin/sh\nprintf "ARG1=%s|ARG2=%s|ARG3=%s" "$1" "$2" "$3"\nexit 0\n')
    os.chmod(worker_script, 0o755)

    captured_stdout_file = str(tmp_path / "captured_child_stdout.txt")
    env = os.environ.copy()
    env["AIR10_STDOUT_CAPTURE_PATH"] = captured_stdout_file

    proc = subprocess.run(
        [boundary_bin, "tr_gate17", "span_root", worker_script, "alpha", "bravo", "charlie"],
        capture_output=True, text=True, env=env
    )
    assert proc.returncode == 0
    telemetry = json.loads(proc.stdout)
    assert telemetry["exit_code"] == 0

    expected_output = b"ARG1=alpha|ARG2=bravo|ARG3=charlie"
    expected_sha = hashlib.sha256(expected_output).hexdigest()
    assert telemetry["stdout_sha256"] == expected_sha

    # Assert physical stdout file was preserved and matches exact bytes
    assert os.path.isfile(captured_stdout_file)
    with open(captured_stdout_file, "rb") as cf:
        captured_bytes = cf.read()
    assert captured_bytes == expected_output
    assert hashlib.sha256(captured_bytes).hexdigest() == expected_sha


def test_gate18_ledger_cryptographic_digest_assertion(hermetic_audit_db, tmp_path):
    """Gate 18: tool_traces_v2 must store physical 64-char SHA-256 digests, zero placeholder strings."""

    from civex.trace_plumbing.air10_layer5_verifier import verify_trace

    input_file = str(tmp_path / "valid_doc.json")
    with open(input_file, "w", encoding="utf-8") as f:
        f.write('{"status": "ok"}')
    in_sha = hashlib.sha256(open(input_file, "rb").read()).hexdigest()

    stdout_file = str(tmp_path / "valid_stdout.json")
    with open(stdout_file, "w", encoding="utf-8") as f:
        f.write('{"status": "ok"}')
    out_sha = hashlib.sha256(open(stdout_file, "rb").read()).hexdigest()

    echo_bin = "/bin/echo"
    bin_sha = hashlib.sha256(open(echo_bin, "rb").read()).hexdigest()

    trace_id = "tr_gate18_digest"
    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO trace_events 
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES (?, 'span_exec_g18', 'span_root', 'PROCESS_EXECUTION', 'c11_supervisor', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (trace_id, json.dumps({
        "binary_path": echo_bin,
        "binary_sha256": bin_sha,
        "input_file": input_file,
        "input_sha256": in_sha,
        "actual_returncode": 0,
        "duration_ms": 1.5,
        "stdout_sha256": out_sha,
        "output_file": stdout_file
    })))
    conn.commit()
    conn.close()

    os.environ["AIR10_AUDIT_DB"] = hermetic_audit_db
    verdict = verify_trace(trace_id, target_stdout_file=stdout_file, audit_db_path=hermetic_audit_db)
    assert verdict == "VERIFIED_PASS"

    conn = sqlite3.connect(hermetic_audit_db)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM tool_traces_v2 WHERE trace_id = ?", (trace_id,))
    row = cur.fetchone()
    conn.close()

    assert row is not None
    sha_regex = re.compile(r"^[0-9a-fA-F]{64}$")

    # Assert binary_sha256 is genuine physical 64-char hex, NOT placeholder or zero sentinel
    assert row["binary_sha256"] != "BOUNDARY_INTERCEPTED"
    assert row["binary_sha256"] != "0" * 64
    assert len(row["binary_sha256"]) == 64
    assert sha_regex.match(row["binary_sha256"]) is not None
    assert row["binary_sha256"] == bin_sha

    # Assert stdout_sha256 is genuine 64-char hex, NOT placeholder or zero sentinel
    assert row["stdout_sha256"] != "STDOUT_RECORDED"
    assert row["stdout_sha256"] != "0" * 64
    assert len(row["stdout_sha256"]) == 64
    assert sha_regex.match(row["stdout_sha256"]) is not None
    assert row["stdout_sha256"] == out_sha

    # Test synthetic sentinel rejection: "0" * 64 must fail closed
    trace_id_fake = "tr_gate18_fake_sentinel"
    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO trace_events 
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES (?, 'span_exec_g18_fake', 'span_root', 'PROCESS_EXECUTION', 'c11_supervisor', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (trace_id_fake, json.dumps({
        "binary_path": "/nonexistent/fake/bin",
        "binary_sha256": "0" * 64,
        "input_file": input_file,
        "input_sha256": in_sha,
        "actual_returncode": 0,
        "duration_ms": 1.5,
        "stdout_sha256": out_sha,
        "output_file": stdout_file
    })))
    conn.commit()
    conn.close()

    verdict_fake = verify_trace(trace_id_fake, target_stdout_file=stdout_file, audit_db_path=hermetic_audit_db)
    assert verdict_fake == "VERIFIED_FAIL_INVARIANT_VIOLATION"

    # Assert NULL digest and MISSING_EXECUTION_ATTESTATION stored in tool_traces_v2 (zero "f"*64)
    conn = sqlite3.connect(hermetic_audit_db)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM tool_traces_v2 WHERE trace_id = ?", (trace_id_fake,))
    fake_row = cur.fetchone()
    conn.close()
    assert fake_row is not None
    assert fake_row["binary_sha256"] is None, "Synthetic sentinel must be stored as SQL NULL, not 'f'*64"
    assert fake_row["semantic_equivalence"] == "MISSING_EXECUTION_ATTESTATION"


def test_gate19_full_closed_loop_reality_test(hermetic_audit_db, tmp_path, monkeypatch):
    """Gate 19: Full End-to-End Closed-Loop Reality Test.
    Proves the complete reality chain:
    1. Quarantined champion with superseded_by pointing to replacement tool.
    2. route_intent() resolves replacement dynamically without NameError or crashes.
    3. execute_process() executes with multi-arg argv, tees stdout, verifies Layer 4 capture parity.
    4. verify_trace() verifies input TOCTOU, stdout TOCTOU, genuine 64-char non-zero hex digests.
    5. Induces 3 failures -> trips breaker -> 4th routing skips failed tool.
    6. Verifies that mutating captured stdout fails closed with STDOUT_TOCTOU_INTEGRITY_VIOLATION.
    """
    from civex.bridge import CIVeXVerifier
    from civex.trace_plumbing import (
        air10_layer4_executor,
        air10_layer5_verifier,
    )

    # Configure hermetic DB and state file
    monkeypatch.setattr(air10_layer2_router, "DB_PATH", hermetic_audit_db)
    monkeypatch.setattr(air10_layer4_executor, "DB_PATH", hermetic_audit_db)
    monkeypatch.setattr(air10_layer5_verifier, "DB_PATH", hermetic_audit_db)
    monkeypatch.setenv("AIR10_AUDIT_DB", hermetic_audit_db)

    cb_state_file = str(tmp_path / "gate19_cb_state.json")
    monkeypatch.setattr(CIVeXVerifier, "STATE_FILE", cb_state_file)

    # 1. Setup physical binaries
    # champ_tool: quarantined champion script
    champ_bin = str(tmp_path / "champ_tool.sh")
    with open(champ_bin, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\nexit 1\n")
    os.chmod(champ_bin, 0o755)
    champ_sha = hashlib.sha256(open(champ_bin, "rb").read()).hexdigest()

    # replacement_tool: valid worker script that reads input file from argv and prints valid JSON matching oracle
    rep_bin = str(tmp_path / "replacement_tool.sh")
    with open(rep_bin, "w", encoding="utf-8") as f:
        f.write('#!/bin/sh\nfor arg do last="$arg"; done\ncat "$last"\nexit 0\n')
    os.chmod(rep_bin, 0o755)
    rep_sha = hashlib.sha256(open(rep_bin, "rb").read()).hexdigest()

    # Seed hermetic audit database with contracts, baseline telemetry, and execution traces
    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO tool_contract_verdicts_v2
        (tool_name, capability, input_format, contract_version, status, binary_path, binary_sha256, reason, quarantined_at, superseded_by, verified_at)
        VALUES ('champ_tool', 'JSON_SINGLE_DOC_STRICT', 'SINGLE_DOC_STRICT_RFC8259', 'v1.0',
                'QUARANTINED', ?, ?, 'CRITICAL_BUG: Memory leak on large streams', '2026-09-10T00:00:00Z', 'replacement_tool', '2026-09-10T00:00:00Z')
    """, (champ_bin, champ_sha))
    conn.execute("""
        INSERT INTO tool_contract_verdicts_v2
        (tool_name, capability, input_format, contract_version, status, binary_path, binary_sha256, reason, quarantined_at, superseded_by, verified_at)
        VALUES ('replacement_tool', 'JSON_SINGLE_DOC_STRICT', 'SINGLE_DOC_STRICT_RFC8259', 'v1.0',
                'ALLOWED', ?, ?, 'VERIFIED_PASS: Pristine AST parity across 559 RFC 8259 documents', NULL, NULL, '2026-09-11T00:00:00Z')
    """, (rep_bin, rep_sha))
    conn.execute("""
        INSERT INTO tool_traces_v2
        (trace_id, task_intent, traffic_class, router_candidates, chosen_tool, binary_path, binary_sha256, input_path, input_sha256, stdout_sha256, actual_exit_code, duration_ms, semantic_equivalence, verification_status, failure_reason, created_at)
        VALUES ('tr_seed_replacement', 'JSON_PARSE', 'BATCH', '[]', 'replacement_tool', ?, ?, '/tmp/in.json', ?, ?, 0, 1.25, 'EXACT_AST_MATCH', 'VERIFIED_PASS', NULL, '2026-09-11T00:00:00Z')
    """, (rep_bin, rep_sha, rep_sha, rep_sha))
    conn.execute("""
        INSERT INTO trace_events
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES ('tr_seed_replacement', 'span_seed', 'span_root', 'PROCESS_EXECUTION', 'air10_exec_boundary_c11', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (json.dumps({"tool_name": "replacement_tool", "binary_path": rep_bin}),))
    conn.commit()
    conn.close()

    # 2. Dynamic superseded_by Routing: candidate is champ_tool, router MUST resolve replacement_tool
    trace_id_1 = "tr_gate19_e2e_01"
    parent_span_root = "span_root_g19"
    candidate_pool = [
        {"name": "champ_tool", "binary": champ_bin}
    ]

    chosen_tool, chosen_bin, router_span_id = air10_layer2_router.route_intent(
        trace_id=trace_id_1,
        parent_span_id=parent_span_root,
        intent_query="parse strict single doc json",
        required_capability="JSON_SINGLE_DOC_STRICT",
        candidates_override=candidate_pool
    )
    assert chosen_tool == "replacement_tool", f"Expected replacement_tool, got {chosen_tool}"
    assert chosen_bin == rep_bin

    # 3. Supervised Execution with multi-arg argv and stdout tee capture
    input_file = str(tmp_path / "valid_input.json")
    with open(input_file, "w", encoding="utf-8") as f:
        f.write('{"civex_closed_loop": true, "score": 100}')
    in_sha = hashlib.sha256(open(input_file, "rb").read()).hexdigest()

    output_file = str(tmp_path / "captured_stdout_g19.json")
    multi_argv = ["--mode", "strict", "--trace-id", trace_id_1, input_file]

    rc, dur_ms, stdout_sha = air10_layer4_executor.execute_process(
        trace_id=trace_id_1,
        binary_path=chosen_bin,
        input_file=input_file,
        parent_span_id=router_span_id,
        output_file=output_file,
        argv=multi_argv
    )
    assert rc == 0
    assert dur_ms > 0.0
    assert os.path.isfile(output_file)
    with open(output_file, "rb") as sf:
        captured_bytes = sf.read()
    assert hashlib.sha256(captured_bytes).hexdigest() == stdout_sha

    # 4. Layer 5 Verification with AST equality and cryptographic digests
    verdict = air10_layer5_verifier.verify_trace(
        trace_id=trace_id_1,
        target_stdout_file=output_file,
        audit_db_path=hermetic_audit_db
    )
    assert verdict == "VERIFIED_PASS"

    # Verify tool_traces_v2 cryptographic digests in DB
    conn = sqlite3.connect(hermetic_audit_db)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM tool_traces_v2 WHERE trace_id = ?", (trace_id_1,)).fetchone()
    conn.close()
    assert row is not None
    assert row["chosen_tool"] == "replacement_tool"
    assert row["verification_status"] == "VERIFIED_PASS"
    assert row["binary_sha256"] == rep_sha
    assert row["stdout_sha256"] == stdout_sha
    assert row["binary_sha256"] != "0" * 64
    assert row["stdout_sha256"] != "0" * 64

    # 5. Circuit Breaker Feedback: Trip breaker with 3 failures, assert 4th routing skips tool
    verifier = CIVeXVerifier()
    verifier.record_outcome("replacement_tool", success=False, error_msg="Fault injection 1")
    verifier.record_outcome("replacement_tool", success=False, error_msg="Fault injection 2")
    verifier.record_outcome("replacement_tool", success=False, error_msg="Fault injection 3")
    assert verifier.is_circuit_open("replacement_tool")

    # 4th routing attempt MUST skip replacement_tool because circuit is open
    trace_id_2 = "tr_gate19_circuit_open"
    tool_after_trip, bin_after_trip, _ = air10_layer2_router.route_intent(
        trace_id=trace_id_2,
        parent_span_id=parent_span_root,
        intent_query="parse strict single doc json",
        required_capability="JSON_SINGLE_DOC_STRICT",
        candidates_override=candidate_pool
    )
    assert tool_after_trip is None, "Circuit-tripped tool should have been refused fail-closed"
    assert bin_after_trip is None

    # Reset circuit breaker for replacement_tool
    verifier.record_outcome("replacement_tool", success=True)
    assert not verifier.is_circuit_open("replacement_tool")

    # 6. Stdout TOCTOU Integrity Violation: Mutating captured stdout file fails closed
    trace_id_3 = "tr_gate19_toctou_stdout"
    output_file_toctou = str(tmp_path / "stdout_toctou.json")
    rc_t, _, out_sha_t = air10_layer4_executor.execute_process(
        trace_id=trace_id_3,
        binary_path=rep_bin,
        input_file=input_file,
        parent_span_id=parent_span_root,
        output_file=output_file_toctou,
        argv=[input_file]
    )
    assert rc_t == 0

    # Tamper with captured stdout file on physical disk before Layer 5 verification
    with open(output_file_toctou, "w", encoding="utf-8") as f:
        f.write('{"tampered": "ADVERSARIAL_MUTATION"}')

    verdict_toctou = air10_layer5_verifier.verify_trace(
        trace_id=trace_id_3,
        target_stdout_file=output_file_toctou,
        audit_db_path=hermetic_audit_db
    )
    assert verdict_toctou == "VERIFIED_FAIL_INVARIANT_VIOLATION"

    conn = sqlite3.connect(hermetic_audit_db)
    cur = conn.cursor()
    cur.execute("SELECT details_json FROM trace_events WHERE trace_id = ? AND stage = 'INDEPENDENT_VERIFICATION'", (trace_id_3,))
    verif_row = cur.fetchone()
    conn.close()
    assert verif_row is not None
    verif_details = json.loads(verif_row[0])
    assert verif_details["semantic_result"] == "STDOUT_TOCTOU_INTEGRITY_VIOLATION"
    assert "STDOUT_TOCTOU_MUTATION_DETECTED" in verif_details["failure_reason"]


def test_gate20_autonomous_self_healing_closed_loop(hermetic_audit_db, tmp_path, monkeypatch):
    """Gate 20: True Autonomous Self-Healing Closed Loop Reality Test.
    Proves that:
    1. Two candidate tools exist: flaky_primary and resilient_fallback.
    2. Initial state: both are ALLOWED in tool_contract_verdicts_v2. flaky_primary has lower latency (0.2ms vs 2.0ms), so router prefers it.
    3. Layer 4 executes flaky_primary -> Layer 5 verifier evaluates trace -> verification fails.
    4. Layer 5 internally calls CIVeXVerifier().record_outcome() to increment failure count.
    5. After 3 consecutive real Layer 4->5 failures of flaky_primary, circuit breaker trips to OPEN.
    6. On 4th intent route with the SAME candidate pool, router automatically skips flaky_primary (circuit OPEN) and selects resilient_fallback.
    7. Layer 4 executes resilient_fallback via C11 supervisor -> Layer 5 verifies -> VERIFIED_PASS.
    8. ZERO manual record_outcome() calls throughout the entire loop.
    """
    from civex.bridge import CIVeXVerifier
    from civex.trace_plumbing import (
        air10_layer4_executor,
        air10_layer5_verifier,
    )

    # Configure hermetic DB and state file
    monkeypatch.setattr(air10_layer2_router, "DB_PATH", hermetic_audit_db)
    monkeypatch.setattr(air10_layer4_executor, "DB_PATH", hermetic_audit_db)
    monkeypatch.setattr(air10_layer5_verifier, "DB_PATH", hermetic_audit_db)
    monkeypatch.setenv("AIR10_AUDIT_DB", hermetic_audit_db)

    cb_state_file = str(tmp_path / "gate20_cb_state.json")
    monkeypatch.setattr(CIVeXVerifier, "STATE_FILE", cb_state_file)

    # Physical binaries
    # 1. flaky_primary: Exits with code 1, causing Layer 5 verification to fail
    flaky_bin = str(tmp_path / "flaky_primary.sh")
    with open(flaky_bin, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\nexit 1\n")
    os.chmod(flaky_bin, 0o755)
    flaky_sha = hashlib.sha256(open(flaky_bin, "rb").read()).hexdigest()

    # 2. resilient_fallback: Valid script that echoes valid JSON input
    resilient_bin = str(tmp_path / "resilient_fallback.sh")
    with open(resilient_bin, "w", encoding="utf-8") as f:
        f.write('#!/bin/sh\nfor arg do last="$arg"; done\ncat "$last"\nexit 0\n')
    os.chmod(resilient_bin, 0o755)
    resilient_sha = hashlib.sha256(open(resilient_bin, "rb").read()).hexdigest()

    # Valid input file
    valid_input = str(tmp_path / "gate20_input.json")
    with open(valid_input, "w", encoding="utf-8") as f:
        f.write('{"service": "civex_autonomous_healing", "active": true}')
    valid_input_sha = hashlib.sha256(open(valid_input, "rb").read()).hexdigest()

    # Seed hermetic DB with contracts and baseline telemetry
    conn = sqlite3.connect(hermetic_audit_db)
    # flaky_primary: lower latency (0.2ms) to make it primary choice
    conn.execute("""
        INSERT INTO tool_contract_verdicts_v2
        (tool_name, capability, input_format, contract_version, status, binary_path, binary_sha256, reason, quarantined_at, superseded_by, verified_at)
        VALUES ('flaky_primary', 'JSON_SINGLE_DOC_STRICT', 'SINGLE_DOC_STRICT_RFC8259', 'v1.0',
                'ALLOWED', ?, ?, 'BASELINE_APPROVED', NULL, NULL, '2026-09-11T00:00:00Z')
    """, (flaky_bin, flaky_sha))
    conn.execute("""
        INSERT INTO tool_traces_v2
        (trace_id, task_intent, traffic_class, router_candidates, chosen_tool, binary_path, binary_sha256, input_path, input_sha256, stdout_sha256, actual_exit_code, duration_ms, semantic_equivalence, verification_status, failure_reason, created_at)
        VALUES ('tr_seed_flaky', 'JSON_PARSE', 'BATCH', '[]', 'flaky_primary', ?, ?, ?, ?, ?, 0, 0.20, 'EXACT_AST_MATCH', 'VERIFIED_PASS', NULL, '2026-09-11T00:00:00Z')
    """, (flaky_bin, flaky_sha, valid_input, valid_input_sha, flaky_sha))
    conn.execute("""
        INSERT INTO trace_events
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES ('tr_seed_flaky', 'span_seed_flaky', 'span_root', 'PROCESS_EXECUTION', 'air10_exec_boundary_c11', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (json.dumps({"tool_name": "flaky_primary", "binary_path": flaky_bin}),))

    # resilient_fallback: higher latency (2.0ms), so ranked second
    conn.execute("""
        INSERT INTO tool_contract_verdicts_v2
        (tool_name, capability, input_format, contract_version, status, binary_path, binary_sha256, reason, quarantined_at, superseded_by, verified_at)
        VALUES ('resilient_fallback', 'JSON_SINGLE_DOC_STRICT', 'SINGLE_DOC_STRICT_RFC8259', 'v1.0',
                'ALLOWED', ?, ?, 'BASELINE_APPROVED', NULL, NULL, '2026-09-11T00:00:00Z')
    """, (resilient_bin, resilient_sha))
    conn.execute("""
        INSERT INTO tool_traces_v2
        (trace_id, task_intent, traffic_class, router_candidates, chosen_tool, binary_path, binary_sha256, input_path, input_sha256, stdout_sha256, actual_exit_code, duration_ms, semantic_equivalence, verification_status, failure_reason, created_at)
        VALUES ('tr_seed_resilient', 'JSON_PARSE', 'BATCH', '[]', 'resilient_fallback', ?, ?, ?, ?, ?, 0, 2.00, 'EXACT_AST_MATCH', 'VERIFIED_PASS', NULL, '2026-09-11T00:00:00Z')
    """, (resilient_bin, resilient_sha, valid_input, valid_input_sha, resilient_sha))
    conn.execute("""
        INSERT INTO trace_events
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES ('tr_seed_resilient', 'span_seed_resilient', 'span_root', 'PROCESS_EXECUTION', 'air10_exec_boundary_c11', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (json.dumps({"tool_name": "resilient_fallback", "binary_path": resilient_bin}),))
    conn.commit()
    conn.close()

    candidate_pool = [
        {"name": "flaky_primary", "binary": flaky_bin},
        {"name": "resilient_fallback", "binary": resilient_bin}
    ]

    # Verify circuit is initially closed for flaky_primary
    verifier = CIVeXVerifier()
    assert not verifier.is_circuit_open("flaky_primary")
    assert not verifier.is_circuit_open("resilient_fallback")

    # Run 3 consecutive execution-to-verification cycles on flaky_primary
    # Layer 5 must naturally trip the breaker via its internal feedback
    for attempt in range(1, 4):
        t_id = f"tr_gate20_fail_{attempt}"
        c_tool, c_bin, r_span = air10_layer2_router.route_intent(
            trace_id=t_id,
            parent_span_id="span_root_g20",
            intent_query="strict single doc json parse",
            required_capability="JSON_SINGLE_DOC_STRICT",
            candidates_override=candidate_pool
        )
        assert c_tool == "flaky_primary", f"Attempt {attempt}: expected flaky_primary, got {c_tool}"
        assert c_bin == flaky_bin

        out_f = str(tmp_path / f"out_flaky_{attempt}.json")
        rc, dur_ms, out_sha = air10_layer4_executor.execute_process(
            trace_id=t_id,
            binary_path=c_bin,
            input_file=valid_input,
            parent_span_id=r_span,
            output_file=out_f,
            argv=[valid_input]
        )
        assert rc == 1  # flaky_primary exited 1

        # Layer 5 verification evaluates trace and internally updates circuit breaker
        verdict = air10_layer5_verifier.verify_trace(
            trace_id=t_id,
            target_stdout_file=out_f,
            audit_db_path=hermetic_audit_db
        )
        assert verdict == "VERIFIED_FAIL_INVARIANT_VIOLATION"

    # Circuit breaker for flaky_primary is now TRIPPED (3 consecutive failures)
    assert verifier.is_circuit_open("flaky_primary"), "Circuit breaker must be OPEN after 3 verifier failures"

    # 4th intent route: with the EXACT SAME candidate pool, router must autonomously skip flaky_primary and pick resilient_fallback
    t_id_4 = "tr_gate20_healed_04"
    c_tool_4, c_bin_4, r_span_4 = air10_layer2_router.route_intent(
        trace_id=t_id_4,
        parent_span_id="span_root_g20",
        intent_query="strict single doc json parse",
        required_capability="JSON_SINGLE_DOC_STRICT",
        candidates_override=candidate_pool
    )
    assert c_tool_4 == "resilient_fallback", f"Expected autonomous failover to resilient_fallback, got {c_tool_4}"
    assert c_bin_4 == resilient_bin

    # Execute resilient_fallback via C11 supervisor
    out_healed = str(tmp_path / "out_healed_04.json")
    rc_4, dur_ms_4, out_sha_4 = air10_layer4_executor.execute_process(
        trace_id=t_id_4,
        binary_path=c_bin_4,
        input_file=valid_input,
        parent_span_id=r_span_4,
        output_file=out_healed,
        argv=[valid_input]
    )
    assert rc_4 == 0

    # Layer 5 verifies healed trace to VERIFIED_PASS
    verdict_4 = air10_layer5_verifier.verify_trace(
        trace_id=t_id_4,
        target_stdout_file=out_healed,
        audit_db_path=hermetic_audit_db
    )
    assert verdict_4 == "VERIFIED_PASS"
    assert not verifier.is_circuit_open("resilient_fallback")


def test_gate21_full_5_layer_dag_reality_test(hermetic_audit_db, tmp_path, monkeypatch):
    """Gate 21: Full 5-Layer DAG Reality Test with SHA-256 Chain Validation.
    Validates complete 5-layer pipeline:
    Layer 1 (INTENT) -> Layer 2 (ROUTER) -> Layer 3 (SHIM) -> Layer 4 (C11 EXEC) -> Layer 5 (VERIFIER).
    Asserts strict causal parent-child span DAG linkages, payload hashes, and cross-trace readback verification.
    """
    from civex.trace_plumbing import (
        air10_cross_trace_readback,
        air10_layer4_executor,
        air10_layer5_verifier,
    )

    monkeypatch.setattr(air10_layer1_intent, "DB_PATH", hermetic_audit_db)
    monkeypatch.setattr(air10_layer2_router, "DB_PATH", hermetic_audit_db)
    monkeypatch.setattr(air10_layer4_executor, "DB_PATH", hermetic_audit_db)
    monkeypatch.setattr(air10_layer5_verifier, "DB_PATH", hermetic_audit_db)
    monkeypatch.setenv("AIR10_AUDIT_DB", hermetic_audit_db)

    # Physical binary
    dag_bin = str(tmp_path / "dag_worker.sh")
    with open(dag_bin, "w", encoding="utf-8") as f:
        f.write('#!/bin/sh\nfor arg do last="$arg"; done\ncat "$last"\nexit 0\n')
    os.chmod(dag_bin, 0o755)
    dag_bin_sha = hashlib.sha256(open(dag_bin, "rb").read()).hexdigest()

    input_file = str(tmp_path / "dag_input.json")
    with open(input_file, "w", encoding="utf-8") as f:
        f.write('{"dag_layer": 5, "verified": true}')
    input_sha = hashlib.sha256(open(input_file, "rb").read()).hexdigest()

    output_file = str(tmp_path / "dag_output.json")
    shim_log_path = str(tmp_path / "shim_intercept.log")

    # Seed contract and baseline trace
    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO tool_contract_verdicts_v2
        (tool_name, capability, input_format, contract_version, status, binary_path, binary_sha256, reason, quarantined_at, superseded_by, verified_at)
        VALUES ('dag_worker', 'JSON_SINGLE_DOC_STRICT', 'SINGLE_DOC_STRICT_RFC8259', 'v1.0',
                'ALLOWED', ?, ?, 'APPROVED', NULL, NULL, '2026-09-11T00:00:00Z')
    """, (dag_bin, dag_bin_sha))
    conn.execute("""
        INSERT INTO tool_traces_v2
        (trace_id, task_intent, traffic_class, router_candidates, chosen_tool, binary_path, binary_sha256, input_path, input_sha256, stdout_sha256, actual_exit_code, duration_ms, semantic_equivalence, verification_status, failure_reason, created_at)
        VALUES ('tr_seed_dag', 'JSON_PARSE', 'BATCH', '[]', 'dag_worker', ?, ?, ?, ?, ?, 0, 1.0, 'EXACT_AST_MATCH', 'VERIFIED_PASS', NULL, '2026-09-11T00:00:00Z')
    """, (dag_bin, dag_bin_sha, input_file, input_sha, dag_bin_sha))
    conn.execute("""
        INSERT INTO trace_events
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES ('tr_seed_dag', 'span_seed_dag', 'span_root', 'PROCESS_EXECUTION', 'air10_exec_boundary_c11', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (json.dumps({"tool_name": "dag_worker", "binary_path": dag_bin}),))
    conn.commit()
    conn.close()

    # Layer 1: INTENT
    trace_id, span_intent_id = air10_layer1_intent.emit_intent(
        intent_name="CANONICAL_JSON_PARSE_RFC8259",
        description="parse strict single doc json with full DAG reality",
        caller="civex_intent_orchestrator",
        db_path=hermetic_audit_db
    )

    # Layer 2: ROUTER
    candidate_pool = [{"name": "dag_worker", "binary": dag_bin}]
    chosen_tool, chosen_bin, span_router_id = air10_layer2_router.route_intent(
        trace_id=trace_id,
        parent_span_id=span_intent_id,
        intent_query="parse strict single doc json",
        required_capability="JSON_SINGLE_DOC_STRICT",
        candidates_override=candidate_pool,
        db_path=hermetic_audit_db
    )
    assert chosen_tool == "dag_worker"
    assert chosen_bin == dag_bin

    # Layer 3: SHIM INTERCEPT
    span_shim_id = air10_layer3_shim.shim_intercept(
        trace_id=trace_id,
        tool_name=chosen_tool,
        binary_path=chosen_bin,
        command_args=[input_file],
        parent_span_id=span_router_id,
        db_path=hermetic_audit_db,
        shim_log=shim_log_path
    )

    # Layer 4: PROCESS_EXECUTION (C11 supervised execution)
    rc, dur_ms, out_sha = air10_layer4_executor.execute_process(
        trace_id=trace_id,
        binary_path=chosen_bin,
        input_file=input_file,
        parent_span_id=span_shim_id,
        output_file=output_file,
        argv=[input_file],
        db_path=hermetic_audit_db
    )
    assert rc == 0

    # Layer 5: INDEPENDENT_VERIFICATION
    verdict = air10_layer5_verifier.verify_trace(
        trace_id=trace_id,
        target_stdout_file=output_file,
        audit_db_path=hermetic_audit_db
    )
    assert verdict == "VERIFIED_PASS"

    # Strict Validation via air10_cross_trace_readback:
    # Mathematical causal DAG validation, DFS acyclicity, 1 root, 0 orphans,
    # exact stage order, shim log correlation, and all payload SHA-256 recomputed.
    assert air10_cross_trace_readback.validate_and_readback(
        trace_id=trace_id,
        db_path=hermetic_audit_db,
        shim_log=shim_log_path
    ) is True


def test_gate22_post_exec_tampering_and_attestation_binding(hermetic_audit_db, tmp_path, monkeypatch):
    """Gate 22: Post-Execution Tampering & Attestation Binding Reality Test.
    1. Missing execution digest (stdout_sha256 or input_sha256) fails closed without disk backfill;
       recorded as SQL NULL in tool_traces_v2 ledger with MISSING_EXECUTION_ATTESTATION.
    2. Post-execution binary mutation (Anti-ABA attack) fails closed with BINARY_INTEGRITY_VIOLATION.
    3. CourtAwareRanker supervision check: rejects candidates without C11 supervisor.
    """
    from civex.bridge import CIVeXVerifier
    from civex.court_ranking import CourtAwareRanker
    from civex.trace_plumbing import air10_layer5_verifier

    monkeypatch.setattr(air10_layer5_verifier, "DB_PATH", hermetic_audit_db)
    monkeypatch.setenv("AIR10_AUDIT_DB", hermetic_audit_db)

    # 1A. Missing stdout execution digest fails closed, stores NULL in tool_traces_v2
    input_file = str(tmp_path / "g22_input.json")
    with open(input_file, "w", encoding="utf-8") as f:
        f.write('{"key": "value"}')
    in_sha = hashlib.sha256(open(input_file, "rb").read()).hexdigest()

    test_bin = str(tmp_path / "g22_tool.sh")
    with open(test_bin, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\ncat $1\nexit 0\n")
    os.chmod(test_bin, 0o755)
    test_bin_sha = hashlib.sha256(open(test_bin, "rb").read()).hexdigest()

    # Trace with missing stdout_sha256
    t_id_missing_out = "tr_gate22_missing_stdout_attest"
    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO trace_events 
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES (?, 'span_exec_g22_m', 'span_root', 'PROCESS_EXECUTION', 'air10_exec_boundary_c11', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (t_id_missing_out, json.dumps({
        "binary_path": test_bin,
        "binary_sha256": test_bin_sha,
        "input_file": input_file,
        "input_sha256": in_sha,
        "actual_returncode": 0,
        "duration_ms": 1.0,
        # stdout_sha256 omitted
    })))
    conn.commit()
    conn.close()

    verdict_m = air10_layer5_verifier.verify_trace(t_id_missing_out, target_stdout_file=None, audit_db_path=hermetic_audit_db)
    assert verdict_m == "VERIFIED_FAIL_INVARIANT_VIOLATION"

    conn = sqlite3.connect(hermetic_audit_db)
    conn.row_factory = sqlite3.Row
    row_m = conn.execute("SELECT * FROM tool_traces_v2 WHERE trace_id = ?", (t_id_missing_out,)).fetchone()
    conn.close()
    assert row_m is not None
    assert row_m["stdout_sha256"] is None, "Missing stdout digest must be stored as SQL NULL"
    assert row_m["semantic_equivalence"] == "MISSING_EXECUTION_ATTESTATION"

    # 1B. Missing input execution digest fails closed, stores NULL in tool_traces_v2
    t_id_missing_in = "tr_gate22_missing_input_attest"
    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO trace_events 
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES (?, 'span_exec_g22_in', 'span_root', 'PROCESS_EXECUTION', 'air10_exec_boundary_c11', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (t_id_missing_in, json.dumps({
        "binary_path": test_bin,
        "binary_sha256": test_bin_sha,
        "input_file": input_file,
        # input_sha256 omitted
        "actual_returncode": 0,
        "duration_ms": 1.0,
        "stdout_sha256": hashlib.sha256(b'{"key": "value"}').hexdigest()
    })))
    conn.commit()
    conn.close()

    verdict_in = air10_layer5_verifier.verify_trace(t_id_missing_in, target_stdout_file=None, audit_db_path=hermetic_audit_db)
    assert verdict_in == "VERIFIED_FAIL_INVARIANT_VIOLATION"

    conn = sqlite3.connect(hermetic_audit_db)
    conn.row_factory = sqlite3.Row
    row_in = conn.execute("SELECT * FROM tool_traces_v2 WHERE trace_id = ?", (t_id_missing_in,)).fetchone()
    conn.close()
    assert row_in is not None
    assert row_in["input_sha256"] is None, "Missing input digest must be stored as SQL NULL"
    assert row_in["semantic_equivalence"] == "MISSING_EXECUTION_ATTESTATION"

    # 2. Anti-ABA: Post-execution binary mutation detected fail-closed
    t_id_aba = "tr_gate22_anti_aba"
    aba_bin = str(tmp_path / "aba_tool.sh")
    with open(aba_bin, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(aba_bin, 0o755)
    aba_orig_sha = hashlib.sha256(open(aba_bin, "rb").read()).hexdigest()
    aba_stdout_sha = hashlib.sha256(b"output").hexdigest()

    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO trace_events 
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES (?, 'span_exec_g22_aba', 'span_root', 'PROCESS_EXECUTION', 'air10_exec_boundary_c11', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (t_id_aba, json.dumps({
        "binary_path": aba_bin,
        "binary_sha256": aba_orig_sha,
        "input_file": input_file,
        "input_sha256": in_sha,
        "actual_returncode": 0,
        "duration_ms": 1.0,
        "stdout_sha256": aba_stdout_sha
    })))
    conn.commit()
    conn.close()

    # Mutate the binary on disk before Layer 5 verification (Anti-ABA attack)
    with open(aba_bin, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\n# MUTATED TAMPERED CONTENT\nexit 0\n")

    verdict_aba = air10_layer5_verifier.verify_trace(t_id_aba, target_stdout_file=None, audit_db_path=hermetic_audit_db)
    assert verdict_aba == "VERIFIED_FAIL_INVARIANT_VIOLATION"

    conn = sqlite3.connect(hermetic_audit_db)
    cur = conn.cursor()
    cur.execute("SELECT details_json FROM trace_events WHERE trace_id = ? AND stage = 'INDEPENDENT_VERIFICATION'", (t_id_aba,))
    aba_details = json.loads(cur.fetchone()[0])
    conn.close()
    assert aba_details["semantic_result"] == "BINARY_INTEGRITY_VIOLATION"
    assert "does not match disk binary SHA" in aba_details["failure_reason"]

    # 3. CourtAwareRanker C11 Supervisor Enforcement
    unsup_bin = str(tmp_path / "unsup_tool.sh")
    with open(unsup_bin, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(unsup_bin, 0o755)
    unsup_bin_sha = hashlib.sha256(open(unsup_bin, "rb").read()).hexdigest()

    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO tool_contract_verdicts_v2
        (tool_name, capability, input_format, contract_version, status, binary_path, binary_sha256, reason, quarantined_at, superseded_by, verified_at)
        VALUES ('unsupervised_tool', 'JSON_SINGLE_DOC_STRICT', 'SINGLE_DOC_STRICT_RFC8259', 'v1.0',
                'ALLOWED', ?, ?, 'APPROVED', NULL, NULL, '2026-09-11T00:00:00Z')
    """, (unsup_bin, unsup_bin_sha))
    conn.execute("""
        INSERT INTO tool_traces_v2
        (trace_id, task_intent, traffic_class, router_candidates, chosen_tool, binary_path, binary_sha256, input_path, input_sha256, stdout_sha256, actual_exit_code, duration_ms, semantic_equivalence, verification_status, failure_reason, created_at)
        VALUES ('tr_unsupervised', 'JSON_PARSE', 'BATCH', '[]', 'unsupervised_tool', ?, ?, ?, ?, ?, 0, 1.0, 'EXACT_AST_MATCH', 'VERIFIED_PASS', NULL, '2026-09-11T00:00:00Z')
    """, (unsup_bin, unsup_bin_sha, input_file, in_sha, unsup_bin_sha))
    conn.execute("""
        INSERT INTO trace_events
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES ('tr_unsupervised', 'span_unsup', 'span_root', 'PROCESS_EXECUTION', 'python_unsafe_direct', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (json.dumps({"tool_name": "unsupervised_tool", "binary_path": unsup_bin}),))
    conn.commit()
    conn.close()

    ranker = CourtAwareRanker(audit_db_path=hermetic_audit_db, verifier=CIVeXVerifier())
    score = ranker.score_tool(
        tool_name="unsupervised_tool",
        capability="JSON_SINGLE_DOC_STRICT",
        binary_path=unsup_bin
    )
    assert score.status == "SUPERVISION_UNVERIFIED_HOLD"
    assert score.final_score == 0.0
    assert "No C11 supervised process execution trace" in score.rationale


def test_gate23_master_closed_loop_and_true_aba(hermetic_audit_db, tmp_path, monkeypatch):
    """Gate 23: Master Closed Loop, Same-Request Self-Healing & True ABA Resistance.
    1. Same-Request Self-Healing: Single-invocation failover when primary tool fails verification.
    2. C11 Supervisor Unavailable: Zero child process execution and fail-closed refusal.
    3. Missing Input Attestation: Fail-closed with SQL NULL in tool_traces_v2 ledger.
    4. True ABA Resistance: Execution of immutable content-addressed snapshots & pre-exec binary SHA verification.
    """
    from civex.bridge import CIVeXVerifier
    from civex.trace_plumbing import (
        air10_layer4_executor,
        air10_layer5_verifier,
    )

    monkeypatch.setattr(air10_layer2_router, "DB_PATH", hermetic_audit_db)
    monkeypatch.setattr(air10_layer4_executor, "DB_PATH", hermetic_audit_db)
    monkeypatch.setattr(air10_layer5_verifier, "DB_PATH", hermetic_audit_db)
    monkeypatch.setenv("AIR10_AUDIT_DB", hermetic_audit_db)

    cb_state_file = str(tmp_path / "gate23_cb_state.json")
    monkeypatch.setattr(CIVeXVerifier, "STATE_FILE", cb_state_file)

    # 1. Multi-Turn Pre-Tripped Circuit Breaker Failover
    primary_bin = str(tmp_path / "primary_tool.sh")
    with open(primary_bin, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\nexit 1\n")
    os.chmod(primary_bin, 0o755)
    primary_sha = hashlib.sha256(open(primary_bin, "rb").read()).hexdigest()

    fallback_bin = str(tmp_path / "fallback_tool.sh")
    with open(fallback_bin, "w", encoding="utf-8") as f:
        f.write('#!/bin/sh\nfor arg do last="$arg"; done\ncat "$last"\nexit 0\n')
    os.chmod(fallback_bin, 0o755)
    fallback_sha = hashlib.sha256(open(fallback_bin, "rb").read()).hexdigest()

    input_file = str(tmp_path / "g23_input.json")
    with open(input_file, "w", encoding="utf-8") as f:
        f.write('{"test": "gate23_master"}')
    in_sha = hashlib.sha256(open(input_file, "rb").read()).hexdigest()

    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO tool_contract_verdicts_v2
        (tool_name, capability, input_format, contract_version, status, binary_path, binary_sha256, reason, quarantined_at, superseded_by, verified_at)
        VALUES ('primary_tool', 'JSON_SINGLE_DOC_STRICT', 'SINGLE_DOC_STRICT_RFC8259', 'v1.0',
                'ALLOWED', ?, ?, 'APPROVED_PRIMARY', NULL, NULL, '2026-09-11T00:00:00Z')
    """, (primary_bin, primary_sha))
    conn.execute("""
        INSERT INTO tool_contract_verdicts_v2
        (tool_name, capability, input_format, contract_version, status, binary_path, binary_sha256, reason, quarantined_at, superseded_by, verified_at)
        VALUES ('fallback_tool', 'JSON_SINGLE_DOC_STRICT', 'SINGLE_DOC_STRICT_RFC8259', 'v1.0',
                'ALLOWED', ?, ?, 'APPROVED_FALLBACK', NULL, NULL, '2026-09-11T00:00:00Z')
    """, (fallback_bin, fallback_sha))
    conn.execute("""
        INSERT INTO tool_traces_v2
        (trace_id, task_intent, traffic_class, router_candidates, chosen_tool, binary_path, binary_sha256, input_path, input_sha256, stdout_sha256, actual_exit_code, duration_ms, semantic_equivalence, verification_status, failure_reason, created_at)
        VALUES ('tr_seed_p', 'JSON_PARSE', 'BATCH', '[]', 'primary_tool', ?, ?, ?, ?, ?, 0, 0.1, 'EXACT_AST_MATCH', 'VERIFIED_PASS', NULL, '2026-09-11T00:00:00Z')
    """, (primary_bin, primary_sha, input_file, in_sha, primary_sha))
    conn.execute("""
        INSERT INTO trace_events
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES ('tr_seed_p', 'span_seed_p', 'span_root', 'PROCESS_EXECUTION', 'air10_exec_boundary_c11', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (json.dumps({"tool_name": "primary_tool", "binary_path": primary_bin}),))
    conn.execute("""
        INSERT INTO tool_traces_v2
        (trace_id, task_intent, traffic_class, router_candidates, chosen_tool, binary_path, binary_sha256, input_path, input_sha256, stdout_sha256, actual_exit_code, duration_ms, semantic_equivalence, verification_status, failure_reason, created_at)
        VALUES ('tr_seed_fb', 'JSON_PARSE', 'BATCH', '[]', 'fallback_tool', ?, ?, ?, ?, ?, 0, 1.5, 'EXACT_AST_MATCH', 'VERIFIED_PASS', NULL, '2026-09-11T00:00:00Z')
    """, (fallback_bin, fallback_sha, input_file, in_sha, fallback_sha))
    conn.execute("""
        INSERT INTO trace_events
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES ('tr_seed_fb', 'span_seed_fb', 'span_root', 'PROCESS_EXECUTION', 'air10_exec_boundary_c11', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (json.dumps({"tool_name": "fallback_tool", "binary_path": fallback_bin}),))
    conn.commit()
    conn.close()

    candidate_pool = [
        {"name": "primary_tool", "binary": primary_bin},
        {"name": "fallback_tool", "binary": fallback_bin}
    ]

    # Trip primary_tool in circuit breaker to demonstrate same-request fallback
    verifier = CIVeXVerifier()
    verifier.record_outcome("primary_tool", success=False, error_msg="Primary execution failure")
    verifier.record_outcome("primary_tool", success=False, error_msg="Primary execution failure")
    verifier.record_outcome("primary_tool", success=False, error_msg="Primary execution failure")
    assert verifier.is_circuit_open("primary_tool")

    trace_id_heal = "tr_gate23_same_req_heal"
    chosen_tool, chosen_bin, span_router = air10_layer2_router.route_intent(
        trace_id=trace_id_heal,
        parent_span_id="span_root_g23",
        intent_query="parse strict single doc json",
        required_capability="JSON_SINGLE_DOC_STRICT",
        candidates_override=candidate_pool,
        db_path=hermetic_audit_db
    )
    assert chosen_tool == "fallback_tool", f"Expected immediate fallback to fallback_tool, got {chosen_tool}"
    assert chosen_bin == fallback_bin

    out_fb = str(tmp_path / "out_fb.json")
    rc_fb, _, out_sha_fb = air10_layer4_executor.execute_process(
        trace_id=trace_id_heal,
        binary_path=chosen_bin,
        input_file=input_file,
        parent_span_id=span_router,
        output_file=out_fb,
        argv=[input_file],
        db_path=hermetic_audit_db
    )
    assert rc_fb == 0
    verdict_fb = air10_layer5_verifier.verify_trace(trace_id_heal, target_stdout_file=out_fb, audit_db_path=hermetic_audit_db)
    assert verdict_fb == "VERIFIED_PASS"

    # 2. C11 Supervisor Unavailable: Zero Child Execution & Fail-Closed Refusal
    non_existent_boundary = str(tmp_path / "nonexistent_air10_boundary")
    monkeypatch.setenv("AIR10_EXEC_BOUNDARY", non_existent_boundary)

    marker_file = str(tmp_path / "should_never_be_created.txt")
    marker_script = str(tmp_path / "marker_script.sh")
    with open(marker_script, "w", encoding="utf-8") as f:
        f.write(f"#!/bin/sh\ntouch {marker_file}\nexit 0\n")
    os.chmod(marker_script, 0o755)

    with pytest.raises(RuntimeError) as excinfo:
        air10_layer4_executor.execute_process(
            trace_id="tr_gate23_no_sup",
            binary_path=marker_script,
            input_file=input_file,
            db_path=hermetic_audit_db
        )
    assert "EXECUTION_SUPERVISOR_UNAVAILABLE_HOLD" in str(excinfo.value)
    # Assert child process NEVER executed: marker file does not exist
    assert not os.path.exists(marker_file), "Child process executed despite missing supervisor!"

    # Restore real boundary binary
    real_boundary = "/tmp/air10_exec_boundary"
    if not os.path.isfile(real_boundary):
        real_boundary = "/Users/rajondas/.local/bin/air10_exec_boundary"
    monkeypatch.setenv("AIR10_EXEC_BOUNDARY", real_boundary)

    # 3. Missing Input Attestation -> Fail-Closed & NULL Ledger Proof
    t_id_missing_inp = "tr_gate23_missing_input_attest"
    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO trace_events 
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES (?, 'span_exec_g23_mi', 'span_root', 'PROCESS_EXECUTION', 'air10_exec_boundary_c11', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (t_id_missing_inp, json.dumps({
        "binary_path": fallback_bin,
        "binary_sha256": fallback_sha,
        "input_file": input_file,
        # input_sha256 omitted
        "actual_returncode": 0,
        "duration_ms": 1.0,
        "stdout_sha256": out_sha_fb
    })))
    conn.commit()
    conn.close()

    v_missing_inp = air10_layer5_verifier.verify_trace(t_id_missing_inp, target_stdout_file=None, audit_db_path=hermetic_audit_db)
    assert v_missing_inp == "VERIFIED_FAIL_INVARIANT_VIOLATION"

    conn = sqlite3.connect(hermetic_audit_db)
    conn.row_factory = sqlite3.Row
    row_mi = conn.execute("SELECT * FROM tool_traces_v2 WHERE trace_id = ?", (t_id_missing_inp,)).fetchone()
    conn.close()
    assert row_mi is not None
    assert row_mi["input_sha256"] is None, "Missing input attestation must store SQL NULL in ledger"
    assert row_mi["semantic_equivalence"] == "MISSING_EXECUTION_ATTESTATION"

    # 4. True ABA Resistance: Execution of Immutable Snapshot & Pre-Exec Verification
    aba_worker = str(tmp_path / "aba_worker.sh")
    with open(aba_worker, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\nprintf 'GENUINE_ABA_PROTECTED_OUTPUT'\nexit 0\n")
    os.chmod(aba_worker, 0o755)
    worker_orig_sha = hashlib.sha256(open(aba_worker, "rb").read()).hexdigest()

    # Sub-check A: Pre-exec binary SHA mismatch fails closed with exit code 76 before fork/exec
    c11_bin = os.environ.get("AIR10_EXEC_BOUNDARY", "/tmp/air10_exec_boundary")
    if not os.path.isfile(c11_bin):
        c11_bin = "/Users/rajondas/.local/bin/air10_exec_boundary"

    env_mismatch = os.environ.copy()
    env_mismatch["AIR10_EXPECTED_BINARY_SHA"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    proc_mismatch = subprocess.run(
        [c11_bin, "tr_gate23_mismatch", "span_root", aba_worker, input_file],
        capture_output=True, text=True, env=env_mismatch
    )
    assert proc_mismatch.returncode == 76, f"Expected fail-closed exit 76 on SHA mismatch, got {proc_mismatch.returncode}"

    # Sub-check B: Content-addressed immutable snapshot execution
    env_valid = os.environ.copy()
    env_valid["AIR10_EXPECTED_BINARY_SHA"] = worker_orig_sha
    proc_valid = subprocess.run(
        [c11_bin, "tr_gate23_valid_snap", "span_root", aba_worker, input_file],
        capture_output=True, text=True, env=env_valid
    )
    assert proc_valid.returncode == 0
    snap_data = json.loads(proc_valid.stdout)
    assert snap_data["executed_binary_sha256"] == worker_orig_sha
    expected_out_sha = hashlib.sha256(b"GENUINE_ABA_PROTECTED_OUTPUT").hexdigest()
    assert snap_data["stdout_sha256"] == expected_out_sha
    # Check that snapshot file exists
    snapshot_file = f"/tmp/air10_exec_snapshots/{worker_orig_sha}"
    assert os.path.isfile(snapshot_file), f"Expected immutable snapshot at {snapshot_file}"


def test_gate24_true_aba_cache_poisoning_and_immutable_input_binding(hermetic_audit_db, tmp_path, monkeypatch):
    """Gate 24: Rigorous ABA Prevention, Snapshot Cache Anti-Poisoning, Immutable Input Snapshot Binding, and Court SHA Propagation."""
    c11_bin = os.environ.get("AIR10_EXEC_BOUNDARY", "/tmp/air10_exec_boundary")
    if not os.path.isfile(c11_bin):
        c11_bin = "/Users/rajondas/.local/bin/air10_exec_boundary"
    monkeypatch.setenv("AIR10_EXEC_BOUNDARY", c11_bin)
    monkeypatch.setenv("AIR10_AUDIT_DB", hermetic_audit_db)

    # 1. Court-Certified Expected SHA Propagation:
    tool_bin = str(tmp_path / "g24_tool.sh")
    with open(tool_bin, "w", encoding="utf-8") as f:
        f.write('#!/bin/sh\nprintf \'{"g24": "ok"}\'\nexit 0\n')
    os.chmod(tool_bin, 0o755)
    tool_sha = hashlib.sha256(open(tool_bin, "rb").read()).hexdigest()

    inp_file = str(tmp_path / "g24_input.json")
    with open(inp_file, "w", encoding="utf-8") as f:
        f.write('{"param": 123}')
    inp_sha = hashlib.sha256(open(inp_file, "rb").read()).hexdigest()

    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO tool_contract_verdicts_v2
        (tool_name, capability, input_format, contract_version, status, binary_path, binary_sha256, reason, quarantined_at, superseded_by, verified_at)
        VALUES ('g24_tool', 'JSON_PARSE', 'SINGLE_DOC_STRICT_RFC8259', 'v1.0',
                'ALLOWED', ?, ?, 'COURT_CERTIFIED', NULL, NULL, '2026-09-11T00:00:00Z')
    """, (tool_bin, tool_sha))
    conn.commit()
    conn.close()

    # If Court SHA does not match actual binary, Layer 4 / C11 must fail closed with exit code 76
    tampered_expected_sha = "e" * 64
    out_fail = str(tmp_path / "out_fail.json")
    with pytest.raises(RuntimeError) as exc_info:
        air10_layer4_executor.execute_process(
            trace_id="tr_g24_mismatch",
            binary_path=tool_bin,
            input_file=inp_file,
            output_file=out_fail,
            expected_binary_sha=tampered_expected_sha,
            require_court_sha=True,
            db_path=hermetic_audit_db
        )
    assert "exit 76" in str(exc_info.value) or "PRE_EXEC_BINARY_TAMPERED" in str(exc_info.value)

    # 2. Poisoned Snapshot Cache Refusal (Exit 79):
    snap_dir = Path("/tmp/air10_exec_snapshots")
    snap_dir.mkdir(parents=True, exist_ok=True)
    poisoned_snap = snap_dir / tool_sha
    poisoned_snap.write_bytes(b"MALICIOUS_POISONED_PAYLOAD")
    poisoned_snap.chmod(0o700)

    res_poison = subprocess.run(
        [c11_bin, "tr_g24_poison", "span_root", tool_bin, inp_file],
        capture_output=True, text=True,
        env=dict(os.environ, AIR10_EXPECTED_BINARY_SHA=tool_sha, AIR10_REQUIRE_EXPECTED_SHA="1")
    )
    assert res_poison.returncode == 79, f"Expected exit 79 (SNAPSHOT_CACHE_POISONED), got {res_poison.returncode}"
    if poisoned_snap.exists():
        poisoned_snap.unlink()

    # 3. Immutable Input Snapshot & Argv Binding:
    probe_script = str(tmp_path / "g24_probe.sh")
    with open(probe_script, "w", encoding="utf-8") as f:
        f.write('#!/bin/sh\necho "ARG1=$1"\necho "ENV_INPUT=$AIR10_INPUT_FILE"\nexit 0\n')
    os.chmod(probe_script, 0o755)
    probe_sha = hashlib.sha256(open(probe_script, "rb").read()).hexdigest()

    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO tool_contract_verdicts_v2
        (tool_name, capability, input_format, contract_version, status, binary_path, binary_sha256, reason, quarantined_at, superseded_by, verified_at)
        VALUES ('g24_probe', 'JSON_PARSE', 'SINGLE_DOC_STRICT_RFC8259', 'v1.0',
                'ALLOWED', ?, ?, 'COURT_CERTIFIED', NULL, NULL, '2026-09-11T00:00:00Z')
    """, (probe_script, probe_sha))
    conn.commit()
    conn.close()

    out_probe = str(tmp_path / "out_probe.txt")
    rc_probe, _, _ = air10_layer4_executor.execute_process(
        trace_id="tr_g24_probe",
        binary_path=probe_script,
        input_file=inp_file,
        output_file=out_probe,
        argv=[inp_file],
        db_path=hermetic_audit_db
    )
    assert rc_probe == 0
    probe_output = open(out_probe, "r", encoding="utf-8").read()
    expected_inp_snap = f"/tmp/air10_input_snapshots/in_{inp_sha}"
    assert os.path.isfile(expected_inp_snap), f"Immutable input snapshot must exist at {expected_inp_snap}"
    assert f"ARG1={expected_inp_snap}" in probe_output, f"Argv must point to immutable input snapshot! Output: {probe_output}"
    assert f"ENV_INPUT={expected_inp_snap}" in probe_output, f"AIR10_INPUT_FILE must point to immutable input snapshot! Output: {probe_output}"

    # 4. Elimination of Mutable Binary Fallback (Exit 78):
    snap_probe = snap_dir / probe_sha
    if snap_probe.exists():
        snap_probe.unlink()
    snap_probe.write_bytes(open(probe_script, "rb").read())
    snap_probe.chmod(0o600)  # non-executable

    res_no_fallback = subprocess.run(
        [c11_bin, "tr_g24_nofallback", "span_root", probe_script, inp_file],
        capture_output=True, text=True,
        env=dict(os.environ, AIR10_EXPECTED_BINARY_SHA=probe_sha)
    )
    assert res_no_fallback.returncode == 78, f"Expected exit 78 (SNAPSHOT_EXECV_FAILED, no fallback), got {res_no_fallback.returncode}"
    snap_probe.chmod(0o700)
    snap_probe.unlink()

    # 5. Zero Execution Attestation Backfill:
    t_id_no_digest = "tr_g24_no_digest"
    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO trace_events 
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES (?, 'span_g24_nd', 'span_root', 'PROCESS_EXECUTION', 'air10_exec_boundary_c11', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (t_id_no_digest, json.dumps({
        "binary_path": tool_bin,
        "input_file": inp_file,
        "actual_returncode": 0,
        "duration_ms": 1.0,
        "stdout_sha256": "0" * 64
    })))
    conn.commit()
    conn.close()

    v_no_digest = air10_layer5_verifier.verify_trace(t_id_no_digest, target_stdout_file=None, audit_db_path=hermetic_audit_db)
    assert v_no_digest == "VERIFIED_FAIL_INVARIANT_VIOLATION"

    conn = sqlite3.connect(hermetic_audit_db)
    conn.row_factory = sqlite3.Row
    row_nd = conn.execute("SELECT * FROM tool_traces_v2 WHERE trace_id = ?", (t_id_no_digest,)).fetchone()
    conn.close()
    assert row_nd is not None
    assert row_nd["binary_sha256"] is None, "Missing binary SHA must be stored as SQL NULL, never synthetic"
    assert row_nd["input_sha256"] is None, "Missing input SHA must be stored as SQL NULL, never synthetic"
    assert row_nd["stdout_sha256"] is None, "Synthetic sentinel stdout SHA must be stored as SQL NULL"


def test_gate25_autonomous_one_call_orchestration_self_healing(hermetic_audit_db, tmp_path, monkeypatch):
    """Gate 25: Autonomous One-Call Closed-Loop Orchestration with Same-Request Self-Healing Failover."""
    from civex.orchestrator import orchestrate_request

    c11_bin = os.environ.get("AIR10_EXEC_BOUNDARY", "/tmp/air10_exec_boundary")
    if not os.path.isfile(c11_bin):
        c11_bin = "/Users/rajondas/.local/bin/air10_exec_boundary"
    monkeypatch.setenv("AIR10_EXEC_BOUNDARY", c11_bin)
    monkeypatch.setenv("AIR10_AUDIT_DB", hermetic_audit_db)

    cb_state_file = str(tmp_path / "g25_cb_state.json")
    monkeypatch.setattr(CIVeXVerifier, "STATE_FILE", cb_state_file)

    # 1. Primary candidate tool that fails execution (exit 1)
    primary_bin = str(tmp_path / "primary_worker.sh")
    with open(primary_bin, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\nexit 1\n")
    os.chmod(primary_bin, 0o755)
    primary_sha = hashlib.sha256(open(primary_bin, "rb").read()).hexdigest()

    # 2. Resilient fallback tool that succeeds and prints valid JSON/AST
    fallback_bin = str(tmp_path / "fallback_worker.sh")
    with open(fallback_bin, "w", encoding="utf-8") as f:
        f.write('#!/bin/sh\nfor arg do last="$arg"; done\ncat "$last"\nexit 0\n')
    os.chmod(fallback_bin, 0o755)
    fallback_sha = hashlib.sha256(open(fallback_bin, "rb").read()).hexdigest()

    # 3. Input file with RFC 8259 JSON
    inp_file = str(tmp_path / "g25_input.json")
    with open(inp_file, "w", encoding="utf-8") as f:
        f.write('{"civex_orchestration": "pass_v7"}')
    inp_sha = hashlib.sha256(open(inp_file, "rb").read()).hexdigest()

    # Register both tools in Court contracts
    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO tool_contract_verdicts_v2
        (tool_name, capability, input_format, contract_version, status, binary_path, binary_sha256, reason, quarantined_at, superseded_by, verified_at)
        VALUES ('primary_worker', 'JSON_SINGLE_DOC_STRICT', 'SINGLE_DOC_STRICT_RFC8259', 'v1.0',
                'ALLOWED', ?, ?, 'COURT_APPROVED_PRIMARY', NULL, NULL, '2026-09-11T00:00:00Z')
    """, (primary_bin, primary_sha))
    conn.execute("""
        INSERT INTO tool_contract_verdicts_v2
        (tool_name, capability, input_format, contract_version, status, binary_path, binary_sha256, reason, quarantined_at, superseded_by, verified_at)
        VALUES ('fallback_worker', 'JSON_SINGLE_DOC_STRICT', 'SINGLE_DOC_STRICT_RFC8259', 'v1.0',
                'ALLOWED', ?, ?, 'COURT_APPROVED_FALLBACK', NULL, NULL, '2026-09-11T00:00:00Z')
    """, (fallback_bin, fallback_sha))

    # Seed initial telemetry: primary has lower latency (0.1ms) so router prefers it initially
    conn.execute("""
        INSERT INTO tool_traces_v2
        (trace_id, attempt_no, task_intent, traffic_class, router_candidates, chosen_tool, binary_path, binary_sha256, input_path, input_sha256, stdout_sha256, actual_exit_code, duration_ms, semantic_equivalence, verification_status, failure_reason, created_at)
        VALUES ('tr_seed_g25_p', 1, 'JSON_PARSE', 'BATCH', '[]', 'primary_worker', ?, ?, ?, ?, ?, 0, 0.10, 'EXACT_AST_MATCH', 'VERIFIED_PASS', NULL, '2026-09-11T00:00:00Z')
    """, (primary_bin, primary_sha, inp_file, inp_sha, primary_sha))
    conn.execute("""
        INSERT INTO trace_events
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES ('tr_seed_g25_p', 'span_seed_g25_p', 'span_root', 'PROCESS_EXECUTION', 'air10_exec_boundary_c11', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (json.dumps({"tool_name": "primary_worker", "binary_path": primary_bin}),))

    conn.execute("""
        INSERT INTO tool_traces_v2
        (trace_id, attempt_no, task_intent, traffic_class, router_candidates, chosen_tool, binary_path, binary_sha256, input_path, input_sha256, stdout_sha256, actual_exit_code, duration_ms, semantic_equivalence, verification_status, failure_reason, created_at)
        VALUES ('tr_seed_g25_fb', 1, 'JSON_PARSE', 'BATCH', '[]', 'fallback_worker', ?, ?, ?, ?, ?, 0, 1.50, 'EXACT_AST_MATCH', 'VERIFIED_PASS', NULL, '2026-09-11T00:00:00Z')
    """, (fallback_bin, fallback_sha, inp_file, inp_sha, fallback_sha))
    conn.execute("""
        INSERT INTO trace_events
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES ('tr_seed_g25_fb', 'span_seed_g25_fb', 'span_root', 'PROCESS_EXECUTION', 'air10_exec_boundary_c11', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (json.dumps({"tool_name": "fallback_worker", "binary_path": fallback_bin}),))
    conn.commit()
    conn.close()

    candidate_pool = [
        {"name": "primary_worker", "binary": primary_bin},
        {"name": "fallback_worker", "binary": fallback_bin}
    ]

    verifier = CIVeXVerifier()
    assert not verifier.is_circuit_open("primary_worker")
    assert not verifier.is_circuit_open("fallback_worker")

    result = orchestrate_request(
        intent_query="parse strict single doc json",
        required_capability="JSON_SINGLE_DOC_STRICT",
        input_file=inp_file,
        candidate_pool=candidate_pool,
        db_path=hermetic_audit_db,
        max_attempts=2,
        output_dir=str(tmp_path)
    )

    assert result["status"] == "SUCCESS", f"Expected SUCCESS, got {result}"
    assert result["chosen_tool"] == "fallback_worker"
    assert result["attempts_needed"] == 2
    assert result["verdict"] == "VERIFIED_PASS"
    t_id = result["trace_id"]

    # Verify multi-attempt compound primary key in tool_traces_v2
    conn = sqlite3.connect(hermetic_audit_db)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM tool_traces_v2 WHERE trace_id = ? ORDER BY attempt_no ASC", (t_id,)).fetchall()
    conn.close()

    assert len(rows) == 2, f"Expected exactly 2 attempts in ledger for trace_id {t_id}, found {len(rows)}"

    # Attempt 1: primary_worker failed
    att1 = rows[0]
    assert att1["attempt_no"] == 1
    assert att1["chosen_tool"] == "primary_worker"
    assert att1["actual_exit_code"] == 1
    assert att1["verification_status"] == "VERIFIED_FAIL_INVARIANT_VIOLATION"

    # Attempt 2: fallback_worker succeeded
    att2 = rows[1]
    assert att2["attempt_no"] == 2
    assert att2["chosen_tool"] == "fallback_worker"
    assert att2["actual_exit_code"] == 0
    assert att2["verification_status"] == "VERIFIED_PASS"

    # Verify table schema has compound primary key (trace_id, attempt_no)
    conn = sqlite3.connect(hermetic_audit_db)
    pk_cols = [r[1] for r in conn.execute("PRAGMA table_info(tool_traces_v2)").fetchall() if r[5] > 0]
    conn.close()
    assert "trace_id" in pk_cols and "attempt_no" in pk_cols, f"Expected compound PK (trace_id, attempt_no), got {pk_cols}"



