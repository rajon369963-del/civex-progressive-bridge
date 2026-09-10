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
import sqlite3
import subprocess
import sys

import pytest
from civex.bridge import ProgressiveToolBridge
from civex.court_ranking import CourtAwareRanker


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
        trace_id TEXT PRIMARY KEY,
        task_intent TEXT NOT NULL,
        traffic_class TEXT NOT NULL,
        router_candidates TEXT NOT NULL,
        chosen_tool TEXT NOT NULL,
        binary_path TEXT NOT NULL,
        binary_sha256 TEXT NOT NULL,
        input_path TEXT NOT NULL,
        input_sha256 TEXT NOT NULL,
        stdout_sha256 TEXT NOT NULL,
        actual_exit_code INTEGER NOT NULL,
        duration_ms REAL NOT NULL,
        semantic_equivalence TEXT NOT NULL,
        verification_status TEXT NOT NULL,
        failure_reason TEXT,
        created_at TEXT NOT NULL
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
        INSERT INTO tool_traces_v2 VALUES (
            'tr_gate1_pristine', 'CANONICAL_TEST', 'INTERACTIVE', '[]',
            'test-valid-tool', ?, ?, '/tmp/in', 'sha_in', 'sha_out',
            0, 4.5, 'EQUIVALENT', 'VERIFIED_PASS', NULL, '2026-09-11T00:00:00Z'
        )
    """, (mock_binaries["valid_path"], mock_binaries["valid_sha"]))

    conn.execute("""
        INSERT INTO trace_events VALUES (
            NULL, 'tr_gate1_pristine', 'span_01', 'span_root',
            'PROCESS_EXECUTION', 'civex_executor', '2026-09-11T00:00:00Z',
            'sha_payload', 'COMPLETED', ?
        )
    """, (json.dumps({"tool_name": "test-valid-tool", "binary_path": mock_binaries["valid_path"]}),))
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
    from civex.trace_plumbing import air10_layer2_router
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

    trace_id = "tr_gate15_toctou"
    conn = sqlite3.connect(hermetic_audit_db)
    conn.execute("""
        INSERT INTO trace_events 
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES (?, 'span_exec_01', 'span_root', 'PROCESS_EXECUTION', 'c11_supervisor', '2026-09-11T00:00:00Z', 'sha', 'COMPLETED', ?)
    """, (trace_id, json.dumps({
        "binary_path": "/bin/echo",
        "binary_sha256": "0" * 64,
        "input_file": input_file,
        "input_sha256": orig_sha,
        "actual_returncode": 0,
        "duration_ms": 1.0,
        "stdout_sha256": "0" * 64
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
    import re

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
        air10_layer2_router,
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

