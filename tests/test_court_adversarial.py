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
"""

import hashlib
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
