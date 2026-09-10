import hashlib
import sqlite3

import pytest
from civex.bridge import ProgressiveToolBridge
from civex.court_ranking import CourtAwareRanker


@pytest.fixture
def hermetic_court_env(tmp_path):
    """Hermetic SQLite court DB fixture isolated from production state."""
    db_file = tmp_path / "hermetic_audit.db"
    conn = sqlite3.connect(str(db_file))
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

    # Create dummy binaries
    bin_ok = tmp_path / "bin_ok.sh"
    bin_ok.write_text("#!/bin/sh\necho ok\n")
    bin_ok.chmod(0o755)
    sha_ok = hashlib.sha256(bin_ok.read_bytes()).hexdigest()

    bin_tampered = tmp_path / "bin_tampered.sh"
    bin_tampered.write_text("#!/bin/sh\necho tampered\n")
    bin_tampered.chmod(0o755)

    bin_noexec = tmp_path / "bin_noexec.sh"
    bin_noexec.write_text("#!/bin/sh\necho noexec\n")
    bin_noexec.chmod(0o644)  # Not executable

    # Seed contract rows
    cur.execute("""
        INSERT INTO tool_contract_verdicts_v2 VALUES
        ('tool_quarantined', 'JSON_STRICT', 'RFC8259', 'v1.0', 'QUARANTINED', ?, ?, 'Truncation flaw', '2026-09-10T00:00:00Z', 'tool_ok', '2026-09-10T00:00:00Z', 'EVIDENCE_GATE_1'),
        ('tool_warning', 'JSON_LENIENT', 'STREAM_PREFIX', 'v1.0', 'ALLOWED_WITH_WARNING', ?, ?, 'Prefix only', NULL, NULL, '2026-09-10T00:00:00Z', 'EVIDENCE_GATE_2'),
        ('tool_ok', 'JSON_STRICT', 'RFC8259', 'v1.0', 'ALLOWED', ?, ?, 'Full RFC 8259 verified', NULL, NULL, '2026-09-10T00:00:00Z', 'EVIDENCE_GATE_3'),
        ('tool_tampered', 'JSON_STRICT', 'RFC8259', 'v1.0', 'ALLOWED', ?, 'certified_expected_sha_123', 'Attested binary', NULL, NULL, '2026-09-10T00:00:00Z', 'EVIDENCE_GATE_4'),
        ('tool_noexec', 'JSON_STRICT', 'RFC8259', 'v1.0', 'ALLOWED', ?, ?, 'Lacks exec bit', NULL, NULL, '2026-09-10T00:00:00Z', 'EVIDENCE_GATE_5');
    """, (
        str(bin_ok), sha_ok,
        str(bin_ok), sha_ok,
        str(bin_ok), sha_ok,
        str(bin_tampered),
        str(bin_noexec), hashlib.sha256(bin_noexec.read_bytes()).hexdigest()
    ))

    # Seed empirical traces and supervision events for tool_ok and tool_warning
    cur.execute("""
        INSERT INTO tool_traces_v2 VALUES
        ('tr_mock_ok', 'INTENT_TEST', 'BATCH', '[]', 'tool_ok', ?, ?, '/tmp/in', 'in_sha', 'out_sha', 0, 5.0, 'EQUIVALENT', 'VERIFIED_PASS', NULL, '2026-09-10T00:00:00Z'),
        ('tr_mock_warn', 'INTENT_TEST', 'BATCH', '[]', 'tool_warning', ?, ?, '/tmp/in', 'in_sha', 'out_sha', 0, 10.0, 'EQUIVALENT', 'VERIFIED_PASS', NULL, '2026-09-10T00:00:00Z');
    """, (str(bin_ok), sha_ok, str(bin_ok), sha_ok))

    cur.execute("""
        INSERT INTO trace_events VALUES
        (NULL, 'tr_mock_ok', 'span_01', 'span_root', 'PROCESS_EXECUTION', 'civex_exec', '2026-09-10T00:00:00Z', 'sha_p', 'COMPLETED', '{"tool_name": "tool_ok", "tool_id": "tool_ok"}'),
        (NULL, 'tr_mock_warn', 'span_02', 'span_root', 'PROCESS_EXECUTION', 'civex_exec', '2026-09-10T00:00:00Z', 'sha_p', 'COMPLETED', '{"tool_name": "tool_warning", "tool_id": "tool_warning"}');
    """)
    conn.commit()
    conn.close()

    verifier = MockVerifier()

    return {
        "db_path": str(db_file),
        "bin_ok": str(bin_ok),
        "bin_tampered": str(bin_tampered),
        "bin_noexec": str(bin_noexec),
        "verifier": verifier
    }

class MockVerifier:
    def __init__(self, open_tools=None):
        self.open_tools = set(open_tools or [])
    def is_circuit_open(self, tool_id: str) -> bool:
        return tool_id in self.open_tools

def test_exact_contract_quarantine_hard_zero(hermetic_court_env):
    ranker = CourtAwareRanker(audit_db_path=hermetic_court_env["db_path"], verifier=hermetic_court_env["verifier"])
    score = ranker.score_tool(
        tool_name="tool_quarantined",
        capability="JSON_STRICT",
        input_format="RFC8259",
        contract_version="v1.0",
        binary_path=hermetic_court_env["bin_ok"]
    )
    assert score.final_score == 0.0
    assert score.status == "QUARANTINED"
    assert "HARD_EXCLUSION" in score.rationale

def test_exact_contract_warning_penalty(hermetic_court_env):
    ranker = CourtAwareRanker(audit_db_path=hermetic_court_env["db_path"], verifier=hermetic_court_env["verifier"])
    score = ranker.score_tool(
        tool_name="tool_warning",
        capability="JSON_LENIENT",
        input_format="STREAM_PREFIX",
        contract_version="v1.0",
        binary_path=hermetic_court_env["bin_ok"],
        observed_latency_ms=10.0
    )
    assert score.correctness_confidence == 0.70
    assert score.status == "WARNING"
    assert score.final_score > 0.0

def test_exact_contract_allowed_full_confidence(hermetic_court_env):
    ranker = CourtAwareRanker(audit_db_path=hermetic_court_env["db_path"], verifier=hermetic_court_env["verifier"])
    score = ranker.score_tool(
        tool_name="tool_ok",
        capability="JSON_STRICT",
        input_format="RFC8259",
        contract_version="v1.0",
        binary_path=hermetic_court_env["bin_ok"],
        observed_latency_ms=10.0
    )
    assert score.correctness_confidence == 1.00
    assert score.status == "ELIGIBLE"
    assert score.final_score > 0.0

def test_unknown_contract_fail_closed_hold(hermetic_court_env):
    ranker = CourtAwareRanker(audit_db_path=hermetic_court_env["db_path"], verifier=hermetic_court_env["verifier"])
    # Tool exists, but contract_version='v2.0' is unverified
    score = ranker.score_tool(
        tool_name="tool_ok",
        capability="JSON_STRICT",
        input_format="RFC8259",
        contract_version="v2.0_UNVERIFIED",
        binary_path=hermetic_court_env["bin_ok"]
    )
    assert score.final_score == 0.0
    assert score.status == "CONTRACT_UNVERIFIED"

def test_authoritative_circuit_breaker_open(hermetic_court_env):
    verifier = MockVerifier(open_tools=["tool_ok"])
    ranker = CourtAwareRanker(audit_db_path=hermetic_court_env["db_path"], verifier=verifier)
    score = ranker.score_tool(
        tool_name="tool_ok",
        capability="JSON_STRICT",
        input_format="RFC8259",
        contract_version="v1.0",
        binary_path=hermetic_court_env["bin_ok"]
    )
    assert score.final_score == 0.0
    assert score.availability == 0.0
    assert score.status == "CIRCUIT_OPEN"

def test_tampered_binary_digest_security_alert(hermetic_court_env):
    ranker = CourtAwareRanker(audit_db_path=hermetic_court_env["db_path"], verifier=hermetic_court_env["verifier"])
    score = ranker.score_tool(
        tool_name="tool_tampered",
        capability="JSON_STRICT",
        input_format="RFC8259",
        contract_version="v1.0",
        binary_path=hermetic_court_env["bin_tampered"]
    )
    assert score.final_score == 0.0
    assert score.availability == 0.0
    assert score.status == "BINARY_HASH_MISMATCH"
    assert "SECURITY_ALERT" in score.rationale

def test_non_executable_binary_failure(hermetic_court_env):
    ranker = CourtAwareRanker(audit_db_path=hermetic_court_env["db_path"], verifier=hermetic_court_env["verifier"])
    score = ranker.score_tool(
        tool_name="tool_noexec",
        capability="JSON_STRICT",
        input_format="RFC8259",
        contract_version="v1.0",
        binary_path=hermetic_court_env["bin_noexec"]
    )
    assert score.final_score == 0.0
    assert score.availability == 0.0
    assert score.status == "BINARY_NOT_EXECUTABLE"

def test_missing_audit_db_fail_closed():
    ranker = CourtAwareRanker(audit_db_path="/tmp/nonexistent_audit_xyz.db", verifier=MockVerifier())
    score = ranker.score_tool(
        tool_name="tool_ok",
        capability="JSON_STRICT"
    )
    assert score.final_score == 0.0
    assert score.status == "VERIFICATION_UNAVAILABLE_HOLD"

def test_discriminative_latency_scale(hermetic_court_env):
    ranker = CourtAwareRanker(audit_db_path=hermetic_court_env["db_path"], verifier=hermetic_court_env["verifier"])
    s_1ms = ranker.score_tool("tool_ok", "JSON_STRICT", "RFC8259", "v1.0", binary_path=hermetic_court_env["bin_ok"], observed_latency_ms=1.0)
    s_10ms = ranker.score_tool("tool_ok", "JSON_STRICT", "RFC8259", "v1.0", binary_path=hermetic_court_env["bin_ok"], observed_latency_ms=10.0)
    s_100ms = ranker.score_tool("tool_ok", "JSON_STRICT", "RFC8259", "v1.0", binary_path=hermetic_court_env["bin_ok"], observed_latency_ms=100.0)

    # Must be strictly ordered: 1ms > 10ms > 100ms (no saturation at 100ms)
    assert s_1ms.final_score > s_10ms.final_score > s_100ms.final_score
    assert s_1ms.performance == pytest.approx(1.0 / (1.0 + 0.1), abs=1e-3)
    assert s_10ms.performance == pytest.approx(0.5, abs=1e-3)
    assert s_100ms.performance == pytest.approx(1.0 / 11.0, abs=1e-3)

def test_bridge_resolve_intent_with_court_integration():
    bridge = ProgressiveToolBridge()
    # Query with court ranking active
    tools = bridge.resolve_intent("git commit", top_k=3)
    assert isinstance(tools, list)
    if tools:
        assert "court_score" in tools[0]
        assert "court_status" in tools[0]
        assert "court_rationale" in tools[0]
