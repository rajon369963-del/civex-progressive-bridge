
import math
import os
import pytest
from civex.court_ranking import CourtAwareRanker, ToolScoreBreakdown

AUDIT_DB = '/Users/rajondas/.antigravity/air10_audit.db'

@pytest.fixture
def ranker():
    return CourtAwareRanker(audit_db_path=AUDIT_DB)

def test_quarantined_tool_hard_zero(ranker):
    # air10-fast-json is quarantined for strict single JSON
    score = ranker.score_tool(
        tool_name='air10-fast-json',
        capability='JSON_SINGLE_DOC_STRICT',
        input_format='SINGLE_DOC_STRICT_RFC8259',
        contract_version='v1.0',
        observed_latency_ms=1.5
    )
    assert score.final_score == 0.0
    assert score.correctness_confidence == 0.0
    assert score.status == 'QUARANTINED'
    assert 'HARD EXCLUSION' in score.rationale

def test_circuit_breaker_open_hard_zero(ranker):
    score = ranker.score_tool(
        tool_name='python_orjson_cli',
        capability='JSON_SINGLE_DOC_STRICT',
        circuit_open=True
    )
    assert score.final_score == 0.0
    assert score.availability == 0.0
    assert score.status == 'CIRCUIT_OPEN'

def test_missing_binary_hard_zero(ranker):
    score = ranker.score_tool(
        tool_name='nonexistent_tool',
        capability='JSON_SINGLE_DOC_STRICT',
        binary_path='/path/to/definitely/nonexistent/binary_xyz_123'
    )
    assert score.final_score == 0.0
    assert score.availability == 0.0
    assert score.status == 'BINARY_MISSING'

def test_allowed_with_warning_penalty(ranker):
    score = ranker.score_tool(
        tool_name='air10-fast-json',
        capability='FIRST_OBJECT_ONLY_LENIENT',
        input_format='STREAM_FIRST_OBJECT_ONLY',
        contract_version='v1.0',
        observed_latency_ms=5.0
    )
    assert score.correctness_confidence == 0.70
    assert score.status == 'WARNING'
    assert score.final_score > 0.0

def test_verified_tool_full_confidence(ranker):
    score = ranker.score_tool(
        tool_name='python_orjson_cli',
        capability='JSON_SINGLE_DOC_STRICT',
        input_format='SINGLE_DOC_STRICT_RFC8259',
        contract_version='v1.0',
        observed_latency_ms=33.8,
        days_since_verification=0.0,
        is_supervised=True
    )
    assert score.correctness_confidence == 1.00
    assert score.status == 'ELIGIBLE'
    assert score.final_score > 0.0
    # Check formula correctness
    expected = score.correctness_confidence * score.availability * score.performance * score.freshness * score.safety
    assert abs(score.final_score - round(expected, 6)) < 1e-5

def test_rank_candidates_ordering(ranker):
    candidates = [
        {'name': 'air10-fast-json', 'latency_ms': 1.0},
        {'name': 'python_orjson_cli', 'latency_ms': 33.8},
    ]
    ranked = ranker.rank_candidates(
        candidates,
        capability='JSON_SINGLE_DOC_STRICT',
        input_format='SINGLE_DOC_STRICT_RFC8259'
    )
    assert len(ranked) == 2
    # python_orjson_cli must rank #1 because air10-fast-json is quarantined (score=0.0)
    assert ranked[0].tool_name == 'python_orjson_cli'
    assert ranked[0].final_score > 0.0
    assert ranked[1].tool_name == 'air10-fast-json'
    assert ranked[1].final_score == 0.0
