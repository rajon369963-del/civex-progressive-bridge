from pathlib import Path

import pytest

from scripts.verify_public_demo_identity import DemoIdentityError, verify_response


SOURCE = Path(__file__).resolve().parents[1] / "index.html"
MARKERS = (
    "CIVEX CANONICAL OKAPI BM25 ROUTER",
    "executeRealRouting",
    "tool_git_commit_and_push",
)


def test_known_good_exact_source_passes():
    body = SOURCE.read_bytes()
    result = verify_response(200, body, body, MARKERS)
    assert result["decision"] == "PASS_PUBLIC_DEMO_IDENTITY"
    assert result["bytes"] == len(body)


def test_http_200_wrong_content_is_rejected():
    expected = SOURCE.read_bytes()
    stale = expected.replace(
        b"CIVEX CANONICAL OKAPI BM25 ROUTER",
        b"CIVEX STALE WRONG DEMO CONTENT    ",
        1,
    )
    assert stale != expected
    with pytest.raises(DemoIdentityError, match="CONTENT_DIGEST_MISMATCH"):
        verify_response(200, stale, expected, MARKERS)


def test_non_200_is_rejected_even_with_correct_body():
    body = SOURCE.read_bytes()
    with pytest.raises(DemoIdentityError, match="HTTP_STATUS_MISMATCH"):
        verify_response(503, body, body, MARKERS)


def test_semantic_marker_is_required_even_when_digest_matches():
    body = SOURCE.read_bytes()
    with pytest.raises(DemoIdentityError, match="SEMANTIC_MARKER_MISSING"):
        verify_response(200, body, body, (*MARKERS, "marker-that-does-not-exist"))
