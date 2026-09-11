import hashlib
import sqlite3
from pathlib import Path

from civex.court_ranking import CourtExecutionPermit, verify_permit


TEST_KEY = "test-only-external-authority-material"


def _signed_permit(tmp_path: Path):
    target = tmp_path / "tool.sh"
    target.write_text("#!/bin/sh\nexit 0\n")
    target.chmod(0o755)
    sha = hashlib.sha256(target.read_bytes()).hexdigest()
    permit = CourtExecutionPermit.issue(
        "tool",
        "cap",
        "json",
        "v1",
        str(target),
        sha,
        verdict_id="verdict-test",
        secret_key=TEST_KEY,
    )
    return permit, sha


def _write_authoritative_db(path: Path, binary_sha: str) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE tool_contract_verdicts_v2 (
            tool_name TEXT NOT NULL,
            capability TEXT NOT NULL,
            input_format TEXT NOT NULL,
            contract_version TEXT NOT NULL,
            status TEXT NOT NULL,
            is_quarantined INTEGER NOT NULL DEFAULT 0,
            binary_sha256 TEXT
        )
        """
    )
    conn.execute(
        """
        INSERT INTO tool_contract_verdicts_v2
        (tool_name, capability, input_format, contract_version, status, is_quarantined, binary_sha256)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        ("tool", "cap", "json", "v1", "ALLOWED", 0, binary_sha),
    )
    conn.commit()
    conn.close()


def test_verify_permit_requires_configured_authoritative_db(monkeypatch, tmp_path):
    """A valid caller-held HMAC is not Court authority when no Court DB is configured."""
    permit, _ = _signed_permit(tmp_path)
    monkeypatch.delenv("AIR10_AUDIT_DB", raising=False)

    ok, reason = verify_permit(
        permit,
        db_path=None,
        secret_key=TEST_KEY,
        required_capability="cap",
    )

    assert not ok, "missing Court DB must fail closed instead of returning PERMIT_VERIFIED"
    assert "COURT_AUTHORITY_DB_UNAVAILABLE_HOLD" in reason


def test_verify_permit_requires_existing_authoritative_db(tmp_path):
    """A missing caller-selected path must not silently skip Court DB verification."""
    permit, _ = _signed_permit(tmp_path)
    missing_db = tmp_path / "missing-court.db"

    ok, reason = verify_permit(
        permit,
        db_path=str(missing_db),
        secret_key=TEST_KEY,
        required_capability="cap",
    )

    assert not ok, "nonexistent Court DB must fail closed instead of returning PERMIT_VERIFIED"
    assert "COURT_AUTHORITY_DB_UNAVAILABLE_HOLD" in reason


def test_verify_permit_known_good_authoritative_db_still_passes(tmp_path):
    """Positive control: matching signed permit + authoritative contract row remains valid."""
    permit, sha = _signed_permit(tmp_path)
    court_db = tmp_path / "court.db"
    _write_authoritative_db(court_db, sha)

    ok, reason = verify_permit(
        permit,
        db_path=str(court_db),
        secret_key=TEST_KEY,
        required_capability="cap",
    )

    assert ok, reason
    assert reason == "PERMIT_VERIFIED"


def test_verify_permit_corrupt_db_fails_closed(tmp_path):
    """An existing but invalid Court DB must remain a hard verification failure."""
    permit, _ = _signed_permit(tmp_path)
    corrupt_db = tmp_path / "corrupt.db"
    corrupt_db.write_text("not sqlite")

    ok, reason = verify_permit(
        permit,
        db_path=str(corrupt_db),
        secret_key=TEST_KEY,
        required_capability="cap",
    )

    assert not ok
    assert "PERMIT_DB_VERIFICATION_FAILED" in reason
