import hashlib
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from civex.court_ranking import CourtExecutionPermit
from civex.trace_plumbing.air10_layer4_executor import execute_process

PUBLIC_FALLBACK_KEY = "air10_sovereign_court_master_secret_v9"
EXTERNAL_TEST_KEY = "test-only-external-authority-material-v2"


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(0o755)


def _write_authority_db(path: Path, target: Path) -> str:
    target_sha = hashlib.sha256(target.read_bytes()).hexdigest()
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE tool_contract_verdicts_v2 (
            tool_name TEXT NOT NULL,
            capability TEXT NOT NULL,
            input_format TEXT NOT NULL,
            contract_version TEXT NOT NULL,
            status TEXT NOT NULL,
            binary_sha256 TEXT,
            PRIMARY KEY (tool_name, capability, input_format, contract_version)
        )
        """
    )
    conn.execute(
        """
        INSERT INTO tool_contract_verdicts_v2
        (tool_name, capability, input_format, contract_version, status, binary_sha256)
        VALUES ('target-tool', 'EXEC_TEST', 'FORMAT_A', 'v1.0', 'ALLOWED', ?)
        """,
        (target_sha,),
    )
    conn.commit()
    conn.close()
    return target_sha


def _permit(target: Path, target_sha: str, key: str) -> CourtExecutionPermit:
    return CourtExecutionPermit.issue(
        tool_name="target-tool",
        capability="EXEC_TEST",
        input_format="FORMAT_A",
        contract_version="v1.0",
        binary_path=str(target),
        approved_sha=target_sha,
        secret_key=key,
    )


def test_missing_external_court_key_blocks_before_any_process(monkeypatch, tmp_path):
    """Known-bad source fallback must never authorize the real Layer4 process path."""
    supervisor_marker = tmp_path / "supervisor-ran"
    target_marker = tmp_path / "target-ran"
    supervisor = tmp_path / "supervisor.sh"
    target = tmp_path / "target.sh"
    audit_db = tmp_path / "court.db"
    audit_db.touch()

    _write_executable(supervisor, f"#!/bin/sh\ntouch '{supervisor_marker}'\nexit 99\n")
    _write_executable(target, f"#!/bin/sh\ntouch '{target_marker}'\n")

    monkeypatch.setenv("AIR10_EXEC_BOUNDARY", str(supervisor))
    monkeypatch.delenv("AIR10_COURT_SECRET_KEY", raising=False)

    with pytest.raises(RuntimeError, match="COURT_AUTHORITY_KEY_UNAVAILABLE_HOLD"):
        execute_process(
            "tr_v22_missing_key",
            binary_path=str(target),
            db_path=str(audit_db),
            permit=object(),
            require_court_sha=True,
        )

    assert not supervisor_marker.exists(), "authority HOLD must occur before supervisor Popen"
    assert not target_marker.exists(), "authority HOLD must guarantee zero target execution"


def test_missing_court_db_blocks_before_any_process(monkeypatch, tmp_path):
    """Caller-held key alone is not independently readable Court authority."""
    supervisor_marker = tmp_path / "supervisor-ran"
    target_marker = tmp_path / "target-ran"
    supervisor = tmp_path / "supervisor.sh"
    target = tmp_path / "target.sh"
    missing_db = tmp_path / "missing-court.db"

    _write_executable(supervisor, f"#!/bin/sh\ntouch '{supervisor_marker}'\nexit 99\n")
    _write_executable(target, f"#!/bin/sh\ntouch '{target_marker}'\n")

    monkeypatch.setenv("AIR10_EXEC_BOUNDARY", str(supervisor))
    monkeypatch.setenv("AIR10_COURT_SECRET_KEY", EXTERNAL_TEST_KEY)

    with pytest.raises(RuntimeError, match="COURT_AUTHORITY_DB_UNAVAILABLE_HOLD"):
        execute_process(
            "tr_v22_missing_db",
            binary_path=str(target),
            db_path=str(missing_db),
            permit=object(),
            require_court_sha=True,
        )

    assert not supervisor_marker.exists(), "missing authority DB must HOLD before supervisor Popen"
    assert not target_marker.exists(), "missing authority DB must guarantee zero target execution"


def test_public_fallback_valid_hmac_is_rejected_before_supervisor(monkeypatch, tmp_path):
    """A correctly recomputed HMAC with source-public fallback material is still untrusted authority."""
    supervisor_marker = tmp_path / "supervisor-public-ran"
    target_marker = tmp_path / "target-public-ran"
    supervisor = tmp_path / "supervisor-public.sh"
    target = tmp_path / "target-public.sh"
    audit_db = tmp_path / "court-public.db"

    _write_executable(supervisor, f"#!/bin/sh\ntouch '{supervisor_marker}'\nexit 99\n")
    _write_executable(target, f"#!/bin/sh\ntouch '{target_marker}'\n")
    target_sha = _write_authority_db(audit_db, target)
    forged_authority_permit = _permit(target, target_sha, PUBLIC_FALLBACK_KEY)

    monkeypatch.setenv("AIR10_EXEC_BOUNDARY", str(supervisor))
    monkeypatch.setenv("AIR10_COURT_SECRET_KEY", PUBLIC_FALLBACK_KEY)

    with pytest.raises(RuntimeError, match="COURT_AUTHORITY_KEY_REJECTED_HOLD"):
        execute_process(
            "tr_v22_public_fallback_valid_hmac",
            binary_path=str(target),
            db_path=str(audit_db),
            permit=forged_authority_permit,
            require_court_sha=True,
        )

    assert not supervisor_marker.exists(), "repository-known signing material must HOLD before Popen"
    assert not target_marker.exists(), "repository-known signing material must guarantee zero target execution"


def test_invalid_signature_with_external_key_is_rejected_before_supervisor(monkeypatch, tmp_path):
    """Malformed signatures remain a separate negative control after authority-source hardening."""
    supervisor_marker = tmp_path / "supervisor-invalid-ran"
    supervisor = tmp_path / "supervisor-invalid.sh"
    target = tmp_path / "target-invalid.sh"
    audit_db = tmp_path / "court-invalid.db"

    _write_executable(supervisor, f"#!/bin/sh\ntouch '{supervisor_marker}'\nexit 99\n")
    _write_executable(target, "#!/bin/sh\nexit 0\n")
    target_sha = _write_authority_db(audit_db, target)
    valid_permit = _permit(target, target_sha, EXTERNAL_TEST_KEY)
    invalid_permit = replace(valid_permit, signature="0" * 64)

    monkeypatch.setenv("AIR10_EXEC_BOUNDARY", str(supervisor))
    monkeypatch.setenv("AIR10_COURT_SECRET_KEY", EXTERNAL_TEST_KEY)

    with pytest.raises(RuntimeError, match="PERMIT_AUTHENTICITY_VERIFICATION_FAILED_HOLD"):
        execute_process(
            "tr_v22_invalid_signature_control",
            binary_path=str(target),
            db_path=str(audit_db),
            permit=invalid_permit,
            require_court_sha=True,
        )

    assert not supervisor_marker.exists(), "invalid signature must fail before physical supervision"


def test_external_nondefault_key_reaches_supervisor_gate(monkeypatch, tmp_path):
    """Positive discriminator: an explicit non-default key + matching Court DB is not rejected as source-public authority."""
    supervisor_marker = tmp_path / "supervisor-external-ran"
    supervisor = tmp_path / "supervisor-external.sh"
    target = tmp_path / "target-external.sh"
    audit_db = tmp_path / "court-external.db"

    _write_executable(supervisor, f"#!/bin/sh\ntouch '{supervisor_marker}'\nexit 99\n")
    _write_executable(target, "#!/bin/sh\nexit 0\n")
    target_sha = _write_authority_db(audit_db, target)
    permit = _permit(target, target_sha, EXTERNAL_TEST_KEY)

    monkeypatch.setenv("AIR10_EXEC_BOUNDARY", str(supervisor))
    monkeypatch.setenv("AIR10_COURT_SECRET_KEY", EXTERNAL_TEST_KEY)

    with pytest.raises(RuntimeError, match="EXECUTION_SUPERVISOR_FAIL_CLOSED"):
        execute_process(
            "tr_v22_external_key_positive_control",
            binary_path=str(target),
            db_path=str(audit_db),
            permit=permit,
            require_court_sha=True,
        )

    assert supervisor_marker.exists(), "valid external authority should pass the authority/signature gate to supervision"
