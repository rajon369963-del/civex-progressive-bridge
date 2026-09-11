from pathlib import Path

import pytest

from civex.trace_plumbing.air10_layer4_executor import execute_process


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(0o755)


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
    monkeypatch.setenv("AIR10_COURT_SECRET_KEY", "test-only-external-authority-material")

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
