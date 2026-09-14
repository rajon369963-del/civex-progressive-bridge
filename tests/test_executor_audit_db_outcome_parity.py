import hashlib
import json
import os
import sqlite3

from civex.trace_plumbing import air10_layer4_executor as executor


def _init_trace_db(path):
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE trace_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            trace_id TEXT,
            span_id TEXT,
            parent_span_id TEXT,
            stage TEXT,
            producer TEXT,
            timestamp_iso TEXT,
            payload_sha256 TEXT,
            status TEXT,
            details_json TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def test_audit_db_alias_is_same_authoritative_outcome_store(tmp_path, monkeypatch):
    """Real execute_process path must persist to the DB used as authority input.

    This catches a cross-layer false-green where `audit_db=` is honored during
    authority selection but later discarded before PROCESS_EXECUTION persistence.
    """
    audit_db = tmp_path / "court.sqlite"
    _init_trace_db(audit_db)

    supervisor = tmp_path / "air10_exec_boundary"
    supervisor.write_text("#!/bin/sh\nexit 0\n")
    supervisor.chmod(0o755)
    monkeypatch.setenv("AIR10_EXEC_BOUNDARY", str(supervisor))

    output_file = tmp_path / "stdout.bin"
    captured = b"bounded-output"
    output_file.write_bytes(captured)
    stdout_sha = hashlib.sha256(captured).hexdigest()

    class FakePopen:
        pid = os.getpid()
        returncode = 0

        def __init__(self, *args, **kwargs):
            pass

        def communicate(self, timeout=None):
            payload = {
                "exit_code": 0,
                "wall_duration_ms": 1.0,
                "stdout_sha256": stdout_sha,
                "supervisor": "air10_exec_boundary_c11",
                "executed_binary_sha256": "a" * 64,
                "executed_input_sha256": None,
            }
            return json.dumps(payload), ""

    monkeypatch.setattr(executor.subprocess, "Popen", FakePopen)

    result = executor.execute_process(
        "trace-audit-db-parity",
        binary_path="/bin/echo",
        argv=[],
        output_file=str(output_file),
        audit_db=str(audit_db),
        require_court_sha=False,
    )
    assert result.actual_returncode == 0

    conn = sqlite3.connect(audit_db)
    row = conn.execute(
        "SELECT stage, status FROM trace_events WHERE trace_id = ? ORDER BY event_id DESC LIMIT 1",
        ("trace-audit-db-parity",),
    ).fetchone()
    conn.close()

    assert row == ("PROCESS_EXECUTION", "COMPLETED")
