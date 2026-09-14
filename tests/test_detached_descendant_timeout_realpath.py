import hashlib
import os
import sqlite3
import subprocess
import time

import pytest
from civex.court_ranking import CourtExecutionPermit
from civex.trace_plumbing import air10_layer4_executor


def _hermetic_audit_db(path):
    conn = sqlite3.connect(path)
    conn.execute("""
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
        )
    """)
    conn.execute("""
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
        )
    """)
    conn.commit()
    conn.close()


def test_issue11_detached_setsid_descendant_cannot_outlive_timeout(tmp_path, monkeypatch):
    """V2.2 real-path court: a setsid() descendant must not survive Layer4 timeout.

    This deliberately exercises execute_process -> compiled C11 boundary -> target worker.
    A process-group-only timeout implementation is a known-bad control: the target's
    detached descendant escapes killpg(), lives beyond the deadline, and writes the
    delayed marker. The court therefore MUST be RED until the production boundary has
    a true descendant-containment/reaping primitive or an equally strong fail-closed
    mechanism.
    """
    supervisor = os.environ.get("AIR10_EXEC_BOUNDARY", "/tmp/air10_exec_boundary")
    assert os.path.isfile(supervisor) and os.access(supervisor, os.X_OK), (
        "real-path court requires the compiled AIR10 C11 execution boundary"
    )
    monkeypatch.setenv("AIR10_EXEC_BOUNDARY", supervisor)

    db_path = str(tmp_path / "issue11_audit.db")
    _hermetic_audit_db(db_path)
    monkeypatch.setenv("AIR10_AUDIT_DB", db_path)

    marker = tmp_path / "detached_survivor.marker"
    pid_file = tmp_path / "detached_survivor.pid"
    control = tmp_path / "marker_positive_control"

    # Positive control: marker evidence is writable/readable in this hermetic directory.
    subprocess.run(
        ["python3", "-c", f"from pathlib import Path; Path({str(control)!r}).write_text('ok')"],
        check=True,
    )
    assert control.read_text() == "ok"

    worker = tmp_path / "issue11_worker.sh"
    py = (
        "import os,time; from pathlib import Path; "
        "os.setsid(); "
        f"Path({str(pid_file)!r}).write_text(str(os.getpid())); "
        "time.sleep(3.0); "
        f"Path({str(marker)!r}).write_text('SURVIVED_TIMEOUT')"
    )
    worker.write_text(
        "#!/bin/sh\n"
        f"python3 -c {subprocess.list2cmdline([py])} &\n"
        "sleep 100\n",
        encoding="utf-8",
    )
    worker.chmod(0o755)
    worker_sha = hashlib.sha256(worker.read_bytes()).hexdigest()

    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        INSERT INTO tool_contract_verdicts_v2
        (tool_name, capability, input_format, contract_version, status, binary_path,
         binary_sha256, reason, quarantined_at, superseded_by, verified_at, adversarial_evidence)
        VALUES ('issue11_tool', 'CLI_HOTPATH', 'JSON', 'v1.0.0', 'ALLOWED', ?, ?,
                'ISSUE11_HERMETIC', NULL, NULL, datetime('now'), 'DETACHED_DESCENDANT_COURT')
        """,
        (str(worker), worker_sha),
    )
    conn.commit()
    conn.close()

    permit = CourtExecutionPermit.issue(
        tool_name="issue11_tool",
        capability="CLI_HOTPATH",
        input_format="JSON",
        contract_version="v1.0.0",
        binary_path=str(worker),
        approved_sha=worker_sha,
        secret_key=os.environ["AIR10_COURT_SECRET_KEY"],
    )

    with pytest.raises(air10_layer4_executor.ExecutionTimeoutError):
        air10_layer4_executor.execute_process(
            trace_id="tr_issue11_detached_survivor",
            parent_span_id="span_issue11_parent",
            target_bin=str(worker),
            audit_db=db_path,
            permit=permit,
            timeout_sec=1.5,
        )

    # Ensure the adversary actually reached the detached state before interpreting absence.
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and not pid_file.exists():
        time.sleep(0.02)
    assert pid_file.exists(), "fixture invalid: detached descendant never materialized"

    detached_pid = int(pid_file.read_text().strip())
    grace_deadline = time.monotonic() + 3.5
    while time.monotonic() < grace_deadline and not marker.exists():
        time.sleep(0.03)

    # The strong process-tree timeout claim requires both no survivor side effect and no PID.
    assert not marker.exists(), (
        f"FALSE_GREEN: detached setsid descendant {detached_pid} survived the Layer4 timeout "
        "and produced a delayed side effect"
    )
    with pytest.raises(ProcessLookupError):
        os.kill(detached_pid, 0)
