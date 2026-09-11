#!/usr/bin/env python3
"""
AIR10 Trace Architecture - Layer 4: Physical Process Execution (Hardened Supervisor)
Executes target binary via air10_exec_boundary C11 supervisor with strict CourtExecutionPermit
verification, captures actual returncode, full SHA-256 hashes, exact latency, and logs PROCESS_EXECUTION span
with explicit parent_span_id correlation.
"""
import hashlib
import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import time
import uuid

DB_PATH = os.environ.get("AIR10_AUDIT_DB", "/Users/rajondas/.antigravity/air10_audit.db")
SUPERVISOR_BIN = os.environ.get("AIR10_EXEC_BOUNDARY", "/Users/rajondas/.local/bin/air10_exec_boundary")

class ExecutionTimeoutError(subprocess.TimeoutExpired, RuntimeError):
    """Raised when supervised tool execution exceeds configured deadline."""
    def __init__(self, msg, timeout=0):
        super().__init__(cmd="", timeout=timeout)
        self.msg = msg

    def __str__(self):
        return self.msg


def execute_process(
    trace_id,
    binary_path=None,
    input_file=None,
    parent_span_id=None,
    output_file=None,
    argv=None,
    db_path=None,
    expected_binary_sha=None,
    expected_input_sha=None,
    require_court_sha=True,
    permit=None,
    timeout_sec=30.0,
    target_bin=None,
    audit_db=None,
):
    effective_bin = binary_path or target_bin
    if not effective_bin:
        raise ValueError("execute_process requires binary_path or target_bin")
    binary_path = effective_bin

    span_id = f"span_exec_{uuid.uuid4().hex[:8]}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    effective_parent = parent_span_id or os.environ.get("AIR10_PARENT_SPAN_ID")
    active_db = db_path or audit_db or DB_PATH

    if not output_file:
        output_file = f"/tmp/air10_stdout_{trace_id}_{span_id}.out"

    # 1. Supervised Execution Invariant: Supervisor binary MUST be available (Fail-Closed)
    supervisor_bin = os.environ.get("AIR10_EXEC_BOUNDARY", SUPERVISOR_BIN)
    if not (os.path.isfile(supervisor_bin) and os.access(supervisor_bin, os.X_OK)):
        err_msg = f"EXECUTION_SUPERVISOR_UNAVAILABLE_HOLD: Mandatory C11 execution supervisor '{supervisor_bin}' missing or not executable. Unsupervised Python fallback strictly refused (fail-closed)."
        sys.stderr.write(f"{err_msg}\n")
        raise RuntimeError(err_msg)

    # 2. Compute input file size (if input_file provided)
    input_size = 0
    if input_file and os.path.isfile(input_file):
        input_size = os.path.getsize(input_file)

    # 3. Court-certified Permit & Execution Attestation Verification (Fail-Closed)
    if permit is None and os.path.exists(active_db):
        try:
            conn = sqlite3.connect(f"file:{active_db}?mode=ro", uri=True)
            cur = conn.cursor()
            cur.execute(
                "SELECT details_json FROM trace_events WHERE trace_id = ? AND stage = 'ROUTER_EVALUATION' ORDER BY event_id DESC LIMIT 1",
                (trace_id,)
            )
            row = cur.fetchone()
            if row and row[0]:
                det = json.loads(row[0])
                p_dict = det.get("permit")
                if p_dict:
                    from civex.court_ranking import CourtExecutionPermit
                    permit = CourtExecutionPermit(**p_dict)

            # If not in trace_events and caller DID NOT pass expected_binary_sha (i.e. not attempting a bypass)
            if permit is None and not expected_binary_sha:
                cur.execute(
                    """SELECT tool_name, capability, input_format, contract_version, binary_sha256
                       FROM tool_contract_verdicts_v2
                       WHERE (binary_path = ? OR tool_name = ?) AND status in ('ALLOWED', 'VERIFIED_CORRECT', 'ELIGIBLE')
                       ORDER BY verified_at DESC LIMIT 1""",
                    (binary_path, os.path.basename(binary_path))
                )
                crow = cur.fetchone()
                if crow and crow[4]:
                    from civex.court_ranking import CourtExecutionPermit
                    permit = CourtExecutionPermit.issue(
                        tool_name=crow[0],
                        capability=crow[1],
                        input_format=crow[2],
                        contract_version=crow[3],
                        binary_path=binary_path,
                        approved_sha=crow[4],
                    )
            conn.close()
        except Exception:
            pass

    # Gate 28: Direct caller-supplied expected_binary_sha without permit is an illegal bypass attempt
    if require_court_sha and expected_binary_sha and permit is None:
        raise RuntimeError(f"COURT_PERMIT_REQUIRED_HOLD COURT_ATTESTATION_MISSING_HOLD: Direct expected_binary_sha '{expected_binary_sha}' bypass without authentic CourtExecutionPermit is prohibited for binary '{binary_path}'")

    if require_court_sha:
        if permit is None:
            raise RuntimeError(f"COURT_PERMIT_REQUIRED_HOLD COURT_ATTESTATION_MISSING_HOLD: Mandatory CourtExecutionPermit missing for binary '{binary_path}'")
        
        try:
            from civex.court_ranking import verify_permit
        except Exception:
            from court_ranking import verify_permit

        valid, reason = verify_permit(permit, db_path=active_db)
        if not valid:
            raise RuntimeError(f"PERMIT_AUTHENTICITY_VERIFICATION_FAILED_HOLD: {reason}")

        permit_bin = getattr(permit, "binary_path", None)
        if permit_bin and os.path.realpath(binary_path) != os.path.realpath(permit_bin):
            raise RuntimeError(f"COURT_PERMIT_PATH_MISMATCH_HOLD: Execution binary '{binary_path}' != permit binary '{permit_bin}'")

        permit_sha = getattr(permit, "approved_sha", None)
        if expected_binary_sha and expected_binary_sha != permit_sha:
            raise RuntimeError(f"COURT_ATTESTATION_MISSING_HOLD: Caller supplied expected_binary_sha '{expected_binary_sha}' does not match permit approved_sha '{permit_sha}'")

        expected_binary_sha = permit_sha
    elif permit is not None:
        try:
            from civex.court_ranking import verify_permit
        except Exception:
            from court_ranking import verify_permit
        valid, reason = verify_permit(permit, db_path=active_db)
        if not valid:
            raise RuntimeError(f"PERMIT_AUTHENTICITY_VERIFICATION_FAILED_HOLD: {reason}")
        permit_sha = getattr(permit, "approved_sha", None)
        if permit_sha:
            expected_binary_sha = permit_sha

    # Determine command arguments
    cmd_args = []
    if argv is not None:
        cmd_args = list(argv)
    elif input_file:
        cmd_args = [input_file]

    env = os.environ.copy()
    env["AIR10_TRACE_ID"] = trace_id
    env["AIR10_STDOUT_CAPTURE_PATH"] = output_file
    if input_file:
        env["AIR10_INPUT_FILE"] = input_file
    if effective_parent:
        env["AIR10_PARENT_SPAN_ID"] = effective_parent
    if expected_binary_sha:
        env["AIR10_EXPECTED_BINARY_SHA"] = expected_binary_sha
        env["AIR10_REQUIRE_EXPECTED_SHA"] = "1"
    if expected_input_sha:
        env["AIR10_EXPECTED_INPUT_SHA"] = expected_input_sha

    # Process-Group Isolated Execution: Ensures entire process tree is terminated on timeout
    proc = subprocess.Popen(
        [supervisor_bin, trace_id, effective_parent or "root", binary_path] + cmd_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True
    )
    try:
        proc_stdout, proc_stderr = proc.communicate(timeout=timeout_sec)
    except subprocess.TimeoutExpired as te:
        pgid = os.getpgid(proc.pid)
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=1.0)
        err_msg = f"EXECUTION_TIMEOUT_HOLD: Process group {pgid} terminated after exceeding deadline of {timeout_sec}s"
        sys.stderr.write(f"{err_msg}\n")
        raise ExecutionTimeoutError(err_msg) from te

    proc_returncode = proc.returncode

    if 70 <= proc_returncode <= 79:
        raise RuntimeError(
            f"EXECUTION_SUPERVISOR_FAIL_CLOSED: C11 supervisor exited with code {proc_returncode} (exit {proc_returncode}). "
            f"Stderr: {proc_stderr.strip()}"
        )
    if not proc_stdout.strip():
        raise RuntimeError(
            f"EXECUTION_SUPERVISOR_FAIL_CLOSED: C11 supervisor emitted no stdout (exit {proc_returncode}). "
            f"Stderr: {proc_stderr.strip()}"
        )

    sha_hex_re = re.compile(r"^[0-9a-fA-F]{64}$")
    try:
        boundary_data = json.loads(proc_stdout)
        actual_returncode = boundary_data["exit_code"]
        duration_ms = boundary_data["wall_duration_ms"]
        duration_us = duration_ms * 1000.0
        stdout_sha256 = boundary_data.get("stdout_sha256")
        supervisor_name = boundary_data.get("supervisor", "")
        executed_binary_sha256 = boundary_data.get("executed_binary_sha256")
        executed_input_sha256 = boundary_data.get("executed_input_sha256")

        # STRICT ZERO BACKFILL: Supervisor must attest directly and authentically
        if supervisor_name != "air10_exec_boundary_c11":
            raise RuntimeError(f"SUPERVISOR_ATTESTATION_INVALID_HOLD: Unverified supervisor identity: '{supervisor_name}'")

        if not executed_binary_sha256 or not sha_hex_re.match(executed_binary_sha256) or executed_binary_sha256 == "0" * 64:
            raise RuntimeError(f"SUPERVISOR_ATTESTATION_INVALID_HOLD: Missing or invalid executed_binary_sha256 from C11 supervisor: '{executed_binary_sha256}'")

        if input_file and (not executed_input_sha256 or not sha_hex_re.match(executed_input_sha256) or executed_input_sha256 == "0" * 64):
            raise RuntimeError(f"SUPERVISOR_ATTESTATION_INVALID_HOLD: Missing or invalid executed_input_sha256 from C11 supervisor: '{executed_input_sha256}'")

        if not stdout_sha256 or not sha_hex_re.match(stdout_sha256) or stdout_sha256 == "0" * 64:
            raise RuntimeError(f"SUPERVISOR_ATTESTATION_INVALID_HOLD: Missing or invalid stdout_sha256 from C11 supervisor: '{stdout_sha256}'")

    except json.JSONDecodeError as e:
        sys.stderr.write(f"C11_BOUNDARY_PARSE_ERROR: Failed to parse boundary json from stdout: {e}. Output: {proc_stdout[:200]}\n")
        raise RuntimeError(f"FAIL-CLOSED: C11 supervisor boundary output parse error: {e}") from e

    stdout_preview = proc_stdout[:200]
    stderr_preview = proc_stderr[:200]

    # Strict Output Capture Parity Verification (Fail-Closed)
    captured_str = ""
    if output_file:
        if not os.path.isfile(output_file):
            raise RuntimeError(f"FAIL-CLOSED: Supervisor completed but output capture file '{output_file}' missing on disk")
        with open(output_file, "rb") as of:
            captured_bytes = of.read()
        captured_sha = hashlib.sha256(captured_bytes).hexdigest()
        if captured_sha != stdout_sha256:
            raise RuntimeError(f"FAIL-CLOSED: Capture file SHA {captured_sha} != supervisor streaming SHA {stdout_sha256}")
        captured_str = captured_bytes.decode("utf-8", errors="replace")

    details = {
        "binary_path": binary_path,
        "binary_sha256": executed_binary_sha256,
        "input_file": input_file,
        "input_size_bytes": input_size,
        "input_sha256": executed_input_sha256,
        "output_file": output_file,
        "actual_returncode": actual_returncode,
        "duration_us": duration_us,
        "duration_ms": duration_ms,
        "stdout_sha256": stdout_sha256,
        "stdout_preview": stdout_preview,
        "stderr_preview": stderr_preview,
        "supervisor": supervisor_name,
        "exec_pid": os.getpid(),
    }
    payload_raw = json.dumps(details, sort_keys=True).encode("utf-8")
    payload_sha256 = hashlib.sha256(payload_raw).hexdigest()

    active_db = db_path or DB_PATH
    if os.path.exists(active_db):
        conn = sqlite3.connect(active_db)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO trace_events 
            (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
            VALUES (?, ?, ?, 'PROCESS_EXECUTION', ?, ?, ?, 'COMPLETED', ?)
        """, (trace_id, span_id, effective_parent, supervisor_name, now_iso, payload_sha256, json.dumps(details)))
        conn.commit()
        conn.close()

    print(f"EXIT_CODE={actual_returncode}|DURATION_MS={duration_ms:.3f}|STDOUT_SHA={stdout_sha256}")
    return ExecuteResult(actual_returncode, duration_ms, stdout_sha256, stdout=captured_str or proc_stdout, stderr=proc_stderr)


class ExecuteResult(tuple):
    """3-tuple subclass: (actual_returncode, duration_ms, stdout_sha256) with dict and attribute access."""
    def __new__(cls, actual_returncode, duration_ms, stdout_sha256, stdout=None, stderr=None):
        return super().__new__(cls, (actual_returncode, duration_ms, stdout_sha256))

    def __init__(self, actual_returncode, duration_ms, stdout_sha256, stdout=None, stderr=None):
        self.actual_returncode = actual_returncode
        self.duration_ms = duration_ms
        self.stdout_sha256 = stdout_sha256
        self.stdout = stdout or ""
        self.stderr = stderr or ""

    def __getitem__(self, item):
        if isinstance(item, str):
            if item == "actual_returncode":
                return self.actual_returncode
            if item == "duration_ms":
                return self.duration_ms
            if item == "stdout_sha256":
                return self.stdout_sha256
            if item == "stdout":
                return self.stdout
            if item == "stderr":
                return self.stderr
            raise KeyError(item)
        return super().__getitem__(item)

    def get(self, item, default=None):
        try:
            return self[item]
        except (KeyError, TypeError):
            return default

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: air10_layer4_executor.py <TRACE_ID> <BINARY_PATH> <INPUT_FILE> [PARENT_SPAN_ID]", file=sys.stderr)
        sys.exit(1)
    trace_id = sys.argv[1]
    binary = sys.argv[2]
    inp = sys.argv[3]
    parent = sys.argv[4] if len(sys.argv) > 4 else None
    execute_process(trace_id, binary, inp, parent_span_id=parent)
