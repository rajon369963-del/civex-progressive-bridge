#!/usr/bin/env python3
"""
AIR10 Trace Architecture - Layer 4: Physical Process Execution
Executes target binary, captures actual returncode, full SHA-256 hashes, exact latency, and logs PROCESS_EXECUTION span.
"""
import sys, os, time, uuid, hashlib, sqlite3, json, subprocess

DB_PATH = "/Users/rajondas/.antigravity/air10_audit.db"

def execute_process(trace_id, binary_path, input_file):
    span_id = f"span_exec_{uuid.uuid4().hex[:8]}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # 1. Compute input file SHA-256
    with open(input_file, "rb") as f:
        input_bytes = f.read()
    input_sha256 = hashlib.sha256(input_bytes).hexdigest()
    input_size = len(input_bytes)

    # 2. Compute binary SHA-256
    bin_sha256 = "UNKNOWN"
    if os.path.isfile(binary_path):
        with open(binary_path, "rb") as f:
            bin_sha256 = hashlib.sha256(f.read()).hexdigest()

    # 3. Physical Process Execution with high-resolution clock
    env = os.environ.copy()
    env["AIR10_TRACE_ID"] = trace_id

    t_start = time.perf_counter_ns()
    p = subprocess.run([binary_path, input_file], capture_output=True, env=env)
    t_end = time.perf_counter_ns()

    duration_us = (t_end - t_start) / 1_000.0
    duration_ms = duration_us / 1_000.0
    actual_returncode = p.returncode

    stdout_raw = p.stdout
    stderr_raw = p.stderr
    stdout_sha256 = hashlib.sha256(stdout_raw).hexdigest()
    stdout_str = stdout_raw.decode("utf-8", errors="replace")
    stderr_str = stderr_raw.decode("utf-8", errors="replace")

    details = {
        "binary_path": binary_path,
        "binary_sha256": bin_sha256,
        "input_file": input_file,
        "input_size_bytes": input_size,
        "input_sha256": input_sha256,
        "actual_returncode": actual_returncode,
        "duration_us": duration_us,
        "duration_ms": duration_ms,
        "stdout_sha256": stdout_sha256,
        "stdout_preview": stdout_str[:200],
        "stderr_preview": stderr_str[:200],
        "exec_pid": os.getpid(),
    }
    payload_raw = json.dumps(details, sort_keys=True).encode("utf-8")
    payload_sha256 = hashlib.sha256(payload_raw).hexdigest()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO trace_events 
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES (?, ?, NULL, 'PROCESS_EXECUTION', 'process_runner', ?, ?, 'COMPLETED', ?)
    """, (trace_id, span_id, now_iso, payload_sha256, json.dumps(details)))
    conn.commit()
    conn.close()

    print(f"EXIT_CODE={actual_returncode}|DURATION_MS={duration_ms:.3f}|STDOUT_SHA={stdout_sha256}")
    return actual_returncode, duration_ms, stdout_sha256

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: air10_layer4_executor.py <TRACE_ID> <BINARY_PATH> <INPUT_FILE>", file=sys.stderr)
        sys.exit(1)
    trace_id = sys.argv[1]
    binary = sys.argv[2]
    inp = sys.argv[3]
    execute_process(trace_id, binary, inp)
