#!/usr/bin/env python3
"""
AIR10 Trace Architecture - Layer 3: Execution Boundary & Shim Dispatcher
Intercepts command execution, logs to physical shim_intercept.log, and writes SHIM_INTERCEPT span.
"""
import sys, os, time, uuid, hashlib, sqlite3, json

DB_PATH = "/Users/rajondas/.antigravity/air10_audit.db"
SHIM_LOG = "/Users/rajondas/.antigravity/shim_intercept.log"

def shim_intercept(trace_id, tool_name, binary_path, command_args):
    span_id = f"span_shim_{uuid.uuid4().hex[:8]}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    pid = os.getpid()

    # 1. Physical append to shim_intercept.log with correlated TRACE_ID
    shim_entry = f"[{now_iso}] PID:{pid} TRACE:{trace_id} SHIM:{tool_name} BIN:{binary_path} ARGS:{command_args}\n"
    with open(SHIM_LOG, "a", encoding="utf-8") as f:
        f.write(shim_entry)

    # 2. Compute binary SHA-256 if file exists
    bin_sha256 = "UNKNOWN"
    if os.path.isfile(binary_path):
        with open(binary_path, "rb") as f:
            bin_sha256 = hashlib.sha256(f.read()).hexdigest()

    details = {
        "tool_name": tool_name,
        "binary_path": binary_path,
        "binary_sha256": bin_sha256,
        "command_args": command_args,
        "shim_pid": pid,
        "env_trace_id": os.environ.get("AIR10_TRACE_ID", trace_id),
    }
    payload_raw = json.dumps(details, sort_keys=True).encode("utf-8")
    payload_sha256 = hashlib.sha256(payload_raw).hexdigest()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO trace_events 
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES (?, ?, NULL, 'SHIM_INTERCEPT', 'antigravity-shim', ?, ?, 'INTERCEPTED', ?)
    """, (trace_id, span_id, now_iso, payload_sha256, json.dumps(details)))
    conn.commit()
    conn.close()

    print(span_id)
    return span_id

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: air10_layer3_shim.py <TRACE_ID> <TOOL_NAME> <BINARY_PATH> [ARGS]", file=sys.stderr)
        sys.exit(1)
    trace_id = sys.argv[1]
    tool = sys.argv[2]
    binary = sys.argv[3]
    args = " ".join(sys.argv[4:]) if len(sys.argv) > 4 else ""
    shim_intercept(trace_id, tool, binary, args)
