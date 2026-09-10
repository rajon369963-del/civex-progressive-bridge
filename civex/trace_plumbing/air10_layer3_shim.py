#!/usr/bin/env python3
"""
AIR10 Trace Architecture - Layer 3: Execution Boundary & Shim Dispatcher
Intercepts command execution, correlates with parent_span_id, and writes SHIM_INTERCEPT span.
"""
import hashlib
import json
import os
import sqlite3
import sys
import time
import uuid

DB_PATH = os.environ.get("AIR10_AUDIT_DB", "/Users/rajondas/.antigravity/air10_audit.db")
SHIM_LOG = os.environ.get("AIR10_SHIM_LOG", os.path.expanduser("~/.antigravity/shim_intercept.log"))

def shim_intercept(trace_id, tool_name, binary_path, command_args, parent_span_id=None):
    span_id = f"span_shim_{uuid.uuid4().hex[:8]}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    pid = os.getpid()
    effective_parent = parent_span_id or os.environ.get("AIR10_PARENT_SPAN_ID")

    # 1. Correlated physical append to shim_intercept.log if directory exists
    try:
        log_dir = os.path.dirname(SHIM_LOG)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        shim_entry = f"[{now_iso}] PID:{pid} TRACE:{trace_id} PARENT:{effective_parent or 'NONE'} SHIM:{tool_name} BIN:{binary_path} ARGS:{command_args}\n"
        with open(SHIM_LOG, "a", encoding="utf-8") as f:
            f.write(shim_entry)
    except Exception as e:
        sys.stderr.write(f"SHIM_LOG_FAILURE: Unable to append to {SHIM_LOG}: {e}\n")
        raise RuntimeError(f"FAIL-CLOSED: Shim log write failure: {e}") from e

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
        "parent_span_id": effective_parent,
        "env_trace_id": os.environ.get("AIR10_TRACE_ID", trace_id),
    }
    payload_raw = json.dumps(details, sort_keys=True).encode("utf-8")
    payload_sha256 = hashlib.sha256(payload_raw).hexdigest()

    if os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO trace_events 
            (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
            VALUES (?, ?, ?, 'SHIM_INTERCEPT', 'antigravity-shim', ?, ?, 'INTERCEPTED', ?)
        """, (trace_id, span_id, effective_parent, now_iso, payload_sha256, json.dumps(details)))
        conn.commit()
        conn.close()

    print(span_id)
    return span_id

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: air10_layer3_shim.py <TRACE_ID> <TOOL_NAME> <BINARY_PATH> [ARGS] [PARENT_SPAN_ID]", file=sys.stderr)
        sys.exit(1)
    trace_id = sys.argv[1]
    tool = sys.argv[2]
    binary = sys.argv[3]
    parent = sys.argv[5] if len(sys.argv) > 5 else None
    args = sys.argv[4] if len(sys.argv) > 4 else ""
    shim_intercept(trace_id, tool, binary, args, parent_span_id=parent)
