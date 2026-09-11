#!/usr/bin/env python3
"""
AIR10 Trace Architecture - Layer 1: Intent Generator & Root Span Emitter
Generates monotonic time-prefixed trace identifier and root INTENT span.
"""
import hashlib
import json
import os
import sqlite3
import sys
import time
import uuid

DB_PATH = os.environ.get("AIR10_AUDIT_DB", "/Users/rajondas/.antigravity/air10_audit.db")

def generate_monotonic_trace_id(prefix="tr"):
    # Monotonic 64-bit microsecond timestamp + 64-bit cryptographic entropy
    now_us = int(time.time() * 1_000_000)
    rand_hex = uuid.uuid4().hex[:12]
    return f"{prefix}_{now_us}_{rand_hex}"

def emit_intent(intent_name, description="", caller="antigravity_agent", db_path=None):
    trace_id = generate_monotonic_trace_id()
    span_id = f"span_intent_{uuid.uuid4().hex[:8]}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    active_db = db_path or os.environ.get("AIR10_AUDIT_DB", DB_PATH)
    
    details = {
        "intent": intent_name,
        "description": description,
        "caller": caller,
        "root_pid": os.getpid(),
    }
    payload_raw = json.dumps(details, sort_keys=True).encode("utf-8")
    payload_sha256 = hashlib.sha256(payload_raw).hexdigest()

    if os.path.exists(active_db):
        conn = sqlite3.connect(active_db)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO trace_events 
            (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
            VALUES (?, ?, 'ROOT_SPAN', 'INTENT', ?, ?, ?, 'INITIATED', ?)
        """, (trace_id, span_id, caller, now_iso, payload_sha256, json.dumps(details)))
        conn.commit()
        conn.close()

    print(f"{trace_id}|{span_id}")
    return trace_id, span_id

def record_intent(trace_id, intent, description="", caller="antigravity_agent", db_path=None):
    span_id = f"span_intent_{uuid.uuid4().hex[:8]}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    active_db = db_path or os.environ.get("AIR10_AUDIT_DB", DB_PATH)
    
    details = {
        "intent": intent,
        "description": description,
        "caller": caller,
        "root_pid": os.getpid(),
    }
    payload_raw = json.dumps(details, sort_keys=True).encode("utf-8")
    payload_sha256 = hashlib.sha256(payload_raw).hexdigest()

    if os.path.exists(active_db):
        conn = sqlite3.connect(active_db)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO trace_events 
            (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
            VALUES (?, ?, 'ROOT_SPAN', 'INTENT', ?, ?, ?, 'INITIATED', ?)
        """, (trace_id, span_id, caller, now_iso, payload_sha256, json.dumps(details)))
        conn.commit()
        conn.close()

    return span_id

if __name__ == "__main__":
    intent = sys.argv[1] if len(sys.argv) > 1 else "CANONICAL_JSON_PARSE_RFC8259"
    desc = sys.argv[2] if len(sys.argv) > 2 else "Parse and validate JSON payload according to RFC 8259 strict contract"
    emit_intent(intent, desc)
