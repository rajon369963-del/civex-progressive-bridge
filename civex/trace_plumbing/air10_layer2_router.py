#!/usr/bin/env python3
"""
AIR10 Trace Architecture - Layer 2: Closed-Loop Router with Capability Quarantine Enforcement
Reads candidates from air10-auto-trigger, consults tool_capability_quarantine table,
rejects disqualified tools, and logs ROUTER_EVALUATION span with explicit parent_span_id.
"""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
import uuid

DB_PATH = "/Users/rajondas/.antigravity/air10_audit.db"

def route_intent(trace_id, parent_span_id, intent_query, required_capability="JSON_SINGLE_DOC_STRICT", input_format="SINGLE_DOC_STRICT_RFC8259", contract_version="v1.0"):
    span_id = f"span_router_{uuid.uuid4().hex[:8]}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # 1. Check Contract-Scoped Quarantine Registry in SQLite
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT tool_name, capability, input_format, contract_version, status, reason, superseded_by 
        FROM tool_capability_quarantine
    """)
    quarantine_rows = cur.fetchall()
    quarantine_map = {f"{r[0]}:{r[1]}:{r[2]}:{r[3]}": r for r in quarantine_rows}
    # Also map (tool, capability) for fallback lookup
    tool_cap_map = {f"{r[0]}:{r[1]}": r for r in quarantine_rows}

    # 2. Run physical air10-auto-trigger
    res = subprocess.run(
        ["/Users/rajondas/.local/bin/air10-auto-trigger", intent_query],
        capture_output=True, text=True
    )
    trigger_out = res.stdout

    # Parse candidates
    candidates = []
    lines = trigger_out.splitlines()
    current_cand = None
    for line in lines:
        if line.startswith("[") and "] " in line:
            parts = line.split("] ")
            cand_name = parts[1].split(" | ")[0]
            current_cand = {"name": cand_name, "raw_header": line.strip()}
            candidates.append(current_cand)
        elif current_cand and "Binary" in line and ":" in line:
            current_cand["binary"] = line.split(":", 1)[1].strip()
        elif current_cand and "Command" in line and ":" in line:
            current_cand["command"] = line.split(":", 1)[1].strip()

    # Evaluate candidate tools against contract-scoped quarantine registry
    quarantine_evaluations = []
    chosen_tool = None
    chosen_binary = None
    selection_rationale = None

    # Check candidate A: air10-fast-json
    scoped_key = f"air10-fast-json:{required_capability}:{input_format}:{contract_version}"
    q_info = quarantine_map.get(scoped_key) or tool_cap_map.get(f"air10-fast-json:{required_capability}")

    if q_info:
        q_status = q_info[4]
        q_reason = q_info[5]
        q_superseded = q_info[6]
        quarantine_evaluations.append({
            "candidate": "air10-fast-json",
            "capability": required_capability,
            "input_format": input_format,
            "contract_version": contract_version,
            "decision": q_status,
            "reason": q_reason,
            "superseded_by": q_superseded
        })
    else:
        q_status = "ALLOWED"

    # Contract-Scoped Decision Logic
    if "json" in intent_query.lower():
        if q_status == "QUARANTINED":
            # CLOSED-LOOP ENFORCEMENT: Fallback to court-certified Python orjson / jq
            chosen_tool = q_info[6] if q_info and q_info[6] else "python_orjson_cli"
            chosen_binary = "/Users/rajondas/.local/bin/air10-orjson-tool"
            selection_rationale = (
                f"ENFORCED_FALLBACK: air10-fast-json is QUARANTINED for ({required_capability}, {input_format}, {contract_version}). "
                f"Routed to certified alternative: {chosen_tool}."
            )
        elif q_status == "ALLOWED_WITH_WARNING":
            chosen_tool = "air10-fast-json"
            chosen_binary = "/Users/rajondas/.local/bin/air10-fast-json"
            selection_rationale = (
                f"ALLOWED_WITH_WARNING: ({required_capability}, {input_format}, {contract_version}) - {q_info[5]}"
            )
        else:
            chosen_tool = "air10-fast-json"
            chosen_binary = "/Users/rajondas/.local/bin/air10-fast-json"
            selection_rationale = f"Candidate cleared contract-scoped verification for {required_capability}."
    else:
        chosen_tool = candidates[0]["name"] if candidates else "default_cli"
        chosen_binary = candidates[0].get("binary", "") if candidates else ""
        selection_rationale = "Selected top ranked candidate."

    details = {
        "intent_query": intent_query,
        "required_capability": required_capability,
        "quarantine_evaluations": quarantine_evaluations,
        "chosen_tool": chosen_tool,
        "chosen_binary": chosen_binary,
        "selection_rationale": selection_rationale,
        "parent_span_id": parent_span_id,
        "pid": os.getpid(),
    }
    payload_raw = json.dumps(details, sort_keys=True).encode("utf-8")
    payload_sha256 = hashlib.sha256(payload_raw).hexdigest()

    cur.execute("""
        INSERT INTO trace_events 
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES (?, ?, ?, 'ROUTER_EVALUATION', 'air10-auto-trigger', ?, ?, 'ROUTED', ?)
    """, (trace_id, span_id, parent_span_id, now_iso, payload_sha256, json.dumps(details)))
    conn.commit()
    conn.close()

    print(f"{chosen_tool}|{chosen_binary}|{span_id}|{selection_rationale}")
    return chosen_tool, chosen_binary, span_id

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: air10_layer2_router.py <TRACE_ID> <PARENT_SPAN_ID> <INTENT_QUERY> [CAPABILITY]", file=sys.stderr)
        sys.exit(1)
    trace_id = sys.argv[1]
    parent_span = sys.argv[2]
    query = sys.argv[3]
    cap = sys.argv[4] if len(sys.argv) > 4 else "JSON_SINGLE_DOC_STRICT"
    route_intent(trace_id, parent_span, query, cap)
