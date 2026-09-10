#!/usr/bin/env python3
"""
AIR10 Trace Architecture - Strict Fail-Closed Mathematical Causal DAG Validator
Enforces 7 Invariants (Zero Warnings, Zero Assert statements, Strict Exit 1 on Any Violation):
1. ROOT_COUNT == 1
2. Referential integrity: parent_span_id exists in same trace
3. Acyclicity: DFS cycle detection (NO_CYCLES == True)
4. Connectedness: NO_ORPHANS == True (all nodes reachable from root)
5. Strict Stage Sequence & Direct Causal Edges:
   INTENT -> ROUTER_EVALUATION -> SHIM_INTERCEPT -> PROCESS_EXECUTION -> INDEPENDENT_VERIFICATION
6. Unique span IDs (no duplicates)
7. Exact field-for-field disk correlation with shim_intercept.log
8. Durable presence of tool_traces_v2 summary record
"""
import sys, os, sqlite3, json, re
from pathlib import Path

DB_PATH = str(Path.home() / ".antigravity" / "air10_audit.db")
SHIM_LOG = str(Path.home() / ".antigravity" / "shim_intercept.log")

EXPECTED_STAGES = ["INTENT", "ROUTER_EVALUATION", "SHIM_INTERCEPT", "PROCESS_EXECUTION", "INDEPENDENT_VERIFICATION"]

def fatal_violation(msg):
    print(f"❌ INVARIANT VIOLATION: {msg}", file=sys.stderr)
    sys.exit(1)

def validate_and_readback(trace_id, db_path=None, shim_log=None):
    active_db = db_path or DB_PATH
    active_shim = shim_log or SHIM_LOG

    if not os.path.exists(active_db):
        fatal_violation(f"Database not found at {active_db}")

    conn = sqlite3.connect(active_db)
    cur = conn.cursor()

    cur.execute("""
        SELECT event_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json
        FROM trace_events
        WHERE trace_id = ?
        ORDER BY event_id ASC
    """, (trace_id,))
    events = cur.fetchall()

    cur.execute("""
        SELECT trace_id, task_intent, chosen_tool, binary_path, actual_exit_code, 
               duration_ms, semantic_equivalence, verification_status, failure_reason, created_at
        FROM tool_traces_v2
        WHERE trace_id = ?
    """, (trace_id,))
    v2_row = cur.fetchone()
    conn.close()

    if not events:
        fatal_violation(f"No trace_events found for trace_id={trace_id}")

    # Invariant 8: Summary record MUST exist
    if not v2_row:
        fatal_violation(f"No tool_traces_v2 summary row found for trace_id={trace_id}! Trace is unsealed/orphaned!")

    print("=" * 95)
    print(f"🏛️ AIR10 STRICT FAIL-CLOSED CAUSAL DAG VALIDATION: {trace_id}")
    print("=" * 95)

    # Invariant 6: Unique Span IDs
    span_ids = [ev[1] for ev in events]
    if len(span_ids) != len(set(span_ids)):
        fatal_violation(f"Duplicate span_id detected! Total: {len(span_ids)}, Unique: {len(set(span_ids))}")
    span_set = set(span_ids)
    print(f"  [1] UNIQUE_SPANS == True                  : ✅ PASS ({len(span_ids)} unique spans)")

    # Build Adjacency List & Validate Referential Integrity
    root_spans = []
    children_by_parent = {}
    parent_by_child = {}
    event_by_span = {}
    event_by_stage = {}

    for ev in events:
        eid, sid, parent_sid, stage, prod, ts, p_sha, status, details_str = ev
        event_by_span[sid] = ev
        event_by_stage[stage] = ev

        if parent_sid == "ROOT_SPAN" or parent_sid is None or parent_sid == "NULL":
            root_spans.append(sid)
        else:
            if parent_sid not in span_set:
                fatal_violation(f"Broken parent reference! Child span '{sid}' points to non-existent parent '{parent_sid}'")
            parent_by_child[sid] = parent_sid
            children_by_parent.setdefault(parent_sid, []).append(sid)

    # Invariant 1: Exactly 1 Root Span
    if len(root_spans) != 1:
        fatal_violation(f"ROOT_COUNT == 1 violated! Expected 1, found {len(root_spans)}: {root_spans}")
    root_span = root_spans[0]
    print(f"  [2] ROOT_COUNT == 1                       : ✅ PASS (Root: {root_span})")

    # Invariant 3: Cycle Detection via DFS
    visited = set()
    rec_stack = set()
    has_cycle = False

    def dfs(u):
        nonlocal has_cycle
        visited.add(u)
        rec_stack.add(u)
        for v in children_by_parent.get(u, []):
            if v not in visited:
                dfs(v)
            elif v in rec_stack:
                has_cycle = True
        rec_stack.remove(u)

    dfs(root_span)

    if has_cycle:
        fatal_violation("Cycle detected in causal span graph!")
    print("  [3] NO_CYCLES == True                     : ✅ PASS (Acyclic Directed Graph)")

    # Invariant 4: No Orphans (all nodes reachable from root)
    if len(visited) != len(span_ids):
        orphans = span_set - visited
        fatal_violation(f"Orphan spans detected! Nodes not reachable from root: {orphans}")
    print(f"  [4] NO_ORPHANS == True                    : ✅ PASS (All {len(visited)} spans reachable from root)")

    # Invariant 5A: Strict Stage Sequence Order (FAIL-CLOSED, NO WARNINGS!)
    stages_in_order = [ev[3] for ev in events]
    if stages_in_order != EXPECTED_STAGES:
        fatal_violation(f"STAGE_ORDER mismatch! Received {stages_in_order} != Expected {EXPECTED_STAGES}")
    print("  [5] STAGE_ORDER == INTENT->ROUTER->SHIM->EXEC->VERIF : ✅ PASS")

    # Invariant 5B: Strict Linear Causal Edge Verification (INTENT -> ROUTER -> SHIM -> EXEC -> VERIFIER)
    # Check direct parent-child edges between stages
    stage_sequence = [
        ("INTENT", None),
        ("ROUTER_EVALUATION", "INTENT"),
        ("SHIM_INTERCEPT", "ROUTER_EVALUATION"),
        ("PROCESS_EXECUTION", "SHIM_INTERCEPT"),
        ("INDEPENDENT_VERIFICATION", "PROCESS_EXECUTION")
    ]
    for child_stage, exp_parent_stage in stage_sequence:
        child_ev = event_by_stage.get(child_stage)
        if not child_ev:
            fatal_violation(f"Missing expected stage: {child_stage}")
        child_sid = child_ev[1]
        actual_parent_sid = child_ev[2]

        if exp_parent_stage is None:
            if actual_parent_sid not in ("ROOT_SPAN", None, "NULL"):
                fatal_violation(f"Root stage {child_stage} ({child_sid}) has unexpected parent '{actual_parent_sid}'")
        else:
            exp_parent_ev = event_by_stage.get(exp_parent_stage)
            if not exp_parent_ev:
                fatal_violation(f"Missing parent stage {exp_parent_stage} for {child_stage}")
            exp_parent_sid = exp_parent_ev[1]
            if actual_parent_sid != exp_parent_sid:
                fatal_violation(f"CAUSAL_EDGE mismatch! Stage {child_stage} parent is '{actual_parent_sid}', expected {exp_parent_stage} ('{exp_parent_sid}')")

    print("  [6] DIRECT_CAUSAL_EDGES == True           : ✅ PASS (Strict linear unbranched dependency chain)")

    # Invariant 7: Structured Field-for-Field Correlation against shim_intercept.log
    shim_log_found = False
    shim_line_parsed = {}
    if os.path.isfile(active_shim):
        with open(active_shim, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if trace_id in line and "SHIM:air10-exec-boundary" in line:
                    shim_log_found = True
                    m = re.search(r"PID:(\d+)\s+TRACE:(\S+)\s+SPAN:(\S+)\s+PARENT:(\S+)\s+SHIM:(\S+)\s+BIN:(\S+)", line)
                    if m:
                        shim_line_parsed = {
                            "pid": int(m.group(1)),
                            "trace_id": m.group(2),
                            "span_id": m.group(3),
                            "parent_span_id": m.group(4),
                            "shim": m.group(5),
                            "bin": m.group(6),
                            "raw": line.strip()
                        }
                    break

    if not shim_log_found or not shim_line_parsed:
        fatal_violation(f"No structured air10-exec-boundary line found in {active_shim} for trace {trace_id}!")

    shim_ev = event_by_stage["SHIM_INTERCEPT"]
    router_ev = event_by_stage["ROUTER_EVALUATION"]
    db_shim_span = shim_ev[1]
    db_shim_parent = shim_ev[2]
    db_router_span = router_ev[1]
    db_shim_details = json.loads(shim_ev[8])
    db_parent_pid = db_shim_details.get("parent_pid")
    db_target_bin = db_shim_details.get("target_bin")

    # Strict explicit comparisons (NO assert statements!)
    if shim_line_parsed["trace_id"] != trace_id:
        fatal_violation(f"Shim log trace_id '{shim_line_parsed['trace_id']}' != expected '{trace_id}'")
    if shim_line_parsed["span_id"] != db_shim_span:
        fatal_violation(f"Shim log span_id '{shim_line_parsed['span_id']}' != DB '{db_shim_span}'")
    if shim_line_parsed["parent_span_id"] != db_router_span:
        fatal_violation(f"Shim log parent_span_id '{shim_line_parsed['parent_span_id']}' != DB router '{db_router_span}'")
    if shim_line_parsed["bin"] != db_target_bin:
        fatal_violation(f"Shim log target_bin '{shim_line_parsed['bin']}' != DB '{db_target_bin}'")
    if shim_line_parsed["pid"] != db_parent_pid:
        fatal_violation(f"Shim log PID '{shim_line_parsed['pid']}' != DB '{db_parent_pid}'")

    print(f"  [7] SHIM_LOG_EXACT_FIELD_CORRELATION      : ✅ PASS (Span, Parent, Bin, PID field-for-field verified)")

    print("\n[VERIFIED CAUSAL SPAN GRAPH]")
    print(f"{'Event':<6} | {'Stage':<24} | {'Producer':<22} | {'ParentSpan':<24} -> {'SpanID'}")
    print("-" * 95)
    for ev in events:
        eid, sid, parent_sid, stage, prod, ts, p_sha, status, details_str = ev
        det = json.loads(details_str)
        extra = ""
        if stage == "PROCESS_EXECUTION":
            extra = f" [ChildPID: {det.get('actual_child_pid')} | Exit: {det.get('actual_returncode')}]"
        elif stage == "INDEPENDENT_VERIFICATION":
            extra = f" [{status}: {det.get('semantic_result')}]"
        print(f"{eid:<6} | {stage:<24} | {prod:<22} | {str(parent_sid):<24} -> {sid}{extra}")

    print("\n[DISK SHIM LINE PROOF]")
    print(f"  {shim_line_parsed['raw']}")

    print("\n[IMMUTABLE TOOL TRACE V2 SUMMARY]")
    t_id, intent, tool, bin_p, code, dur, sem, status, reason, ts = v2_row
    print(f"  • Trace ID           : {t_id}")
    print(f"  • Intent             : {intent}")
    print(f"  • Chosen Tool        : {tool}")
    print(f"  • Actual Exit Code   : {code}")
    print(f"  • Duration           : {dur:.3f} ms")
    print(f"  • Semantic Result    : {sem}")
    print(f"  • Court Verdict      : {status}")
    print(f"  • Failure Reason     : {reason}")

    print("\n🏆 FINAL SEAL: MATHEMATICALLY_VALIDATED_CAUSAL_DAG_PASS")
    print("=" * 95)
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: air10_cross_trace_readback.py <TRACE_ID> [DB_PATH] [SHIM_LOG]", file=sys.stderr)
        sys.exit(1)
    db = sys.argv[2] if len(sys.argv) > 2 else None
    shim = sys.argv[3] if len(sys.argv) > 3 else None
    validate_and_readback(sys.argv[1], db, shim)