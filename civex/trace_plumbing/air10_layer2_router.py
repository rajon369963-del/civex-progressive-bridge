#!/usr/bin/env python3
"""
AIR10 Trace Architecture - Layer 2: Closed-Loop Router with CourtAwareRanker Integration
Single Canonical Judiciary: Consumes CourtAwareRanker directly, enforces contract verdicts,
rejects quarantined/unverified tools, and logs ROUTER_EVALUATION span with explicit parent_span_id.
"""
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid

# Portable DB path
DB_PATH = os.environ.get("AIR10_AUDIT_DB", "/Users/rajondas/.antigravity/air10_audit.db")

def route_intent(trace_id, parent_span_id, intent_query, required_capability="JSON_SINGLE_DOC_STRICT", input_format="SINGLE_DOC_STRICT_RFC8259", contract_version="v1.0", candidates_override=None, db_path=None):
    span_id = f"span_router_{uuid.uuid4().hex[:8]}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    active_db = db_path or DB_PATH

    # CHAKKA JODO: Import and consume single authoritative CourtAwareRanker
    try:
        from civex.bridge import CIVeXVerifier
        from civex.court_ranking import CourtAwareRanker
        verifier = CIVeXVerifier()
        ranker = CourtAwareRanker(audit_db_path=active_db, verifier=verifier)
    except Exception:
        # Standalone plumbing fallback
        try:
            from court_ranking import CourtAwareRanker
            ranker = CourtAwareRanker(audit_db_path=active_db)
        except Exception:
            ranker = None

    # 1. Zero-Fork In-Process Dispatch (§3) with CLI and heuristic fallback
    trigger_cmd = os.environ.get("AIR10_AUTO_TRIGGER_BIN", "/Users/rajondas/.local/bin/air10-auto-trigger")
    candidates = []
    if candidates_override is not None:
        candidates = list(candidates_override)
    else:
        # Zero-fork in-process dispatch via air1_trigger (<200us)
        try:
            import air1_trigger
            res_dict = air1_trigger.run(intent_query, limit=5, return_dict=True)
            if res_dict and res_dict.get("status") == "MATCH_FOUND" and res_dict.get("name"):
                candidates.append({
                    "name": res_dict["name"],
                    "binary": res_dict.get("binary_path") or f"/Users/rajondas/.local/bin/{res_dict['name']}",
                    "raw_header": f"[1] {res_dict['name']} | score 1.0",
                    "command": res_dict.get("resolved_cmd")
                })
        except Exception:
            pass

        # Fallback to physical air10-auto-trigger binary if in-process yielded no candidates
        if not candidates and os.path.isfile(trigger_cmd) and os.access(trigger_cmd, os.X_OK):
            res = subprocess.run([trigger_cmd, intent_query], capture_output=True, text=True)
            lines = res.stdout.splitlines()
            current_cand = None
            for line in lines:
                if line.startswith("[") and "] " in line:
                    parts = line.split("] ")
                    cand_name = parts[1].split(" | ")[0].strip()
                    current_cand = {"name": cand_name, "raw_header": line.strip()}
                    candidates.append(current_cand)
                elif current_cand and "Binary" in line and ":" in line:
                    current_cand["binary"] = line.split(":", 1)[1].strip()
                elif current_cand and "Command" in line and ":" in line:
                    current_cand["command"] = line.split(":", 1)[1].strip()

        # Default fallback candidate pool based on intent if still no candidates
        if not candidates:
            if "json" in intent_query.lower():
                candidates = [
                    {"name": "air10-fast-json", "binary": "/Users/rajondas/.local/bin/air10-fast-json"},
                    {"name": "air10-orjson-tool", "binary": "/Users/rajondas/.local/bin/air10-orjson-tool"}
                ]
            else:
                candidates = [
                    {"name": "git-commit-helper", "binary": "/usr/bin/git"}
                ]

    # 2. Evaluate candidate tools via CourtAwareRanker
    evaluations = []
    chosen_tool = None
    chosen_binary = None
    selection_rationale = None

    if ranker is not None:
        scored_candidates = []
        for cand in candidates:
            c_name = cand.get("name")
            c_bin = cand.get("binary")
            score_breakdown = ranker.score_tool(
                tool_name=c_name,
                capability=required_capability,
                input_format=input_format,
                contract_version=contract_version,
                binary_path=c_bin
            )
            eval_entry = {
                "candidate": c_name,
                "capability": required_capability,
                "input_format": input_format,
                "contract_version": contract_version,
                "status": score_breakdown.status,
                "score": score_breakdown.final_score,
                "rationale": score_breakdown.rationale,
                "superseded_by": score_breakdown.superseded_by
            }
            evaluations.append(eval_entry)
            if score_breakdown.status == "ELIGIBLE" and score_breakdown.final_score > 0.0:
                scored_candidates.append((score_breakdown.final_score, cand, score_breakdown))

        # Select highest-scoring eligible candidate
        if scored_candidates:
            scored_candidates.sort(key=lambda x: x[0], reverse=True)
            best_score, best_cand, best_breakdown = scored_candidates[0]
            chosen_tool = best_cand["name"]
            chosen_binary = best_cand["binary"]
            selection_rationale = f"COURT_VERIFIED_ROUTING: Selected {chosen_tool} with score {best_score:.4f} ({best_breakdown.rationale})"
        else:
            # Dynamic superseded_by resolution (Zero synthetic constants, pure Court contract truth)
            for ev in evaluations:
                sup_tool = ev.get("superseded_by")
                if ev.get("status") == "QUARANTINED" and sup_tool:
                    sup_bin = None
                    for cand in candidates:
                        if cand.get("name") == sup_tool:
                            sup_bin = cand.get("binary")
                            break
                    if not sup_bin and os.path.exists(DB_PATH):
                        try:
                            conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
                            cur = conn.cursor()
                            cur.execute(
                                "SELECT binary_path FROM tool_contract_verdicts_v2 WHERE tool_name = ? AND binary_path IS NOT NULL LIMIT 1;",
                                (sup_tool,)
                            )
                            brow = cur.fetchone()
                            if brow and brow[0]:
                                sup_bin = brow[0]
                            conn.close()
                        except Exception:
                            pass
                    if not sup_bin:
                        sup_bin = shutil.which(sup_tool) or f"/Users/rajondas/.local/bin/{sup_tool}"

                    # Strict empirical scoring path with canonical tool_id
                    sup_score = ranker.score_tool(
                        tool_name=sup_tool,
                        capability=required_capability,
                        input_format=input_format,
                        contract_version=contract_version,
                        binary_path=sup_bin,
                        tool_id=sup_tool
                    )
                    evaluations.append({
                        "candidate": sup_tool,
                        "capability": required_capability,
                        "input_format": input_format,
                        "contract_version": contract_version,
                        "status": sup_score.status,
                        "score": sup_score.final_score,
                        "rationale": sup_score.rationale,
                        "superseded_by": sup_score.superseded_by
                    })
                    if sup_score.status == "ELIGIBLE" and sup_score.final_score > 0.0:
                        chosen_tool = sup_tool
                        chosen_binary = sup_bin
                        selection_rationale = f"ENFORCED_FALLBACK: Candidate quarantined. Routed to verified supersede: {chosen_tool} (score {sup_score.final_score:.4f})."
                        break

    # STRICT FAIL-CLOSED INVARIANT: NO FALLBACK_UNRANKED!
    permit = None
    if not chosen_tool:
        chosen_tool = None
        chosen_binary = None
        selection_rationale = "NO_VERIFIED_TOOL_AVAILABLE: All candidate tools held, quarantined, or unverified by Court"
    else:
        # Issue CourtExecutionPermit bound to exact Court contract verdict
        approved_sha = ""
        if 'best_breakdown' in locals() and best_breakdown and best_breakdown.binary_sha256:
            approved_sha = best_breakdown.binary_sha256
        elif 'sup_score' in locals() and sup_score and sup_score.binary_sha256:
            approved_sha = sup_score.binary_sha256

        if not approved_sha and os.path.exists(active_db):
            try:
                conn = sqlite3.connect(f"file:{active_db}?mode=ro", uri=True)
                cur = conn.cursor()
                cur.execute(
                    "SELECT binary_sha256 FROM tool_contract_verdicts_v2 WHERE tool_name = ? AND capability = ? AND status = 'ALLOWED' LIMIT 1",
                    (chosen_tool, required_capability)
                )
                r = cur.fetchone()
                if r and r[0]:
                    approved_sha = r[0]
                conn.close()
            except Exception:
                pass

        try:
            from civex.court_ranking import CourtExecutionPermit
        except Exception:
            from court_ranking import CourtExecutionPermit

        permit = CourtExecutionPermit.issue(
            tool_name=chosen_tool,
            capability=required_capability,
            input_format=input_format,
            contract_version=contract_version,
            binary_path=chosen_binary,
            approved_sha=approved_sha,
        )

    # 3. Correlation payload & hash
    details = {
        "intent_query": intent_query,
        "required_capability": required_capability,
        "input_format": input_format,
        "contract_version": contract_version,
        "candidate_evaluations": evaluations,
        "chosen_tool": chosen_tool,
        "chosen_binary": chosen_binary,
        "selection_rationale": selection_rationale,
        "parent_span_id": parent_span_id,
        "permit": permit.to_dict() if permit else None
    }
    payload_raw = json.dumps(details, sort_keys=True).encode("utf-8")
    payload_sha256 = hashlib.sha256(payload_raw).hexdigest()

    # 4. Insert ROUTER_EVALUATION span with explicit parent_span_id
    if os.path.exists(active_db):
        conn = sqlite3.connect(active_db)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO trace_events 
            (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
            VALUES (?, ?, ?, 'ROUTER_EVALUATION', 'civex-court-router', ?, ?, 'EVALUATED', ?)
        """, (trace_id, span_id, parent_span_id, now_iso, payload_sha256, json.dumps(details)))
        conn.commit()
        conn.close()

    print(f"CHOSEN_TOOL={chosen_tool}|CHOSEN_BINARY={chosen_binary}|SPAN_ID={span_id}")
    return RouteResult(chosen_tool, chosen_binary, span_id, permit=permit)


class RouteResult(tuple):
    """3-tuple subclass: (chosen_tool, chosen_binary, span_id) that also provides .permit attribute."""
    def __new__(cls, chosen_tool, chosen_binary, span_id, permit=None):
        inst = super().__new__(cls, (chosen_tool, chosen_binary, span_id))
        inst.chosen_tool = chosen_tool
        inst.chosen_binary = chosen_binary
        inst.span_id = span_id
        inst.permit = permit
        return inst


def record_routing(trace_id, parent_span_id, chosen_tool, candidates=None, db_path=None):
    span_id = f"span_router_{uuid.uuid4().hex[:8]}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    active_db = db_path or os.environ.get("AIR10_AUDIT_DB", DB_PATH)
    details = {
        "chosen_tool": chosen_tool,
        "candidates": candidates or [],
        "routing_engine": "record_routing",
    }
    payload_raw = json.dumps(details, sort_keys=True).encode("utf-8")
    payload_sha256 = hashlib.sha256(payload_raw).hexdigest()

    if os.path.exists(active_db):
        conn = sqlite3.connect(active_db)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO trace_events 
            (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
            VALUES (?, ?, ?, 'ROUTER_EVALUATION', 'civex-court-router', ?, ?, 'EVALUATED', ?)
        """, (trace_id, span_id, parent_span_id, now_iso, payload_sha256, json.dumps(details)))
        conn.commit()
        conn.close()

    return span_id

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: air10_layer2_router.py <TRACE_ID> <PARENT_SPAN_ID> <INTENT_QUERY> [CAPABILITY] [INPUT_FORMAT] [CONTRACT_VERSION]", file=sys.stderr)
        sys.exit(1)
    trace_id = sys.argv[1]
    parent = sys.argv[2]
    intent = sys.argv[3]
    cap = sys.argv[4] if len(sys.argv) > 4 else "JSON_SINGLE_DOC_STRICT"
    fmt = sys.argv[5] if len(sys.argv) > 5 else "SINGLE_DOC_STRICT_RFC8259"
    ver = sys.argv[6] if len(sys.argv) > 6 else "v1.0"
    route_intent(trace_id, parent, intent, cap, fmt, ver)
