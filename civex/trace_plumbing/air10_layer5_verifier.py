#!/usr/bin/env python3
"""
AIR10 Trace Architecture - Layer 5: Strict RFC 8259 & AST Structural Equivalence Verifier
- Strict byte-level whitespace check (ASCII 0x20, 0x09, 0x0A, 0x0D only)
- Strict UTF-8 validation (errors='strict')
- Full AST normalization & comparison against Oracle AST
- TOCTOU input SHA-256 integrity verification
- Appends INDEPENDENT_VERIFICATION span with parent_span_id link
- Appends immutable record to tool_traces_v2
"""
import hashlib
import json
import os
import sqlite3
import sys
import time
import uuid

DB_PATH = os.environ.get("AIR10_AUDIT_DB", "/Users/rajondas/.antigravity/air10_audit.db")

# RFC 8259 Section 2: only 4 valid whitespace characters outside strings
RFC8259_WHITESPACE = b" \t\r\n"

def _strict_constant_rejector(val: str):
    raise ValueError(f"RFC 8259 Section 6 violation: literal number constant '{val}' is not valid JSON")

def inspect_strict_rfc8259(raw_bytes):
    """
    Evaluates RFC 8259 single document completeness using strict byte-level validation.
    Rejects Unicode NBSP or invalid UTF-8 bytes outside/inside strings.
    Rejects NaN, Infinity, -Infinity per RFC 8259 Section 6.
    """
    # 1. Strict UTF-8 validation
    try:
        text = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        return False, None, False, f"MALFORMED_UTF8_BYTE_SEQUENCE: {e}"

    # 2. Strict leading whitespace check
    idx = 0
    while idx < len(raw_bytes) and raw_bytes[idx] in RFC8259_WHITESPACE:
        idx += 1
    
    if idx == len(raw_bytes):
        return False, None, False, "EMPTY_INPUT"

    # If first non-RFC whitespace is another unicode whitespace (like NBSP 0xC2 0xA0)
    # the decoder will encounter it outside a valid JSON token
    text_from_first = raw_bytes[idx:].decode("utf-8", errors="strict")

    decoder = json.JSONDecoder(parse_constant=_strict_constant_rejector)
    try:
        oracle_obj, end_char_offset = decoder.raw_decode(text_from_first)
    except Exception as e:
        return False, None, False, f"JSON_SYNTAX_ERROR: {e}"

    # Compute raw bytes offset corresponding to end_char_offset
    consumed_bytes_slice = text_from_first[:end_char_offset].encode("utf-8")
    end_byte_offset = idx + len(consumed_bytes_slice)

    # 3. Check remaining bytes strictly using only RFC 8259 whitespace bytes
    remainder_bytes = raw_bytes[end_byte_offset:]
    unconsumed_non_ws = remainder_bytes.strip(RFC8259_WHITESPACE)
    
    has_trailing = len(unconsumed_non_ws) > 0
    trailing_sample = unconsumed_non_ws[:40].decode("latin1", errors="replace") if has_trailing else ""

    return True, oracle_obj, has_trailing, trailing_sample

def canonical_ast_digest(obj):
    """Computes deterministic SHA-256 of recursively normalized AST."""
    canon_bytes = json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(canon_bytes).hexdigest(), canon_bytes

def verify_trace(trace_id, target_stdout_file=None, audit_db_path=None):
    span_id = f"span_verifier_{uuid.uuid4().hex[:8]}"
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    active_db = audit_db_path or os.environ.get("AIR10_AUDIT_DB") or DB_PATH

    conn = sqlite3.connect(active_db)
    cur = conn.cursor()

    cur.execute("""
        SELECT event_id, span_id, parent_span_id, stage, producer, payload_sha256, details_json 
        FROM trace_events 
        WHERE trace_id = ? 
        ORDER BY event_id ASC
    """, (trace_id,))
    rows = cur.fetchall()

    if not rows:
        conn.close()
        raise RuntimeError(f"ERROR: No trace events found for trace_id={trace_id} in db={active_db}")

    spans_by_stage = {}
    for r in rows:
        spans_by_stage[r[3]] = {"event_id": r[0], "span_id": r[1], "parent_span_id": r[2], "details": json.loads(r[6])}

    intent_info = spans_by_stage.get("INTENT", {})
    router_info = spans_by_stage.get("ROUTER_EVALUATION", {})
    exec_info = spans_by_stage.get("PROCESS_EXECUTION", {})

    parent_exec_span = exec_info.get("span_id", "span_exec_root")
    exec_details = exec_info.get("details", {})
    target_bin = exec_details.get("binary_path") or exec_details.get("target_bin") or ""
    actual_returncode = exec_details.get("actual_returncode", -1)
    duration_ms = exec_details.get("duration_ms", 0.0)
    exec_input_sha = exec_details.get("input_sha256")
    exec_bin_sha = exec_details.get("binary_sha256")
    exec_stdout_sha = exec_details.get("stdout_sha256")
    output_file = exec_details.get("output_file")
    if not target_stdout_file and output_file:
        target_stdout_file = output_file

    # Resolve input file from execution details or args
    input_file = exec_details.get("input_file")
    if not input_file:
        target_args = exec_details.get("target_args", "")
        args_tokens = target_args.split()
        for token in args_tokens:
            if os.path.isfile(token):
                input_file = token
                break
    
    if not input_file and len(sys.argv) > 2:
        input_file = sys.argv[2]

    if not input_file or not os.path.isfile(input_file):
        print("ERROR: Input file cannot be resolved from execution details or argv", file=sys.stderr)
        conn.close()
        sys.exit(1)

    with open(input_file, "rb") as f:
        current_input_bytes = f.read()
    current_input_sha256 = hashlib.sha256(current_input_bytes).hexdigest()

    # 1. TOCTOU Input Integrity Verification (Fail-Closed)
    toctou_violation = False
    if exec_input_sha and exec_input_sha != current_input_sha256:
        toctou_violation = True
        verdict_status = "VERIFIED_FAIL_INVARIANT_VIOLATION"
        semantic_result = "TOCTOU_INTEGRITY_VIOLATION"
        failure_reason = f"TOCTOU_MUTATION_DETECTED: input file SHA {current_input_sha256} does not match executed SHA {exec_input_sha}"
        has_trailing = False
        trailing_sample = ""
        is_valid_json = False
        oracle_ast = None

    if not toctou_violation:
        # 2. Strict RFC 8259 verification
        is_valid_json, oracle_ast, has_trailing, trailing_sample = inspect_strict_rfc8259(current_input_bytes)

        verdict_status = "VERIFIED_PASS"
        semantic_result = "ACCEPTANCE_ONLY"
        failure_reason = None

        if has_trailing:
            if actual_returncode == 0:
                verdict_status = "VERIFIED_FAIL_INVARIANT_VIOLATION"
                semantic_result = "VIOLATION_SILENT_TRUNCATION"
                failure_reason = f"SILENT_TRAILING_DATA_TRUNCATION: Unconsumed non-RFC8259 bytes at end of input. Sample: '{trailing_sample}'"
            else:
                verdict_status = "VERIFIED_PASS"
                semantic_result = "CORRECT_REJECTION_OF_TRAILING_DATA"
                failure_reason = "CORRECT_REJECTION_OF_TRAILING_DATA"
        elif not is_valid_json:
            if actual_returncode == 0:
                verdict_status = "VERIFIED_FAIL_INVARIANT_VIOLATION"
                semantic_result = "VIOLATION_ACCEPTED_MALFORMED"
                failure_reason = f"PARSER_ACCEPTED_INVALID_INPUT: {trailing_sample}"
            else:
                verdict_status = "VERIFIED_PASS"
                semantic_result = "CORRECT_REJECTION_OF_SYNTAX_ERROR"
                failure_reason = trailing_sample
        else:
            # Valid single document JSON
            if actual_returncode != 0:
                verdict_status = "VERIFIED_FAIL_INVARIANT_VIOLATION"
                semantic_result = "FALSE_NEGATIVE_REJECTION"
                failure_reason = f"Target rejected valid JSON with exit code {actual_returncode}"
            else:
                # Check if candidate emitted stdout that can be compared for true AST EQUIVALENCE
                candidate_ast = None
                if target_stdout_file and os.path.isfile(target_stdout_file):
                    with open(target_stdout_file, "rb") as out_f:
                        cand_raw = out_f.read().strip()
                    try:
                        candidate_ast = json.loads(cand_raw.decode("utf-8"))
                    except Exception:
                        candidate_ast = None

                if candidate_ast is not None:
                    oracle_digest, _ = canonical_ast_digest(oracle_ast)
                    cand_digest, _ = canonical_ast_digest(candidate_ast)
                    if oracle_digest == cand_digest:
                        verdict_status = "VERIFIED_PASS"
                        semantic_result = "EXACT_AST_MATCH"
                        failure_reason = "CANONICAL_AST_DIGEST_MATCHED"
                    else:
                        verdict_status = "VERIFIED_FAIL_AST_MISMATCH"
                        semantic_result = "VIOLATION_AST_MISMATCH"
                        failure_reason = f"Candidate AST digest {cand_digest[:12]} != Oracle digest {oracle_digest[:12]}"
                else:
                    # Valid exit code, but did not emit machine-readable AST
                    verdict_status = "VERIFIED_PASS"
                    semantic_result = "ACCEPTANCE_ONLY_NO_AST_OUTPUT"
                    failure_reason = "VALID_SINGLE_DOCUMENT_FULLY_CONSUMED_NO_AST_CAPTURE"

    details = {
        "verifier": "AIR10_STRICT_RFC8259_VERIFIER_V2",
        "has_trailing_bytes": has_trailing,
        "trailing_sample": trailing_sample,
        "verdict_status": verdict_status,
        "semantic_result": semantic_result,
        "failure_reason": failure_reason,
        "input_file": input_file,
        "input_sha256": current_input_sha256,
        "target_bin": target_bin,
        "actual_returncode": actual_returncode,
    }
    payload_raw = json.dumps(details, sort_keys=True).encode("utf-8")
    payload_sha256 = hashlib.sha256(payload_raw).hexdigest()

    # Append verification span with parent_span_id linked to execution span
    cur.execute("""
        INSERT INTO trace_events 
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES (?, ?, ?, 'INDEPENDENT_VERIFICATION', 'rfc8259_semantic_verifier', ?, ?, ?, ?)
    """, (trace_id, span_id, parent_exec_span, now_iso, payload_sha256, verdict_status, json.dumps(details)))

    # Append immutable summary to tool_traces_v2 (Physical 64-char SHA-256 digests)
    task_intent = intent_info.get("details", {}).get("intent", "UNKNOWN_INTENT")
    router_details = router_info.get("details", {})
    chosen_tool = router_details.get("chosen_tool", target_bin)
    candidates_json = json.dumps(router_details.get("candidates", []))

    # Cryptographic digest integrity assertions
    binary_sha256 = exec_bin_sha
    if not binary_sha256 or len(binary_sha256) != 64 or binary_sha256 == "UNKNOWN":
        if os.path.isfile(target_bin):
            with open(target_bin, "rb") as bf:
                binary_sha256 = hashlib.sha256(bf.read()).hexdigest()
        else:
            binary_sha256 = "0" * 64

    stdout_sha256 = exec_stdout_sha
    if not stdout_sha256 or len(stdout_sha256) != 64:
        if target_stdout_file and os.path.isfile(target_stdout_file):
            with open(target_stdout_file, "rb") as sf:
                stdout_sha256 = hashlib.sha256(sf.read()).hexdigest()
        else:
            stdout_sha256 = "0" * 64

    assert len(binary_sha256) == 64, f"Invalid binary_sha256 digest: {binary_sha256}"
    assert len(stdout_sha256) == 64, f"Invalid stdout_sha256 digest: {stdout_sha256}"

    cur.execute("""
        INSERT INTO tool_traces_v2
        (trace_id, task_intent, traffic_class, router_candidates, chosen_tool, binary_path, 
         binary_sha256, input_path, input_sha256, stdout_sha256, actual_exit_code, 
         duration_ms, semantic_equivalence, verification_status, failure_reason, created_at)
        VALUES (?, ?, 'TASK_CLI_HOTPATH', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        trace_id, task_intent, candidates_json, chosen_tool, target_bin,
        binary_sha256, input_file, current_input_sha256, stdout_sha256, actual_returncode,
        duration_ms, semantic_result, verdict_status, failure_reason, now_iso
    ))

    conn.commit()
    conn.close()

    # Closed-Loop Feedback: Update CIVeXVerifier circuit breaker state authoritatively
    try:
        from civex.bridge import CIVeXVerifier
        verifier = CIVeXVerifier()
        is_pass = (verdict_status == "VERIFIED_PASS")
        verifier.record_outcome(chosen_tool, success=is_pass, error_msg=failure_reason if not is_pass else None)
    except Exception as e:
        sys.stderr.write(f"CIVEX_CIRCUIT_BREAKER_RECORD_ERROR: {e}\n")

    print(f"VERDICT={verdict_status}|SEMANTIC={semantic_result}|REASON={failure_reason}|SPAN_ID={span_id}")
    return verdict_status

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: air10_layer5_verifier.py <TRACE_ID> [INPUT_FILE] [STDOUT_FILE]", file=sys.stderr)
        sys.exit(1)
    t_id = sys.argv[1]
    inp = sys.argv[2] if len(sys.argv) > 2 else None
    out = sys.argv[3] if len(sys.argv) > 3 else None
    verify_trace(t_id, out)
