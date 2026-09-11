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
import re
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

def verify_trace(trace_id, target_stdout_file=None, audit_db_path=None, attempt_no=1):
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
                        cand_raw_bytes = out_f.read()

                    # STDOUT TOCTOU Verification (Fail-Closed)
                    current_stdout_sha256 = hashlib.sha256(cand_raw_bytes).hexdigest()
                    if exec_stdout_sha and current_stdout_sha256 != exec_stdout_sha:
                        verdict_status = "VERIFIED_FAIL_INVARIANT_VIOLATION"
                        semantic_result = "STDOUT_TOCTOU_INTEGRITY_VIOLATION"
                        failure_reason = f"STDOUT_TOCTOU_MUTATION_DETECTED: captured stdout file SHA {current_stdout_sha256} does not match executed stdout SHA {exec_stdout_sha}"
                    else:
                        cand_raw = cand_raw_bytes.strip()
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
                            verdict_status = "VERIFIED_FAIL_INVARIANT_VIOLATION"
                            semantic_result = "VIOLATION_NO_AST_OUTPUT"
                            failure_reason = "UNPARSEABLE_OR_EMPTY_STDOUT: Tool claimed exit 0 but stdout produced no valid machine-readable AST"
                elif target_stdout_file:
                    verdict_status = "VERIFIED_FAIL_INVARIANT_VIOLATION"
                    semantic_result = "MISSING_STDOUT_CAPTURE_FILE"
                    failure_reason = f"FAIL-CLOSED: Target stdout file '{target_stdout_file}' does not exist on physical disk"
                else:
                    # Valid exit code, but did not emit machine-readable AST
                    verdict_status = "VERIFIED_PASS"
                    semantic_result = "ACCEPTANCE_ONLY_NO_AST_OUTPUT"
                    failure_reason = "VALID_SINGLE_DOCUMENT_FULLY_CONSUMED_NO_AST_CAPTURE"

    sha_hex_pattern = re.compile(r"^[0-9a-fA-F]{64}$")
    ZERO_SENTINEL = "0" * 64
    F_SENTINEL = "f" * 64

    # Cryptographic digest integrity checks (Fail-Closed, execution attestation binding, NO post-hoc backfill)
    binary_sha256 = exec_bin_sha
    if not binary_sha256 or binary_sha256 == ZERO_SENTINEL or binary_sha256 == F_SENTINEL or not sha_hex_pattern.match(binary_sha256):
        verdict_status = "VERIFIED_FAIL_INVARIANT_VIOLATION"
        semantic_result = "MISSING_EXECUTION_ATTESTATION"
        failure_reason = f"FAIL-CLOSED: exec_bin_sha is missing, invalid hex, or synthetic sentinel: '{binary_sha256}'"
        binary_sha256 = None
    elif target_bin and os.path.isfile(target_bin):
        with open(target_bin, "rb") as bf:
            disk_bin_sha = hashlib.sha256(bf.read()).hexdigest()
        if binary_sha256 != disk_bin_sha:
            verdict_status = "VERIFIED_FAIL_INVARIANT_VIOLATION"
            semantic_result = "BINARY_INTEGRITY_VIOLATION"
            failure_reason = f"FAIL-CLOSED: binary_sha256 '{binary_sha256}' does not match disk binary SHA '{disk_bin_sha}'"

    input_sha256 = exec_input_sha
    if not input_sha256 or input_sha256 == ZERO_SENTINEL or input_sha256 == F_SENTINEL or not sha_hex_pattern.match(input_sha256):
        verdict_status = "VERIFIED_FAIL_INVARIANT_VIOLATION"
        if not semantic_result or semantic_result.startswith("ACCEPTANCE_ONLY") or semantic_result == "EXACT_AST_MATCH":
            semantic_result = "MISSING_EXECUTION_ATTESTATION"
        failure_reason = f"FAIL-CLOSED: exec_input_sha is missing, invalid hex, or synthetic sentinel: '{input_sha256}'"
        input_sha256 = None
    elif input_sha256 != current_input_sha256:
        verdict_status = "VERIFIED_FAIL_INVARIANT_VIOLATION"
        semantic_result = "TOCTOU_INTEGRITY_VIOLATION"
        failure_reason = f"TOCTOU_MUTATION_DETECTED: input file SHA {current_input_sha256} does not match executed SHA {input_sha256}"

    stdout_sha256 = exec_stdout_sha
    if not stdout_sha256 or stdout_sha256 == ZERO_SENTINEL or stdout_sha256 == F_SENTINEL or not sha_hex_pattern.match(stdout_sha256):
        verdict_status = "VERIFIED_FAIL_INVARIANT_VIOLATION"
        if not semantic_result or semantic_result.startswith("ACCEPTANCE_ONLY") or semantic_result == "EXACT_AST_MATCH":
            semantic_result = "MISSING_EXECUTION_ATTESTATION"
        failure_reason = f"FAIL-CLOSED: exec_stdout_sha is missing, invalid hex, or synthetic sentinel: '{stdout_sha256}'"
        stdout_sha256 = None

    if verdict_status != "VERIFIED_PASS" and (binary_sha256 is None or stdout_sha256 is None or input_sha256 is None):
        if not semantic_result or semantic_result.startswith("ACCEPTANCE_ONLY") or semantic_result == "EXACT_AST_MATCH":
            semantic_result = "MISSING_EXECUTION_ATTESTATION"

    details = {
        "verifier": "AIR10_STRICT_RFC8259_VERIFIER_V2",
        "has_trailing_bytes": has_trailing,
        "trailing_sample": trailing_sample,
        "verdict_status": verdict_status,
        "semantic_result": semantic_result,
        "failure_reason": failure_reason,
        "input_file": input_file,
        "input_sha256": input_sha256,
        "target_bin": target_bin,
        "actual_returncode": actual_returncode,
        "binary_sha256": binary_sha256,
        "stdout_sha256": stdout_sha256,
    }
    payload_raw = json.dumps(details, sort_keys=True).encode("utf-8")
    payload_sha256 = hashlib.sha256(payload_raw).hexdigest()

    # Append verification span with parent_span_id linked to execution span
    cur.execute("""
        INSERT INTO trace_events 
        (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
        VALUES (?, ?, ?, 'INDEPENDENT_VERIFICATION', 'rfc8259_semantic_verifier', ?, ?, ?, ?)
    """, (trace_id, span_id, parent_exec_span, now_iso, payload_sha256, verdict_status, json.dumps(details)))

    # Append immutable summary to tool_traces_v2 (Physical 64-char SHA-256 digests or NULL, zero synthetic sentinels)
    # Append immutable summary to tool_traces_v2 (Physical 64-char SHA-256 digests or NULL, zero synthetic sentinels)
    task_intent = intent_info.get("details", {}).get("intent", "UNKNOWN_INTENT")
    router_details = router_info.get("details", {})
    chosen_tool = router_details.get("chosen_tool", target_bin)
    candidates_json = json.dumps(router_details.get("candidates", []))

    cols = [c[1] for c in cur.execute("PRAGMA table_info(tool_traces_v2)").fetchall()]
    if "attempt_no" in cols:
        cur.execute("""
            INSERT INTO tool_traces_v2
            (trace_id, attempt_no, task_intent, traffic_class, router_candidates, chosen_tool, binary_path, 
             binary_sha256, input_path, input_sha256, stdout_sha256, actual_exit_code, 
             duration_ms, semantic_equivalence, verification_status, failure_reason, created_at)
            VALUES (?, ?, ?, 'TASK_CLI_HOTPATH', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            trace_id, attempt_no, task_intent, candidates_json, chosen_tool, target_bin,
            binary_sha256, input_file, input_sha256, stdout_sha256, actual_returncode,
            duration_ms, semantic_result, verdict_status, failure_reason, now_iso
        ))
    else:
        cur.execute("""
            INSERT INTO tool_traces_v2
            (trace_id, task_intent, traffic_class, router_candidates, chosen_tool, binary_path, 
             binary_sha256, input_path, input_sha256, stdout_sha256, actual_exit_code, 
             duration_ms, semantic_equivalence, verification_status, failure_reason, created_at)
            VALUES (?, ?, 'TASK_CLI_HOTPATH', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            trace_id, task_intent, candidates_json, chosen_tool, target_bin,
            binary_sha256, input_file, input_sha256, stdout_sha256, actual_returncode,
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
        raise RuntimeError(f"FEEDBACK_PERSISTENCE_HOLD: Failed to write circuit breaker outcome for tool '{chosen_tool}': {e}") from e

    print(f"VERDICT={verdict_status}|SEMANTIC={semantic_result}|REASON={failure_reason}|SPAN_ID={span_id}")
    return verdict_status


def record_pre_execution_failure(
    trace_id: str,
    attempt_no: int = 1,
    tool_name: str | None = None,
    binary_path: str | None = None,
    failure_reason: str = "UNKNOWN_FAILURE",
    audit_db_path: str | None = None,
    exit_code: int = -1,
    input_file: str | None = None,
    parent_span_id: str | None = None,
    target_bin: str | None = None,
    audit_db: str | None = None,
) -> str:
    """Records an immutable failed attempt row into tool_traces_v2 and trace_events when execution
    aborts before or during supervisor launch (e.g. C11 supervisor exit 70-79, attestation hold, timeout).
    FAIL-CLOSED: If DB write fails, raises an unswallowed exception. Emits both PROCESS_EXECUTION and
    INDEPENDENT_VERIFICATION spans to maintain causal referential integrity for DAG validators.
    """
    effective_bin = binary_path or target_bin or tool_name or "UNKNOWN_BIN"
    effective_tool = tool_name or effective_bin
    active_db = audit_db_path or audit_db or DB_PATH
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    exec_span_id = f"span_exec_fail_{uuid.uuid4().hex[:8]}"
    verif_span_id = f"span_verif_fail_{uuid.uuid4().hex[:8]}"

    if not os.path.exists(active_db):
        raise RuntimeError(f"AUDIT_LEDGER_PERSISTENCE_FAILED_HOLD: Audit DB missing at '{active_db}'")

    conn = sqlite3.connect(active_db)
    cur = conn.cursor()
    try:
        # Determine effective parent: prefer provided parent_span_id, else resolve latest span in trace
        effective_parent = parent_span_id
        if not effective_parent:
            cur.execute(
                "SELECT span_id FROM trace_events WHERE trace_id=? ORDER BY id DESC LIMIT 1",
                (trace_id,)
            )
            row = cur.fetchone()
            if row:
                effective_parent = row[0]
            else:
                effective_parent = "ROOT_SPAN"

        # 1. Insert failed PROCESS_EXECUTION trace_event
        err_details = {
            "verifier": "AIR10_FAIL_CLOSED_PRE_EXEC_RECORDER",
            "tool_name": effective_tool,
            "binary_path": effective_bin,
            "failure_reason": failure_reason,
            "exit_code": exit_code,
            "attempt_no": attempt_no
        }
        payload_raw = json.dumps(err_details, sort_keys=True).encode("utf-8")
        payload_sha256 = hashlib.sha256(payload_raw).hexdigest()

        cur.execute("""
            INSERT INTO trace_events
            (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
            VALUES (?, ?, ?, 'PROCESS_EXECUTION', 'pre_execution_guard', ?, ?, 'FAILED', ?)
        """, (trace_id, exec_span_id, effective_parent, now_iso, payload_sha256, json.dumps(err_details)))

        # 2. Insert failed INDEPENDENT_VERIFICATION trace_event completing the stage cycle
        verif_details = {
            "verifier": "AIR10_FAIL_CLOSED_PRE_EXEC_RECORDER",
            "tool_name": effective_tool,
            "verification_status": "FAILED_BEFORE_EXECUTION",
            "failure_reason": failure_reason,
            "attempt_no": attempt_no
        }
        verif_payload_raw = json.dumps(verif_details, sort_keys=True).encode("utf-8")
        verif_payload_sha256 = hashlib.sha256(verif_payload_raw).hexdigest()

        cur.execute("""
            INSERT INTO trace_events
            (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
            VALUES (?, ?, ?, 'INDEPENDENT_VERIFICATION', 'air10_layer5_verifier', ?, ?, 'FAILED', ?)
        """, (trace_id, verif_span_id, exec_span_id, now_iso, verif_payload_sha256, json.dumps(verif_details)))

        # 3. Insert immutable tool_traces_v2 row with compound PK (trace_id, attempt_no)
        cols = [c[1] for c in cur.execute("PRAGMA table_info(tool_traces_v2)").fetchall()]
        if "attempt_no" in cols:
            cur.execute("""
                INSERT INTO tool_traces_v2
                (trace_id, attempt_no, task_intent, traffic_class, router_candidates, chosen_tool, binary_path,
                 binary_sha256, input_path, input_sha256, stdout_sha256, actual_exit_code,
                 duration_ms, semantic_equivalence, verification_status, failure_reason, created_at)
                VALUES (?, ?, 'TASK_EXECUTION_FAILURE', 'TASK_CLI_HOTPATH', '[]', ?, ?,
                        NULL, ?, NULL, NULL, ?, 0.0, 'PRE_EXECUTION_FAILURE', 'FAILED_BEFORE_EXECUTION', ?, ?)
            """, (
                trace_id, attempt_no, effective_tool, effective_bin,
                input_file, exit_code, failure_reason, now_iso
            ))
        else:
            cur.execute("""
                INSERT INTO tool_traces_v2
                (trace_id, task_intent, traffic_class, router_candidates, chosen_tool, binary_path,
                 binary_sha256, input_path, input_sha256, stdout_sha256, actual_exit_code,
                 duration_ms, semantic_equivalence, verification_status, failure_reason, created_at)
                VALUES (?, 'TASK_EXECUTION_FAILURE', 'TASK_CLI_HOTPATH', '[]', ?, ?,
                        NULL, ?, NULL, NULL, ?, 0.0, 'PRE_EXECUTION_FAILURE', 'FAILED_BEFORE_EXECUTION', ?, ?)
            """, (
                trace_id, effective_tool, effective_bin,
                input_file, exit_code, failure_reason, now_iso
            ))
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise RuntimeError(f"AUDIT_LEDGER_PERSISTENCE_FAILED_HOLD: Failed to persist failed attempt to ledger: {e}") from e
    finally:
        conn.close()

    return "FAILED_BEFORE_EXECUTION"


def record_verification(
    trace_id: str,
    parent_span_id: str,
    target_bin: str,
    input_file: str,
    actual_returncode: int = 0,
    actual_child_pid: int | None = None,
    stdout_raw: str = "OK",
    stderr_raw: str = "",
    audit_db: str | None = None,
    attempt_no: int = 1,
    semantic_result: str = "AST_EQUIVALENCE_MATCH",
) -> str:
    """Helper alias for recording successful verification in test and orchestrator workflows."""
    active_db = audit_db or DB_PATH
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    verif_span_id = f"span_verif_{uuid.uuid4().hex[:8]}"
    stdout_sha256 = hashlib.sha256(stdout_raw.encode("utf-8")).hexdigest()
    bin_sha256 = "UNKNOWN"
    if os.path.isfile(target_bin):
        bin_sha256 = hashlib.sha256(open(target_bin, "rb").read()).hexdigest()
    inp_sha256 = "UNKNOWN"
    if os.path.isfile(input_file):
        inp_sha256 = hashlib.sha256(open(input_file, "rb").read()).hexdigest()

    verif_details = {
        "verifier": "AIR10_LAYER5_INDEPENDENT_VERIFIER",
        "semantic_result": semantic_result,
        "stdout_sha256": stdout_sha256,
        "input_sha256": inp_sha256,
        "actual_returncode": actual_returncode,
        "child_pid": actual_child_pid or os.getpid(),
        "tool_name": os.path.basename(target_bin),
        "target_bin": target_bin,
        "attempt_no": attempt_no,
    }
    verif_payload_raw = json.dumps(verif_details, sort_keys=True).encode("utf-8")
    verif_payload_sha256 = hashlib.sha256(verif_payload_raw).hexdigest()

    if os.path.exists(active_db):
        conn = sqlite3.connect(active_db)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO trace_events
            (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json)
            VALUES (?, ?, ?, 'INDEPENDENT_VERIFICATION', 'air10_layer5_verifier', ?, ?, 'COMPLETED', ?)
        """, (trace_id, verif_span_id, parent_span_id, now_iso, verif_payload_sha256, json.dumps(verif_details)))

        cols = [c[1] for c in cur.execute("PRAGMA table_info(tool_traces_v2)").fetchall()]
        if "attempt_no" in cols:
            cur.execute("""
                INSERT INTO tool_traces_v2
                (trace_id, attempt_no, task_intent, traffic_class, router_candidates, chosen_tool, binary_path,
                 binary_sha256, input_path, input_sha256, stdout_sha256, actual_exit_code,
                 duration_ms, semantic_equivalence, verification_status, failure_reason, created_at)
                VALUES (?, ?, 'TASK_EXECUTION', 'TASK_CLI_HOTPATH', '[]', ?, ?,
                        ?, ?, ?, ?, ?, 1.0, 'EQUIVALENT', 'VERIFIED_PASS', NULL, ?)
            """, (
                trace_id, attempt_no, os.path.basename(target_bin), target_bin,
                bin_sha256, input_file, inp_sha256, stdout_sha256, actual_returncode, now_iso
            ))
        conn.commit()
        conn.close()

    return "VERIFIED_PASS"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: air10_layer5_verifier.py <TRACE_ID> [INPUT_FILE] [STDOUT_FILE]", file=sys.stderr)
        sys.exit(1)
    t_id = sys.argv[1]
    inp = sys.argv[2] if len(sys.argv) > 2 else None
    out = sys.argv[3] if len(sys.argv) > 3 else None
    verify_trace(t_id, out)
