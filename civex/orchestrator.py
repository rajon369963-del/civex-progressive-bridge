#!/usr/bin/env python3
"""
CIVEX Autonomous Execution Orchestrator
Single-invocation closed-loop execution and self-healing engine across Layers 1 to 5.
Automatically intercepts execution failures, updates circuit breaker state via Layer 5,
and retries alternate candidate tools for the SAME request without manual test intervention.
"""
from __future__ import annotations

import os
from typing import Any

from civex.trace_plumbing import (
    air10_layer1_intent,
    air10_layer2_router,
    air10_layer3_shim,
    air10_layer4_executor,
    air10_layer5_verifier,
)


def orchestrate_request(
    intent_query: str,
    required_capability: str,
    input_file: str,
    candidate_pool: list[dict[str, Any]] | None = None,
    db_path: str | None = None,
    max_attempts: int = 2,
    argv: list[str] | None = None,
    output_dir: str = "/tmp"
) -> dict[str, Any]:
    """Executes a single intent request with autonomous same-request self-healing failover.
    
    Flow:
    1. Layer 1: Emits root INTENT event.
    2. Attempt loop (1..max_attempts):
       a. Layer 2: Routes intent to optimal eligible candidate (skipping open-circuit tools).
       b. Layer 3: Shim intercepts and records parent-child span correlation.
       c. Layer 4: C11 execution boundary enforces content-addressed snapshots and expected SHA.
       d. Layer 5: Strictly verifies execution trace, stores attempt in ledger, and updates circuit breaker.
       e. If VERIFIED_PASS: returns success immediately.
       f. If failure and attempts remain: automatically retries next alternate candidate.
    """
    trace_id, span_intent_id = air10_layer1_intent.emit_intent(
        intent_name=required_capability,
        description=intent_query,
        caller="civex_autonomous_orchestrator",
        db_path=db_path
    )

    attempt_history = []

    active_candidates = list(candidate_pool) if candidate_pool is not None else None

    for attempt in range(1, max_attempts + 1):
        chosen_tool, chosen_bin, span_router_id = air10_layer2_router.route_intent(
            trace_id=trace_id,
            parent_span_id=span_intent_id,
            intent_query=intent_query,
            required_capability=required_capability,
            candidates_override=active_candidates,
            db_path=db_path
        )

        if not chosen_tool or not chosen_bin:
            return {
                "status": "REFUSED_NO_TOOL_AVAILABLE",
                "trace_id": trace_id,
                "completed_attempts": attempt - 1,
                "history": attempt_history,
                "error": f"Router found no verified, eligible tool on attempt {attempt}"
            }

        cmd_args = argv or [input_file]
        span_shim_id = air10_layer3_shim.shim_intercept(
            trace_id=trace_id,
            tool_name=chosen_tool,
            binary_path=chosen_bin,
            command_args=cmd_args,
            parent_span_id=span_router_id,
            db_path=db_path
        )

        out_file = os.path.join(output_dir, f"stdout_{trace_id}_att{attempt}.out")

        try:
            rc, dur_ms, out_sha = air10_layer4_executor.execute_process(
                trace_id=trace_id,
                binary_path=chosen_bin,
                input_file=input_file,
                parent_span_id=span_shim_id,
                output_file=out_file,
                argv=cmd_args,
                db_path=db_path
            )
        except Exception as exec_err:
            try:
                from civex.bridge import CIVeXVerifier
                verifier = CIVeXVerifier()
                verifier.record_outcome(chosen_tool, success=False, error_msg=str(exec_err))
            except Exception:
                pass
            if active_candidates:
                active_candidates = [c for c in active_candidates if c.get("name") != chosen_tool]
            attempt_history.append({
                "attempt": attempt,
                "tool": chosen_tool,
                "error": str(exec_err),
                "verdict": "EXECUTION_EXCEPTION"
            })
            continue

        verdict = air10_layer5_verifier.verify_trace(
            trace_id=trace_id,
            target_stdout_file=out_file,
            audit_db_path=db_path,
            attempt_no=attempt
        )

        attempt_record = {
            "attempt": attempt,
            "tool": chosen_tool,
            "binary": chosen_bin,
            "exit_code": rc,
            "verdict": verdict,
            "stdout_file": out_file
        }
        attempt_history.append(attempt_record)

        if verdict == "VERIFIED_PASS":
            return {
                "status": "SUCCESS",
                "trace_id": trace_id,
                "chosen_tool": chosen_tool,
                "binary_path": chosen_bin,
                "attempts_needed": attempt,
                "verdict": verdict,
                "history": attempt_history
            }

        if active_candidates:
            active_candidates = [c for c in active_candidates if c.get("name") != chosen_tool]

    return {
        "status": "FAILED_MAX_ATTEMPTS_EXCEEDED",
        "trace_id": trace_id,
        "completed_attempts": max_attempts,
        "history": attempt_history
    }
