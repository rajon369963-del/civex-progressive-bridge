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
    output_dir: str = "/tmp",
    effect_class: str = "unknown",
) -> dict[str, Any]:
    """Executes a single intent request with bounded same-request failover.

    ``effect_class`` must be one of ``read_only``, ``write_bearing`` or ``unknown``.
    Once Layer 4 reports that execution may have started but trustworthy outcome evidence
    is unavailable, write-bearing and unknown effects are fenced and returned for
    reconciliation instead of automatically trying an alternate tool.
    """
    if effect_class not in {"read_only", "write_bearing", "unknown"}:
        raise ValueError(f"Unsupported effect_class: {effect_class}")

    trace_id, span_intent_id = air10_layer1_intent.emit_intent(
        intent_name=required_capability,
        description=intent_query,
        caller="civex_autonomous_orchestrator",
        db_path=db_path,
    )

    attempt_history = []
    active_candidates = list(candidate_pool) if candidate_pool is not None else None

    for attempt in range(1, max_attempts + 1):
        router_res = air10_layer2_router.route_intent(
            trace_id=trace_id,
            parent_span_id=span_intent_id,
            intent_query=intent_query,
            required_capability=required_capability,
            candidates_override=active_candidates,
            db_path=db_path,
        )
        chosen_tool, chosen_bin, span_router_id = router_res
        permit = getattr(router_res, "permit", None)

        if not chosen_tool or not chosen_bin:
            return {
                "status": "REFUSED_NO_TOOL_AVAILABLE",
                "trace_id": trace_id,
                "completed_attempts": attempt - 1,
                "history": attempt_history,
                "error": f"Router found no verified, eligible tool on attempt {attempt}",
            }

        cmd_args = argv or [input_file]
        span_shim_id = air10_layer3_shim.shim_intercept(
            trace_id=trace_id,
            tool_name=chosen_tool,
            binary_path=chosen_bin,
            command_args=cmd_args,
            parent_span_id=span_router_id,
            db_path=db_path,
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
                db_path=db_path,
                require_court_sha=True,
                permit=permit,
                timeout_sec=30.0,
            )
        except air10_layer4_executor.PostExecutionOutcomeUnknown as exec_err:
            attempt_record = {
                "attempt": attempt,
                "tool": chosen_tool,
                "error": str(exec_err),
                "effect_class": effect_class,
                "execution_started": True,
                "child_exit_observed": bool(getattr(exec_err, "child_exit_observed", False)),
                "evidence_valid": False,
                "verdict": "POST_EXECUTION_OUTCOME_UNKNOWN",
            }
            attempt_history.append(attempt_record)

            # Read-only effects may retain the existing bounded failover behavior because
            # replay cannot create a write-bearing duplicate. Unknown defaults fail closed.
            if effect_class == "read_only":
                if active_candidates:
                    active_candidates = [c for c in active_candidates if c.get("name") != chosen_tool]
                continue

            return {
                "status": "HOLD_RECONCILE_AMBIGUOUS_EXECUTION",
                "trace_id": trace_id,
                "completed_attempts": attempt,
                "retry_allowed": False,
                "effect_class": effect_class,
                "disposition": "POST_EXECUTION_OUTCOME_UNKNOWN",
                "history": attempt_history,
            }
        except Exception as exec_err:
            try:
                from civex.bridge import CIVeXVerifier

                verifier = CIVeXVerifier()
                verifier.record_outcome(chosen_tool, success=False, error_msg=str(exec_err))
            except Exception as cb_err:
                raise RuntimeError(f"CIRCUIT_BREAKER_PERSISTENCE_FAILED_HOLD: Failed to update circuit breaker for {chosen_tool}: {cb_err}") from cb_err

            air10_layer5_verifier.record_pre_execution_failure(
                trace_id=trace_id,
                attempt_no=attempt,
                tool_name=chosen_tool,
                binary_path=chosen_bin,
                failure_reason=str(exec_err),
                audit_db_path=db_path,
                input_file=input_file,
                parent_span_id=span_shim_id
            )

            if active_candidates:
                active_candidates = [c for c in active_candidates if c.get("name") != chosen_tool]
            attempt_history.append(
                {
                    "attempt": attempt,
                    "tool": chosen_tool,
                    "error": str(exec_err),
                    "effect_class": effect_class,
                    "execution_started": False,
                    "evidence_valid": False,
                    "verdict": "FAILED_BEFORE_EXECUTION",
                }
            )
            continue

        verdict = air10_layer5_verifier.verify_trace(
            trace_id=trace_id,
            target_stdout_file=out_file,
            audit_db_path=db_path,
            attempt_no=attempt,
        )

        attempt_record = {
            "attempt": attempt,
            "tool": chosen_tool,
            "binary": chosen_bin,
            "exit_code": rc,
            "verdict": verdict,
            "stdout_file": out_file,
            "effect_class": effect_class,
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
                "history": attempt_history,
            }

        # Layer 5 rejected evidence after a completed execution. For write-bearing and
        # unknown effects this is also ambiguous and must not trigger alternate execution.
        if effect_class != "read_only":
            return {
                "status": "HOLD_RECONCILE_AMBIGUOUS_VERDICT",
                "trace_id": trace_id,
                "completed_attempts": attempt,
                "retry_allowed": False,
                "effect_class": effect_class,
                "disposition": "POST_EXECUTION_VERIFICATION_FAILED",
                "history": attempt_history,
            }

        if active_candidates:
            active_candidates = [c for c in active_candidates if c.get("name") != chosen_tool]

    return {
        "status": "FAILED_MAX_ATTEMPTS_EXCEEDED",
        "trace_id": trace_id,
        "completed_attempts": max_attempts,
        "history": attempt_history,
    }
