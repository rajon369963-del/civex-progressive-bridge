#!/Users/rajondas/.air1/speed_wheels_env/bin/python3
"""
CIVEX Court-Aware Ranking Model (Production-Hardened & Fail-Closed)
===================================================================
Integrates Tool Court verification, authoritative CIVeX circuit breaker state,
contract-scoped quarantine registries, and cryptographic binary attestation
into a mathematical utility score for autonomous tool routing.

Eligibility Gate:
  EligibilityGate = VerifiedCorrect & Available & ContractMatch & CircuitClosed
  (Any failure yields Score = 0.0 immediately)

Discriminative Utility Score:
  Score(tool, capability) = CorrectnessConfidence * Availability * LatencyScore * Freshness * Safety

where:
  LatencyScore = 1.0 / (1.0 + observed_latency_ms / 10.0)  [Never saturates, discriminates 1ms vs 10ms vs 100ms]
"""

from __future__ import annotations

import hashlib
import math
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class ToolScoreBreakdown:
    tool_name: str
    capability: str
    input_format: str
    contract_version: str
    correctness_confidence: float
    availability: float
    performance: float
    freshness: float
    safety: float
    final_score: float
    status: str  # 'ELIGIBLE', 'QUARANTINED', 'CIRCUIT_OPEN', 'WARNING', 'CONTRACT_UNVERIFIED', 'BINARY_TAMPERED', 'VERIFICATION_UNAVAILABLE_HOLD', 'CIRCUIT_STATE_UNKNOWN_HOLD'
    rationale: str
    binary_sha256: str | None = None
    superseded_by: str | None = None


class CourtAwareRanker:
    """Ranks and scores tools based on court verification verdicts and authoritative operational telemetry."""

    DEFAULT_AUDIT_DB = "/Users/rajondas/.antigravity/air10_audit.db"

    def __init__(self, audit_db_path: str | None = None, verifier: Any = None):
        if audit_db_path:
            self.audit_db_path = audit_db_path
        elif env_path := os.environ.get("AIR10_AUDIT_DB"):
            self.audit_db_path = env_path
        else:
            self.audit_db_path = self.DEFAULT_AUDIT_DB

        self.verifier = verifier

    def _get_circuit_open(self, tool_id: str, tool_name: str | None = None) -> tuple[bool, str]:
        """Derives circuit breaker status authoritatively from CIVeXVerifier.
        FAIL-CLOSED INVARIANT: If no verifier is provided, circuit state is UNKNOWN and must HOLD.
        """
        if self.verifier is None or not hasattr(self.verifier, "is_circuit_open"):
            return True, "CIRCUIT_STATE_UNKNOWN_HOLD"
        try:
            # Check canonical tool_id first
            if bool(self.verifier.is_circuit_open(tool_id)):
                return True, "CIRCUIT_OPEN"
            # Secondary check on tool_name if distinct
            if tool_name and tool_name != tool_id:
                if bool(self.verifier.is_circuit_open(tool_name)):
                    return True, "CIRCUIT_OPEN"
            return False, "CIRCUIT_CLOSED"
        except Exception:
            return True, "CIRCUIT_QUERY_EXCEPTION"

    def score_tool(
        self,
        tool_name: str,
        capability: str,
        input_format: str = "SINGLE_DOC_STRICT_RFC8259",
        contract_version: str = "v1.0",
        binary_path: str | None = None,
        observed_latency_ms: float | None = None,
        days_since_verification: float | None = None,
        is_supervised: bool | None = None,
        tool_id: str | None = None
    ) -> ToolScoreBreakdown:
        # 1. Authoritative Circuit Breaker Check (Chakka Jodo: Consume CIVeX state via tool_id)
        effective_id = tool_id or tool_name
        is_open, cb_status = self._get_circuit_open(effective_id, tool_name)
        if is_open:
            rationale = (
                "FAIL-CLOSED: No authoritative circuit breaker verifier provided (CIRCUIT_STATE_UNKNOWN_HOLD)."
                if cb_status == "CIRCUIT_STATE_UNKNOWN_HOLD"
                else f"Tool isolated: CIVeX circuit breaker is OPEN for '{effective_id}'."
            )
            return ToolScoreBreakdown(
                tool_name=tool_name,
                capability=capability,
                input_format=input_format,
                contract_version=contract_version,
                correctness_confidence=0.0,
                availability=0.0,
                performance=0.0,
                freshness=0.0,
                safety=0.0,
                final_score=0.0,
                status=cb_status,
                rationale=rationale
            )

        # 2. Binary Identity & Executability Protection (Realpath + X_OK + SHA-256)
        actual_bin_sha = None
        if binary_path:
            real_bin = os.path.realpath(binary_path)
            if not os.path.isfile(real_bin):
                return ToolScoreBreakdown(
                    tool_name=tool_name,
                    capability=capability,
                    input_format=input_format,
                    contract_version=contract_version,
                    correctness_confidence=0.0,
                    availability=0.0,
                    performance=0.0,
                    freshness=0.0,
                    safety=0.0,
                    final_score=0.0,
                    status="BINARY_MISSING",
                    rationale=f"Binary file missing on physical disk at {binary_path} (resolved: {real_bin})"
                )
            if not os.access(real_bin, os.X_OK):
                return ToolScoreBreakdown(
                    tool_name=tool_name,
                    capability=capability,
                    input_format=input_format,
                    contract_version=contract_version,
                    correctness_confidence=0.0,
                    availability=0.0,
                    performance=0.0,
                    freshness=0.0,
                    safety=0.0,
                    final_score=0.0,
                    status="BINARY_NOT_EXECUTABLE",
                    rationale=f"Binary at {real_bin} lacks executable permissions (os.X_OK false)"
                )
            try:
                with open(real_bin, "rb") as bf:
                    actual_bin_sha = hashlib.sha256(bf.read()).hexdigest()
            except Exception as e:
                return ToolScoreBreakdown(
                    tool_name=tool_name,
                    capability=capability,
                    input_format=input_format,
                    contract_version=contract_version,
                    correctness_confidence=0.0,
                    availability=0.0,
                    performance=0.0,
                    freshness=0.0,
                    safety=0.0,
                    final_score=0.0,
                    status="BINARY_READ_ERROR",
                    rationale=f"Failed to read binary for SHA-256 digest: {e}"
                )

        observed_ms = observed_latency_ms
        verified_days = days_since_verification
        supervised_val = is_supervised

        # 3. Court Quarantine & Contract Verdict Query (STRICT FAIL-CLOSED)
        if not os.path.exists(self.audit_db_path):
            return ToolScoreBreakdown(
                tool_name=tool_name,
                capability=capability,
                input_format=input_format,
                contract_version=contract_version,
                correctness_confidence=0.0,
                availability=0.0,
                performance=0.0,
                freshness=0.0,
                safety=0.0,
                final_score=0.0,
                status="VERIFICATION_UNAVAILABLE_HOLD",
                rationale=f"FAIL-CLOSED: Audit database not found at {self.audit_db_path}"
            )

        try:
            conn = sqlite3.connect(f"file:{self.audit_db_path}?mode=ro", uri=True)
            cur = conn.cursor()

            # Prefer v2 table, fallback to legacy if v2 doesn't exist
            tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            is_v2 = "tool_contract_verdicts_v2" in tables
            target_table = "tool_contract_verdicts_v2" if is_v2 else "tool_capability_quarantine"

            select_cols = "status, reason, superseded_by, binary_sha256, verified_at" if is_v2 else "status, reason, superseded_by, NULL, quarantined_at"

            # Strict exact contract lookup (tool_name, capability, input_format, contract_version)
            cur.execute(f"""
                SELECT {select_cols}
                FROM {target_table}
                WHERE tool_name = ? AND capability = ? AND input_format = ? AND contract_version = ?
            """, (tool_name, capability, input_format, contract_version))
            row = cur.fetchone()

            if not row:
                # Check explicit wildcard contract if registered
                cur.execute(f"""
                    SELECT {select_cols}
                    FROM {target_table}
                    WHERE tool_name = ? AND capability = ? AND input_format = '*' AND contract_version = '*'
                """, (tool_name, capability))
                row = cur.fetchone()

            # If no exact or wildcard contract registered: FAIL-CLOSED HOLD
            if not row:
                conn.close()
                return ToolScoreBreakdown(
                    tool_name=tool_name,
                    capability=capability,
                    input_format=input_format,
                    contract_version=contract_version,
                    correctness_confidence=0.0,
                    availability=1.0 if binary_path else 0.5,
                    performance=0.0,
                    freshness=0.0,
                    safety=0.0,
                    final_score=0.0,
                    status="CONTRACT_UNVERIFIED",
                    rationale=f"FAIL-CLOSED: No verified contract registered for ({capability}, {input_format}, {contract_version})."
                )

            q_status, q_reason, superseded_by, certified_sha = row[:4]

            # Binary Digest Attestation against certified court hash
            if certified_sha and actual_bin_sha and certified_sha != actual_bin_sha:
                conn.close()
                return ToolScoreBreakdown(
                    tool_name=tool_name,
                    capability=capability,
                    input_format=input_format,
                    contract_version=contract_version,
                    correctness_confidence=0.0,
                    availability=0.0,
                    performance=0.0,
                    freshness=0.0,
                    safety=0.0,
                    final_score=0.0,
                    status="BINARY_HASH_MISMATCH",
                    rationale=f"SECURITY_ALERT: Physical binary digest {actual_bin_sha[:12]} does NOT match certified court digest {certified_sha[:12]}",
                    binary_sha256=actual_bin_sha
                )

            # Status Evaluation: Check quarantine / invalid status before telemetry extraction
            if q_status == "QUARANTINED":
                conn.close()
                return ToolScoreBreakdown(
                    tool_name=tool_name,
                    capability=capability,
                    input_format=input_format,
                    contract_version=contract_version,
                    correctness_confidence=0.0,
                    availability=1.0,
                    performance=0.0,
                    freshness=0.0,
                    safety=0.0,
                    final_score=0.0,
                    status="QUARANTINED",
                    rationale=f"HARD_EXCLUSION: Quarantined ({q_reason}). Superseded by {superseded_by}.",
                    superseded_by=superseded_by
                )
            elif q_status == "ALLOWED_WITH_WARNING":
                correctness = 0.70
                status = "WARNING"
                rationale = f"ALLOWED_WITH_WARNING: {q_reason}"
            elif q_status == "ALLOWED":
                correctness = 1.00
                status = "ELIGIBLE"
                rationale = f"VERIFIED_PASS: {q_reason}"
            else:
                conn.close()
                return ToolScoreBreakdown(
                    tool_name=tool_name,
                    capability=capability,
                    input_format=input_format,
                    contract_version=contract_version,
                    correctness_confidence=0.0,
                    availability=0.0,
                    performance=0.0,
                    freshness=0.0,
                    safety=0.0,
                    final_score=0.0,
                    status="UNKNOWN_STATUS_HOLD",
                    rationale=f"FAIL-CLOSED: Unknown contract status '{q_status}'"
                )

            # EMPIRICAL TELEMETRY EXTRACTION (Audit DB derived, zero synthetic constants)
            # 1. Empirical Latency (Checked against VERIFIED_PASS and PASS)
            if observed_ms is None:
                if "tool_traces_v2" in tables:
                    cur.execute("""
                        SELECT AVG(duration_ms) FROM tool_traces_v2 
                        WHERE (chosen_tool = ? OR chosen_tool = ?) AND verification_status IN ('VERIFIED_PASS', 'PASS')
                    """, (tool_name, effective_id))
                    lat_row = cur.fetchone()
                    if lat_row and lat_row[0] is not None:
                        observed_ms = float(lat_row[0])
                if observed_ms is None and "tool_traces" in tables:
                    cur.execute("""
                        SELECT AVG(benchmark_p50_us) / 1000.0 FROM tool_traces
                        WHERE tool_name = ? OR tool_name = ?
                    """, (tool_name, effective_id))
                    lat_row = cur.fetchone()
                    if lat_row and lat_row[0] is not None:
                        observed_ms = float(lat_row[0])
                if observed_ms is None:
                    # FAIL-CLOSED: No synthetic default latency allowed
                    conn.close()
                    return ToolScoreBreakdown(
                        tool_name=tool_name,
                        capability=capability,
                        input_format=input_format,
                        contract_version=contract_version,
                        correctness_confidence=0.0,
                        availability=0.0,
                        performance=0.0,
                        freshness=0.0,
                        safety=0.0,
                        final_score=0.0,
                        status="TELEMETRY_UNAVAILABLE_HOLD",
                        rationale=f"FAIL-CLOSED: No empirical latency telemetry recorded in audit DB for {tool_name}"
                    )

            # 2. Empirical Verification Freshness (from verified_at timestamp)
            if verified_days is None:
                verified_at_str = row[4] if len(row) > 4 and row[4] else None
                if not verified_at_str:
                    conn.close()
                    return ToolScoreBreakdown(
                        tool_name=tool_name,
                        capability=capability,
                        input_format=input_format,
                        contract_version=contract_version,
                        correctness_confidence=0.0,
                        availability=0.0,
                        performance=0.0,
                        freshness=0.0,
                        safety=0.0,
                        final_score=0.0,
                        status="FRESHNESS_EVIDENCE_HOLD",
                        rationale=f"FAIL-CLOSED: Missing verified_at timestamp in contract verdict for {tool_name}"
                    )
                try:
                    clean_ts = verified_at_str.replace("Z", "+00:00")
                    ver_dt = datetime.fromisoformat(clean_ts)
                    now_dt = datetime.now(timezone.utc)
                    delta_sec = max(0.0, (now_dt - ver_dt).total_seconds())
                    verified_days = delta_sec / 86400.0
                except Exception as e:
                    conn.close()
                    return ToolScoreBreakdown(
                        tool_name=tool_name,
                        capability=capability,
                        input_format=input_format,
                        contract_version=contract_version,
                        correctness_confidence=0.0,
                        availability=0.0,
                        performance=0.0,
                        freshness=0.0,
                        safety=0.0,
                        final_score=0.0,
                        status="FRESHNESS_EVIDENCE_HOLD",
                        rationale=f"FAIL-CLOSED: Malformed verified_at timestamp '{verified_at_str}' for {tool_name}: {e}"
                    )

            # 3. Empirical Execution Supervision (Structured JSON match, zero LIKE substring)
            if supervised_val is None:
                if "trace_events" in tables:
                    cur.execute("""
                        SELECT COUNT(*) FROM trace_events
                        WHERE (json_extract(details_json, '$.tool_name') = ? 
                               OR json_extract(details_json, '$.tool_id') = ?
                               OR json_extract(details_json, '$.binary_path') = ?)
                          AND stage = 'PROCESS_EXECUTION'
                          AND parent_span_id IS NOT NULL
                    """, (tool_name, effective_id, binary_path or tool_name))
                    sup_count = cur.fetchone()[0]
                    supervised_val = (sup_count > 0)
                else:
                    supervised_val = False

                if not supervised_val:
                    # FAIL-CLOSED: Missing supervision evidence cannot assume Supervised=True
                    conn.close()
                    return ToolScoreBreakdown(
                        tool_name=tool_name,
                        capability=capability,
                        input_format=input_format,
                        contract_version=contract_version,
                        correctness_confidence=0.0,
                        availability=0.0,
                        performance=0.0,
                        freshness=0.0,
                        safety=0.0,
                        final_score=0.0,
                        status="SUPERVISION_UNVERIFIED_HOLD",
                        rationale=f"FAIL-CLOSED: No supervised process execution trace recorded in audit DB for {tool_name}"
                    )

            conn.close()
        except Exception as e:
            # FAIL-CLOSED INVARIANT: Any DB error must yield 0 score, never default 0.50
            return ToolScoreBreakdown(
                tool_name=tool_name,
                capability=capability,
                input_format=input_format,
                contract_version=contract_version,
                correctness_confidence=0.0,
                availability=0.0,
                performance=0.0,
                freshness=0.0,
                safety=0.0,
                final_score=0.0,
                status="VERIFICATION_UNAVAILABLE_HOLD",
                rationale=f"FAIL-CLOSED: Audit DB query exception: {e}"
            )

        # 4. Discriminative Non-Saturating Latency Scoring
        latency_score = 1.0 / (1.0 + max(0.0, observed_ms) / 10.0)

        # 5. Freshness Factor (decay over days since verification)
        freshness = math.exp(-0.0231 * max(0.0, verified_days))

        # 6. Safety Factor (Strict empirical supervision requirement)
        safety = 1.00 if supervised_val else 0.00

        # Multiplicative Utility Score
        final_score = correctness * 1.0 * latency_score * freshness * safety

        return ToolScoreBreakdown(
            tool_name=tool_name,
            capability=capability,
            input_format=input_format,
            contract_version=contract_version,
            correctness_confidence=round(correctness, 4),
            availability=1.0,
            performance=round(latency_score, 4),
            freshness=round(freshness, 4),
            safety=round(safety, 4),
            final_score=round(final_score, 6),
            status=status,
            rationale=rationale,
            binary_sha256=actual_bin_sha or certified_sha,
            superseded_by=superseded_by
        )

    def rank_candidates(
        self,
        candidates: list[dict[str, Any]],
        capability: str,
        input_format: str = "SINGLE_DOC_STRICT_RFC8259",
        contract_version: str = "v1.0"
    ) -> list[ToolScoreBreakdown]:
        scores = []
        for cand in candidates:
            name = cand.get("name", cand.get("tool_id", "unknown"))
            tool_id = cand.get("id", cand.get("tool_id", name))
            bin_path = cand.get("binary_path", cand.get("binary", None))
            latency = cand.get("latency_ms", None)
            days = cand.get("days_since_verification", None)
            supervised = cand.get("is_supervised", None)
            scores.append(self.score_tool(
                tool_name=name,
                capability=capability,
                input_format=input_format,
                contract_version=contract_version,
                binary_path=bin_path,
                observed_latency_ms=latency,
                days_since_verification=days,
                is_supervised=supervised,
                tool_id=tool_id
            ))
        scores.sort(key=lambda s: s.final_score, reverse=True)
        return scores
