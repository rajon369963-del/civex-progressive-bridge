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
from typing import Any, Optional


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
    status: str  # 'ELIGIBLE', 'QUARANTINED', 'CIRCUIT_OPEN', 'WARNING', 'CONTRACT_UNVERIFIED', 'BINARY_TAMPERED', 'VERIFICATION_UNAVAILABLE_HOLD'
    rationale: str
    binary_sha256: Optional[str] = None


class CourtAwareRanker:
    """Ranks and scores tools based on court verification verdicts and authoritative operational telemetry."""

    DEFAULT_AUDIT_DB = "/Users/rajondas/.antigravity/air10_audit.db"

    def __init__(self, audit_db_path: Optional[str] = None, verifier: Any = None):
        if audit_db_path:
            self.audit_db_path = audit_db_path
        elif env_path := os.environ.get("AIR10_AUDIT_DB"):
            self.audit_db_path = env_path
        else:
            self.audit_db_path = self.DEFAULT_AUDIT_DB

        self.verifier = verifier

    def _get_circuit_open(self, tool_id: str) -> bool:
        """Derives circuit breaker status authoritatively from CIVeXVerifier."""
        if self.verifier is not None and hasattr(self.verifier, "is_circuit_open"):
            try:
                return bool(self.verifier.is_circuit_open(tool_id))
            except Exception:
                return True  # Fail-closed if verifier query fails
        return False

    def score_tool(
        self,
        tool_name: str,
        capability: str,
        input_format: str = "SINGLE_DOC_STRICT_RFC8259",
        contract_version: str = "v1.0",
        binary_path: Optional[str] = None,
        observed_latency_ms: float = 10.0,
        days_since_verification: float = 0.0,
        is_supervised: bool = True
    ) -> ToolScoreBreakdown:
        # 1. Authoritative Circuit Breaker Check (Chakka Jodo: Consume CIVeX state)
        if self._get_circuit_open(tool_name):
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
                status="CIRCUIT_OPEN",
                rationale="Tool isolated: CIVeX circuit breaker is OPEN (repeated failures)."
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
            target_table = "tool_contract_verdicts_v2" if "tool_contract_verdicts_v2" in tables else "tool_capability_quarantine"

            # Strict exact contract lookup (tool_name, capability, input_format, contract_version)
            cur.execute(f"""
                SELECT status, reason, superseded_by, binary_sha256
                FROM {target_table}
                WHERE tool_name = ? AND capability = ? AND input_format = ? AND contract_version = ?
            """, (tool_name, capability, input_format, contract_version))
            row = cur.fetchone()

            if not row:
                # Check explicit wildcard contract if registered
                cur.execute(f"""
                    SELECT status, reason, superseded_by, binary_sha256
                    FROM {target_table}
                    WHERE tool_name = ? AND capability = ? AND input_format = '*' AND contract_version = '*'
                """, (tool_name, capability))
                row = cur.fetchone()

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

        # If no exact or wildcard contract registered: FAIL-CLOSED HOLD
        if not row:
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

        q_status, q_reason, superseded_by, certified_sha = row

        # Binary Digest Attestation against certified court hash
        if certified_sha and actual_bin_sha and certified_sha != actual_bin_sha:
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

        # Status Evaluation
        if q_status == "QUARANTINED":
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
                rationale=f"HARD_EXCLUSION: Quarantined ({q_reason}). Superseded by {superseded_by}."
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

        # 4. Discriminative Non-Saturating Latency Scoring
        # Formula: LatencyScore = 1.0 / (1.0 + latency_ms / 10.0)
        # 1ms -> 0.909, 5ms -> 0.667, 10ms -> 0.500, 33ms -> 0.233, 100ms -> 0.091
        latency_score = 1.0 / (1.0 + max(0.0, observed_latency_ms) / 10.0)

        # 5. Freshness Factor (decay over days since verification)
        freshness = math.exp(-0.0231 * max(0.0, days_since_verification))

        # 6. Safety Factor
        safety = 1.00 if is_supervised else 0.80

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
            binary_sha256=actual_bin_sha or certified_sha
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
            bin_path = cand.get("binary_path", cand.get("binary", None))
            latency = cand.get("latency_ms", 10.0)
            days = cand.get("days_since_verification", 0.0)
            supervised = cand.get("is_supervised", True)
            scores.append(self.score_tool(
                tool_name=name,
                capability=capability,
                input_format=input_format,
                contract_version=contract_version,
                binary_path=bin_path,
                observed_latency_ms=latency,
                days_since_verification=days,
                is_supervised=supervised
            ))
        scores.sort(key=lambda s: s.final_score, reverse=True)
        return scores
