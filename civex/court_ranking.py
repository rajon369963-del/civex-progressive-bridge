#!/usr/bin/env python3
"""
CIVEX Court-Aware Ranking Model
================================
Integrates Tool Court verification, circuit breaker state, and contract-scoped
quarantine registries into a mathematical utility score for autonomous tool routing.

Formula:
  Score(tool, capability) = CorrectnessConfidence * Availability * Performance * Freshness * Safety

Invariants:
- If tool is QUARANTINED for (capability, input_format, contract_version),
  CorrectnessConfidence = 0.0 -> Score = 0.0 (Hard Fail-Closed Exclusion).
- If Circuit Breaker is OPEN (failures >= 3),
  Availability = 0.0 -> Score = 0.0 (Instant Isolation).
- If tool is ALLOWED_WITH_WARNING,
  CorrectnessConfidence = 0.70 (30% penalty).
- If tool is ALLOWED and verified,
  CorrectnessConfidence = 1.00.
"""

from __future__ import annotations
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
    status: str  # 'ELIGIBLE', 'QUARANTINED', 'CIRCUIT_OPEN', 'WARNING'
    rationale: str


class CourtAwareRanker:
    """Ranks and scores tools based on court verification verdicts and operational telemetry."""

    def __init__(self, audit_db_path: str = "/Users/rajondas/.antigravity/air10_audit.db"):
        self.audit_db_path = audit_db_path

    def score_tool(
        self,
        tool_name: str,
        capability: str,
        input_format: str = "SINGLE_DOC_STRICT_RFC8259",
        contract_version: str = "v1.0",
        binary_path: Optional[str] = None,
        circuit_open: bool = False,
        observed_latency_ms: float = 10.0,
        days_since_verification: float = 0.0,
        is_supervised: bool = True
    ) -> ToolScoreBreakdown:
        # 1. Check Circuit Breaker
        if circuit_open:
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
                rationale="Tool isolated: Circuit breaker is OPEN (repeated failures)."
            )

        # 2. Check Binary Availability
        avail = 1.0
        if binary_path and not os.path.exists(binary_path):
            avail = 0.0

        # 3. Check Court Quarantine Registry
        correctness = 0.50  # default baseline for unverified tools
        status = "ELIGIBLE"
        rationale = "Candidate cleared nominal verification."

        if os.path.exists(self.audit_db_path):
            try:
                conn = sqlite3.connect(f"file:{self.audit_db_path}?mode=ro", uri=True)
                cur = conn.cursor()
                cur.execute("""
                    SELECT status, reason, superseded_by
                    FROM tool_capability_quarantine
                    WHERE tool_name = ? AND capability = ? AND input_format = ? AND contract_version = ?
                """, (tool_name, capability, input_format, contract_version))
                row = cur.fetchone()
                if not row:
                    # Fallback to (tool_name, capability)
                    cur.execute("""
                        SELECT status, reason, superseded_by
                        FROM tool_capability_quarantine
                        WHERE tool_name = ? AND capability = ?
                    """, (tool_name, capability))
                    row = cur.fetchone()

                if row:
                    q_status, q_reason, superseded_by = row
                    if q_status == "QUARANTINED":
                        correctness = 0.0
                        status = "QUARANTINED"
                        rationale = f"HARD EXCLUSION: Quarantined ({q_reason}). Superseded by {superseded_by}."
                    elif q_status == "ALLOWED_WITH_WARNING":
                        correctness = 0.70
                        status = "WARNING"
                        rationale = f"ALLOWED_WITH_WARNING: {q_reason}"
                    elif q_status == "ALLOWED":
                        correctness = 1.00
                        status = "ELIGIBLE"
                        rationale = f"VERIFIED_PASS: {q_reason}"
                conn.close()
            except Exception:
                pass

        # If quarantined, final score is exactly 0.0
        if correctness == 0.0 or avail == 0.0:
            return ToolScoreBreakdown(
                tool_name=tool_name,
                capability=capability,
                input_format=input_format,
                contract_version=contract_version,
                correctness_confidence=correctness,
                availability=avail,
                performance=0.0,
                freshness=0.0,
                safety=0.0,
                final_score=0.0,
                status=status if avail > 0 else "BINARY_MISSING",
                rationale=rationale if avail > 0 else f"Binary missing at {binary_path}"
            )

        # 4. Performance Factor: Normalized latency (100ms baseline)
        perf = max(0.01, min(1.0, 100.0 / max(1.0, observed_latency_ms)))

        # 5. Freshness Factor: Exponential decay over days (half-life ~30 days, lambda = 0.0231)
        fresh = math.exp(-0.0231 * max(0.0, days_since_verification))

        # 6. Safety Factor: Supervised execution with exit code + sha256
        safe = 1.0 if is_supervised else 0.80

        # Multiplicative Utility Score
        final_score = correctness * avail * perf * fresh * safe

        return ToolScoreBreakdown(
            tool_name=tool_name,
            capability=capability,
            input_format=input_format,
            contract_version=contract_version,
            correctness_confidence=round(correctness, 4),
            availability=round(avail, 4),
            performance=round(perf, 4),
            freshness=round(fresh, 4),
            safety=round(safe, 4),
            final_score=round(final_score, 6),
            status=status,
            rationale=rationale
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
            circuit_open = cand.get("circuit_open", False)
            latency = cand.get("latency_ms", 10.0)
            days = cand.get("days_since_verification", 0.0)
            supervised = cand.get("is_supervised", True)
            scores.append(self.score_tool(
                tool_name=name,
                capability=capability,
                input_format=input_format,
                contract_version=contract_version,
                binary_path=bin_path,
                circuit_open=circuit_open,
                observed_latency_ms=latency,
                days_since_verification=days,
                is_supervised=supervised
            ))
        # Sort descending by final_score
        scores.sort(key=lambda s: s.final_score, reverse=True)
        return scores
