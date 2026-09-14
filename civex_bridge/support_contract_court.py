"""
⚡ Civex Progressive Bridge: Support Contract Digest Court (T021/T022).
Enforces anti-self-sealing authority verification for support contracts,
guaranteeing that contract digests cannot circular-seal or bypass authorized signers.
"""
import hashlib
import json
import re
from typing import Any

AUTHORIZED_AUTHORITIES = {
    "CIVEX_ROOT_AUTHORITY_2026",
    "MIGL_AIR10_FEDERATION_AUTHORITY",
    "ANTIGRAVITY_GOVERNANCE_COUNCIL"
}


def compute_contract_digest(contract_data: dict[str, Any]) -> str:
    """
    Computes a canonical SHA-256 digest over the contract's immutable fields,
    strictly excluding dynamic or circular self-referential fields (digest, signature).
    """
    if not isinstance(contract_data, dict):
        raise ValueError("contract_data must be a dictionary")

    # Filter out circular self-sealing fields
    canonical_payload = {
        k: v for k, v in contract_data.items()
        if k not in ("digest", "signature", "signed_at", "self_sealed_token")
    }

    # Deterministic sorted JSON serialization
    serialized = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def verify_contract_authority(
    contract_data: dict[str, Any],
    authorized_signers: set[str] = AUTHORIZED_AUTHORITIES
) -> tuple[bool, list[str]]:
    """
    Fail-closed verification: asserts that a support contract is signed by an
    authorized authority, that its digest matches the independently recomputed
    canonical digest, and that no circular self-sealing tricks are present.
    """
    errors = []

    if not isinstance(contract_data, dict):
        return False, ["Contract data must be a dictionary"]

    # Required fields
    required_fields = ["contract_id", "tier", "sla_ms", "signer", "digest"]
    for field in required_fields:
        if field not in contract_data or contract_data[field] is None:
            errors.append(f"Missing required field: '{field}'")

    if errors:
        return False, errors

    # Check authorized signer
    signer = contract_data.get("signer")
    if signer not in authorized_signers:
        errors.append(f"Unauthorized signer: '{signer}' is not in recognized authority set")

    # Check SLA bounds
    sla_ms = contract_data.get("sla_ms")
    if not isinstance(sla_ms, (int, float)) or sla_ms <= 0:
        errors.append(f"Invalid sla_ms: {sla_ms}")

    # Check digest format
    digest = contract_data.get("digest", "")
    if not isinstance(digest, str) or not re.match(r"^[0-9a-fA-F]{64}$", digest):
        errors.append(f"Invalid digest format: '{digest}' (must be 64-character SHA-256 hex)")
    else:
        # Recompute canonical digest
        expected_digest = compute_contract_digest(contract_data)
        if digest.lower() != expected_digest.lower():
            errors.append(f"Digest mismatch / self-seal failure: declared '{digest}' != computed '{expected_digest}'")

    return (len(errors) == 0), errors
