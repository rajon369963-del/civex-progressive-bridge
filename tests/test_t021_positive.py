"""
⚡ Positive Test for Task T021: Support Contract Digest Authority Court.
"""
import unittest

from civex_bridge.support_contract_court import (
    compute_contract_digest,
    verify_contract_authority,
)


class TestT021Positive(unittest.TestCase):
    def test_canonical_contract_evaluation(self):
        contract = {
            "contract_id": "CIVEX-ENTERPRISE-2026",
            "tier": "enterprise_gold",
            "sla_ms": 50,
            "signer": "CIVEX_ROOT_AUTHORITY_2026",
        }
        digest = compute_contract_digest(contract)
        self.assertEqual(len(digest), 64)
        int(digest, 16)  # Validate hex format

        contract["digest"] = digest
        valid, errors = verify_contract_authority(contract)
        self.assertTrue(valid, f"Canonical contract must pass verification, errors: {errors}")
        self.assertEqual(len(errors), 0)

    def test_digest_excludes_circular_signature_fields(self):
        contract_base = {
            "contract_id": "CIVEX-SECURE-002",
            "tier": "sovereign",
            "sla_ms": 25,
            "signer": "MIGL_AIR10_FEDERATION_AUTHORITY",
        }
        digest_clean = compute_contract_digest(contract_base)

        contract_with_sig = dict(contract_base)
        contract_with_sig["signature"] = "SIG_SAMPLE_123"
        contract_with_sig["signed_at"] = 1789407290.0
        contract_with_sig["digest"] = "DUMMY_DIGEST"

        digest_filtered = compute_contract_digest(contract_with_sig)
        self.assertEqual(digest_clean, digest_filtered, "Digest must strictly exclude circular signature fields")


if __name__ == "__main__":
    unittest.main()
