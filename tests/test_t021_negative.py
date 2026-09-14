"""
⚡ Negative Test & Mutant Kills for Task T021: Support Contract Authority Court.
"""
import copy
import json
import os
import unittest

from civex_bridge.support_contract_court import (
    compute_contract_digest,
    verify_contract_authority,
)


class TestT021Negative(unittest.TestCase):
    def setUp(self):
        self.repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.known_bad_path = os.path.join(self.repo_root, "tests", "fixtures", "known_bad_t021.json")

    def test_known_bad_fixture_rejected(self):
        self.assertTrue(os.path.exists(self.known_bad_path), "known_bad_t021.json fixture must exist")
        with open(self.known_bad_path, "r", encoding="utf-8") as f:
            bad_data = json.load(f)

        contract = bad_data["support_contract"]
        valid, errors = verify_contract_authority(contract)
        self.assertFalse(valid, "Known-bad self-sealed contract MUST be rejected")
        self.assertGreaterEqual(len(errors), 2)

    def test_mutant_unauthorized_signer(self):
        valid_contract = {
            "contract_id": "CIVEX-SAMPLE-001",
            "tier": "gold",
            "sla_ms": 100,
            "signer": "CIVEX_ROOT_AUTHORITY_2026",
        }
        valid_contract["digest"] = compute_contract_digest(valid_contract)

        mutant = copy.deepcopy(valid_contract)
        mutant["signer"] = "rogue_signer"
        # Recompute digest with rogue signer to test authority gate specifically
        mutant["digest"] = compute_contract_digest(mutant)

        valid, errors = verify_contract_authority(mutant)
        self.assertFalse(valid, "Contract with unauthorized signer must be rejected")
        self.assertTrue(any("Unauthorized signer" in e for e in errors))

    def test_mutant_tampered_payload_hash_mismatch(self):
        valid_contract = {
            "contract_id": "CIVEX-SAMPLE-001",
            "tier": "gold",
            "sla_ms": 100,
            "signer": "CIVEX_ROOT_AUTHORITY_2026",
        }
        valid_contract["digest"] = compute_contract_digest(valid_contract)

        # Tamper with sla_ms after digest was calculated
        mutant = copy.deepcopy(valid_contract)
        mutant["sla_ms"] = 10  # Unauthorized SLA elevation
        valid, errors = verify_contract_authority(mutant)
        self.assertFalse(valid, "Tampered payload must fail digest verification")
        self.assertTrue(any("Digest mismatch" in e for e in errors))

    def test_mutant_negative_sla(self):
        contract = {
            "contract_id": "CIVEX-SAMPLE-002",
            "tier": "gold",
            "sla_ms": -50,
            "signer": "CIVEX_ROOT_AUTHORITY_2026",
        }
        contract["digest"] = compute_contract_digest(contract)
        valid, errors = verify_contract_authority(contract)
        self.assertFalse(valid, "Negative SLA must be rejected")
        self.assertTrue(any("Invalid sla_ms" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
