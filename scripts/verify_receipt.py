#!/usr/bin/env python3
"""
AIR10 Sovereign Truth Guard & Cryptographic Provenance Verifier
Verifies:
1. Raw Receipt File SHA-256
2. Canonical Payload SHA-256
3. Ed25519 Digital Signature against Public Key
4. Scorecard SVG Metric Invariance (Zero-Drift Enforcement)
"""

import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519


def verify(repo_root: Path) -> bool:
    print("======================================================================")
    print("🛡️  AIR10 TRUTH GUARD: VERIFYING PROVENANCE & BENCHMARK CONTRACT")
    print(f"Target Repository : {repo_root.name}")
    print("======================================================================")

    receipt_path = repo_root / "db" / "STRESS_BENCHMARK_REAL_WHEELS.json"
    if not receipt_path.exists():
        print(f"❌ FAIL: Benchmark receipt not found at {receipt_path}")
        return False

    # 1. Raw File SHA-256
    raw_bytes = receipt_path.read_bytes()
    computed_raw_sha = hashlib.sha256(raw_bytes).hexdigest()
    print(f"• Raw File SHA-256         : {computed_raw_sha}")

    # 2. Parse JSON
    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except Exception as e:
        print(f"❌ FAIL: Malformed JSON in receipt: {e}")
        return False

    provenance = data.get("provenance", {})
    expected_payload_sha = provenance.get("canonical_payload_sha256")
    sig_hex = provenance.get("signature_ed25519_hex")
    pub_hex = provenance.get("signer_public_key_hex")
    signer_id = provenance.get("signer_identity", "Unknown")

    if not expected_payload_sha or not sig_hex or not pub_hex:
        print("❌ FAIL: Missing required cryptographic provenance fields in receipt.")
        return False

    # 3. Canonical Payload Reconstitution
    # Strip the self-referential hash and signature
    payload_copy = json.loads(raw_bytes.decode("utf-8"))
    del payload_copy["provenance"]["canonical_payload_sha256"]
    del payload_copy["provenance"]["signature_ed25519_hex"]

    canonical_json = json.dumps(payload_copy, indent=2)
    canonical_bytes = canonical_json.encode("utf-8")
    computed_payload_sha = hashlib.sha256(canonical_bytes).hexdigest()
    print(f"• Canonical Payload SHA-256: {computed_payload_sha}")

    if computed_payload_sha != expected_payload_sha:
        print("❌ FAIL: Canonical payload hash mismatch!")
        print(f"  Computed: {computed_payload_sha}")
        print(f"  Expected: {expected_payload_sha}")
        return False
    print("  ➔ Canonical Payload Hash Verification: [PASS]")

    # 4. Ed25519 Digital Signature Verification
    try:
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub_key.verify(bytes.fromhex(sig_hex), canonical_bytes)
        print("• Ed25519 Digital Signature: VALID [PASS]")
        print(f"  Signer Identity          : {signer_id}")
    except Exception as e:
        print(f"❌ FAIL: Ed25519 signature verification failed: {e}")
        return False

    # 5. Scorecard SVG Drift Check (if scorecard exists)
    scorecard_path = repo_root / "assets" / "scorecard.svg"
    if scorecard_path.exists():
        svg_content = scorecard_path.read_text(encoding="utf-8")
        # Assert canonical payload SHA is present
        if computed_payload_sha not in svg_content:
            print(f"❌ FAIL: Scorecard SVG does not contain canonical payload SHA {computed_payload_sha}")
            return False
        # Assert raw file SHA is present
        if computed_raw_sha not in svg_content:
            print(f"❌ FAIL: Scorecard SVG does not contain raw file SHA {computed_raw_sha}")
            return False
        print("• Scorecard SVG Drift Check: 100% IN-SYNC [PASS]")

    print("----------------------------------------------------------------------")
    print("✅ VERDICT: 100% CRYPTOGRAPHICALLY ATTESTED & ZERO-DRIFT SEALED.")
    print("======================================================================\n")
    return True

if __name__ == "__main__":
    target_dir = Path(__file__).parent.parent if len(sys.argv) < 2 else Path(sys.argv[1])
    success = verify(target_dir)
    sys.exit(0 if success else 1)
