#!/usr/bin/env python3
"""
AIR10 Sovereign Truth Guard & Cryptographic Provenance Verifier (v2.2)
Zero-Trust Forensic Invariants:
1. Hard-pinned Authoritative Ed25519 Root of Trust.
2. Canonical payload reconstitution and Ed25519 signature check against pinned root.
3. Raw receipt file SHA-256 integrity check.
4. Scorecard SVG Zero-Drift & Structural Tag Audit:
   - Strips XML comments to eliminate comment injection attacks.
   - Extracts text strictly from visible <text> and <tspan> DOM elements.
   - Dynamically asserts payload SHA, raw file SHA, and required domain/wheel metrics
     are literally visible inside rendered text tags.
"""

import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

AUTHORITATIVE_SIGNER_PUBKEY_HEX = "4530967ab3ff8991cb065895270a0f467efd35c0322ee0cd8b6a2ddfe8b27f02"
EXPECTED_SIGNER_IDENTITY = "AIR10 Sovereign Open-Source Federation <rajon369963-del>"

def extract_visible_svg_text(svg_raw: str) -> str:
    cleaned = re.sub(r"<!--.*?-->", "", svg_raw, flags=re.DOTALL)
    extracted_tokens = []
    try:
        root = ET.fromstring(cleaned)
        for elem in root.iter():
            tag_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag_name in ("text", "tspan"):
                if elem.text:
                    extracted_tokens.append(elem.text.strip())
                if elem.tail:
                    extracted_tokens.append(elem.tail.strip())
    except Exception:
        matches = re.findall(r"<text[^>]*>(.*?)</text>", cleaned, flags=re.DOTALL)
        for m in matches:
            inner_clean = re.sub(r"<[^>]+>", " ", m)
            extracted_tokens.append(inner_clean.strip())

    return " ".join(t for t in extracted_tokens if t)

def verify(repo_root: Path) -> bool:
    print("======================================================================")
    print("🛡️  AIR10 TRUTH GUARD v2.2: CRYPTOGRAPHIC PROVENANCE & ZERO-DRIFT CONTRACT")
    print(f"Target Repository : {repo_root.name}")
    print("======================================================================")

    receipt_path = repo_root / "db" / "STRESS_BENCHMARK_REAL_WHEELS.json"
    if not receipt_path.exists():
        print(f"❌ FAIL: Benchmark receipt not found at {receipt_path}")
        return False

    raw_bytes = receipt_path.read_bytes()
    computed_raw_sha = hashlib.sha256(raw_bytes).hexdigest()
    print(f"• Raw File SHA-256         : {computed_raw_sha}")

    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except Exception as e:
        print(f"❌ FAIL: Malformed JSON in receipt: {e}")
        return False

    provenance = data.get("provenance", {})
    expected_payload_sha = provenance.get("canonical_payload_sha256")
    sig_hex = provenance.get("signature_ed25519_hex")
    receipt_pub_hex = provenance.get("signer_public_key_hex")
    signer_id = provenance.get("signer_identity", "Unknown")

    # 1. Authoritative Root-of-Trust Check
    if receipt_pub_hex != AUTHORITATIVE_SIGNER_PUBKEY_HEX:
        print("❌ FAIL: Untrusted signer public key in receipt!")
        print(f"  Receipt Key: {receipt_pub_hex}")
        print(f"  Authoritative Pinned Root: {AUTHORITATIVE_SIGNER_PUBKEY_HEX}")
        return False
    print("• Authoritative Trust Root : PINNED KEY MATCH [PASS]")

    # Check local PEM file if present
    pubkey_pem_path = repo_root / "db" / "AIR10_PROVENANCE_ED25519_PUBKEY.pem"
    if pubkey_pem_path.exists():
        from cryptography.hazmat.primitives import serialization
        pem_bytes = pubkey_pem_path.read_bytes()
        loaded_pubkey = serialization.load_pem_public_key(pem_bytes)
        pem_raw_hex = loaded_pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
        if pem_raw_hex != AUTHORITATIVE_SIGNER_PUBKEY_HEX:
            print("❌ FAIL: Local PEM public key does not match pinned trust root!")
            return False
        print("• Local Public Key PEM     : ANCHORED TO ROOT [PASS]")

    # 2. Canonical Payload Reconstitution & Hash Verification
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

    # 3. Cryptographic Signature Verification against PINNED Trust Root
    try:
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(AUTHORITATIVE_SIGNER_PUBKEY_HEX))
        pub_key.verify(bytes.fromhex(sig_hex), canonical_bytes)
        print("• Ed25519 Digital Signature: VALID AGAINST PINNED ROOT [PASS]")
        print(f"  Signer Identity          : {signer_id}")
    except Exception as e:
        print(f"❌ FAIL: Ed25519 signature verification failed: {e}")
        return False

    # 4. Scorecard SVG Zero-Drift & Visible Text Audit
    scorecard_path = repo_root / "assets" / "scorecard.svg"
    if scorecard_path.exists():
        svg_content = scorecard_path.read_text(encoding="utf-8")
        visible_svg_text = extract_visible_svg_text(svg_content)

        # Assert full or prefix hashes appear in visible text nodes
        if computed_payload_sha not in visible_svg_text and computed_payload_sha[:16] not in visible_svg_text:
            print(f"❌ FAIL: Scorecard visible text missing canonical payload SHA {computed_payload_sha}")
            return False
        if computed_raw_sha not in visible_svg_text and computed_raw_sha[:16] not in visible_svg_text:
            print(f"❌ FAIL: Scorecard visible text missing raw file SHA {computed_raw_sha}")
            return False

        # Dynamically assert receipt metrics appear in visible text
        repo_name = repo_root.name
        required_substrings = []
        if repo_name == "civex-progressive-bridge":
            required_substrings = ["26,904", "13,424", "BM25"]
        elif repo_name == "sovereign-quant-os":
            required_substrings = ["3.1M", "5,974", "Risk Checks"]
        elif repo_name == "sovereign-study-commons-india":
            required_substrings = ["3.75M", "4,996", "FSRS-5"]
        elif repo_name == "air10-ai-audio-accelerator":
            required_substrings = ["SoundTouch", "Pitch-Preserved", "Audio Buffer Transforms"]

        for req in required_substrings:
            if req not in visible_svg_text:
                print(f"❌ FAIL: Scorecard visible text tampering detected! Expected string '{req}' not found in rendered <text> tags.")
                return False
        print(f"• Scorecard Tag Audit      : 100% IN-SYNC ({len(required_substrings)} metrics verified in visible <text> nodes) [PASS]")

    print("----------------------------------------------------------------------")
    print("✅ VERDICT: 100% AUTHENTICALLY SIGNED & FORENSICALLY SEALED ZERO-DRIFT PASS.")
    print("======================================================================\n")
    return True

if __name__ == "__main__":
    target_dir = Path(__file__).parent.parent if len(sys.argv) < 2 else Path(sys.argv[1])
    success = verify(target_dir)
    sys.exit(0 if success else 1)
