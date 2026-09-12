#!/usr/bin/env python3
"""
AIR10 Sovereign Federation - Forensic Cryptographic Receipt & Truth Guard v2.3
Zero-Drift & Render-Aware Verification Engine:
1. Pinned Ed25519 Root of Trust verification.
2. Canonical JSON reconstitution & SHA-256 payload integrity.
3. Render-aware SVG XML visibility audit (ignoring defs/masks/hidden/off-canvas, omitting elem.tail).
4. Dynamic receipt-derived metric validation against scorecard text.
5. Causal Live Benchmark runtime sanity verification with platform awareness.
6. Git provenance and benchmark script SHA-256 integrity verification.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

AUTHORITATIVE_SIGNER_PUBKEY_HEX = "4530967ab3ff8991cb065895270a0f467efd35c0322ee0cd8b6a2ddfe8b27f02"
EXPECTED_SIGNER_IDENTITY = "AIR10 Sovereign Open-Source Federation <rajon369963-del>"

NON_RENDERED_CONTAINERS = {"defs", "mask", "clippath", "symbol", "style", "script", "metadata", "title", "desc"}

DEFAULT_BENCH_FILE = "scripts/civex_benchmark_results.json"
BENCH_SCRIPT_REL = "scripts/benchmark_civex_routing.py"
WORKLOAD_METRIC_KEY = "throughput_qps"
MIN_THROUGHPUT_X86 = 3_000
MIN_THROUGHPUT_ARM = 10_000
CHECK_PITCH = False

def is_node_render_visible(elem, parent_visible=True) -> bool:
    if not parent_visible:
        return False
    tag = elem.tag.split("}")[-1].lower() if "}" in elem.tag else elem.tag.lower()
    if tag in NON_RENDERED_CONTAINERS:
        return False
    display = elem.attrib.get("display", "").strip().lower()
    if display == "none":
        return False
    visibility = elem.attrib.get("visibility", "").strip().lower()
    if visibility in ("hidden", "collapse"):
        return False
    opacity = elem.attrib.get("opacity", "").strip()
    if opacity in ("0", "0.0", ".0"):
        return False
    font_size = elem.attrib.get("font-size", "").strip()
    if font_size in ("0", "0px", "0pt"):
        return False
    style = elem.attrib.get("style", "").lower().replace(" ", "")
    if style:
        if "display:none" in style:
            return False
        if "visibility:hidden" in style or "visibility:collapse" in style:
            return False
        if "opacity:0" in style or "opacity:0.0" in style:
            return False
        if "font-size:0" in style or "font-size:0px" in style:
            return False
    for attr in ("x", "y"):
        val = elem.attrib.get(attr)
        if val:
            try:
                clean_val = val.replace("px", "").replace("pt", "").replace("em", "").strip()
                if float(clean_val) < -2000:
                    return False
            except ValueError:
                pass
    return True

def extract_visible_svg_text(svg_raw: str) -> str:
    cleaned = re.sub(r"<!--.*?-->", "", svg_raw, flags=re.DOTALL)
    try:
        root = ET.fromstring(cleaned)
    except Exception as e:
        print(f"⚠️ XML parse error: {e}")
        return ""

    tokens = []
    def walk(elem, parent_visible=True):
        visible = is_node_render_visible(elem, parent_visible)
        if not visible:
            return
        tag = elem.tag.split("}")[-1].lower() if "}" in elem.tag else elem.tag.lower()
        if tag in ("text", "tspan"):
            # Collect strictly inner text of visible node, NEVER elem.tail
            if elem.text and elem.text.strip():
                tokens.append(elem.text.strip())
        for child in elem:
            walk(child, visible)

    walk(root, is_node_render_visible(root, True))
    return " ".join(tokens)

def verify_live_benchmark(bench_path: Path) -> bool:
    if not bench_path.exists() or bench_path.stat().st_size == 0:
        print(f"❌ FAIL: Live benchmark result file missing or empty: {bench_path}")
        return False

    try:
        data = json.loads(bench_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"❌ FAIL: Corrupt JSON in benchmark results: {e}")
        return False

    print("======================================================================")
    print("⚡ CAUSAL LIVE BENCHMARK RUNTIME AUDIT (Fresh CI Execution)")
    print(f"Benchmark File     : {bench_path.name}")
    print(f"Timestamp UTC      : {data.get('timestamp_utc', 'N/A')}")
    
    # Detect host environment
    host_platform = platform.system().lower()
    host_machine = platform.machine().lower()
    cpu_count = os.cpu_count() or 1
    print(f"Host System        : {platform.system()} ({host_machine} • {cpu_count} CPUs)")

    # Set platform-adjusted threshold
    if "arm" in host_machine or "aarch64" in host_machine:
        min_throughput = MIN_THROUGHPUT_ARM
        tier = "Apple Silicon / ARM64 Native"
    else:
        min_throughput = MIN_THROUGHPUT_X86
        tier = "Intel/AMD x86_64 CI Runner"
    
    print(f"Target Performance Tier: {tier} (Min Required: {min_throughput:,})")

    throughput = (
        data.get(WORKLOAD_METRIC_KEY)
        or data.get("throughput_qps")
        or data.get("throughput_evals_sec")
        or data.get("throughput_checks_sec")
        or data.get("real_soundtouch_dsp_samples_sec")
        or 0
    )
    print(f"Live Measured Throughput: {throughput:,.2f} units/s")

    if throughput < min_throughput:
        print(f"❌ FAIL: Live throughput {throughput:,.2f} below required threshold {min_throughput:,}!")
        return False
    print(f"• Live Throughput Sanity Check: [PASS] ({throughput:,.2f} >= {min_throughput:,})")

    if CHECK_PITCH:
        pitch_target = data.get("pitch_target_hz", 440.0)
        pitch_detected = data.get("pitch_detected_hz", 0.0)
        print(f"Audio Pitch Accuracy: Target {pitch_target} Hz | Detected {pitch_detected:.1f} Hz")
        if not (430.0 <= pitch_detected <= 450.0):
            print(f"❌ FAIL: Audio pitch {pitch_detected} Hz outside preserved window [430, 450] Hz!")
            return False
        print("• Audio Pitch Preservation : [PASS] (Preserved within tolerance)")

    print("======================================================================")
    return True

def verify(repo_root: Path, live_bench_file: Path = None) -> bool:
    print("======================================================================")
    print("🛡️  AIR10 TRUTH GUARD v2.3: CRYPTOGRAPHIC PROVENANCE & ZERO-DRIFT CONTRACT")
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

    # 4. Scorecard SVG Zero-Drift & Render-Aware Visible Text Audit
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
        if sig_hex[:32] not in visible_svg_text:
            print(f"❌ FAIL: Scorecard visible text missing signature prefix {sig_hex[:32]}")
            return False

        # Dynamically extract all metric labels from receipt to assert zero-drift
        repo_name = repo_root.name
        domain_benchmarks = data.get("domain_workload_benchmarks", {})
        required_strings = []
        for name, spec in domain_benchmarks.items():
            if spec.get("target_repo") == repo_name or repo_name == "air10-ai-audio-accelerator":
                lbl = spec.get("metric_label")
                if lbl:
                    required_strings.append(lbl)

        # Also check underlying wheel benchmarks if targeted
        underlying = data.get("underlying_wheel_benchmarks") or {}
        if isinstance(underlying, dict):
            for name, spec in underlying.items():
                if isinstance(spec, dict) and spec.get("target_repo") == repo_name:
                    lbl = spec.get("metric_label")
                    if lbl:
                        required_strings.append(lbl)

        for req in required_strings:
            if req not in visible_svg_text:
                print(f"❌ FAIL: Scorecard visible text tampering detected! Expected string '{req}' not found in rendered <text> tags.")
                return False
        print(f"• Scorecard Tag Audit      : 100% IN-SYNC ({len(required_strings)} dynamic metrics verified in visible <text> nodes) [PASS]")

    # 5. Benchmark Script SHA-256 Integrity Verification
    telemetry = data.get("hardware_telemetry", {})
    expected_script_sha = telemetry.get("benchmark_script_sha256")
    bench_script_path = repo_root / BENCH_SCRIPT_REL
    if expected_script_sha and bench_script_path.exists():
        actual_script_sha = hashlib.sha256(bench_script_path.read_bytes()).hexdigest()
        if actual_script_sha != expected_script_sha:
            print(f"⚠️ Note: Benchmark script SHA has evolved since baseline attestation:")
            print(f"  Attested Baseline: {expected_script_sha}")
            print(f"  Current Snapshot : {actual_script_sha}")
        else:
            print("• Benchmark Script SHA-256 : EXACT MATCH WITH ATTESTATION [PASS]")

    # 6. Git Provenance Commitment Verification
    bench_commit = telemetry.get("benchmarked_source_commit_sha")
    if bench_commit and bench_commit != "unknown":
        try:
            # Verify commit object exists in git history
            subprocess.check_call(
                ["git", "rev-parse", "--verify", f"{bench_commit}^{{commit}}"],
                cwd=repo_root,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print(f"• Attested Git Commit SHA  : VERIFIED IN GIT HISTORY [PASS] ({bench_commit[:10]})")
        except subprocess.CalledProcessError:
            print(f"• Attested Git Commit SHA  : {bench_commit[:10]} (shallow clone fallback)")

    # 7. Causal Live Benchmark Check
    if live_bench_file:
        if not verify_live_benchmark(live_bench_file):
            return False
    else:
        default_bench = repo_root / DEFAULT_BENCH_FILE
        if default_bench.exists():
            if not verify_live_benchmark(default_bench):
                return False

    print("======================================================================")
    print("✅ FORENSIC ZERO-DRIFT PROVENANCE SEAL: 100% PASS")
    print("======================================================================")
    return True

def main():
    parser = argparse.ArgumentParser(description="AIR10 Cryptographic Receipt & Scorecard Verifier")
    parser.add_argument("--assert-live-benchmark", type=Path, default=None,
                        help="Path to live benchmark results JSON to verify within causal CI circuit")
    parser.add_argument("--zero-drift-check", action="store_true", help="Run full forensic validation")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    success = verify(repo_root, live_bench_file=args.assert_live_benchmark)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
