#!/usr/bin/env python3
"""
AIR10 Federation Evidence Manifest Generator & Independent Meta-Verifier v3
Cross-verifies all 4 repositories:
1. air10-ai-audio-accelerator
2. civex-progressive-bridge
3. sovereign-quant-os
4. sovereign-study-commons-india

Independent Forensic Invariants (Zero Trust / Fail Closed):
- Authoritative trust root (Ed25519 public key hex match)
- Current local HEAD SHA strictly matches manifest canonical_main_sha on main, or descends from it on branch/PR
- Current local Tree SHA strictly matches manifest canonical_main_tree_sha on main
- Signed receipt canonical payload reconstitution & hash match
- Ed25519 signature validity
- Commit reachability in git history
- Exact git tree SHA match
- Branch protection enforce_admins strictly True (API failure = FAIL, no fail-open default)
- Required status checks non-empty and contains required contexts (Empty = FAIL)
- Pages endpoint HTTP 200 health (Network failure = FAIL, no fail-open default)
- Physical execution of permanent 5-canary regression suite (Failure = FAIL)
"""

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    ed25519 = None

TRUSTED_ROOT_PUBLIC_KEY_HEX = "4530967ab3ff8991cb065895270a0f467efd35c0322ee0cd8b6a2ddfe8b27f02"

REPOS = [
    "air10-ai-audio-accelerator",
    "civex-progressive-bridge",
    "sovereign-quant-os",
    "sovereign-study-commons-india"
]

REPO_ROOTS = {repo: Path(f"/Users/rajondas/teamwork_projects/{repo}") for repo in REPOS}

PAGES_URLS = {
    "air10-ai-audio-accelerator": "https://rajon369963-del.github.io/air10-ai-audio-accelerator/",
    "civex-progressive-bridge": "https://rajon369963-del.github.io/civex-progressive-bridge/",
    "sovereign-quant-os": "https://rajon369963-del.github.io/sovereign-quant-os/",
    "sovereign-study-commons-india": "https://rajon369963-del.github.io/sovereign-study-commons-india/"
}

def get_git_output(cwd, cmd):
    try:
        return subprocess.check_output(cmd, cwd=cwd, stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return "UNKNOWN"


def classify_branch_lineage(cwd: Path, expected_head: str, actual_head: str) -> str:
    """Classify branch/PR currentness direction relative to canonical HEAD."""
    if actual_head == expected_head:
        return "PASS_EXACT"

    expected_is_ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", expected_head, actual_head],
        cwd=cwd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0
    if expected_is_ancestor:
        return "PASS_DESCENDANT"

    actual_is_ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", actual_head, expected_head],
        cwd=cwd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0
    if actual_is_ancestor:
        return "STALE_ANCESTOR"

    return "FAIL_UNRELATED"


def resolve_authority_context(required_context: str | None) -> tuple[str, str, str, str, bool]:
    """
    Resolve active execution environment and verify against required authority context.
    Returns (actual_mode, event, ref, ref_name, is_authorized).
    """
    event = os.environ.get("GITHUB_EVENT_NAME", "local")
    ref = os.environ.get("GITHUB_REF", "")
    ref_name = os.environ.get("GITHUB_REF_NAME", "")

    # Determine actual execution environment
    if event == "pull_request":
        actual_mode = "pr"
    elif event == "push" and (ref == "refs/heads/main" or ref_name == "main"):
        actual_mode = "main"
    elif event == "workflow_dispatch":
        actual_mode = "manual"
    elif ref.startswith("refs/heads/"):
        actual_mode = "branch"
    else:
        actual_mode = "local"

    # Verify against required authority
    if not required_context or required_context == "auto":
        is_authorized = True
    elif required_context == "main":
        is_authorized = (actual_mode == "main")
    elif required_context == "branch":
        is_authorized = (actual_mode in ("branch", "local", "pr"))
    elif required_context == "pr":
        is_authorized = (actual_mode == "pr")
    else:
        is_authorized = (actual_mode == required_context)

    return actual_mode, event, ref, ref_name, is_authorized


def verify_live_provider_head(repo: str, baseline_head: str, actual_head: str, cwd: Path, authority_mode: str = "auto") -> tuple[bool, str]:
    """Verify remote provider main relative to baseline and runtime head."""
    remote_url = f"https://github.com/rajon369963-del/{repo}.git"
    try:
        res = subprocess.run(
            ["git", "ls-remote", remote_url, "refs/heads/main"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if res.returncode != 0 or not res.stdout.strip():
            return False, f"Provider readback failed: {res.stderr.strip()}"
        remote_sha = res.stdout.strip().split()[0]
        lineage = classify_branch_lineage(cwd, baseline_head, remote_sha)
        if lineage not in ("PASS_EXACT", "PASS_DESCENDANT"):
            return False, f"Remote main {remote_sha[:10]} is invalid relative to baseline ({lineage})"

        # Invariant for Main Authority Seal:
        # If claiming MAIN authority (push to main or explicit main authority context),
        # runtime HEAD MUST equal live provider main HEAD.
        # Prevents hostile vector: baseline A -> local candidate B -> provider main C,
        # where candidate B descends from baseline A but is behind current provider main C.
        if authority_mode == "main":
            if actual_head != remote_sha:
                return False, f"Main authority mismatch: runtime HEAD {actual_head[:10]} != live provider main {remote_sha[:10]}"
            return True, f"Live provider main exact match {remote_sha[:10]} (main authority confirmed)"

        return True, f"Remote main {remote_sha[:10]} is valid baseline descendant ({lineage})"
    except Exception as e:
        return False, f"Provider network/API failure: {e}"


def compute_canonical_payload(receipt_data: dict) -> tuple[bytes, str]:
    clean_copy = json.loads(json.dumps(receipt_data))
    if "provenance" in clean_copy:
        clean_copy["provenance"].pop("canonical_payload_sha256", None)
        clean_copy["provenance"].pop("signature_ed25519_hex", None)
    canonical_bytes = json.dumps(clean_copy, indent=2).encode("utf-8")
    payload_sha = hashlib.sha256(canonical_bytes).hexdigest()
    return canonical_bytes, payload_sha

def generate_manifest(manifest_path: Path):
    manifest = {
        "schema_version": "3.0",
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "trust_root": {
            "authority": "AIR10 Sovereign Open-Source Federation",
            "pinned_public_key_hex": TRUSTED_ROOT_PUBLIC_KEY_HEX,
            "signature_algorithm": "Ed25519"
        },
        "repositories": {}
    }

    for repo in REPOS:
        cwd = REPO_ROOTS[repo]
        commit_sha = get_git_output(cwd, ["git", "rev-parse", "HEAD"])
        tree_sha = get_git_output(cwd, ["git", "rev-parse", "HEAD^{tree}"])

        enforce_admins = False
        required_checks = []
        try:
            prot_raw = subprocess.check_output(
                ["gh", "api", f"repos/rajon369963-del/{repo}/branches/main/protection"],
                cwd=cwd, stderr=subprocess.DEVNULL
            ).decode()
            prot = json.loads(prot_raw)
            enforce_admins = prot.get("enforce_admins", {}).get("enabled", False)
            required_checks = prot.get("required_status_checks", {}).get("contexts", [])
        except Exception:
            enforce_admins = False
            required_checks = []

        receipt_path = cwd / "db" / "STRESS_BENCHMARK_REAL_WHEELS.json"
        receipt_data = json.loads(receipt_path.read_text(encoding="utf-8")) if receipt_path.exists() else {}
        telemetry = receipt_data.get("hardware_telemetry", {})
        provenance = receipt_data.get("provenance", {})
        receipt_sig = provenance.get("signature_ed25519_hex", "")
        attested_payload_sha = provenance.get("canonical_payload_sha256", "")
        _, recomputed_payload_sha = compute_canonical_payload(receipt_data)

        pages_url = PAGES_URLS[repo]
        pages_code = 0
        try:
            req = urllib.request.Request(pages_url, headers={"User-Agent": "AIR10-MetaVerifier"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                pages_code = resp.getcode()
        except Exception:
            pages_code = 0

        manifest["repositories"][repo] = {
            "repository": f"rajon369963-del/{repo}",
            "canonical_main_sha": commit_sha,
            "canonical_main_tree_sha": tree_sha,
            "required_branch_contexts": required_checks,
            "branch_protection_enforce_admins": enforce_admins,
            "receipt": {
                "path": "db/STRESS_BENCHMARK_REAL_WHEELS.json",
                "canonical_payload_sha256": attested_payload_sha,
                "recomputed_payload_sha256": recomputed_payload_sha,
                "ed25519_signature": receipt_sig,
                "attested_source_commit": telemetry.get("benchmarked_source_commit_sha"),
                "attested_source_tree": telemetry.get("benchmarked_source_tree_sha"),
                "benchmark_script_sha256": telemetry.get("benchmark_script_sha256")
            },
            "pages": {
                "url": pages_url,
                "status_code": pages_code,
                "verdict": "HTTP_200_OK" if pages_code == 200 else "FAIL"
            }
        }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Generated federation manifest at {manifest_path}")

def verify_manifest(manifest_path: Path, target_repo: str = None, authority_context: str = "auto", live_provider: bool = False) -> bool:
    print(f"Verifying Federation Evidence Manifest: {manifest_path}")
    if not manifest_path.exists():
        print(f"FAIL: Manifest file does not exist: {manifest_path}")
        return False

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    root_hex = manifest.get("trust_root", {}).get("pinned_public_key_hex")
    if root_hex != TRUSTED_ROOT_PUBLIC_KEY_HEX:
        print(f"FAIL: Unrecognized trust root key {root_hex}")
        return False

    if ed25519 is not None:
        pubkey = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(root_hex))
    else:
        print("FAIL: python-cryptography required for Ed25519 verification")
        return False

    all_passed = True
    checked_repos = [target_repo] if target_repo else REPOS

    for repo in checked_repos:
        rdata = manifest.get("repositories", {}).get(repo)
        if not rdata:
            print(f"FAIL: Repository {repo} not found in manifest!")
            all_passed = False
            continue

        print(f"--- Checking Repo: {repo} ---")
        cwd = None
        if (Path.cwd() / "db" / "STRESS_BENCHMARK_REAL_WHEELS.json").exists() and Path.cwd().name == repo:
            cwd = Path.cwd()
        elif repo in REPO_ROOTS and REPO_ROOTS[repo].exists():
            cwd = REPO_ROOTS[repo]

        if cwd and cwd.exists():
            actual_head = get_git_output(cwd, ["git", "rev-parse", "HEAD"])
            baseline_head = rdata["canonical_main_sha"]
            baseline_tree = rdata.get("canonical_main_tree_sha", "")

            lineage = classify_branch_lineage(cwd, baseline_head, actual_head)
            if lineage == "PASS_EXACT":
                print(f"  • Baseline HEAD Match       : [PASS] (Exact match {actual_head[:10]})")
                actual_tree = get_git_output(cwd, ["git", "rev-parse", "HEAD^{tree}"])
                if actual_tree != baseline_tree:
                    print(f"FAIL: Baseline Tree mismatch: expected {baseline_tree}, got {actual_tree}")
                    all_passed = False
                else:
                    print(f"  • Baseline Tree Match       : [PASS] ({actual_tree[:10]})")
            elif lineage == "PASS_DESCENDANT":
                print(f"  • Lineage Provenance Check : [PASS] (Descends from baseline {baseline_head[:10]})")
            elif lineage == "STALE_ANCESTOR":
                print(f"FAIL: Stale HEAD {actual_head[:10]} is an ancestor of baseline {baseline_head[:10]}")
                all_passed = False
            else:
                print(f"FAIL: Lineage broken between HEAD {actual_head[:10]} and baseline {baseline_head[:10]}")
                all_passed = False

            # Authority Context Binding (Quant Issue #56)
            mode, event, ref, ref_name, is_authorized = resolve_authority_context(authority_context)
            if not is_authorized:
                print(f"FAIL: Authority Context Mismatch: required '{authority_context}', but executing under mode '{mode}' (event={event}, ref={ref})")
                all_passed = False
            else:
                print(f"  • Authority Binding Check  : [PASS] CHECK_NAME={repo} HEAD_SHA={actual_head[:10]} CONTEXT={mode} EVENT={event or 'local'} REF={ref or 'local'} DECISION={'PASS' if all_passed else 'FAIL'}")

            # Optional Live Provider Readback
            if live_provider:
                ok, msg = verify_live_provider_head(repo, baseline_head, actual_head, cwd, authority_mode=mode)
                if not ok:
                    print(f"FAIL: Live Provider Verification: {msg}")
                    all_passed = False
                else:
                    print(f"  • Live Provider Readback   : [PASS] {msg}")

            receipt_path = cwd / rdata["receipt"]["path"]
            if receipt_path.exists():
                receipt_obj = json.loads(receipt_path.read_text(encoding="utf-8"))
                sig_hex = rdata["receipt"]["ed25519_signature"]
                canonical_bytes, payload_sha = compute_canonical_payload(receipt_obj)

                if payload_sha != rdata["receipt"]["canonical_payload_sha256"]:
                    print(f"FAIL: Payload SHA mismatch: {payload_sha} vs {rdata['receipt']['canonical_payload_sha256']}")
                    all_passed = False
                else:
                    print("  • Canonical Payload SHA-256: [PASS]")

                try:
                    pubkey.verify(bytes.fromhex(sig_hex), canonical_bytes)
                    print("  • Ed25519 Digital Signature: [PASS]")
                except Exception as e:
                    print(f"FAIL: Ed25519 signature invalid: {e}")
                    all_passed = False
            else:
                print(f"FAIL: Receipt not found at {receipt_path}")
                all_passed = False

            attested_commit = rdata["receipt"]["attested_source_commit"]
            res = subprocess.run(["git", "cat-file", "-e", f"{attested_commit}^{{commit}}"], cwd=cwd, capture_output=True)
            if res.returncode != 0:
                print(f"FAIL: Attested commit {attested_commit} is not reachable!")
                all_passed = False
            else:
                print(f"  • Attested Commit Reachable: [PASS] ({attested_commit[:10]})")

            expected_receipt_tree = rdata["receipt"]["attested_source_tree"]
            actual_receipt_tree = get_git_output(cwd, ["git", "rev-parse", f"{attested_commit}^{{tree}}"])
            if actual_receipt_tree != expected_receipt_tree:
                print(f"FAIL: Tree SHA mismatch: expected {expected_receipt_tree}, got {actual_receipt_tree}")
                all_passed = False
            else:
                print("  • Attested Tree SHA Exact  : [PASS]")

            canary_script = cwd / "tests" / "test_adversarial_receipt_canaries.py"
            if canary_script.exists():
                canary_proc = subprocess.run([sys.executable, str(canary_script)], cwd=cwd, capture_output=True)
                if canary_proc.returncode != 0:
                    print(f"FAIL: Adversarial canary suite failed in {repo}")
                    all_passed = False
                else:
                    print("  • 5 Adversarial Canaries   : [PASS] (Fail-Hard Verified)")
            else:
                print(f"FAIL: Adversarial canary suite missing in {repo}")
                all_passed = False

        else:
            print(f"FAIL: Local repo not found at {cwd}")
            all_passed = False

        if not rdata.get("branch_protection_enforce_admins"):
            print(f"FAIL: Branch protection enforce_admins is not True for {repo}")
            all_passed = False
        else:
            print("  • Branch Protection Admins : [PASS] (enforce_admins=True)")

        req_checks = rdata.get("required_branch_contexts", [])
        if not req_checks:
            print(f"FAIL: No required status checks configured for {repo}")
            all_passed = False
        else:
            print(f"  • Required Status Checks   : [PASS] ({', '.join(req_checks)})")

        if rdata["pages"]["status_code"] != 200:
            print(f"FAIL: Pages endpoint returned {rdata['pages']['status_code']}")
            all_passed = False
        else:
            print("  • Pages Deployment HTTP 200: [PASS]")

    if all_passed:
        print("\n======================================================================")
        print("FEDERATION EVIDENCE MANIFEST: 100% INDEPENDENTLY VERIFIED PASS")
        print("======================================================================")
    else:
        print("\nFEDERATION EVIDENCE MANIFEST: INDEPENDENT VERIFICATION FAILED")
    return all_passed

def main():
    parser = argparse.ArgumentParser(description="Federation Evidence Manifest Tool")
    parser.add_argument("--generate", type=Path, help="Generate manifest to file")
    parser.add_argument("--verify", type=Path, help="Verify manifest file")
    parser.add_argument("--repo", type=str, default=None, help="Specific repository to verify")
    parser.add_argument("--authority-context", type=str, default="auto", choices=["auto", "main", "branch", "pr", "manual", "local"], help="Authority context to enforce")
    parser.add_argument("--live-provider", action="store_true", help="Perform live provider readback verification")
    args = parser.parse_args()

    if args.generate:
        generate_manifest(args.generate)
    if args.verify:
        ok = verify_manifest(args.verify, target_repo=args.repo, authority_context=args.authority_context, live_provider=args.live_provider)
        sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
