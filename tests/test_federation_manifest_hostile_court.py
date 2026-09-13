#!/usr/bin/env python3
"""
AIR10 Federation Manifest Hostile Court (Study Issue #108, CIVEX Issue #38, Quant Issue #56)

Guarantees fail-hard behavior on:
1. NORMAL_MERGE_ADVANCES_HEAD_BASELINE_UNCHANGED: Forward descendant advances HEAD past baseline without self-staling (PASS_DESCENDANT).
2. STALE_ANCESTOR_CHECKOUT: Outdated ancestor HEAD is rejected fail-closed (STALE_ANCESTOR).
3. UNRELATED_HISTORY: Divergent or orphan commits are rejected fail-closed (FAIL_UNRELATED).
4. AUTHORITY_CONTEXT_MISMATCH (Quant #56): Alternate-ref (PR/feature) check runs attempting to claim main authority are rejected fail-hard.
5. AUTHORITY_CONTEXT_MATCH: True main push ref correctly satisfies main authority context.
6. LIVE_PROVIDER_FAIL_CLOSED: Unreachable provider or broken lineage on remote fails closed (no fail-open default).
"""

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "verify_federation_manifest.py"

spec = importlib.util.spec_from_file_location("air10_federation_verifier", VERIFIER)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

classify_branch_lineage = module.classify_branch_lineage
resolve_authority_context = module.resolve_authority_context
verify_live_provider_head = module.verify_live_provider_head


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def commit(repo: Path, value: str) -> str:
    (repo / "state.txt").write_text(value, encoding="utf-8")
    subprocess.check_call(["git", "add", "state.txt"], cwd=repo)
    subprocess.check_call(["git", "commit", "-m", f"state-{value}"], cwd=repo, stdout=subprocess.DEVNULL)
    return git(repo, "rev-parse", "HEAD")


def build_dag(repo: Path):
    subprocess.check_call(["git", "init", "-q"], cwd=repo)
    git(repo, "config", "user.email", "air10-manifest-court@example.invalid")
    git(repo, "config", "user.name", "AIR10 Manifest Court")
    a = commit(repo, "A")
    b = commit(repo, "B")
    c = commit(repo, "C")
    d = commit(repo, "D")
    subprocess.check_call(["git", "checkout", "--orphan", "unrelated"], cwd=repo, stdout=subprocess.DEVNULL)
    for path in repo.iterdir():
        if path.name != ".git" and path.is_file():
            path.unlink()
    unrelated = commit(repo, "U")
    return a, b, c, d, unrelated


class FederationManifestHostileCourt(unittest.TestCase):
    def test_directional_lineage_and_advancement(self):
        with tempfile.TemporaryDirectory(prefix="air10-manifest-lineage-") as tmp:
            repo = Path(tmp)
            a, b, c, d, unrelated = build_dag(repo)

            # 1. Exact match to baseline
            self.assertEqual(classify_branch_lineage(repo, c, c), "PASS_EXACT")

            # 2. Forward advancement (normal merge) past baseline
            self.assertEqual(classify_branch_lineage(repo, c, d), "PASS_DESCENDANT")

            # 3. Stale ancestor checkout
            self.assertEqual(classify_branch_lineage(repo, c, b), "STALE_ANCESTOR")
            self.assertEqual(classify_branch_lineage(repo, c, a), "STALE_ANCESTOR")

            # 4. Unrelated history
            self.assertEqual(classify_branch_lineage(repo, c, unrelated), "FAIL_UNRELATED")

    def test_authority_context_binding_quant_56_adapter(self):
        """Quant Issue #56: Alternate-ref runs must NOT certify main authority."""
        saved_env = os.environ.copy()
        try:
            # Vector 1: PR run attempting to certify main authority
            os.environ["GITHUB_EVENT_NAME"] = "pull_request"
            os.environ["GITHUB_REF"] = "refs/pull/49/merge"
            os.environ["GITHUB_REF_NAME"] = "49/merge"
            mode, event, ref, ref_name, is_auth = resolve_authority_context("main")
            self.assertEqual(mode, "pr")
            self.assertFalse(is_auth, "Security Failure: PR context satisfied required main authority!")

            # Vector 2: Feature branch push attempting to certify main authority
            os.environ["GITHUB_EVENT_NAME"] = "push"
            os.environ["GITHUB_REF"] = "refs/heads/feat/quant49-receipt-discriminator"
            os.environ["GITHUB_REF_NAME"] = "feat/quant49-receipt-discriminator"
            os.environ["GITHUB_REF_NAME"] = "feat/quant49-receipt-discriminator"
            mode, event, ref, ref_name, is_auth = resolve_authority_context("main")
            self.assertEqual(mode, "branch")
            self.assertFalse(is_auth, "Security Failure: Feature branch satisfied required main authority!")

            # Vector 3: True main push
            os.environ["GITHUB_EVENT_NAME"] = "push"
            os.environ["GITHUB_REF"] = "refs/heads/main"
            os.environ["GITHUB_REF_NAME"] = "main"
            mode, event, ref, ref_name, is_auth = resolve_authority_context("main")
            self.assertEqual(mode, "main")
            self.assertTrue(is_auth, "Main push must satisfy required main authority")

            # Vector 4: Auto mode does not force main constraint
            os.environ["GITHUB_EVENT_NAME"] = "push"
            os.environ["GITHUB_REF"] = "refs/heads/feat/quant49-receipt-discriminator"
            os.environ["GITHUB_REF_NAME"] = "feat/quant49-receipt-discriminator"
            mode, event, ref, ref_name, is_auth = resolve_authority_context("auto")
            self.assertEqual(mode, "branch")
            self.assertTrue(is_auth)

        finally:
            os.environ.clear()
            os.environ.update(saved_env)

    def test_live_provider_fail_closed(self):
        """Live provider readback must fail-closed on unreachable / non-existent target."""
        with tempfile.TemporaryDirectory(prefix="air10-provider-") as tmp:
            repo = Path(tmp)
            build_dag(repo)
            ok, msg = verify_live_provider_head("non-existent-repo-air10-xyz", "0000000000000000000000000000000000000000", "0000000000000000000000000000000000000000", repo)
            self.assertFalse(ok, "Fail-closed invariant broken: non-existent repo should fail!")

    def test_live_provider_runtime_head_match_for_main_authority(self):
        """Main authority seal invariant: RUNTIME_HEAD == LIVE_PROVIDER_MAIN_HEAD.
        Hostile vector: baseline A -> local candidate B -> provider main C (A -> B -> C).
        Candidate B descends from baseline A, but is behind provider main C.
        Attempting to claim main authority on B must FAIL-CLOSED.
        """
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix="air10-provider-match-") as tmp:
            repo = Path(tmp)
            a, b, c, d, _ = build_dag(repo)

            # Scenario 1: baseline=A, candidate=B, remote_main=C (B is behind C)
            # When authority_mode="main", candidate B must NOT be certified as main!
            with patch("subprocess.run") as mock_run:
                mock_run.return_value.returncode = 0
                mock_run.return_value.stdout = f"{c}\trefs/heads/main\n"
                mock_run.return_value.stderr = ""

                # Candidate B claims main authority while remote main is C -> MUST FAIL
                ok, msg = verify_live_provider_head("dummy-repo", a, b, repo, authority_mode="main")
                self.assertFalse(ok, "Security Failure: Outdated candidate B certified as main authority while remote is C!")
                self.assertIn("Main authority mismatch", msg)

                # Candidate C (exact match) claims main authority -> MUST PASS
                ok, msg = verify_live_provider_head("dummy-repo", a, c, repo, authority_mode="main")
                self.assertTrue(ok, f"Exact match candidate C must pass: {msg}")
                self.assertIn("Live provider main exact match", msg)

                # Under branch/pr authority, candidate B does NOT need to equal remote main C
                ok, msg = verify_live_provider_head("dummy-repo", a, b, repo, authority_mode="branch")
                self.assertTrue(ok, "Non-main authority should permit candidate B != remote C as long as baseline lineage holds")


if __name__ == "__main__":
    unittest.main(verbosity=2)

