#!/usr/bin/env python3
"""
CIVEX ADAPTER SHIELD COMPREHENSIVE REGRESSION & ADVERSARIAL TEST SUITE
======================================================================
Verifies all 16 contract invariants across:
1. Playwright/DevTools schema normalization
2. Markdown fence stripping
3. Async IIFE wrapper for await
4. Anti-storm 5s deduplication
5. Panic probe root detection
6. Syntax flag sanitizer
7. CIVeX False-Green Kill Switch (Exit 0 decoupling)
8. Sovereign Circuit Breaker fallback
"""

import os
import tempfile
import time

from civex.adapter_shield import (
    CivexCausalShield,
    DedupShield,
    PlaywrightPayloadAdapter,
    SovereignCircuitBreaker,
    SyntaxAndPanicSanitizer,
)


# ---------------------------------------------------------------------------
# 1. PLAYWRIGHT & SCHEMA NORMALIZATION TESTS
# ---------------------------------------------------------------------------
def test_playwright_schema_coercion_script_to_arrow():
    args = {"script": "document.title"}
    norm, mutated = PlaywrightPayloadAdapter.normalize_arguments("browser_evaluate", args)
    assert mutated is True
    assert "function" in norm
    assert "script" not in norm
    assert norm["function"] == "() => { return (document.title); }"


def test_playwright_multiline_script_wrapping():
    args = {"expression": "let x = 1;\nlet y = 2;\nreturn x + y;"}
    norm, mutated = PlaywrightPayloadAdapter.normalize_arguments("evaluate_script", args)
    assert mutated is True
    assert "function" in norm
    assert norm["function"] == "() => { let x = 1;\nlet y = 2;\nreturn x + y; }"


def test_playwright_async_await_iife_wrapping():
    args = {"script": "const text = await page.innerText('.heading'); return text;"}
    norm, mutated = PlaywrightPayloadAdapter.normalize_arguments("browser_run_code", args)
    assert mutated is True
    assert norm["function"].startswith("(async () =>")
    assert "await page.innerText" in norm["function"]


def test_playwright_markdown_fence_stripping():
    fenced_code = "```javascript\nreturn window.innerWidth;\n```"
    args = {"script": fenced_code}
    norm, mutated = PlaywrightPayloadAdapter.normalize_arguments("browser_evaluate", args)
    assert mutated is True
    assert "```" not in norm["function"]
    assert "window.innerWidth" in norm["function"]


def test_browser_tabs_empty_arguments_defaulting():
    norm, mutated = PlaywrightPayloadAdapter.normalize_arguments("browser_tabs", {})
    assert mutated is True
    assert norm["action"] == "list"


def test_type_coercion_boolean_and_numbers():
    args = {"headless": "true", "strict": "false", "timeout": "10000", "limit": "50"}
    norm, mutated = PlaywrightPayloadAdapter.normalize_arguments("browser_navigate", args)
    assert mutated is True
    assert norm["headless"] is True
    assert norm["strict"] is False
    assert norm["timeout"] == 10000
    assert norm["limit"] == 50


# ---------------------------------------------------------------------------
# 2. ANTI-STORM 5-SECOND DEDUPLICATION TESTS
# ---------------------------------------------------------------------------
def test_anti_storm_5s_deduplication_filter():
    tool = "run_command"
    args = {"CommandLine": "ls -la"}
    
    # First call: allowed
    is_dup1, msg1 = DedupShield.check_and_record(tool, args)
    assert is_dup1 is False
    assert msg1 == "PROCEED"

    # Second immediate call: blocked
    is_dup2, msg2 = DedupShield.check_and_record(tool, args)
    assert is_dup2 is True
    assert "DUPLICATE_CALL_5S_COOLDOWN" in msg2


def test_deduplication_allows_different_args():
    tool = "run_command"
    args1 = {"CommandLine": f"echo test_{time.time_ns()}_1"}
    args2 = {"CommandLine": f"echo test_{time.time_ns()}_2"}

    is_dup1, _ = DedupShield.check_and_record(tool, args1)
    is_dup2, _ = DedupShield.check_and_record(tool, args2)
    assert is_dup1 is False
    assert is_dup2 is False


# ---------------------------------------------------------------------------
# 3. PANIC PROBE BLOCKER & SYNTAX SANITIZER TESTS
# ---------------------------------------------------------------------------
def test_panic_probe_blocker_root_traversal():
    root_cmds = [
        "find / -name password.txt",
        "cat /etc/passwd",
        "grep -r secret /",
        "ls -R /",
    ]
    for cmd in root_cmds:
        _, _, reason = SyntaxAndPanicSanitizer.sanitize_command(cmd)
        assert reason is not None, f"Expected block for {cmd}"
        assert "PANIC_PROBE_BLOCKED" in reason


def test_panic_probe_allow_workspace_search():
    safe_cmds = [
        "find /Users/rajondas/teamwork_projects -name '*.py'",
        "grep -r 'class' /Users/rajondas/teamwork_projects/civex-progressive-bridge",
        "ls -la /Users/rajondas/.gemini",
    ]
    for cmd in safe_cmds:
        _, _, reason = SyntaxAndPanicSanitizer.sanitize_command(cmd)
        assert reason is None, f"Unexpected block for safe command: {cmd}"


def test_syntax_sanitizer_hallucinated_flags():
    bad_cmd = "gorun-fast --json -j --safe-run main.go"
    clean_cmd, modified, _ = SyntaxAndPanicSanitizer.sanitize_command(bad_cmd)
    assert modified is True
    assert "--json" not in clean_cmd
    assert "-j" not in clean_cmd
    assert "--safe-run" in clean_cmd
    assert "main.go" in clean_cmd


# ---------------------------------------------------------------------------
# 4. CIVEX CAUSAL FALSE-GREEN KILL SWITCH TESTS
# ---------------------------------------------------------------------------
def test_civex_causal_false_green_detection():
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("constant_state_bytes")
        f.flush()
        temp_path = f.name

    try:
        pre_hash = CivexCausalShield.calculate_sha256(temp_path)
        # Simulate exit code 0 but file was NOT modified
        verdict = CivexCausalShield.verify_file_mutation(
            target_path=temp_path,
            pre_hash=pre_hash,
            exit_code=0,
            expect_mutation=True
        )
        assert verdict["verdict"] == "FALSE_GREEN"
        assert verdict["certified"] is False
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_civex_causal_target_missing_detection():
    phantom_path = "/tmp/phantom_file_that_does_not_exist_99.txt"
    if os.path.exists(phantom_path):
        os.remove(phantom_path)

    verdict = CivexCausalShield.verify_file_mutation(
        target_path=phantom_path,
        pre_hash=None,
        exit_code=0,
        expect_mutation=True
    )
    assert verdict["verdict"] == "TARGET_MISSING"
    assert verdict["certified"] is False


def test_civex_causal_0_byte_mutation_detection():
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        # 0 byte file
        temp_path = f.name

    try:
        verdict = CivexCausalShield.verify_file_mutation(
            target_path=temp_path,
            pre_hash=None,
            exit_code=0,
            expect_mutation=True
        )
        assert verdict["verdict"] == "0_BYTE_MUTATION"
        assert verdict["certified"] is False
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_civex_causal_certified_execution_record():
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("initial_v1")
        f.flush()
        temp_path = f.name

    try:
        pre_hash = CivexCausalShield.calculate_sha256(temp_path)
        # Real mutation
        with open(temp_path, "w") as f:
            f.write("mutated_v2_new_content_bytes")

        verdict = CivexCausalShield.verify_file_mutation(
            target_path=temp_path,
            pre_hash=pre_hash,
            exit_code=0,
            expect_mutation=True
        )
        assert verdict["verdict"] == "CERTIFIED_EXECUTION_RECORD"
        assert verdict["certified"] is True
        assert verdict["post_hash"] is not None
        assert verdict["pre_hash"] != verdict["post_hash"]
        assert verdict["size_bytes"] > 0
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_sovereign_circuit_breaker_structure():
    cmd = "cat myfile.txt"
    # Even if DB not present or zero failures, resolving should return valid tuple
    resolved, substituted = SovereignCircuitBreaker.resolve_fallback(cmd)
    assert isinstance(resolved, str)
    assert isinstance(substituted, bool)
