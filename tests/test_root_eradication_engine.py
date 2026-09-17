#!/usr/bin/env python3
"""
Unit and Integration Tests for CIVeX Phase 4 Root Eradication Engine
====================================================================
Verifies:
1. AST Shell Interceptor & Panic Root Probe Suppression
2. Hallucinated Flag Sanitization
3. Playwright Parameter Coercion (Arrow function & Async IIFE)
4. Partial JSON Stream Repair
5. Anti-Storm Deduplication Sliding Window Filter
6. SQLite WAL Mode & Concurrency Retries
7. False-Green Kill Switch & Certified Execution Record (CER)
8. Disk Bloat Governor Free Space Inspection
"""

import sqlite3

from civex.root_eradication_engine import (
    AntiStormDedupShield,
    ASTShellInterceptor,
    CIVeXCausalVerifier,
    DiskBloatGovernor,
    RootEradicationEngine,
    SchemaAdapterShield,
    SQLiteConcurrencyShield,
)


def test_ast_shell_interceptor_panic_root():
    workspace = "/Users/rajondas/teamwork_projects"

    # 1. find / with arguments
    cmd = "find / -name credentials.env"
    sanitized, modified, reason = ASTShellInterceptor.intercept(cmd, cwd=workspace)
    assert modified is True
    assert sanitized == "find /Users/rajondas/teamwork_projects -name credentials.env"
    assert "Panic root probe intercepted" in reason

    # 2. standalone find /
    sanitized2, mod2, _ = ASTShellInterceptor.intercept("find /", cwd=workspace)
    assert mod2 is True
    assert sanitized2 == "find /Users/rajondas/teamwork_projects"

    # 3. ls / and ls -la /
    sanitized_ls, mod_ls, _ = ASTShellInterceptor.intercept("ls /", cwd=workspace)
    assert mod_ls is True
    assert sanitized_ls == "ls /Users/rajondas/teamwork_projects"

    sanitized_ls_la, mod_ls_la, _ = ASTShellInterceptor.intercept("ls -la /", cwd=workspace)
    assert mod_ls_la is True
    assert sanitized_ls_la == "ls -la /Users/rajondas/teamwork_projects"

    # 4. grep -rn and plain grep
    sanitized_grep, mod_grep, _ = ASTShellInterceptor.intercept("grep -rn foo /", cwd=workspace)
    assert mod_grep is True
    assert sanitized_grep == "grep -rn foo /Users/rajondas/teamwork_projects"

    # 5. ripgrep
    sanitized_rg, mod_rg, _ = ASTShellInterceptor.intercept("rg secret /", cwd=workspace)
    assert mod_rg is True
    assert sanitized_rg == "rg secret /Users/rajondas/teamwork_projects"

    # 6. cat /etc/passwd
    sanitized_cat, mod_cat, _ = ASTShellInterceptor.intercept("cat /etc/passwd", cwd=workspace)
    assert mod_cat is True
    assert "blocked" in sanitized_cat

    # 7. non-root paths should not be intercepted
    sanitized_safe, mod_safe, _ = ASTShellInterceptor.intercept("ls /tmp", cwd=workspace)
    assert mod_safe is False
    assert sanitized_safe == "ls /tmp"


def test_ast_shell_interceptor_strip_flags():
    cmd = "gorun-fast --json run main.go"
    sanitized, modified, reason = ASTShellInterceptor.intercept(cmd)
    assert modified is True
    assert "--json" not in sanitized
    assert "gorun-fast" in sanitized
    assert "Stripped hallucinated flags" in reason


def test_schema_adapter_playwright_arrow():
    args = {"script": "document.title"}
    norm, mutated = SchemaAdapterShield.normalize_mcp_arguments("playwright:browser_evaluate", args)
    assert mutated is True
    assert "function" in norm
    assert norm["function"] == "() => { return (document.title); }"


def test_schema_adapter_playwright_async_iife():
    args = {"expression": "const t = await page.title(); return t;"}
    norm, mutated = SchemaAdapterShield.normalize_mcp_arguments("browser_evaluate", args)
    assert mutated is True
    assert "function" in norm
    assert norm["function"].startswith("(async () =>")
    assert "await page.title()" in norm["function"]


def test_schema_adapter_partialjson_repair():
    raw_truncated = '{"action": "click", "selector": "#submit-btn'
    repaired, was_repaired = SchemaAdapterShield.repair_json_stream(raw_truncated)
    assert isinstance(repaired, dict)
    assert repaired.get("action") == "click"


def test_anti_storm_dedup_window(tmp_path):
    shield = AntiStormDedupShield(cache_dir=str(tmp_path))
    tool = "test_tool"
    args = {"param": "value"}

    # First call allowed
    ok1, reason1 = shield.check_and_record(tool, args)
    assert ok1 is True
    assert reason1 is None

    # Immediate second call dropped
    ok2, reason2 = shield.check_and_record(tool, args)
    assert ok2 is False
    assert "Anti-Storm Filter" in reason2

    # Different arguments allowed immediately
    ok3, reason3 = shield.check_and_record(tool, {"param": "other_value"})
    assert ok3 is True
    assert reason3 is None


def test_sqlite_concurrency_shield_wal(tmp_path):
    db_file = tmp_path / "test_wal.sqlite"
    conn = sqlite3.connect(str(db_file))
    SQLiteConcurrencyShield.configure_connection(conn)

    # Verify WAL mode
    mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
    assert mode.lower() == "wal"

    # Verify execution with retry
    cursor = SQLiteConcurrencyShield.execute_with_retry(
        conn, "CREATE TABLE test_table (id INTEGER PRIMARY KEY, val TEXT);"
    )
    assert cursor is not None

    SQLiteConcurrencyShield.execute_with_retry(
        conn, "INSERT INTO test_table (val) VALUES (?);", ("alpha",)
    )
    count = conn.execute("SELECT count(*) FROM test_table;").fetchone()[0]
    assert count == 1
    conn.close()


def test_civex_causal_false_green(tmp_path):
    target = tmp_path / "immutable.txt"
    target.write_text("initial content", encoding="utf-8")

    pre_state = CIVeXCausalVerifier.capture_pre_state(target)

    # Simulate exit 0 without mutating content
    valid, status, cer = CIVeXCausalVerifier.verify_post_state(pre_state, exit_code=0)
    assert valid is False
    assert "FALSE_GREEN_REJECTED" in status
    assert cer is None


def test_civex_causal_valid_mutation(tmp_path):
    target = tmp_path / "mutable.txt"
    target.write_text("initial content", encoding="utf-8")

    pre_state = CIVeXCausalVerifier.capture_pre_state(target)

    # Mutate content
    target.write_text("updated content with new bytes", encoding="utf-8")

    valid, status, cer = CIVeXCausalVerifier.verify_post_state(pre_state, exit_code=0)
    assert valid is True
    assert status == "CERTIFIED_STATE_MUTATION"
    assert cer is not None
    assert cer["status"] == "CERTIFIED_EXECUTION_RECORD"
    assert cer["delta_bytes"] > 0


def test_disk_bloat_governor():
    free_bytes = DiskBloatGovernor.get_free_bytes()
    assert isinstance(free_bytes, int)
    assert free_bytes > 0


def test_unified_root_eradication_engine():
    engine = RootEradicationEngine()

    # Preflight shell
    cmd, modified, _ = engine.preflight_shell_command("gorun-fast --json run main.go")
    assert "--json" not in cmd

    # Preflight tool
    norm, ok, reason = engine.preflight_tool_call("browser_evaluate", {"script": "1 + 1"})
    assert ok is True
    assert norm["function"] == "() => { return (1 + 1); }"


def test_phase3_civex_cli_subcommands():
    from civex.bridge import main
    # 1. intercept
    assert main(["intercept", "find / -name secret.txt"]) == 0
    # 2. adapt
    assert main(["adapt", "playwright:browser_evaluate", '{"script": "document.title"}']) == 0
    # 3. preflight
    assert main(["preflight", "browser_tabs", "{}"]) == 0
    # 4. thin-snapshots
    assert main(["thin-snapshots", "--bytes", "1000000"]) == 0


def test_phase3_lifecycle_hook_panic_interception(tmp_path):
    from civex.root_eradication_engine import ASTShellInterceptor
    cmd = "find / -type f -name test.py"
    clean, mod, reason = ASTShellInterceptor.intercept(cmd, cwd=str(tmp_path))
    assert mod is True
    assert str(tmp_path) in clean
    assert "Panic root probe" in reason

