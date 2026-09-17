#!/usr/bin/env python3
"""
CIVEX UNIFIED FAIL-CLOSED MCP & TOOL CONTRACT ADAPTER SHIELD
============================================================
Synthesized from Phase 1 Causal Frontier and Phase 2 Google Deep-Research Solution Space.

Interconnects:
1. Playwright/Chrome-DevTools 2026.09 Schema Adapter (Arrow function & Async IIFE coercion)
2. 5-Second Anti-Storm Deduplication Filter (Halts infinite retry loops)
3. Syntax Sanitizer & Panic Probe Blocker (Strips hallucinated flags & arrests root filesystem scanning)
4. CIVeX Causal Hash Verification & False-Green Kill Switch (Exit 0 decoupling via SHA-256 state tracking)
5. Sovereign Circuit Breaker & Fallback Router (3-Strike state machine routing legacy tools to SIMD wheels)
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sqlite3
import time
from typing import Any

AUDIT_DB_PATH = os.path.expanduser("~/.antigravity/air10_audit.db")
CIRCUIT_BREAKER_FILE = os.path.expanduser("~/.antigravity/circuit_breaker_state.json")
DEDUP_CACHE_FILE = os.path.expanduser("~/.antigravity/mcp_dedup_cache.json")

SOVEREIGN_FALLBACKS: dict[str, list[str]] = {
    "cat": ["bat", "--plain"],
    "grep": ["rg"],
    "find": ["fd"],
    "sed": ["sd"],
    "awk": ["jaq"],
    "ls": ["eza"]
}

# ---------------------------------------------------------------------------
# 1. PLAYWRIGHT & BROWSER MCP PAYLOAD ADAPTER
# ---------------------------------------------------------------------------
class PlaywrightPayloadAdapter:
    """Normalizes MCP tool payloads to eliminate 2026.09 Playwright schema rejections."""

    @staticmethod
    def strip_markdown_fences(code: str) -> str:
        """Strips markdown code fences (```js, ```json, etc.) accidentally passed in code strings."""
        if not code or not isinstance(code, str):
            return code
        code = code.strip()
        if code.startswith("```"):
            lines = code.splitlines()
            if len(lines) >= 2 and lines[-1].strip() == "```":
                return "\n".join(lines[1:-1]).strip()
        return code

    @classmethod
    def normalize_arguments(cls, tool_name: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """
        Normalizes tool call arguments in-flight.
        Returns: (normalized_args, was_mutated)
        """
        mutated = False
        args = dict(arguments) if arguments else {}
        lower_tool = tool_name.lower()

        # 1. Evaluate tools: browser_evaluate, evaluate_script, etc.
        if "evaluate" in lower_tool or "run_code" in lower_tool:
            # Key mapping: script, expression, code -> function
            for candidate in ["script", "expression", "code"]:
                if candidate in args and "function" not in args:
                    args["function"] = args.pop(candidate)
                    mutated = True
                    break

            # Process function body if present
            if "function" in args and isinstance(args["function"], str):
                code = cls.strip_markdown_fences(args["function"])
                if code != args["function"]:
                    mutated = True

                has_await = bool(re.search(r"\bawait\b", code))
                is_arrow = code.startswith("() =>") or code.startswith("async () =>")
                is_func = code.startswith("function") or code.startswith("async function")
                is_iife = code.startswith("(async () =>") or code.startswith("(() =>")

                if not (is_arrow or is_func or is_iife):
                    if has_await:
                        # Wrap in async IIFE or async arrow function to avoid SyntaxError
                        args["function"] = f"(async () => {{ try {{ {code}; }} catch (e) {{ throw e; }} }})()"
                    elif ";" in code or "\n" in code:
                        args["function"] = f"() => {{ {code} }}"
                    else:
                        args["function"] = f"() => {{ return ({code}); }}"
                    mutated = True
                else:
                    args["function"] = code

        # 2. Browser tabs: ensure non-empty arguments
        elif "tabs" in lower_tool:
            if not args or "action" not in args:
                args["action"] = "list"
                mutated = True

        # 3. Type Coercion: Booleans and Numbers for common flags
        for k, v in list(args.items()):
            if isinstance(v, str):
                v_lower = v.strip().lower()
                if v_lower in ("true", "false") and k in ("headless", "strict", "isolate", "all", "recursive"):
                    args[k] = (v_lower == "true")
                    mutated = True
                elif v.strip().isdigit() and k in ("timeout", "delay", "max_depth", "limit", "port"):
                    args[k] = int(v.strip())
                    mutated = True

        return args, mutated


# ---------------------------------------------------------------------------
# 2. ANTI-STORM 5-SECOND DEDUPLICATION FILTER
# ---------------------------------------------------------------------------
class DedupShield:
    """Filters duplicate identical tool calls within a 5-second window to prevent retry storms."""

    COOLDOWN_SECONDS = 5.0

    @classmethod
    def check_and_record(cls, tool_name: str, arguments: dict[str, Any]) -> tuple[bool, str]:
        """
        Checks if the exact tool call was executed within the last 5 seconds.
        Returns: (is_duplicate, message)
        """
        os.makedirs(os.path.dirname(DEDUP_CACHE_FILE), exist_ok=True)
        now = time.time()
        
        # Build canonical payload hash
        canonical_str = f"{tool_name}:{json.dumps(arguments, sort_keys=True)}"
        call_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        lock_path = DEDUP_CACHE_FILE + ".lock"
        with open(lock_path, "w") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                cache: dict[str, float] = {}
                if os.path.exists(DEDUP_CACHE_FILE):
                    try:
                        with open(DEDUP_CACHE_FILE, "r", encoding="utf-8") as f:
                            cache = json.load(f)
                    except Exception:
                        cache = {}

                # Clean expired entries (> 60s)
                cache = {h: ts for h, ts in cache.items() if now - ts < 60.0}

                if call_hash in cache:
                    elapsed = now - cache[call_hash]
                    if elapsed < cls.COOLDOWN_SECONDS:
                        return True, f"DUPLICATE_CALL_5S_COOLDOWN: Tool '{tool_name}' called with identical payload {elapsed:.2f}s ago. Dropping duplicate to halt storm."

                # Record current invocation
                cache[call_hash] = now
                temp_path = DEDUP_CACHE_FILE + f".tmp.{os.getpid()}"
                with open(temp_path, "w", encoding="utf-8") as tf:
                    json.dump(cache, tf)
                os.replace(temp_path, DEDUP_CACHE_FILE)
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

        return False, "PROCEED"

    @classmethod
    def clear_cache(cls) -> None:
        """Clears the deduplication cache file for hermetic test isolation."""
        if os.path.exists(DEDUP_CACHE_FILE):
            try:
                os.remove(DEDUP_CACHE_FILE)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# 3. SYNTAX SANITIZER & PANIC PROBE BLOCKER
# ---------------------------------------------------------------------------
class SyntaxAndPanicSanitizer:
    """Detects and arrests panic probe sweeps and sanitizes hallucinated CLI flags."""

    PANIC_ROOT_PATTERNS = [
        re.compile(r"^find\s+/\s+(?!Users|Volumes)"),
        re.compile(r"^grep\s+-[a-zA-Z]*r[a-zA-Z]*\s+.*\s+/\s*$"),
        re.compile(r"^ls\s+-[a-zA-Z]*R[a-zA-Z]*\s+/\s*$"),
        re.compile(r"^cat\s+/etc/(?:passwd|shadow|hosts)"),
    ]

    HALLUCINATED_FLAGS = {
        "gorun-fast": ["--json", "-j", "--fmt", "--format=json"],
        "air10-auto-trigger": ["--format=json", "-f"],
    }

    @classmethod
    def sanitize_command(cls, command: str) -> tuple[str, bool, str | None]:
        """
        Inspects and sanitizes shell command.
        Returns: (sanitized_command, was_modified, block_reason)
        """
        stripped = command.strip()

        # 1. Check Panic Probing
        for pat in cls.PANIC_ROOT_PATTERNS:
            if pat.search(stripped):
                return stripped, False, "PANIC_PROBE_BLOCKED: Root filesystem traversal is prohibited. Re-route to current workspace."

        # 2. Sanitize hallucinated flags
        parts = stripped.split()
        if not parts:
            return command, False, None

        base_bin = os.path.basename(parts[0])
        if base_bin in cls.HALLUCINATED_FLAGS:
            bad_flags = set(cls.HALLUCINATED_FLAGS[base_bin])
            cleaned_parts = [p for p in parts if p not in bad_flags]
            if len(cleaned_parts) != len(parts):
                return " ".join(cleaned_parts), True, None

        return command, False, None


# ---------------------------------------------------------------------------
# 4. CIVEX CAUSAL VERIFIER & FALSE-GREEN KILL SWITCH
# ---------------------------------------------------------------------------
class CivexCausalShield:
    """Cryptographic SHA-256 state assertions decoupling exit code 0 from true execution."""

    @staticmethod
    def calculate_sha256(path: str) -> str | None:
        if not os.path.exists(path):
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    @classmethod
    def verify_file_mutation(
        cls,
        target_path: str,
        pre_hash: str | None,
        exit_code: int,
        expect_mutation: bool = True
    ) -> dict[str, Any]:
        """
        Enforces False-Green Kill Switch.
        """
        exists = os.path.exists(target_path)
        post_hash = cls.calculate_sha256(target_path) if exists else None
        file_size = os.path.getsize(target_path) if exists else 0

        # Verdict 1: Process exit code failure
        if exit_code != 0:
            return {
                "verdict": "NONZERO_EXIT",
                "certified": False,
                "reason": f"Command exited with non-zero code {exit_code}",
                "pre_hash": pre_hash,
                "post_hash": post_hash,
            }

        # Verdict 2: Target missing on disk
        if not exists:
            return {
                "verdict": "TARGET_MISSING",
                "certified": False,
                "reason": "Exit code was 0 but target file does not exist on physical disk",
                "pre_hash": pre_hash,
                "post_hash": None,
            }

        # Verdict 3: 0-byte corrupt file
        if file_size == 0:
            return {
                "verdict": "0_BYTE_MUTATION",
                "certified": False,
                "reason": "Exit code was 0 but target file is empty (0 bytes)",
                "pre_hash": pre_hash,
                "post_hash": post_hash,
            }

        # Verdict 4: False-Green (claimed mutation but pre_hash == post_hash)
        if expect_mutation and pre_hash is not None and pre_hash == post_hash:
            return {
                "verdict": "FALSE_GREEN",
                "certified": False,
                "reason": "Exit code was 0 but target file bytes were identical before and after execution",
                "pre_hash": pre_hash,
                "post_hash": post_hash,
            }

        # Verdict 5: Certified Execution Record (CER)
        return {
            "verdict": "CERTIFIED_EXECUTION_RECORD",
            "certified": True,
            "pre_hash": pre_hash,
            "post_hash": post_hash,
            "size_bytes": file_size,
            "timestamp": time.time(),
        }


# ---------------------------------------------------------------------------
# 5. SOVEREIGN 3-STRIKE CIRCUIT BREAKER ROUTER
# ---------------------------------------------------------------------------
class SovereignCircuitBreaker:
    """Re-routes failing legacy unix tools to modern high-performance wheels after 3 strikes."""

    @classmethod
    def resolve_fallback(cls, command: str) -> tuple[str, bool]:
        parts = command.strip().split()
        if not parts:
            return command, False

        base_tool = os.path.basename(parts[0])
        if base_tool not in SOVEREIGN_FALLBACKS:
            return command, False

        if not os.path.exists(AUDIT_DB_PATH):
            return command, False

        try:
            conn = sqlite3.connect(AUDIT_DB_PATH, timeout=1.0)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT status FROM tool_traces_v2 
                WHERE tool_name = ? 
                ORDER BY timestamp_ns DESC LIMIT 3
            """, (base_tool,))
            rows = cursor.fetchall()
            conn.close()

            if len(rows) == 3 and all(r[0] in ("ERROR", "FAIL", "NON_ZERO") for r in rows):
                sub = SOVEREIGN_FALLBACKS[base_tool]
                new_cmd = " ".join(sub + parts[1:])
                return new_cmd, True
        except Exception:
            pass

        return command, False
