#!/usr/bin/env python3
"""
CIVEX: PROGRESSIVE TOOL DISCLOSURE, HEADROOM COMPRESSION & CAUSAL VERIFIER
===========================================================================
Sub-millisecond adaptive tool retrieval and token-efficient dynamic schema hydration
for large-scale agentic tool catalogs (5,000+ tools).

Core Architecture:
1. JIT Progressive Tool Discovery via SQLite FTS5 BM25 Ranking
2. Bounded Shadow Schemas (strictly <= 250B per tool representation)
3. Headroom Output Compression (SmartCrusher pattern: 60-95% token savings)
4. CIVeX Causal State Verification (Cryptographic SHA-256 pre/post delta check)
5. 3-Strike Stateful Circuit Breaker with POSIX flock concurrency safety
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import time
from contextlib import contextmanager
from typing import Any

# Default local production path, with fixture fallback for portable CI
DEFAULT_PROD_CATALOG = os.path.expanduser('~/teamwork_projects/air10_ee_rig/db/air10_tool_catalog.sqlite')
FIXTURE_CATALOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures", "sample_catalog.sqlite")


# ---------------------------------------------------------------------------
# 1. HEADROOM OUTPUT PAYLOAD COMPRESSOR (SmartCrusher Pattern)
# ---------------------------------------------------------------------------
class HeadroomCompressor:
    """Compresses verbose JSON/log payloads by 60-95% before returning to LLM context."""

    SIGNALS = (
        "error", "exception", "failed", "failure", "critical",
        "bug", "traceback", "false_green", "segfault", "panic", "fatal"
    )

    def compress(self, data: Any, max_list_items: int = 3, max_str_len: int = 120) -> Any:
        if isinstance(data, str):
            try:
                parsed = json.loads(data)
                return self.compress_json(parsed, max_list_items, max_str_len)
            except Exception:
                return self.compress_text(data)
        return self.compress_json(data, max_list_items, max_str_len)

    @classmethod
    def _has_critical_signal(cls, x: Any) -> bool:
        if isinstance(x, dict):
            for k, v in x.items():
                k_str = str(k).lower()
                v_str = str(v).lower()
                if any(t in k_str or t in v_str for t in cls.SIGNALS):
                    return True
                if isinstance(v, (dict, list)) and cls._has_critical_signal(v):
                    return True
        elif isinstance(x, str):
            low = x.lower()
            if any(t in low for t in cls.SIGNALS):
                return True
        elif isinstance(x, (list, tuple)):
            return any(cls._has_critical_signal(item) for item in x)
        return False

    @classmethod
    def compress_json(cls, data: Any, max_list_items: int = 3, max_str_len: int = 120) -> Any:
        if isinstance(data, dict):
            compressed = {}
            for k, v in data.items():
                if v is None or v == "" or v == []:
                    continue  # Strip nulls and empty lists
                compressed[k] = cls.compress_json(v, max_list_items, max_str_len)
            return compressed
        elif isinstance(data, list):
            sampled = [cls.compress_json(x, max_list_items, max_str_len) for x in data[:max_list_items]]
            if len(data) > max_list_items:
                critical_extras = [
                    cls.compress_json(x, max_list_items, max_str_len)
                    for x in data[max_list_items:]
                    if cls._has_critical_signal(x)
                ]
                sampled.append(f"... [omitted {len(data) - max_list_items - len(critical_extras)} nominal items] ...")
                sampled.extend(critical_extras)
            return sampled
        elif isinstance(data, str):
            if len(data) > max_str_len:
                if cls._has_critical_signal(data):
                    low = data.lower()
                    best_pos = -1
                    best_len = 0
                    for sig in cls.SIGNALS:
                        pos = low.find(sig)
                        if pos != -1:
                            if best_pos == -1 or pos < best_pos:
                                best_pos = pos
                                best_len = len(sig)

                    if best_pos != -1:
                        w_start = max(0, best_pos - 40)
                        w_end = min(len(data), best_pos + best_len + 50)
                        sig_window = data[w_start:w_end]

                        head = data[:50] if w_start > 50 else ""
                        tail = data[-50:] if w_end < len(data) - 50 else ""

                        parts = []
                        if head:
                            parts.append(head)
                        if w_start > len(head):
                            parts.append(f"... [omitted {w_start - len(head)} chars] ...")
                        parts.append(sig_window)
                        if len(data) - len(tail) > w_end:
                            parts.append(f"... [omitted {len(data) - len(tail) - w_end} chars] ...")
                        if tail:
                            parts.append(tail)
                        return "".join(parts)
                return data[:max_str_len] + f"... [truncated {len(data)-max_str_len} chars]"
            return data
        return data

    @classmethod
    def compress_text(cls, text: str) -> str:
        lines = text.split("\n")
        if len(lines) > 20:
            head = lines[:5]
            tail = lines[-5:]
            critical = [line for line in lines[5:-5] if cls._has_critical_signal(line)]
            return "\n".join(head + [f"... [omitted {len(lines)-10-len(critical)} lines of logs] ..."] + critical + tail)
        return text


# ---------------------------------------------------------------------------
# 2. SCHEMA SHRINKER (Shadow Schemas: Name + Intent + Compact Signature)
# ---------------------------------------------------------------------------
class SchemaShrinker:
    """Generates minimal shadow schemas (<= 250 bytes) to prevent context blowout."""

    @staticmethod
    def shrink_tool(row: tuple) -> dict[str, Any]:
        tool_id, name, category, bin_path, exec_tmpl, desc, intents, tags = row[:8]
        clean_desc = (desc or "").split("\n")[0].strip()
        if len(clean_desc) > 90:
            clean_desc = clean_desc[:90] + "..."

        shadow = {
            "id": tool_id,
            "name": name,
            "cat": category,
            "summary": clean_desc,
            "cmd": exec_tmpl or name
        }
        if len(json.dumps(shadow).encode("utf-8")) >= 250:
            shadow["cmd"] = None
        for field in ("summary", "name", "cat"):
            while len(json.dumps(shadow).encode("utf-8")) >= 250 and shadow[field]:
                shadow[field] = shadow[field][:-1]
        if len(json.dumps(shadow).encode("utf-8")) >= 250:
            raise ValueError("Tool ID cannot fit in a 250-byte shadow schema")
        return shadow


# ---------------------------------------------------------------------------
# 3. CIVEX CAUSAL VERIFIER & EXPECTATION LEDGER
# ---------------------------------------------------------------------------
class CIVeXVerifier:
    """Causal State Verifier: Decouples exit codes from genuine physical disk mutations."""

    STATE_FILE = os.path.expanduser("~/.antigravity/circuit_breaker_state.json")
    MAX_CONSECUTIVE_FAILURES = 3

    def __init__(self):
        self._ensure_state_dir()

    def _ensure_state_dir(self):
        os.makedirs(os.path.dirname(self.STATE_FILE), exist_ok=True)

    @contextmanager
    def _locked_state(self):
        lock_file = self.STATE_FILE + ".lock"
        with open(lock_file, "w") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                state = {}
                if os.path.exists(self.STATE_FILE):
                    try:
                        with open(self.STATE_FILE, "r", encoding="utf-8") as f:
                            state = json.load(f)
                    except Exception as e:
                        raise ValueError(f"Corrupt state file: {e}")

                # Automatic legacy state migration
                if isinstance(state, dict):
                    if "failure_counts" not in state:
                        # Migrate legacy flat dict: {tool_id: count}
                        migrated_fc = {k: v for k, v in state.items() if isinstance(v, int)}
                        state = {
                            "failure_counts": migrated_fc,
                            "execution_history": []
                        }
                    else:
                        state.setdefault("failure_counts", {})
                        state.setdefault("execution_history", [])
                else:
                    state = {"failure_counts": {}, "execution_history": []}

                yield state
                temp_path = self.STATE_FILE + f".tmp.{os.getpid()}_{time.time_ns()}"
                with open(temp_path, "w", encoding="utf-8") as tf:
                    json.dump(state, tf, indent=2)
                    tf.flush()
                    os.fsync(tf.fileno())
                os.replace(temp_path, self.STATE_FILE)
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

    @property
    def failure_counts(self) -> dict[str, int]:
        with self._locked_state() as state:
            return state.get("failure_counts", {})

    def record_outcome(self, tool_id: str, success: bool, error_msg: str | None = None):
        with self._locked_state() as state:
            fc = state.setdefault("failure_counts", {})
            if success:
                fc[tool_id] = 0
            else:
                fc[tool_id] = fc.get(tool_id, 0) + 1
            hist = state.setdefault("execution_history", [])
            hist.append({
                "tool_id": tool_id,
                "timestamp": time.time(),
                "success": success,
                "error": error_msg,
                "failure_count": fc[tool_id]
            })
            if len(hist) > 500:
                state["execution_history"] = hist[-500:]

    def is_circuit_open(self, tool_id: str) -> bool:
        with self._locked_state() as state:
            fc = state.get("failure_counts", {})
            return fc.get(tool_id, 0) >= self.MAX_CONSECUTIVE_FAILURES

    def guard(self, tool_id: str):
        if self.is_circuit_open(tool_id):
            count = self.failure_counts.get(tool_id, self.MAX_CONSECUTIVE_FAILURES)
            raise RuntimeError(
                f"CIRCUIT_BREAKER_BLOCKED: Tool '{tool_id}' has failed {count} consecutive times."
            )

    @staticmethod
    def hash_file(path: str) -> str | None:
        if not os.path.exists(path):
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def verify_causal_write(self, target_path: str, pre_hash: str | None, exit_code: int) -> dict[str, Any]:
        """Verifies physical disk state against exit code and cryptographic hashes."""
        post_hash = self.hash_file(target_path)
        file_exists = os.path.exists(target_path)
        file_size = os.path.getsize(target_path) if file_exists else 0

        # REJECTION 1: Non-zero exit code
        if exit_code != 0:
            return {
                "verdict": "NONZERO_EXIT",
                "error": f"Command exited with code {exit_code}",
                "pre_hash": pre_hash,
                "post_hash": post_hash,
                "size_bytes": file_size
            }

        # REJECTION 2: Target file does NOT exist on disk (phantom green / false positive)
        if not file_exists:
            return {
                "verdict": "TARGET_MISSING",
                "error": "Exit code 0 but target file does NOT exist on disk (phantom execution)",
                "pre_hash": pre_hash,
                "post_hash": None,
                "size_bytes": 0
            }

        # REJECTION 3: Idempotent no-op execution (pre_hash == post_hash)
        if pre_hash == post_hash and pre_hash is not None:
            return {
                "verdict": "FALSE_GREEN",
                "error": "Exit code 0 but target file was NOT mutated (idempotent/noop execution)",
                "pre_hash": pre_hash,
                "post_hash": post_hash,
                "size_bytes": file_size
            }

        # REJECTION 4: Empty 0-byte file mutation
        if file_size == 0:
            return {
                "verdict": "0_BYTE_MUTATION",
                "error": "Exit code 0 but target file is 0 bytes (corrupt or empty payload)",
                "pre_hash": pre_hash,
                "post_hash": post_hash,
                "size_bytes": 0
            }

        # Genuine physical state mutation confirmed
        return {
            "verdict": "CONFIRMED",
            "pre_hash": pre_hash,
            "post_hash": post_hash,
            "size_bytes": file_size
        }


# ---------------------------------------------------------------------------
# 4. PROGRESSIVE 2-TIER DISCOVERY ENGINE
# ---------------------------------------------------------------------------
class ProgressiveToolBridge:
    """Sub-millisecond Progressive Discovery Bridge over large-scale catalogs using SQLite FTS5 BM25."""

    def __init__(self, db_path: str | None = None):
        if db_path:
            self.db_path = db_path
        elif env_path := os.environ.get("CIVEX_CATALOG_DB"):
            self.db_path = env_path
        elif os.path.exists(DEFAULT_PROD_CATALOG):
            self.db_path = DEFAULT_PROD_CATALOG
        elif os.path.exists(FIXTURE_CATALOG):
            self.db_path = FIXTURE_CATALOG
        else:
            raise FileNotFoundError(
                f"No catalog database found at {DEFAULT_PROD_CATALOG} or fixture {FIXTURE_CATALOG}. "
                "Specify db_path or set CIVEX_CATALOG_DB environment variable."
            )

        self.con = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        self.compressor = HeadroomCompressor()
        self.verifier = CIVeXVerifier()

    @staticmethod
    def _build_fts5_query(query: str) -> str:
        """Build disjunctive FTS5 MATCH expression from user query."""
        tokens = [tok.strip() for tok in query.split() if len(tok.strip()) > 1]
        if not tokens:
            return '""'
        safe = lambda t: t.replace('"', '').replace("'", '').replace('*', '').replace('^', '')
        parts = []
        full = ' '.join(safe(t) for t in tokens)
        if full.strip():
            parts.append(f'"{full}"*')
        for t in tokens[:6]:
            s = safe(t)
            if s:
                parts.append(f'"{s}"*')
        return ' OR '.join(parts) if parts else '""'

    def find_tools(self, query: str, category: str | None = None, limit: int = 3) -> dict[str, Any]:
        """Search catalog with FTS5 BM25 ranking and return shadow schemas."""
        t0 = time.perf_counter()
        if not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")

        fts_expr = self._build_fts5_query(query)

        if category:
            sql = """
            SELECT t.tool_id, t.name, t.category, t.binary_path, t.exec_template,
                   t.description, t.auto_trigger_intents, t.tags, fts.rank
            FROM tools_v2_fts fts
            JOIN tools_v2 t ON t.tool_id = fts.tool_id
            WHERE fts.tools_v2_fts MATCH ?
              AND t.category = ?
            ORDER BY fts.rank ASC
            LIMIT ?;
            """
            rows = self.con.execute(sql, [fts_expr, category, limit]).fetchall()
        else:
            sql = """
            SELECT t.tool_id, t.name, t.category, t.binary_path, t.exec_template,
                   t.description, t.auto_trigger_intents, t.tags, fts.rank
            FROM tools_v2_fts fts
            JOIN tools_v2 t ON t.tool_id = fts.tool_id
            WHERE fts.tools_v2_fts MATCH ?
            ORDER BY fts.rank ASC
            LIMIT ?;
            """
            rows = self.con.execute(sql, [fts_expr, limit]).fetchall()

        elapsed_ms = (time.perf_counter() - t0) * 1000

        shadow_schemas = []
        for r in rows:
            try:
                shadow_schemas.append(SchemaShrinker.shrink_tool(r))
            except ValueError:
                raw_id = str(r[0])
                bounded_id = (raw_id[:40] + "...[trunc]") if len(raw_id) > 50 else raw_id
                diag = {
                    "id": bounded_id,
                    "name": str(r[1])[:40],
                    "cat": str(r[2])[:20],
                    "err": "OVERSIZED_SCHEMA_TRUNCATED"
                }
                diag_bytes = json.dumps(diag).encode("utf-8")
                if len(diag_bytes) > 250:
                    diag = {"id": bounded_id[:25], "err": "OVERSIZED"}
                shadow_schemas.append(diag)

        return {
            "status": "SUCCESS",
            "query": query,
            "fts5_expr": fts_expr,
            "category_filter": category,
            "matched_count": len(shadow_schemas),
            "latency_ms": round(elapsed_ms, 3),
            "tools": shadow_schemas
        }

    def resolve_intent(self, intent: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Convenience method returning the list of shadow schemas directly."""
        res = self.find_tools(query=intent, limit=top_k)
        return res.get("tools", [])

    def hydrate_tool(self, tool_id: str) -> dict[str, Any] | None:
        """Hydrates full schema and execution parameters on demand when chosen."""
        sql = (
            "SELECT tool_id, name, category, binary_path, exec_template, "
            "description, auto_trigger_intents, tags FROM tools_v2 WHERE tool_id = ? LIMIT 1;"
        )
        rows = self.con.execute(sql, [tool_id]).fetchall()
        if not rows:
            return None
        r = rows[0]
        return {
            "tool_id": r[0],
            "name": r[1],
            "category": r[2],
            "binary_path": r[3],
            "exec_template": r[4],
            "description": r[5],
            "intents": r[6],
            "tags": r[7]
        }


# ---------------------------------------------------------------------------
# 5. CLI ENTRYPOINT
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    """CLI Entry point for civex-bridge console script."""
    parser = argparse.ArgumentParser(description="CIVEX Progressive 2-Tier Tool Bridge")
    parser.add_argument("--db", dest="db_path", default=None, help="Custom SQLite catalog database path")
    subparsers = parser.add_subparsers(dest="command")

    # search
    search_p = subparsers.add_parser("search", help="Search shadow schemas")
    search_p.add_argument("query", nargs="?", default="transformer copper loss", help="Search query")
    search_p.add_argument("--cat", dest="category", default=None, help="Filter by category")
    search_p.add_argument("--limit", dest="limit", type=int, default=3, help="Max results")

    # hydrate
    hyd_p = subparsers.add_parser("hydrate", help="Hydrate full tool schema by ID")
    hyd_p.add_argument("tool_id", help="Tool ID to hydrate")

    # compress
    comp_p = subparsers.add_parser("compress", help="Compress JSON payload via Headroom")
    comp_p.add_argument("payload", help="Raw JSON string or file path")

    # verify
    ver_p = subparsers.add_parser("verify", help="CIVeX verify execution")
    ver_p.add_argument("path", help="Target file path")
    ver_p.add_argument("pre_hash", help="Pre-execution SHA-256 hash")
    ver_p.add_argument("--code", type=int, default=0, help="Exit code")

    args = parser.parse_args(argv)

    try:
        bridge = ProgressiveToolBridge(db_path=args.db_path) if args.command in (None, "search", "hydrate") else None
    except Exception as e:
        sys.stderr.write(f"CIVEX Initialization Error: {e}\n")
        return 1

    if args.command == "search" or args.command is None:
        q = getattr(args, "query", "transformer copper loss")
        cat = getattr(args, "category", None)
        lim = getattr(args, "limit", 3)
        res = bridge.find_tools(q, category=cat, limit=lim)
        print(json.dumps(res, indent=2))
        return 0
    elif args.command == "hydrate":
        res = bridge.hydrate_tool(args.tool_id)
        print(json.dumps(res, indent=2))
        return 0
    elif args.command == "compress":
        compressor = HeadroomCompressor()
        if os.path.exists(args.payload):
            with open(args.payload, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = json.loads(args.payload)
        res = compressor.compress(data)
        print(json.dumps(res, indent=2))
        return 0
    elif args.command == "verify":
        verifier = CIVeXVerifier()
        res = verifier.verify_causal_write(args.path, args.pre_hash, args.code)
        print(json.dumps(res, indent=2))
        return 0 if res["verdict"] == "CONFIRMED" else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
