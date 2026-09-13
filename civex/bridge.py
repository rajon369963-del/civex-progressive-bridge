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
import time
from contextlib import contextmanager
from typing import Any

# Default local production path, with bundled package data and fixture fallback
DEFAULT_PROD_CATALOG = os.path.expanduser('~/teamwork_projects/air10_ee_rig/db/air10_tool_catalog.sqlite')
BUNDLED_CATALOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "sample_catalog.sqlite")
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
                    spans = []
                    for sig in cls.SIGNALS:
                        start = 0
                        while True:
                            idx = low.find(sig, start)
                            if idx == -1:
                                break
                            w_start = max(0, idx - 40)
                            w_end = min(len(data), idx + len(sig) + 50)
                            spans.append((w_start, w_end))
                            start = idx + len(sig)

                    if spans:
                        spans.sort(key=lambda s: s[0])
                        merged = []
                        for s_start, s_end in spans:
                            if not merged:
                                merged.append([s_start, s_end])
                            else:
                                last = merged[-1]
                                if s_start <= last[1] + 30:
                                    last[1] = max(last[1], s_end)
                                else:
                                    merged.append([s_start, s_end])

                        head_len = 50
                        tail_len = 50
                        parts = []

                        if merged[0][0] > head_len:
                            parts.append(data[:head_len])
                            parts.append(f"... [omitted {merged[0][0] - head_len} chars] ...")
                        elif merged[0][0] > 0:
                            merged[0][0] = 0

                        for i, (m_start, m_end) in enumerate(merged):
                            parts.append(data[m_start:m_end])
                            if i + 1 < len(merged):
                                next_start = merged[i+1][0]
                                if next_start > m_end:
                                    parts.append(f"... [omitted {next_start - m_end} chars] ...")

                        if len(data) - tail_len > merged[-1][1]:
                            parts.append(f"... [omitted {len(data) - tail_len - merged[-1][1]} chars] ...")
                            parts.append(data[-tail_len:])
                        elif merged[-1][1] < len(data):
                            parts.append(data[merged[-1][1]:])

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
                        if any(type(v) is not int or v < 0 for v in state.values()):
                            raise ValueError("Corrupt state: invalid legacy failure count")
                        migrated_fc = dict(state)
                        state = {
                            "failure_counts": migrated_fc,
                            "execution_history": []
                        }
                    else:
                        state.setdefault("failure_counts", {})
                        state.setdefault("execution_history", [])
                else:
                    raise ValueError("Corrupt state: expected an object")

                counts = state["failure_counts"]
                if not isinstance(counts, dict) or any(type(v) is not int or v < 0 for v in counts.values()):
                    raise ValueError("Corrupt state: invalid failure_counts")
                if not isinstance(state["execution_history"], list):
                    raise ValueError("Corrupt state: invalid execution_history")

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
        elif os.path.exists(BUNDLED_CATALOG):
            self.db_path = BUNDLED_CATALOG
        elif os.path.exists(FIXTURE_CATALOG):
            self.db_path = FIXTURE_CATALOG
        else:
            raise FileNotFoundError(
                f"No catalog database found at {DEFAULT_PROD_CATALOG}, bundled {BUNDLED_CATALOG}, or fixture {FIXTURE_CATALOG}. "
                "Specify db_path or set CIVEX_CATALOG_DB environment variable."
            )

        self.con = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        self.compressor = HeadroomCompressor()
        self.verifier = CIVeXVerifier()

        # CHAKKA JODO: Authoritative CourtAwareRanker consuming CIVeX circuit breaker
        try:
            from .court_ranking import CourtAwareRanker
            self.ranker = CourtAwareRanker(verifier=self.verifier)
            self.ranker_init_error = None
        except Exception as e:
            self.ranker = None
            self.ranker_init_error = str(e)

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

    def find_tools(
        self,
        query: str,
        category: str | None = None,
        limit: int = 3,
        capability: str | None = None,
        input_format: str = "SINGLE_DOC_STRICT_RFC8259",
        contract_version: str = "v1.0",
        rank_with_court: bool = True
    ) -> dict[str, Any]:
        """Search catalog with FTS5 BM25 ranking and apply authoritative CourtAwareRanker.
        FAIL-CLOSED INVARIANT: Only court-verified tools with score > 0.0 enter routable tools.
        """
        t0 = time.perf_counter()
        # Check if query matches any legacy tool to substitute primary sovereign tool
        try:
            from .court_ranking import (
                PRIMARY_SOVEREIGN_TOOLS,
                PRIMARY_TOOL_SUBSTITUTIONS,
            )
        except ImportError:
            from court_ranking import (
                PRIMARY_TOOL_SUBSTITUTIONS,
            )

        active_substitutions = {}
        for tok in query.lower().split():
            clean_tok = tok.strip(" ,.-_\"'")
            if clean_tok in PRIMARY_TOOL_SUBSTITUTIONS:
                active_substitutions[clean_tok] = PRIMARY_TOOL_SUBSTITUTIONS[clean_tok]

        search_query = query
        if active_substitutions:
            search_query = f"{query} " + " ".join(active_substitutions.values())

        fts_expr = self._build_fts5_query(search_query)

        # Retrieve a broader candidate pool to allow court ranking to promote certified tools
        retrieval_limit = min(100, max(limit * 3, 10))

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
            rows = self.con.execute(sql, [fts_expr, category, retrieval_limit]).fetchall()
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
            rows = self.con.execute(sql, [fts_expr, retrieval_limit]).fetchall()

        shadow_schemas = []
        raw_row_map = {}
        for r in rows:
            raw_id = str(r[0])
            raw_row_map[raw_id] = r
            try:
                shadow_schemas.append(SchemaShrinker.shrink_tool(r))
            except ValueError:
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

        # FAIL-CLOSED CHECK: If ranker is unavailable, bridge MUST refuse routing
        if self.ranker is None:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            return {
                "status": "VERIFICATION_UNAVAILABLE_HOLD",
                "query": query,
                "fts5_expr": fts_expr,
                "category_filter": category,
                "matched_count": 0,
                "latency_ms": round(elapsed_ms, 3),
                "tools": [],
                "held_candidates": shadow_schemas,
                "error": f"FAIL-CLOSED: CourtAwareRanker unavailable ({getattr(self, 'ranker_init_error', 'Uninitialized')}). Routing refused."
            }

        verified_tools = []
        held_tools = []

        # Apply Court-Aware Ranking & Fail-Closed Exclusion
        if shadow_schemas:
            eval_cap = capability or ("JSON_SINGLE_DOC_STRICT" if "json" in query.lower() else "DEFAULT_EXEC")
            for schema in shadow_schemas:
                t_id = schema.get("id")
                r_match = raw_row_map.get(t_id)
                bin_path = r_match[3] if r_match else None
                t_name = schema.get("name", t_id)
                score = self.ranker.score_tool(
                    tool_id=t_id,
                    tool_name=t_name,
                    capability=eval_cap,
                    input_format=input_format,
                    contract_version=contract_version,
                    binary_path=bin_path
                )
                schema["court_score"] = score.final_score
                schema["court_status"] = score.status
                schema["court_rationale"] = score.rationale
                schema["court_verified"] = (score.status == "ELIGIBLE" and score.final_score > 0.0)
                schema["is_primary_sovereign"] = getattr(score, "is_primary_sovereign", False) or (t_name in PRIMARY_SOVEREIGN_TOOLS or t_id in PRIMARY_SOVEREIGN_TOOLS)

                # FAIL-CLOSED HARD EXCLUSION:
                # Candidate MUST NOT enter routable tools if score <= 0.0 or court_verified != True
                if schema["court_verified"]:
                    verified_tools.append(schema)
                else:
                    held_tools.append(schema)

            # Sort verified candidates with primary sovereign wheels first, then by court utility score
            verified_tools.sort(key=lambda s: (s.get("is_primary_sovereign", False), s.get("court_score", 0.0)), reverse=True)

        routable_tools = verified_tools[:limit]
        elapsed_ms = (time.perf_counter() - t0) * 1000

        status = "SUCCESS" if routable_tools else "NO_VERIFIED_TOOL_AVAILABLE"
        return {
            "status": status,
            "query": query,
            "fts5_expr": fts_expr,
            "category_filter": category,
            "matched_count": len(routable_tools),
            "latency_ms": round(elapsed_ms, 3),
            "tools": routable_tools,
            "held_candidates": held_tools,
            "primary_substitutions": active_substitutions
        }

    def resolve_intent(
        self,
        intent: str,
        top_k: int = 5,
        capability: str | None = None,
        input_format: str = "SINGLE_DOC_STRICT_RFC8259",
        contract_version: str = "v1.0"
    ) -> list[dict[str, Any]]:
        """Convenience method returning ONLY court-verified, routable shadow schemas.
        Unverified or quarantined candidates are strictly excluded.
        """
        res = self.find_tools(
            query=intent,
            limit=top_k,
            capability=capability,
            input_format=input_format,
            contract_version=contract_version,
            rank_with_court=True
        )
        return res.get("tools", [])

    def hydrate_tool(
        self,
        tool_id: str,
        capability: str | None = None,
        input_format: str = "SINGLE_DOC_STRICT_RFC8259",
        contract_version: str = "v1.0"
    ) -> dict[str, Any] | None:
        """Hydrates full schema and execution parameters on demand when chosen.
        Strictly enforces Court verification fail-closed to prevent unverified known-tool-ID bypass.
        Zero bypass parameters permitted.
        """
        sql = (
            "SELECT tool_id, name, category, binary_path, exec_template, "
            "description, auto_trigger_intents, tags FROM tools_v2 WHERE tool_id = ? LIMIT 1;"
        )
        rows = self.con.execute(sql, [tool_id]).fetchall()
        if not rows:
            return None
        r = rows[0]
        tool_dict = {
            "tool_id": r[0],
            "name": r[1],
            "category": r[2],
            "binary_path": r[3],
            "exec_template": r[4],
            "description": r[5],
            "intents": r[6],
            "tags": r[7]
        }

        # STRICT FAIL-CLOSED COURT ENFORCEMENT ON DIRECT HYDRATION
        if self.ranker is None:
            return {
                "tool_id": tool_dict["tool_id"],
                "name": tool_dict["name"],
                "court_status": "VERIFICATION_UNAVAILABLE_HOLD",
                "court_score": 0.0,
                "court_verdict": "REFUSED_FAIL_CLOSED",
                "court_rationale": "COURT_REFUSAL: CourtAwareRanker unavailable. Direct hydration refused.",
                "binary_path": None,
                "exec_template": None
            }

        eval_cap = capability or ("JSON_SINGLE_DOC_STRICT" if "json" in tool_dict["name"].lower() else "DEFAULT_EXEC")
        score = self.ranker.score_tool(
            tool_id=tool_dict["tool_id"],
            tool_name=tool_dict["name"],
            capability=eval_cap,
            input_format=input_format,
            contract_version=contract_version,
            binary_path=tool_dict["binary_path"]
        )
        if score.status != "ELIGIBLE" or score.final_score <= 0.0:
            return {
                "tool_id": tool_dict["tool_id"],
                "name": tool_dict["name"],
                "court_status": score.status,
                "court_score": score.final_score,
                "court_verdict": "REFUSED_FAIL_CLOSED",
                "court_rationale": f"COURT_REFUSAL: Tool hydration blocked by Tool Court ({score.status}: {score.rationale})",
                "binary_path": None,
                "exec_template": None
            }
        tool_dict["court_status"] = score.status
        tool_dict["court_score"] = score.final_score
        tool_dict["court_verified"] = True

        return tool_dict

    def inspect_tool_metadata(self, tool_id: str) -> dict[str, Any] | None:
        """Returns non-executable metadata only for inspection/catalog browsing.
        Strictly omits execution parameters (binary_path, exec_template) to prevent
        unverified execution bypass.
        """
        sql = (
            "SELECT tool_id, name, category, description, auto_trigger_intents, tags "
            "FROM tools_v2 WHERE tool_id = ? LIMIT 1;"
        )
        rows = self.con.execute(sql, [tool_id]).fetchall()
        if not rows:
            return None
        r = rows[0]
        return {
            "tool_id": r[0],
            "name": r[1],
            "category": r[2],
            "description": r[3],
            "intents": r[4],
            "tags": r[5]
        }


def inspect_tool_metadata(tool_id: str, catalog_path: Path | str | None = None) -> dict[str, Any] | None:
    """Convenience module function: returns non-executable metadata only for inspection.
    Strictly omits execution parameters (binary_path, exec_template).
    """
    bridge = ProgressiveToolBridge(db_path=catalog_path)
    return bridge.inspect_tool_metadata(tool_id)


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


# ============================================================================

# TASK_015_CIVEX_INVARIANT_CONTRACTS: PROGRESSIVE RPC GATING & INVARIANTS
# ============================================================================

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum


class CivexErrorCode(str, Enum):
    MALFORMED_RPC_PAYLOAD = 'MALFORMED_RPC_PAYLOAD'
    CIVEX_DISCLOSURE_REJECTED = 'CIVEX_DISCLOSURE_REJECTED'
    SCHEMA_MISMATCH = 'SCHEMA_MISMATCH'
    INTERNAL_GUARD_VIOLATION = 'INTERNAL_GUARD_VIOLATION'


class CivexBridgeException(Exception):
    def __init__(self, error_code: CivexErrorCode, message: str, details: dict[str, Any] | None = None):
        super().__init__(f'[{error_code.value}] {message}')
        self.error_code = error_code
        self.message = message
        self.details = details or {}


def sanitize_error_text(text: str) -> str:
    text = re.sub(r"(bearer\s+)[A-Za-z0-9_\-\.]{8,}", r"\1[REDACTED]", text, flags=re.IGNORECASE)
    text = re.sub(r"((?:key|token|secret|password)['\":\s=]+)[A-Za-z0-9_\-\.]{8,}", r"\1[REDACTED]", text, flags=re.IGNORECASE)
    text = re.sub(r'File "[^"]+", line \d+, in [^\n]+', "[FRAME_REDACTED]", text)
    return text


def build_error_envelope(
    error_code: CivexErrorCode,
    message: str,
    rpc_id: str | int | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    clean_msg = sanitize_error_text(message)
    clean_details = {}
    if details:
        for k, v in details.items():
            if isinstance(v, str):
                clean_details[k] = sanitize_error_text(v)
            else:
                clean_details[k] = v

    rpc_numeric_code = -32600
    if error_code == CivexErrorCode.MALFORMED_RPC_PAYLOAD:
        rpc_numeric_code = -32700
    elif error_code == CivexErrorCode.CIVEX_DISCLOSURE_REJECTED:
        rpc_numeric_code = -32001
    elif error_code == CivexErrorCode.SCHEMA_MISMATCH:
        rpc_numeric_code = -32602

    return {
        'jsonrpc': '2.0',
        'id': rpc_id,
        'error': {
            'code': rpc_numeric_code,
            'civex_error_code': error_code.value,
            'message': clean_msg,
            'data': {
                'timestamp_ns': time.perf_counter_ns(),
                'details': clean_details,
            },
        },
    }


@dataclass(slots=True)
class ParameterContract:
    name: str
    expected_type: type
    required: bool = True
    min_val: int | float | None = None
    max_val: int | float | None = None


@dataclass(slots=True)
class ToolContract:
    tool_id: str
    name: str
    description: str
    parameters: dict[str, ParameterContract]
    handler: Callable[[dict[str, Any]], Any] | None = None
    required_permission: str = 'civil:standard'


class CivexProgressiveBridge:
    def __init__(self):
        self._tools: dict[str, ToolContract] = {}
        self._client_permissions: dict[str, set[str]] = {}
        self._total_requests_evaluated: int = 0

    def register_tool(self, tool: ToolContract) -> None:
        self._tools[tool.tool_id] = tool

    def authorize_client(self, client_id: str, permissions: set[str]) -> None:
        self._client_permissions[client_id] = set(permissions)

    def get_disclosed_tool_schemas(self, client_id: str) -> list[dict[str, Any]]:
        client_perms = self._client_permissions.get(client_id, set())
        disclosed = []
        for tool in self._tools.values():
            if tool.required_permission in client_perms:
                schema = {
                    'tool_id': tool.tool_id,
                    'name': tool.name,
                    'description': tool.description,
                    'parameters': {
                        p_name: {
                            'type': p_contract.expected_type.__name__,
                            'required': p_contract.required,
                        }
                        for p_name, p_contract in tool.parameters.items()
                    },
                }
                disclosed.append(schema)
        return disclosed

    def evaluate_rpc_request(
        self,
        client_id: str,
        payload_input: str | bytes | dict[str, Any],
    ) -> dict[str, Any]:
        self._total_requests_evaluated += 1

        rpc_id: str | int | None = None
        if isinstance(payload_input, (str, bytes)):
            try:
                payload = json.loads(payload_input)
            except Exception as e:
                return build_error_envelope(
                    CivexErrorCode.MALFORMED_RPC_PAYLOAD,
                    f'JSON parse failure: {e}',
                    rpc_id=None,
                )
        elif isinstance(payload_input, dict):
            payload = payload_input
        else:
            return build_error_envelope(
                CivexErrorCode.MALFORMED_RPC_PAYLOAD,
                f'Invalid payload type: {type(payload_input).__name__}',
                rpc_id=None,
            )

        if not isinstance(payload, dict):
            return build_error_envelope(
                CivexErrorCode.MALFORMED_RPC_PAYLOAD,
                'Payload must be a JSON object',
                rpc_id=None,
            )

        if payload.get('jsonrpc') != '2.0':
            return build_error_envelope(
                CivexErrorCode.MALFORMED_RPC_PAYLOAD,
                "Missing or invalid jsonrpc protocol header (must be '2.0')",
                rpc_id=payload.get('id'),
            )

        method = payload.get('method')
        if not method or not isinstance(method, str):
            return build_error_envelope(
                CivexErrorCode.MALFORMED_RPC_PAYLOAD,
                "Field 'method' must be a non-empty string",
                rpc_id=payload.get('id'),
            )

        rpc_id = payload.get('id')

        tool = self._tools.get(method)
        if not tool:
            return build_error_envelope(
                CivexErrorCode.CIVEX_DISCLOSURE_REJECTED,
                f"Tool '{method}' is not disclosed or does not exist",
                rpc_id=rpc_id,
            )

        client_perms = self._client_permissions.get(client_id, set())
        if tool.required_permission not in client_perms:
            return build_error_envelope(
                CivexErrorCode.CIVEX_DISCLOSURE_REJECTED,
                f"Client '{client_id}' lacks permission '{tool.required_permission}' for tool '{method}'",
                rpc_id=rpc_id,
            )

        params = payload.get('params')
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return build_error_envelope(
                CivexErrorCode.SCHEMA_MISMATCH,
                "Field 'params' must be an object/dictionary",
                rpc_id=rpc_id,
            )

        for p_name, p_contract in tool.parameters.items():
            if p_contract.required and p_name not in params:
                return build_error_envelope(
                    CivexErrorCode.SCHEMA_MISMATCH,
                    f"Missing required parameter '{p_name}' for tool '{method}'",
                    rpc_id=rpc_id,
                    details={'missing_param': p_name},
                )

            if p_name in params:
                val = params[p_name]
                if p_contract.expected_type is int:
                    if not isinstance(val, int) or isinstance(val, bool):
                        val_str = str(val)[:50]
                        return build_error_envelope(
                            CivexErrorCode.SCHEMA_MISMATCH,
                            f"Parameter '{p_name}' expects int, got {type(val).__name__} with value: {val_str}",
                            rpc_id=rpc_id,
                            details={'rejected_param': p_name, 'raw_sample': val_str},
                        )
                elif p_contract.expected_type is float:
                    if not isinstance(val, (int, float)) or isinstance(val, bool):
                        val_str = str(val)[:50]
                        return build_error_envelope(
                            CivexErrorCode.SCHEMA_MISMATCH,
                            f"Parameter '{p_name}' expects numeric type float, got {type(val).__name__} with value: {val_str}",
                            rpc_id=rpc_id,
                            details={'rejected_param': p_name, 'raw_sample': val_str},
                        )
                elif not isinstance(val, p_contract.expected_type):
                    val_str = str(val)[:50]
                    return build_error_envelope(
                        CivexErrorCode.SCHEMA_MISMATCH,
                        f"Parameter '{p_name}' expects type {p_contract.expected_type.__name__}, got {type(val).__name__} with value: {val_str}",
                        rpc_id=rpc_id,
                        details={'rejected_param': p_name, 'raw_sample': val_str},
                    )

                if p_contract.min_val is not None and val < p_contract.min_val:
                    return build_error_envelope(
                        CivexErrorCode.SCHEMA_MISMATCH,
                        f"Parameter '{p_name}' value {val} is below minimum {p_contract.min_val}",
                        rpc_id=rpc_id,
                    )
                if p_contract.max_val is not None and val > p_contract.max_val:
                    return build_error_envelope(
                        CivexErrorCode.SCHEMA_MISMATCH,
                        f"Parameter '{p_name}' value {val} is above maximum {p_contract.max_val}",
                        rpc_id=rpc_id,
                    )

        try:
            result_data = tool.handler(params) if tool.handler else {'status': 'ACKNOWLEDGED'}
            return {
                'jsonrpc': '2.0',
                'id': rpc_id,
                'result': result_data,
            }
        except Exception as ex:
            return build_error_envelope(
                CivexErrorCode.INTERNAL_GUARD_VIOLATION,
                f'Execution failed: {ex!s}',
                rpc_id=rpc_id,
            )
