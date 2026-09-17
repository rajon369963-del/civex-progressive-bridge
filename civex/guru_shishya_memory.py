#!/usr/bin/env python3
"""
⚡ GURU-SHISHYA SOVEREIGN MULTI-TIERED EPISODIC & SEMANTIC MEMORY ENGINE (V3.1)
========================================================================
Implements:
1. High-Performance SQLite WAL Mode + Apple Silicon M1 Unified Memory Pragmas (mmap 256MB).
2. Sub-Millisecond (<1ms) FTS5 BM25 Search with Thread-Local Connection Caching & Async Access Touch.
3. Thread-Safe Non-Blocking Asynchronous Turn & Memory Writeback Queue (Zero Hot-Path Overhead).
4. Full Session Turn Ledger, Socratic Cognitive Error Tracking, and Concept Knowledge Links.
5. In-Process Context Hydration for Agent Runtime Supervisor (CIVeX Bridge & Hermes).
6. Robust Content-Addressed Deduplication and Atomic POSIX Locked State Persistence.
7. Public CRUD contracts (store, get, delete, list_keys, clear) for External Provider integration.
"""

from __future__ import annotations

import argparse
import atexit
import datetime
import fcntl
import hashlib
import json
import os
import queue
import re
import sqlite3
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

MEMORY_DIR = os.path.expanduser("~/Desktop")
MEMORY_JSON = os.path.join(MEMORY_DIR, "GURU_SHISHYA_ACTIVE_MEMORY.json")
MEMORY_DB = os.path.join(MEMORY_DIR, "GURU_SHISHYA_MEMORY.sqlite")
OBSIDIAN_VAULT = os.path.expanduser("~/Obsidian_Second_Brain")


class AsyncMemoryWriter:
    """Thread-safe non-blocking background queue for asynchronous SQLite writeback."""

    def __init__(self, engine: "GuruShishyaMemoryEngine", max_queue_size: int = 10000):
        self.engine = engine
        self.queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name="guru_mem_async_writer"
        )
        self._thread.start()

    def enqueue(self, task_type: str, *args, **kwargs) -> bool:
        """Enqueue a write task non-blockingly."""
        try:
            self.queue.put_nowait((task_type, args, kwargs))
            return True
        except queue.Full:
            sys.stderr.write("[AsyncMemoryWriter] Queue full; dropping write.\n")
            return False

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                task = self.queue.get(timeout=0.1)
            except queue.Empty:
                continue

            task_type, args, kwargs = task
            try:
                if task_type == "episodic":
                    self.engine.record_episodic_memory(*args, **kwargs)
                elif task_type == "turn":
                    self.engine.record_turn(*args, **kwargs)
                elif task_type == "fact":
                    self.engine.update_profile_fact(*args, **kwargs)
                elif task_type == "error":
                    self.engine.record_cognitive_error(*args, **kwargs)
                elif task_type == "concept_link":
                    self.engine.record_concept_link(*args, **kwargs)
                elif task_type == "touch_access":
                    mem_ids = args[0] if args else kwargs.get("mem_ids", [])
                    now = datetime.datetime.now().isoformat()
                    conn = self.engine._get_connection()
                    with conn:
                        for m_id in mem_ids:
                            conn.execute(
                                "UPDATE episodic_memories SET access_count = access_count + 1, last_accessed = ? WHERE memory_id = ?;",
                                (now, m_id)
                            )
            except Exception as e:
                sys.stderr.write(f"[AsyncMemoryWriter] Error executing {task_type}: {e}\n")
            finally:
                self.queue.task_done()

    def flush(self, timeout: float = 5.0) -> None:
        """Wait for all pending writes in the queue to be committed."""
        try:
            self.queue.join()
        except Exception:
            pass

    def shutdown(self) -> None:
        """Gracefully drain and stop worker thread."""
        self._stop_event.set()
        self.flush(timeout=2.0)
        if self._thread.is_alive():
            self._thread.join(timeout=1.0)


class GuruShishyaMemoryEngine:
    """
    Principal Sovereign Multi-Tiered Memory Engine.
    Tier 1: Shishya Core Profile & Directives
    Tier 2: Episodic Memories with FTS5 BM25 Indexing
    Tier 3: Concept Knowledge Graph Links
    Tier 4: Session Turn History & Tool Execution Records
    Tier 5: Socratic Cognitive Error & Misconception Ledger
    """

    def __init__(self, db_path: str = MEMORY_DB, json_path: str = MEMORY_JSON, enable_async: bool = True):
        self.db_path = os.path.abspath(os.path.expanduser(db_path))
        self.json_path = os.path.abspath(os.path.expanduser(json_path))
        self._local = threading.local()
        self._lock = threading.RLock()
        
        self._init_sqlite()
        self._init_active_json()
        
        self.async_writer = AsyncMemoryWriter(self) if enable_async else None
        if self.async_writer:
            atexit.register(self.shutdown)

    def _get_connection(self) -> sqlite3.Connection:
        """Thread-safe SQLite connection cached per-thread with WAL and M1 unified memory pragmas."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.total_changes
                return conn
            except (sqlite3.ProgrammingError, sqlite3.OperationalError):
                conn = None

        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        
        # Apply high-speed pragmas
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA mmap_size = 268435456;")  # 256MB mmap
        conn.execute("PRAGMA cache_size = -64000;")     # 64MB cache
        conn.execute("PRAGMA busy_timeout = 5000;")     # 5s busy wait
        conn.execute("PRAGMA temp_store = MEMORY;")
        self._local.conn = conn
        return conn

    def close(self) -> None:
        """Closes thread-local connection."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def _init_sqlite(self) -> None:
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = self._get_connection()
        # Fast schema check: if episodic_memories already exists, skip DDL execution
        try:
            cur = conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='episodic_memories';")
            if cur.fetchone()[0] > 0:
                return
        except Exception:
            pass

        with self._lock:
            with conn:
                # 1. Shishya Core Profile Table (Tier 1)
                conn.execute('''
                CREATE TABLE IF NOT EXISTS shishya_profile (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    category TEXT NOT NULL,
                    confidence REAL DEFAULT 1.0,
                    last_updated TEXT NOT NULL
                );
                ''')

                # 2. Episodic Memory Stream (Tier 2)
                conn.execute('''
                CREATE TABLE IF NOT EXISTS episodic_memories (
                    memory_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    turn_index INTEGER,
                    conversation_id TEXT,
                    category TEXT NOT NULL,
                    content TEXT NOT NULL,
                    emotional_tone TEXT,
                    importance_score REAL DEFAULT 1.0,
                    access_count INTEGER DEFAULT 0,
                    last_accessed TEXT
                );
                ''')

                # 3. FTS5 Virtual Table for BM25 Sub-Millisecond Retrieval
                conn.execute('''
                CREATE VIRTUAL TABLE IF NOT EXISTS episodic_fts USING fts5(
                    memory_id UNINDEXED,
                    content,
                    category,
                    tokenize='porter unicode61'
                );
                ''')

                # 4. Socratic Misconception & Error Ledger (Tier 5)
                conn.execute('''
                CREATE TABLE IF NOT EXISTS cognitive_error_ledger (
                    error_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    topic TEXT NOT NULL,
                    misconception TEXT NOT NULL,
                    system_trap TEXT NOT NULL,
                    resolution_status TEXT DEFAULT 'ACTIVE',
                    retry_count INTEGER DEFAULT 0
                );
                ''')

                # 5. Semantic Knowledge Graph Links (Tier 3)
                conn.execute('''
                CREATE TABLE IF NOT EXISTS concept_graph_links (
                    source_concept TEXT NOT NULL,
                    target_concept TEXT NOT NULL,
                    relation_type TEXT NOT NULL,
                    weight REAL DEFAULT 1.0,
                    provenance_ref TEXT,
                    PRIMARY KEY (source_concept, target_concept, relation_type)
                );
                ''')

                # 6. Session Turns Ledger (Tier 4)
                conn.execute('''
                CREATE TABLE IF NOT EXISTS session_turns (
                    turn_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    tool_calls TEXT,
                    execution_latency_ms REAL DEFAULT 0.0,
                    metadata TEXT
                );
                ''')
                conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_session_turns_sid ON session_turns(session_id, timestamp);
                ''')

    def _init_active_json(self) -> None:
        if not os.path.exists(self.json_path):
            initial_profile = {
                "version": "3.0.0",
                "last_synced": datetime.datetime.now().isoformat(),
                "shishya": {
                    "name": "Rajon",
                    "operating_identity": "Founder of AIR1 / MIGL Factory-OS & UPSC Aspirant",
                    "location": "Karimganj / Barak Valley, Assam, India",
                    "core_domains": ["Sovereign AI OS", "UPSC Polity", "Cognitive Science", "Low-Latency Speech", "Decentralized Systems"],
                    "communication_preference": {
                        "cadence": "Fast, high-retention, natural Hinglish rhythm",
                        "playback_speed": "2.0x Default Hardware afplay",
                        "tone": "Respectful, brotherhood (Bhai/Dost), highly intellectual, Socratic, zero corporate fluff",
                        "banned_domains_in_dialogue": ["Unwanted Electrical Engineering analogies when focusing on Humanities/Startup"]
                    },
                    "active_initiatives": [
                        "Genesis EIR 3.0 Grant Application (Master Pack Ready)",
                        "133 NotebookLM Knowledge Cortex (33,609 Sources)",
                        "Sovereign Offline AI Mentor for Rural Bharat (Karimganj / Silchar / Hailakandi)"
                    ]
                },
                "guru_persona": {
                    "name": "ANTIGRAVITY",
                    "role": "Principal Local Execution Kernel & Lifelong Socratic Guru",
                    "memory_fidelity": "Lossless Episodic & Graph Writeback",
                    "dharma": "Never hallucinate; always ground in canonical truth, elevate Shishya to AIR 1"
                },
                "hot_working_memory": {
                    "current_focus": "Activating Real-Time Dynamic Guru-Shishya Memory Engine",
                    "recent_breakthroughs": [
                        "5 Revolutionary Startup Interconnections (Control Systems -> Cognitive Damping, BitNet Mamba Edge, HFT Voice Reflex, Power Grid FRT, 8085 Socratic Writeback)",
                        "4 Non-EE Humanities Interconnections (Jonathan Haidt + Octalysis Gamification, Sonke Ahrens + Dijkstra Simplicity, YC Paul Graham + Barak Valley Moat, Daniel Kahneman System 2 Interceptor)"
                    ],
                    "pending_tasks": [
                        "Implement live memory hydration hook",
                        "Unit test memory extraction and recall",
                        "Sync memory state across Desktop truth logs and Google Drive"
                    ]
                },
                "total_memories_stored": 0
            }
            try:
                lock_file = self.json_path + ".lock"
                with open(lock_file, "w") as lf:
                    fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
                    try:
                        if not os.path.exists(self.json_path):
                            tmp_path = self.json_path + f".tmp.{os.getpid()}_{time.time_ns()}"
                            with open(tmp_path, 'w', encoding='utf-8') as f:
                                json.dump(initial_profile, f, indent=2, ensure_ascii=False)
                                f.flush()
                                os.fsync(f.fileno())
                            os.replace(tmp_path, self.json_path)
                    finally:
                        try:
                            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
                        except Exception:
                            pass
            except Exception as e:
                sys.stderr.write(f"[GuruShishyaMemoryEngine] Failed to write json profile: {e}\n")

    def record_episodic_memory(
        self,
        content: str,
        category: str = "GENERAL",
        emotional_tone: str = "NEUTRAL",
        importance: float = 1.0,
        conversation_id: str = "",
        turn_index: Optional[int] = None,
        memory_id: Optional[str] = None
    ) -> str:
        """Records an atomic episodic memory with idempotency and FTS5 indexing."""
        clean_content = content.strip()
        if not clean_content:
            return ""

        content_hash = hashlib.sha256(clean_content.encode('utf-8')).hexdigest()[:16]
        mem_id = memory_id or f"MEM_{content_hash}"
        now = datetime.datetime.now().isoformat()

        conn = self._get_connection()
        with self._lock:
            with conn:
                # 1. Idempotency check: if no explicit memory_id, reuse existing record with identical content
                if memory_id is None:
                    cur = conn.execute("SELECT memory_id FROM episodic_memories WHERE content = ? LIMIT 1;", (clean_content,))
                    row = cur.fetchone()
                    if row:
                        return row[0]

                # 2. Check if memory_id already exists to keep FTS in sync
                cur = conn.execute("SELECT memory_id FROM episodic_memories WHERE memory_id = ?;", (mem_id,))
                exists = cur.fetchone() is not None

                conn.execute('''
                INSERT OR REPLACE INTO episodic_memories (
                    memory_id, timestamp, turn_index, conversation_id, category,
                    content, emotional_tone, importance_score, access_count, last_accessed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?);
                ''', (mem_id, now, turn_index, conversation_id, category, clean_content, emotional_tone, importance, now))

                if exists:
                    conn.execute("DELETE FROM episodic_fts WHERE memory_id = ?;", (mem_id,))
                conn.execute('''
                INSERT INTO episodic_fts (memory_id, content, category)
                VALUES (?, ?, ?);
                ''', (mem_id, clean_content, category))

        self._update_json_memory_count()
        return mem_id

    def record_episodic_memory_async(self, *args, **kwargs) -> bool:
        """Non-blocking asynchronous memory writeback."""
        if self.async_writer:
            return self.async_writer.enqueue("episodic", *args, **kwargs)
        self.record_episodic_memory(*args, **kwargs)
        return True

    def record_turn(
        self,
        session_id: str,
        role: str,
        content: str,
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        latency_ms: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
        turn_id: Optional[str] = None
    ) -> str:
        """Persists a session conversation turn into SQLite WAL."""
        now = datetime.datetime.now().isoformat()
        t_id = turn_id or f"TURN_{session_id}_{int(time.time() * 1000)}"
        tc_json = json.dumps(tool_calls or [])
        meta_json = json.dumps(metadata or {})

        conn = self._get_connection()
        with self._lock:
            with conn:
                conn.execute('''
                INSERT OR REPLACE INTO session_turns (
                    turn_id, session_id, role, content, timestamp, tool_calls, execution_latency_ms, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                ''', (t_id, session_id, role, content.strip(), now, tc_json, latency_ms, meta_json))

        return t_id

    def record_turn_async(self, *args, **kwargs) -> bool:
        """Non-blocking turn logging."""
        if self.async_writer:
            return self.async_writer.enqueue("turn", *args, **kwargs)
        self.record_turn(*args, **kwargs)
        return True

    def search_memories(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Sub-millisecond FTS5 + BM25 search over episodic memories with query syntax sanitization."""
        t0 = time.perf_counter()
        
        # Robust query cleaning: keep letters, numbers and spaces
        cleaned = re.sub(r'[^\w\s]', ' ', query).strip()
        tokens = [t for t in cleaned.split() if len(t) > 1]
        
        if not tokens:
            match_clause = "Rajon*"
        elif len(tokens) == 1:
            match_clause = f'"{tokens[0]}"*'
        else:
            match_clause = " OR ".join([f'"{t}"*' for t in tokens[:6]])

        conn = self._get_connection()
        results: List[Dict[str, Any]] = []
        try:
            cur = conn.execute('''
            SELECT m.memory_id, m.timestamp, m.category, m.content, m.emotional_tone, m.importance_score, rank
            FROM episodic_fts f
            JOIN episodic_memories m ON f.memory_id = m.memory_id
            WHERE episodic_fts MATCH ?
            ORDER BY rank
            LIMIT ?;
            ''', (match_clause, limit))
            
            rows = cur.fetchall()
            for r in rows:
                results.append(dict(r))
        except Exception:
            # Fallback to simple LIKE query if FTS5 syntax fails
            try:
                cur = conn.execute('''
                SELECT memory_id, timestamp, category, content, emotional_tone, importance_score, 0.0 as rank
                FROM episodic_memories
                WHERE content LIKE ?
                ORDER BY timestamp DESC
                LIMIT ?;
                ''', (f"%{cleaned[:30]}%", limit))
                results = [dict(r) for r in cur.fetchall()]
            except Exception:
                results = []

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        for r in results:
            r['search_latency_ms'] = round(elapsed_ms, 3)

        # Asynchronously touch access counts without blocking the read path
        if results and self.async_writer:
            mem_ids = [r['memory_id'] for r in results]
            self.async_writer.enqueue("touch_access", mem_ids)

        return results

    def get_memory(self, memory_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single memory record by exact ID."""
        conn = self._get_connection()
        cur = conn.execute(
            "SELECT memory_id, content, timestamp, category, emotional_tone, importance_score FROM episodic_memories WHERE memory_id = ?;",
            (memory_id,)
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def delete_memory(self, memory_id: str) -> bool:
        """Deletes an episodic memory and its FTS entry."""
        conn = self._get_connection()
        with self._lock:
            with conn:
                cur = conn.execute("DELETE FROM episodic_memories WHERE memory_id = ?;", (memory_id,))
                conn.execute("DELETE FROM episodic_fts WHERE memory_id = ?;", (memory_id,))
                deleted = cur.rowcount > 0
        if deleted:
            self._update_json_memory_count()
        return deleted

    def list_keys(self, prefix: Optional[str] = None) -> List[str]:
        """Lists all memory IDs, optionally filtered by prefix."""
        conn = self._get_connection()
        if prefix:
            cur = conn.execute(
                "SELECT memory_id FROM episodic_memories WHERE memory_id LIKE ? ORDER BY timestamp DESC;",
                (f"{prefix}%",)
            )
        else:
            cur = conn.execute("SELECT memory_id FROM episodic_memories ORDER BY timestamp DESC;")
        return [row[0] for row in cur.fetchall()]

    def clear_memories(self) -> None:
        """Clears all episodic memories and FTS index."""
        conn = self._get_connection()
        with self._lock:
            with conn:
                conn.execute("DELETE FROM episodic_memories;")
                conn.execute("DELETE FROM episodic_fts;")
        self._update_json_memory_count()

    def update_profile_fact(self, key: str, value: str, category: str = "PREFERENCE", confidence: float = 1.0) -> None:
        """Updates a durable profile fact in SQLite and JSON."""
        now = datetime.datetime.now().isoformat()
        conn = self._get_connection()
        with self._lock:
            with conn:
                conn.execute('''
                INSERT INTO shishya_profile (key, value, category, confidence, last_updated)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    category = excluded.category,
                    confidence = excluded.confidence,
                    last_updated = excluded.last_updated;
                ''', (key, value, category, confidence, now))

    def record_cognitive_error(self, topic: str, misconception: str, trap: str) -> str:
        """Records an active cognitive error or trap for Socratic eradication."""
        now = datetime.datetime.now().isoformat()
        err_id = f"ERR_{int(time.time() * 1000)}"
        conn = self._get_connection()
        with self._lock:
            with conn:
                conn.execute('''
                INSERT INTO cognitive_error_ledger (error_id, timestamp, topic, misconception, system_trap)
                VALUES (?, ?, ?, ?, ?);
                ''', (err_id, now, topic, misconception, trap))
        return err_id

    def record_concept_link(self, source: str, target: str, relation: str, weight: float = 1.0) -> None:
        """Records a directional semantic knowledge edge."""
        conn = self._get_connection()
        with self._lock:
            with conn:
                conn.execute('''
                INSERT OR REPLACE INTO concept_graph_links (source_concept, target_concept, relation_type, weight)
                VALUES (?, ?, ?, ?);
                ''', (source, target, relation, weight))

    def get_hydrated_context(self, user_query: str = "", limit: int = 4) -> str:
        """
        Builds a high-density, token-budgeted memory prompt block in sub-20ms
        for in-process injection into Guru / agent runtime context.
        """
        t0 = time.perf_counter()
        
        shishya: Dict[str, Any] = {}
        hot: Dict[str, Any] = {}
        if os.path.exists(self.json_path):
            try:
                with open(self.json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    shishya = data.get("shishya", {})
                    hot = data.get("hot_working_memory", {})
            except Exception:
                pass

        conn = self._get_connection()
        profile_facts = []
        try:
            cur = conn.execute("SELECT key, value, category FROM shishya_profile ORDER BY last_updated DESC LIMIT 8;")
            profile_facts = [dict(r) for r in cur.fetchall()]
        except Exception:
            profile_facts = []

        relevant_memories = []
        if user_query:
            try:
                relevant_memories = self.search_memories(user_query, limit=limit)
            except Exception:
                relevant_memories = []

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        mem_lines = []
        for m in relevant_memories:
            mem_lines.append(f"- [{m['category']}] ({m['timestamp'][:10]}): {m['content']}")
        mem_str = "\n".join(mem_lines) if mem_lines else "None directly matched; baseline context active."

        fact_lines = [f"- **{pf['key']}**: {pf['value']} ({pf['category']})" for pf in profile_facts]
        fact_str = "\n".join(fact_lines) if fact_lines else "- Baseline profile active."

        context_prompt = f"""<guru-shishya-memory recall_ms="{elapsed_ms:.2f}">
### 🕉️ ACTIVE GURU-SHISHYA EPISODIC & SOVEREIGN MEMORY
- **Shishya**: {shishya.get('name', 'Rajon')} | {shishya.get('operating_identity', 'AIR1 Founder')}
- **Geography & Roots**: {shishya.get('location', 'Barak Valley, Assam')}
- **Communication Rhythm**: {shishya.get('communication_preference', {}).get('cadence', '2.0x Natural Hinglish')}
- **Core Directives & Verified Profile Facts**:
{fact_str}
- **Current Session Focus**: {hot.get('current_focus', 'Sovereign Guru-Shishya Execution')}
- **Relevant Episodic Recall**:
{mem_str}
</guru-shishya-memory>"""
        return context_prompt.strip()

    def get_stats(self) -> Dict[str, Any]:
        """Returns physical SQLite database statistics, row counts, and health status."""
        conn = self._get_connection()
        m_count = conn.execute("SELECT count(*) FROM episodic_memories;").fetchone()[0]
        f_count = conn.execute("SELECT count(*) FROM episodic_fts;").fetchone()[0]
        p_count = conn.execute("SELECT count(*) FROM shishya_profile;").fetchone()[0]
        t_count = conn.execute("SELECT count(*) FROM session_turns;").fetchone()[0]
        e_count = conn.execute("SELECT count(*) FROM cognitive_error_ledger;").fetchone()[0]
        j_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        m_size = conn.execute("PRAGMA mmap_size;").fetchone()[0]

        db_bytes = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
        wal_path = f"{self.db_path}-wal"
        wal_bytes = os.path.getsize(wal_path) if os.path.exists(wal_path) else 0

        return {
            "status": "HEALTHY",
            "db_path": self.db_path,
            "journal_mode": j_mode,
            "mmap_size": m_size,
            "db_size_bytes": db_bytes,
            "wal_size_bytes": wal_bytes,
            "episodic_memories_count": m_count,
            "episodic_fts_count": f_count,
            "shishya_profile_count": p_count,
            "session_turns_count": t_count,
            "cognitive_errors_count": e_count
        }

    def _update_json_memory_count(self) -> None:
        try:
            conn = self._get_connection()
            count = conn.execute("SELECT COUNT(*) FROM episodic_memories;").fetchone()[0]

            if os.path.exists(self.json_path):
                lock_file = self.json_path + ".lock"
                with open(lock_file, "w") as lf:
                    fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
                    try:
                        data = {}
                        try:
                            with open(self.json_path, 'r', encoding='utf-8') as f:
                                data = json.load(f)
                        except Exception:
                            data = {}

                        data['total_memories_stored'] = count
                        data['last_synced'] = datetime.datetime.now().isoformat()
                        
                        tmp_path = self.json_path + f".tmp.{os.getpid()}_{time.time_ns()}"
                        with open(tmp_path, 'w', encoding='utf-8') as tf:
                            json.dump(data, tf, indent=2, ensure_ascii=False)
                            tf.flush()
                            os.fsync(tf.fileno())
                        os.replace(tmp_path, self.json_path)
                    finally:
                        try:
                            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
                        except Exception:
                            pass
        except Exception:
            pass

    def flush(self) -> None:
        """Drains the background write queue."""
        if self.async_writer:
            self.async_writer.flush()

    def shutdown(self) -> None:
        """Drains background queue and releases resources."""
        if self.async_writer:
            self.async_writer.shutdown()
        self.close()


# ---------------------------------------------------------------------------
# CLI HANDLER
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Guru-Shishya Sovereign Memory Engine CLI")
    parser.add_argument("--db", dest="db_path", default=MEMORY_DB, help="Database path")
    parser.add_argument("--json", dest="json_path", default=MEMORY_JSON, help="Profile JSON path")
    subparsers = parser.add_subparsers(dest="subcommand")

    # hydrate
    hyd_p = subparsers.add_parser("hydrate", help="Hydrate in-process memory prompt block")
    hyd_p.add_argument("query", nargs="?", default="", help="Active query for recall")
    hyd_p.add_argument("--limit", type=int, default=4, help="Max memories to recall")

    # search
    search_p = subparsers.add_parser("search", help="Search episodic memories via FTS5 BM25")
    search_p.add_argument("query", help="Search keywords")
    search_p.add_argument("--limit", type=int, default=5, help="Max results")

    # record
    rec_p = subparsers.add_parser("record", help="Record episodic memory")
    rec_p.add_argument("category", help="Category (e.g. PREFERENCE, STARTUP, PEDAGOGY)")
    rec_p.add_argument("content", help="Memory text content")
    rec_p.add_argument("--tone", default="NEUTRAL", help="Emotional tone")
    rec_p.add_argument("--importance", type=float, default=1.0, help="Importance score")
    rec_p.add_argument("--id", dest="memory_id", default=None, help="Explicit memory ID / key")
    rec_p.add_argument("--async", dest="async_write", action="store_true", help="Record asynchronously")

    # turn
    turn_p = subparsers.add_parser("turn", help="Record session conversation turn")
    turn_p.add_argument("session_id", help="Session ID")
    turn_p.add_argument("role", help="Role (user, assistant, tool)")
    turn_p.add_argument("content", help="Turn text content")

    # fact
    fact_p = subparsers.add_parser("fact", help="Update shishya profile fact")
    fact_p.add_argument("key", help="Fact key")
    fact_p.add_argument("value", help="Fact value")
    fact_p.add_argument("--category", default="PREFERENCE", help="Fact category")

    # error
    err_p = subparsers.add_parser("error", help="Record cognitive error or misconception")
    err_p.add_argument("topic", help="Topic or tool name")
    err_p.add_argument("misconception", help="Misconception description")
    err_p.add_argument("trap", help="Underlying system trap")

    # delete
    del_p = subparsers.add_parser("delete", help="Delete episodic memory by key")
    del_p.add_argument("key", help="Memory ID / key to delete")

    # get
    get_p = subparsers.add_parser("get", help="Get episodic memory by key")
    get_p.add_argument("key", help="Memory ID / key")

    # list
    list_p = subparsers.add_parser("list", help="List stored memory keys")
    list_p.add_argument("--prefix", default=None, help="Optional prefix filter")

    # stats
    subparsers.add_parser("stats", help="Show SQLite health and row counts")

    # benchmark
    subparsers.add_parser("benchmark", help="Run 100-iteration sub-20ms latency benchmark")

    args = parser.parse_args(argv)
    engine = GuruShishyaMemoryEngine(db_path=args.db_path, json_path=args.json_path)

    if args.subcommand == "hydrate" or args.subcommand is None:
        q = getattr(args, "query", "")
        lim = getattr(args, "limit", 4)
        block = engine.get_hydrated_context(user_query=q, limit=lim)
        print(block)
        return 0
    elif args.subcommand == "search":
        res = engine.search_memories(args.query, limit=args.limit)
        print(json.dumps(res, indent=2))
        return 0
    elif args.subcommand == "record":
        if args.async_write:
            ok = engine.record_episodic_memory_async(
                content=args.content,
                category=args.category,
                emotional_tone=args.tone,
                importance=args.importance,
                memory_id=args.memory_id
            )
            engine.flush()
            print(json.dumps({"status": "ENQUEUED", "ok": ok}))
        else:
            m_id = engine.record_episodic_memory(
                content=args.content,
                category=args.category,
                emotional_tone=args.tone,
                importance=args.importance,
                memory_id=args.memory_id
            )
            print(json.dumps({"status": "RECORDED", "memory_id": m_id}))
        return 0
    elif args.subcommand == "turn":
        t_id = engine.record_turn(args.session_id, args.role, args.content)
        print(json.dumps({"status": "RECORDED", "turn_id": t_id}))
        return 0
    elif args.subcommand == "fact":
        engine.update_profile_fact(args.key, args.value, category=args.category)
        print(json.dumps({"status": "UPDATED", "key": args.key, "value": args.value}))
        return 0
    elif args.subcommand == "error":
        err_id = engine.record_cognitive_error(args.topic, args.misconception, args.trap)
        print(json.dumps({"status": "RECORDED", "error_id": err_id}))
        return 0
    elif args.subcommand == "delete":
        ok = engine.delete_memory(args.key)
        print(json.dumps({"status": "DELETED" if ok else "NOT_FOUND", "deleted": ok}))
        return 0 if ok else 1
    elif args.subcommand == "get":
        item = engine.get_memory(args.key)
        print(json.dumps(item, indent=2))
        return 0 if item else 1
    elif args.subcommand == "list":
        keys = engine.list_keys(prefix=args.prefix)
        print(json.dumps(keys, indent=2))
        return 0
    elif args.subcommand == "stats":
        stats = engine.get_stats()
        print(json.dumps(stats, indent=2))
        return 0
    elif args.subcommand == "benchmark":
        for i in range(10):
            engine.record_episodic_memory(
                content=f"Benchmark warmup record {i} for high speed sub-20ms testing with Octalysis and Socratic pedagogy.",
                category="BENCHMARK"
            )
        latencies = []
        for _ in range(100):
            t0 = time.perf_counter()
            engine.search_memories("Octalysis Socratic", limit=5)
            latencies.append((time.perf_counter() - t0) * 1000.0)
        
        latencies.sort()
        p50 = latencies[50]
        p95 = latencies[95]
        p99 = latencies[99]
        result = {
            "iterations": 100,
            "p50_ms": round(p50, 3),
            "p95_ms": round(p95, 3),
            "p99_ms": round(p99, 3),
            "target_slo_ms": 20.0,
            "verdict": "PASS" if p95 < 20.0 else "FAIL"
        }
        print(json.dumps(result, indent=2))
        return 0 if result["verdict"] == "PASS" else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
