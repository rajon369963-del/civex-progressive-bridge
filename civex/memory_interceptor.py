"""
CIVEX GURU-SHISHYA IN-PROCESS LIFECYCLE MEMORY INTERCEPTOR
==========================================================
Wires runtime execution, C11 execution boundary, and agent turns
directly into the high-performance Guru-Shishya Sovereign Memory Engine
(SQLite WAL + Apple Silicon M1 Unified Memory + FTS5 BM25).

Core Contracts:
1. before_turn(): Sub-20ms context hydration with BM25 episodic recall.
2. after_turn(): Non-blocking asynchronous SQLite WAL writeback of turns & thoughts.
3. record_tool_execution(): Captures C11 supervisor process outcomes & tool telemetry.
4. record_breakthrough(): Persists atomic high-importance discoveries & facts.
5. flush(): Ensures thread-safe draining before process exit.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

# Dynamically import GuruShishyaMemoryEngine from ~/.local/bin/guru_shishya_memory.py
GURU_SCRIPT_PATH = os.path.expanduser("~/.local/bin/guru_shishya_memory.py")

def _load_guru_engine_class():
    # 1. First attempt package import
    try:
        from civex.guru_shishya_memory import GuruShishyaMemoryEngine
        return GuruShishyaMemoryEngine
    except ImportError:
        pass

    # 2. Dynamic import from ~/.local/bin/guru_shishya_memory.py if present
    if os.path.exists(GURU_SCRIPT_PATH):
        spec = importlib.util.spec_from_file_location("guru_shishya_memory", GURU_SCRIPT_PATH)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            sys.modules["guru_shishya_memory"] = mod
            spec.loader.exec_module(mod)
            return getattr(mod, "GuruShishyaMemoryEngine")
    
    # 3. Fallback to global namespace import
    try:
        from guru_shishya_memory import GuruShishyaMemoryEngine
        return GuruShishyaMemoryEngine
    except ImportError:
        pass
    return None


class GuruShishyaLifecycleInterceptor:
    """
    In-process lifecycle supervisor hook connecting CIVeX execution loop
    to Guru-Shishya episodic memory.
    """

    _instance: Optional["GuruShishyaLifecycleInterceptor"] = None

    def __init__(self, db_path: Optional[str] = None, json_path: Optional[str] = None):
        cls = _load_guru_engine_class()
        if cls is None:
            raise RuntimeError(f"Could not load GuruShishyaMemoryEngine from {GURU_SCRIPT_PATH}")
        
        kwargs = {}
        if db_path:
            kwargs["db_path"] = db_path
        if json_path:
            kwargs["json_path"] = json_path
            
        self.engine = cls(**kwargs)

    @classmethod
    def get_instance(cls, db_path: Optional[str] = None, json_path: Optional[str] = None) -> "GuruShishyaLifecycleInterceptor":
        if cls._instance is None:
            cls._instance = cls(db_path=db_path, json_path=json_path)
        return cls._instance

    def before_turn(self, user_query: str, session_id: str = "civex_session", limit: int = 4) -> str:
        """
        Sub-20ms hydration hook executed before model invocation.
        Returns formatted XML prompt block with relevant memories & profile facts.
        """
        return self.engine.get_hydrated_context(user_query=user_query, limit=limit)

    def after_turn(
        self,
        session_id: str,
        role: str,
        content: str,
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        latency_ms: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
        async_write: bool = True
    ) -> str:
        """
        Writeback hook executed after turn completes.
        Persists turn details into SQLite WAL.
        """
        if async_write:
            self.engine.record_turn_async(
                session_id=session_id,
                role=role,
                content=content,
                tool_calls=tool_calls,
                latency_ms=latency_ms,
                metadata=metadata
            )
            return f"ASYNC_ENQUEUED_{session_id}"
        else:
            return self.engine.record_turn(
                session_id=session_id,
                role=role,
                content=content,
                tool_calls=tool_calls,
                latency_ms=latency_ms,
                metadata=metadata
            )

    def record_tool_execution(
        self,
        tool_name: str,
        args: Dict[str, Any],
        output_summary: str,
        returncode: int,
        latency_ms: float,
        session_id: str = "civex_exec",
        async_write: bool = True
    ) -> str:
        """
        Captures tool execution boundary telemetry and stores as episodic memory if critical.
        """
        meta = {
            "tool_name": tool_name,
            "args": args,
            "returncode": returncode,
            "latency_ms": latency_ms
        }
        turn_text = f"Tool Execution [{tool_name}] (code={returncode}, {latency_ms:.1f}ms): {output_summary[:300]}"
        
        # If execution had an error or critical effect, record an episodic memory
        if returncode != 0:
            self.record_episodic(
                content=f"Tool failure in {tool_name}: {output_summary[:200]}",
                category="TOOL_ERROR",
                importance=1.2,
                async_write=async_write
            )

        return self.after_turn(
            session_id=session_id,
            role="tool",
            content=turn_text,
            latency_ms=latency_ms,
            metadata=meta,
            async_write=async_write
        )

    def record_episodic(
        self,
        content: str,
        category: str = "GENERAL",
        emotional_tone: str = "NEUTRAL",
        importance: float = 1.0,
        conversation_id: str = "",
        async_write: bool = True
    ) -> str:
        """Records an atomic episodic memory."""
        if async_write:
            self.engine.record_episodic_memory_async(
                content=content,
                category=category,
                emotional_tone=emotional_tone,
                importance=importance,
                conversation_id=conversation_id
            )
            return "ASYNC_ENQUEUED"
        else:
            return self.engine.record_episodic_memory(
                content=content,
                category=category,
                emotional_tone=emotional_tone,
                importance=importance,
                conversation_id=conversation_id
            )

    def search_memories(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Sub-20ms FTS5 BM25 search."""
        return self.engine.search_memories(query=query, limit=limit)

    def update_profile_fact(self, key: str, value: str, category: str = "PREFERENCE") -> None:
        """Updates durable profile facts."""
        self.engine.update_profile_fact(key=key, value=value, category=category)

    def get_stats(self) -> Dict[str, Any]:
        """Returns SQLite WAL row counts and memory health stats."""
        return self.engine.get_stats()

    def flush(self) -> None:
        """Flushes background write queue."""
        self.engine.flush()
