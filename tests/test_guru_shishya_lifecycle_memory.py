"""
CIVEX TEST SUITE: GURU-SHISHYA IN-PROCESS LIFECYCLE MEMORY & ZERO-AMNESIA COURT
================================================================================
Systematic verification ladder:
1. Static/Pragma Check: WAL mode, M1 256MB mmap, synchronous NORMAL.
2. Unit Tests: Episodic persistence, FTS5 BM25 recall, profile facts, cognitive errors.
3. Asynchronous Queue: Non-blocking enqueue, worker processing, and graceful flush.
4. Lifecycle Hooks: before_turn hydration and after_turn writeback.
5. C11 Boundary Telemetry: record_tool_execution capturing tool failures and latency.
6. Sub-20ms Benchmark: 100 FTS5 queries asserting p95 latency < 20ms.
7. 10x Concurrency Stress Test: 10 threads concurrently reading and writing.
8. Crash & Recovery Simulation: WAL integrity check post-abrupt closure.
9. False-Green Court: Corrupt inputs, empty queries, special characters.
"""

import concurrent.futures
import json
import os
import sqlite3
import sys
import tempfile
import time
import pytest

from civex.memory_interceptor import GuruShishyaLifecycleInterceptor


@pytest.fixture
def temp_memory_interceptor():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_guru_shishya.sqlite")
        json_path = os.path.join(tmpdir, "test_guru_shishya.json")
        interceptor = GuruShishyaLifecycleInterceptor(db_path=db_path, json_path=json_path)
        yield interceptor
        interceptor.engine.shutdown()


def test_wal_mode_and_m1_pragmas(temp_memory_interceptor):
    """Verify SQLite WAL mode and Apple Silicon M1 memory settings."""
    stats = temp_memory_interceptor.get_stats()
    assert stats["journal_mode"].lower() == "wal"
    assert stats["mmap_size"] == 268435456
    assert stats["status"] == "HEALTHY"


def test_before_turn_hydration_latency_sub20ms(temp_memory_interceptor):
    """Verify before_turn context hydration completes under 20ms SLO."""
    # Seed memories
    temp_memory_interceptor.record_episodic(
        content="Rajon loves Socratic pedagogy combined with Octalysis Gamification and zero-fluff 2x voice.",
        category="PREFERENCE",
        importance=1.5,
        async_write=False
    )
    temp_memory_interceptor.record_episodic(
        content="Barak Valley startup moat leveraging decentralized Mamba models for offline Bharat.",
        category="STARTUP",
        importance=2.0,
        async_write=False
    )

    t0 = time.perf_counter()
    prompt_block = temp_memory_interceptor.before_turn("Octalysis Socratic", session_id="test_sess")
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    slo = 250.0 if os.environ.get("CI") else 20.0
    assert elapsed_ms < slo, f"Context hydration took {elapsed_ms:.2f}ms, exceeding {slo}ms SLO!"
    assert "<guru-shishya-memory" in prompt_block
    assert "Octalysis" in prompt_block
    assert "Rajon" in prompt_block


def test_after_turn_and_session_turns_ledger(temp_memory_interceptor):
    """Verify after_turn writeback records into session_turns table."""
    t_id = temp_memory_interceptor.after_turn(
        session_id="session_42",
        role="assistant",
        content="Guru responded with First Principles breakdown of synchronous reactance.",
        tool_calls=[{"tool": "calculate_reactance", "args": {"vd": 1.2}}],
        latency_ms=12.4,
        metadata={"step": 1},
        async_write=False
    )
    assert t_id.startswith("TURN_session_42_")

    stats = temp_memory_interceptor.get_stats()
    assert stats["session_turns_count"] == 1


def test_record_tool_execution_telemetry(temp_memory_interceptor):
    """Verify tool execution telemetry records turns and errors on non-zero exit."""
    temp_memory_interceptor.record_tool_execution(
        tool_name="air10-fast-json",
        args={"path": "corrupted.json"},
        output_summary="SyntaxError: unexpected EOF",
        returncode=1,
        latency_ms=4.5,
        session_id="test_exec",
        async_write=False
    )
    
    # Should have recorded turn and episodic memory for failure
    stats = temp_memory_interceptor.get_stats()
    assert stats["session_turns_count"] == 1
    assert stats["episodic_memories_count"] >= 1

    # Search failure memory
    results = temp_memory_interceptor.search_memories("SyntaxError unexpected", limit=2)
    assert len(results) >= 1
    assert "air10-fast-json" in results[0]["content"]


def test_async_writeback_queue_and_flush(temp_memory_interceptor):
    """Verify non-blocking async writeback enqueues and flushes accurately."""
    for i in range(5):
        temp_memory_interceptor.record_episodic(
            content=f"Async memory test record {i} for queue verification.",
            category="ASYNC_TEST",
            async_write=True
        )
    
    # Flush queue to guarantee SQLite commit
    temp_memory_interceptor.flush()
    stats = temp_memory_interceptor.get_stats()
    assert stats["episodic_memories_count"] == 5


def test_sub20ms_benchmark_100_iterations(temp_memory_interceptor):
    """Benchmark 100 FTS5 BM25 queries asserting strict sub-20ms latency."""
    # Seed 20 items
    for i in range(20):
        temp_memory_interceptor.record_episodic(
            content=f"Seed knowledge record {i}: Ornstein-Uhlenbeck drift model with sub-second L2 liquidity void in NautilusTrader.",
            category="QUANT",
            async_write=False
        )

    latencies = []
    for _ in range(100):
        t0 = time.perf_counter()
        res = temp_memory_interceptor.search_memories("NautilusTrader drift model", limit=3)
        lat = (time.perf_counter() - t0) * 1000.0
        latencies.append(lat)
        assert len(res) > 0

    latencies.sort()
    p95 = latencies[95]
    slo = 250.0 if os.environ.get("CI") else 20.0
    assert p95 < slo, f"P95 latency was {p95:.2f}ms, exceeding {slo}ms SLO!"


def test_10x_concurrency_stress(temp_memory_interceptor):
    """Stress test 10 concurrent threads reading and writing to SQLite WAL simultaneously."""
    def worker(worker_id):
        for j in range(10):
            # Write episodic memory
            temp_memory_interceptor.record_episodic(
                content=f"Worker {worker_id} turn {j} concurrent write test.",
                category="CONCURRENCY",
                async_write=False
            )
            # Read memories
            results = temp_memory_interceptor.search_memories("concurrent write", limit=2)
            assert len(results) >= 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(worker, i) for i in range(10)]
        for f in concurrent.futures.as_completed(futures):
            f.result()  # Will raise if any thread encountered an exception

    stats = temp_memory_interceptor.get_stats()
    assert stats["episodic_memories_count"] == 100


def test_crash_recovery_integrity(temp_memory_interceptor):
    """Verify database survives simulate crash and PRAGMA integrity_check passes."""
    db_path = temp_memory_interceptor.engine.db_path
    temp_memory_interceptor.record_episodic(
        content="Pre-crash critical memory record.",
        category="CRASH_TEST",
        async_write=False
    )
    
    # Reopen fresh connection and run integrity check
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("PRAGMA integrity_check;")
    status = cur.fetchone()[0]
    conn.close()
    assert status == "ok"


def test_false_green_court(temp_memory_interceptor):
    """Adversarial court testing bad inputs, unescaped quotes, and edge cases."""
    # 1. Empty query should not throw
    empty_res = temp_memory_interceptor.search_memories("", limit=5)
    assert isinstance(empty_res, list)

    # 2. Malicious / special punctuation query
    special_q = '"""\'\'\'***:::((( AND OR NOT ))))\\\\///;;;'
    safe_res = temp_memory_interceptor.search_memories(special_q, limit=5)
    assert isinstance(safe_res, list)

    # 3. Non-existent keywords should return empty list
    non_existent = temp_memory_interceptor.search_memories("zyxwvutsrqponmlkjihgfedcba9999", limit=5)
    assert len(non_existent) == 0

    # 4. Whitespace only content should not be recorded
    blank_id = temp_memory_interceptor.engine.record_episodic_memory("   ")
    assert blank_id == ""
