"""
Test Suite for AIR10 Continuous Convergence & Live Backup Engine
Validates:
- SQLite WAL pragma configuration
- SHA-256 deterministic content hashing
- File stability debouncing logic
- 10x concurrent stress testing on SQLite change journal (10 threads x 50 writes)
- Multi-repo git cleanliness
"""

import os
import time
import sqlite3
import tempfile
import threading
import pytest
from pathlib import Path

from civex.sync.air10_continuous_sync_daemon import (
    init_ledger,
    compute_sha256,
    verify_file_stability,
    ContinuumSyncEngine,
)

def test_ledger_initialization(tmp_path):
    db_file = tmp_path / "test_ledger.sqlite"
    conn = init_ledger(db_file)
    cur = conn.cursor()
    
    cur.execute("PRAGMA journal_mode;")
    mode = cur.fetchone()[0]
    assert mode.lower() == "wal", f"Expected WAL mode, got {mode}"
    
    cur.execute("PRAGMA synchronous;")
    sync_mode = cur.fetchone()[0]
    # NORMAL is 1 in SQLite
    assert sync_mode in (1, "NORMAL"), f"Expected NORMAL synchronous, got {sync_mode}"
    
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sync_journal';")
    assert cur.fetchone() is not None, "sync_journal table must exist"
    conn.close()

def test_sha256_deterministic_hashing(tmp_path):
    test_file = tmp_path / "sample.txt"
    test_file.write_text("Hello Sovereign World! Phase 4 Root Cause Eradication.")
    h1 = compute_sha256(test_file)
    h2 = compute_sha256(test_file)
    assert len(h1) == 64
    assert h1 == h2

def test_file_stability_check(tmp_path):
    stable_file = tmp_path / "stable.txt"
    stable_file.write_text("Stable content")
    assert verify_file_stability(stable_file, delay_seconds=0.05) is True

def test_10x_concurrent_wal_stress_test(tmp_path):
    """
    10x Stress Test: 10 concurrent threads simultaneously writing 50 sync events
    into the SQLite WAL journal. Asserts zero locked errors and 100% record integrity.
    """
    db_file = tmp_path / "stress_ledger.sqlite"
    init_ledger(db_file).close()
    
    num_threads = 10
    writes_per_thread = 50
    errors = []
    
    def worker(thread_id):
        try:
            conn = sqlite3.connect(str(db_file), timeout=15.0)
            cur = conn.cursor()
            for i in range(writes_per_thread):
                fp = f"/mock/path/file_t{thread_id}_{i}.py"
                fhash = f"hash_{thread_id}_{i}_{time.time()}"
                cur.execute("""
                INSERT INTO sync_journal (filepath, file_hash, file_size, modified_time, status, last_sync_timestamp)
                VALUES (?, ?, 1024, ?, 'PENDING', datetime('now'))
                ON CONFLICT(filepath) DO UPDATE SET file_hash = excluded.file_hash;
                """, (fp, fhash, time.time()))
                conn.commit()
            conn.close()
        except Exception as e:
            errors.append(f"Thread {thread_id} error: {e}")

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
    start_time = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start_time

    assert len(errors) == 0, f"Encountered concurrency errors: {errors}"
    
    # Verify records
    conn = sqlite3.connect(str(db_file), timeout=15.0)
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM sync_journal;")
    total = cur.fetchone()[0]
    conn.close()
    
    assert total == num_threads * writes_per_thread
    throughput = (num_threads * writes_per_thread) / elapsed
    print(f"\n[10x Stress Test] 500 writes completed across 10 threads in {elapsed:.3f}s ({throughput:.1f} writes/sec)")

def test_git_cleanliness_audit():
    engine = ContinuumSyncEngine()
    report = engine.check_federation_git_cleanliness()
    print(f"\nFederation Git Status: {report}")
    for repo_name, status in report.items():
        assert status == "CLEAN", f"Repository {repo_name} must be CLEAN, got {status}"
