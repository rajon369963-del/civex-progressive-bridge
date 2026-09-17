"""
⚡ AIR10 INTERCONNECTION² DIFFERENTIAL & PROPERTY-BASED TEST SUITE
Verifies in-process acceleration shims (§2.2), zero-fork dispatch (§3),
SQLite WAL concurrency (§4), and kill switch integrity (§7).
"""

import os
import sys
import json
import base64
import sqlite3
import tempfile
import threading
import subprocess
import pytest

def test_orjson_str_return_contract():
    """Verify json.dumps always returns str, never bytes, preserving stdlib contract."""
    payload = {"message": "Apple Silicon M1 NEON Acceleration", "code": 100, "status": True}
    encoded = json.dumps(payload)
    assert isinstance(encoded, str), f"Expected str, got {type(encoded)}"
    # Verify string concatenation works without TypeError
    line = encoded + "\n"
    assert line.endswith("\n")
    # Verify round-trip via loads
    decoded = json.loads(encoded)
    assert decoded == payload

def test_orjson_options_parity():
    """Verify sort_keys and indent options behave correctly."""
    data = {"zebra": 1, "apple": 2, "mango": 3}
    # Sort keys test
    sorted_str = json.dumps(data, sort_keys=True)
    assert '"apple"' in sorted_str
    assert sorted_str.index('"apple"') < sorted_str.index('"mango"') < sorted_str.index('"zebra"')
    
    # Indent test
    indented_str = json.dumps(data, indent=2)
    assert "\n" in indented_str
    assert "  " in indented_str

def test_orjson_nan_fallback():
    """Verify NaN/Infinity does not crash but falls back to stdlib json."""
    payload = {"value": float("nan")}
    # Should not raise orjson.JSONEncodeError
    result = json.dumps(payload)
    assert "value" in result
    assert "null" in result or "NaN" in result

def test_pybase64_byte_parity():
    """Verify pybase64 produces 100% byte-for-byte identical output to stdlib."""
    test_bytes = b"Universal Fractal Recursive 80/20 Pareto Distribution Law - Apple Silicon arm64"
    orig_b64 = base64._orig_b64encode(test_bytes)
    fast_b64 = base64.b64encode(test_bytes)
    assert orig_b64 == fast_b64
    
    orig_dec = base64._orig_b64decode(fast_b64)
    fast_dec = base64.b64decode(fast_b64)
    assert orig_dec == fast_dec == test_bytes

def test_sqlite3_wal_auto_upgrade():
    """Verify file-based SQLite databases automatically receive WAL, busy_timeout, and mmap pragmas."""
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
        db_path = tf.name

    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        
        # Check journal_mode
        cur.execute("PRAGMA journal_mode;")
        mode = cur.fetchone()[0].lower()
        assert mode == "wal", f"Expected WAL mode, got {mode}"
        
        # Check busy_timeout
        cur.execute("PRAGMA busy_timeout;")
        timeout = cur.fetchone()[0]
        assert timeout == 5000, f"Expected 5000ms busy_timeout, got {timeout}"
        
        # Check mmap_size
        cur.execute("PRAGMA mmap_size;")
        mmap = cur.fetchone()[0]
        assert mmap >= 134217728, f"Expected >= 128MB mmap_size, got {mmap}"
        
        conn.close()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

def test_sqlite3_concurrency_stress():
    """Verify 10 concurrent threads can write to SQLite WAL without 'database is locked'."""
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
        db_path = tf.name

    try:
        # Initialize schema
        init_conn = sqlite3.connect(db_path)
        init_conn.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, thread_id INT, val TEXT);")
        init_conn.commit()
        init_conn.close()

        errors = []
        def worker(thread_idx):
            try:
                conn = sqlite3.connect(db_path)
                for i in range(25):
                    conn.execute("INSERT INTO records (thread_id, val) VALUES (?, ?);", (thread_idx, f"thread_{thread_idx}_{i}"))
                    conn.commit()
                conn.close()
            except Exception as e:
                errors.append((thread_idx, str(e)))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Encountered concurrency locking errors: {errors}"
        
        # Verify row count
        check_conn = sqlite3.connect(db_path)
        cur = check_conn.cursor()
        cur.execute("SELECT COUNT(*) FROM records;")
        count = cur.fetchone()[0]
        assert count == 250, f"Expected 250 records, found {count}"
        check_conn.close()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

def test_kill_switch_behavior():
    """Verify AIR1_SHIM_OFF=1 completely disables shimming in subshells."""
    cmd = [
        sys.executable, "-c",
        "import json, base64, sqlite3; "
        "print(getattr(json, '_air10_accelerated', False), "
        "getattr(base64, '_air10_neon_accelerated', False), "
        "getattr(sqlite3, '_air10_wal_accelerated', False))"
    ]
    env = os.environ.copy()
    env["AIR1_SHIM_OFF"] = "1"
    
    out = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert out.returncode == 0
    stdout = out.stdout.strip()
    assert "False False False" in stdout

def test_ast_guard_detection():
    """Verify air1_ast_guard.py accurately detects banned patterns."""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as tf:
        tf.write("""
import json
import glob
import subprocess

def bad_func():
    subprocess.run("ls -la", shell=True)
""")
        script_path = tf.name

    try:
        guard_bin = "/Users/rajondas/.air1/air1_ast_guard.py"
        out = subprocess.run([guard_bin, script_path, "--json"], capture_output=True, text=True)
        assert out.returncode == 0
        data = json.loads(out.stdout)
        assert data["total_errors"] >= 1  # shell=True flagged as ERROR
        assert data["total_warnings"] >= 2  # json & glob imports flagged as WARNING
    finally:
        if os.path.exists(script_path):
            os.remove(script_path)
