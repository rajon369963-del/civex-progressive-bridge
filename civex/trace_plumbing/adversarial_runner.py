import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

VALIDATOR = "/Users/rajondas/.antigravity/trace_plumbing/air10_cross_trace_readback.py"
BASE_DB = "/Users/rajondas/.antigravity/air10_audit.db"
BASE_SHIM = "/Users/rajondas/.antigravity/shim_intercept.log"

conn = sqlite3.connect(BASE_DB)
cur = conn.cursor()
cur.execute("SELECT t.trace_id FROM tool_traces_v2 t WHERE (SELECT COUNT(*) FROM trace_events WHERE trace_id = t.trace_id) >= 5 AND (SELECT COUNT(*) FROM trace_events WHERE trace_id = t.trace_id AND parent_span_id = 'ROOT_SPAN') = 1 ORDER BY t.created_at DESC LIMIT 1;")
row = cur.fetchone()
conn.close()

if not row:
    print("FATAL: No baseline trace found in database!", file=sys.stderr)
    sys.exit(1)

BASELINE_TRACE_ID = row[0]
print(f"Baseline Trace ID for Adversarial Testing: {BASELINE_TRACE_ID}")

test_results = []

def run_test(name, mutate_fn, expect_exit_code=1, python_flags=[]):
    temp_dir = tempfile.mkdtemp(prefix="court_adv_")
    test_db = os.path.join(temp_dir, "test_audit.db")
    test_shim = os.path.join(temp_dir, "test_shim.log")

    shutil.copy2(BASE_DB, test_db)
    if os.path.exists(BASE_SHIM):
        shutil.copy2(BASE_SHIM, test_shim)
    else:
        with open(test_shim, "w") as f:
            f.write("")

    conn = sqlite3.connect(test_db)
    conn.execute("DROP TRIGGER IF EXISTS abort_trace_events_update;")
    conn.execute("DROP TRIGGER IF EXISTS abort_trace_events_delete;")
    conn.execute("DROP TRIGGER IF EXISTS abort_tool_traces_v2_update;")
    conn.execute("DROP TRIGGER IF EXISTS abort_tool_traces_v2_delete;")
    mutate_fn(conn, test_shim)
    conn.commit()
    conn.close()

    cmd = [sys.executable] + python_flags + [VALIDATOR, BASELINE_TRACE_ID, test_db, test_shim]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    passed = (proc.returncode == expect_exit_code)
    verdict = "PASS" if passed else "FAIL"
    err_snippet = " ".join(proc.stderr.strip().splitlines())[:120]
    test_results.append((name, expect_exit_code, proc.returncode, verdict, err_snippet))

    shutil.rmtree(temp_dir)
    return passed

# 1. Wrong Stage Order
def m_stage_order(conn, shim):
    cur = conn.cursor()
    cur.execute("SELECT event_id FROM trace_events WHERE trace_id=? AND stage='PROCESS_EXECUTION';", (BASELINE_TRACE_ID,))
    eid1 = cur.fetchone()[0]
    cur.execute("SELECT event_id FROM trace_events WHERE trace_id=? AND stage='INDEPENDENT_VERIFICATION';", (BASELINE_TRACE_ID,))
    eid2 = cur.fetchone()[0]
    cur.execute("UPDATE trace_events SET stage='INDEPENDENT_VERIFICATION' WHERE event_id=?", (eid1,))
    cur.execute("UPDATE trace_events SET stage='PROCESS_EXECUTION' WHERE event_id=?", (eid2,))

run_test("1. Wrong Stage Order (EXEC <-> VERIF swapped)", m_stage_order, expect_exit_code=1)

# 2. Wrong Causal Parent (VERIF points to ROUTER)
def m_wrong_parent(conn, shim):
    cur = conn.cursor()
    cur.execute("SELECT span_id FROM trace_events WHERE trace_id=? AND stage='ROUTER_EVALUATION';", (BASELINE_TRACE_ID,))
    router_span = cur.fetchone()[0]
    cur.execute("UPDATE trace_events SET parent_span_id=? WHERE trace_id=? AND stage='INDEPENDENT_VERIFICATION';", (router_span, BASELINE_TRACE_ID))

run_test("2. Wrong Causal Edge (VERIF points to ROUTER)", m_wrong_parent, expect_exit_code=1)

# 3. Duplicate Span ID
def m_dup_span(conn, shim):
    cur = conn.cursor()
    cur.execute("SELECT span_id FROM trace_events WHERE trace_id=? LIMIT 1;", (BASELINE_TRACE_ID,))
    span0 = cur.fetchone()[0]
    cur.execute("INSERT INTO trace_events (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json) VALUES (?, ?, 'fake_p', 'FAKE_STAGE', 'fake_prod', '2026-09-10T00:00:00Z', 'fake_sha', 'COMPLETED', '{}');", (BASELINE_TRACE_ID, span0))

run_test("3. Duplicate Span ID injected", m_dup_span, expect_exit_code=1)

# 4. Orphan Node
def m_orphan(conn, shim):
    cur = conn.cursor()
    cur.execute("INSERT INTO trace_events (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json) VALUES (?, 'span_orphan_123', 'span_orphan_parent_999', 'ORPHAN_STAGE', 'fake_prod', '2026-09-10T00:00:00Z', 'fake_sha', 'COMPLETED', '{}');", (BASELINE_TRACE_ID,))
    cur.execute("INSERT INTO trace_events (trace_id, span_id, parent_span_id, stage, producer, timestamp_iso, payload_sha256, status, details_json) VALUES (?, 'span_orphan_parent_999', 'ROOT_SPAN', 'ORPHAN_ROOT', 'fake_prod', '2026-09-10T00:00:00Z', 'fake_sha', 'COMPLETED', '{}');", (BASELINE_TRACE_ID,))

run_test("4. Orphan Node (Disconnected subtree)", m_orphan, expect_exit_code=1)

# 5. Cycle Detection
def m_cycle(conn, shim):
    cur = conn.cursor()
    cur.execute("SELECT span_id FROM trace_events WHERE trace_id=? AND stage='INTENT';", (BASELINE_TRACE_ID,))
    intent_span = cur.fetchone()[0]
    cur.execute("SELECT span_id FROM trace_events WHERE trace_id=? AND stage='INDEPENDENT_VERIFICATION';", (BASELINE_TRACE_ID,))
    verif_span = cur.fetchone()[0]
    cur.execute("UPDATE trace_events SET parent_span_id=? WHERE span_id=?", (verif_span, intent_span))

run_test("5. Cyclic Span Dependency (INTENT points to VERIF)", m_cycle, expect_exit_code=1)

# 6. Missing Tool Trace V2 Row
def m_missing_v2(conn, shim):
    cur = conn.cursor()
    cur.execute("DELETE FROM tool_traces_v2 WHERE trace_id=?;", (BASELINE_TRACE_ID,))

run_test("6. Missing tool_traces_v2 summary row", m_missing_v2, expect_exit_code=1)

# 7. Shim PID Tampered
def m_shim_pid(conn, shim):
    with open(shim, "r") as f:
        lines = f.readlines()
    with open(shim, "w") as f:
        for l in lines:
            if BASELINE_TRACE_ID in l:
                f.write(l.replace("PID:", "PID:999999"))
            else:
                f.write(l)

run_test("7. Shim log PID tampered", m_shim_pid, expect_exit_code=1)

# 8. Shim Binary Tampered
def m_shim_bin(conn, shim):
    with open(shim, "r") as f:
        lines = f.readlines()
    with open(shim, "w") as f:
        for l in lines:
            if BASELINE_TRACE_ID in l:
                f.write(l.replace("BIN:/", "BIN:/tampered/path/"))
            else:
                f.write(l)

run_test("8. Shim log target binary tampered", m_shim_bin, expect_exit_code=1)

# 9. Python -O Mode on bad trace (assertions disabled)
def m_py_opt(conn, shim):
    m_wrong_parent(conn, shim)

run_test("9. Python -O (Optimized Mode) on bad causal edge", m_py_opt, expect_exit_code=1, python_flags=["-O"])

# 10. Pristine Valid Trace
def m_pristine(conn, shim):
    pass

run_test("10. Pristine Valid Trace (Baseline Check)", m_pristine, expect_exit_code=0)

print("\n" + "=" * 95)
print("🏛️ AIR10 TOOL COURT ADVERSARIAL SELF-AUDIT RESULTS (10/10 GATES)")
print("=" * 95)
print(f"{'Test Name':<50} | {'Expected':<8} | {'Actual':<8} | {'Verdict':<8} | {'Failure Reason Captured'}")
print("-" * 95)
all_passed = True
for name, exp, act, verd, err in test_results:
    if verd != "PASS":
        all_passed = False
    print(f"{name:<50} | {exp:<8} | {act:<8} | {verd:<8} | {err}")
print("=" * 95)

if all_passed:
    print("🏆 VERDICT: TOOL COURT HAS OFFICIALLY PASSED ITS OWN COURT (10/10 GATES SECURED)")
    sys.exit(0)
else:
    print("❌ VERDICT: ONE OR MORE ADVERSARIAL GATES FAILED!", file=sys.stderr)
    sys.exit(1)