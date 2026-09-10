import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

from civex.trace_plumbing import air10_cross_trace_readback as trace_readback


class TracePlumbingPortabilityTest(unittest.TestCase):
    TRACE_ID = "trace-portability-fixture"

    def _seed_valid_fixture(self, home: Path):
        runtime_dir = home / ".antigravity"
        runtime_dir.mkdir(parents=True, exist_ok=True)
        db_path = runtime_dir / "air10_audit.db"
        shim_log = runtime_dir / "shim_intercept.log"

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE trace_events (
                event_id INTEGER,
                trace_id TEXT,
                span_id TEXT,
                parent_span_id TEXT,
                stage TEXT,
                producer TEXT,
                timestamp_iso TEXT,
                payload_sha256 TEXT,
                status TEXT,
                details_json TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE tool_traces_v2 (
                trace_id TEXT,
                task_intent TEXT,
                chosen_tool TEXT,
                binary_path TEXT,
                actual_exit_code INTEGER,
                duration_ms REAL,
                semantic_equivalence TEXT,
                verification_status TEXT,
                failure_reason TEXT,
                created_at TEXT
            )
            """
        )

        events = [
            (1, "intent", "ROOT_SPAN", "INTENT", {}),
            (2, "router", "intent", "ROUTER_EVALUATION", {}),
            (
                3,
                "shim",
                "router",
                "SHIM_INTERCEPT",
                {"parent_pid": 123, "target_bin": "/bin/echo"},
            ),
            (
                4,
                "exec",
                "shim",
                "PROCESS_EXECUTION",
                {"actual_child_pid": 124, "actual_returncode": 0},
            ),
            (
                5,
                "verify",
                "exec",
                "INDEPENDENT_VERIFICATION",
                {"semantic_result": "PASS"},
            ),
        ]
        for event_id, span_id, parent_span_id, stage, details in events:
            cur.execute(
                """
                INSERT INTO trace_events
                (event_id, trace_id, span_id, parent_span_id, stage, producer,
                 timestamp_iso, payload_sha256, status, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    self.TRACE_ID,
                    span_id,
                    parent_span_id,
                    stage,
                    "fixture",
                    "2026-09-11T00:00:00Z",
                    "0" * 64,
                    "PASS",
                    json.dumps(details),
                ),
            )

        cur.execute(
            """
            INSERT INTO tool_traces_v2
            (trace_id, task_intent, chosen_tool, binary_path, actual_exit_code,
             duration_ms, semantic_equivalence, verification_status,
             failure_reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                self.TRACE_ID,
                "fixture",
                "echo",
                "/bin/echo",
                0,
                1.0,
                "PASS",
                "PASS",
                None,
                "2026-09-11T00:00:00Z",
            ),
        )
        conn.commit()
        conn.close()

        shim_log.write_text(
            "PID:123 TRACE:trace-portability-fixture SPAN:shim PARENT:router "
            "SHIM:air10-exec-boundary BIN:/bin/echo\n",
            encoding="utf-8",
        )
        return db_path, shim_log

    def test_default_paths_follow_runtime_home_and_validate_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            self._seed_valid_fixture(home)
            with patch.object(trace_readback.Path, "home", return_value=home):
                self.assertEqual(
                    trace_readback._default_db_path(),
                    str(home / ".antigravity" / "air10_audit.db"),
                )
                self.assertEqual(
                    trace_readback._default_shim_log_path(),
                    str(home / ".antigravity" / "shim_intercept.log"),
                )
                self.assertTrue(trace_readback.validate_and_readback(self.TRACE_ID))

    def test_explicit_overrides_ignore_home_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture_home = Path(tmp) / "fixture-home"
            db_path, shim_log = self._seed_valid_fixture(fixture_home)
            with patch.object(
                trace_readback.Path,
                "home",
                return_value=Path(tmp) / "wrong-home",
            ):
                self.assertTrue(
                    trace_readback.validate_and_readback(
                        self.TRACE_ID,
                        str(db_path),
                        str(shim_log),
                    )
                )

    def test_missing_default_database_fails_closed_with_resolved_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            stderr = io.StringIO()
            with patch.object(trace_readback.Path, "home", return_value=home):
                with redirect_stderr(stderr), self.assertRaises(SystemExit) as exc:
                    trace_readback.validate_and_readback("missing-trace")
            self.assertEqual(exc.exception.code, 1)
            self.assertIn(
                str(home / ".antigravity" / "air10_audit.db"),
                stderr.getvalue(),
            )


if __name__ == "__main__":
    unittest.main()
