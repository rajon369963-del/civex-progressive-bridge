from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from civex import orchestrator
from civex.trace_plumbing import air10_layer4_executor


class RouterResult(tuple):
    permit = None

    def __new__(cls, tool, binary, span):
        return super().__new__(cls, (tool, binary, span))


class AmbiguousPostExecutionFenceTests(unittest.TestCase):
    def _common_patches(self):
        return (
            patch.object(orchestrator.air10_layer1_intent, "emit_intent", return_value=("trace-1", "intent-1")),
            patch.object(orchestrator.air10_layer3_shim, "shim_intercept", return_value="shim-1"),
        )

    def test_write_bearing_ambiguous_outcome_holds_without_alternate(self):
        router = patch.object(
            orchestrator.air10_layer2_router,
            "route_intent",
            side_effect=[RouterResult("writer-a", "/bin/a", "router-a"), RouterResult("writer-b", "/bin/b", "router-b")],
        )
        execute = patch.object(
            orchestrator.air10_layer4_executor,
            "execute_process",
            side_effect=air10_layer4_executor.PostExecutionOutcomeUnknown("capture mismatch", child_exit_observed=True),
        )
        p1, p2 = self._common_patches()
        with p1, p2, router as route_mock, execute as exec_mock:
            result = orchestrator.orchestrate_request(
                "mutate state", "write", "/tmp/in",
                candidate_pool=[{"name": "writer-a"}, {"name": "writer-b"}],
                max_attempts=2, effect_class="write_bearing",
            )
        self.assertEqual(result["status"], "HOLD_RECONCILE_AMBIGUOUS_EXECUTION")
        self.assertFalse(result["retry_allowed"])
        self.assertEqual(route_mock.call_count, 1)
        self.assertEqual(exec_mock.call_count, 1)

    def test_durable_counter_stays_one_and_alternate_is_never_invoked(self):
        with tempfile.TemporaryDirectory() as td:
            counter = Path(td) / "counter.txt"
            counter.write_text("0", encoding="utf-8")
            calls = []

            def first_execution(**kwargs):
                value = int(counter.read_text(encoding="utf-8")) + 1
                counter.write_text(str(value), encoding="utf-8")
                calls.append("writer-a")
                raise air10_layer4_executor.PostExecutionOutcomeUnknown(
                    "evidence failed after durable mutation", child_exit_observed=True
                )

            p1, p2 = self._common_patches()
            with p1, p2, patch.object(
                orchestrator.air10_layer2_router,
                "route_intent",
                side_effect=[RouterResult("writer-a", "/bin/a", "router-a"), RouterResult("writer-b", "/bin/b", "router-b")],
            ) as route_mock, patch.object(
                orchestrator.air10_layer4_executor, "execute_process", side_effect=first_execution
            ):
                result = orchestrator.orchestrate_request(
                    "durable mutation", "write", "/tmp/in",
                    candidate_pool=[{"name": "writer-a"}, {"name": "writer-b"}],
                    max_attempts=2, effect_class="write_bearing",
                )

            self.assertEqual(result["status"], "HOLD_RECONCILE_AMBIGUOUS_EXECUTION")
            self.assertEqual(counter.read_text(encoding="utf-8"), "1")
            self.assertEqual(calls, ["writer-a"])
            self.assertEqual(route_mock.call_count, 1)

    def test_unknown_effect_class_fails_closed_after_ambiguous_outcome(self):
        p1, p2 = self._common_patches()
        with p1, p2, patch.object(
            orchestrator.air10_layer2_router, "route_intent",
            return_value=RouterResult("tool-a", "/bin/a", "router-a"),
        ) as route_mock, patch.object(
            orchestrator.air10_layer4_executor, "execute_process",
            side_effect=air10_layer4_executor.PostExecutionOutcomeUnknown("timeout"),
        ):
            result = orchestrator.orchestrate_request("unknown", "cap", "/tmp/in", max_attempts=2)
        self.assertEqual(result["status"], "HOLD_RECONCILE_AMBIGUOUS_EXECUTION")
        self.assertEqual(result["effect_class"], "unknown")
        self.assertEqual(route_mock.call_count, 1)

    def test_read_only_ambiguous_outcome_keeps_bounded_failover(self):
        p1, p2 = self._common_patches()
        with p1, p2, patch.object(
            orchestrator.air10_layer2_router, "route_intent",
            side_effect=[RouterResult("reader-a", "/bin/a", "router-a"), RouterResult("reader-b", "/bin/b", "router-b")],
        ) as route_mock, patch.object(
            orchestrator.air10_layer4_executor, "execute_process",
            side_effect=[air10_layer4_executor.PostExecutionOutcomeUnknown("bad evidence", child_exit_observed=True), (0, 1.0, "a" * 64)],
        ), patch.object(orchestrator.air10_layer5_verifier, "verify_trace", return_value="VERIFIED_PASS"):
            result = orchestrator.orchestrate_request(
                "read state", "read", "/tmp/in",
                candidate_pool=[{"name": "reader-a"}, {"name": "reader-b"}],
                max_attempts=2, effect_class="read_only",
            )
        self.assertEqual(result["status"], "SUCCESS")
        self.assertEqual(result["attempts_needed"], 2)
        self.assertEqual(route_mock.call_count, 2)

    def test_pre_execution_failure_still_retries(self):
        p1, p2 = self._common_patches()
        with p1, p2, patch.object(
            orchestrator.air10_layer2_router, "route_intent",
            side_effect=[RouterResult("tool-a", "/bin/a", "router-a"), RouterResult("tool-b", "/bin/b", "router-b")],
        ) as route_mock, patch.object(
            orchestrator.air10_layer4_executor, "execute_process",
            side_effect=[RuntimeError("court permit missing before start"), (0, 1.0, "b" * 64)],
        ), patch.object(orchestrator.air10_layer5_verifier, "record_pre_execution_failure") as record_pre, patch.object(
            orchestrator.air10_layer5_verifier, "verify_trace", return_value="VERIFIED_PASS",
        ):
            result = orchestrator.orchestrate_request(
                "safe retry", "cap", "/tmp/in",
                candidate_pool=[{"name": "tool-a"}, {"name": "tool-b"}],
                max_attempts=2, effect_class="write_bearing",
            )
        self.assertEqual(result["status"], "SUCCESS")
        self.assertEqual(result["attempts_needed"], 2)
        self.assertEqual(route_mock.call_count, 2)
        record_pre.assert_called_once()

    def test_nonpass_verdict_after_execution_holds_write_bearing(self):
        p1, p2 = self._common_patches()
        with p1, p2, patch.object(
            orchestrator.air10_layer2_router, "route_intent",
            return_value=RouterResult("writer-a", "/bin/a", "router-a"),
        ) as route_mock, patch.object(
            orchestrator.air10_layer4_executor, "execute_process", return_value=(0, 1.0, "a" * 64),
        ), patch.object(orchestrator.air10_layer5_verifier, "verify_trace", return_value="FAILED_EVIDENCE"):
            result = orchestrator.orchestrate_request(
                "mutate", "write", "/tmp/in", max_attempts=2, effect_class="write_bearing"
            )
        self.assertEqual(result["status"], "HOLD_RECONCILE_AMBIGUOUS_VERDICT")
        self.assertFalse(result["retry_allowed"])
        self.assertEqual(route_mock.call_count, 1)


if __name__ == "__main__":
    unittest.main()
