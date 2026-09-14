from __future__ import annotations

import pytest

from civex import orchestrator


class _RouteResult:
    permit = object()

    def __iter__(self):
        return iter(("tool-a", "/bin/echo", "span-router"))


@pytest.mark.parametrize(
    ("requested_argv", "expected_argv"),
    [
        ([], []),
        (None, ["/tmp/input.txt"]),
        (["--flag"], ["--flag"]),
    ],
)
def test_orchestrator_preserves_argv_boundary(monkeypatch, tmp_path, requested_argv, expected_argv):
    """Exercise the real orchestrator -> shim -> executor argv boundary.

    Invariant: explicit empty argv is distinct from an unset argv.  The spy captures
    the exact production argument passed into both downstream layers so an unrelated
    failure cannot make this court falsely green.
    """
    observed: dict[str, list[str]] = {}

    monkeypatch.setattr(
        orchestrator.air10_layer1_intent,
        "emit_intent",
        lambda **kwargs: ("trace-argv-boundary", "span-intent"),
    )
    monkeypatch.setattr(
        orchestrator.air10_layer2_router,
        "route_intent",
        lambda **kwargs: _RouteResult(),
    )

    def capture_shim(**kwargs):
        observed["shim"] = list(kwargs["command_args"])
        return "span-shim"

    monkeypatch.setattr(orchestrator.air10_layer3_shim, "shim_intercept", capture_shim)

    def capture_execute(**kwargs):
        observed["executor"] = list(kwargs["argv"])
        return 0, 1.0, "stdout-sha"

    monkeypatch.setattr(orchestrator.air10_layer4_executor, "execute_process", capture_execute)
    monkeypatch.setattr(
        orchestrator.air10_layer5_verifier,
        "verify_trace",
        lambda **kwargs: "VERIFIED_PASS",
    )

    result = orchestrator.orchestrate_request(
        intent_query="argv boundary court",
        required_capability="echo",
        input_file="/tmp/input.txt",
        candidate_pool=[{"name": "tool-a"}],
        db_path=str(tmp_path / "audit.db"),
        max_attempts=1,
        argv=requested_argv,
        output_dir=str(tmp_path),
        effect_class="read_only",
    )

    assert result["status"] == "SUCCESS"
    assert observed["shim"] == expected_argv
    assert observed["executor"] == expected_argv
