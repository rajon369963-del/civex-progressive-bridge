import sys

import pytest


# V2.2 support contract: attested SAME_OBJECT execution currently has a proven
# descriptor-bound implementation only on Linux (fexecve).  On non-Linux the C11
# boundary intentionally fails closed with exit 78 rather than re-resolving a path.
# Keep this allowlist exact: these legacy positive-path tests require the child to
# execute, so running them on an unsupported platform would assert the opposite of
# the production security contract.  A separate real-path negative test proves the
# non-Linux exit-78 path and proves the child never executes.
_NONLINUX_SAME_OBJECT_POSITIVE_TESTS = frozenset(
    {
        "test_gate13_c11_execution_boundary_integration",
        "test_gate17_c11_stdout_preservation_and_arbitrary_argv",
        "test_gate19_full_closed_loop_reality_test",
        "test_gate20_autonomous_self_healing_closed_loop",
        "test_gate21_full_5_layer_dag_reality_test",
        "test_gate23_master_closed_loop_and_true_aba",
        "test_gate24_true_aba_cache_poisoning_and_immutable_input_binding",
        "test_gate25_autonomous_one_call_orchestration_self_healing",
        "test_gate26_exact_court_permit_and_retry_aware_dag_reconstruction",
        "test_gate27_randomized_concurrent_stress_loop",
        "test_gate28_permit_authenticity_and_sha_bypass_rejection",
        "test_gate29_snapshot_aba_and_inode_binding",
    }
)


def pytest_collection_modifyitems(config, items):
    """Apply the explicit platform support contract without weakening Linux court coverage."""
    if sys.platform.startswith("linux"):
        return

    unsupported = pytest.mark.skip(
        reason=(
            "Attested SAME_OBJECT child execution is not supported on this platform: "
            "the C11 boundary must fail closed with exit 78 instead of pathname re-lookup."
        )
    )
    for item in items:
        if item.name in _NONLINUX_SAME_OBJECT_POSITIVE_TESTS:
            item.add_marker(unsupported)


@pytest.fixture(autouse=True)
def explicit_test_court_authority(monkeypatch):
    """Tests opt in to explicit authority; production has no repository fallback here.

    Individual negative tests may delete this variable to prove fail-closed behavior.
    This value is intentionally test-only and confers no production authority.
    """
    monkeypatch.setenv(
        "AIR10_COURT_SECRET_KEY",
        "civex-test-suite-only-nonproduction-authority-material",
    )
