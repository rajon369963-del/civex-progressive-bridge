from pathlib import Path
import hashlib
import importlib.util


ROOT = Path(__file__).resolve().parents[1]
CONFTEST = ROOT / "tests" / "conftest.py"

# Diagnostic coordinated co-edit mutant for Issue #53.  This deliberately changes
# the candidate-controlled expected inventory and its local digest together with
# the runtime skip inventory.  If the current v1 court still passes, the supposed
# frozen authority is self-authorizable by the candidate revision.
SUPPORT_CONTRACT_VERSION = "nonlinux-same-object-positive-courts-v2-mutant"
FROZEN_COURT_SET_SHA256 = "b46933ffbe13736aa25796a7138af7bc0860ea4354077f36c64cabde6aa59f5b"

EXPECTED_NONLINUX_POSITIVE_COURTS = frozenset(
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


def _load_conftest_module():
    spec = importlib.util.spec_from_file_location("civex_test_conftest_contract", CONFTEST)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _court_set_digest(names):
    payload = "\n".join(sorted(names)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def test_nonlinux_positive_court_inventory_is_frozen_and_real():
    """Explicit acceptance gate for the narrowed non-Linux SAME_OBJECT contract."""
    conftest = _load_conftest_module()
    actual = conftest._NONLINUX_SAME_OBJECT_POSITIVE_TESTS
    assert actual == EXPECTED_NONLINUX_POSITIVE_COURTS, (
        "NONLINUX_SUPPORT_CONTRACT_DRIFT: skipped positive-court inventory changed "
        "without updating the explicit acceptance contract"
    )
    assert _court_set_digest(actual) == FROZEN_COURT_SET_SHA256, (
        f"NONLINUX_SUPPORT_CONTRACT_AUTHORITY_DRIFT[{SUPPORT_CONTRACT_VERSION}]: "
        "runtime and local inventories may not be co-edited around the frozen authority"
    )

    corpus = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "tests").glob("test_*.py"))
    )
    missing = sorted(
        name for name in EXPECTED_NONLINUX_POSITIVE_COURTS if f"def {name}(" not in corpus
    )
    assert not missing, f"NONLINUX_SUPPORT_CONTRACT_STALE_TEST_IDS: {missing}"


def test_nonlinux_failclosed_realpath_court_is_never_in_positive_skip_inventory():
    """The production-path exit-78/child-nonexecution court must execute on non-Linux."""
    conftest = _load_conftest_module()
    assert (
        "test_nonlinux_attested_same_object_fails_closed_before_child_execution"
        not in conftest._NONLINUX_SAME_OBJECT_POSITIVE_TESTS
    )
