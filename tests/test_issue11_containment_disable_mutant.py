"""Mechanism-disable mutant for CIVEX Issue #11.

This court deliberately disables only the detached-descendant containment seam while
reusing the frozen real-path hostile fixture unchanged. The branch is expected to be
RED. A GREEN result would be a false-green in the containment court.
"""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from civex.trace_plumbing import air10_layer4_executor


def _load_frozen_issue11_court():
    path = Path(__file__).with_name("test_detached_descendant_timeout_realpath.py")
    spec = spec_from_file_location("issue11_frozen_realpath_court", path)
    module = module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module.test_issue11_detached_setsid_descendant_cannot_outlive_timeout


def test_issue11_group_only_cleanup_mutant_is_rejected(tmp_path, monkeypatch):
    # Target-specific ablation: restore group-only timeout cleanup without changing
    # the detached setsid() adversary or any of its marker/PID assertions.
    monkeypatch.setattr(
        air10_layer4_executor,
        "_signal_detached_descendants",
        lambda root_pid, root_pgid, sig: [],
    )
    frozen_court = _load_frozen_issue11_court()
    frozen_court(tmp_path, monkeypatch)
