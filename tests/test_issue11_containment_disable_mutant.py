"""V2.2 mutation court: disabling detached-descendant containment must turn Issue11 RED.

This file is intentionally hosted only on a disposable mutant branch/PR. It monkeypatches
the production containment primitive to a no-op and reuses the exact frozen real-path
Issue11 oracle. A green result would be a FALSE_GREEN in the repair's mutation sensitivity.
The mutant is expected to fail on the hosted production-shaped path; never merge it.
"""

from civex.trace_plumbing import air10_layer4_executor
from tests.test_detached_descendant_timeout_realpath import (
    test_issue11_detached_setsid_descendant_cannot_outlive_timeout,
)


def test_issue11_containment_disable_mutant_must_be_caught(tmp_path, monkeypatch):
    monkeypatch.setattr(
        air10_layer4_executor,
        "_signal_detached_descendants",
        lambda root_pid, root_pgid, sig: [],
    )
    test_issue11_detached_setsid_descendant_cannot_outlive_timeout(tmp_path, monkeypatch)
