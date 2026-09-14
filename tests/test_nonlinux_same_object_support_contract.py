import hashlib
import os
import subprocess
import sys

import pytest


@pytest.mark.skipif(
    sys.platform.startswith("linux"),
    reason="Linux exercises descriptor-bound fexecve positive execution in the full Court suite.",
)
def test_nonlinux_attested_same_object_fails_closed_before_child_execution(tmp_path):
    """V2.2 real-path negative fixture for the non-Linux SAME_OBJECT contract.

    This compiles the production C11 boundary, requests an attested execution, and
    proves that unsupported non-Linux platforms return the typed exit-78 HOLD before
    the verified child can create any side effect.  Restoring pathname re-lookup
    would make this test fail because the child marker would be created.
    """
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    c_source = os.path.join(repo_root, "civex", "trace_plumbing", "air10_exec_boundary.c")
    boundary_bin = str(tmp_path / "air10_exec_boundary_nonlinux_contract")

    comp = subprocess.run(
        ["cc", "-O3", "-std=c11", c_source, "-o", boundary_bin],
        capture_output=True,
        text=True,
    )
    assert comp.returncode == 0, comp.stderr

    marker = tmp_path / "child_executed.marker"
    worker = tmp_path / "worker.sh"
    worker.write_text(
        "#!/bin/sh\n"
        f"printf 'EXECUTED' > '{marker}'\n"
        "exit 0\n",
        encoding="utf-8",
    )
    worker.chmod(0o755)
    worker_sha = hashlib.sha256(worker.read_bytes()).hexdigest()

    input_file = tmp_path / "input.json"
    input_file.write_text('{"same_object": "nonlinux_fail_closed"}', encoding="utf-8")

    snapshot_dir = tmp_path / "snapshots"
    snapshot_dir.mkdir(mode=0o700)

    env = os.environ.copy()
    env.update(
        {
            "AIR10_EXPECTED_BINARY_SHA": worker_sha,
            "AIR10_REQUIRE_EXPECTED_SHA": "1",
            "AIR10_INPUT_FILE": str(input_file),
            "AIR10_EXEC_SNAPSHOT_DIR": str(snapshot_dir),
            "AIR10_SNAPSHOT_DIR": str(snapshot_dir),
        }
    )

    proc = subprocess.run(
        [
            boundary_bin,
            "tr_nonlinux_same_object_contract",
            "span_root",
            str(worker),
            str(input_file),
        ],
        capture_output=True,
        text=True,
        env=env,
    )

    assert proc.returncode == 78, (
        f"expected typed SAME_OBJECT unsupported HOLD (78), got {proc.returncode}; "
        f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
    assert "SAME_OBJECT_EXEC_UNAVAILABLE" in proc.stderr
    assert not marker.exists(), "unsupported-platform boundary executed the child after verification"
