from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "civex" / "trace_plumbing" / "air10_exec_boundary.c"


def test_non_system_fallback_executes_the_verified_object_not_snapshot_path():
    """V2.2 RED court: final verified descriptor must be the execution authority.

    A re-hash followed by close(fd) + execv(snapshot_path, ...) still leaves a
    pathname re-lookup window. This source-level court intentionally fails the
    inherited implementation until the fallback executes the verified object
    (or fails closed on platforms without a same-object primitive).
    """
    text = SOURCE.read_text(encoding="utf-8")
    marker = "/* On Darwin / BSD / Fallback: verify child opened descriptor against supervisor verified inode */"
    assert marker in text
    fallback = text.split(marker, 1)[1].split("/* FAIL CLOSED: Zero fallback to mutable binary_path */", 1)[0]

    assert "child_snap_fd = open(snapshot_path, O_RDONLY | O_NOFOLLOW)" in fallback
    assert "fstat(child_snap_fd" in fallback
    assert "strcasecmp(child_sha, executed_binary_sha256)" in fallback

    # Exact false-green discriminator: verifying the descriptor and then closing
    # it before a fresh pathname exec does not prove hash(object A)->execute(A).
    assert "execv(snapshot_path, child_args)" not in fallback, (
        "SAME_OBJECT_FALSE_GREEN: verified snapshot descriptor is discarded and "
        "execution re-enters snapshot_path via a fresh pathname lookup"
    )
