#!/usr/bin/env python3
"""Fail closed unless the hosted CIVEX demo is the same bytes as canonical source."""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Iterable


class DemoIdentityError(RuntimeError):
    pass


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def verify_response(
    status: int,
    body: bytes,
    expected_body: bytes,
    markers: Iterable[str],
) -> dict[str, object]:
    if status != 200:
        raise DemoIdentityError(f"HTTP_STATUS_MISMATCH:{status}")

    body_sha = sha256_hex(body)
    expected_sha = sha256_hex(expected_body)
    if body_sha != expected_sha:
        raise DemoIdentityError(
            f"CONTENT_DIGEST_MISMATCH:hosted={body_sha}:source={expected_sha}"
        )

    text = body.decode("utf-8", errors="strict")
    expected_text = expected_body.decode("utf-8", errors="strict")
    missing = [m for m in markers if m not in text or m not in expected_text]
    if missing:
        raise DemoIdentityError(f"SEMANTIC_MARKER_MISSING:{missing!r}")

    return {
        "decision": "PASS_PUBLIC_DEMO_IDENTITY",
        "status": status,
        "sha256": body_sha,
        "bytes": len(body),
        "markers": list(markers),
    }


def fetch_public_bytes(url: str, timeout: float) -> tuple[int, bytes]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "AIR10-04-public-demo-identity-court/2.2"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        status = int(getattr(response, "status", response.getcode()))
        return status, response.read()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--marker", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    expected_body = Path(args.source).read_bytes()
    status, body = fetch_public_bytes(args.url, args.timeout)
    result = verify_response(status, body, expected_body, args.marker)
    result.update({"url": args.url, "source": args.source})
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
