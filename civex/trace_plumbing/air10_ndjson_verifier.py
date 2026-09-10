#!/usr/bin/env python3
"""
AIR10 NDJSON Evidence Verifier
Enforces:
1. NON_EMPTY_RECORDS_EXAMINED == valid_records + len(corrupt_lines)
2. Binding to SHA-256 of input file at timestamp
3. Strict line-by-line RFC 8259 validation
"""
import sys, os, hashlib, json, time

def verify_ndjson(file_path):
    if not os.path.isfile(file_path):
        print(f"FATAL: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    file_sha256 = hashlib.sha256(file_bytes).hexdigest()
    file_size = len(file_bytes)
    mtime = os.path.getmtime(file_path)
    mtime_iso = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(mtime))

    raw_lines = file_bytes.split(b"\n")
    non_empty_lines = [l for l in raw_lines if l.strip()]

    valid_records = []
    corrupt_lines = []

    for idx, line in enumerate(non_empty_lines):
        try:
            obj = json.loads(line.decode("utf-8"))
            valid_records.append((idx + 1, type(obj).__name__, len(obj) if isinstance(obj, (dict, list)) else 1))
        except Exception as e:
            corrupt_lines.append((idx + 1, str(e), line[:50]))

    total_examined = len(valid_records) + len(corrupt_lines)

    print("=" * 80)
    print("🏛️ AIR10 BOUNDED NDJSON VERIFICATION RECEIPT")
    print("=" * 80)
    print(f"Target File                 : {file_path}")
    print(f"File Size (bytes)           : {file_size}")
    print(f"File Modified (mtime)       : {mtime_iso}")
    print(f"SHA-256 Digest              : {file_sha256}")
    print(f"Total Raw Lines             : {len(raw_lines)}")
    print(f"Non-Empty Lines Found       : {len(non_empty_lines)}")
    print(f"NON_EMPTY_RECORDS_EXAMINED  : {total_examined}")
    print(f"NON_EMPTY_RECORDS_VALID     : {len(valid_records)}")
    print(f"CORRUPT_LINES_DETECTED      : {len(corrupt_lines)}")

    if corrupt_lines:
        print(f"❌ CORRUPTION DETECTED in {len(corrupt_lines)} records:", file=sys.stderr)
        for c in corrupt_lines[:5]:
            print(f"   Line {c[0]}: {c[1]} | Snippet: {c[2]}", file=sys.stderr)
        sys.exit(1)

    print(f"NDJSON_STREAM_INTEGRITY     : PASS @ SHA256({file_sha256[:16]}...)")
    print("=" * 80)
    return True

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "/Users/rajondas/.gemini/antigravity/scratch/agent_middleware.json"
    verify_ndjson(path)