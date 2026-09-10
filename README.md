# ⚡ CIVEX Progressive Tool Disclosure Engine
### Sub-Millisecond Adaptive Tool Retrieval & Schema Hydration for Large-Scale Agentic LLM Catalogs (5,000+ Tools)

[![CIVEX Test Suite](https://github.com/rajon369963-del/civex-progressive-bridge/actions/workflows/python-tests.yml/badge.svg)](https://github.com/rajon369963-del/civex-progressive-bridge/actions/workflows/python-tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Platform: POSIX / macOS / Linux](https://img.shields.io/badge/Platform-POSIX-informational.svg)](https://github.com/rajon369963-del/civex-progressive-bridge)
[![Catalog Scale: 5,283 Tools](https://img.shields.io/badge/Catalog-5%2C283%20Tools-success.svg)](https://github.com/rajon369963-del/civex-progressive-bridge)

Modern agentic LLMs face severe context bloat and reasoning degradation when connected to comprehensive real-world tool registries. Injecting full schema definitions for thousands of tools into prompt context consumes over 400,000 tokens per invocation, exhausting context windows, inflating inference costs, and diluting model attention.

**CIVEX Progressive Bridge** provides a progressive tool disclosure architecture for large-scale agent systems:
1. **Sub-Millisecond Disjunctive FTS5 BM25 Routing**: Selects top-$k$ candidate tools in **< 1ms** via SQLite FTS5 `ORDER BY fts.rank ASC` (native BM25 score).
2. **Shadow Schema Shrinking**: Compresses tool representations into concise shadow schemas strictly capped at **≤ 250 bytes**, preserving routing and execution signatures (`id`, `name`, `cat`, `summary`, `cmd`).
3. **On-Demand JIT Schema Hydration**: Reconstructs complete execution parameters, descriptions, and environment flags only for the tools selected by the model.
4. **Headroom Signal-Aware Log Compressor**: Prunes verbose logs/traces by 60–95% while deterministically retaining error markers, stack traces, and exception cues.
5. **CIVeX Causal Verification & Circuit Breaker**: Decouples exit code 0 from physical reality via SHA-256 pre/post state hashing, and isolates flapping tools via a thread-safe/process-safe POSIX `flock` circuit breaker.

---

## 📊 Architecture & Internal Benchmark Overview (5,283-Tool Catalog)

> **Note & Disclaimer**: Illustrative and architectural comparison. Measurements reflect internal test runs on local production catalog (macOS Darwin ARM64, Python 3.11, SQLite 3.43 with FTS5). External baseline numbers are architectural reference estimates and are not claimed as independent head-to-head empirical results. A formal, fully reproducible comparative benchmark suite is scheduled for `v0.2.0`.

| Benchmark Dimension | Full Context Injection | Embedding Vector RAG | **CIVEX Progressive Bridge** |
| :--- | :--- | :--- | :--- |
| **Catalog Scalability** | Fails at > 100 tools | Scales to 10k+ tools | **5,283+ Tools Indexed** |
| **Context Overhead per Turn** | ~450,000 tokens (~1.8 MB) | ~3,500 tokens | **~1,200 tokens (~375x reduction)** |
| **Routing Retrieval Latency** | N/A (Linear Scan) | 25 - 120 ms (Vector DB) | **0.20 - 0.36 ms (FTS5 BM25)** |
| **Max Shadow Schema Size** | Up to 8,400 bytes | ~1,200 bytes | **≤ 249 Bytes (Strict Cap)** |
| **Concurrency & Lock Safety** | Race condition prone | Database-dependent | **POSIX `flock` + Atomic File Replacement** |

---

## 🚀 Quick Start

### Installation

Install in development mode from source:

```bash
git clone https://github.com/rajon369963-del/civex-progressive-bridge.git
cd civex-progressive-bridge
pip install -e .
```

*Requirements: Python ≥ 3.10 on POSIX-compliant platforms (macOS / Linux).*

---

### Python API Usage

```python
from civex import ProgressiveToolBridge

# Initialize bridge (automatically discovers local or fixture catalog)
bridge = ProgressiveToolBridge()

# 1. Resolve intent dynamically (returns top-k shadow schemas)
tools = bridge.resolve_intent("git commit", top_k=2)

for tool in tools:
    print(f"Tool: {tool['name']} [{tool['cat']}] | ID: {tool['id']}")
    print(f"Compact Command: {tool['cmd']}")
    print(f"Summary: {tool['summary']}\n")

# 2. Hydrate full parameters on-demand only when chosen
if tools:
    full_spec = bridge.hydrate_tool(tools[0]["id"])
    print(f"Full Exec Template: {full_spec['exec_template']}")
    print(f"Binary Path: {full_spec['binary_path']}")
```

---

### CLI Usage

The package installs the `civex-bridge` executable console script:

```bash
# Search shadow schemas via FTS5 BM25
civex-bridge search "git" --limit 3

# Hydrate full schema by tool ID
civex-bridge hydrate "tool_git_commit"

# Compress verbose diagnostic payload via Headroom
civex-bridge compress '{"status": "error", "trace": "Traceback ...", "data": [1,2,3]}'

# Causal state verification of target file
civex-bridge verify /path/to/target.txt <pre_execution_sha256> --code 0
```

---

## 🧪 Testing & CI/CD

The test suite runs seamlessly in both local environments (verifying all 5,283 production tools) and clean CI environments (using the bundled deterministic 50-tool SQLite fixture):

```bash
# Run the complete regression test suite
python tests/test_bridge.py
```

GitHub Actions executes the full matrix across Ubuntu and macOS on Python 3.10, 3.11, and 3.12 on every push.

---

## 📄 License
MIT License. Authored by Rajon Das and the AIR10 / MIGL Autonomous Systems Team.
