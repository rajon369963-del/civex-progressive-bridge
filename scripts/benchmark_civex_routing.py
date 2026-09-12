#!/usr/bin/env python3
"""
CIVEX Progressive Bridge - Standalone Okapi BM25 Domain Benchmark Reproducer
Runs 2,000 queries against the 10-tool catalog and measures:
- Average Latency (µs)
- p95 Latency (µs)
- Throughput (Queries/sec)
"""

import math
import re
import time

TOOL_CATALOG = [
  {"id": "tool_git_commit_and_push", "name": "Git Auto Committer & Branch Push", "keywords": ["git", "commit", "push", "remote", "branch", "repository"], "summary": "Stage code, format conventional commit message and push to GitHub remote branch"},
  {"id": "tool_weather_telemetry", "name": "Weather Telemetry & Barometric Forecast", "keywords": ["weather", "temperature", "forecast", "rain", "precipitation", "barometer"], "summary": "Live meteorological sensor readings and localized precipitation forecasting"},
  {"id": "tool_secret_scanner", "name": "Vault Secret Scanner & Redactor", "keywords": ["secret", "token", "password", "credential", "leak", "scanner"], "summary": "Heuristic scan of files for exposed API keys and cryptographic secrets"},
  {"id": "tool_fsrs5_spaced_repetition", "name": "FSRS-5 Synaptic Retention Memory Engine", "keywords": ["fsrs", "spaced", "repetition", "memory", "retention", "flashcard", "forget"], "summary": "Calculate memory retrievability and optimal review intervals using continuous FSRS-5"},
  {"id": "tool_sql_duckdb_lake", "name": "DuckDB Columnar Analytical Engine", "keywords": ["duckdb", "sql", "parquet", "columnar", "analytics", "table"], "summary": "Zero-copy vectorized SQL queries across local Parquet files and data lakes"},
  {"id": "tool_simd_fast_json", "name": "Apple Silicon NEON SIMD Fast JSON Validator", "keywords": ["json", "simd", "neon", "parser", "validator", "schema"], "summary": "Gigabyte per second JSON structural validation using compiled ARM64 NEON intrinsics"},
  {"id": "tool_bloom_dedup", "name": "Counting Bloom Filter Deduplication Guard", "keywords": ["bloom", "filter", "dedup", "duplicate", "fingerprint", "membership"], "summary": "Sub-millisecond set membership test for suppressing duplicate transcript processing"},
  {"id": "tool_risk_gate_interceptor", "name": "Deterministic Pretrade Risk Gate Interceptor", "keywords": ["risk", "margin", "limit", "pretrade", "gate", "order", "interceptor"], "summary": "Microsecond pre-trade risk policy check ensuring margin and position band compliance prior to dispatch"},
  {"id": "tool_svg_badge_generator", "name": "Darkmode Glassmorphism SVG Badge Renderer", "keywords": ["svg", "badge", "render", "scorecard", "darkmode", "shield"], "summary": "Programmatic generation of high-contrast SVG status cards embedding cryptographic SHA digests"},
  {"id": "tool_gauss_law_derivation", "name": "Electromagnetic Gauss Divergence Solver", "keywords": ["gauss", "divergence", "flux", "derivation", "maxwell", "physics"], "summary": "Symbolic physics proof engine computing electrostatic field flux and boundary potentials"}
]

N = len(TOOL_CATALOG)
k1 = 1.2
b = 0.75

def tokenize(text):
    return [t.lower() for t in re.split(r"[\s_]+", text) if len(t) > 1]

doc_tokens = []
df = {}
for tool in TOOL_CATALOG:
    # 2x frequency for name and keywords
    corpus = f"{tool['id']} {tool['name']} {tool['name']} {' '.join(tool['keywords'])} {' '.join(tool['keywords'])} {tool['summary']}"
    tokens = tokenize(corpus)
    doc_tokens.append(tokens)
    unique_tokens = set(tokens)
    for t in unique_tokens:
        df[t] = df.get(t, 0) + 1

avgdl = sum(len(d) for d in doc_tokens) / N

def bm25_score(query_tokens, doc_idx):
    score = 0.0
    doc = doc_tokens[doc_idx]
    doc_len = len(doc)
    for qt in query_tokens:
        n_qi = df.get(qt, 0)
        if n_qi == 0:
            continue
        idf = math.log(1.0 + (N - n_qi + 0.5) / (n_qi + 0.5))
        tf = doc.count(qt)
        numerator = tf * (k1 + 1.0)
        denominator = tf + k1 * (1.0 - b + b * (doc_len / avgdl))
        score += idf * (numerator / denominator)
    return score

queries = [
    "publish my code changes to remote repository",
    "will it rain in my city weather forecast",
    "scan repository for passwords and credentials",
    "spaced repetition flashcard review for retention",
    "vectorized sql query on columnar parquet table",
    "simd parser for json using neon acceleration",
    "bloom filter duplicate suppression",
    "pretrade margin limit gate check",
    "render darkmode svg badge with sha digest",
    "calculate electric flux using gauss divergence law"
]

tokenized_queries = [tokenize(q) for q in queries]

print("======================================================================")
print("⚡ CIVEX OKAPI BM25 ROUTER BENCHMARK REPRODUCER (Apple Silicon M1)")
print("======================================================================")
rounds = 2000
latencies = []

for r in range(rounds):
    q_tokens = tokenized_queries[r % len(tokenized_queries)]
    t0 = time.perf_counter_ns()
    best_tool = None
    best_score = -1.0
    for idx in range(N):
        s = bm25_score(q_tokens, idx)
        if s > best_score:
            best_score = s
            best_tool = TOOL_CATALOG[idx]["id"]
    t1 = time.perf_counter_ns()
    latencies.append((t1 - t0) / 1000.0)

avg_lat = sum(latencies) / len(latencies)
latencies.sort()
p95_lat = latencies[int(len(latencies) * 0.95)]
qps = 1000000.0 / avg_lat

print(f"• Total Queries Routed : {rounds}")
print(f"• Average Latency      : {avg_lat:.2f} µs")
print(f"• p95 Latency          : {p95_lat:.2f} µs")
print(f"• Throughput           : {qps:,.1f} queries/sec")
print(f"• Baseline Target      : ~26,904 queries/sec (avg ~37.17 µs)")
print("======================================================================")
