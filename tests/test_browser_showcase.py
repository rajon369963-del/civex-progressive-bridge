import pytest
import math
import re
from pathlib import Path

def test_civex_html_contains_canonical_bm25():
    html_path = Path(__file__).parent.parent / "index.html"
    assert html_path.exists(), "index.html must exist in repo root"
    content = html_path.read_text(encoding="utf-8")
    
    assert "k1 = 1.2" in content
    assert "b = 0.75" in content
    assert "Math.log((N - df[t] + 0.5) / (df[t] + 0.5) + 1.0)" in content
    assert "avgdl" in content
    assert "termTf * (k1 + 1)" in content
    assert "termTf + k1 * (1 - b + b * (dLen / avgdl))" in content

def test_okapi_bm25_routing_semantics():
    tools = [
      {"id": "tool_git_commit_and_push", "keywords": ["git", "commit", "push", "vcs", "repo", "branch", "permit", "repository", "remote", "code", "publish"], "summary": "Commits working tree changes and pushes to remote GitHub repository with atomic verification."},
      {"id": "tool_sql_duckdb_lake", "keywords": ["sql", "query", "database", "duckdb", "parquet", "lake", "table", "data", "columnar", "vectorized", "olap"], "summary": "Zero-copy columnar vectorized SQL queries over local Parquet and DuckDB lakehouse tables."},
      {"id": "tool_simd_fast_json", "keywords": ["json", "simd", "parse", "neon", "speed", "serialize", "fast", "parser", "submillisecond", "validation"], "summary": "SIMD C++17 sub-millisecond JSON parsing and validation engine exploiting Apple Silicon M1 NEON lanes."},
      {"id": "tool_bloom_dedup", "keywords": ["bloom", "filter", "dedup", "duplicate", "memory", "hash", "suppression", "counting", "membership"], "summary": "In-memory libbloom counting filter for O(1) duplicate suppression across event streams."},
      {"id": "tool_risk_gate_interceptor", "keywords": ["risk", "trade", "order", "hedge", "market", "pnl", "exchange", "trading", "pretrade", "margin", "limits", "gate"], "summary": "Pre-trade risk enforcement checking margin bounds, price bands, and daily loss thresholds before dispatch."},
      {"id": "tool_fsrs5_spaced_repetition", "keywords": ["fsrs", "memory", "review", "study", "retention", "flashcard", "exam", "spaced", "repetition", "consolidation"], "summary": "Continuous memory scheduling using retrievability-ascending min-heap."},
      {"id": "tool_secret_scanner", "keywords": ["secret", "password", "key", "token", "security", "scan", "audit", "cve", "passwords", "credentials", "leaks"], "summary": "Scans code and commit history for exposed API keys, private keys, passwords, and sensitive tokens."},
      {"id": "tool_svg_badge_generator", "keywords": ["svg", "badge", "scorecard", "visual", "retina", "render", "card", "metrics", "svgwrite", "digest", "darkmode"], "summary": "Hardware-accelerated dark-mode SVG scorecard badge generator embedding verifiable SHA-256 digests."},
      {"id": "tool_weather_telemetry", "keywords": ["weather", "temperature", "humidity", "climate", "sensor", "rain", "forecast", "telemetry", "stream", "timeseries"], "summary": "Real-time municipal weather sensor ingest and localized environmental forecasting stream."},
      {"id": "tool_gauss_law_derivation", "keywords": ["gauss", "physics", "electromagnetic", "electric", "flux", "field", "maxwell", "coulomb", "divergence", "derivation"], "summary": "First-principles electromagnetic physics solver for Gauss law, divergence theorem, and electrostatic flux."}
    ]
    
    N = len(tools)
    k1 = 1.2
    b = 0.75
    
    def tokenize(text):
        return [w.strip() for w in re.sub(r"[^a-z0-9_\s]", " ", text.lower()).split() if len(w) > 1]
        
    doc_tokens = [tokenize(t["id"] + " " + " ".join(t["keywords"]) + " " + t["summary"]) for t in tools]
    avgdl = sum(len(d) for d in doc_tokens) / N
    
    df = {}
    for d in doc_tokens:
        for term in set(d):
            df[term] = df.get(term, 0) + 1
            
    idf = {term: math.log((N - count + 0.5) / (count + 0.5) + 1.0) for term, count in df.items()}
    
    def route(query):
        q_toks = tokenize(query)
        best_tool = None
        best_score = -1.0
        for i, d in enumerate(doc_tokens):
            tf = {}
            for t in d:
                tf[t] = tf.get(t, 0) + 1
            score = 0.0
            for q in q_toks:
                if q in tf:
                    t_idf = idf.get(q, 0.0)
                    t_tf = tf[q]
                    score += t_idf * (t_tf * (k1 + 1)) / (t_tf + k1 * (1 - b + b * (len(d) / avgdl)))
            if score > best_score:
                best_score = score
                best_tool = tools[i]
        return best_tool, best_score
        
    adversarial_tests = [
        ("publish my code changes to remote repository", "tool_git_commit_and_push"),
        ("will it rain in my city weather forecast", "tool_weather_telemetry"),
        ("scan repository for passwords and credentials", "tool_secret_scanner"),
        ("spaced repetition flashcard review for retention", "tool_fsrs5_spaced_repetition"),
        ("vectorized sql query on columnar parquet table", "tool_sql_duckdb_lake"),
        ("simd parser for json using neon acceleration", "tool_simd_fast_json"),
        ("bloom filter duplicate suppression", "tool_bloom_dedup"),
        ("pretrade margin limit gate check", "tool_risk_gate_interceptor"),
        ("render darkmode svg badge with sha digest", "tool_svg_badge_generator"),
        ("calculate electric flux using gauss divergence law", "tool_gauss_law_derivation")
    ]
    
    matched_tools = set()
    for query, expected_id in adversarial_tests:
        tool, score = route(query)
        assert tool is not None, f"Query {query} failed to match"
        assert tool["id"] == expected_id, f"Query {query} matched {tool['id']}, expected {expected_id}"
        assert score > 0.0, f"Score for {query} must be > 0"
        matched_tools.add(tool["id"])
        
    assert len(matched_tools) == 10, "All 10 tools must be uniquely and discriminatively matched"
