"""
Civex Progressive Tool Disclosure Engine & Adapter Shield
=========================================================
Sub-50µs adaptive tool retrieval, token-efficient dynamic schema hydration,
and unified fail-closed MCP parameter adapter shield.
"""

from .adapter_shield import (
    CivexCausalShield,
    DedupShield,
    PlaywrightPayloadAdapter,
    SovereignCircuitBreaker,
    SyntaxAndPanicSanitizer,
)
from .bridge import (
    CIVeXVerifier,
    HeadroomCompressor,
    ProgressiveToolBridge,
    SchemaShrinker,
)
from .root_eradication_engine import (
    AntiStormDedupShield,
    ASTShellInterceptor,
    CIVeXCausalVerifier,
    DiskBloatGovernor,
    RootEradicationEngine,
    SchemaAdapterShield,
    SQLiteConcurrencyShield,
)

__version__ = "0.3.0"
__all__ = [
    "ASTShellInterceptor",
    "AntiStormDedupShield",
    "CIVeXCausalVerifier",
    "CIVeXVerifier",
    "CivexCausalShield",
    "DedupShield",
    "DiskBloatGovernor",
    "HeadroomCompressor",
    "PlaywrightPayloadAdapter",
    "ProgressiveToolBridge",
    "RootEradicationEngine",
    "SQLiteConcurrencyShield",
    "SchemaAdapterShield",
    "SchemaShrinker",
    "SovereignCircuitBreaker",
    "SyntaxAndPanicSanitizer",
]
