"""
Civex Progressive Tool Disclosure Engine
========================================
Sub-50µs adaptive tool retrieval and token-efficient dynamic schema hydration
for large-scale agentic tool catalogs (5,000+ tools).
"""

from .bridge import (
    HeadroomCompressor,
    SchemaShrinker,
    CIVeXVerifier,
    ProgressiveToolBridge,
)

__version__ = "0.1.0"
__all__ = [
    "HeadroomCompressor",
    "SchemaShrinker",
    "CIVeXVerifier",
    "ProgressiveToolBridge",
]
