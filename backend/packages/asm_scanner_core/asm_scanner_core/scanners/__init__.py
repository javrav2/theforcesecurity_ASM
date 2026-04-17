"""
Aegis Vanguard scanner wrappers.

Public (Aegis-branded):
    run_argus / ArgusResult  - secrets scanner (wraps Praetorian titus)
    run_atlas / AtlasResult  - attack-surface discovery (wraps Praetorian pius)

The lower-level `titus` and `pius` modules remain available for callers that
want to reference the upstream Praetorian CLIs by name.
"""

from asm_scanner_core.scanners.argus import run_argus, ArgusResult
from asm_scanner_core.scanners.atlas import run_atlas, AtlasResult
from asm_scanner_core.scanners.titus import run_titus, TitusResult
from asm_scanner_core.scanners.pius import run_pius, PiusResult

__all__ = [
    "run_argus",
    "ArgusResult",
    "run_atlas",
    "AtlasResult",
    "run_titus",
    "TitusResult",
    "run_pius",
    "PiusResult",
]
