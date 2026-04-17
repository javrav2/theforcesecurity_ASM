"""
Aegis Vanguard scanner wrappers.

Public (Aegis-branded):
    run_argus  / ArgusResult   - secrets on local paths       (wraps Praetorian titus)
    run_atlas  / AtlasResult   - org-wide attack surface      (wraps Praetorian pius)
    run_hermes / HermesResult  - secrets on remote sources    (wraps TruffleHog v3)
    run_janus  / JanusResult   - DAST scanning (baseline/full)(wraps OWASP ZAP)

The lower-level Praetorian-named modules (titus, pius) remain available for
callers that want to reference the upstream CLIs by name.
"""

from asm_scanner_core.scanners.argus import run_argus, ArgusResult
from asm_scanner_core.scanners.atlas import run_atlas, AtlasResult
from asm_scanner_core.scanners.hermes import run_hermes, HermesResult
from asm_scanner_core.scanners.janus import run_janus, JanusResult
from asm_scanner_core.scanners.titus import run_titus, TitusResult
from asm_scanner_core.scanners.pius import run_pius, PiusResult

__all__ = [
    "run_argus",
    "ArgusResult",
    "run_atlas",
    "AtlasResult",
    "run_hermes",
    "HermesResult",
    "run_janus",
    "JanusResult",
    "run_titus",
    "TitusResult",
    "run_pius",
    "PiusResult",
]
