"""
Argus - Aegis Vanguard's all-seeing secrets scanner.

Argus was the hundred-eyed giant of Greek myth — nothing escaped his sight.
Here he wraps Praetorian's `titus` CLI (487 detection rules, Hyperscan-
accelerated regex matching, optional live credential validation).

The wrapper shape and normalized Finding output are defined in
`scanners/titus.py`; this module is the public Aegis-branded entry point.
"""

from __future__ import annotations

from typing import List, Optional

from asm_scanner_core.findings import Finding
from asm_scanner_core.scanners.titus import TitusResult as _TitusResult, run_titus as _run_titus

ArgusResult = _TitusResult  # same shape; re-exported under the Aegis brand


def run_argus(
    path: str,
    *,
    validate: bool = False,
    timeout: int = 900,
    binary: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> ArgusResult:
    """
    Scan a filesystem path, file, or local git repo for leaked secrets.

    Under the hood this invokes `titus scan <path> --format json`. Set
    `validate=True` to enable live credential validation (makes outbound
    API calls to confirm which secrets are active).
    """
    return _run_titus(
        path,
        validate=validate,
        timeout=timeout,
        binary=binary,
        extra_args=extra_args,
    )


__all__ = ["run_argus", "ArgusResult", "Finding"]
