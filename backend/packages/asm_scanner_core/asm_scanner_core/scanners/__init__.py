"""Concrete CLI scanner wrappers (titus, pius, ...)."""

from asm_scanner_core.scanners.titus import run_titus, TitusResult
from asm_scanner_core.scanners.pius import run_pius, PiusResult

__all__ = ["run_titus", "TitusResult", "run_pius", "PiusResult"]
