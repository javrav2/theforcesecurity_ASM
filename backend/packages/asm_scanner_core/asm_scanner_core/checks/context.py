"""Context passed into security check implementations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SecurityCheckContext:
    """Inputs for asm_scanner_core checks (worker or tests)."""

    organization_id: int
    scan_id: Optional[int] = None
    domain: Optional[str] = None
    targets: List[str] = field(default_factory=list)
    scratch_dir: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)
