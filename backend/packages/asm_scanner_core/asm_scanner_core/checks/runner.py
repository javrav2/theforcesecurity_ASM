"""Run security checks from merged project `security_checks` config."""

from __future__ import annotations

import logging
from typing import Dict, List

from asm_scanner_core.findings import Finding
from asm_scanner_core.checks.context import SecurityCheckContext
from asm_scanner_core.checks.builtins import registry

logger = logging.getLogger(__name__)


def run_security_checks(
    security_checks_config: Dict,
    ctx: SecurityCheckContext,
) -> List[Finding]:
    """
    Execute enabled asm_scanner_core checks.

    `security_checks_config` is the merged JSON from project_settings.security_checks.
    Keys:
      - asm_core_checks: master toggle (default True in platform defaults)
      - asm_core_nerva / asm_core_titus / asm_core_gitleaks: per-tool toggles
    """
    if not security_checks_config.get("asm_core_checks", True):
        logger.info("asm_core_checks disabled; skipping asm_scanner_core checks")
        return []

    findings: List[Finding] = []
    for key, fn in registry():
        if not security_checks_config.get(key):
            continue
        try:
            batch = fn(ctx, security_checks_config)
            findings.extend(batch or [])
            logger.info("check %s produced %s findings", key, len(batch or []))
        except Exception as e:
            logger.warning("check %s failed: %s", key, e, exc_info=True)
    return findings
