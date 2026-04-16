"""Synchronous subprocess helpers for scanner CLIs."""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Sequence

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def run_command(
    cmd: Sequence[str],
    *,
    timeout: int = 600,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
) -> CommandResult:
    """Run a command; capture stdout/stderr (UTF-8, replace errors)."""
    logger.info("Running: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            errors="replace",
        )
        return CommandResult(
            exit_code=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after %ss: %s", timeout, cmd[0])
        return CommandResult(exit_code=-1, stdout="", stderr=f"timeout after {timeout}s")
    except FileNotFoundError:
        return CommandResult(exit_code=-1, stdout="", stderr=f"not found: {cmd[0]}")
