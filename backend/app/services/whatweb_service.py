"""
WhatWeb technology fingerprinting service.

Runs the WhatWeb CLI (https://github.com/urbanadventurer/WhatWeb) to enrich
technology detection with 1800+ plugins (CMS, frameworks, servers, versions).
Output is merged with Wappalyzer in the technology scan pipeline.

Install: gem install whatweb  OR  apt install whatweb
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from app.services.wappalyzer_service import DetectedTechnology, slugify

logger = logging.getLogger(__name__)


@dataclass
class WhatWebResult:
    """Single URL result from WhatWeb."""
    url: str
    technologies: List[DetectedTechnology]
    http_status: Optional[int] = None
    raw_plugins: Optional[dict] = None


def _check_whatweb_available() -> bool:
    """Check if WhatWeb CLI is installed."""
    return shutil.which("whatweb") is not None


def _parse_whatweb_json(content: str, url: str) -> List[DetectedTechnology]:
    """
    Parse WhatWeb JSON output into DetectedTechnology list.
    WhatWeb can output: (1) single JSON object, (2) array of objects, (3) one JSON object per line.
    """
    techs: List[DetectedTechnology] = []
    try:
        # Try single object or array
        data = json.loads(content)
        if isinstance(data, list):
            for item in data:
                techs.extend(_extract_techs_from_item(item, url))
        elif isinstance(data, dict):
            techs.extend(_extract_techs_from_item(data, url))
    except json.JSONDecodeError:
        # One JSON object per line
        for line in content.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                techs.extend(_extract_techs_from_item(item, url))
            except json.JSONDecodeError:
                continue
    return techs


def _extract_techs_from_item(item: dict, default_url: str) -> List[DetectedTechnology]:
    """Extract technologies from one WhatWeb result object."""
    techs: List[DetectedTechnology] = []
    target = item.get("target") or item.get("url") or default_url
    plugins = item.get("plugins") or item.get("Plugin") or {}
    if not isinstance(plugins, dict):
        return techs
    for name, info in plugins.items():
        if not name or not isinstance(info, dict):
            continue
        version = None
        ver_list = info.get("version") or info.get("Version") or []
        if isinstance(ver_list, list) and ver_list:
            version = str(ver_list[0]) if ver_list else None
        elif isinstance(ver_list, str):
            version = ver_list
        slug = slugify(name)
        techs.append(DetectedTechnology(
            name=name,
            slug=slug,
            confidence=90,  # WhatWeb plugin match
            version=version,
            categories=[],  # WhatWeb doesn't provide categories in JSON
        ))
    return techs


class WhatWebService:
    """
    Run WhatWeb against URLs and return detected technologies.
    """

    def __init__(self, whatweb_path: str = "whatweb", timeout: int = 60):
        self.whatweb_path = whatweb_path or shutil.which("whatweb") or "whatweb"
        self.timeout = timeout

    def is_available(self) -> bool:
        return _check_whatweb_available()

    async def scan_url(self, url: str, aggression: int = 1) -> WhatWebResult:
        """
        Run WhatWeb on a single URL.
        aggression: 1=stealthy (one request), 3=aggressive, 4=heavy
        """
        if not self.is_available():
            return WhatWebResult(url=url, technologies=[])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            out_path = f.name
        try:
            cmd = [
                self.whatweb_path,
                "--log-json", out_path,
                "-a", str(max(1, min(4, aggression))),
                "--no-errors",
                url,
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                logger.warning(f"WhatWeb timed out for {url}")
                return WhatWebResult(url=url, technologies=[])
            if proc.returncode != 0 and stderr:
                logger.debug(f"WhatWeb stderr: {stderr.decode()[:200]}")
            content = Path(out_path).read_text(encoding="utf-8", errors="ignore")
            technologies = _parse_whatweb_json(content, url)
            return WhatWebResult(url=url, technologies=technologies)
        except Exception as e:
            logger.warning(f"WhatWeb scan failed for {url}: {e}")
            return WhatWebResult(url=url, technologies=[])
        finally:
            try:
                Path(out_path).unlink(missing_ok=True)
            except Exception:
                pass

    async def scan_urls(self, urls: List[str], aggression: int = 1) -> List[WhatWebResult]:
        """Run WhatWeb on multiple URLs (sequentially to avoid overload)."""
        results = []
        for url in urls:
            r = await self.scan_url(url, aggression=aggression)
            results.append(r)
        return results
