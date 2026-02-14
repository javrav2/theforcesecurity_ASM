"""
Playwright-based screenshot capture for Docker/headless environments.

Used when EyeWitness is unavailable or fails. Playwright's bundled Chromium
works reliably in containers without a display or xvfb.
"""

import asyncio
import hashlib
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# Reuse result type from eyewitness_service for compatibility
try:
    from app.services.eyewitness_service import ScreenshotResult
except ImportError:
    from dataclasses import dataclass
    @dataclass
    class ScreenshotResult:
        url: str
        success: bool
        file_path: Optional[str] = None
        thumbnail_path: Optional[str] = None
        source_path: Optional[str] = None
        http_status: Optional[int] = None
        page_title: Optional[str] = None
        server_header: Optional[str] = None
        response_headers: Optional[dict] = None
        category: Optional[str] = None
        default_creds: Optional[dict] = None
        error_message: Optional[str] = None
        image_hash: Optional[str] = None
        width: Optional[int] = None
        height: Optional[int] = None
        file_size: Optional[int] = None


def _sanitize_filename(url: str) -> str:
    """Safe filename from URL."""
    name = url.replace("https://", "").replace("http://", "")
    for char in [":", "/", "?", "&", "=", "#", "%"]:
        name = name.replace(char, "_")
    if len(name) > 200:
        name = name[:200] + "_" + hashlib.md5(url.encode()).hexdigest()[:8]
    return name


def _check_playwright_available() -> bool:
    """Return True if Playwright and Chromium are usable."""
    try:
        from playwright.async_api import async_playwright
        return True
    except ImportError:
        return False


async def capture_screenshots_playwright(
    urls: List[str],
    organization_id: int,
    *,
    timeout_ms: int = 30000,
    viewport_width: int = 1280,
    viewport_height: int = 720,
    screenshots_dir: Optional[str] = None,
) -> List[ScreenshotResult]:
    """
    Capture screenshots using Playwright (Chromium). Works in Docker without display.

    Args:
        urls: List of URLs to capture
        organization_id: Org ID for storage path
        timeout_ms: Page load timeout per URL
        viewport_width: Viewport width
        viewport_height: Viewport height
        screenshots_dir: Base directory (default from SCREENSHOTS_DIR env)

    Returns:
        List of ScreenshotResult (same shape as EyeWitness for pipeline compatibility)
    """
    if not urls:
        return []

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.warning("Playwright not installed; run: pip install playwright && playwright install chromium")
        return [
            ScreenshotResult(url=u, success=False, error_message="Playwright not installed")
            for u in urls
        ]

    base_dir = screenshots_dir or os.environ.get("SCREENSHOTS_DIR", "/app/data/screenshots")
    org_dir = os.path.join(base_dir, str(organization_id))
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    session_dir = os.path.join(org_dir, timestamp)
    Path(session_dir).mkdir(parents=True, exist_ok=True)

    results: List[ScreenshotResult] = []
    # Process in small batches to avoid too many concurrent pages
    batch_size = 5
    for i in range(0, len(urls), batch_size):
        batch = urls[i : i + batch_size]
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--single-process",
                    "--no-zygote",
                ],
            )
            try:
                for url in batch:
                    normalized = url if url.startswith(("http://", "https://")) else f"https://{url}"
                    result = await _capture_one(
                        browser, normalized, session_dir, base_dir, timeout_ms, viewport_width, viewport_height
                    )
                    results.append(result)
            finally:
                await browser.close()

        if i + batch_size < len(urls):
            await asyncio.sleep(0.5)

    return results


async def _capture_one(
    browser,
    url: str,
    session_dir: str,
    base_dir: str,
    timeout_ms: int,
    viewport_width: int,
    viewport_height: int,
) -> ScreenshotResult:
    """Capture a single URL; return ScreenshotResult."""
    page = None
    try:
        context = await browser.new_context(
            viewport={"width": viewport_width, "height": viewport_height},
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
        )
        page = await context.new_page()
        await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        await asyncio.sleep(1)
        title = await page.title()
        filename = _sanitize_filename(url) + ".png"
        path = os.path.join(session_dir, filename)
        await page.screenshot(path=path, full_page=False)
        await context.close()

        if not os.path.exists(path):
            return ScreenshotResult(url=url, success=False, error_message="Screenshot file not created")

        rel_path = os.path.relpath(path, base_dir)
        file_size = os.path.getsize(path)
        image_hash = _file_hash(path)
        width, height = _image_dimensions(path)

        return ScreenshotResult(
            url=url,
            success=True,
            file_path=rel_path,
            page_title=title or None,
            image_hash=image_hash,
            width=width,
            height=height,
            file_size=file_size,
        )
    except Exception as e:
        err_msg = str(e)[:500]
        logger.debug("Playwright capture failed for %s: %s", url, err_msg)
        return ScreenshotResult(url=url, success=False, error_message=err_msg)
    finally:
        if page and not page.is_closed():
            try:
                await page.close()
            except Exception:
                pass


def _file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _image_dimensions(path: str) -> tuple:
    try:
        from PIL import Image
        with Image.open(path) as img:
            return img.size
    except Exception:
        return None, None
