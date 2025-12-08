"""
EyeWitness Service for capturing website screenshots.

Integrates with EyeWitness (https://github.com/RedSiege/EyeWitness) to capture
screenshots of web assets for visual monitoring and change detection.
"""

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import logging

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


@dataclass
class ScreenshotResult:
    """Result from a single screenshot capture."""
    url: str
    success: bool
    file_path: Optional[str] = None
    thumbnail_path: Optional[str] = None
    source_path: Optional[str] = None
    http_status: Optional[int] = None
    page_title: Optional[str] = None
    server_header: Optional[str] = None
    response_headers: Optional[Dict[str, str]] = None
    category: Optional[str] = None
    default_creds: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    image_hash: Optional[str] = None
    width: Optional[int] = None
    height: Optional[int] = None
    file_size: Optional[int] = None


@dataclass
class EyeWitnessConfig:
    """Configuration for EyeWitness execution."""
    timeout: int = 30
    threads: int = 5
    delay: int = 0
    jitter: int = 0
    user_agent: Optional[str] = None
    proxy_ip: Optional[str] = None
    proxy_port: Optional[int] = None
    prepend_https: bool = True
    resolve_dns: bool = False
    max_retries: int = 2


class EyeWitnessService:
    """
    Service for running EyeWitness screenshots.
    
    Handles:
    - Running EyeWitness on URLs
    - Processing output reports
    - Managing screenshot storage
    - Change detection between screenshots
    """
    
    # Base directory for storing screenshots
    SCREENSHOTS_DIR = os.environ.get("SCREENSHOTS_DIR", "/app/data/screenshots")
    EYEWITNESS_PATH = os.environ.get("EYEWITNESS_PATH", "/opt/EyeWitness/Python/EyeWitness.py")
    EYEWITNESS_VENV = os.environ.get("EYEWITNESS_VENV", "/opt/EyeWitness/eyewitness-venv/bin/python")
    
    def __init__(self):
        """Initialize the EyeWitness service."""
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Ensure required directories exist."""
        Path(self.SCREENSHOTS_DIR).mkdir(parents=True, exist_ok=True)
    
    def check_installation(self) -> Dict[str, Any]:
        """
        Check if EyeWitness is properly installed.
        
        Returns:
            Dictionary with installation status and version info
        """
        result = {
            "installed": False,
            "version": None,
            "path": self.EYEWITNESS_PATH,
            "venv_path": self.EYEWITNESS_VENV,
            "error": None
        }
        
        # Check if EyeWitness script exists
        if not os.path.exists(self.EYEWITNESS_PATH):
            result["error"] = f"EyeWitness not found at {self.EYEWITNESS_PATH}"
            return result
        
        # Check if venv Python exists
        if not os.path.exists(self.EYEWITNESS_VENV):
            result["error"] = f"EyeWitness venv not found at {self.EYEWITNESS_VENV}"
            return result
        
        # Try to get version
        try:
            proc = subprocess.run(
                [self.EYEWITNESS_VENV, self.EYEWITNESS_PATH, "--help"],
                capture_output=True,
                text=True,
                timeout=30
            )
            result["installed"] = True
            # Extract version from help output if available
            if "EyeWitness" in proc.stdout:
                result["version"] = "installed"
        except subprocess.TimeoutExpired:
            result["error"] = "EyeWitness check timed out"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def capture_screenshots(
        self,
        urls: List[str],
        organization_id: int,
        config: Optional[EyeWitnessConfig] = None
    ) -> List[ScreenshotResult]:
        """
        Capture screenshots for a list of URLs.
        
        Args:
            urls: List of URLs to screenshot
            organization_id: Organization ID for storage organization
            config: Optional configuration settings
            
        Returns:
            List of ScreenshotResult objects
        """
        if not urls:
            return []
        
        config = config or EyeWitnessConfig()
        results = []
        
        # Create temporary directory for EyeWitness output
        with tempfile.TemporaryDirectory() as temp_dir:
            # Write URLs to file
            urls_file = os.path.join(temp_dir, "urls.txt")
            with open(urls_file, "w") as f:
                for url in urls:
                    # Ensure URL has protocol
                    if not url.startswith(("http://", "https://")):
                        if config.prepend_https:
                            url = f"https://{url}"
                        else:
                            url = f"http://{url}"
                    f.write(f"{url}\n")
            
            output_dir = os.path.join(temp_dir, "output")
            
            # Build EyeWitness command
            cmd = [
                self.EYEWITNESS_VENV,
                self.EYEWITNESS_PATH,
                "-f", urls_file,
                "-d", output_dir,
                "--timeout", str(config.timeout),
                "--threads", str(config.threads),
                "--no-prompt"
            ]
            
            if config.delay > 0:
                cmd.extend(["--delay", str(config.delay)])
            
            if config.jitter > 0:
                cmd.extend(["--jitter", str(config.jitter)])
            
            if config.user_agent:
                cmd.extend(["--user-agent", config.user_agent])
            
            if config.proxy_ip and config.proxy_port:
                cmd.extend([
                    "--proxy-ip", config.proxy_ip,
                    "--proxy-port", str(config.proxy_port)
                ])
            
            if config.resolve_dns:
                cmd.append("--resolve")
            
            logger.info(f"Running EyeWitness for {len(urls)} URLs")
            
            # Run EyeWitness
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=config.timeout * len(urls) + 60  # Buffer time
                )
                
                if proc.returncode != 0:
                    logger.warning(f"EyeWitness returned non-zero: {stderr.decode()}")
                
            except asyncio.TimeoutError:
                logger.error("EyeWitness execution timed out")
                # Return timeout results for all URLs
                return [
                    ScreenshotResult(url=url, success=False, error_message="Timeout")
                    for url in urls
                ]
            except Exception as e:
                logger.error(f"EyeWitness execution failed: {e}")
                return [
                    ScreenshotResult(url=url, success=False, error_message=str(e))
                    for url in urls
                ]
            
            # Process results
            results = await self._process_eyewitness_output(
                output_dir, urls, organization_id
            )
        
        return results
    
    async def _process_eyewitness_output(
        self,
        output_dir: str,
        original_urls: List[str],
        organization_id: int
    ) -> List[ScreenshotResult]:
        """
        Process EyeWitness output directory and extract results.
        
        Args:
            output_dir: Path to EyeWitness output directory
            original_urls: Original list of URLs
            organization_id: Organization ID for storage
            
        Returns:
            List of processed ScreenshotResult objects
        """
        results = []
        processed_urls = set()
        
        # Create organization screenshot directory
        org_dir = os.path.join(self.SCREENSHOTS_DIR, str(organization_id))
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        session_dir = os.path.join(org_dir, timestamp)
        Path(session_dir).mkdir(parents=True, exist_ok=True)
        
        screens_dir = os.path.join(output_dir, "screens")
        source_dir = os.path.join(output_dir, "source")
        
        # Parse the EyeWitness database if available
        db_path = os.path.join(output_dir, "ew.db")
        db_results = {}
        
        if os.path.exists(db_path):
            db_results = self._parse_eyewitness_db(db_path)
        
        # Process screenshots
        if os.path.exists(screens_dir):
            for screenshot_file in os.listdir(screens_dir):
                if not screenshot_file.endswith(".png"):
                    continue
                
                # Extract URL from filename (EyeWitness format)
                url = self._extract_url_from_filename(screenshot_file)
                if not url:
                    continue
                
                processed_urls.add(url)
                
                # Copy screenshot to permanent storage
                src_path = os.path.join(screens_dir, screenshot_file)
                dst_filename = self._sanitize_filename(url) + ".png"
                dst_path = os.path.join(session_dir, dst_filename)
                
                try:
                    shutil.copy2(src_path, dst_path)
                    relative_path = os.path.relpath(dst_path, self.SCREENSHOTS_DIR)
                    
                    # Get file info
                    file_size = os.path.getsize(dst_path)
                    image_hash = self._calculate_file_hash(dst_path)
                    
                    # Get dimensions
                    width, height = self._get_image_dimensions(dst_path)
                    
                    # Get DB info if available
                    db_info = db_results.get(url, {})
                    
                    result = ScreenshotResult(
                        url=url,
                        success=True,
                        file_path=relative_path,
                        http_status=db_info.get("http_status"),
                        page_title=db_info.get("page_title"),
                        server_header=db_info.get("server_header"),
                        response_headers=db_info.get("headers"),
                        category=db_info.get("category"),
                        default_creds=db_info.get("default_creds"),
                        image_hash=image_hash,
                        width=width,
                        height=height,
                        file_size=file_size
                    )
                    
                    # Check for source file
                    source_filename = screenshot_file.replace(".png", ".txt")
                    source_path = os.path.join(source_dir, source_filename)
                    if os.path.exists(source_path):
                        dst_source = os.path.join(session_dir, self._sanitize_filename(url) + "_source.html")
                        shutil.copy2(source_path, dst_source)
                        result.source_path = os.path.relpath(dst_source, self.SCREENSHOTS_DIR)
                    
                    results.append(result)
                    
                except Exception as e:
                    logger.error(f"Error processing screenshot for {url}: {e}")
                    results.append(ScreenshotResult(
                        url=url,
                        success=False,
                        error_message=str(e)
                    ))
        
        # Add failed results for URLs without screenshots
        for url in original_urls:
            normalized_url = url
            if not url.startswith(("http://", "https://")):
                normalized_url = f"https://{url}"
            
            if normalized_url not in processed_urls and url not in processed_urls:
                results.append(ScreenshotResult(
                    url=url,
                    success=False,
                    error_message="No screenshot captured"
                ))
        
        return results
    
    def _parse_eyewitness_db(self, db_path: str) -> Dict[str, Dict[str, Any]]:
        """
        Parse EyeWitness SQLite database for additional metadata.
        
        Args:
            db_path: Path to ew.db file
            
        Returns:
            Dictionary mapping URLs to their metadata
        """
        import sqlite3
        
        results = {}
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Query the targets table
            cursor.execute("""
                SELECT url, http_status, page_title, headers, 
                       source_code_path, screenshot_path, category
                FROM targets
            """)
            
            for row in cursor.fetchall():
                url, http_status, page_title, headers, source_path, screenshot_path, category = row
                
                results[url] = {
                    "http_status": http_status,
                    "page_title": page_title,
                    "headers": json.loads(headers) if headers else None,
                    "category": category
                }
            
            conn.close()
            
        except Exception as e:
            logger.warning(f"Could not parse EyeWitness database: {e}")
        
        return results
    
    def _extract_url_from_filename(self, filename: str) -> Optional[str]:
        """
        Extract URL from EyeWitness screenshot filename.
        
        EyeWitness uses format: http_domain_port.png or https_domain_port.png
        """
        try:
            # Remove extension
            name = filename.rsplit(".", 1)[0]
            
            # Replace underscores back to proper URL format
            if name.startswith("http_"):
                url = "http://" + name[5:].replace("_", ".", 1)
            elif name.startswith("https_"):
                url = "https://" + name[6:].replace("_", ".", 1)
            else:
                return None
            
            # Handle port numbers
            parts = url.split("_")
            if len(parts) > 1 and parts[-1].isdigit():
                url = "_".join(parts[:-1]) + ":" + parts[-1]
            
            return url.replace("_", "/")
            
        except Exception:
            return None
    
    def _sanitize_filename(self, url: str) -> str:
        """Create a safe filename from URL."""
        # Remove protocol
        name = url.replace("https://", "").replace("http://", "")
        # Replace unsafe characters
        for char in [":", "/", "?", "&", "=", "#", "%"]:
            name = name.replace(char, "_")
        # Truncate if too long
        if len(name) > 200:
            name = name[:200] + "_" + hashlib.md5(url.encode()).hexdigest()[:8]
        return name
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _get_image_dimensions(self, file_path: str) -> tuple:
        """Get image dimensions without full image library."""
        try:
            # Try using PIL if available
            from PIL import Image
            with Image.open(file_path) as img:
                return img.size
        except ImportError:
            # Fallback: read PNG header
            try:
                with open(file_path, "rb") as f:
                    f.read(16)  # Skip to IHDR
                    width = int.from_bytes(f.read(4), "big")
                    height = int.from_bytes(f.read(4), "big")
                    return width, height
            except Exception:
                return None, None
        except Exception:
            return None, None
    
    async def capture_single(
        self,
        url: str,
        organization_id: int,
        config: Optional[EyeWitnessConfig] = None
    ) -> ScreenshotResult:
        """
        Capture a single screenshot.
        
        Args:
            url: URL to screenshot
            organization_id: Organization ID
            config: Optional configuration
            
        Returns:
            ScreenshotResult
        """
        results = await self.capture_screenshots([url], organization_id, config)
        return results[0] if results else ScreenshotResult(
            url=url, success=False, error_message="No result returned"
        )
    
    def get_screenshot_path(self, relative_path: str) -> str:
        """Get absolute path for a screenshot."""
        return os.path.join(self.SCREENSHOTS_DIR, relative_path)
    
    def delete_screenshot(self, relative_path: str) -> bool:
        """Delete a screenshot file."""
        try:
            full_path = self.get_screenshot_path(relative_path)
            if os.path.exists(full_path):
                os.remove(full_path)
                return True
            return False
        except Exception as e:
            logger.error(f"Error deleting screenshot: {e}")
            return False
    
    def calculate_change_percentage(
        self,
        hash1: str,
        hash2: str
    ) -> int:
        """
        Calculate percentage difference between two image hashes.
        
        For now, returns 100 if different, 0 if same.
        Could be enhanced with perceptual hashing.
        """
        if hash1 == hash2:
            return 0
        return 100  # Simple binary comparison


# Singleton instance
_eyewitness_service: Optional[EyeWitnessService] = None


def get_eyewitness_service() -> EyeWitnessService:
    """Get or create the EyeWitness service singleton."""
    global _eyewitness_service
    if _eyewitness_service is None:
        _eyewitness_service = EyeWitnessService()
    return _eyewitness_service




