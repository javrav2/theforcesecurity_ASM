"""
CommonCrawl Live CDX API service for subdomain enumeration.

Queries the CommonCrawl CDX (Capture Index) API directly to discover
subdomains without requiring a pre-built S3 index.

Inspired by CCrawlDNS (https://github.com/lgandx/CCrawlDNS):
  fetch available collections → filter by year → query *.domain pattern
  on each selected dataset → deduplicate subdomains.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

CCRAWL_COLLECTIONS_URL = "https://index.commoncrawl.org/collinfo.json"
CCRAWL_INDEX_URL = "https://index.commoncrawl.org/{release}-index"

DEFAULT_YEARS = "last2"       # mirror CCrawlDNS default
DEFAULT_MAX_PER_YEAR = 1      # most efficient — same as CCrawlDNS default
DEFAULT_TIMEOUT = 120.0
DEFAULT_RATE_LIMIT_DELAY = 1.0
DEFAULT_MAX_RESULTS_PER_RELEASE = 100_000


@dataclass
class CCrawlLiveResult:
    """Result from a live CommonCrawl CDX lookup for a single domain."""
    domain: str
    subdomains: List[str] = field(default_factory=list)
    releases_queried: List[str] = field(default_factory=list)
    elapsed_time: float = 0.0
    source: str = "commoncrawl-live"
    error: Optional[str] = None


class CommonCrawlLiveService:
    """
    Live CommonCrawl CDX API service for subdomain enumeration.

    Queries the Common Crawl CDX API directly — no S3 index required.
    Uses the same dataset-selection logic as CCrawlDNS:

      1. GET collinfo.json  →  list of available crawl releases
      2. Filter by desired years / "last N"
      3. For each selected release query ``*.domain`` via CDX API
      4. Parse NDJSON responses, extract unique hostnames
      5. Return deduplicated subdomains

    Year options:
      "last2"          — most recent 2 calendar years (default, fastest)
      "last3"          — most recent 3 calendar years
      "lastN"          — most recent N calendar years
      "all"            — every available release (slowest, most complete)
      "2025"           — a single specific year
      "2025,2024"      — multiple specific years (comma-separated)
    """

    def __init__(
        self,
        years: str = DEFAULT_YEARS,
        max_per_year: int = DEFAULT_MAX_PER_YEAR,
        timeout: float = DEFAULT_TIMEOUT,
        rate_limit_delay: float = DEFAULT_RATE_LIMIT_DELAY,
        max_results_per_release: int = DEFAULT_MAX_RESULTS_PER_RELEASE,
    ):
        self.years = years
        self.max_per_year = max_per_year
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay
        self.max_results_per_release = max_results_per_release

    # ------------------------------------------------------------------
    # Collection / release selection
    # ------------------------------------------------------------------

    async def _get_collections(self, client: httpx.AsyncClient) -> List[dict]:
        """Fetch the list of available CC crawl releases from collinfo.json."""
        try:
            response = await client.get(CCRAWL_COLLECTIONS_URL, timeout=30.0)
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            logger.error(f"Failed to fetch CC collections: {exc}")
            return []

    def _filter_releases(self, collections: List[dict]) -> List[str]:
        """
        Choose which CC releases to query based on ``self.years``.

        Release IDs look like "CC-MAIN-2025-13" — the third segment is the year.
        For each qualifying year we take at most ``self.max_per_year`` releases
        (collinfo.json lists newest first, so the first entry is the most recent).
        """
        current_year = datetime.now(timezone.utc).year
        target_years: Optional[Set[int]]

        if self.years == "all":
            target_years = None
        elif self.years.startswith("last"):
            n = int(self.years[4:])
            target_years = {current_year - i for i in range(n)}
        else:
            target_years = {
                int(y.strip()) for y in self.years.split(",") if y.strip().isdigit()
            }

        by_year: Dict[int, List[str]] = {}
        for col in collections:
            col_id = col.get("id", "")
            parts = col_id.split("-")
            # IDs are shaped like CC-MAIN-YYYY-WW
            if len(parts) >= 3 and parts[2].isdigit():
                year = int(parts[2])
                if target_years is None or year in target_years:
                    by_year.setdefault(year, []).append(col_id)

        selected: List[str] = []
        for year in sorted(by_year.keys(), reverse=True):
            # collinfo is already newest-first within each year
            selected.extend(by_year[year][: self.max_per_year])

        return selected

    # ------------------------------------------------------------------
    # CDX API query
    # ------------------------------------------------------------------

    async def _query_release(
        self,
        client: httpx.AsyncClient,
        release: str,
        domain: str,
    ) -> Set[str]:
        """Query one CC release for all crawled URLs matching ``*.domain``."""
        subdomains: Set[str] = set()
        url = CCRAWL_INDEX_URL.format(release=release)
        params = {
            "url": f"*.{domain}",
            "output": "json",
            "fl": "url",
            "limit": self.max_results_per_release,
        }

        try:
            response = await client.get(url, params=params, timeout=self.timeout)
            if response.status_code == 404:
                logger.debug(f"CC release {release} has no data for {domain}")
                return subdomains
            response.raise_for_status()

            suffix = f".{domain}"
            for line in response.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    raw_url = record.get("url", "")
                    if not raw_url:
                        continue
                    parsed = urlparse(raw_url)
                    hostname = parsed.netloc.lower()
                    # Strip port if present
                    if ":" in hostname:
                        hostname = hostname.rsplit(":", 1)[0]
                    if hostname and hostname.endswith(suffix) and hostname != domain:
                        subdomains.add(hostname)
                except (json.JSONDecodeError, Exception):
                    continue

            logger.info(
                f"CC {release}: {len(subdomains)} subdomains found for {domain}"
            )

        except httpx.TimeoutException:
            logger.warning(f"CC {release} timed out querying {domain}")
        except Exception as exc:
            logger.warning(f"CC {release} query error for {domain}: {exc}")

        return subdomains

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def search_domain(self, domain: str) -> CCrawlLiveResult:
        """
        Discover subdomains using the live CommonCrawl CDX API.

        Args:
            domain: Root domain to enumerate (e.g. "example.com")

        Returns:
            CCrawlLiveResult with a deduplicated list of subdomains.
        """
        result = CCrawlLiveResult(domain=domain)
        start = datetime.now(timezone.utc)
        all_subdomains: Set[str] = set()

        async with httpx.AsyncClient(
            headers={"User-Agent": "TheForce-ASM/1.0 (+https://theforce.security)"},
            follow_redirects=True,
        ) as client:
            collections = await self._get_collections(client)
            if not collections:
                result.error = "Failed to fetch CommonCrawl collection index"
                result.elapsed_time = (datetime.now(timezone.utc) - start).total_seconds()
                return result

            releases = self._filter_releases(collections)
            if not releases:
                result.error = f"No CC releases matched years={self.years!r}"
                result.elapsed_time = (datetime.now(timezone.utc) - start).total_seconds()
                return result

            logger.info(
                f"CommonCrawl live: querying {len(releases)} release(s) for {domain}: "
                + ", ".join(releases)
            )
            result.releases_queried = releases

            for release in releases:
                subs = await self._query_release(client, release, domain)
                all_subdomains.update(subs)
                if self.rate_limit_delay > 0 and release != releases[-1]:
                    await asyncio.sleep(self.rate_limit_delay)

        result.subdomains = sorted(all_subdomains)
        result.elapsed_time = (datetime.now(timezone.utc) - start).total_seconds()
        logger.info(
            f"CommonCrawl live complete: {len(result.subdomains)} unique subdomains "
            f"for {domain} in {result.elapsed_time:.1f}s"
        )
        return result

    async def search_domains(self, domains: List[str]) -> Dict[str, CCrawlLiveResult]:
        """
        Run ``search_domain`` for multiple domains sequentially.

        Returns a dict mapping each domain to its result.
        """
        results: Dict[str, CCrawlLiveResult] = {}
        for domain in domains:
            results[domain] = await self.search_domain(domain)
        return results
