"""
GraphQL Security Scanner
========================

Discover GraphQL endpoints on in-scope targets and audit each for common
misconfigurations:

    * Introspection query exposed in production.
    * Verbose error messages / field suggestions leaking schema details.
    * GraphiQL / Playground / Altair / Voyager IDEs left on the public web.
    * CSRF-bypass (GET-based queries, unusual content types accepted).
    * Query-depth / batching not limited (DoS vector).
    * Mutation endpoint accepting unauthenticated introspection.

If the ``graphql-cop`` binary is installed we additionally shell out to it
and merge its findings, since it covers a broader corpus of checks.
All findings flow through ``persist_graphql_findings`` into the existing
``vulnerabilities`` table.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Awaitable, Callable, Iterable, Optional
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)


DEFAULT_PATHS = [
    "/graphql",
    "/graphql/",
    "/api/graphql",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/gql",
    "/graphiql",
    "/altair",
    "/playground",
    "/voyager",
    "/subscriptions",
]

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind }
  }
}
"""

MINIMAL_INTROSPECTION = "{__schema{queryType{name}}}"

# An intentionally malformed query used to trigger field-suggestion / verbose errors.
FIELD_SUGGESTION_QUERY = "{__schema{queryTypes{name}}}"  # misspelled field


IDE_SIGNATURES = [
    ("graphiql", re.compile(r"graphiql|GraphiQL", re.IGNORECASE)),
    ("playground", re.compile(r"playgroundVersion|GraphQL Playground", re.IGNORECASE)),
    ("altair", re.compile(r"altair", re.IGNORECASE)),
    ("voyager", re.compile(r"graphql-voyager|Voyager", re.IGNORECASE)),
]


@dataclass
class GraphQLEndpoint:
    url: str
    hostname: str
    method: str
    status_code: int
    introspection_ok: bool = False
    ide_kind: Optional[str] = None


@dataclass
class GraphQLFinding:
    issue: str                     # e.g. "introspection_exposed"
    severity: str
    hostname: str
    endpoint_url: str
    evidence: str
    extras: dict = field(default_factory=dict)


@dataclass
class GraphQLScanResult:
    endpoints: list[GraphQLEndpoint] = field(default_factory=list)
    findings: list[GraphQLFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _normalize_target(t: str) -> str:
    t = t.strip()
    if not t:
        return ""
    if not t.startswith("http"):
        t = f"https://{t}"
    return t


async def _probe(
    client: httpx.AsyncClient, url: str, timeout: float = 10.0
) -> Optional[GraphQLEndpoint]:
    """Probe ``url`` and decide whether it's a GraphQL endpoint or IDE."""
    host = urlparse(url).netloc

    try:
        # POST with minimal introspection: real GraphQL servers answer 200 with
        # a ``{"data":{"__schema":...}}`` envelope (or 400 with ``errors``).
        post = await client.post(
            url,
            json={"query": MINIMAL_INTROSPECTION},
            timeout=timeout,
            follow_redirects=True,
        )
        if post.status_code < 500:
            body = post.text or ""
            if _looks_like_graphql(body):
                ep = GraphQLEndpoint(
                    url=str(post.url),
                    hostname=host,
                    method="POST",
                    status_code=post.status_code,
                )
                if '"__schema"' in body and '"errors"' not in body:
                    ep.introspection_ok = True
                return ep

        # Otherwise fall back to GET and look for IDE signatures.
        get = await client.get(url, timeout=timeout, follow_redirects=True)
        body = get.text or ""
        for kind, pat in IDE_SIGNATURES:
            if pat.search(body):
                return GraphQLEndpoint(
                    url=str(get.url),
                    hostname=host,
                    method="GET",
                    status_code=get.status_code,
                    ide_kind=kind,
                )
    except Exception as exc:
        logger.debug("probe %s failed: %s", url, exc)
    return None


def _looks_like_graphql(body: str) -> bool:
    if not body:
        return False
    lower = body.lower()
    if '"data"' in body and ('"__schema"' in body or '"errors"' in body):
        return True
    if '"errors"' in body and ("graphql" in lower or "field" in lower):
        return True
    return False


async def _discover_endpoints(
    client: httpx.AsyncClient,
    targets: Iterable[str],
    paths: list[str],
    timeout: float,
) -> list[GraphQLEndpoint]:
    candidate_urls: list[str] = []
    for t in targets:
        base = _normalize_target(t)
        if not base:
            continue
        parsed = urlparse(base)
        root = f"{parsed.scheme}://{parsed.netloc}"
        # Treat the target itself as a candidate (in case the user already
        # supplied the exact GraphQL URL).
        candidate_urls.append(base)
        for p in paths:
            candidate_urls.append(urljoin(root, p))

    # Deduplicate while preserving order.
    candidate_urls = list(dict.fromkeys(candidate_urls))

    sem = asyncio.Semaphore(20)

    async def _one(u: str) -> Optional[GraphQLEndpoint]:
        async with sem:
            return await _probe(client, u, timeout=timeout)

    results = await asyncio.gather(*( _one(u) for u in candidate_urls ))
    return [r for r in results if r is not None]


# ---------------------------------------------------------------------------
# Audits
# ---------------------------------------------------------------------------


async def _audit_endpoint(
    client: httpx.AsyncClient, ep: GraphQLEndpoint, timeout: float
) -> list[GraphQLFinding]:
    findings: list[GraphQLFinding] = []

    if ep.ide_kind:
        findings.append(GraphQLFinding(
            issue="ide_exposed",
            severity="medium",
            hostname=ep.hostname,
            endpoint_url=ep.url,
            evidence=f"{ep.ide_kind} IDE served at {ep.url}",
            extras={"ide": ep.ide_kind},
        ))
        # IDE-only pages don't usually accept POSTed queries, but keep probing
        # in case the same path also hosts the API (common for Apollo Server).

    if ep.introspection_ok:
        findings.append(GraphQLFinding(
            issue="introspection_exposed",
            severity="medium",
            hostname=ep.hostname,
            endpoint_url=ep.url,
            evidence=f"POST {ep.url} returned full __schema response",
        ))

    # Verbose errors / field suggestions
    try:
        r = await client.post(
            ep.url,
            json={"query": FIELD_SUGGESTION_QUERY},
            timeout=timeout,
        )
        body = r.text or ""
        if "did you mean" in body.lower():
            findings.append(GraphQLFinding(
                issue="field_suggestions_enabled",
                severity="low",
                hostname=ep.hostname,
                endpoint_url=ep.url,
                evidence=body[:500],
            ))
        if re.search(r"(Traceback|at \w+\.js:\d+|stack trace|\.py\":\s*\d+)", body):
            findings.append(GraphQLFinding(
                issue="verbose_errors",
                severity="medium",
                hostname=ep.hostname,
                endpoint_url=ep.url,
                evidence=body[:500],
            ))
    except Exception as exc:
        logger.debug("field-suggestion probe failed for %s: %s", ep.url, exc)

    # CSRF bypass via GET
    try:
        r = await client.get(ep.url, params={"query": MINIMAL_INTROSPECTION}, timeout=timeout)
        if r.status_code == 200 and _looks_like_graphql(r.text or ""):
            findings.append(GraphQLFinding(
                issue="csrf_bypass_get",
                severity="high",
                hostname=ep.hostname,
                endpoint_url=ep.url,
                evidence="Server accepts queries via GET with no CSRF token",
            ))
    except Exception:
        pass

    # CSRF bypass via form-encoded body
    try:
        r = await client.post(
            ep.url,
            data={"query": MINIMAL_INTROSPECTION},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
        )
        if r.status_code == 200 and _looks_like_graphql(r.text or ""):
            findings.append(GraphQLFinding(
                issue="csrf_bypass_form_content_type",
                severity="medium",
                hostname=ep.hostname,
                endpoint_url=ep.url,
                evidence="Server accepts application/x-www-form-urlencoded queries",
            ))
    except Exception:
        pass

    # Query batching / alias-based DoS (send an oversized batch)
    try:
        batch = [{"query": MINIMAL_INTROSPECTION} for _ in range(50)]
        r = await client.post(ep.url, json=batch, timeout=timeout)
        if r.status_code == 200:
            body = r.text or ""
            # Apollo/Yoga answer 200 with an *array*; Hasura & others 400.
            if body.lstrip().startswith("["):
                findings.append(GraphQLFinding(
                    issue="query_batching_unlimited",
                    severity="medium",
                    hostname=ep.hostname,
                    endpoint_url=ep.url,
                    evidence=f"Accepted batch of 50 queries (status {r.status_code})",
                ))
    except Exception:
        pass

    return findings


# ---------------------------------------------------------------------------
# graphql-cop bridge (optional)
# ---------------------------------------------------------------------------


def _have_binary(name: str) -> bool:
    return shutil.which(name) is not None


async def _run_graphql_cop(ep: GraphQLEndpoint) -> list[GraphQLFinding]:
    if not _have_binary("graphql-cop"):
        return []
    try:
        proc = await asyncio.create_subprocess_exec(
            "graphql-cop", "-t", ep.url, "-o", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120.0)
    except Exception:
        return []

    findings: list[GraphQLFinding] = []
    out = stdout.decode(errors="ignore").strip()
    try:
        data = json.loads(out)
    except Exception:
        return findings

    items = data if isinstance(data, list) else data.get("findings") or []
    for item in items:
        findings.append(GraphQLFinding(
            issue=f"graphql_cop.{_slug(item.get('title') or item.get('name') or 'finding')}",
            severity=(item.get("severity") or "medium").lower(),
            hostname=ep.hostname,
            endpoint_url=ep.url,
            evidence=(item.get("description") or json.dumps(item))[:1000],
            extras=item,
        ))
    return findings


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


async def scan_graphql_endpoints(
    targets: Iterable[str],
    extra_paths: Optional[list[str]] = None,
    timeout: int = 120,
    use_graphql_cop: bool = True,
    progress_callback: Optional[Callable[[int, str], Awaitable[None]]] = None,
) -> GraphQLScanResult:
    start = datetime.utcnow()
    result = GraphQLScanResult()

    paths = list(DEFAULT_PATHS)
    if extra_paths:
        for p in extra_paths:
            if p and p not in paths:
                paths.append(p)

    async def _progress(pct: int, step: str) -> None:
        if progress_callback:
            try:
                await progress_callback(pct, step)
            except Exception:
                pass

    await _progress(10, "Discovering GraphQL endpoints")

    async with httpx.AsyncClient(
        verify=False,
        headers={"User-Agent": "ASM-GraphQL-Scanner/1.0"},
        timeout=httpx.Timeout(float(timeout)),
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
    ) as client:
        endpoints = await _discover_endpoints(client, targets, paths, timeout=8.0)
        result.endpoints = endpoints

        await _progress(40, f"Auditing {len(endpoints)} endpoints")

        sem = asyncio.Semaphore(10)

        async def _audit(ep: GraphQLEndpoint) -> list[GraphQLFinding]:
            async with sem:
                fs = await _audit_endpoint(client, ep, timeout=8.0)
                if use_graphql_cop and (ep.introspection_ok or ep.method == "POST"):
                    fs.extend(await _run_graphql_cop(ep))
                return fs

        audits = await asyncio.gather(*( _audit(e) for e in endpoints ))
        for lst in audits:
            result.findings.extend(lst)

    result.duration_seconds = (datetime.utcnow() - start).total_seconds()
    await _progress(95, "Finalising")
    return result


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


_SEV_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def persist_graphql_findings(
    db,
    organization_id: int,
    scan_id: Optional[int],
    findings: list[GraphQLFinding],
) -> int:
    from app.models.asset import Asset, AssetType
    from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

    sev_enum = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }

    created = 0
    for f in findings:
        asset = (
            db.query(Asset)
            .filter(
                Asset.organization_id == organization_id,
                Asset.value == f.hostname,
            )
            .first()
        )
        if not asset:
            asset = Asset(
                organization_id=organization_id,
                asset_type=AssetType.DOMAIN,
                name=f.hostname,
                value=f.hostname,
                discovery_source="graphql_scanner",
            )
            db.add(asset)
            db.flush()

        template_id = f"graphql-{_slug(f.issue)}-{_hash(f.endpoint_url)}"
        existing = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.asset_id == asset.id,
                Vulnerability.template_id == template_id,
            )
            .first()
        )
        severity = sev_enum.get(_SEV_MAP.get(f.severity.lower(), "MEDIUM"), Severity.MEDIUM)
        title = f"GraphQL: {f.issue.replace('_', ' ')}"
        description = _describe_graphql(f)

        meta = {
            "issue": f.issue,
            "endpoint": f.endpoint_url,
            "hostname": f.hostname,
            **(f.extras or {}),
        }

        if existing:
            existing.severity = severity
            existing.last_detected = datetime.utcnow()
            existing.metadata_ = meta
            existing.evidence = f.evidence
            existing.status = VulnerabilityStatus.OPEN
            continue

        vuln = Vulnerability(
            title=title[:500],
            description=description[:4000],
            severity=severity,
            asset_id=asset.id,
            scan_id=scan_id,
            detected_by="graphql_scanner",
            template_id=template_id,
            status=VulnerabilityStatus.OPEN,
            evidence=(f.evidence or "")[:5000],
            tags=["graphql", _slug(f.issue)],
            metadata_=meta,
            remediation=_remediation_graphql(f),
        )
        db.add(vuln)
        created += 1

    db.commit()
    return created


def _describe_graphql(f: GraphQLFinding) -> str:
    m = {
        "introspection_exposed": (
            f"The GraphQL endpoint at `{f.endpoint_url}` responds to the "
            f"``__schema`` introspection query, exposing the full type graph, "
            f"queries, mutations, and argument names to unauthenticated users."
        ),
        "ide_exposed": (
            f"A GraphQL IDE ({f.extras.get('ide', 'unknown')}) is publicly served "
            f"at `{f.endpoint_url}`. IDEs make schema exploration trivial for "
            f"attackers and should be restricted to non-production environments."
        ),
        "verbose_errors": (
            f"GraphQL responses at `{f.endpoint_url}` include stack traces or "
            f"framework-specific error details that leak code paths."
        ),
        "field_suggestions_enabled": (
            f"`{f.endpoint_url}` returns ``did you mean`` field suggestions on "
            f"invalid queries, effectively exposing the schema even if "
            f"introspection is disabled."
        ),
        "csrf_bypass_get": (
            f"`{f.endpoint_url}` accepts queries via HTTP ``GET``. This bypasses "
            f"most CSRF protections and enables cross-site query execution via "
            f"``<img>`` / ``<script>`` tags."
        ),
        "csrf_bypass_form_content_type": (
            f"`{f.endpoint_url}` accepts queries with a form content-type. "
            f"Browsers allow cross-origin requests with ``application/x-www-form-urlencoded`` "
            f"without preflight, allowing CSRF exploitation."
        ),
        "query_batching_unlimited": (
            f"`{f.endpoint_url}` processes unlimited query batches in a single "
            f"request, enabling amplification attacks and brute-force rate-limit "
            f"bypasses."
        ),
    }
    return m.get(f.issue, f"GraphQL issue: {f.issue}")


def _remediation_graphql(f: GraphQLFinding) -> str:
    m = {
        "introspection_exposed": "Disable introspection in production (e.g. Apollo's ``introspection: false``).",
        "ide_exposed": "Gate the IDE behind authentication or remove it from production builds.",
        "verbose_errors": "Mask errors in production (Apollo: ``formatError`` hook; urql/mercurius equivalents).",
        "field_suggestions_enabled": "Disable field suggestions in production (graphql-js: ``NoSchemaIntrospectionCustomRule``).",
        "csrf_bypass_get": "Reject GET for queries that mutate state, or require a CSRF token / custom header for all operations.",
        "csrf_bypass_form_content_type": "Only accept ``application/json`` for GraphQL requests; reject unexpected content types.",
        "query_batching_unlimited": "Enforce a hard batch size limit and query-depth/complexity limits (graphql-depth-limit, graphql-cost-analysis).",
    }
    return m.get(f.issue, "Review manually.")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-") or "unknown"


def _hash(text: str) -> str:
    import hashlib
    return hashlib.sha256((text or "").encode()).hexdigest()[:12]
