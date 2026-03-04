"""
EvoGraph — Cross-Session Learning via Neo4j

Stores agent execution chains as a persistent graph so new sessions can
build on intelligence from prior sessions instead of starting from scratch.

Node types:
  - AgentChain       — root node for one conversation session
  - ChainStep        — single tool execution within a chain
  - ChainFinding     — important discovery (vulnerability, credential, etc.)
  - ChainFailure     — failed attempt with lesson learned

Relationships:
  - (AgentChain)-[:HAS_STEP]->(ChainStep)
  - (ChainStep)-[:NEXT_STEP]->(ChainStep)
  - (ChainStep)-[:PRODUCED]->(ChainFinding)
  - (ChainStep)-[:FAILED_WITH]->(ChainFailure)
  - (AgentChain)-[:TARGETS]->(Asset/IP/Domain)  — bridge to recon graph
"""

import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from app.core.config import settings

logger = logging.getLogger(__name__)

_driver = None


def _get_driver():
    """Lazy-init Neo4j driver, shared across calls."""
    global _driver
    if _driver is not None:
        return _driver
    try:
        from neo4j import GraphDatabase
        _driver = GraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
        )
        _driver.verify_connectivity()
        logger.info("EvoGraph: connected to Neo4j")
        return _driver
    except Exception as e:
        logger.warning(f"EvoGraph: Neo4j unavailable — cross-session learning disabled ({e})")
        return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Write helpers (fire-and-forget, never block the agent loop)
# ---------------------------------------------------------------------------

def record_chain_start(
    session_id: str,
    organization_id: int,
    user_id: str,
    objective: str,
    mode: str = "assist",
) -> None:
    """Create or update the root AgentChain node for this session."""
    driver = _get_driver()
    if not driver:
        return
    try:
        with driver.session() as s:
            s.run(
                """
                MERGE (c:AgentChain {session_id: $sid})
                ON CREATE SET
                    c.organization_id = $org,
                    c.user_id         = $uid,
                    c.objective        = $obj,
                    c.mode             = $mode,
                    c.status           = 'running',
                    c.started_at       = $ts,
                    c.step_count       = 0
                ON MATCH SET
                    c.objective = $obj,
                    c.status    = 'running'
                """,
                sid=session_id, org=organization_id, uid=user_id,
                obj=objective[:500], mode=mode, ts=_now_iso(),
            )
    except Exception as e:
        logger.debug(f"EvoGraph record_chain_start error: {e}")


def record_step(
    session_id: str,
    iteration: int,
    phase: str,
    tool_name: Optional[str],
    tool_args: Optional[Dict[str, Any]],
    tool_output_summary: Optional[str],
    success: Optional[bool],
    thought: str,
) -> None:
    """Record a ChainStep and link it to the chain."""
    driver = _get_driver()
    if not driver:
        return
    try:
        args_str = str(tool_args)[:500] if tool_args else ""
        output_str = (tool_output_summary or "")[:1000]
        with driver.session() as s:
            s.run(
                """
                MATCH (c:AgentChain {session_id: $sid})
                CREATE (step:ChainStep {
                    session_id: $sid,
                    iteration:  $iter,
                    phase:      $phase,
                    tool_name:  $tool,
                    tool_args:  $args,
                    output_summary: $output,
                    success:    $success,
                    thought:    $thought,
                    created_at: $ts
                })
                MERGE (c)-[:HAS_STEP]->(step)
                SET c.step_count = $iter
                WITH step
                OPTIONAL MATCH (prev:ChainStep {session_id: $sid, iteration: $prev_iter})
                WHERE prev IS NOT NULL
                MERGE (prev)-[:NEXT_STEP]->(step)
                """,
                sid=session_id, iter=iteration, phase=phase,
                tool=tool_name or "", args=args_str, output=output_str,
                success=success, thought=thought[:300], ts=_now_iso(),
                prev_iter=iteration - 1,
            )
    except Exception as e:
        logger.debug(f"EvoGraph record_step error: {e}")


def record_finding(
    session_id: str,
    iteration: int,
    finding_type: str,
    severity: str,
    description: str,
) -> None:
    """Record a ChainFinding linked to the step that produced it."""
    driver = _get_driver()
    if not driver:
        return
    try:
        with driver.session() as s:
            s.run(
                """
                MATCH (step:ChainStep {session_id: $sid, iteration: $iter})
                CREATE (f:ChainFinding {
                    session_id:   $sid,
                    finding_type: $ftype,
                    severity:     $sev,
                    description:  $desc,
                    created_at:   $ts
                })
                MERGE (step)-[:PRODUCED]->(f)
                """,
                sid=session_id, iter=iteration,
                ftype=finding_type, sev=severity,
                desc=description[:500], ts=_now_iso(),
            )
    except Exception as e:
        logger.debug(f"EvoGraph record_finding error: {e}")


def record_failure(
    session_id: str,
    iteration: int,
    tool_name: str,
    error: str,
    lesson: str,
) -> None:
    """Record a ChainFailure so future sessions know what didn't work."""
    driver = _get_driver()
    if not driver:
        return
    try:
        with driver.session() as s:
            s.run(
                """
                MATCH (step:ChainStep {session_id: $sid, iteration: $iter})
                CREATE (f:ChainFailure {
                    session_id: $sid,
                    tool_name:  $tool,
                    error:      $err,
                    lesson:     $lesson,
                    created_at: $ts
                })
                MERGE (step)-[:FAILED_WITH]->(f)
                """,
                sid=session_id, iter=iteration,
                tool=tool_name, err=error[:500],
                lesson=lesson[:500], ts=_now_iso(),
            )
    except Exception as e:
        logger.debug(f"EvoGraph record_failure error: {e}")


def record_chain_end(
    session_id: str,
    status: str = "completed",
    outcome: str = "",
    final_phase: str = "informational",
    iteration_count: int = 0,
) -> None:
    """Finalize the AgentChain node."""
    driver = _get_driver()
    if not driver:
        return
    try:
        with driver.session() as s:
            s.run(
                """
                MATCH (c:AgentChain {session_id: $sid})
                SET c.status          = $status,
                    c.outcome          = $outcome,
                    c.final_phase      = $phase,
                    c.iteration_count  = $iters,
                    c.ended_at         = $ts
                """,
                sid=session_id, status=status,
                outcome=outcome[:500], phase=final_phase,
                iters=iteration_count, ts=_now_iso(),
            )
    except Exception as e:
        logger.debug(f"EvoGraph record_chain_end error: {e}")


# ---------------------------------------------------------------------------
# Read helpers — cross-session context
# ---------------------------------------------------------------------------

def get_prior_chain_context(
    organization_id: int,
    current_session_id: str,
    max_chains: int = 5,
    max_findings: int = 15,
    max_failures: int = 10,
) -> str:
    """
    Load summaries from prior sessions for the same org.

    Returns a formatted string to inject into the agent's system prompt
    so it starts with accumulated intelligence rather than a blank slate.
    """
    driver = _get_driver()
    if not driver:
        return ""

    try:
        with driver.session() as s:
            # Recent chains
            chains = s.run(
                """
                MATCH (c:AgentChain {organization_id: $org})
                WHERE c.session_id <> $cur AND c.status IN ['completed', 'aborted']
                RETURN c.objective AS objective,
                       c.status AS status,
                       c.outcome AS outcome,
                       c.final_phase AS phase,
                       c.iteration_count AS iters,
                       c.started_at AS started
                ORDER BY c.started_at DESC
                LIMIT $limit
                """,
                org=organization_id, cur=current_session_id, limit=max_chains,
            ).data()

            # Key findings (critical + high)
            findings = s.run(
                """
                MATCH (c:AgentChain {organization_id: $org})-[:HAS_STEP]->()-[:PRODUCED]->(f:ChainFinding)
                WHERE c.session_id <> $cur
                  AND f.severity IN ['critical', 'high']
                RETURN f.finding_type AS type,
                       f.severity AS severity,
                       f.description AS description
                ORDER BY f.created_at DESC
                LIMIT $limit
                """,
                org=organization_id, cur=current_session_id, limit=max_findings,
            ).data()

            # Lessons learned from failures
            failures = s.run(
                """
                MATCH (c:AgentChain {organization_id: $org})-[:HAS_STEP]->()-[:FAILED_WITH]->(f:ChainFailure)
                WHERE c.session_id <> $cur AND f.lesson <> ''
                RETURN f.tool_name AS tool,
                       f.error AS error,
                       f.lesson AS lesson
                ORDER BY f.created_at DESC
                LIMIT $limit
                """,
                org=organization_id, cur=current_session_id, limit=max_failures,
            ).data()

        if not chains and not findings and not failures:
            return ""

        parts = ["## Prior Session Intelligence\n"]

        if chains:
            parts.append("### Recent Sessions")
            for c in chains:
                status_icon = "completed" if c["status"] == "completed" else "aborted"
                parts.append(
                    f"- [{status_icon}] {c.get('objective', '?')[:120]} "
                    f"(phase: {c.get('phase', '?')}, {c.get('iters', 0)} steps)"
                )
                if c.get("outcome"):
                    parts.append(f"  Outcome: {c['outcome'][:200]}")

        if findings:
            parts.append("\n### Key Findings from Prior Sessions")
            for f in findings:
                parts.append(f"- [{f['severity']}] {f['type']}: {f['description'][:200]}")

        if failures:
            parts.append("\n### Lessons Learned (avoid repeating)")
            for f in failures:
                parts.append(f"- {f['tool']}: {f.get('lesson', f.get('error', ''))[:200]}")

        return "\n".join(parts)

    except Exception as e:
        logger.debug(f"EvoGraph get_prior_chain_context error: {e}")
        return ""
