"""
Reactivation service: handles reactivating closed findings on redetection
and syncing their linked Jira tickets.

When a scanner reports a finding that already exists in the platform in a closed
state (resolved / accepted / false_positive / mitigated), we reactivate the
existing record instead of creating a duplicate. If that record has a linked
Jira ticket we also reopen the ticket via the configured close→open transitions.
"""
import asyncio
import logging
import threading
from datetime import datetime

from app.models.vulnerability import Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

CLOSED_STATUSES: frozenset = frozenset({
    VulnerabilityStatus.RESOLVED,
    VulnerabilityStatus.ACCEPTED,
    VulnerabilityStatus.FALSE_POSITIVE,
    VulnerabilityStatus.MITIGATED,
})


def reactivate_if_closed(vuln: Vulnerability) -> bool:
    """
    Reactivate a closed vulnerability in-place.

    Sets status to OPEN, clears resolved_at, and updates last_detected.
    Returns True if the record was actually reactivated; False if it was
    already OPEN or IN_PROGRESS (no changes made in that case).

    The caller is responsible for flushing/committing the session.
    """
    if vuln.status not in CLOSED_STATUSES:
        return False

    logger.info(
        "Reactivating closed vulnerability id=%s '%s' (was: %s) — scanner redetection",
        vuln.id,
        vuln.title,
        vuln.status.value,
    )
    vuln.status = VulnerabilityStatus.OPEN
    vuln.resolved_at = None
    vuln.last_detected = datetime.utcnow()
    return True


def trigger_jira_reopen_background(vuln_id: int, old_status: str) -> None:
    """
    Spawn a daemon thread that opens its own DB session, locates all active
    Jira tickets linked to *vuln_id*, and executes the configured
    close→open transition chain on each.

    Safe to call immediately after the caller's session has been committed.
    """
    t = threading.Thread(
        target=_jira_reopen_worker,
        args=(vuln_id, old_status),
        daemon=True,
        name=f"jira-reopen-{vuln_id}",
    )
    t.start()
    logger.debug("Spawned Jira reopen background thread for vuln_id=%s", vuln_id)


# ---------------------------------------------------------------------------
# Internal worker
# ---------------------------------------------------------------------------

def _jira_reopen_worker(vuln_id: int, old_status: str) -> None:
    """
    Self-contained worker: opens its own DB session, fetches the Jira
    integration + linked tickets, and fires the reopen sync for each ticket.
    """
    try:
        from app.db.database import SessionLocal
        from app.models.jira_integration import JiraIntegration, JiraTicket
        from app.models.vulnerability import Vulnerability as _Vuln
        from app.services.jira_service import sync_ticket_for_status_change

        db = SessionLocal()
        try:
            vuln = db.query(_Vuln).filter(_Vuln.id == vuln_id).first()
            if not vuln or not vuln.asset:
                logger.debug(
                    "Jira reopen skipped: vuln %s not found or has no asset", vuln_id
                )
                return

            org_id = vuln.asset.organization_id
            integration = (
                db.query(JiraIntegration)
                .filter(
                    JiraIntegration.organization_id == org_id,
                    JiraIntegration.is_active == True,
                )
                .first()
            )
            if not integration:
                logger.debug(
                    "Jira reopen skipped: no active integration for org %s", org_id
                )
                return

            if not integration.close_to_open_transitions:
                logger.debug(
                    "Jira reopen skipped: no close→open transitions configured for org %s",
                    org_id,
                )
                return

            tickets = (
                db.query(JiraTicket)
                .filter(
                    JiraTicket.vulnerability_id == vuln_id,
                    JiraTicket.integration_id == integration.id,
                    JiraTicket.disconnected_at.is_(None),
                )
                .all()
            )

            if not tickets:
                logger.debug(
                    "Jira reopen skipped: no linked tickets for vuln %s", vuln_id
                )
                return

            for ticket in tickets:
                try:
                    asyncio.run(
                        sync_ticket_for_status_change(
                            integration,
                            ticket,
                            old_status,
                            "open",
                            "scanner:redetection",
                        )
                    )
                    logger.info(
                        "Jira reopen sync completed for ticket %s (vuln %s)",
                        ticket.jira_issue_key,
                        vuln_id,
                    )
                except Exception:
                    logger.exception(
                        "Jira reopen sync failed for ticket %s (vuln %s)",
                        ticket.jira_issue_key,
                        vuln_id,
                    )
        finally:
            db.close()

    except Exception:
        logger.exception(
            "Jira reopen background worker error for vuln_id=%s", vuln_id
        )
