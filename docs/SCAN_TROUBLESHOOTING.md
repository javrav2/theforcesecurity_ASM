# Scan troubleshooting: scans not completing

If scans stay in **Pending** or **Running** and never reach **Completed**, use this guide.

## 1. Check scan status

- **Pending** → The scanner worker is not picking up the job (see [Worker not running](#2-worker-not-running) and [Queue/DB](#3-queue--database)).
- **Running** → The worker started the scan but either it’s still running (long pipeline) or the worker died before updating status (see [Stuck Running](#4-stuck-running)).

For a specific scan (e.g. `/scans/177`), note its **status** and **scan type** (Discovery, Vulnerability, Port scan, etc.).

---

## 2. Worker not running

Scans are processed by the **scanner worker** (`backend/app/workers/scanner_worker.py`). If that process isn’t running, scans stay **Pending**.

**Checks:**

- **Docker Compose:** Is the `scanner` (or `asm-scanner`) service running?
  - `docker compose ps` → scanner container should be `Up`.
- **ECS/Cloud:** Is the scanner task running and healthy?
- **Logs:** Scanner logs show polling and job processing, e.g.:
  - `Processing job ... type=..., scan_id=...`
  - `Scan 177 marked as RUNNING`
  - `Scan 177 marked COMPLETED` or `marked as FAILED`

If the scanner never logs receiving scan 177, it isn’t getting the job (see next section).

---

## 3. Queue & database

The worker gets jobs from:

1. **SQS** (if `SQS_QUEUE_URL` is set), or  
2. **Database** (polls `scans` where `status = 'pending'`).

**If you use SQS:**

- Backend must send the scan to SQS when the scan is created (`send_scan_to_sqs(scan)`).
- Worker must have `SQS_QUEUE_URL` and `AWS_REGION` (and credentials) so it can receive messages.
- If SQS is misconfigured or the message was never sent, the scan stays **Pending** in the DB and the worker (when it falls back to DB poll) will only see it if it’s actually polling the same DB.

**If you don’t use SQS:**

- Worker relies on **database polling**.
- Worker and API must use the **same database** (`DATABASE_URL`).
- Worker polls every `POLL_INTERVAL` seconds (default 20). Pending scans should be picked up within a couple of minutes.

**Quick check:** Call the queue status API (if you have it), e.g. `GET /api/v1/scans/queue/status`, and confirm pending count and that the worker can see the same pending scans.

---

## 4. Stuck “Running”

If a scan is **Running** for a long time with no progress:

1. **Worker crashed or was killed** mid-scan (e.g. OOM, deploy, scale-in). The scan was marked **Running** but never updated to **Completed** or **Failed**.

2. **Recovery behavior (built-in):**
   - **Stale scan recovery:** Every 5 minutes the worker looks for scans that have been **Running** for more than **60 minutes** and are not in its active set. Those are reset to **Pending** and retried (up to 3 times).
   - **Skip recovery:** If the worker receives a job for a scan that is already **Running** and that scan has been running for more than **10 minutes**, it resets that scan to **Pending** so the next poll can retry it.

3. **Manual retry:** Use the “Retry” action on the scan in the UI (e.g. `/scans/177`). That resets the scan to **Pending** and re-queues it (or leaves it for the next DB poll).

---

## 5. Failures and errors

If the scan ends in **Failed**, the worker sets `error_message` on the scan. Check:

- The scan detail page (e.g. `/scans/177`) for **Error message**.
- Scanner worker logs for the same scan ID and the exception (e.g. “Scan 177 handler failed: ...”).

Common causes:

- **No database connection** in the worker (`DATABASE_URL` wrong or DB unreachable).
- **Nuclei / port scan / discovery** tool error (timeout, no targets, permission, network).
- **Target list empty** (e.g. no assets for a port scan or discovery).

---

## 6. Checklist

| Check | What to verify |
|-------|----------------|
| Scanner worker running | Container/task is up; logs show polling and “Processing job”. |
| Same DB | Worker `DATABASE_URL` matches API so it sees the same `scans` rows. |
| SQS (if used) | `SQS_QUEUE_URL` set on API and worker; message sent on scan create; worker can receive. |
| Scan status | Pending → worker not getting job. Running → still running or worker died; wait for recovery or retry. |
| Error message | For **Failed** scans, read `error_message` and worker logs. |
| Retry | Use UI “Retry” for stuck/failed scans to re-queue. |

---

## 7. Code references

- Scan creation and SQS: `backend/app/api/routes/scans.py` (`send_scan_to_sqs`, scan create endpoints).
- Worker loop and DB poll: `backend/app/workers/scanner_worker.py` (`poll_for_jobs`, `poll_database_for_jobs`).
- Marking completed/failed: `scanner_worker.py` (`_mark_scan_running`, `_mark_scan_failed`, and each `handle_*`).
- Stale recovery: `scanner_worker.py` (`recover_stale_scans`, `_recover_stuck_scan_if_needed`).
