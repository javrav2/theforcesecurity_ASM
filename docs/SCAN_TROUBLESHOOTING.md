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

## 7. "No URLs discovered" (Katana / resource enumeration)

When the **resource enumeration** step (Katana crawler) finds no URLs on your targets, the scan can complete but with a message like:

- *"No URLs discovered (site may block automated crawlers, require auth, or return no links)"*

**Common causes:**

- **Bot protection** – Sites behind Cloudflare, Akamai, or similar may block default crawler requests.
- **Auth required** – Target returns a login page and no public links.
- **JS-heavy SPAs** – Content is rendered by JavaScript; default crawl may not execute it.
- **No links** – Page really has no crawlable links.

**What to do:**

1. **Re-run with headless crawl**  
   Create a new Full/Recon scan and pass **config** that enables headless mode so Katana uses a headless browser (better for JS and some bot protection):
   - In the API when creating the scan, set `config: { "headless": true }`.
   - If your UI supports scan config, enable "Headless crawl" or "Use headless browser for resource enumeration".

2. **Optional: browser-like User-Agent**  
   You can pass a custom User-Agent in config to reduce simple bot blocking:
   - `config: { "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" }`

3. **Run HTTP probe first**  
   The recon pipeline runs HTTP probe before Katana; ensure those targets are reachable and marked live. If you run only a "Resource enumeration" scan, run an HTTP probe scan first so targets are known to be live.

4. **Check the scan result hint**  
   For completed scans with no URLs, the scan `results.hint` field contains a short reminder about headless and User-Agent (see API response or scan detail page).

---

## 8. Parameter discovery (ParamSpider) returns 0 parameters / 0 URLs

When an ad hoc **Parameter Discovery (ParamSpider)** scan completes with **domains_scanned: 30** but **total_parameters: 0**, **total_urls: 0**, **total_endpoints: 0**, the scan *is* working—ParamSpider just found nothing in the archives.

**Why:**

- **ParamSpider** gets data from **web archives** (Wayback Machine, Common Crawl), not from live sites.
- If the 30 domains have little or no archived history, or the archives have no parameterized URLs for those domains, the result is zero.

**What to do:**

1. **Use Katana for live discovery**  
   Run a **Deep Web Crawling (Katana)** ad hoc scan on the same targets. Katana crawls live sites and discovers endpoints, parameters, and JS from the current pages. If you still get 0 URLs, see [§7 "No URLs discovered"](#7-no-urls-discovered-katana--resource-enumeration) (headless, User-Agent, HTTP probe).

2. **Run WaybackURLs first (optional)**  
   WaybackURLs pulls historical URLs from archives. Running it before ParamSpider doesn’t change ParamSpider’s archive backend, but it can help confirm whether archives have any data for your domains.

3. **Check the scan detail page**  
   For ParamSpider runs that return zero, the scan stores `results.error` and `results.hint`; the scan detail page shows these so you get an explanation and the suggestion to use Katana or WaybackURLs.

---

## 9. Code references

- Scan creation and SQS: `backend/app/api/routes/scans.py` (`send_scan_to_sqs`, scan create endpoints).
- Worker loop and DB poll: `backend/app/workers/scanner_worker.py` (`poll_for_jobs`, `poll_database_for_jobs`).
- Marking completed/failed: `scanner_worker.py` (`_mark_scan_running`, `_mark_scan_failed`, and each `handle_*`).
- Stale recovery: `scanner_worker.py` (`recover_stale_scans`, `_recover_stuck_scan_if_needed`).
- Katana (resource enumeration): `katana_service.py` (headless, user_agent); `scanner_worker.py` (`handle_katana_scan`, config `headless`, `user_agent`).
- ParamSpider (parameter discovery): `paramspider_service.py`; `scanner_worker.py` (`handle_paramspider_scan`); zero-result hint in `scan.results.error` / `scan.results.hint`.
