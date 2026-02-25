# How scans run and where results go

This doc explains how to **see what the application is running** (e.g. Katana, Nuclei) and how **results are parsed and attached to the right assets**, which can differ from running the same tools manually.

---

## 1. Where to see what is being run

### Scanner worker logs (recommended)

The **scanner worker** is what actually runs Katana, Nuclei, port scans, etc. Its logs show the exact step and, for Katana, the **equivalent command**:

```bash
# Docker Compose
docker compose logs -f scanner

# Or for a specific scan (grep by scan_id)
docker compose logs scanner 2>&1 | grep -E "scan_id=181|Katana|Running Katana"
```

You’ll see lines like:

- `Processing job ... type=RECON_PIPELINE, scan_id=181`
- `Running Katana on 20 targets with depth=5 (batch stdin (one process), timeout=1800s)`
- `Katana batch command: /usr/local/bin/katana -silent -nc -d 5 -rl 150 -c 10 ... (stdin with 20 URLs, timeout=1800s)`

So you can compare with your manual run (e.g. `katana -u rok_js_test.txt -d 5 -jc -fx ...`).

### Scan record in the UI/API

- **Current step:** While a scan is running, `scan.current_step` is updated (e.g. `"Deep crawling with Katana"`, `"Deep crawling 20 targets (batch)"`). The scan detail page and API show this.
- **Results:** When the scan completes, `scan.results` holds a summary (e.g. `targets_crawled`, `total_urls`, `total_endpoints`, `total_js_files`, `error`, `hint`). Same data is visible on the scan detail page and via the scans API.

### Code locations

| What you want to see | Where it’s implemented |
|----------------------|-------------------------|
| Which step is running | `scanner_worker.py`: `scan.current_step = "..."` before each phase |
| Exact Katana command (single URL) | `katana_service.py`: `crawl()` → `logger.info("Katana command: ...")` |
| Exact Katana command (batch stdin) | `katana_service.py`: `crawl_batch_stdin()` → `logger.info("Katana batch command: ...")` |
| Scan summary when done | `scanner_worker.py`: `scan.results = { ... }` in each `handle_*` |

---

## 2. How the app runs Katana vs manual CLI

### Manual (your working example)

- You run: `katana -u rok_js_test.txt -d 5 -jc -fx -ef woff,css,... -o live_rok_js_test.txt`
- One process, many URLs from a file, output to a file.

### In the application

- **Multiple targets:** The app uses **batch stdin mode** by default: one Katana process, all target URLs sent on **stdin** (same idea as a file of URLs). Command shape: `katana -silent -nc -d 5 -jc -fx -ef ...` with stdin = one URL per line. So the “input” is equivalent to your `rok_js_test.txt`; the “output” is not a file but **stdout**, which the app reads and parses.
- **Single target:** One process per URL: `katana -u <single_url> -d 5 -jc -fx ...`, again with stdout captured and parsed.

So the main differences from manual are:

1. **Input:** File path (`-u file.txt`) vs stdin (URLs piped in).
2. **Output:** File (`-o out.txt`) vs stdout (captured in memory and parsed).
3. **Parsing:** The app reads stdout line-by-line and builds structured data (URLs, endpoints, params, JS files, API-like paths) instead of writing raw lines to a file.

---

## 3. Parsing and attribution: how data gets onto the right assets

After Katana (or another tool) runs, the worker:

1. **Parses** the tool’s stdout (or result object).
2. **Groups** discovered items by **host** (domain/hostname from the URL).
3. **Finds** the matching **asset** in the DB (same `organization_id`, `value` = host).
4. **Updates** that asset’s fields and metadata.

So “correct asset” = asset whose `value` equals the URL’s hostname (e.g. `status.cloud.rockwellautomation.com`).

### Katana: what gets parsed from stdout

- Each line of stdout that starts with `http` is treated as a URL.
- For each URL the app derives:
  - **Endpoint:** path (e.g. `/api/login`, `/static/.../js/main.js`).
  - **Parameters:** query parameter names.
  - **JS files:** path ends with `.js` or contains `/js/`.
  - **API-like URLs:** path matches patterns like `/api/`, `/vN/`, `/graphql`, `/rest/`.

These are stored in the `KatanaResult` (e.g. `result.urls`, `result.endpoints`, `result.parameters`, `result.js_files`, `result.api_endpoints`).

### Katana: how results are attributed to assets

**Per-target mode** (one URL per run):

- There is one `KatanaResult` per target URL.
- The “target” is a single base URL; the asset is looked up by **hostname** of that URL.
- That asset gets: `endpoints`, `parameters`, `js_files`, `metadata_['katana_last_scan']`, `metadata_['katana_urls_found']`, `metadata_['katana_api_endpoints']`.

**Batch stdin mode** (one run, many URLs):

- There is a **single** `KatanaResult` with all discovered URLs.
- The worker groups these URLs **by host** (e.g. `status.cloud.rockwellautomation.com`, `flourish.rockwellautomation.com`).
- For each host it finds the asset with `Asset.value == host` and assigns:
  - **endpoints** – paths from URLs on that host
  - **parameters** – query param names from URLs on that host
  - **js_files** – JS URLs on that host
  - **metadata_: katana_last_scan, katana_urls_found, katana_api_endpoints**

So even though Katana runs once for all targets, the app **splits the combined output by host** and writes to the correct asset per host.

### Where this lives in code

| Step | File | What it does |
|------|------|---------------|
| Run Katana (single or batch) | `backend/app/services/katana_service.py` | Builds CLI args, runs subprocess, reads stdout |
| Parse stdout into URLs/endpoints/params/js | `katana_service.py` | Line-by-line parse, urlparse, pattern checks |
| Per-target: assign one result to one asset | `scanner_worker.py` → `handle_katana_scan` | Match asset by `result.target` hostname |
| Batch: group by host, assign to many assets | `scanner_worker.py` → `handle_katana_scan` | `by_host[host]` then lookup `Asset.value == host` |
| Write to DB | `scanner_worker.py` | `asset.endpoints`, `asset.parameters`, `asset.js_files`, `asset.metadata_`, `db.commit()` |

---

## 4. Quick checklist: “Why don’t I see data on my asset?”

1. **Scanner logs** – Do you see `Katana command:` or `Katana batch command:` and did the run finish without timeout/error?
2. **Scan results** – Does `scan.results` show `total_urls` / `total_endpoints` > 0? If zero, the crawl didn’t return URLs (or parsing didn’t match).
3. **Asset match** – Asset must exist with `value` = **exact hostname** (e.g. `status.cloud.rockwellautomation.com`). If the scan used a different form (e.g. with/without `www`), the host derived from the URL might not match `Asset.value`.
4. **Organization** – Asset must be in the same `organization_id` as the scan.

---

## 5. Summary

- **See what’s run:** Scanner worker logs (`docker compose logs -f scanner`) and `scan.current_step` / `scan.results` in the UI or API.
- **How it’s implemented:** Katana is run with the same flags as your manual run (e.g. `-d 5 -jc -fx -ef ...`), but input is stdin (or one `-u` URL) and output is stdout, which the app parses.
- **Correct assets:** Parsed URLs are grouped by hostname; each host is matched to an asset with `Asset.value == host`, and that asset gets endpoints, parameters, js_files, and Katana metadata.
