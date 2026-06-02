#!/usr/bin/env bash
# =============================================================================
# Patch Tuesday → Oracle report
# =============================================================================
# Runs each CVE on stdin (or the defaults below) through the Aegis Oracle
# Phase-A endpoint (GET /cve/{id}) and produces:
#
#   reports/<run-date>/<CVE>.json    — full Oracle response
#   reports/<run-date>/summary.md    — comparative markdown table + per-CVE briefings
#
# Usage:
#   ./scripts/patch-tuesday-analysis.sh                       # uses built-in May-2026 Critical list
#   ./scripts/patch-tuesday-analysis.sh CVE-2026-1 CVE-2026-2 # explicit list
#   echo "CVE-2026-40365" | ./scripts/patch-tuesday-analysis.sh -    # stdin
#
# Requires: jq, curl. Oracle daemon must be reachable at $ORACLE_URL (default
# http://localhost:8742 — that's the port exposed by docker-compose.yml).
# We bypass the ASM backend's auth proxy and hit the daemon directly because
# this is a local analyst workflow; for a multi-user setup swap the URL for
# https://<host>/api/v1/oracle/cve/<id> and add a bearer token.
# =============================================================================
set -euo pipefail

ORACLE_URL="${ORACLE_URL:-http://localhost:8742}"
RUN_LABEL="${RUN_LABEL:-$(date +%Y-%m)-msft-patch-tuesday}"
OUT_DIR="${OUT_DIR:-reports/${RUN_LABEL}}"

# ── Default CVE list: the 16 Critical CVEs in Microsoft May-2026 PT ────────
DEFAULT_CVES=(
  # Internet-exposed servers
  CVE-2026-40365   # SharePoint Server RCE
  CVE-2026-42898   # Dynamics 365 On-Premises RCE
  CVE-2026-41103   # SSO Plugin for Jira & Confluence EoP

  # AD / network infrastructure
  CVE-2026-41089   # Netlogon RCE
  CVE-2026-41096   # Windows DNS Client RCE

  # Office preview-pane RCEs
  CVE-2026-42831   # Office RCE
  CVE-2026-40363   # Office RCE
  CVE-2026-40358   # Office RCE
  CVE-2026-40361   # Word RCE
  CVE-2026-40367   # Word RCE
  CVE-2026-40366   # Word RCE
  CVE-2026-40364   # Word RCE

  # File-handling RCEs
  CVE-2026-35421   # GDI RCE (EMF in Paint)
  CVE-2026-40403   # Graphics Component RCE

  # Hypervisor + driver
  CVE-2026-40402   # Hyper-V EoP
  CVE-2026-32161   # Native WiFi Miniport Driver RCE

  # AI / data
  CVE-2026-26164   # M365 Copilot InfoDisc
)

# ── Parse args ─────────────────────────────────────────────────────────────
CVES=()
if [[ $# -eq 0 ]]; then
  CVES=("${DEFAULT_CVES[@]}")
elif [[ $# -eq 1 && "$1" == "-" ]]; then
  # stdin mode — one CVE per line, blanks/comments ignored
  while read -r line; do
    line="${line%%#*}"; line="$(echo "$line" | xargs || true)"
    [[ -n "$line" ]] && CVES+=("$line")
  done
else
  CVES=("$@")
fi

mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.md"

echo "# Oracle analysis — ${RUN_LABEL}" >  "$SUMMARY"
echo "" >> "$SUMMARY"
echo "Run: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$SUMMARY"
echo "Oracle: \`${ORACLE_URL}\`" >> "$SUMMARY"
echo "CVEs analysed: ${#CVES[@]}" >> "$SUMMARY"
echo "" >> "$SUMMARY"

# ── Pre-flight: make sure Oracle is up ─────────────────────────────────────
if ! curl -fsS --max-time 5 "${ORACLE_URL}/health" > /dev/null; then
  echo "ERROR: Oracle daemon not reachable at ${ORACLE_URL}." >&2
  echo "       Start it with:  docker compose up -d aegis-oracle" >&2
  exit 1
fi

# ── Fetch each CVE ─────────────────────────────────────────────────────────
declare -a ROWS=()

for CVE in "${CVES[@]}"; do
  CVE="$(echo "$CVE" | tr '[:lower:]' '[:upper:]')"
  printf '  → %s ... ' "$CVE"
  OUT="$OUT_DIR/${CVE}.json"

  # First call may take 30-60s while Oracle auto-ingests from vulnx/NVD and
  # runs Phase A. Subsequent calls hit the cache (<1s).
  if ! curl -fsS --max-time 240 "${ORACLE_URL}/cve/${CVE}" -o "$OUT"; then
    printf 'FAILED\n'
    ROWS+=("| ${CVE} | _unavailable_ | _unavailable_ | _unavailable_ | _unavailable_ |")
    continue
  fi
  printf 'ok\n'

  TIER=$(jq -r '.analysis.analyst_brief.exploitability_tier // "unknown"' "$OUT")
  PATH_CLASS=$(jq -r '.analysis.attack_path_class // "unknown"' "$OUT")
  RT=$(jq -r '.analysis.remote_triggerability // "unknown"' "$OUT")
  COMPLEXITY=$(jq -r '.analysis.exploit_complexity // "unknown"' "$OUT")
  KEV=$(jq -r 'if .cve.in_kev then "KEV" else "" end' "$OUT")
  EPSS=$(jq -r '.cve.epss.score // 0 | (. * 100 | floor) / 100' "$OUT")

  ROWS+=("| \`${CVE}\` | **${TIER}** | ${PATH_CLASS} | RT:${RT} • Cx:${COMPLEXITY} | ${KEV:-—} • EPSS ${EPSS} |")
done

# ── Comparative table ──────────────────────────────────────────────────────
{
  echo "## Comparative ranking"
  echo ""
  echo "| CVE | Tier | Attack path | Intrinsic | Exploitation |"
  echo "| --- | --- | --- | --- | --- |"
  printf '%s\n' "${ROWS[@]}"
  echo ""
} >> "$SUMMARY"

# ── Per-CVE briefings ──────────────────────────────────────────────────────
{
  echo "## Per-CVE briefings"
  echo ""
} >> "$SUMMARY"

for CVE in "${CVES[@]}"; do
  CVE="$(echo "$CVE" | tr '[:lower:]' '[:upper:]')"
  OUT="$OUT_DIR/${CVE}.json"
  [[ -f "$OUT" ]] || continue

  {
    echo "### ${CVE}"
    echo ""
    jq -r '
      "**Description**: " + (.cve.description // "—") + "\n\n" +
      "**Attack vector summary**: " + (.analysis.analyst_brief.attack_vector_summary // "—") + "\n\n" +
      "**Affected if**: " + (.analysis.analyst_brief.affected_if // "—") + "\n\n" +
      "**Not affected if**: " + (.analysis.analyst_brief.not_affected_if // "—") + "\n\n" +
      "**Real-world likelihood**: " + (.analysis.analyst_brief.real_world_likelihood // "—") + "\n"
    ' "$OUT"
    echo ""
    echo "---"
    echo ""
  } >> "$SUMMARY"
done

echo ""
echo "Done."
echo "  Raw:     $OUT_DIR/*.json"
echo "  Summary: $SUMMARY"
