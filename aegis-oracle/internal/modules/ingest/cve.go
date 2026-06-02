// Package ingest fetches canonical CVE records from upstream sources and
// normalises them into schema.CVE so the rest of the daemon can treat the
// store as the source of truth.
//
// We do not run the full multi-source merge pipeline that the standalone
// Oracle ingester does (cvelistV5 + NVD + OSV + GHSA + KEV + EPSS); that
// requires nightly bulk feeds. Instead, on-demand ingestion uses two
// real-time HTTP sources in order:
//
//  1. ProjectDiscovery vulnx — single-call CVE intelligence with merged
//     CVSS vectors, EPSS, KEV flags, references, and CPEs.
//  2. NVD 2.0 — fallback for CVEs not yet in vulnx (very new IDs).
//
// The result is good enough for the LLM Phase A analysis. The nightly
// merge pipeline overwrites these rows when it catches up.
package ingest
