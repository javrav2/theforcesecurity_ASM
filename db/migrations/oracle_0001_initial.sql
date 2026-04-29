-- Aegis Oracle initial schema (v1).
--
-- Designed for Postgres 15+. Apply with `psql -f` or via the migration
-- runner once the daemon is in place. See pkg/schema/* for the matching
-- Go types — table column names mirror the JSON tags where practical.

BEGIN;

-- ──────────────────────────────────────────────────────────────────────
-- Raw ingest tables — one per source, lossless. Authoritative records
-- can always be rebuilt from these even if the canonical merge fails.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS raw_cvelistv5 (
    cve_id     text        NOT NULL,
    fetched_at timestamptz NOT NULL DEFAULT now(),
    payload    jsonb       NOT NULL,
    PRIMARY KEY (cve_id, fetched_at)
);

CREATE TABLE IF NOT EXISTS raw_nvd (
    cve_id     text        NOT NULL,
    fetched_at timestamptz NOT NULL DEFAULT now(),
    payload    jsonb       NOT NULL,
    PRIMARY KEY (cve_id, fetched_at)
);

CREATE TABLE IF NOT EXISTS raw_osv (
    osv_id     text        NOT NULL,
    cve_id     text,
    fetched_at timestamptz NOT NULL DEFAULT now(),
    payload    jsonb       NOT NULL,
    PRIMARY KEY (osv_id, fetched_at)
);
CREATE INDEX IF NOT EXISTS raw_osv_cve_idx ON raw_osv (cve_id) WHERE cve_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS raw_epss (
    cve_id     text         NOT NULL,
    scored_on  date         NOT NULL,
    score      numeric(5,4) NOT NULL,
    percentile numeric(5,4) NOT NULL,
    PRIMARY KEY (cve_id, scored_on)
);

CREATE TABLE IF NOT EXISTS raw_kev (
    cve_id           text PRIMARY KEY,
    added_on         date NOT NULL,
    vendor           text,
    product          text,
    required_action  text,
    ransomware_use   boolean,
    fetched_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS raw_pocs (
    cve_id     text        NOT NULL,
    source     text        NOT NULL,           -- 'github' | 'exploitdb' | 'metasploit' | 'trickest' | 'vulncheck'
    url        text        NOT NULL,
    title      text,
    stars      int,
    pushed_at  timestamptz,
    fetched_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cve_id, source, url)
);

CREATE TABLE IF NOT EXISTS raw_hackerone_reports (
    report_id    text PRIMARY KEY,
    cve_id       text,
    url          text NOT NULL,
    title        text,
    cvss_vector  text,
    cvss_score   numeric(3,1),
    severity     text,
    reporter     text,
    team         text,
    disclosed_at timestamptz,
    body_text    text,
    fetched_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS raw_hackerone_cve_idx ON raw_hackerone_reports (cve_id) WHERE cve_id IS NOT NULL;

-- ──────────────────────────────────────────────────────────────────────
-- Canonical CVE table — merged view, refreshed by ingest workers.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cves (
    cve_id               text PRIMARY KEY,
    published_at         timestamptz NOT NULL,
    modified_at          timestamptz NOT NULL,
    description          text NOT NULL,
    cwes                 text[] NOT NULL DEFAULT '{}',
    cpes                 jsonb NOT NULL DEFAULT '[]'::jsonb,
    cvss_vectors         jsonb NOT NULL DEFAULT '[]'::jsonb,
    reference_urls       text[] NOT NULL DEFAULT '{}',
    epss_score           numeric(5,4),
    epss_percentile      numeric(5,4),
    in_kev               boolean NOT NULL DEFAULT false,
    kev_added_on         date,
    nuclei_template      text,
    poc_count            int NOT NULL DEFAULT 0,
    primary_source       text NOT NULL DEFAULT 'cve.org',
    adp_enrichment       jsonb,
    ghsa_id              text,
    osv_ids              text[] NOT NULL DEFAULT '{}',
    source_versions      jsonb NOT NULL DEFAULT '{}'::jsonb,
    intrinsic_input_hash text,
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cves_modified_at_idx ON cves (modified_at DESC);
CREATE INDEX IF NOT EXISTS cves_kev_idx         ON cves (in_kev) WHERE in_kev;
CREATE INDEX IF NOT EXISTS cves_epss_high_idx   ON cves (epss_score DESC) WHERE epss_score > 0.5;
CREATE INDEX IF NOT EXISTS cves_cpes_gin        ON cves USING gin (cpes jsonb_path_ops);
CREATE INDEX IF NOT EXISTS cves_cwes_gin        ON cves USING gin (cwes);

-- ──────────────────────────────────────────────────────────────────────
-- Reference content cache — fetched HTML/text used by Phase A.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS reference_content (
    url           text PRIMARY KEY,
    cve_ids       text[] NOT NULL,
    source_kind   text NOT NULL,
    content_text  text,
    content_hash  text NOT NULL,
    http_status   int,
    fetched_at    timestamptz NOT NULL DEFAULT now(),
    fetch_error   text
);

CREATE INDEX IF NOT EXISTS reference_content_cves_gin ON reference_content USING gin (cve_ids);

-- ──────────────────────────────────────────────────────────────────────
-- Exploitation observations — KEV-class evidence aggregated across sources.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS exploitation_observations (
    cve_id        text NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    source        text NOT NULL,             -- 'cisa_kev' | 'vulncheck_kev' | 'inthewild' | 'github_threat'
    first_seen_at timestamptz NOT NULL,
    evidence_url  text,
    notes         text,
    PRIMARY KEY (cve_id, source)
);

-- ──────────────────────────────────────────────────────────────────────
-- Phase A intrinsic analyses — LLM output, content-addressed by inputs.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cve_intrinsic_analyses (
    cve_id                text NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    input_hash            text NOT NULL,
    prompt_version        text NOT NULL,
    llm_provider          text NOT NULL,
    llm_model             text NOT NULL,

    remote_triggerability text NOT NULL CHECK (remote_triggerability IN ('yes','no','conditional')),
    exploit_complexity    text NOT NULL CHECK (exploit_complexity IN ('low','medium','high')),
    attacker_capability   text NOT NULL,
    preconditions         jsonb NOT NULL,
    cvss_reconciliation   jsonb NOT NULL,
    attack_chain_summary  text NOT NULL,
    detection_signals     jsonb NOT NULL DEFAULT '[]'::jsonb,
    rationale             text NOT NULL,
    confidence            text NOT NULL CHECK (confidence IN ('high','medium','low')),

    token_usage           jsonb,
    cost_usd              numeric(8,4),
    created_at            timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (cve_id, input_hash, prompt_version)
);

CREATE INDEX IF NOT EXISTS cve_intrinsic_latest_idx
    ON cve_intrinsic_analyses (cve_id, created_at DESC);

-- ──────────────────────────────────────────────────────────────────────
-- Knowledge base — derived state for git-authored YAMLs in /knowledgebase.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cwe_profiles (
    cwe_id             text PRIMARY KEY,
    name               text NOT NULL,
    abstraction        text NOT NULL,
    parent_cwes        text[] NOT NULL DEFAULT '{}',
    exploit_archetypes jsonb NOT NULL DEFAULT '[]'::jsonb,
    ecosystem_notes    jsonb NOT NULL DEFAULT '{}'::jsonb,
    framework_notes    jsonb NOT NULL DEFAULT '{}'::jsonb,
    detection_signals  jsonb NOT NULL DEFAULT '[]'::jsonb,
    curator_notes      text,
    source_refs        text[] NOT NULL DEFAULT '{}',
    last_reviewed_at   timestamptz,
    reviewed_by        text,
    yaml_hash          text NOT NULL,        -- sha256 of source YAML; drives reload
    loaded_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS dev_patterns (
    pattern_id            text PRIMARY KEY,
    cwe_ids               text[] NOT NULL,
    ecosystem             text NOT NULL,
    framework             text,
    library               text,
    pattern_name          text NOT NULL,
    summary               text NOT NULL,
    exploit_preconditions jsonb NOT NULL,
    code_indicators       text[] NOT NULL DEFAULT '{}',
    config_indicators     text[] NOT NULL DEFAULT '{}',
    runtime_indicators    text[] NOT NULL DEFAULT '{}',
    attacker_capability   text NOT NULL,
    remote_triggerability text NOT NULL,
    vulnerable_example    text,
    secure_example        text,
    remediation_summary   text NOT NULL,
    references_           text[] NOT NULL DEFAULT '{}',
    related_cves          text[] NOT NULL DEFAULT '{}',
    curator               text NOT NULL,
    reviewed_at           timestamptz NOT NULL,
    yaml_hash             text NOT NULL,
    loaded_at             timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS dev_patterns_cwe_gin ON dev_patterns USING gin (cwe_ids);
CREATE INDEX IF NOT EXISTS dev_patterns_eco_idx ON dev_patterns (ecosystem, framework);

-- ──────────────────────────────────────────────────────────────────────
-- Assets — populated by the inventory adapter. The bot is read-only here
-- in its own data; writes go through the adapter back to the host ASM.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS assets (
    asset_id     text PRIMARY KEY,
    tenant_id    text,
    hostname     text,
    ip           inet,
    open_ports   int[] NOT NULL DEFAULT '{}',
    signals      jsonb NOT NULL DEFAULT '{}'::jsonb,
    signals_hash text NOT NULL,
    criticality  text NOT NULL DEFAULT 'unknown',
    exposure     text NOT NULL DEFAULT 'unknown',
    source       text NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS assets_signals_gin ON assets USING gin (signals jsonb_path_ops);

-- ──────────────────────────────────────────────────────────────────────
-- Findings — Phase B output, one per (cve, asset). OPES score lives here.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS findings (
    finding_id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id                  text NOT NULL REFERENCES cves(cve_id),
    asset_id                text NOT NULL REFERENCES assets(asset_id),

    intrinsic_input_hash    text NOT NULL,
    asset_signals_hash      text NOT NULL,
    evaluator_version       text NOT NULL,

    preconditions_evaluated jsonb NOT NULL,

    opes_score              numeric(3,1) NOT NULL,
    opes_category           text NOT NULL CHECK (opes_category IN ('P0','P1','P2','P3','P4')),
    opes_label              text NOT NULL,
    opes_components         jsonb NOT NULL,
    opes_top_contributors   jsonb NOT NULL DEFAULT '[]'::jsonb,
    opes_dampener           text,
    opes_override           text,

    confidence              text NOT NULL CHECK (confidence IN ('high','medium','low')),
    priority_rationale      text NOT NULL,
    recommendation_text     text NOT NULL,

    status                  text NOT NULL DEFAULT 'open'
                            CHECK (status IN ('open','verifying','suppressed','fixed','superseded')),
    superseded_by           uuid REFERENCES findings(finding_id),
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),

    UNIQUE (cve_id, asset_id, intrinsic_input_hash, asset_signals_hash, evaluator_version)
);

CREATE INDEX IF NOT EXISTS findings_open_priority_idx
    ON findings (opes_category, created_at DESC) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS findings_asset_open_idx
    ON findings (asset_id) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS findings_cve_idx
    ON findings (cve_id);

-- ──────────────────────────────────────────────────────────────────────
-- Verification tasks — the close-the-loop work items.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS verification_tasks (
    task_id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id           uuid NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    precondition_id      text NOT NULL,
    task_kind            text NOT NULL,    -- 'container_inspect' | 'config_check' | 'nuclei_run' | 'manual'
    command              text,
    expected_signal_path text NOT NULL,
    expected_match       text,
    external_ref         text,             -- Linear/Jira issue ID once filed
    status               text NOT NULL DEFAULT 'open'
                         CHECK (status IN ('open','in_progress','resolved','wont_do')),
    resolution_notes     text,
    signal_value         text,
    created_at           timestamptz NOT NULL DEFAULT now(),
    resolved_at          timestamptz
);

CREATE INDEX IF NOT EXISTS verification_open_idx ON verification_tasks (status) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS verification_finding_idx ON verification_tasks (finding_id);

-- ──────────────────────────────────────────────────────────────────────
-- Module state — opaque key-value store for module bookkeeping (last-sync
-- timestamps etc.). Goes through the module.Store interface.
-- ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS module_state (
    module_name text NOT NULL,
    key         text NOT NULL,
    value       jsonb NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (module_name, key)
);

COMMIT;
