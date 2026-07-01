-- Migration 0002: add missing columns to cve_intrinsic_analyses and findings.
--
-- Root cause: the initial schema omitted several fields that the store
-- write-path expected and the frontend renders:
--
--   cve_intrinsic_analyses (all three were completely absent):
--     attack_path_class          → IntrinsicAnalysis.AttackPathClass
--     lateral_movement_potential → IntrinsicAnalysis.LateralMovementPotential
--     analyst_brief              → IntrinsicAnalysis.AnalystBrief (full JSON)
--
--   findings (cvss_reconciliation and analyst_brief were in UpsertFinding SQL
--     but never in the CREATE TABLE; attack_path_class and
--     lateral_movement_potential were never stored anywhere):
--     cvss_reconciliation        → Finding.CVSSReconciliation
--     analyst_brief              → Finding.AnalystBrief
--     attack_path_class          → Finding.AttackPathClass
--     lateral_movement_potential → Finding.LateralMovementPotential
--
-- Impact: on first LLM call all fields were populated in memory and returned
-- correctly. Every cached call (GetIntrinsicAnalysis / GetOpenFindings)
-- returned zero values for the missing fields, causing the UI to show only
-- CVSS + preconditions while hiding the analyst brief, attack path badge,
-- lateral movement badge, and exploitability index.

BEGIN;

-- ── cve_intrinsic_analyses ────────────────────────────────────────────────

ALTER TABLE cve_intrinsic_analyses
    ADD COLUMN IF NOT EXISTS attack_path_class          text,
    ADD COLUMN IF NOT EXISTS lateral_movement_potential text,
    ADD COLUMN IF NOT EXISTS analyst_brief              jsonb NOT NULL DEFAULT '{}'::jsonb;

-- ── findings ─────────────────────────────────────────────────────────────

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS cvss_reconciliation        jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS analyst_brief              jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS attack_path_class          text,
    ADD COLUMN IF NOT EXISTS lateral_movement_potential text;

COMMIT;
