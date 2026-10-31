-- ================================================================
-- db_init.sql  —  vuln_intel PostgreSQL Schema
-- Run once: psql -U vuln_admin -d vuln_intel -f db_init.sql
-- ================================================================

-- Ensure pgcrypto is available for hashing / encryption helpers
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ----------------------------------------------------------------
-- 1. AUDIT LOG  — every significant user action is recorded here
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    username    TEXT        NOT NULL DEFAULT 'anonymous',
    action      TEXT        NOT NULL,              -- e.g. 'login', 'run_scan', 'exploit'
    module      TEXT,                              -- e.g. 'AggressiveMode', 'Pentest', 'Wargame'
    target      TEXT,                              -- IP / host / CVE affected
    detail      JSONB       DEFAULT '{}',          -- arbitrary extra context
    ip_address  TEXT,
    success     BOOLEAN     DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_audit_ts       ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log (username);
CREATE INDEX IF NOT EXISTS idx_audit_action   ON audit_log (action);

-- ----------------------------------------------------------------
-- 2. SCAN REPORTS  — raw JSON output from every scanner run
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_reports (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scanner     TEXT        NOT NULL,              -- 'nmap','nuclei','zap','aegisprobe'
    target      TEXT        NOT NULL,              -- IP or URL
    findings    INT         DEFAULT 0,
    raw_json    JSONB       DEFAULT '{}',          -- full parsed output
    summary     TEXT,
    ingested    BOOLEAN     DEFAULT FALSE          -- TRUE once sent to Neo4j
);
CREATE INDEX IF NOT EXISTS idx_sr_scanner ON scan_reports (scanner);
CREATE INDEX IF NOT EXISTS idx_sr_target  ON scan_reports (target);
CREATE INDEX IF NOT EXISTS idx_sr_ts      ON scan_reports (ts DESC);

-- ----------------------------------------------------------------
-- 3. EXPLOIT LOG  — Aggressive Mode execution records
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS exploit_log (
    id             BIGSERIAL PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    asset_ip       TEXT        NOT NULL,
    vuln_name      TEXT,
    cve_id         TEXT,
    searchsploit   JSONB       DEFAULT '[]',
    github_pocs    JSONB       DEFAULT '[]',
    execution      JSONB       DEFAULT '{}',
    metasploit     JSONB       DEFAULT '{}',
    success        BOOLEAN     DEFAULT FALSE,
    log_file       TEXT
);
CREATE INDEX IF NOT EXISTS idx_el_asset ON exploit_log (asset_ip);
CREATE INDEX IF NOT EXISTS idx_el_cve   ON exploit_log (cve_id);
CREATE INDEX IF NOT EXISTS idx_el_ts    ON exploit_log (ts DESC);

-- ----------------------------------------------------------------
-- 4. CVE CACHE  — cached EPSS / KEV / NVD lookups
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id      TEXT        PRIMARY KEY,
    epss_score  FLOAT,
    epss_pct    FLOAT,
    in_kev      BOOLEAN     DEFAULT FALSE,
    kev_date    DATE,
    cvss_score  FLOAT,
    cvss_vector TEXT,
    description TEXT,
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_cc_kev  ON cve_cache (in_kev);
CREATE INDEX IF NOT EXISTS idx_cc_epss ON cve_cache (epss_score DESC);

-- ----------------------------------------------------------------
-- 5. USER SESSIONS  — auth session tracking
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id  TEXT        PRIMARY KEY,
    username    TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address  TEXT,
    user_agent  TEXT,
    active      BOOLEAN     DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_us_username ON user_sessions (username);
CREATE INDEX IF NOT EXISTS idx_us_active   ON user_sessions (active, last_seen DESC);

-- ----------------------------------------------------------------
-- Confirm
-- ----------------------------------------------------------------
DO $$
BEGIN
    RAISE NOTICE 'vuln_intel schema initialised successfully.';
END
$$;
