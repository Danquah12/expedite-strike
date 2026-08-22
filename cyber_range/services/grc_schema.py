# ================================================================
# grc_schema.py  —  Create GRC tables + seed NIST 800-53 Rev 5
#
# Usage:
#   python3 grc_schema.py            # runs migrations + seed
#   from cyber_range.services.grc_schema import init_grc_schema
#   init_grc_schema()                # called from app startup
# ================================================================

import logging
from cyber_range.services.pg_engine import pg_execute, get_pg, _PG_AVAILABLE

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────
# DDL — 11 GRC tables
# ──────────────────────────────────────────────────────────────────
GRC_DDL = """
-- 1. Organizations
CREATE TABLE IF NOT EXISTS organizations (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    acronym         TEXT,
    org_type        TEXT DEFAULT 'Federal',       -- Federal, DoD, Contractor, Commercial
    parent_org_id   INT REFERENCES organizations(id),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Users (GRC roles)
CREATE TABLE IF NOT EXISTS grc_users (
    id              SERIAL PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    full_name       TEXT,
    email           TEXT,
    role            TEXT DEFAULT 'Viewer',         -- Viewer, Assessor, ISSO, SystemOwner, Admin
    org_id          INT REFERENCES organizations(id),
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Systems (FISMA system boundaries)
CREATE TABLE IF NOT EXISTS systems (
    id              SERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    acronym         TEXT,
    description     TEXT,
    org_id          INT REFERENCES organizations(id),
    impact_level    TEXT DEFAULT 'Moderate',       -- Low, Moderate, High
    system_type     TEXT DEFAULT 'General Support System',
    status          TEXT DEFAULT 'Operational',    -- Development, Operational, Decommissioned
    ato_date        DATE,
    ato_expiry      DATE,
    isso_id         INT REFERENCES grc_users(id),
    owner_id        INT REFERENCES grc_users(id),
    data_types      TEXT[] DEFAULT '{}',           -- PII, PHI, CUI, FCI
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Controls (NIST 800-53 Rev 5 library)
CREATE TABLE IF NOT EXISTS controls (
    id              SERIAL PRIMARY KEY,
    control_id      TEXT NOT NULL UNIQUE,          -- e.g. AC-2, SI-2(3)
    family          TEXT NOT NULL,                 -- AC, AT, AU, ...
    family_name     TEXT NOT NULL,                 -- Access Control, ...
    title           TEXT NOT NULL,
    description     TEXT,
    priority        TEXT,                          -- P1, P2, P3
    baseline_low    BOOLEAN DEFAULT FALSE,
    baseline_mod    BOOLEAN DEFAULT FALSE,
    baseline_high   BOOLEAN DEFAULT FALSE,
    is_enhancement  BOOLEAN DEFAULT FALSE,
    parent_control  TEXT,                          -- parent for enhancements
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 5. System Controls (control implementation per system)
CREATE TABLE IF NOT EXISTS system_controls (
    id              SERIAL PRIMARY KEY,
    system_id       INT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    control_id      INT NOT NULL REFERENCES controls(id),
    status          TEXT DEFAULT 'Not Implemented', -- Implemented, Partially, Planned, Not Implemented, N/A
    implementation  TEXT,                           -- implementation narrative
    responsible     TEXT,
    assessed_date   DATE,
    assessed_by     TEXT,
    assessment_result TEXT DEFAULT 'Not Assessed', -- Satisfied, Other Than Satisfied, Not Assessed
    notes           TEXT,
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(system_id, control_id)
);

-- 6. Vulnerabilities (persistent vuln records)
CREATE TABLE IF NOT EXISTS grc_vulnerabilities (
    id              SERIAL PRIMARY KEY,
    vuln_id         TEXT NOT NULL,                 -- CVE-XXXX-XXXX or scanner ID
    system_id       INT REFERENCES systems(id),
    host            TEXT,
    service         TEXT,
    port            INT,
    cvss            NUMERIC(3,1),
    severity        TEXT,                          -- Critical, High, Medium, Low
    title           TEXT,
    description     TEXT,
    source          TEXT,                          -- Nmap, OpenVAS, Nessus, Qualys, etc.
    status          TEXT DEFAULT 'Open',           -- Open, Mitigated, Accepted, FalsePositive
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    neo4j_node_id   TEXT,                          -- link to Neo4j Vulnerability node
    UNIQUE(vuln_id, host, port)
);

-- 7. POA&M (Plan of Action & Milestones)
CREATE TABLE IF NOT EXISTS poam (
    id              SERIAL PRIMARY KEY,
    poam_id         TEXT NOT NULL UNIQUE,          -- POAM-001
    system_id       INT REFERENCES systems(id),
    weakness        TEXT NOT NULL,
    vuln_id         INT REFERENCES grc_vulnerabilities(id),
    control_id      INT REFERENCES controls(id),
    risk_level      TEXT DEFAULT 'Medium',         -- Critical, High, Medium, Low
    cvss            NUMERIC(3,1),
    status          TEXT DEFAULT 'Open',           -- Open, In Progress, Closed, Accepted
    remediation     TEXT,
    milestones      TEXT,
    due_date        DATE,
    completion_date DATE,
    responsible     TEXT,
    source          TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 8. Risks (risk register)
CREATE TABLE IF NOT EXISTS risks (
    id              SERIAL PRIMARY KEY,
    risk_id         TEXT NOT NULL UNIQUE,          -- RISK-001
    system_id       INT REFERENCES systems(id),
    title           TEXT NOT NULL,
    description     TEXT,
    category        TEXT,                          -- Technical, Operational, Strategic
    likelihood      INT CHECK (likelihood BETWEEN 1 AND 5),
    impact          INT CHECK (impact BETWEEN 1 AND 5),
    risk_score      INT GENERATED ALWAYS AS (likelihood * impact) STORED,
    risk_level      TEXT,                          -- Critical, High, Medium, Low
    status          TEXT DEFAULT 'Open',           -- Open, Mitigated, Accepted, Transferred
    mitigation      TEXT,
    owner           TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 9. Evidence (artifacts for control compliance)
CREATE TABLE IF NOT EXISTS evidence (
    id              SERIAL PRIMARY KEY,
    system_control_id INT REFERENCES system_controls(id) ON DELETE CASCADE,
    filename        TEXT NOT NULL,
    file_path       TEXT,
    file_type       TEXT,                          -- PDF, DOCX, PNG, XML, CSV
    description     TEXT,
    uploaded_by     TEXT,
    uploaded_at     TIMESTAMPTZ DEFAULT NOW()
);

-- 10. Assessments (assessment sessions)
CREATE TABLE IF NOT EXISTS assessments (
    id              SERIAL PRIMARY KEY,
    system_id       INT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    assessment_type TEXT DEFAULT 'Annual',         -- Annual, Continuous, Ad-Hoc, Initial
    assessor        TEXT,
    start_date      DATE,
    end_date        DATE,
    status          TEXT DEFAULT 'Planned',        -- Planned, In Progress, Complete
    findings_count  INT DEFAULT 0,
    score           NUMERIC(5,2),                  -- 0-100
    notes           TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 11. Compliance Scores (historical tracking)
CREATE TABLE IF NOT EXISTS compliance_scores (
    id              SERIAL PRIMARY KEY,
    system_id       INT NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
    framework       TEXT DEFAULT 'NIST 800-53',
    score           NUMERIC(5,2) NOT NULL,         -- 0-100
    controls_total  INT DEFAULT 0,
    controls_implemented INT DEFAULT 0,
    controls_partial INT DEFAULT 0,
    controls_planned INT DEFAULT 0,
    controls_na      INT DEFAULT 0,
    open_findings   INT DEFAULT 0,
    open_poams      INT DEFAULT 0,
    recorded_at     TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_sys_ctrl_system   ON system_controls(system_id);
CREATE INDEX IF NOT EXISTS idx_sys_ctrl_control  ON system_controls(control_id);
CREATE INDEX IF NOT EXISTS idx_poam_system       ON poam(system_id);
CREATE INDEX IF NOT EXISTS idx_poam_status       ON poam(status);
CREATE INDEX IF NOT EXISTS idx_vulns_system      ON grc_vulnerabilities(system_id);
CREATE INDEX IF NOT EXISTS idx_vulns_status      ON grc_vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_risks_system      ON risks(system_id);
CREATE INDEX IF NOT EXISTS idx_scores_system     ON compliance_scores(system_id);
CREATE INDEX IF NOT EXISTS idx_controls_family   ON controls(family);
"""


# ──────────────────────────────────────────────────────────────────
# NIST 800-53 Rev 5 Seed Data — 20 families, key controls
# ──────────────────────────────────────────────────────────────────
NIST_CONTROLS = [
    # (control_id, family, family_name, title, priority, baseline_low, baseline_mod, baseline_high, is_enhancement, parent)
    # ── AC: Access Control ─────────────────────────────────────────
    ("AC-1",  "AC", "Access Control",     "Policy and Procedures",                      "P1", True,  True,  True,  False, None),
    ("AC-2",  "AC", "Access Control",     "Account Management",                         "P1", True,  True,  True,  False, None),
    ("AC-2(1)","AC","Access Control",     "Automated System Account Management",        "P1", False, True,  True,  True,  "AC-2"),
    ("AC-2(3)","AC","Access Control",     "Disable Accounts",                           "P1", False, True,  True,  True,  "AC-2"),
    ("AC-3",  "AC", "Access Control",     "Access Enforcement",                         "P1", True,  True,  True,  False, None),
    ("AC-4",  "AC", "Access Control",     "Information Flow Enforcement",               "P1", False, True,  True,  False, None),
    ("AC-5",  "AC", "Access Control",     "Separation of Duties",                       "P1", False, True,  True,  False, None),
    ("AC-6",  "AC", "Access Control",     "Least Privilege",                            "P1", False, True,  True,  False, None),
    ("AC-6(1)","AC","Access Control",     "Authorize Access to Security Functions",     "P1", False, True,  True,  True,  "AC-6"),
    ("AC-7",  "AC", "Access Control",     "Unsuccessful Login Attempts",                "P1", True,  True,  True,  False, None),
    ("AC-8",  "AC", "Access Control",     "System Use Notification",                    "P1", True,  True,  True,  False, None),
    ("AC-11", "AC", "Access Control",     "Device Lock",                                "P2", False, True,  True,  False, None),
    ("AC-14", "AC", "Access Control",     "Permitted Actions Without Identification",   "P3", True,  True,  True,  False, None),
    ("AC-17", "AC", "Access Control",     "Remote Access",                              "P1", True,  True,  True,  False, None),
    ("AC-17(1)","AC","Access Control",    "Monitoring / Control",                       "P1", False, True,  True,  True,  "AC-17"),
    ("AC-18", "AC", "Access Control",     "Wireless Access",                            "P1", True,  True,  True,  False, None),
    ("AC-19", "AC", "Access Control",     "Access Control for Mobile Devices",          "P1", False, True,  True,  False, None),
    ("AC-20", "AC", "Access Control",     "Use of External Systems",                    "P1", True,  True,  True,  False, None),
    # ── AT: Awareness and Training ─────────────────────────────────
    ("AT-1",  "AT", "Awareness and Training","Policy and Procedures",                   "P1", True,  True,  True,  False, None),
    ("AT-2",  "AT", "Awareness and Training","Literacy Training and Awareness",         "P1", True,  True,  True,  False, None),
    ("AT-2(2)","AT","Awareness and Training","Insider Threat",                          "P2", False, True,  True,  True,  "AT-2"),
    ("AT-3",  "AT", "Awareness and Training","Role-Based Training",                     "P1", True,  True,  True,  False, None),
    ("AT-4",  "AT", "Awareness and Training","Training Records",                        "P3", True,  True,  True,  False, None),
    # ── AU: Audit and Accountability ───────────────────────────────
    ("AU-1",  "AU", "Audit and Accountability","Policy and Procedures",                 "P1", True,  True,  True,  False, None),
    ("AU-2",  "AU", "Audit and Accountability","Event Logging",                         "P1", True,  True,  True,  False, None),
    ("AU-3",  "AU", "Audit and Accountability","Content of Audit Records",              "P1", True,  True,  True,  False, None),
    ("AU-4",  "AU", "Audit and Accountability","Audit Log Storage Capacity",            "P1", True,  True,  True,  False, None),
    ("AU-5",  "AU", "Audit and Accountability","Response to Audit Logging Failures",    "P1", True,  True,  True,  False, None),
    ("AU-6",  "AU", "Audit and Accountability","Audit Record Review, Analysis, Reporting","P1",True, True,  True,  False, None),
    ("AU-6(1)","AU","Audit and Accountability","Automated Process Integration",         "P1", False, True,  True,  True,  "AU-6"),
    ("AU-8",  "AU", "Audit and Accountability","Time Stamps",                           "P1", True,  True,  True,  False, None),
    ("AU-9",  "AU", "Audit and Accountability","Protection of Audit Information",       "P1", True,  True,  True,  False, None),
    ("AU-11", "AU", "Audit and Accountability","Audit Record Retention",                "P3", True,  True,  True,  False, None),
    ("AU-12", "AU", "Audit and Accountability","Audit Record Generation",               "P1", True,  True,  True,  False, None),
    # ── CA: Assessment, Authorization, and Monitoring ──────────────
    ("CA-1",  "CA", "Assessment, Authorization, and Monitoring","Policy and Procedures","P1", True,  True,  True,  False, None),
    ("CA-2",  "CA", "Assessment, Authorization, and Monitoring","Control Assessments",  "P2", True,  True,  True,  False, None),
    ("CA-3",  "CA", "Assessment, Authorization, and Monitoring","Information Exchange", "P1", True,  True,  True,  False, None),
    ("CA-5",  "CA", "Assessment, Authorization, and Monitoring","Plan of Action and Milestones","P3",True,True,True,False,None),
    ("CA-6",  "CA", "Assessment, Authorization, and Monitoring","Authorization",        "P2", True,  True,  True,  False, None),
    ("CA-7",  "CA", "Assessment, Authorization, and Monitoring","Continuous Monitoring","P2", True,  True,  True,  False, None),
    ("CA-8",  "CA", "Assessment, Authorization, and Monitoring","Penetration Testing",  "P2", False, False, True,  False, None),
    # ── CM: Configuration Management ───────────────────────────────
    ("CM-1",  "CM", "Configuration Management","Policy and Procedures",                 "P1", True,  True,  True,  False, None),
    ("CM-2",  "CM", "Configuration Management","Baseline Configuration",                "P1", True,  True,  True,  False, None),
    ("CM-3",  "CM", "Configuration Management","Configuration Change Control",          "P1", False, True,  True,  False, None),
    ("CM-4",  "CM", "Configuration Management","Impact Analyses",                       "P2", False, True,  True,  False, None),
    ("CM-5",  "CM", "Configuration Management","Access Restrictions for Change",        "P1", False, True,  True,  False, None),
    ("CM-6",  "CM", "Configuration Management","Configuration Settings",                "P1", True,  True,  True,  False, None),
    ("CM-7",  "CM", "Configuration Management","Least Functionality",                   "P1", True,  True,  True,  False, None),
    ("CM-8",  "CM", "Configuration Management","System Component Inventory",            "P1", True,  True,  True,  False, None),
    # ── CP: Contingency Planning ───────────────────────────────────
    ("CP-1",  "CP", "Contingency Planning","Policy and Procedures",                     "P1", True,  True,  True,  False, None),
    ("CP-2",  "CP", "Contingency Planning","Contingency Plan",                          "P1", True,  True,  True,  False, None),
    ("CP-3",  "CP", "Contingency Planning","Contingency Training",                      "P2", True,  True,  True,  False, None),
    ("CP-4",  "CP", "Contingency Planning","Contingency Plan Testing",                  "P2", True,  True,  True,  False, None),
    ("CP-9",  "CP", "Contingency Planning","System Backup",                             "P1", True,  True,  True,  False, None),
    ("CP-10", "CP", "Contingency Planning","System Recovery and Reconstitution",        "P1", True,  True,  True,  False, None),
    # ── IA: Identification and Authentication ──────────────────────
    ("IA-1",  "IA", "Identification and Authentication","Policy and Procedures",        "P1", True,  True,  True,  False, None),
    ("IA-2",  "IA", "Identification and Authentication","Identification and Authentication (Organizational Users)","P1",True,True,True,False,None),
    ("IA-2(1)","IA","Identification and Authentication","Multi-Factor Authentication to Privileged Accounts","P1",False,True,True,True,"IA-2"),
    ("IA-2(2)","IA","Identification and Authentication","Multi-Factor Authentication to Non-Privileged Accounts","P1",False,True,True,True,"IA-2"),
    ("IA-4",  "IA", "Identification and Authentication","Identifier Management",        "P1", True,  True,  True,  False, None),
    ("IA-5",  "IA", "Identification and Authentication","Authenticator Management",     "P1", True,  True,  True,  False, None),
    ("IA-5(1)","IA","Identification and Authentication","Password-Based Authentication","P1", True,  True,  True,  True,  "IA-5"),
    ("IA-6",  "IA", "Identification and Authentication","Authentication Feedback",      "P2", True,  True,  True,  False, None),
    ("IA-7",  "IA", "Identification and Authentication","Cryptographic Module Authentication","P1",True,True,True,False,None),
    # ── IR: Incident Response ──────────────────────────────────────
    ("IR-1",  "IR", "Incident Response",   "Policy and Procedures",                     "P1", True,  True,  True,  False, None),
    ("IR-2",  "IR", "Incident Response",   "Incident Response Training",                "P2", True,  True,  True,  False, None),
    ("IR-4",  "IR", "Incident Response",   "Incident Handling",                         "P1", True,  True,  True,  False, None),
    ("IR-5",  "IR", "Incident Response",   "Incident Monitoring",                       "P1", True,  True,  True,  False, None),
    ("IR-6",  "IR", "Incident Response",   "Incident Reporting",                        "P1", True,  True,  True,  False, None),
    ("IR-7",  "IR", "Incident Response",   "Incident Response Assistance",              "P2", True,  True,  True,  False, None),
    ("IR-8",  "IR", "Incident Response",   "Incident Response Plan",                    "P1", True,  True,  True,  False, None),
    # ── MA: Maintenance ────────────────────────────────────────────
    ("MA-1",  "MA", "Maintenance",         "Policy and Procedures",                     "P1", True,  True,  True,  False, None),
    ("MA-2",  "MA", "Maintenance",         "Controlled Maintenance",                    "P2", True,  True,  True,  False, None),
    ("MA-4",  "MA", "Maintenance",         "Nonlocal Maintenance",                      "P2", True,  True,  True,  False, None),
    ("MA-5",  "MA", "Maintenance",         "Maintenance Personnel",                     "P2", True,  True,  True,  False, None),
    ("MA-6",  "MA", "Maintenance",         "Timely Maintenance",                        "P2", False, True,  True,  False, None),
    # ── MP: Media Protection ───────────────────────────────────────
    ("MP-1",  "MP", "Media Protection",    "Policy and Procedures",                     "P1", True,  True,  True,  False, None),
    ("MP-2",  "MP", "Media Protection",    "Media Access",                              "P1", True,  True,  True,  False, None),
    ("MP-6",  "MP", "Media Protection",    "Media Sanitization",                        "P1", True,  True,  True,  False, None),
    ("MP-7",  "MP", "Media Protection",    "Media Use",                                 "P1", True,  True,  True,  False, None),
    # ── PE: Physical and Environmental Protection ──────────────────
    ("PE-1",  "PE", "Physical and Environmental Protection","Policy and Procedures",    "P1", True,  True,  True,  False, None),
    ("PE-2",  "PE", "Physical and Environmental Protection","Physical Access Authorizations","P1",True,True,True,False,None),
    ("PE-3",  "PE", "Physical and Environmental Protection","Physical Access Control",  "P1", True,  True,  True,  False, None),
    ("PE-6",  "PE", "Physical and Environmental Protection","Monitoring Physical Access","P1",True, True,  True,  False, None),
    ("PE-8",  "PE", "Physical and Environmental Protection","Visitor Access Records",   "P3", True,  True,  True,  False, None),
    ("PE-12", "PE", "Physical and Environmental Protection","Emergency Lighting",       "P1", True,  True,  True,  False, None),
    ("PE-13", "PE", "Physical and Environmental Protection","Fire Protection",          "P1", True,  True,  True,  False, None),
    # ── PL: Planning ───────────────────────────────────────────────
    ("PL-1",  "PL", "Planning",            "Policy and Procedures",                     "P1", True,  True,  True,  False, None),
    ("PL-2",  "PL", "Planning",            "System Security and Privacy Plans",         "P1", True,  True,  True,  False, None),
    ("PL-4",  "PL", "Planning",            "Rules of Behavior",                         "P2", True,  True,  True,  False, None),
    ("PL-8",  "PL", "Planning",            "Security and Privacy Architectures",        "P1", False, True,  True,  False, None),
    # ── PM: Program Management ─────────────────────────────────────
    ("PM-1",  "PM", "Program Management",  "Information Security Program Plan",         "P1", True,  True,  True,  False, None),
    ("PM-2",  "PM", "Program Management",  "Information Security Program Leadership Role","P1",True,True,True,False,None),
    ("PM-9",  "PM", "Program Management",  "Risk Management Strategy",                  "P1", True,  True,  True,  False, None),
    ("PM-10", "PM", "Program Management",  "Authorization Process",                     "P1", True,  True,  True,  False, None),
    ("PM-11", "PM", "Program Management",  "Mission and Business Process Definition",   "P1", True,  True,  True,  False, None),
    # ── PS: Personnel Security ─────────────────────────────────────
    ("PS-1",  "PS", "Personnel Security",  "Policy and Procedures",                     "P1", True,  True,  True,  False, None),
    ("PS-2",  "PS", "Personnel Security",  "Position Risk Designation",                 "P1", True,  True,  True,  False, None),
    ("PS-3",  "PS", "Personnel Security",  "Personnel Screening",                       "P1", True,  True,  True,  False, None),
    ("PS-4",  "PS", "Personnel Security",  "Personnel Termination",                     "P1", True,  True,  True,  False, None),
    ("PS-5",  "PS", "Personnel Security",  "Personnel Transfer",                        "P2", True,  True,  True,  False, None),
    ("PS-6",  "PS", "Personnel Security",  "Access Agreements",                         "P3", True,  True,  True,  False, None),
    # ── PT: PII Processing and Transparency (NEW Rev 5) ────────────
    ("PT-1",  "PT", "PII Processing and Transparency","Policy and Procedures",          "P1", True,  True,  True,  False, None),
    ("PT-2",  "PT", "PII Processing and Transparency","Authority to Process PII",       "P1", True,  True,  True,  False, None),
    ("PT-3",  "PT", "PII Processing and Transparency","PII Processing Purposes",        "P1", True,  True,  True,  False, None),
    # ── RA: Risk Assessment ────────────────────────────────────────
    ("RA-1",  "RA", "Risk Assessment",     "Policy and Procedures",                     "P1", True,  True,  True,  False, None),
    ("RA-2",  "RA", "Risk Assessment",     "Security Categorization",                   "P1", True,  True,  True,  False, None),
    ("RA-3",  "RA", "Risk Assessment",     "Risk Assessment",                           "P1", True,  True,  True,  False, None),
    ("RA-5",  "RA", "Risk Assessment",     "Vulnerability Monitoring and Scanning",     "P1", True,  True,  True,  False, None),
    ("RA-5(2)","RA","Risk Assessment",     "Update Vulnerabilities to Be Scanned",      "P1", False, True,  True,  True,  "RA-5"),
    ("RA-7",  "RA", "Risk Assessment",     "Risk Response",                             "P1", True,  True,  True,  False, None),
    # ── SA: System and Services Acquisition ────────────────────────
    ("SA-1",  "SA", "System and Services Acquisition","Policy and Procedures",          "P1", True,  True,  True,  False, None),
    ("SA-2",  "SA", "System and Services Acquisition","Allocation of Resources",        "P1", True,  True,  True,  False, None),
    ("SA-3",  "SA", "System and Services Acquisition","System Development Life Cycle",  "P1", True,  True,  True,  False, None),
    ("SA-4",  "SA", "System and Services Acquisition","Acquisition Process",            "P1", True,  True,  True,  False, None),
    ("SA-5",  "SA", "System and Services Acquisition","System Documentation",           "P2", True,  True,  True,  False, None),
    ("SA-9",  "SA", "System and Services Acquisition","External System Services",       "P1", True,  True,  True,  False, None),
    # ── SC: System and Communications Protection ───────────────────
    ("SC-1",  "SC", "System and Communications Protection","Policy and Procedures",     "P1", True,  True,  True,  False, None),
    ("SC-5",  "SC", "System and Communications Protection","Denial-of-Service Protection","P1",True,True,True,False,None),
    ("SC-7",  "SC", "System and Communications Protection","Boundary Protection",       "P1", True,  True,  True,  False, None),
    ("SC-7(5)","SC","System and Communications Protection","Deny by Default — Allow by Exception","P1",False,True,True,True,"SC-7"),
    ("SC-8",  "SC", "System and Communications Protection","Transmission Confidentiality and Integrity","P1",False,True,True,False,None),
    ("SC-12", "SC", "System and Communications Protection","Cryptographic Key Establishment and Management","P1",True,True,True,False,None),
    ("SC-13", "SC", "System and Communications Protection","Cryptographic Protection",  "P1", True,  True,  True,  False, None),
    ("SC-15", "SC", "System and Communications Protection","Collaborative Computing Devices and Applications","P1",True,True,True,False,None),
    ("SC-20", "SC", "System and Communications Protection","Secure Name/Address Resolution Service","P1",True,True,True,False,None),
    ("SC-28", "SC", "System and Communications Protection","Protection of Information at Rest","P1",False,True,True,False,None),
    # ── SI: System and Information Integrity ───────────────────────
    ("SI-1",  "SI", "System and Information Integrity","Policy and Procedures",         "P1", True,  True,  True,  False, None),
    ("SI-2",  "SI", "System and Information Integrity","Flaw Remediation",              "P1", True,  True,  True,  False, None),
    ("SI-3",  "SI", "System and Information Integrity","Malicious Code Protection",     "P1", True,  True,  True,  False, None),
    ("SI-4",  "SI", "System and Information Integrity","System Monitoring",             "P1", True,  True,  True,  False, None),
    ("SI-5",  "SI", "System and Information Integrity","Security Alerts, Advisories, and Directives","P1",True,True,True,False,None),
    ("SI-7",  "SI", "System and Information Integrity","Software, Firmware, and Information Integrity","P1",False,True,True,False,None),
    ("SI-10", "SI", "System and Information Integrity","Information Input Validation",  "P1", False, True,  True,  False, None),
    # ── SR: Supply Chain Risk Management (NEW Rev 5) ───────────────
    ("SR-1",  "SR", "Supply Chain Risk Management","Policy and Procedures",             "P1", True,  True,  True,  False, None),
    ("SR-2",  "SR", "Supply Chain Risk Management","Supply Chain Risk Management Plan", "P1", True,  True,  True,  False, None),
    ("SR-3",  "SR", "Supply Chain Risk Management","Supply Chain Controls and Processes","P1",True,  True,  True,  False, None),
    ("SR-5",  "SR", "Supply Chain Risk Management","Acquisition Strategies, Tools, and Methods","P1",True,True,True,False,None),
]


def init_grc_schema():
    """Create GRC tables and seed NIST 800-53 Rev 5 controls."""
    if not _PG_AVAILABLE:
        log.warning("[GRC] psycopg2 not available — skipping schema init")
        return False

    try:
        with get_pg() as conn:
            if conn is None:
                return False
            with conn.cursor() as cur:
                # Create tables
                cur.execute(GRC_DDL)
                log.info("[GRC] ✅ 11 GRC tables created/verified")

                # Seed NIST controls (skip if already populated)
                cur.execute("SELECT count(*) FROM controls")
                existing = cur.fetchone()[0]
                if existing >= len(NIST_CONTROLS):
                    log.info("[GRC] ✅ NIST controls already seeded (%d rows)", existing)
                    return True

                for ctrl in NIST_CONTROLS:
                    cur.execute("""
                        INSERT INTO controls
                            (control_id, family, family_name, title, priority,
                             baseline_low, baseline_mod, baseline_high,
                             is_enhancement, parent_control)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (control_id) DO NOTHING
                    """, ctrl)

                log.info("[GRC] ✅ Seeded %d NIST 800-53 Rev 5 controls", len(NIST_CONTROLS))

                # Seed a default organization and system
                cur.execute("""
                    INSERT INTO organizations (name, acronym, org_type)
                    VALUES ('Default Organization', 'DEFAULT', 'Federal')
                    ON CONFLICT (name) DO NOTHING
                    RETURNING id
                """)
                org_row = cur.fetchone()
                org_id = org_row[0] if org_row else 1

                cur.execute("""
                    INSERT INTO systems (name, acronym, description, org_id, impact_level, system_type, status)
                    VALUES ('Vulnerability Intelligence Platform', 'VIP', 'Primary security intelligence and analysis platform', %s, 'Moderate', 'Major Application', 'Operational')
                    ON CONFLICT DO NOTHING
                """, (org_id,))

                log.info("[GRC] ✅ Default organization and system created")

        return True

    except Exception as e:
        log.error("[GRC] Schema init failed: %s", e)
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ok = init_grc_schema()
    print(f"GRC schema init: {'✅ SUCCESS' if ok else '❌ FAILED'}")
