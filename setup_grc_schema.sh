#!/bin/bash
# ================================================================
# setup_grc_schema.sh — Create GRC tables + seed NIST 800-53
#
# Run as: bash setup_grc_schema.sh
# Requires: sudo postgres access (peer auth)
# ================================================================

set -e

echo "🔧 Step 1: Granting CREATE privilege to vuln_admin..."
sudo -u postgres psql -d vuln_intel -c "
    GRANT CREATE ON SCHEMA public TO vuln_admin;
    GRANT ALL ON SCHEMA public TO vuln_admin;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO vuln_admin;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO vuln_admin;
"
echo "✅ Privileges granted"

echo ""
echo "🔧 Step 2: Creating 11 GRC tables and seeding NIST 800-53 controls..."
cd /opt/vuln_intel/app
source venv/bin/activate
python3 -m cyber_range.services.grc_schema

echo ""
echo "🔧 Step 3: Verifying..."
PGPASSWORD='VuIntelPg2026!' psql -U vuln_admin -d vuln_intel -h localhost -c "
    SELECT 'organizations' AS tbl, count(*) FROM organizations
    UNION ALL SELECT 'grc_users', count(*) FROM grc_users
    UNION ALL SELECT 'systems', count(*) FROM systems
    UNION ALL SELECT 'controls', count(*) FROM controls
    UNION ALL SELECT 'system_controls', count(*) FROM system_controls
    UNION ALL SELECT 'grc_vulnerabilities', count(*) FROM grc_vulnerabilities
    UNION ALL SELECT 'poam', count(*) FROM poam
    UNION ALL SELECT 'risks', count(*) FROM risks
    UNION ALL SELECT 'evidence', count(*) FROM evidence
    UNION ALL SELECT 'assessments', count(*) FROM assessments
    UNION ALL SELECT 'compliance_scores', count(*) FROM compliance_scores;
"

echo ""
echo "🎉 GRC Schema complete!"
