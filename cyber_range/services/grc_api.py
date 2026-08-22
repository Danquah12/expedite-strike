# ================================================================
# grc_api.py  —  GRC REST API routes
#
# Mounts on the Dash server as Flask routes under /api/grc/
#
# Usage:
#   from cyber_range.services.grc_api import register_grc_api
#   register_grc_api(server)   # pass Flask server object
#
# Endpoints:
#   GET  /api/grc/systems              — list all systems
#   POST /api/grc/systems              — create a system
#   GET  /api/grc/systems/<id>         — get system detail
#   GET  /api/grc/controls             — list controls (filter by family, baseline)
#   GET  /api/grc/vulnerabilities      — list vulns (filter by system, severity)
#   POST /api/grc/poam                 — create POA&M item
#   GET  /api/grc/poam                 — list POA&M items
#   GET  /api/grc/compliance-score     — get compliance score
#   GET  /api/grc/dashboard            — dashboard summary (score, findings, heatmap)
# ================================================================

import json
import logging
from datetime import date, datetime
from flask import request, jsonify

from cyber_range.services.pg_engine import pg_execute, _PG_AVAILABLE

log = logging.getLogger(__name__)


def _json_serial(obj):
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


def register_grc_api(server):
    """Register all GRC REST API routes on the Flask server."""

    if not _PG_AVAILABLE:
        log.warning("[GRC API] psycopg2 not available — GRC API disabled")
        return

    # ── GET /api/grc/systems ─────────────────────────────────────
    @server.route("/api/grc/systems", methods=["GET"])
    def api_get_systems():
        rows = pg_execute("""
            SELECT s.*, o.name AS org_name, o.acronym AS org_acronym
            FROM systems s
            LEFT JOIN organizations o ON s.org_id = o.id
            ORDER BY s.name
        """)
        return json.dumps({"systems": rows, "count": len(rows)}, default=_json_serial)

    # ── POST /api/grc/systems ────────────────────────────────────
    @server.route("/api/grc/systems", methods=["POST"])
    def api_create_system():
        data = request.get_json(force=True)
        required = ["name"]
        for f in required:
            if f not in data:
                return jsonify({"error": f"Missing required field: {f}"}), 400

        rows = pg_execute("""
            INSERT INTO systems (name, acronym, description, org_id, impact_level, system_type, status, data_types)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, name, acronym, impact_level, status
        """, (
            data["name"],
            data.get("acronym", ""),
            data.get("description", ""),
            data.get("org_id", 1),
            data.get("impact_level", "Moderate"),
            data.get("system_type", "Major Application"),
            data.get("status", "Operational"),
            data.get("data_types", []),
        ))
        if rows:
            return jsonify({"system": rows[0], "message": "System created"}), 201
        return jsonify({"error": "Failed to create system"}), 500

    # ── GET /api/grc/systems/<id> ────────────────────────────────
    @server.route("/api/grc/systems/<int:sys_id>", methods=["GET"])
    def api_get_system(sys_id):
        rows = pg_execute("""
            SELECT s.*, o.name AS org_name,
                   (SELECT count(*) FROM system_controls sc WHERE sc.system_id = s.id) AS total_controls,
                   (SELECT count(*) FROM system_controls sc WHERE sc.system_id = s.id AND sc.status = 'Implemented') AS implemented_controls,
                   (SELECT count(*) FROM poam p WHERE p.system_id = s.id AND p.status != 'Closed') AS open_poams,
                   (SELECT count(*) FROM grc_vulnerabilities v WHERE v.system_id = s.id AND v.status = 'Open') AS open_vulns
            FROM systems s
            LEFT JOIN organizations o ON s.org_id = o.id
            WHERE s.id = %s
        """, (sys_id,))
        if not rows:
            return jsonify({"error": "System not found"}), 404
        return json.dumps({"system": rows[0]}, default=_json_serial)

    # ── GET /api/grc/controls ────────────────────────────────────
    @server.route("/api/grc/controls", methods=["GET"])
    def api_get_controls():
        family = request.args.get("family")
        baseline = request.args.get("baseline")  # low, moderate, high

        sql = "SELECT * FROM controls WHERE 1=1"
        params = []

        if family:
            sql += " AND family = %s"
            params.append(family.upper())
        if baseline == "low":
            sql += " AND baseline_low = TRUE"
        elif baseline == "moderate":
            sql += " AND baseline_mod = TRUE"
        elif baseline == "high":
            sql += " AND baseline_high = TRUE"

        sql += " ORDER BY control_id"
        rows = pg_execute(sql, params or None)

        # Count by family
        families = {}
        for r in rows:
            fam = r.get("family", "")
            families[fam] = families.get(fam, 0) + 1

        return json.dumps({
            "controls": rows,
            "count": len(rows),
            "families": families,
        }, default=_json_serial)

    # ── GET /api/grc/vulnerabilities ─────────────────────────────
    @server.route("/api/grc/vulnerabilities", methods=["GET"])
    def api_get_vulns():
        system_id = request.args.get("system_id")
        severity = request.args.get("severity")
        status = request.args.get("status", "Open")

        sql = "SELECT * FROM grc_vulnerabilities WHERE 1=1"
        params = []

        if system_id:
            sql += " AND system_id = %s"
            params.append(int(system_id))
        if severity:
            sql += " AND severity = %s"
            params.append(severity)
        if status:
            sql += " AND status = %s"
            params.append(status)

        sql += " ORDER BY cvss DESC NULLS LAST"
        rows = pg_execute(sql, params or None)

        # Summary stats
        stats = {
            "total": len(rows),
            "critical": sum(1 for r in rows if r.get("severity") == "Critical"),
            "high": sum(1 for r in rows if r.get("severity") == "High"),
            "medium": sum(1 for r in rows if r.get("severity") == "Medium"),
            "low": sum(1 for r in rows if r.get("severity") == "Low"),
        }
        return json.dumps({"vulnerabilities": rows, "stats": stats}, default=_json_serial)

    # ── POST /api/grc/poam ───────────────────────────────────────
    @server.route("/api/grc/poam", methods=["POST"])
    def api_create_poam():
        data = request.get_json(force=True)
        required = ["weakness"]
        for f in required:
            if f not in data:
                return jsonify({"error": f"Missing required field: {f}"}), 400

        # Auto-generate POAM ID
        count_rows = pg_execute("SELECT count(*) AS n FROM poam")
        next_id = (count_rows[0]["n"] if count_rows else 0) + 1
        poam_id = f"POAM-{next_id:04d}"

        rows = pg_execute("""
            INSERT INTO poam
                (poam_id, system_id, weakness, risk_level, cvss,
                 status, remediation, milestones, due_date, responsible, source)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, poam_id, weakness, risk_level, status, due_date
        """, (
            poam_id,
            data.get("system_id", 1),
            data["weakness"],
            data.get("risk_level", "Medium"),
            data.get("cvss"),
            data.get("status", "Open"),
            data.get("remediation", ""),
            data.get("milestones", ""),
            data.get("due_date"),
            data.get("responsible", ""),
            data.get("source", "Manual"),
        ))

        if rows:
            return json.dumps({"poam": rows[0], "message": f"{poam_id} created"}, default=_json_serial), 201
        return jsonify({"error": "Failed to create POA&M item"}), 500

    # ── GET /api/grc/poam ────────────────────────────────────────
    @server.route("/api/grc/poam", methods=["GET"])
    def api_get_poam():
        system_id = request.args.get("system_id")
        status = request.args.get("status")

        sql = "SELECT * FROM poam WHERE 1=1"
        params = []

        if system_id:
            sql += " AND system_id = %s"
            params.append(int(system_id))
        if status:
            sql += " AND status = %s"
            params.append(status)

        sql += " ORDER BY CASE risk_level WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END, due_date ASC"
        rows = pg_execute(sql, params or None)

        today = date.today()
        stats = {
            "total": len(rows),
            "open": sum(1 for r in rows if r.get("status") == "Open"),
            "in_progress": sum(1 for r in rows if r.get("status") == "In Progress"),
            "closed": sum(1 for r in rows if r.get("status") == "Closed"),
            "critical": sum(1 for r in rows if r.get("risk_level") == "Critical"),
            "overdue": sum(1 for r in rows if r.get("due_date") and r["due_date"] < today and r.get("status") != "Closed"),
        }
        return json.dumps({"poam_items": rows, "stats": stats}, default=_json_serial)

    # ── GET /api/grc/compliance-score ────────────────────────────
    @server.route("/api/grc/compliance-score", methods=["GET"])
    def api_compliance_score():
        system_id = request.args.get("system_id", "1")

        # Calculate live compliance score
        controls = pg_execute("""
            SELECT
                count(*) AS total,
                count(*) FILTER (WHERE status = 'Implemented')     AS implemented,
                count(*) FILTER (WHERE status = 'Partially Implemented') AS partial,
                count(*) FILTER (WHERE status = 'Planned')         AS planned,
                count(*) FILTER (WHERE status = 'Not Implemented') AS not_implemented,
                count(*) FILTER (WHERE status = 'N/A')             AS na
            FROM system_controls
            WHERE system_id = %s
        """, (int(system_id),))

        vulns = pg_execute("""
            SELECT
                count(*) AS total,
                count(*) FILTER (WHERE status = 'Open')     AS open,
                count(*) FILTER (WHERE severity = 'Critical') AS critical,
                count(*) FILTER (WHERE severity = 'High')   AS high
            FROM grc_vulnerabilities
            WHERE system_id = %s
        """, (int(system_id),))

        poams = pg_execute("""
            SELECT
                count(*) AS total,
                count(*) FILTER (WHERE status = 'Open')     AS open,
                count(*) FILTER (WHERE status = 'Closed')   AS closed,
                count(*) FILTER (WHERE risk_level = 'Critical') AS critical
            FROM poam
            WHERE system_id = %s
        """, (int(system_id),))

        ctrl = controls[0] if controls else {"total": 0, "implemented": 0, "partial": 0}
        vuln = vulns[0] if vulns else {"total": 0, "open": 0, "critical": 0}
        poam = poams[0] if poams else {"total": 0, "open": 0}

        # Score calculation: implemented + 0.5*partial / (total - na)
        denom = (ctrl["total"] or 1) - (ctrl.get("na") or 0)
        denom = max(denom, 1)
        score = round(
            ((ctrl["implemented"] or 0) + 0.5 * (ctrl["partial"] or 0)) / denom * 100,
            1
        )

        return jsonify({
            "system_id": int(system_id),
            "compliance_score": score,
            "controls": ctrl,
            "vulnerabilities": vuln,
            "poam": poam,
        })

    # ── GET /api/grc/dashboard ───────────────────────────────────
    @server.route("/api/grc/dashboard", methods=["GET"])
    def api_grc_dashboard():
        """Combined dashboard endpoint: compliance score + open findings + risk heatmap."""
        system_id = request.args.get("system_id", "1")

        # Compliance score
        score_rows = pg_execute("""
            SELECT
                count(*) AS total,
                count(*) FILTER (WHERE status = 'Implemented')     AS implemented,
                count(*) FILTER (WHERE status = 'Partially Implemented') AS partial,
                count(*) FILTER (WHERE status = 'N/A') AS na
            FROM system_controls WHERE system_id = %s
        """, (int(system_id),))
        sc = score_rows[0] if score_rows else {"total": 0, "implemented": 0, "partial": 0, "na": 0}
        denom = max((sc["total"] or 1) - (sc.get("na") or 0), 1)
        compliance_score = round(
            ((sc["implemented"] or 0) + 0.5 * (sc["partial"] or 0)) / denom * 100, 1
        )

        # Open findings by severity
        findings = pg_execute("""
            SELECT severity, count(*) AS cnt
            FROM grc_vulnerabilities
            WHERE system_id = %s AND status = 'Open'
            GROUP BY severity
            ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END
        """, (int(system_id),))

        # Risk heatmap data (likelihood x impact grid)
        heatmap = pg_execute("""
            SELECT likelihood, impact, count(*) AS cnt, risk_level
            FROM risks
            WHERE system_id = %s AND status != 'Closed'
            GROUP BY likelihood, impact, risk_level
        """, (int(system_id),))

        # Historical scores
        history = pg_execute("""
            SELECT score, recorded_at, open_findings, open_poams
            FROM compliance_scores
            WHERE system_id = %s
            ORDER BY recorded_at DESC
            LIMIT 12
        """, (int(system_id),))

        return json.dumps({
            "system_id": int(system_id),
            "compliance_score": compliance_score,
            "controls_summary": sc,
            "open_findings": findings,
            "risk_heatmap": heatmap,
            "score_history": list(reversed(history)),
        }, default=_json_serial)

    # ── POST /api/grc/agents/run ─────────────────────────────────
    @server.route("/api/grc/agents/run", methods=["POST"])
    def api_run_agents():
        """Run the full 5-agent GRC pipeline via LangGraph."""
        try:
            data = request.get_json(force=True) if request.is_json else {}
            system_id = data.get("system_id", 1)

            from cyber_range.services.grc_agents import run_grc_pipeline
            result = run_grc_pipeline(system_id=system_id)

            # Extract serializable summary
            return json.dumps({
                "status": "complete",
                "summary": result.get("summary", {}),
                "poam_count": len(result.get("poam_items", [])),
                "risk_count": len(result.get("risks", [])),
                "asset_count": len(result.get("assets", [])),
                "vuln_count": len(result.get("vulnerabilities", [])),
                "risk_heatmap": result.get("risk_heatmap", []),
                "poam_items": result.get("poam_items", [])[:20],  # top 20
                "risks": result.get("risks", [])[:20],
            }, default=_json_serial)
        except Exception as e:
            log.error(f"[GRC Agent API] Pipeline error: {e}")
            import traceback
            traceback.print_exc()
            return jsonify({"error": str(e)}), 500

    # ── POST /api/grc/compliance-chat ────────────────────────────
    @server.route("/api/grc/compliance-chat", methods=["POST"])
    def api_compliance_chat():
        """AI Compliance Assistant — ask questions about NIST, FedRAMP, STIGs."""
        data = request.get_json(force=True)
        message = data.get("message", "")
        if not message:
            return jsonify({"error": "Missing 'message' field"}), 400

        try:
            from cyber_range.services.grc_agents import compliance_chat
            context = data.get("context", {})
            answer = compliance_chat(message, context)
            return jsonify({"question": message, "answer": answer})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── POST /api/grc/explain-vuln ───────────────────────────────
    @server.route("/api/grc/explain-vuln", methods=["POST"])
    def api_explain_vuln():
        """Explain a vulnerability and its compliance implications."""
        data = request.get_json(force=True)
        vuln = data.get("vulnerability", data.get("cve", ""))
        if not vuln:
            return jsonify({"error": "Missing 'vulnerability' or 'cve' field"}), 400

        try:
            from cyber_range.services.grc_agents import explain_vulnerability
            answer = explain_vulnerability(vuln)
            return jsonify({"vulnerability": vuln, "explanation": answer})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── POST /api/grc/implementation-statement ───────────────────
    @server.route("/api/grc/implementation-statement", methods=["POST"])
    def api_implementation_statement():
        """Generate an SSP implementation statement for a NIST control."""
        data = request.get_json(force=True)
        control_id = data.get("control_id", "")
        if not control_id:
            return jsonify({"error": "Missing 'control_id' field"}), 400

        try:
            from cyber_range.services.grc_agents import generate_implementation_statement
            statement = generate_implementation_statement(control_id)
            return jsonify({"control_id": control_id, "statement": statement})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── POST /api/grc/evidence-requirements ──────────────────────
    @server.route("/api/grc/evidence-requirements", methods=["POST"])
    def api_evidence_requirements():
        """List required evidence artifacts for a NIST control."""
        data = request.get_json(force=True)
        control_id = data.get("control_id", "")
        if not control_id:
            return jsonify({"error": "Missing 'control_id' field"}), 400

        try:
            from cyber_range.services.grc_agents import get_evidence_requirements
            evidence = get_evidence_requirements(control_id)
            return jsonify({"control_id": control_id, "evidence": evidence})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── GET /api/grc/docs/<type> ─────────────────────────────────
    @server.route("/api/grc/docs/<doc_type>", methods=["GET"])
    def api_generate_doc(doc_type):
        """Generate a GRC document (ssp, sar, poam, risk, ato)."""
        system_id = request.args.get("system_id", "1")
        try:
            from cyber_range.services.grc_doc_generator import GrcDocGenerator
            gen = GrcDocGenerator(system_id=int(system_id))

            generators = {
                "ssp": gen.generate_ssp,
                "sar": gen.generate_sar,
                "poam": gen.generate_poam_report,
                "risk": gen.generate_risk_assessment,
                "ato": gen.generate_ato_package,
            }

            if doc_type not in generators:
                return jsonify({"error": f"Unknown doc type '{doc_type}'. Options: {list(generators.keys())}"}), 400

            content = generators[doc_type]()
            return jsonify({"type": doc_type, "content": content, "system_id": int(system_id)})
        except Exception as e:
            log.error(f"[GRC Docs] Error generating {doc_type}: {e}")
            return jsonify({"error": str(e)}), 500

    # ── POST /api/grc/docs/ato-package ───────────────────────────
    @server.route("/api/grc/docs/ato-package", methods=["POST"])
    def api_generate_ato_package():
        """Generate the complete ATO package (all 5 documents)."""
        data = request.get_json(force=True) if request.is_json else {}
        system_id = data.get("system_id", 1)
        try:
            from cyber_range.services.grc_doc_generator import GrcDocGenerator
            gen = GrcDocGenerator(system_id=int(system_id))
            package = gen.generate_all()
            # Remove raw system dict to keep response clean
            package.pop("system", None)
            return json.dumps(package, default=_json_serial)
        except Exception as e:
            log.error(f"[GRC Docs] ATO package error: {e}")
            return jsonify({"error": str(e)}), 500

    # ── POST /api/grc/monitor/run ────────────────────────────────
    @server.route("/api/grc/monitor/run", methods=["POST"])
    def api_monitor_run():
        """Run one continuous monitoring cycle."""
        data = request.get_json(force=True) if request.is_json else {}
        system_id = data.get("system_id", 1)
        try:
            from cyber_range.services.grc_monitor import run_monitor_cycle
            result = run_monitor_cycle(system_id=system_id)
            return json.dumps(result, default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── GET /api/grc/monitor/status ──────────────────────────────
    @server.route("/api/grc/monitor/status", methods=["GET"])
    def api_monitor_status():
        """Get continuous monitoring status."""
        try:
            from cyber_range.services.grc_monitor import get_monitor_status
            return jsonify(get_monitor_status())
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── POST /api/grc/monitor/start ──────────────────────────────
    @server.route("/api/grc/monitor/start", methods=["POST"])
    def api_monitor_start():
        """Start the background monitoring scheduler."""
        try:
            from cyber_range.services.grc_monitor import start_monitor, get_monitor_status
            start_monitor()
            return jsonify({"message": "Monitor started", **get_monitor_status()})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── POST /api/grc/monitor/stop ───────────────────────────────
    @server.route("/api/grc/monitor/stop", methods=["POST"])
    def api_monitor_stop():
        """Stop the background monitoring scheduler."""
        try:
            from cyber_range.services.grc_monitor import stop_monitor
            stop_monitor()
            return jsonify({"message": "Monitor stopped"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── POST /api/grc/cloud/discover ─────────────────────────────
    @server.route("/api/grc/cloud/discover", methods=["POST"])
    def api_cloud_discover():
        """Discover cloud assets (AWS/Azure/GCP)."""
        try:
            from cyber_range.services.grc_monitor import discover_cloud_assets
            assets = discover_cloud_assets()
            return json.dumps(assets, default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ═══════════════════════════════════════════════════════════════
    # DevSecOps Endpoints (Step 18)
    # ═══════════════════════════════════════════════════════════════

    @server.route("/api/grc/devsecops/scan-github", methods=["POST"])
    def api_scan_github():
        """Scan a GitHub repo for vulnerabilities and secrets."""
        data = request.get_json(force=True)
        repo = data.get("repo", "")
        if not repo:
            return jsonify({"error": "Missing 'repo' field (owner/repo)"}), 400
        try:
            from cyber_range.services.devsecops_engine import DevSecOpsEngine
            engine = DevSecOpsEngine()
            result = engine.scan_github_repo(repo, data.get("branch", "main"))
            return json.dumps(result, default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @server.route("/api/grc/devsecops/scan-gitlab", methods=["POST"])
    def api_scan_gitlab():
        """Scan a GitLab project for vulnerabilities."""
        data = request.get_json(force=True)
        project_id = data.get("project_id", "")
        if not project_id:
            return jsonify({"error": "Missing 'project_id'"}), 400
        try:
            from cyber_range.services.devsecops_engine import DevSecOpsEngine
            engine = DevSecOpsEngine()
            result = engine.scan_gitlab_project(str(project_id))
            return json.dumps(result, default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @server.route("/api/grc/devsecops/scan-local", methods=["POST"])
    def api_scan_local():
        """Scan a local path for code vulnerabilities and secrets."""
        data = request.get_json(force=True)
        path = data.get("path", "")
        if not path:
            return jsonify({"error": "Missing 'path'"}), 400
        try:
            from cyber_range.services.devsecops_engine import DevSecOpsEngine
            engine = DevSecOpsEngine()
            result = engine.scan_local_path(path)
            return json.dumps(result, default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ═══════════════════════════════════════════════════════════════
    # Threat Intelligence Endpoints (Step 19)
    # ═══════════════════════════════════════════════════════════════

    @server.route("/api/grc/threat-intel/ingest", methods=["POST"])
    def api_ingest_ioc():
        """Ingest IOCs into the threat intel store."""
        data = request.get_json(force=True)
        try:
            from cyber_range.services.threat_intel_engine import ThreatIntelEngine
            engine = ThreatIntelEngine()
            iocs = data.get("iocs", [data]) if "iocs" in data else [data]
            result = engine.bulk_ingest(iocs)
            return jsonify(result)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @server.route("/api/grc/threat-intel/search", methods=["GET"])
    def api_search_ioc():
        """Search for IOCs by value."""
        query = request.args.get("q", "")
        if not query:
            return jsonify({"error": "Missing 'q' query parameter"}), 400
        try:
            from cyber_range.services.threat_intel_engine import ThreatIntelEngine
            engine = ThreatIntelEngine()
            results = engine.search_ioc(query)
            return json.dumps({"query": query, "results": results, "count": len(results)}, default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @server.route("/api/grc/threat-intel/feeds", methods=["POST"])
    def api_refresh_feeds():
        """Refresh all threat intelligence feeds."""
        try:
            from cyber_range.services.threat_intel_engine import ThreatIntelEngine
            engine = ThreatIntelEngine()
            result = engine.refresh_feeds()
            return json.dumps({
                "cisa_kev_count": len(result.get("cisa_kev", [])),
                "feodo_count": len(result.get("feodo_c2", [])),
                "urlhaus_count": len(result.get("urlhaus", [])),
                "ioc_stats": result.get("ioc_stats", {}),
            }, default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @server.route("/api/grc/threat-intel/adversaries", methods=["GET"])
    def api_list_adversaries():
        """List all tracked adversary groups."""
        try:
            from cyber_range.services.threat_intel_engine import ThreatIntelEngine
            engine = ThreatIntelEngine()
            return json.dumps({"adversaries": engine.list_adversaries()}, default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @server.route("/api/grc/threat-intel/adversary/<name>", methods=["GET"])
    def api_get_adversary(name):
        """Get detailed adversary profile."""
        try:
            from cyber_range.services.threat_intel_engine import ThreatIntelEngine
            engine = ThreatIntelEngine()
            return json.dumps(engine.get_adversary(name), default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @server.route("/api/grc/threat-intel/correlate", methods=["POST"])
    def api_correlate_threats():
        """Correlate adversary TTPs with internal findings."""
        try:
            from cyber_range.services.threat_intel_engine import ThreatIntelEngine
            engine = ThreatIntelEngine()
            correlations = engine.correlate_threats()
            return json.dumps({"correlations": correlations, "count": len(correlations)}, default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @server.route("/api/grc/threat-intel/risk-score", methods=["POST"])
    def api_risk_score():
        """Compute threat-intel-enhanced risk score for a vulnerability."""
        data = request.get_json(force=True)
        try:
            from cyber_range.services.threat_intel_engine import ThreatIntelEngine
            engine = ThreatIntelEngine()
            score = engine.compute_risk_score(data)
            return json.dumps(score, default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @server.route("/api/grc/threat-intel/landscape", methods=["GET"])
    def api_threat_landscape():
        """Get complete threat landscape overview."""
        try:
            from cyber_range.services.threat_intel_engine import ThreatIntelEngine
            engine = ThreatIntelEngine()
            return json.dumps(engine.get_threat_landscape(), default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ═══════════════════════════════════════════════════════════════
    # Certification Tracker Endpoints (Step 22)
    # ═══════════════════════════════════════════════════════════════

    @server.route("/api/grc/certifications", methods=["GET"])
    def api_list_certifications():
        """Get all certification statuses."""
        try:
            from cyber_range.services.cert_tracker import get_tracker
            tracker = get_tracker()
            return json.dumps({"certifications": tracker.get_all_certifications()}, default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @server.route("/api/grc/certifications/<cert_id>", methods=["GET"])
    def api_get_certification(cert_id):
        """Get detailed certification status with readiness score."""
        try:
            from cyber_range.services.cert_tracker import get_tracker
            tracker = get_tracker()
            return json.dumps(tracker.get_certification(cert_id), default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @server.route("/api/grc/certifications/<cert_id>/start", methods=["POST"])
    def api_start_certification(cert_id):
        """Start a certification process."""
        data = request.get_json(force=True) if request.is_json else {}
        try:
            from cyber_range.services.cert_tracker import get_tracker
            tracker = get_tracker()
            result = tracker.start_certification(cert_id, data.get("target_date"))
            return json.dumps(result, default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @server.route("/api/grc/certifications/<cert_id>/evidence", methods=["POST"])
    def api_add_evidence(cert_id):
        """Add evidence artifact for a certification."""
        data = request.get_json(force=True)
        try:
            from cyber_range.services.cert_tracker import get_tracker
            tracker = get_tracker()
            result = tracker.add_evidence(cert_id, data)
            return json.dumps(result, default=_json_serial)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    log.info("[GRC API] ✅ 38 GRC REST API routes registered under /api/grc/")
