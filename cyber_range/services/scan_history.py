"""
scan_history.py
───────────────
Scan history persistence layer — stores ScanResult objects in Neo4j
and retrieves past scans for the History tab.

Analogue of the recommended "Scan history (SQLite / PostgreSQL)"
upgrade from the reference spec, but using the existing Neo4j store.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import List, Optional

from neo4j import GraphDatabase

from cyber_range.models.scan_result import ScanResult

_URI  = os.getenv("NEO4J_URI",  "bolt://localhost:7687")
_USER = os.getenv("NEO4J_USER", "neo4j")
_PASS = os.getenv("NEO4J_PASS", os.getenv("NEO4J_PASSWORD", "Adomaa12@"))


def _driver():
    try:
        return GraphDatabase.driver(_URI, auth=(_USER, _PASS))
    except Exception:
        return None


class ScanHistory:
    """
    Persist and retrieve AD scan results.

    Nodes created:
      (:ADScan { scan_id, timestamp, dc_ip, domain, risk_score, ... })
    """

    @staticmethod
    def save(result: ScanResult) -> str:
        """
        Save a ScanResult to Neo4j.  Returns the scan_id.
        Silently swallows DB errors so a missing DB never crashes the scan.
        """
        if not result.scan_id:
            result.scan_id  = str(uuid.uuid4())[:8].upper()
        if not result.timestamp:
            result.timestamp = datetime.now()

        props = result.to_neo4j_props()

        drv = _driver()
        if not drv:
            return result.scan_id

        try:
            with drv.session() as s:
                s.run(
                    """
                    MERGE (a:ADScan {scan_id: $scan_id})
                    SET a += $props
                    """,
                    scan_id=result.scan_id, props=props
                )
                # Save individual findings as :ADFinding nodes
                for f in result.findings:
                    s.run(
                        """
                        MATCH (scan:ADScan {scan_id: $sid})
                        MERGE (f:ADFinding {scan_id: $sid, rule: $rule})
                        SET f.category = $cat,
                            f.severity = $sev,
                            f.description = $desc,
                            f.tool = $tool
                        MERGE (scan)-[:HAS_FINDING]->(f)
                        """,
                        sid=result.scan_id,
                        rule=f.rule, cat=f.category,
                        sev=f.severity, desc=f.description, tool=f.tool
                    )
        except Exception:
            pass
        finally:
            drv.close()

        return result.scan_id

    @staticmethod
    def get_all(limit: int = 20) -> List[dict]:
        """Return the most recent scans ordered by timestamp desc."""
        drv = _driver()
        if not drv:
            return []
        try:
            with drv.session() as s:
                rows = s.run(
                    """
                    MATCH (a:ADScan)
                    RETURN a
                    ORDER BY a.timestamp DESC
                    LIMIT $limit
                    """,
                    limit=limit
                ).data()
            return [dict(r["a"]) for r in rows]
        except Exception:
            return []
        finally:
            drv.close()

    @staticmethod
    def get_findings(scan_id: str) -> List[dict]:
        """Return all findings for a given scan_id."""
        drv = _driver()
        if not drv:
            return []
        try:
            with drv.session() as s:
                rows = s.run(
                    """
                    MATCH (f:ADFinding {scan_id: $sid})
                    RETURN f ORDER BY f.severity
                    """,
                    sid=scan_id
                ).data()
            return [dict(r["f"]) for r in rows]
        except Exception:
            return []
        finally:
            drv.close()

    @staticmethod
    def get_trend(limit: int = 10) -> List[dict]:
        """Return risk_score trend data for charting."""
        drv = _driver()
        if not drv:
            return []
        try:
            with drv.session() as s:
                rows = s.run(
                    """
                    MATCH (a:ADScan)
                    RETURN a.timestamp AS ts, a.risk_score AS score,
                           a.domain AS domain
                    ORDER BY a.timestamp DESC
                    LIMIT $limit
                    """,
                    limit=limit
                ).data()
            return rows
        except Exception:
            return []
        finally:
            drv.close()
