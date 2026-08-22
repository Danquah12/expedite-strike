# ================================================================
# devsecops_engine.py — DevSecOps Integration Engine
#
# Connects to: GitHub, GitLab, Jenkins, CI/CD Pipelines
# Detects: Vulnerabilities in code repositories
#
# Features:
#   1. GitHub Integration — repo scanning, secret detection, SAST
#   2. GitLab Integration — repo analysis, pipeline monitoring
#   3. Jenkins Integration — build status, security gate checks
#   4. Code Vulnerability Scanner — pattern-based + AI-enhanced
#   5. CI/CD Pipeline Monitor — track security gates
#
# Usage:
#   from cyber_range.services.devsecops_engine import DevSecOpsEngine
#   engine = DevSecOpsEngine()
#   engine.scan_github_repo("owner/repo")
#   engine.check_jenkins_security()
# ================================================================

import os
import re
import json
import logging
import hashlib
from datetime import datetime
from typing import Optional

log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────
GITHUB_TOKEN   = os.getenv("GITHUB_TOKEN", "")
GITLAB_TOKEN   = os.getenv("GITLAB_TOKEN", "")
GITLAB_URL     = os.getenv("GITLAB_URL", "https://gitlab.com")
JENKINS_URL    = os.getenv("JENKINS_URL", "")
JENKINS_USER   = os.getenv("JENKINS_USER", "")
JENKINS_TOKEN  = os.getenv("JENKINS_TOKEN", "")


# ── Secret Patterns ──────────────────────────────────────────────
SECRET_PATTERNS = [
    {"name": "AWS Access Key",       "regex": r"AKIA[0-9A-Z]{16}",                "severity": "Critical"},
    {"name": "AWS Secret Key",       "regex": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key.*?['\"][0-9a-zA-Z/+=]{40}['\"]", "severity": "Critical"},
    {"name": "Private Key",          "regex": r"-----BEGIN\s*(RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----", "severity": "Critical"},
    {"name": "GitHub Token",         "regex": r"gh[pousr]_[A-Za-z0-9_]{36,255}",  "severity": "High"},
    {"name": "GitLab Token",         "regex": r"glpat-[A-Za-z0-9\-_]{20,}",       "severity": "High"},
    {"name": "Generic API Key",      "regex": r"(?i)(api[_\-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]", "severity": "High"},
    {"name": "Password in Code",     "regex": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]", "severity": "High"},
    {"name": "JWT Token",            "regex": r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+", "severity": "High"},
    {"name": "Database URL",         "regex": r"(?i)(postgres|mysql|mongodb|redis)://[^\s'\"]+",  "severity": "High"},
    {"name": "Slack Webhook",        "regex": r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+","severity": "Medium"},
    {"name": "Bearer Token",         "regex": r"(?i)bearer\s+[a-zA-Z0-9\-_.]{20,}",              "severity": "Medium"},
    {"name": "Hardcoded IP",         "regex": r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.\d+\b", "severity": "Low"},
]

# ── Code Vulnerability Patterns ──────────────────────────────────
CODE_VULN_PATTERNS = [
    {"name": "SQL Injection",        "regex": r"(?i)(execute|raw|cursor\.execute)\s*\([^)]*['\"].*?%s",
     "severity": "Critical", "cwe": "CWE-89",  "nist": "SI-10"},
    {"name": "Command Injection",    "regex": r"(?i)(os\.system|subprocess\.call|popen)\s*\([^)]*\+",
     "severity": "Critical", "cwe": "CWE-78",  "nist": "SI-10"},
    {"name": "XSS Vulnerability",    "regex": r"(?i)(innerHTML|document\.write|\.html\()\s*[^)]*\+",
     "severity": "High",     "cwe": "CWE-79",  "nist": "SI-10"},
    {"name": "Path Traversal",       "regex": r"(?i)(open|read|write)\s*\([^)]*\.\./",
     "severity": "High",     "cwe": "CWE-22",  "nist": "SI-10"},
    {"name": "Insecure Deserialization", "regex": r"(?i)(pickle\.loads|yaml\.load\(|eval\()",
     "severity": "High",     "cwe": "CWE-502", "nist": "SI-10"},
    {"name": "Hardcoded Credentials","regex": r"(?i)(password|secret|key)\s*=\s*['\"][^'\"]{8,}['\"]",
     "severity": "High",     "cwe": "CWE-798", "nist": "IA-5"},
    {"name": "Weak Crypto",          "regex": r"(?i)(md5|sha1|DES|RC4)\s*\(",
     "severity": "Medium",   "cwe": "CWE-327", "nist": "SC-12"},
    {"name": "Debug Mode",           "regex": r"(?i)(DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True)",
     "severity": "Medium",   "cwe": "CWE-489", "nist": "CM-6"},
    {"name": "Missing HTTPS",        "regex": r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)",
     "severity": "Medium",   "cwe": "CWE-319", "nist": "SC-8"},
    {"name": "CORS Wildcard",        "regex": r"(?i)Access-Control-Allow-Origin.*?\*",
     "severity": "Medium",   "cwe": "CWE-942", "nist": "SC-7"},
    {"name": "Unsafe Redirect",      "regex": r"(?i)redirect\s*\(\s*request\.(args|form|params)",
     "severity": "Medium",   "cwe": "CWE-601", "nist": "SI-10"},
    {"name": "Missing Input Validation", "regex": r"(?i)request\.(args|form|json)\[.*\](?!\s*\.strip)",
     "severity": "Low",      "cwe": "CWE-20",  "nist": "SI-10"},
]


# ================================================================
# DevSecOps Engine
# ================================================================
class DevSecOpsEngine:
    """Integrated DevSecOps scanning engine."""

    def __init__(self):
        self.findings = []
        self.timestamp = datetime.now().isoformat()

    # ── GitHub Integration ───────────────────────────────────────
    def scan_github_repo(self, repo: str, branch: str = "main") -> dict:
        """
        Scan a GitHub repository for security issues.
        repo: "owner/repo" format
        """
        log.info(f"[DevSecOps] Scanning GitHub repo: {repo}")
        results = {"repo": repo, "branch": branch, "findings": [], "stats": {}}

        try:
            import requests
            headers = {"Accept": "application/vnd.github+json"}
            if GITHUB_TOKEN:
                headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

            # 1. Get repo info
            resp = requests.get(f"https://api.github.com/repos/{repo}", headers=headers, timeout=10)
            if resp.status_code != 200:
                return {"error": f"GitHub API error: {resp.status_code}", "repo": repo}
            repo_info = resp.json()
            results["language"] = repo_info.get("language", "Unknown")
            results["visibility"] = "public" if not repo_info.get("private") else "private"

            # 2. Check for security advisories
            adv_resp = requests.get(
                f"https://api.github.com/repos/{repo}/security-advisories",
                headers=headers, timeout=10
            )
            if adv_resp.status_code == 200:
                advisories = adv_resp.json()
                for adv in advisories:
                    results["findings"].append({
                        "type": "advisory", "severity": adv.get("severity", "medium").capitalize(),
                        "title": adv.get("summary", "Security Advisory"),
                        "cve": adv.get("cve_id", ""),
                        "source": "github_advisories",
                    })

            # 3. Check Dependabot alerts
            dep_resp = requests.get(
                f"https://api.github.com/repos/{repo}/dependabot/alerts?state=open",
                headers=headers, timeout=10
            )
            if dep_resp.status_code == 200:
                alerts = dep_resp.json()
                for alert in alerts[:30]:
                    sev = alert.get("security_advisory", {}).get("severity", "medium")
                    results["findings"].append({
                        "type": "dependency", "severity": sev.capitalize(),
                        "title": alert.get("security_advisory", {}).get("summary", "Dependency Alert"),
                        "cve": alert.get("security_advisory", {}).get("cve_id", ""),
                        "package": alert.get("dependency", {}).get("package", {}).get("name", ""),
                        "source": "dependabot",
                    })

            # 4. Check code scanning alerts
            code_resp = requests.get(
                f"https://api.github.com/repos/{repo}/code-scanning/alerts?state=open",
                headers=headers, timeout=10
            )
            if code_resp.status_code == 200:
                code_alerts = code_resp.json()
                for alert in code_alerts[:30]:
                    results["findings"].append({
                        "type": "code_scanning", "severity": alert.get("rule", {}).get("severity", "Medium"),
                        "title": alert.get("rule", {}).get("description", "Code Scanning Alert"),
                        "cwe": alert.get("rule", {}).get("tags", []),
                        "file": alert.get("most_recent_instance", {}).get("location", {}).get("path", ""),
                        "source": "codeql",
                    })

            # 5. Scan repo contents for secrets
            tree_resp = requests.get(
                f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1",
                headers=headers, timeout=10
            )
            if tree_resp.status_code == 200:
                tree = tree_resp.json().get("tree", [])
                scan_files = [
                    f for f in tree
                    if f.get("type") == "blob"
                    and f.get("size", 0) < 50000
                    and any(f["path"].endswith(ext) for ext in
                            (".py", ".js", ".ts", ".java", ".go", ".rb", ".php",
                             ".yml", ".yaml", ".json", ".env", ".cfg", ".ini", ".conf"))
                ]
                for file_info in scan_files[:50]:
                    blob_resp = requests.get(
                        f"https://api.github.com/repos/{repo}/contents/{file_info['path']}?ref={branch}",
                        headers=headers, timeout=10
                    )
                    if blob_resp.status_code == 200:
                        import base64
                        content = base64.b64decode(blob_resp.json().get("content", "")).decode("utf-8", errors="ignore")
                        file_findings = self._scan_content(content, file_info["path"], "github")
                        results["findings"].extend(file_findings)

        except Exception as e:
            log.error(f"[DevSecOps] GitHub scan error: {e}")
            results["error"] = str(e)

        results["stats"] = self._compute_stats(results["findings"])
        self.findings.extend(results["findings"])
        log.info(f"[DevSecOps] ✅ GitHub {repo}: {len(results['findings'])} findings")
        return results

    # ── GitLab Integration ───────────────────────────────────────
    def scan_gitlab_project(self, project_id: str) -> dict:
        """Scan a GitLab project for security issues."""
        log.info(f"[DevSecOps] Scanning GitLab project: {project_id}")
        results = {"project": project_id, "findings": [], "stats": {}}

        try:
            import requests
            headers = {}
            if GITLAB_TOKEN:
                headers["PRIVATE-TOKEN"] = GITLAB_TOKEN

            # 1. Get project vulnerabilities
            vuln_resp = requests.get(
                f"{GITLAB_URL}/api/v4/projects/{project_id}/vulnerabilities?state=detected",
                headers=headers, timeout=10
            )
            if vuln_resp.status_code == 200:
                for v in vuln_resp.json()[:50]:
                    results["findings"].append({
                        "type": "vulnerability", "severity": v.get("severity", "medium").capitalize(),
                        "title": v.get("title", "GitLab Vulnerability"),
                        "description": v.get("description", "")[:200],
                        "source": "gitlab_sast",
                    })

            # 2. Check pipeline security
            pipe_resp = requests.get(
                f"{GITLAB_URL}/api/v4/projects/{project_id}/pipelines?per_page=5",
                headers=headers, timeout=10
            )
            if pipe_resp.status_code == 200:
                for pipe in pipe_resp.json():
                    if pipe.get("status") == "failed":
                        results["findings"].append({
                            "type": "pipeline_failure", "severity": "Medium",
                            "title": f"Pipeline #{pipe.get('id')} failed",
                            "source": "gitlab_cicd",
                        })

        except Exception as e:
            log.error(f"[DevSecOps] GitLab scan error: {e}")
            results["error"] = str(e)

        results["stats"] = self._compute_stats(results["findings"])
        self.findings.extend(results["findings"])
        return results

    # ── Jenkins Integration ──────────────────────────────────────
    def check_jenkins_security(self) -> dict:
        """Check Jenkins for security issues and build status."""
        log.info("[DevSecOps] Checking Jenkins security...")
        results = {"findings": [], "builds": [], "stats": {}}

        if not JENKINS_URL:
            results["error"] = "JENKINS_URL not configured"
            return results

        try:
            import requests
            auth = (JENKINS_USER, JENKINS_TOKEN) if JENKINS_USER else None

            # 1. Get all jobs
            resp = requests.get(
                f"{JENKINS_URL}/api/json?tree=jobs[name,color,url,lastBuild[number,result,timestamp]]",
                auth=auth, timeout=10
            )
            if resp.status_code == 200:
                for job in resp.json().get("jobs", []):
                    build = job.get("lastBuild", {})
                    result = build.get("result", "UNKNOWN")
                    results["builds"].append({
                        "name": job.get("name"), "result": result,
                        "number": build.get("number"),
                    })
                    if result == "FAILURE":
                        results["findings"].append({
                            "type": "build_failure", "severity": "Medium",
                            "title": f"Build #{build.get('number')} failed: {job.get('name')}",
                            "source": "jenkins",
                        })

            # 2. Check security configuration
            sec_resp = requests.get(
                f"{JENKINS_URL}/configureSecurity/api/json",
                auth=auth, timeout=10
            )
            if sec_resp.status_code == 200:
                sec = sec_resp.json()
                if not sec.get("useSecurity"):
                    results["findings"].append({
                        "type": "config", "severity": "Critical",
                        "title": "Jenkins security is disabled",
                        "source": "jenkins",
                    })

        except Exception as e:
            log.error(f"[DevSecOps] Jenkins error: {e}")
            results["error"] = str(e)

        results["stats"] = self._compute_stats(results["findings"])
        self.findings.extend(results["findings"])
        return results

    # ── Code Scanner ─────────────────────────────────────────────
    def scan_local_path(self, path: str) -> dict:
        """Scan a local file or directory for vulnerabilities and secrets."""
        log.info(f"[DevSecOps] Scanning local path: {path}")
        results = {"path": path, "findings": [], "files_scanned": 0}

        scan_exts = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".sh",
                     ".yml", ".yaml", ".json", ".env", ".cfg", ".ini", ".conf",
                     ".tf", ".hcl", ".xml", ".html"}

        if os.path.isfile(path):
            with open(path, encoding="utf-8", errors="ignore") as f:
                content = f.read()
            results["findings"] = self._scan_content(content, path, "local")
            results["files_scanned"] = 1
        elif os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                # Skip common non-code dirs
                dirs[:] = [d for d in dirs if d not in (
                    ".git", "node_modules", "venv", "__pycache__", ".tox",
                    "dist", "build", ".cache", "vendor")]
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in scan_exts:
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        if os.path.getsize(fpath) > 100000:
                            continue
                        with open(fpath, encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        file_findings = self._scan_content(content, fpath, "local")
                        results["findings"].extend(file_findings)
                        results["files_scanned"] += 1
                    except Exception:
                        pass

        results["stats"] = self._compute_stats(results["findings"])
        self.findings.extend(results["findings"])
        log.info(f"[DevSecOps] ✅ Scanned {results['files_scanned']} files, "
                 f"{len(results['findings'])} findings")
        return results

    # ── CI/CD Pipeline Monitor ───────────────────────────────────
    def get_pipeline_status(self) -> dict:
        """Get aggregated CI/CD pipeline status across all integrations."""
        status = {
            "github_actions": [], "gitlab_pipelines": [],
            "jenkins_builds": [], "security_gates": [],
        }

        # Check GitHub Actions (if token available)
        if GITHUB_TOKEN:
            try:
                import requests
                headers = {"Authorization": f"Bearer {GITHUB_TOKEN}",
                           "Accept": "application/vnd.github+json"}
                resp = requests.get(
                    "https://api.github.com/user/repos?per_page=10&sort=updated",
                    headers=headers, timeout=10
                )
                if resp.status_code == 200:
                    for repo in resp.json():
                        run_resp = requests.get(
                            f"https://api.github.com/repos/{repo['full_name']}/actions/runs?per_page=1",
                            headers=headers, timeout=10
                        )
                        if run_resp.status_code == 200:
                            runs = run_resp.json().get("workflow_runs", [])
                            if runs:
                                status["github_actions"].append({
                                    "repo": repo["full_name"],
                                    "status": runs[0].get("conclusion", "pending"),
                                    "workflow": runs[0].get("name", ""),
                                })
            except Exception:
                pass

        return status

    # ── Internal Helpers ─────────────────────────────────────────
    def _scan_content(self, content: str, filepath: str, source: str) -> list:
        """Scan file content for secrets and code vulnerabilities."""
        findings = []
        lines = content.split("\n")

        # Secret detection
        for pattern in SECRET_PATTERNS:
            for i, line in enumerate(lines, 1):
                if re.search(pattern["regex"], line):
                    findings.append({
                        "type": "secret",
                        "severity": pattern["severity"],
                        "title": f"{pattern['name']} found in {os.path.basename(filepath)}",
                        "file": filepath,
                        "line": i,
                        "snippet": line.strip()[:100],
                        "source": source,
                    })

        # Code vulnerability detection
        for pattern in CODE_VULN_PATTERNS:
            for i, line in enumerate(lines, 1):
                if re.search(pattern["regex"], line):
                    findings.append({
                        "type": "code_vuln",
                        "severity": pattern["severity"],
                        "title": f"{pattern['name']} in {os.path.basename(filepath)}",
                        "file": filepath,
                        "line": i,
                        "cwe": pattern.get("cwe", ""),
                        "nist": pattern.get("nist", ""),
                        "snippet": line.strip()[:100],
                        "source": source,
                    })

        return findings

    def _compute_stats(self, findings: list) -> dict:
        """Compute finding statistics."""
        stats = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0,
                 "secrets": 0, "code_vulns": 0, "dependencies": 0}
        for f in findings:
            sev = f.get("severity", "Medium")
            if sev == "Critical":   stats["critical"] += 1
            elif sev == "High":     stats["high"] += 1
            elif sev == "Medium":   stats["medium"] += 1
            else:                   stats["low"] += 1
            if f.get("type") == "secret":       stats["secrets"] += 1
            elif f.get("type") == "code_vuln":  stats["code_vulns"] += 1
            elif f.get("type") == "dependency": stats["dependencies"] += 1
        return stats

    def get_all_findings(self) -> dict:
        """Return all accumulated findings."""
        return {
            "findings": self.findings,
            "stats": self._compute_stats(self.findings),
            "timestamp": self.timestamp,
        }
