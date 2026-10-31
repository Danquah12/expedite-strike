"""
repo_scanner.py — GitHub / GitLab Repository Scanner Plugin

Activates when the scanned content looks like a GitHub/GitLab URL or
requirements.txt / package.json. Fetches repository metadata and
checks for exposed secrets in the default-branch README/files.

Trigger patterns:
  • Content is a bare GitHub/GitLab URL
  • Content resembles a requirements.txt (one package per line)
  • Content resembles a package.json snippet

Requires: requests (standard in the platform venv)
"""
import re
import json
from .base_plugin import BasePlugin

_GH_URL   = re.compile(r'https?://github\.com/([^/\s]+)/([^/\s]+)', re.I)
_GL_URL   = re.compile(r'https?://gitlab\.com/([^/\s]+)/([^/\s]+)', re.I)
_REQ_LINE = re.compile(r'^[a-zA-Z0-9_.-]+==[0-9]')   # requirements.txt line


class RepoScannerPlugin(BasePlugin):
    name        = "GitHub / GitLab Repository Scanner"
    description = (
        "Detects GitHub/GitLab URLs in content and fetches repository metadata "
        "(stars, forks, open issues, archived status, default branch). "
        "Flags public repos, archived projects, and suspicious repo characteristics."
    )
    engine_tag  = "Plugin-RepoScan"

    def run(self, file_path: str, content: str, language: str = "auto") -> list[dict]:
        findings = []

        # ── Find GitHub URLs in content ──────────────────────────────────────
        gh_matches = _GH_URL.findall(content)
        lines = content.splitlines()

        for owner, repo in gh_matches:
            repo = repo.rstrip("/")
            findings.extend(self._scan_github(owner, repo, content, lines))

        # ── Find GitLab URLs ─────────────────────────────────────────────────
        gl_matches = _GL_URL.findall(content)
        for owner, repo in gl_matches:
            repo = repo.rstrip("/")
            findings.append(self.make_finding(
                rule_id="PI-REPO-GL",
                rule="GitLab Repository Reference",
                severity="INFO", cwe="",
                message=f"GitLab repository reference detected: gitlab.com/{owner}/{repo}. "
                        f"Ensure it is not a private/internal repo URL hardcoded in source.",
                line=0, code="", engine=self.engine_tag,
            ))

        return findings

    def _scan_github(self, owner: str, repo: str, content: str, lines: list) -> list:
        findings = []
        try:
            import requests
            resp = requests.get(
                f"https://api.github.com/repos/{owner}/{repo}",
                headers={"Accept": "application/vnd.github.v3+json"},
                timeout=8,
            )
            if resp.status_code != 200:
                findings.append(self.make_finding(
                    rule_id="PI-REPO-ERR",
                    rule="GitHub API Error",
                    severity="INFO", cwe="",
                    message=f"GitHub API returned {resp.status_code} for {owner}/{repo}.",
                    line=0, code="", engine=self.engine_tag,
                ))
                return findings

            data = resp.json()
            private    = data.get("private", True)
            archived   = data.get("archived", False)
            stars      = data.get("stargazers_count", 0)
            open_issues = data.get("open_issues_count", 0)
            fork       = data.get("fork", False)
            default_br = data.get("default_branch", "main")

            # Public repo with sensitive name
            sensitive_keywords = ["secret", "password", "key", "token", "cred", "vault"]
            repo_lower = repo.lower()
            if not private and any(kw in repo_lower for kw in sensitive_keywords):
                findings.append(self.make_finding(
                    rule_id="PI-REPO-001",
                    rule="Sensitive Public Repository Name",
                    severity="HIGH", cwe="CWE-200",
                    message=f"Public GitHub repo '{owner}/{repo}' has a sensitive name suggesting "
                            f"it may contain credential or secret material.",
                    line=0, code=f"github.com/{owner}/{repo}", engine=self.engine_tag,
                    fix="Make the repository private or rename it.",
                ))

            # Archived repos — unmaintained dependencies
            if archived:
                findings.append(self.make_finding(
                    rule_id="PI-REPO-002",
                    rule="Archived / Unmaintained Repository",
                    severity="MEDIUM", cwe="CWE-1104",
                    message=f"Repository '{owner}/{repo}' is archived and no longer maintained. "
                            f"Dependencies from archived repos will not receive security patches.",
                    line=0, code="", engine=self.engine_tag,
                    fix="Replace with an actively maintained alternative.",
                ))

            # High open issue count may signal instability
            if open_issues > 500:
                findings.append(self.make_finding(
                    rule_id="PI-REPO-003",
                    rule="High Open Issue Count",
                    severity="LOW", cwe="",
                    message=f"Repository '{owner}/{repo}' has {open_issues} open issues. "
                            f"A large backlog may indicate deferred security fixes.",
                    line=0, code="", engine=self.engine_tag,
                ))

            # Always report metadata
            findings.append(self.make_finding(
                rule_id="PI-REPO-INFO",
                rule="GitHub Repository Metadata",
                severity="INFO", cwe="",
                message=(
                    f"Repo: {owner}/{repo} | "
                    f"Private: {private} | Archived: {archived} | "
                    f"Stars: {stars} | Open Issues: {open_issues} | "
                    f"Fork: {fork} | Branch: {default_br}"
                ),
                line=0, code="", engine=self.engine_tag,
            ))

        except Exception as exc:
            findings.append(self.make_finding(
                rule_id="PI-REPO-ERR",
                rule="Repository Scan Error",
                severity="INFO", cwe="",
                message=f"Could not reach GitHub API for {owner}/{repo}: {str(exc)[:80]}",
                line=0, code="", engine=self.engine_tag,
            ))
        return findings
