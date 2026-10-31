"""
vercel_sync.py
==============
Expedite Strike - Vercel / GitHub Deployment Sync Utility

Provides helpers to:
  1. Trigger a Vercel production deployment (via Vercel REST API or CLI)
  2. Push report artifacts (PDF, JSON, heatmap) to a GitHub repo
  3. Check current deployment status / latest deployment URL
  4. Optionally post a deployment summary comment to a GitHub PR

Configuration:
    Set environment variables (or pass explicitly):
      VERCEL_TOKEN         - Vercel personal access token
      VERCEL_PROJECT_ID    - Vercel project ID (not name)
      VERCEL_TEAM_ID       - Optional: Vercel team ID
      GITHUB_TOKEN         - GitHub personal access token
      GITHUB_REPO          - owner/repo  e.g. "expedite-consults/aegis-reports"
      GITHUB_BRANCH        - Branch to push artifacts to (default: "reports")

Usage:
    from cyber_range.services.vercel_sync import VercelSync

    # Trigger a fresh production deploy
    result = VercelSync.trigger_deployment()
    print(result["url"])       # e.g. https://aegis-xxxxxx.vercel.app

    # Push PDF to GitHub
    VercelSync.push_artifact_to_github(
        file_bytes=open("report.pdf","rb").read(),
        filename="reports/2026/acme_report_20260829.pdf",
        commit_message="chore: add Acme pentest report Aug-2026",
    )

    # Check deployment status
    status = VercelSync.get_deployment_status()
    print(status["state"])    # READY | BUILDING | ERROR | CANCELED
"""

import base64
import json
import os
import time
import urllib.request
import urllib.error
from datetime import datetime
from typing import Any, Dict, Optional

# ── Config from env (can also be passed per-call) ────────────────────────────
_VERCEL_TOKEN      = os.getenv("VERCEL_TOKEN", "")
_VERCEL_PROJECT_ID = os.getenv("VERCEL_PROJECT_ID", "")
_VERCEL_TEAM_ID    = os.getenv("VERCEL_TEAM_ID", "")
_GITHUB_TOKEN      = os.getenv("GITHUB_TOKEN", "")
_GITHUB_REPO       = os.getenv("GITHUB_REPO", "")       # e.g. "expedite-consults/aegis"
_GITHUB_BRANCH     = os.getenv("GITHUB_BRANCH", "reports")

_VERCEL_API_BASE   = "https://api.vercel.com"
_GITHUB_API_BASE   = "https://api.github.com"


def _http(
    url: str,
    method: str = "GET",
    headers: Optional[Dict] = None,
    body: Optional[bytes] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """Thin urllib wrapper returning {status, data}."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                return {"status": resp.status, "data": json.loads(raw), "raw": raw}
            except Exception:
                return {"status": resp.status, "data": {}, "raw": raw}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return {"status": e.code, "data": json.loads(raw), "raw": raw, "error": str(e)}
        except Exception:
            return {"status": e.code, "data": {}, "raw": raw, "error": str(e)}
    except Exception as exc:
        return {"status": 0, "data": {}, "raw": b"", "error": str(exc)}


class VercelSync:
    """Utility class for Vercel deployments and GitHub artifact sync."""

    # ── VERCEL ────────────────────────────────────────────────────────────────

    @classmethod
    def trigger_deployment(
        cls,
        token: str = "",
        project_id: str = "",
        team_id: str = "",
        target: str = "production",
        force: bool = True,
    ) -> Dict[str, Any]:
        """
        Trigger a new Vercel deployment.

        Args:
            token:      Vercel API token (overrides VERCEL_TOKEN env var).
            project_id: Vercel project ID (overrides VERCEL_PROJECT_ID env var).
            team_id:    Vercel team ID (optional).
            target:     "production" or "preview".
            force:      Force a new build even if nothing changed.

        Returns dict with keys: deployment_id, url, state, created_at, error (if any).
        """
        tok  = token      or _VERCEL_TOKEN
        pid  = project_id or _VERCEL_PROJECT_ID
        tid  = team_id    or _VERCEL_TEAM_ID

        if not tok or not pid:
            return {
                "error": "VERCEL_TOKEN and VERCEL_PROJECT_ID must be set.",
                "deployment_id": None, "url": None, "state": "unconfigured",
            }

        url = f"{_VERCEL_API_BASE}/v13/deployments"
        if tid:
            url += f"?teamId={tid}"

        payload = json.dumps({
            "name":   pid,
            "target": target,
            "source": "api",
            **({"force": True} if force else {}),
        }).encode()

        resp = _http(url, method="POST", headers={
            "Authorization": f"Bearer {tok}",
            "Content-Type":  "application/json",
        }, body=payload)

        data = resp.get("data", {})
        if resp.get("status", 0) not in (200, 201):
            return {
                "error": data.get("error", {}).get("message", resp.get("error", "Unknown error")),
                "deployment_id": None, "url": None, "state": "error",
            }

        return {
            "deployment_id": data.get("id"),
            "url":           f"https://{data.get('url', '')}",
            "state":         data.get("readyState", "BUILDING"),
            "created_at":    data.get("createdAt"),
            "error":         None,
        }

    @classmethod
    def get_deployment_status(
        cls,
        deployment_id: str = "",
        token: str = "",
        team_id: str = "",
    ) -> Dict[str, Any]:
        """
        Fetch current status of a specific deployment, or the latest production deployment.

        Returns dict with: deployment_id, url, state, created_at, ready_at, error.
        """
        tok = token   or _VERCEL_TOKEN
        tid = team_id or _VERCEL_TEAM_ID
        pid = _VERCEL_PROJECT_ID

        if not tok:
            return {"error": "VERCEL_TOKEN not configured.", "state": "unconfigured"}

        if deployment_id:
            url = f"{_VERCEL_API_BASE}/v13/deployments/{deployment_id}"
            if tid:
                url += f"?teamId={tid}"
        else:
            # Get latest production deployment for the project
            url = f"{_VERCEL_API_BASE}/v6/deployments?projectId={pid}&target=production&limit=1"
            if tid:
                url += f"&teamId={tid}"

        resp = _http(url, headers={"Authorization": f"Bearer {tok}"})
        data = resp.get("data", {})

        if resp.get("status", 0) != 200:
            return {"error": data.get("error", {}).get("message", "Request failed"), "state": "error"}

        # /v6/deployments returns a list inside "deployments"
        if "deployments" in data:
            deploys = data["deployments"]
            if not deploys:
                return {"error": "No deployments found.", "state": "none"}
            data = deploys[0]

        return {
            "deployment_id": data.get("uid") or data.get("id"),
            "url":           f"https://{data.get('url', '')}",
            "state":         data.get("readyState") or data.get("state", "UNKNOWN"),
            "created_at":    data.get("createdAt"),
            "ready_at":      data.get("ready"),
            "error":         None,
        }

    @classmethod
    def wait_for_deployment(
        cls,
        deployment_id: str,
        token: str = "",
        team_id: str = "",
        timeout_s: int = 300,
        poll_interval: int = 10,
    ) -> Dict[str, Any]:
        """
        Poll until the deployment reaches READY or ERROR (or timeout).
        Returns the final status dict.
        """
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            status = cls.get_deployment_status(deployment_id, token=token, team_id=team_id)
            state = status.get("state", "")
            if state in ("READY", "ERROR", "CANCELED"):
                return status
            time.sleep(poll_interval)
        return {**status, "error": "Deployment timed out."}

    # ── GITHUB ────────────────────────────────────────────────────────────────

    @classmethod
    def push_artifact_to_github(
        cls,
        file_bytes: bytes,
        filename: str,
        commit_message: str = "",
        token: str = "",
        repo: str = "",
        branch: str = "",
    ) -> Dict[str, Any]:
        """
        Push a binary artifact to a GitHub repository via the Contents API.
        Creates or updates the file at the given path.

        Args:
            file_bytes:     Raw bytes of the file to upload.
            filename:       Path inside the repo, e.g. "reports/acme_20260829.pdf".
            commit_message: Git commit message.
            token:          GitHub personal access token (overrides GITHUB_TOKEN).
            repo:           "owner/repo" (overrides GITHUB_REPO).
            branch:         Target branch (overrides GITHUB_BRANCH, default "reports").

        Returns dict with: html_url, sha, commit_sha, error (if any).
        """
        tok    = token  or _GITHUB_TOKEN
        rep    = repo   or _GITHUB_REPO
        br     = branch or _GITHUB_BRANCH

        if not tok or not rep:
            return {"error": "GITHUB_TOKEN and GITHUB_REPO must be set.", "html_url": None}

        url    = f"{_GITHUB_API_BASE}/repos/{rep}/contents/{filename}"
        b64    = base64.b64encode(file_bytes).decode()
        msg    = commit_message or f"chore: upload {filename} [{datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}]"
        headers = {
            "Authorization": f"token {tok}",
            "Accept":        "application/vnd.github+json",
            "Content-Type":  "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        # Check if file already exists (need SHA for updates)
        existing_sha = None
        check = _http(url + f"?ref={br}", headers=headers)
        if check.get("status") == 200:
            existing_sha = check["data"].get("sha")

        body_dict: Dict[str, Any] = {"message": msg, "content": b64, "branch": br}
        if existing_sha:
            body_dict["sha"] = existing_sha

        resp = _http(url, method="PUT", headers=headers,
                     body=json.dumps(body_dict).encode())
        data = resp.get("data", {})

        if resp.get("status", 0) not in (200, 201):
            return {
                "error":    data.get("message", resp.get("error", "Unknown error")),
                "html_url": None, "sha": None,
            }

        return {
            "html_url":   data.get("content", {}).get("html_url"),
            "sha":        data.get("content", {}).get("sha"),
            "commit_sha": data.get("commit", {}).get("sha"),
            "error":      None,
        }

    @classmethod
    def create_branch_if_missing(
        cls,
        branch: str,
        base_branch: str = "main",
        token: str = "",
        repo: str = "",
    ) -> bool:
        """Create the target branch if it does not already exist. Returns True on success."""
        tok = token or _GITHUB_TOKEN
        rep = repo  or _GITHUB_REPO
        if not tok or not rep:
            return False

        headers = {
            "Authorization": f"token {tok}",
            "Accept":        "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        # Check if branch exists
        check = _http(f"{_GITHUB_API_BASE}/repos/{rep}/branches/{branch}", headers=headers)
        if check.get("status") == 200:
            return True  # Already exists

        # Get SHA of base branch HEAD
        base_resp = _http(f"{_GITHUB_API_BASE}/repos/{rep}/branches/{base_branch}", headers=headers)
        if base_resp.get("status") != 200:
            return False
        sha = base_resp["data"].get("commit", {}).get("sha", "")
        if not sha:
            return False

        # Create branch
        body = json.dumps({"ref": f"refs/heads/{branch}", "sha": sha}).encode()
        create = _http(f"{_GITHUB_API_BASE}/repos/{rep}/git/refs",
                       method="POST", headers=headers, body=body)
        return create.get("status") in (200, 201)

    @classmethod
    def push_evidence_bundle(
        cls,
        pdf_bytes: Optional[bytes] = None,
        findings_json: Optional[dict] = None,
        heatmap_png: Optional[bytes] = None,
        scan_id: str = "",
        workspace_name: str = "engagement",
        token: str = "",
        repo: str = "",
        branch: str = "",
    ) -> Dict[str, Any]:
        """
        High-level helper: push a complete evidence bundle (PDF + JSON + PNG)
        to GitHub in a single call. Creates the branch if missing.

        Returns dict of {pdf, json, png} push results.
        """
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_ws  = workspace_name.lower().replace(" ", "_").replace("/", "-")[:32]
        br       = branch or _GITHUB_BRANCH or "reports"
        results  = {}

        # Create branch if needed
        cls.create_branch_if_missing(br, token=token, repo=repo)

        if pdf_bytes:
            results["pdf"] = cls.push_artifact_to_github(
                pdf_bytes, f"reports/{safe_ws}/pentest_report_{ts}.pdf",
                commit_message=f"feat: {safe_ws} pentest report {ts}",
                token=token, repo=repo, branch=br,
            )

        if findings_json:
            raw = json.dumps(findings_json, indent=2, default=str).encode()
            results["json"] = cls.push_artifact_to_github(
                raw, f"reports/{safe_ws}/raw_findings_{ts}.json",
                commit_message=f"chore: {safe_ws} raw findings {ts}",
                token=token, repo=repo, branch=br,
            )

        if heatmap_png:
            results["png"] = cls.push_artifact_to_github(
                heatmap_png, f"reports/{safe_ws}/mitre_heatmap_{ts}.png",
                commit_message=f"chore: {safe_ws} MITRE heatmap {ts}",
                token=token, repo=repo, branch=br,
            )

        return results

    @classmethod
    def get_config_status(cls) -> Dict[str, Any]:
        """Returns the configuration state (which env vars are set, without leaking values)."""
        return {
            "vercel_token_set":      bool(_VERCEL_TOKEN),
            "vercel_project_id_set": bool(_VERCEL_PROJECT_ID),
            "vercel_team_id_set":    bool(_VERCEL_TEAM_ID),
            "github_token_set":      bool(_GITHUB_TOKEN),
            "github_repo":           _GITHUB_REPO or "(not set)",
            "github_branch":         _GITHUB_BRANCH or "(not set)",
        }
