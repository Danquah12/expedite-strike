"""
ui_supply_chain.py
Software Supply Chain Security Tab
SBOM Generation · Dependency Scanning · Typosquatting · License Compliance ·
Package Audit (npm/pip/maven/cargo) · Scorecard · AI Risk Analysis
"""
from __future__ import annotations

import subprocess
import threading
import time
from datetime import datetime

from dash import callback, dcc, html, Input, Output, State, ctx
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

try:
    from llm_engine import call_llm
except ImportError:
    def call_llm(prompt: str) -> str:
        return "LLM engine not available."

DARK_BG   = "#0d0d0d"
CARD_BG   = "#111317"
BORDER    = "1px solid #1e2230"
INPUT_STY = {"background": "#1a1d24", "border": BORDER, "color": "#e0e0e0",
             "borderRadius": "6px", "fontSize": "13px"}
BTN_SM    = {"borderRadius": "6px", "fontSize": "12px", "padding": "4px 10px"}
LABEL     = {"color": "#8e9eb0", "fontSize": "11px", "marginBottom": "4px",
             "fontWeight": "600", "textTransform": "uppercase", "letterSpacing": "0.5px"}
MONO      = {"fontFamily": "monospace", "fontSize": "11px"}

_OUTPUTS: dict[str, str] = {}
_LOCK     = threading.Lock()


def _card(*children, style=None):
    base = {"background": CARD_BG, "border": BORDER, "borderRadius": "10px",
            "padding": "16px", "marginBottom": "12px"}
    if style:
        base.update(style)
    return html.Div(children, style=base)

def _label(t): return html.Div(t, style=LABEL)
def _cmd(c):   return html.Div(c, style={**MONO, "color": "#50fa7b",
                                          "background": "#0d0d0d",
                                          "padding": "3px 8px",
                                          "borderRadius": "4px",
                                          "marginBottom": "3px"})

def _run_bg(cmd: str, key: str):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=90)
        out = r.stdout + ("\n[STDERR]\n" + r.stderr if r.stderr else "")
    except subprocess.TimeoutExpired:
        out = "[TIMEOUT] Command exceeded 90s"
    except Exception as e:
        out = f"[ERROR] {e}"
    with _LOCK:
        _OUTPUTS[key] = out


def _phase_card(phase_id: str, title: str, default_cmd: str):
    return _card(
        html.Div(title, style={"color": "#e0e0e0", "fontWeight": "600",
                               "marginBottom": "10px"}),
        _label("Command"),
        dbc.Textarea(id=f"sc-{phase_id}-cmd", value=default_cmd,
                     style={**INPUT_STY, "height": "200px",
                            "fontFamily": "monospace", "fontSize": "11px",
                            "marginBottom": "8px"}),
        dbc.Row([
            dbc.Col(dbc.Button("▶ Run", id=f"sc-{phase_id}-run",
                               color="danger", size="sm",
                               style={**BTN_SM, "width": "100%"}), width=4),
            dbc.Col(dbc.Button("✨ AI Analyse", id=f"sc-{phase_id}-ai",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%"}), width=4),
        ], style={"marginBottom": "8px"}),
        _label("Output"),
        dbc.Textarea(id=f"sc-{phase_id}-out", value="", readOnly=True,
                     style={**INPUT_STY, "height": "200px",
                            "fontFamily": "monospace", "fontSize": "11px",
                            "color": "#50fa7b", "marginBottom": "6px"}),
        html.Div(id=f"sc-{phase_id}-ai-out",
                 style={"color": "#b0b0b0", "fontSize": "12px",
                        "whiteSpace": "pre-wrap", "maxHeight": "200px",
                        "overflowY": "auto", "marginTop": "6px"}),
    )


def _sbom_cmd(target: str, fmt: str) -> str:
    t = target or "."
    if fmt == "grype":
        return f"""# ── Grype Dependency + Image Vulnerability Scan ──────────
# Scan a directory
grype dir:{t}

# Scan a container image
# grype python:3.11-slim

# JSON report
grype dir:{t} -o json > /tmp/grype_deps.json

# Only fixable/critical
grype dir:{t} --only-fixed --fail-on critical

# DB update
grype db update"""
    elif fmt == "cyclonedx":
        return f"""# ── CycloneDX SBOM Generation ────────────────────────────
# Python projects
cyclonedx-py poetry -o /tmp/sbom.cyclonedx.json
cyclonedx-py pip --requirements requirements.txt -o /tmp/sbom.json

# Node.js
cyclonedx-npm --output-format json --output-file /tmp/sbom.npm.json

# Java/Maven
mvn org.cyclonedx:cyclonedx-maven-plugin:makeBom
cat target/bom.json

# .NET
dotnet CycloneDX . -o /tmp/bom.xml"""
    else:  # syft (default)
        return f"""# ── Syft SBOM Generation ─────────────────────────────────
# Generate SBOM for a directory
syft {t} -o table

# SBOM in SPDX-JSON format (standard)
syft {t} -o spdx-json > /tmp/sbom.spdx.json

# CycloneDX format
syft {t} -o cyclonedx-json > /tmp/sbom.cdx.json

# Scan a container image
# syft ubuntu:22.04 -o table

# Then scan SBOM for vulnerabilities
grype sbom:/tmp/sbom.spdx.json

# SBOM attestation (cosign)
# cosign attest --type spdx --predicate /tmp/sbom.spdx.json IMAGE"""


def _pkg_audit_cmd(pm: str, path: str) -> str:
    p = path or "."
    if pm == "npm":
        return f"""# ── NPM Security Audit ───────────────────────────────────
cd {p}
npm audit
npm audit --json > /tmp/npm_audit.json

# Fix automatically
npm audit fix
npm audit fix --force  # Warning: may break semver!

# Check for outdated packages
npm outdated

# Detect typosquatting-prone packages
npm ls

# OSV-Scanner (Google)
osv-scanner --lockfile package-lock.json

# Snyk scan (requires login)
snyk test --json > /tmp/snyk_npm.json"""
    elif pm == "pip":
        return f"""# ── Python pip Security Audit ────────────────────────────
cd {p}
# pip-audit (recommended)
pip-audit -r requirements.txt
pip-audit -r requirements.txt -f json > /tmp/pip_audit.json

# safety (classic tool)
safety check -r requirements.txt

# OSV-Scanner
osv-scanner --lockfile requirements.txt

# Check for outdated packages
pip list --outdated

# Bandit (code security linter)
bandit -r {p} -f json > /tmp/bandit.json
bandit -r {p} -l -ii  # high severity only"""
    elif pm == "maven":
        return f"""# ── Maven Dependency Audit ───────────────────────────────
cd {p}
# OWASP Dependency-Check
mvn org.owasp:dependency-check-maven:check
cat target/dependency-check-report.html

# Check for outdated dependencies
mvn versions:display-dependency-updates

# OSV-Scanner on pom.xml
osv-scanner --lockfile pom.xml

# Trivy filesystem scan
trivy fs {p} --security-checks vuln"""
    else:  # cargo/rust
        return f"""# ── Rust/Cargo Security Audit ────────────────────────────
cd {p}
# cargo-audit (official)
cargo audit

# JSON output
cargo audit --json > /tmp/cargo_audit.json

# cargo-deny (policy engine)
cargo deny check advisories
cargo deny check licenses
cargo deny check bans

# OSV-Scanner
osv-scanner --lockfile Cargo.lock"""


def _typosquat_cmd(packages: str) -> str:
    pkgs = packages or "requests flask django numpy pandas"
    return f"""# ── Typosquatting Detection ──────────────────────────────
# Check for suspicious package names similar to popular packages:
# {pkgs}

# TypoSqueeze (Python tool)
pip install typogard
# typogard check requests flask django

# OSV-Scanner for known malicious packages
osv-scanner -r .

# Fake package detection via PyPI API
python3 -c "
import requests
packages = '{pkgs}'.split()
for pkg in packages:
    # Check PyPI for typosquatted variants
    variants = [pkg[:-1], pkg + 's', pkg.replace('-','_'), pkg.replace('_','-')]
    for v in variants:
        try:
            r = requests.get(f'https://pypi.org/pypi/{{v}}/json', timeout=5)
            if r.status_code == 200:
                data = r.json()
                print(f'[FOUND] {{v}} — {{data[\"info\"][\"author\"]}}')
        except:
            pass
"

# Check npm for suspicious packages
npm search {pkgs.split()[0]}

# Backstabber's Knife Collection (known malicious packages)
# https://github.com/colmmacc/backstabber-knife-collection"""


def _scorecard_cmd(repo: str) -> str:
    r = repo or "github.com/owner/repo"
    return f"""# ── OpenSSF Scorecard ────────────────────────────────────
# Checks security hygiene of open source projects

# Install
# go install sigs.k8s.io/release-utils/cmd/scorecard@latest
# Or: docker pull gcr.io/openssf/scorecard:stable

# Run scorecard
scorecard --repo={r}

# JSON output
scorecard --repo={r} --format=json > /tmp/scorecard.json

# Check specific checks
scorecard --repo={r} --checks=BranchProtection,CodeReview,DependencyUpdateTool

# Dependency Review via GitHub API (for GitHub repos)
gh api repos/{r.replace('github.com/','')} | jq '.security_and_analysis'

# SLSA provenance check
# slsa-verifier verify-artifact artifact.zip \\
#   --provenance-path provenance.intoto.jsonl \\
#   --source-uri {r}

# Sigstore cosign (verify image signatures)
cosign verify nginx:latest --certificate-identity-regexp=".*" \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com"""


def _license_cmd(path: str) -> str:
    p = path or "."
    return f"""# ── License Compliance Check ─────────────────────────────
cd {p}
# licensecheck (Python)
pip install licensecheck
licensecheck

# pip-licenses
pip install pip-licenses
pip-licenses --format=table
pip-licenses --format=json > /tmp/licenses.json

# npm license-checker
npx license-checker --summary
npx license-checker --json > /tmp/npm_licenses.json

# cargo-deny license check
cargo deny check licenses

# FOSSA (commercial, free tier)
fossa analyze
fossa test  # Fails CI if license policy violated

# SPDX compliance
# Check for GPL contamination (copyleft risk)
pip-licenses | grep -E "GPL|LGPL|AGPL|MPL"
npx license-checker | grep -E "GPL|LGPL|AGPL"

# Trivy license scanning
trivy fs {p} --security-checks license --ignored-unfixed"""


def layout() -> html.Div:
    return html.Div([
        dcc.Store(id="sc-state", data={}),

        html.Div([
            html.H4("🔗 Software Supply Chain Security",
                    style={"color": "#e0e0e0", "fontWeight": "700", "margin": "0"}),
            html.Div("SBOM · Dependency Scanning · Typosquatting · License Compliance · "
                     "OpenSSF Scorecard · AI Risk Analysis",
                     style={"color": "#636e72", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            # ── Left ────────────────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("🎯 Target Configuration",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "12px"}),
                    _label("Project Path"),
                    dbc.Input(id="sc-path", placeholder="/path/to/project",
                              value=".",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("SBOM Tool"),
                    dbc.Select(id="sc-sbom-tool",
                               options=[
                                   {"label": "Syft (recommended)", "value": "syft"},
                                   {"label": "Grype",              "value": "grype"},
                                   {"label": "CycloneDX",          "value": "cyclonedx"},
                               ], value="syft",
                               style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Package Manager"),
                    dbc.Select(id="sc-pm",
                               options=[
                                   {"label": "npm / Node.js",   "value": "npm"},
                                   {"label": "pip / Python",    "value": "pip"},
                                   {"label": "Maven / Java",    "value": "maven"},
                                   {"label": "Cargo / Rust",    "value": "cargo"},
                               ], value="pip",
                               style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Packages to Check (typosquat)"),
                    dbc.Textarea(id="sc-packages",
                                 placeholder="requests flask django",
                                 value="requests flask django numpy pandas",
                                 style={**INPUT_STY, "height": "60px",
                                        "marginBottom": "8px"}),
                    _label("Repo (scorecard)"),
                    dbc.Input(id="sc-repo",
                              placeholder="github.com/owner/repo",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    dbc.Button("🔄 Update Commands", id="sc-update-btn",
                               color="primary", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "4px"}),
                    html.Div(id="sc-update-status",
                             style={"color": "#636e72", "fontSize": "11px",
                                    "minHeight": "14px"}),
                ),
                _card(
                    html.Div("🤖 AI Analysis", style={"color": "#e0e0e0",
                                                        "fontWeight": "600",
                                                        "marginBottom": "10px"}),
                    dbc.Button("🔗 Attack Surface", id="sc-ai-attack",
                               color="outline-danger", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Button("📋 Remediation Plan", id="sc-ai-remed",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "8px"}),
                    html.Div(id="sc-ai-global",
                             style={"color": "#b0b0b0", "fontSize": "12px",
                                    "whiteSpace": "pre-wrap",
                                    "maxHeight": "300px", "overflowY": "auto"}),
                ),
            ], width=3),

            # ── Centre: Tabs ─────────────────────────────────────────────────
            dbc.Col([
                dbc.Tabs(id="sc-tabs", active_tab="sc-tab-sbom",
                         style={"marginBottom": "12px"},
                         children=[
                     dbc.Tab(label="📦 SBOM",          tab_id="sc-tab-sbom"),
                     dbc.Tab(label="🔍 Pkg Audit",     tab_id="sc-tab-pkg"),
                     dbc.Tab(label="😈 Typosquatting", tab_id="sc-tab-typo"),
                     dbc.Tab(label="📊 Scorecard",     tab_id="sc-tab-score"),
                     dbc.Tab(label="⚖️ Licenses",      tab_id="sc-tab-license"),
                 ]),
                html.Div(id="sc-phase-content"),
            ], width=6),

            # ── Right: Checklists ────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("✅ Supply Chain Checklist",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[html.Div([
                        html.Span("□ ", style={"color": "#636e72"}),
                        html.Span(item, style={"color": "#b0b0b0",
                                               "fontSize": "11px"}),
                      ], style={"marginBottom": "4px"})
                      for item in [
                          "SBOM generated for every release",
                          "No CRITICAL vulns in deps",
                          "Dependencies pinned (exact versions)",
                          "Lockfiles committed (package-lock.json)",
                          "Dependency update automation (Dependabot)",
                          "No GPL in proprietary product",
                          "No typosquatted packages",
                          "OpenSSF Scorecard ≥ 7/10",
                          "SLSA provenance level ≥ 2",
                          "Image signing (cosign/Sigstore)",
                          "Private package registry used",
                          "Build pipeline integrity verified",
                          "Secrets not in source code",
                          "git-secrets pre-commit hook",
                      ]],
                ),
                _card(
                    html.Div("🎯 Known Attack Patterns",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[html.Div([
                        html.Span("⚠ ", style={"color": "#e67e22",
                                                "fontWeight": "700"}),
                        html.Span(a, style={"color": "#b0b0b0",
                                            "fontSize": "11px"}),
                      ], style={"marginBottom": "5px"})
                      for a in [
                          "Typosquatting (reqeusts vs requests)",
                          "Dependency confusion attacks",
                          "Compromised maintainer accounts",
                          "Malicious pre/post-install scripts",
                          "Protestware (sabotage by author)",
                          "XZ Utils-style backdoor injection",
                          "CI/CD pipeline compromise",
                          "Git tag manipulation",
                          "Artifact registry poisoning",
                      ]],
                ),
                _card(
                    html.Div("📋 Quick Commands",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[_cmd(c) for c in [
                        "syft . -o table",
                        "grype dir:.",
                        "pip-audit -r requirements.txt",
                        "npm audit",
                        "cargo audit",
                        "scorecard --repo=owner/repo",
                        "pip-licenses --format=table",
                        "osv-scanner -r .",
                        "git-secrets --scan",
                    ]],
                ),
            ], width=3),
        ]),
    ], style={"background": DARK_BG, "minHeight": "100vh", "padding": "24px"})


@callback(
    Output("sc-phase-content", "children"),
    Output("sc-update-status", "children"),
    Input("sc-tabs",           "active_tab"),
    Input("sc-update-btn",     "n_clicks"),
    State("sc-path",           "value"),
    State("sc-sbom-tool",      "value"),
    State("sc-pm",             "value"),
    State("sc-packages",       "value"),
    State("sc-repo",           "value"),
)
def render_phase(tab, upd_n, path, sbom_tool, pm, packages, repo):
    status = f"✅ Updated — {datetime.now().strftime('%H:%M:%S')}" if upd_n else ""
    path   = path or "."
    if tab == "sc-tab-sbom":
        content = _phase_card("sbom",    "📦 SBOM Generation",   _sbom_cmd(path, sbom_tool or "syft"))
    elif tab == "sc-tab-pkg":
        content = _phase_card("pkg",     "🔍 Package Audit",     _pkg_audit_cmd(pm or "pip", path))
    elif tab == "sc-tab-typo":
        content = _phase_card("typo",    "😈 Typosquatting",     _typosquat_cmd(packages or ""))
    elif tab == "sc-tab-score":
        content = _phase_card("score",   "📊 OpenSSF Scorecard", _scorecard_cmd(repo or ""))
    elif tab == "sc-tab-license":
        content = _phase_card("license", "⚖️ License Compliance", _license_cmd(path))
    else:
        content = html.Div()
    return content, status


def _make_callbacks(phase_id: str, label: str):
    @callback(
        Output(f"sc-{phase_id}-out",    "value"),
        Input(f"sc-{phase_id}-run",     "n_clicks"),
        State(f"sc-{phase_id}-cmd",     "value"),
        prevent_initial_call=True,
    )
    def run_ph(n, cmd, _pid=phase_id):
        if not n or not cmd:
            raise PreventUpdate
        threading.Thread(target=_run_bg, args=(cmd, _pid), daemon=True).start()
        time.sleep(5)
        with _LOCK:
            return _OUTPUTS.get(_pid, "[Running…]")
    run_ph.__name__ = f"sc_run_{phase_id}"

    @callback(
        Output(f"sc-{phase_id}-ai-out", "children"),
        Input(f"sc-{phase_id}-ai",      "n_clicks"),
        State(f"sc-{phase_id}-out",     "value"),
        prevent_initial_call=True,
    )
    def ai_ph(n, output, _lbl=label):
        if not n:
            raise PreventUpdate
        prompt = (
            f"Supply Chain Security — {_lbl} analysis:\n\n"
            f"{output or '(no output)'}\n\n"
            f"Identify:\n"
            f"1) **Vulnerabilities** with CVE IDs and CVSS scores\n"
            f"2) **Malicious packages** or suspicious indicators\n"
            f"3) **License risks** (copyleft contamination)\n"
            f"4) **Remediation** — specific upgrade commands\n"
            f"5) **Risk Rating** and business impact"
        )
        try:
            return call_llm(prompt)
        except Exception as e:
            return f"LLM error: {e}"
    ai_ph.__name__ = f"sc_ai_{phase_id}"


for _pid, _lbl in [
    ("sbom",    "SBOM Generation"),
    ("pkg",     "Package Audit"),
    ("typo",    "Typosquatting Detection"),
    ("score",   "OpenSSF Scorecard"),
    ("license", "License Compliance"),
]:
    _make_callbacks(_pid, _lbl)


@callback(
    Output("sc-ai-global", "children"),
    Input("sc-ai-attack",  "n_clicks"),
    Input("sc-ai-remed",   "n_clicks"),
    State("sc-path",       "value"),
    prevent_initial_call=True,
)
def global_ai(attack_n, remed_n, path):
    if not ctx.triggered_id:
        raise PreventUpdate
    with _LOCK:
        all_out = "\n\n".join(f"[{k.upper()}]\n{v[:400]}"
                               for k, v in _OUTPUTS.items())
    tid = ctx.triggered_id
    if tid == "sc-ai-attack":
        prompt = (
            f"Supply chain attack surface analysis for project at {path or '.'}:\n\n"
            f"{all_out}\n\n"
            f"Map full attack paths:\n"
            f"1) **Worst-case scenario** if a dep is compromised\n"
            f"2) **Blast radius** — what systems/users affected?\n"
            f"3) **Real-world parallels** (SolarWinds, XZ Utils, etc.)\n"
            f"4) **Detection** — how would you detect a compromise?\n"
            f"5) **Prevention** — policy changes to prevent"
        )
    else:
        prompt = (
            f"Supply chain remediation plan for project at {path or '.'}:\n\n"
            f"{all_out}\n\n"
            f"Provide a prioritized remediation plan:\n"
            f"1) **Immediate** (today): critical fixes with exact commands\n"
            f"2) **Short-term** (this week): policy changes\n"
            f"3) **Long-term** (this month): process improvements\n"
            f"4) **Automation** to prevent recurrence\n"
            f"5) **Monitoring** — ongoing alerts and checks"
        )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"
