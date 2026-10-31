"""
ui_container_security.py
Container & Kubernetes Security Tab
Image Scanning · K8s RBAC Audit · Kubescape · Falco Alerts · Runtime Analysis · AI Threat Analysis
"""
from __future__ import annotations

import subprocess
import threading
import time
from datetime import datetime
from typing import Any

from dash import callback, dcc, html, Input, Output, State, ctx
from dash.exceptions import PreventUpdate
import dash_bootstrap_components as dbc

try:
    from llm_engine import call_llm
except ImportError:
    def call_llm(prompt: str) -> str:
        return "LLM engine not available."

# ── Styling ───────────────────────────────────────────────────────────────────
DARK_BG   = "#0d0d0d"
CARD_BG   = "#111317"
BORDER    = "1px solid #1e2230"
INPUT_STY = {"background": "#1a1d24", "border": BORDER, "color": "#e0e0e0",
             "borderRadius": "6px", "fontSize": "13px"}
BTN_SM    = {"borderRadius": "6px", "fontSize": "12px", "padding": "4px 10px"}
LABEL     = {"color": "#8e9eb0", "fontSize": "11px", "marginBottom": "4px",
             "fontWeight": "600", "textTransform": "uppercase", "letterSpacing": "0.5px"}
MONO      = {"fontFamily": "monospace", "fontSize": "11px"}
SEV_CLR   = {"CRITICAL": "#c0392b", "HIGH": "#e67e22",
             "MEDIUM": "#f1c40f",   "LOW": "#27ae60", "UNKNOWN": "#636e72"}

# ── In-memory ────────────────────────────────────────────────────────────────
_OUTPUTS: dict[str, str] = {}
_LOCK     = threading.Lock()

# ── Helpers ──────────────────────────────────────────────────────────────────
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


def _phase_card(phase_id: str, title: str, default_cmd: str, extra_inputs=None):
    return _card(
        html.Div(title, style={"color": "#e0e0e0", "fontWeight": "600",
                               "marginBottom": "10px"}),
        *(extra_inputs or []),
        _label("Command"),
        dbc.Textarea(id=f"cs-{phase_id}-cmd", value=default_cmd,
                     style={**INPUT_STY, "height": "180px",
                            "fontFamily": "monospace", "fontSize": "11px",
                            "marginBottom": "8px"}),
        dbc.Row([
            dbc.Col(dbc.Button("▶ Run", id=f"cs-{phase_id}-run",
                               color="danger", size="sm",
                               style={**BTN_SM, "width": "100%"}), width=4),
            dbc.Col(dbc.Button("✨ AI Analyse", id=f"cs-{phase_id}-ai",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%"}), width=4),
            dbc.Col(dbc.Button("📋 Save", id=f"cs-{phase_id}-save",
                               color="outline-warning", size="sm",
                               style={**BTN_SM, "width": "100%"}), width=4),
        ], style={"marginBottom": "8px"}),
        _label("Output"),
        dbc.Textarea(id=f"cs-{phase_id}-out", value="", readOnly=True,
                     style={**INPUT_STY, "height": "200px",
                            "fontFamily": "monospace", "fontSize": "11px",
                            "color": "#50fa7b", "marginBottom": "6px"}),
        html.Div(id=f"cs-{phase_id}-ai-out",
                 style={"color": "#b0b0b0", "fontSize": "12px",
                        "whiteSpace": "pre-wrap", "maxHeight": "200px",
                        "overflowY": "auto", "marginTop": "6px"}),
    )


# ── Command builders ──────────────────────────────────────────────────────────
def _img_scan_cmd(image: str, scanner: str) -> str:
    img = image or "nginx:latest"
    if scanner == "grype":
        return f"""# ── Grype Image Vulnerability Scan ──────────────────────
grype {img} -o table

# JSON output (for parsing)
grype {img} -o json > /tmp/grype_report.json

# Only show fixable vulns
grype {img} --only-fixed

# Scan a local tarball
# grype docker-archive:/path/to/image.tar"""
    elif scanner == "syft":
        return f"""# ── Syft SBOM Generation ─────────────────────────────
syft {img} -o table

# Generate SBOM in SPDX format
syft {img} -o spdx-json > /tmp/sbom.spdx.json

# CycloneDX format
syft {img} -o cyclonedx-json > /tmp/sbom.cyclonedx.json

# Then scan SBOM with grype
grype sbom:/tmp/sbom.spdx.json"""
    else:  # trivy (default)
        return f"""# ── Trivy Image Vulnerability Scan ─────────────────────
trivy image {img}

# Table format with severity filter
trivy image --severity CRITICAL,HIGH {img}

# JSON output
trivy image -f json -o /tmp/trivy_report.json {img}

# Scan filesystem
trivy fs / --severity CRITICAL,HIGH

# Check container misconfigurations
trivy image --security-checks config {img}

# Scan OCI archive
# trivy image --input /path/to/image.tar"""


def _k8s_audit_cmd(namespace: str, context: str) -> str:
    ns = namespace or "default"
    ctx_flag = f"--context {context}" if context and context != "current" else ""
    return f"""# ── Kubernetes Security Audit ────────────────────────────
# 1. Cluster info
kubectl cluster-info {ctx_flag}
kubectl get nodes -o wide {ctx_flag}

# 2. RBAC — over-privileged roles
kubectl get clusterrolebindings {ctx_flag} -o json | \\
  jq '.items[] | select(.roleRef.name == "cluster-admin") | .subjects'

# 3. Pods running as root
kubectl get pods -n {ns} {ctx_flag} -o json | \\
  jq '.items[] | .metadata.name + " " + (.spec.containers[].securityContext.runAsUser // "root" | tostring)'

# 4. Service accounts with mounted tokens
kubectl get serviceaccounts -n {ns} {ctx_flag}
kubectl describe serviceaccount default -n {ns} {ctx_flag}

# 5. Privileged containers
kubectl get pods -n {ns} {ctx_flag} -o json | \\
  jq '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.name'

# 6. Exposed services (LoadBalancer / NodePort)
kubectl get services -A {ctx_flag} | grep -E "LoadBalancer|NodePort"

# 7. Network policies
kubectl get networkpolicies -A {ctx_flag}

# 8. Pod security standards
kubectl get pods -n {ns} {ctx_flag} -o json | \\
  jq '.items[].metadata.name'

# 9. Secrets in env vars
kubectl get pods -n {ns} {ctx_flag} -o json | \\
  jq '[.items[].spec.containers[].env[]? | select(.valueFrom.secretKeyRef) | .name]'

# 10. Audit logs
kubectl get events -n {ns} {ctx_flag} --sort-by='.lastTimestamp' | tail -20"""


def _kubescape_cmd(target: str) -> str:
    t = target or "cluster"
    return f"""# ── Kubescape Compliance Scanner ─────────────────────────
# Install: curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash

# Scan entire cluster against NSA+CISA framework
kubescape scan framework nsa --submit

# Scan against MITRE ATT&CK
kubescape scan framework mitre

# Scan against CIS Kubernetes Benchmark
kubescape scan framework cis-v1.23-t1.0.1

# Scan specific namespace
kubescape scan --namespace {t}

# Scan YAML manifests before deployment
kubescape scan ./k8s-manifests/

# Output as HTML report
kubescape scan framework nsa -f html -o kubescape_report.html

# List all controls
kubescape list controls --frameworks nsa

# Scan specific control
kubescape scan control C-0017  # Immutable container filesystem"""


def _falco_cmd() -> str:
    return """# ── Falco Runtime Security ───────────────────────────────
# Install: helm install falco falcosecurity/falco

# Start Falco
sudo falco -r /etc/falco/falco_rules.yaml

# View alerts
sudo journalctl -u falco -f

# Sample rules to write (falco_rules.local.yaml):
# --- Detect shell in container ---
# - rule: Terminal shell in container
#   desc: A shell was used as the entrypoint/exec point into a container
#   condition: >
#     spawned_process and container and shell_procs and proc.tty != 0
#     and container_entrypoint
#   output: >
#     A shell was spawned in a container with an attached terminal (user=%user.name
#     %container.info shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
#   priority: NOTICE

# Detect crypto mining
falco -r /etc/falco/falco_rules.yaml -M 60 2>&1 | grep -i "crypto\\|miner\\|xmr"

# Detect privilege escalation
falco -r /etc/falco/falco_rules.yaml 2>&1 | grep -i "privilege\\|setuid\\|sudo"

# Export to syslog
falco --out-format=json | logger -t falco

# Falcosidekick (forward to SIEM/Slack/Teams)
helm install falcosidekick falcosecurity/falcosidekick \\
  --set config.slack.webhookurl=YOUR_WEBHOOK"""


def _escape_cmd(container_id: str) -> str:
    cid = container_id or "$(docker ps -q | head -1)"
    return f"""# ── Container Escape & Hardening Checks ──────────────────
# 1. Check container capabilities
docker inspect {cid} | jq '.[0].HostConfig.CapAdd'

# 2. Check if privileged
docker inspect {cid} | jq '.[0].HostConfig.Privileged'

# 3. Mounted Docker socket (escape vector!)
docker inspect {cid} | jq '.[0].Mounts[] | select(.Source == "/var/run/docker.sock")'

# 4. Check namespace sharing (hostPID, hostNetwork)
docker inspect {cid} | jq '.[0].HostConfig | {{pid: .PidMode, net: .NetworkMode, ipc: .IpcMode}}'

# 5. Read-only root filesystem
docker inspect {cid} | jq '.[0].HostConfig.ReadonlyRootfs'

# 6. User namespace mapping
docker inspect {cid} | jq '.[0].HostConfig.UsernsMode'

# 7. AppArmor / seccomp profiles
docker inspect {cid} | jq '.[0].HostConfig | {{apparmor: .SecurityOpt, seccomp: .SecurityOpt}}'

# 8. Check for breakout via /proc
cat /proc/1/cgroup  # If shows host PID, container may be breakable

# 9. Scan with Deepce (container escape tool)
# curl -sL https://github.com/stealthcopter/deepce/raw/main/deepce.sh | sh

# 10. Dockerfile best practices
docker run --rm -i hadolint/hadolint < Dockerfile"""


# ── Layout ────────────────────────────────────────────────────────────────────
def layout() -> html.Div:
    return html.Div([
        dcc.Store(id="cs-state", data={}),

        # Header
        html.Div([
            html.H4("📦 Container & Kubernetes Security",
                    style={"color": "#e0e0e0", "fontWeight": "700", "margin": "0"}),
            html.Div("Image Scanning (Trivy/Grype/Syft) · K8s RBAC Audit · "
                     "Kubescape · Falco Runtime · Container Escape · AI Analysis",
                     style={"color": "#636e72", "fontSize": "13px"}),
        ], style={"marginBottom": "16px"}),

        dbc.Row([
            # ── Left: Target Config ──────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("🎯 Target Configuration",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "12px"}),
                    _label("Container Image"),
                    dbc.Input(id="cs-image", placeholder="nginx:latest",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Scanner"),
                    dbc.Select(id="cs-scanner",
                               options=[
                                   {"label": "Trivy (recommended)", "value": "trivy"},
                                   {"label": "Grype",               "value": "grype"},
                                   {"label": "Syft (SBOM)",         "value": "syft"},
                               ], value="trivy",
                               style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("K8s Namespace"),
                    dbc.Input(id="cs-namespace", placeholder="default",
                              value="default",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("K8s Context"),
                    dbc.Input(id="cs-context", placeholder="current / minikube",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    _label("Container ID"),
                    dbc.Input(id="cs-container-id",
                              placeholder="docker ps -q | head -1",
                              style={**INPUT_STY, "marginBottom": "8px"}),
                    dbc.Button("🔄 Update Commands", id="cs-update-btn",
                               color="primary", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "4px"}),
                    html.Div(id="cs-update-status",
                             style={"color": "#636e72", "fontSize": "11px",
                                    "minHeight": "14px"}),
                ),

                _card(
                    html.Div("📋 Quick Reference",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[_cmd(c) for c in [
                        "trivy image nginx:latest",
                        "grype nginx:latest",
                        "syft nginx:latest -o table",
                        "kubescape scan framework nsa",
                        "kubectl get clusterrolebindings",
                        "kubectl auth can-i --list",
                        "falco -r /etc/falco/falco_rules.yaml",
                        "docker inspect <id> | jq .[0].HostConfig",
                        "hadolint Dockerfile",
                    ]],
                ),

                _card(
                    html.Div("🤖 AI Analysis",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    dbc.Button("⚠ Risk Summary", id="cs-ai-risk",
                               color="outline-danger", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Button("🛡️ Hardening Guide", id="cs-ai-harden",
                               color="outline-info", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "6px"}),
                    dbc.Button("⛓️ Attack Paths", id="cs-ai-attack",
                               color="outline-warning", size="sm",
                               style={**BTN_SM, "width": "100%",
                                      "marginBottom": "8px"}),
                    html.Div(id="cs-ai-global",
                             style={"color": "#b0b0b0", "fontSize": "12px",
                                    "whiteSpace": "pre-wrap",
                                    "maxHeight": "300px", "overflowY": "auto"}),
                ),
            ], width=3),

            # ── Centre: Phase tabs ───────────────────────────────────────────
            dbc.Col([
                dbc.Tabs(id="cs-tabs", active_tab="cs-tab-image",
                         style={"marginBottom": "12px"},
                         children=[
                     dbc.Tab(label="🔍 Image Scan",      tab_id="cs-tab-image"),
                     dbc.Tab(label="⚙️ K8s Audit",       tab_id="cs-tab-k8s"),
                     dbc.Tab(label="📊 Kubescape",       tab_id="cs-tab-kube"),
                     dbc.Tab(label="🚨 Falco Runtime",   tab_id="cs-tab-falco"),
                     dbc.Tab(label="🔓 Escape Checks",   tab_id="cs-tab-escape"),
                 ]),
                html.Div(id="cs-phase-content"),
            ], width=6),

            # ── Right: Checklists ────────────────────────────────────────────
            dbc.Col([
                _card(
                    html.Div("✅ Container Hardening Checklist",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[html.Div([
                        html.Span("□ ", style={"color": "#636e72"}),
                        html.Span(item, style={"color": "#b0b0b0",
                                               "fontSize": "11px"}),
                      ], style={"marginBottom": "4px"})
                      for item in [
                          "No CRITICAL/HIGH vulns in image",
                          "Non-root user (USER directive)",
                          "Read-only root filesystem",
                          "No privileged mode",
                          "No docker.sock mounted",
                          "Resource limits set (CPU/mem)",
                          "Minimal base image (distroless/alpine)",
                          "Multi-stage build",
                          "No hardcoded secrets",
                          "Secrets via env/vault (not Dockerfile)",
                          "Hadolint passes",
                          "Image signed (cosign/notary)",
                      ]],
                ),

                _card(
                    html.Div("✅ Kubernetes Hardening Checklist",
                             style={"color": "#e0e0e0", "fontWeight": "600",
                                    "marginBottom": "10px"}),
                    *[html.Div([
                        html.Span("□ ", style={"color": "#636e72"}),
                        html.Span(item, style={"color": "#b0b0b0",
                                               "fontSize": "11px"}),
                      ], style={"marginBottom": "4px"})
                      for item in [
                          "RBAC with least privilege",
                          "No cluster-admin except admins",
                          "Pod Security Standards enforced",
                          "Network policies defined",
                          "Secrets encrypted at rest",
                          "etcd access restricted",
                          "API server audit logging enabled",
                          "Node OS hardened (CIS benchmark)",
                          "Falco/runtime monitoring active",
                          "Admission controllers enabled",
                          "Kubescape passes NSA framework",
                          "Image pull policy: Always",
                      ]],
                ),
            ], width=3),
        ]),
    ], style={"background": DARK_BG, "minHeight": "100vh", "padding": "24px"})


# ── Phase router ──────────────────────────────────────────────────────────────

@callback(
    Output("cs-phase-content",  "children"),
    Output("cs-update-status",  "children"),
    Input("cs-tabs",            "active_tab"),
    Input("cs-update-btn",      "n_clicks"),
    State("cs-image",           "value"),
    State("cs-scanner",         "value"),
    State("cs-namespace",       "value"),
    State("cs-context",         "value"),
    State("cs-container-id",    "value"),
)
def render_phase(tab, upd_n, image, scanner, namespace, context, container_id):
    status = f"✅ Commands updated — {datetime.now().strftime('%H:%M:%S')}" if upd_n else ""
    img    = image        or "nginx:latest"
    ns     = namespace    or "default"
    cid    = container_id or "$(docker ps -q | head -1)"
    sc     = scanner      or "trivy"

    if tab == "cs-tab-image":
        content = _phase_card("image", f"🔍 Image Scan — {img}",
                              _img_scan_cmd(img, sc))
    elif tab == "cs-tab-k8s":
        content = _phase_card("k8s", f"⚙️ Kubernetes Audit — {ns}",
                              _k8s_audit_cmd(ns, context or ""))
    elif tab == "cs-tab-kube":
        content = _phase_card("kube", "📊 Kubescape Compliance",
                              _kubescape_cmd(ns))
    elif tab == "cs-tab-falco":
        content = _phase_card("falco", "🚨 Falco Runtime Security",
                              _falco_cmd())
    elif tab == "cs-tab-escape":
        content = _phase_card("escape", f"🔓 Container Escape Checks — {cid}",
                              _escape_cmd(cid))
    else:
        content = html.Div()

    return content, status


# ── Per-phase run + AI callbacks ──────────────────────────────────────────────

def _make_callbacks(phase_id: str, label: str):
    @callback(
        Output(f"cs-{phase_id}-out",    "value"),
        Input(f"cs-{phase_id}-run",     "n_clicks"),
        State(f"cs-{phase_id}-cmd",     "value"),
        prevent_initial_call=True,
    )
    def run_phase(n, cmd, _pid=phase_id):
        if not n or not cmd:
            raise PreventUpdate
        threading.Thread(target=_run_bg, args=(cmd, _pid), daemon=True).start()
        time.sleep(5)
        with _LOCK:
            return _OUTPUTS.get(_pid, "[Running…]")
    run_phase.__name__ = f"cs_run_{phase_id}"

    @callback(
        Output(f"cs-{phase_id}-ai-out", "children"),
        Input(f"cs-{phase_id}-ai",      "n_clicks"),
        State(f"cs-{phase_id}-out",     "value"),
        prevent_initial_call=True,
    )
    def ai_phase(n, output, _lbl=label):
        if not n:
            raise PreventUpdate
        prompt = (
            f"You are a container security expert. Analyse this {_lbl} output:\n\n"
            f"{output or '(no output)'}\n\n"
            f"Provide:\n"
            f"1) **Critical Findings** with CVE IDs where applicable\n"
            f"2) **Attack Surface** — what can an attacker exploit?\n"
            f"3) **Remediation Steps** — specific commands/configs to fix each issue\n"
            f"4) **Severity Rating** — CVSS-based risk assessment\n"
            f"5) **Quick Wins** — zero-cost fixes implementable today"
        )
        try:
            return call_llm(prompt)
        except Exception as e:
            return f"LLM error: {e}"
    ai_phase.__name__ = f"cs_ai_{phase_id}"


for _pid, _lbl in [
    ("image",  "Image Vulnerability Scan"),
    ("k8s",    "Kubernetes RBAC Audit"),
    ("kube",   "Kubescape Compliance Scan"),
    ("falco",  "Falco Runtime Alert"),
    ("escape", "Container Escape Check"),
]:
    _make_callbacks(_pid, _lbl)


# ── Global AI ────────────────────────────────────────────────────────────────

@callback(
    Output("cs-ai-global",  "children"),
    Input("cs-ai-risk",     "n_clicks"),
    Input("cs-ai-harden",   "n_clicks"),
    Input("cs-ai-attack",   "n_clicks"),
    State("cs-image",       "value"),
    State("cs-namespace",   "value"),
    prevent_initial_call=True,
)
def global_ai(risk_n, harden_n, attack_n, image, namespace):
    if not ctx.triggered_id:
        raise PreventUpdate
    with _LOCK:
        all_out = "\n\n".join(f"[{k.upper()}]\n{v[:400]}"
                               for k, v in _OUTPUTS.items())
    img = image or "nginx:latest"
    ns  = namespace or "default"
    tid = ctx.triggered_id
    if tid == "cs-ai-risk":
        prompt = (
            f"Container/K8s Risk Summary for image={img}, namespace={ns}\n\n"
            f"Scan Results:\n{all_out}\n\n"
            f"Provide:\n"
            f"1) **Overall Risk Rating** (Critical/High/Medium/Low)\n"
            f"2) **Top 5 Risks** with business impact\n"
            f"3) **Exploitability** — how easy is exploitation?\n"
            f"4) **Blast Radius** — what happens if compromised?\n"
            f"5) **Priority Actions** this week"
        )
    elif tid == "cs-ai-harden":
        prompt = (
            f"Kubernetes/Container Hardening Guide for image={img}, namespace={ns}\n\n"
            f"Scan Results:\n{all_out}\n\n"
            f"Provide a step-by-step hardening guide:\n"
            f"1) **Dockerfile Changes** (specific directives)\n"
            f"2) **SecurityContext** settings for K8s manifests\n"
            f"3) **Network Policy** YAML templates\n"
            f"4) **RBAC** least privilege role definitions\n"
            f"5) **Admission Controller** configurations\n"
            f"Include actual YAML/code snippets."
        )
    else:  # attack paths
        prompt = (
            f"Container/Kubernetes Attack Path Analysis for image={img}, namespace={ns}\n\n"
            f"Scan Results:\n{all_out}\n\n"
            f"Map the full attack path:\n"
            f"1) **Initial Access** vectors (image vuln, exposed service, misconfiguration)\n"
            f"2) **Container Escape** techniques feasible given findings\n"
            f"3) **Lateral Movement** within the cluster\n"
            f"4) **Privilege Escalation** paths to cluster-admin\n"
            f"5) **Data Exfiltration** — what secrets/data can be stolen?\n"
            f"Map to MITRE ATT&CK for Containers framework."
        )
    try:
        return call_llm(prompt)
    except Exception as e:
        return f"LLM error: {e}"
