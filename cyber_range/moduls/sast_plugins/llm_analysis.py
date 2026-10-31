"""
llm_analysis.py — LLM-Powered Vulnerability Detection Plugin

Uses the platform's existing llm_engine (supports Local/ChatGPT/Claude) to
perform semantic analysis of code beyond what pattern matching can detect:
  • Logic flaws and business logic vulnerabilities
  • Authentication bypass patterns
  • Insecure state machine transitions
  • Race conditions and TOCTOU

Falls back gracefully if the LLM is unavailable.
"""
import json
from .base_plugin import BasePlugin

# Max characters of code to send — keeps token cost reasonable
_MAX_CODE_CHARS = 3000


class LLMAnalysisPlugin(BasePlugin):
    name        = "LLM Semantic Vulnerability Analyser"
    description = (
        "Uses the platform LLM engine to detect logic flaws, auth bypasses, and business "
        "logic vulnerabilities that regular pattern matchers miss."
    )
    engine_tag  = "Plugin-LLM"
    language    = None   # runs on all languages

    # Only run if code is at least this many non-blank characters
    _MIN_CODE_LEN = 80

    def run(self, file_path: str, content: str, language: str = "auto") -> list[dict]:
        if not content or len(content.strip()) < self._MIN_CODE_LEN:
            return []

        try:
            from llm_engine import call_llm
        except ImportError:
            return [self.make_finding(
                rule_id="PI-LLM-ERR",
                rule="LLM Engine Unavailable",
                severity="INFO", cwe="",
                message="llm_engine not importable — LLM analysis skipped.",
                line=0, code="", engine=self.engine_tag,
            )]

        snippet = content[:_MAX_CODE_CHARS]
        truncated = len(content) > _MAX_CODE_CHARS

        prompt = (
            f"You are an application security expert performing SAST code review.\n"
            f"Analyse the following {language} code for security vulnerabilities.\n"
            f"Focus on: logic flaws, authentication bypasses, race conditions, "
            f"business-logic errors, insecure state transitions, and any vulnerability "
            f"that a regex scanner would miss.\n\n"
            f"Respond ONLY with a valid JSON array. Each item must have:\n"
            f'  {{"rule": "short name", "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", '
            f'"cwe": "CWE-NNN or empty", "line": <best-guess int or 0>, '
            f'"message": "explanation", "fix": "one-line fix suggestion"}}\n\n'
            f"If no vulnerabilities found, respond with an empty array: []\n\n"
            f"{'[Code truncated to first 3000 chars]' if truncated else ''}\n"
            f"```{language}\n{snippet}\n```"
        )

        try:
            raw = call_llm(prompt)
            # Strip markdown code fences if LLM wrapped the JSON
            raw = raw.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            items = json.loads(raw)
            if not isinstance(items, list):
                items = []
        except Exception as exc:
            return [self.make_finding(
                rule_id="PI-LLM-PARSE",
                rule="LLM Response Parse Error",
                severity="INFO", cwe="",
                message=f"LLM returned non-JSON response: {str(exc)[:120]}",
                line=0, code="", engine=self.engine_tag,
            )]

        findings = []
        valid_sevs = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for i, item in enumerate(items[:20]):   # cap at 20 findings
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity", "MEDIUM")).upper()
            if sev not in valid_sevs:
                sev = "MEDIUM"
            findings.append(self.make_finding(
                rule_id=f"PI-LLM-{i+1:03d}",
                rule=item.get("rule", "LLM Finding"),
                severity=sev,
                cwe=item.get("cwe", ""),
                message=item.get("message", ""),
                line=int(item.get("line", 0) or 0),
                code="",
                fix=item.get("fix", ""),
                engine=self.engine_tag,
            ))

        if not findings:
            findings.append(self.make_finding(
                rule_id="PI-LLM-OK",
                rule="LLM Analysis Clean",
                severity="INFO", cwe="",
                message="LLM semantic analysis found no additional vulnerabilities.",
                line=0, code="", engine=self.engine_tag,
            ))

        return findings
