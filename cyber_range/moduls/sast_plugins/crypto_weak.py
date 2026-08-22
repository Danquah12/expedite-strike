"""
crypto_weak.py — Weak Cryptography / Insecure Randomness plugin
"""
import re
from .base_plugin import BasePlugin


class WeakCryptoPlugin(BasePlugin):
    name        = "Weak Cryptography Detector"
    description = "Detects use of weak hashing algorithms, broken ciphers, and insecure randomness"
    engine_tag  = "Plugin-Crypto"

    RULES = [
        (
            r'\bMD5\b|hashlib\.md5\s*\(',
            "PI-CRY-001", "MD5 Usage",
            "HIGH", "CWE-327",
            "MD5 is cryptographically broken. Use SHA-256 or SHA-3 for security-sensitive hashing.",
            "hashlib.sha256(data).hexdigest()",
        ),
        (
            r'\bSHA1\b|hashlib\.sha1\s*\(',
            "PI-CRY-002", "SHA-1 Usage",
            "HIGH", "CWE-327",
            "SHA-1 is deprecated for security use. Upgrade to SHA-256 or better.",
            "hashlib.sha256(data).hexdigest()",
        ),
        (
            r'\bDES\b(?!K)|Cipher\.DES|from\s+Crypto\.Cipher\s+import\s+DES\b',
            "PI-CRY-003", "DES Cipher Usage",
            "CRITICAL", "CWE-327",
            "DES has a 56-bit key and is trivially broken. Use AES-256-GCM.",
            "from Crypto.Cipher import AES",
        ),
        (
            r'\bRC4\b|ARC4|from\s+Crypto\.Cipher\s+import\s+ARC4',
            "PI-CRY-004", "RC4 Stream Cipher",
            "CRITICAL", "CWE-327",
            "RC4 is broken and should never be used. Use AES-GCM or ChaCha20-Poly1305.",
            "",
        ),
        (
            r'random\.(?:random|randint|randrange|choice|shuffle)\s*\(',
            "PI-CRY-005", "Insecure Random (not CSPRNG)",
            "MEDIUM", "CWE-338",
            "Python's random module is NOT cryptographically secure. "
            "Use secrets or os.urandom() for security-sensitive values.",
            "import secrets\ntok = secrets.token_hex(32)",
        ),
        (
            r'Math\.random\s*\(',
            "PI-CRY-006", "JavaScript Math.random (Not CSPRNG)",
            "MEDIUM", "CWE-338",
            "Math.random() is not cryptographically secure. "
            "Use crypto.getRandomValues() for security tokens.",
            "crypto.getRandomValues(new Uint8Array(32))",
        ),
        (
            r'ECB|mode\s*=\s*paddings?\.ECB|AES\.MODE_ECB',
            "PI-CRY-007", "ECB Block Cipher Mode",
            "HIGH", "CWE-327",
            "ECB mode leaks patterns in ciphertext. Use AES-GCM or AES-CBC with a random IV.",
            "AES.new(key, AES.MODE_GCM)",
        ),
        (
            r'ssl\._create_unverified_context|CERT_NONE|verify\s*=\s*False',
            "PI-CRY-008", "TLS Certificate Verification Disabled",
            "CRITICAL", "CWE-295",
            "TLS certificate verification disabled — vulnerable to MITM attacks. "
            "Never set verify=False in production.",
            "requests.get(url, verify=True)  # default",
        ),
    ]

    def run(self, file_path: str, content: str, language: str = "auto") -> list[dict]:
        findings = []
        lines = content.splitlines()
        for rule in self.RULES:
            pat, rid, rname, sev, cwe, msg, fix = rule
            compiled = re.compile(pat, re.IGNORECASE | re.MULTILINE)
            for i, line in enumerate(lines, 1):
                if compiled.search(line):
                    findings.append(self.make_finding(
                        rule_id=rid, rule=rname, severity=sev, cwe=cwe,
                        message=msg, line=i, code=line, fix=fix,
                        engine=self.engine_tag,
                    ))
        return findings
