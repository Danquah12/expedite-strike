"""
remediation_plugin.py — Auto Remediation Plugin

Maps every rule ID (and generic vulnerability categories) to a concrete,
actionable remediation. Acts as a post-processor — does not generate findings.

Usage:
    from sast_plugins.remediation_plugin import get_fix, enrich_fixes
    enriched = enrich_fixes(findings)
"""
from .base_plugin import BasePlugin


# ── Remediation database ──────────────────────────────────────────────────────
# Key: rule_id prefix  →  (short_fix, detailed_steps)
REMEDIATIONS: dict[str, tuple[str, str]] = {

    # ── Taint / Data Flow ─────────────────────────────────────────────────────
    "PI-TA-001": (
        "Use parameterised queries",
        "Replace string-concatenated SQL with parameterised queries:\n"
        "  cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
        "Or use an ORM (SQLAlchemy, Django ORM) which handles binding automatically."
    ),
    "PI-TA-002": (
        "Use parameterised queries (executemany)",
        "Pass a sequence of parameter tuples to executemany instead of formatting SQL strings:\n"
        "  cursor.executemany('INSERT INTO t VALUES (?,?)', rows)"
    ),
    "PI-TA-003": (
        "Avoid os.system with user input",
        "Replace os.system() with subprocess and pass a list:\n"
        "  subprocess.run(['cmd', safe_arg], shell=False, check=True)\n"
        "Validate and whitelist all input before use."
    ),
    "PI-TA-004": (
        "Use subprocess.Popen with list args",
        "Pass arguments as a list and set shell=False:\n"
        "  subprocess.Popen(['cmd', user_arg], shell=False)"
    ),
    "PI-TA-005": ("Use subprocess list args, shell=False",
                  "subprocess.call(['cmd', arg], shell=False)"),
    "PI-TA-006": ("Use subprocess list args, shell=False",
                  "subprocess.run(['cmd', arg], shell=False, check=True)"),
    "PI-TA-007": (
        "Canonicalise and validate file paths",
        "Resolve the path and assert it stays within the allowed directory:\n"
        "  safe = os.path.realpath(os.path.join(BASE_DIR, user_input))\n"
        "  if not safe.startswith(BASE_DIR): raise ValueError('Invalid path')"
    ),
    "PI-TA-008": (
        "Remove eval() — never pass user input to it",
        "Refactor the logic to avoid eval(). If dynamic dispatch is needed,\n"
        "use a whitelist dict of allowed functions:\n"
        "  ALLOWED = {'add': add_fn, 'sub': sub_fn}\n"
        "  fn = ALLOWED.get(user_cmd)\n"
        "  if fn: fn()"
    ),
    "PI-TA-009": ("Remove exec() — use explicit function calls",
                  "Never pass user input to exec(). Use importlib for dynamic imports with strict allowlisting."),
    "PI-TA-010": (
        "Avoid render_template_string with user data",
        "Use render_template() with a static template file. If dynamic templates are required,\n"
        "sanitise with MarkupSafe.escape() and never embed raw user input."
    ),
    "PI-TA-011": ("Validate before deserialising",
                  "Use json.loads() for JSON data. For pickle/yaml, validate the source is trusted and use yaml.safe_load()."),
    "PI-TA-012": ("Avoid str.format with user input",
                  "Use f-strings with explicit escaping or template libraries. Never pass user input as the format string itself."),
    "PI-TA-013": (
        "Validate redirect targets",
        "Restrict redirects to a known safe list of URLs:\n"
        "  SAFE = {'dashboard', 'profile'}\n"
        "  if target not in SAFE: target = 'dashboard'\n"
        "  return redirect(url_for(target))"
    ),
    "PI-TA-014": ("Use send_from_directory with fixed base",
                  "flask.send_from_directory(UPLOAD_DIR, secure_filename(user_input))"),

    # ── SQL Injection ─────────────────────────────────────────────────────────
    "PI-SQL-001": (
        "Use parameterised queries",
        "Never build SQL by concatenating strings. Use bind parameters:\n"
        "  cursor.execute('SELECT ... WHERE id = %s', (user_id,))"
    ),
    "PI-SQL-002": ("Use bind parameters instead of %-format",
                   "cursor.execute('SELECT ... WHERE id = %s', (user_id,))"),
    "PI-SQL-003": ("Assign SQL via bind parameters only",
                   "Build queries with an ORM or always use parameterised statements."),
    "PI-SQL-004": ("Do not append to SQL strings",
                   "Rewrite the query using a single parameterised statement."),
    "PI-SQL-005": ("Escape LIKE wildcards",
                   "Escape % and _ in LIKE patterns: val = val.replace('%','\\%').replace('_','\\_')"),

    # ── XSS ──────────────────────────────────────────────────────────────────
    "PI-XSS-001": (
        "Use textContent instead of innerHTML",
        "element.textContent = userInput;  // or DOMPurify.sanitize(userInput)"
    ),
    "PI-XSS-002": ("Avoid document.write",
                   "Use DOM manipulation (createElement, appendChild) instead."),
    "PI-XSS-003": ("Avoid outerHTML with user data",
                   "Use textContent or cloneNode to replace elements safely."),
    "PI-XSS-004": ("Never eval() URL-derived data",
                   "Parse URL parameters with URLSearchParams and handle them without eval."),
    "PI-XSS-005": ("Escape output with template engine auto-escape",
                   "Enable Jinja2 autoescaping: app = Flask(__name__) with autoescape=True."),
    "PI-XSS-006": ("Use jQuery .text() for plain text",
                   "$(elem).text(userInput);  // safe for plain text content"),
    "PI-XSS-007": ("Sanitise before dangerouslySetInnerHTML",
                   "__html: DOMPurify.sanitize(userHtml, { ALLOWED_TAGS: ['b','i','em'] })"),

    # ── Secrets ───────────────────────────────────────────────────────────────
    "PI-SEC-001": (
        "Rotate AWS key and use IAM roles",
        "1. Revoke the exposed key in AWS IAM immediately.\n"
        "2. Use IAM roles for EC2/Lambda instead of access keys.\n"
        "3. Store keys in AWS Secrets Manager or env vars: os.environ['AWS_ACCESS_KEY_ID']"
    ),
    "PI-SEC-002": (
        "Remove private key from source",
        "1. Revoke the key pair immediately.\n"
        "2. Load keys at runtime from a secrets manager (Vault, AWS SM).\n"
        "3. Add the key file to .gitignore."
    ),
    "PI-SEC-003": ("Move password to environment variable",
                   "PASSWORD = os.environ['APP_PASSWORD']  # or use python-decouple"),
    "PI-SEC-004": ("Move API key to environment variable",
                   "API_KEY = os.environ['API_KEY']"),
    "PI-SEC-005": ("Move auth token to environment variable",
                   "TOKEN = os.environ['AUTH_TOKEN']"),
    "PI-SEC-006": ("Move secret key to environment variable",
                   "SECRET_KEY = os.environ['SECRET_KEY']  # min 32 random bytes"),
    "PI-SEC-007": ("Move database password to environment variable",
                   "DB_PASS = os.environ['DB_PASSWORD']"),
    "PI-SEC-008": ("Revoke GitHub PAT immediately",
                   "Go to GitHub → Settings → Developer settings → Personal access tokens → Revoke."),
    "PI-SEC-009": ("Revoke the sk- key immediately",
                   "Visit the provider dashboard (OpenAI / Stripe) and regenerate the key."),

    # ── Command Injection ─────────────────────────────────────────────────────
    "PI-CMD-001": ("Replace os.system with subprocess list",
                   "subprocess.run(['cmd', user_arg], shell=False, check=True)"),
    "PI-CMD-002": ("Use subprocess.Popen with list args",
                   "subprocess.Popen(['cmd', user_arg], shell=False)"),
    "PI-CMD-003": ("Use list args and shell=False",
                   "subprocess.call(['cmd', arg], shell=False)"),
    "PI-CMD-004": (
        "Remove shell=True",
        "subprocess.run(['git', 'clone', user_url], shell=False, check=True)\n"
        "Validate user_url against an allowlist."
    ),
    "PI-CMD-005": ("Replace os.popen with subprocess",
                   "result = subprocess.run(['cmd'], capture_output=True, text=True).stdout"),
    "PI-CMD-006": ("Remove eval/exec — use explicit dispatch",
                   "ALLOWED = {'func1': fn1}\nALLOWED[user_cmd]()  # KeyError if not allowed"),
    "PI-CMD-007": ("PHP: use escapeshellarg or avoid shell functions",
                   "$output = shell_exec('grep ' . escapeshellarg($userInput));"),
    "PI-CMD-008": ("Node: use execFile or spawn with args array",
                   "const { execFile } = require('child_process');\nexecFile('cmd', [userArg]);"),

    # ── Cryptography ──────────────────────────────────────────────────────────
    "PI-CRY-001": ("Replace MD5 with SHA-256",
                   "hashlib.sha256(data).hexdigest()"),
    "PI-CRY-002": ("Replace SHA-1 with SHA-256",
                   "hashlib.sha256(data).hexdigest()"),
    "PI-CRY-003": ("Replace DES with AES-256-GCM",
                   "from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_GCM)"),
    "PI-CRY-004": ("Replace RC4 with AES-GCM or ChaCha20-Poly1305",
                   "from Crypto.Cipher import ChaCha20_Poly1305"),
    "PI-CRY-005": ("Use secrets module for cryptographic randomness",
                   "import secrets\ntok = secrets.token_hex(32)"),
    "PI-CRY-006": ("Use crypto.getRandomValues for secure random in JS",
                   "const arr = new Uint8Array(32); crypto.getRandomValues(arr);"),
    "PI-CRY-007": ("Use AES-GCM mode instead of ECB",
                   "AES.new(key, AES.MODE_GCM)  # authenticated, no pattern leakage"),
    "PI-CRY-008": ("Never disable TLS verification",
                   "requests.get(url, verify=True)  # or pass the CA bundle path"),

    # ── Deserialization ───────────────────────────────────────────────────────
    "PI-DES-001": ("Replace pickle with JSON",
                   "import json\ndata = json.loads(user_input)"),
    "PI-DES-002": ("Use yaml.safe_load",
                   "import yaml\ndata = yaml.safe_load(stream)"),
    "PI-DES-003": ("Remove eval of request data",
                   "Never call eval() on user-supplied content."),
    "PI-DES-004": ("Avoid marshal for untrusted data",
                   "Use JSON or protobuf for serialisation instead of marshal."),
    "PI-DES-005": ("Use a deserialisation allowlist in Java",
                   "Implement a custom ObjectInputFilter to whitelist safe classes."),
    "PI-DES-006": ("Use JSON.parse without eval",
                   "const obj = JSON.parse(userInput);  // safe on its own"),
    "PI-DES-007": ("PHP: use json_decode instead of unserialize",
                   "$data = json_decode($userInput, true);"),

    # ── Auth / JWT ────────────────────────────────────────────────────────────
    "PI-AUTH-001": ("Specify allowed algorithms explicitly",
                    "jwt.decode(token, SECRET, algorithms=['HS256'])"),
    "PI-AUTH-002": ("Remove verify=False from jwt.decode",
                    "jwt.decode(token, SECRET, algorithms=['HS256'])"),
    "PI-AUTH-003": ("Load session secret from environment",
                    "SECRET_KEY = os.environ['SESSION_SECRET']  # min 32 random bytes"),
    "PI-AUTH-004": ("Hash passwords with bcrypt before comparing",
                    "bcrypt.checkpw(password.encode(), stored_hash)"),
    "PI-AUTH-005": ("Derive auth state from real checks, not literals",
                    "is_authenticated = db.verify_credentials(user, password)"),
    "PI-AUTH-006": ("Use a long random JWT secret from env",
                    "JWT_SECRET = os.environ['JWT_SECRET']  # secrets.token_hex(32)"),
    "PI-AUTH-007": ("Enable Secure and HttpOnly on session cookies",
                    "app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, "
                    "SESSION_COOKIE_SAMESITE='Lax')"),

    # ── Path Traversal ────────────────────────────────────────────────────────
    "PI-PT-001": ("Canonicalise path before open()",
                  "safe = os.path.realpath(os.path.join(BASE_DIR, filename))\n"
                  "assert safe.startswith(BASE_DIR)\nopen(safe)"),
    "PI-PT-002": ("Remove literal ../ sequences",
                  "Validate paths do not contain traversal sequences."),
    "PI-PT-003": ("Validate os.path.join result against base dir",
                  "safe = os.path.realpath(os.path.join(BASE, user_input))\n"
                  "if not safe.startswith(BASE): raise ValueError"),
    "PI-PT-004": ("Use send_from_directory with secure_filename",
                  "send_from_directory(UPLOAD_FOLDER, secure_filename(user_input))"),
    "PI-PT-005": ("Canonicalise path with path.resolve()",
                  "const safe = path.resolve(BASE, filename);\n"
                  "if (!safe.startsWith(BASE)) throw new Error('Invalid path');"),

    # ── SSRF ──────────────────────────────────────────────────────────────────
    "PI-SSRF-001": (
        "Validate URL against hostname allowlist",
        "from urllib.parse import urlparse\n"
        "ALLOWED = {'api.example.com'}\n"
        "if urlparse(url).hostname not in ALLOWED:\n"
        "    raise ValueError('Disallowed host')"
    ),
    "PI-SSRF-002": ("Validate f-string URL before fetching",
                    "Ensure the hostname is derived from config, not user input."),
    "PI-SSRF-003": ("Validate urljoin base and fragment separately",
                    "Ensure the second arg to urljoin cannot start with // or a scheme."),
    "PI-SSRF-004": ("Restrict socket hosts to an allowlist",
                    "ALLOWED_HOSTS = {'10.0.0.1'}\nassert host in ALLOWED_HOSTS"),

    # ── API Auth / BOLA ───────────────────────────────────────────────────────
    "PI-API-001": ("Scope object lookup to authenticated user",
                   "user = User.objects.get(pk=pk, owner=request.user)"),
    "PI-API-002": ("Add owner filter to object lookup",
                   "obj = Model.objects.get(pk=pk, owner=current_user)"),
    "PI-API-003": ("Add authentication middleware/decorator",
                   "@login_required  # or @jwt_required"),

    # ── Vulnerable Dependencies ───────────────────────────────────────────────
    "PI-DEP-001": ("Upgrade log4j to 2.17.1+",
                   "Update pom.xml: <log4j.version>2.17.1</log4j.version>\n"
                   "Set -Dlog4j2.formatMsgNoLookups=true as a short-term mitigation."),
    "PI-DEP-002": ("Upgrade Django to a supported LTS version",
                   "pip install 'django>=4.2'"),
    "PI-DEP-003": ("Upgrade Django to 3.2 LTS or 4.2 LTS",
                   "pip install 'django>=4.2'"),
    "PI-DEP-004": ("Upgrade Flask to 2.x or 3.x",
                   "pip install 'flask>=2.3'"),
    "PI-DEP-005": ("Upgrade PyYAML to 6.x",
                   "pip install 'pyyaml>=6.0'  and use yaml.safe_load()"),
    "PI-DEP-006": ("Upgrade requests to 2.31+",
                   "pip install 'requests>=2.31'"),
    "PI-DEP-007": ("Upgrade Pillow to 9.x+",
                   "pip install 'pillow>=9.5'"),
    "PI-DEP-008": ("Upgrade cryptography to 41+",
                   "pip install 'cryptography>=41'"),
    "PI-DEP-009": ("Upgrade lodash to 4.17.21+",
                   "npm install lodash@latest"),
    "PI-DEP-010": ("Upgrade Express to 4.x",
                   "npm install express@latest"),
    "PI-DEP-011": ("Upgrade jQuery to 3.7+",
                   "npm install jquery@latest"),
    "PI-DEP-012": ("Upgrade Apache Struts immediately",
                   "Update to Struts 2.5.33+ or 6.x. Apply CVE-2017-5638 patch."),
    "PI-DEP-013": ("Upgrade jackson-databind to 2.14+",
                   "Update pom.xml: <jackson.version>2.15.2</jackson.version>"),
}


def get_fix(rule_id: str = "", vulnerability_type: str = "") -> str:
    """
    Return a short remediation string for a rule_id or vulnerability type keyword.
    Falls back to a generic message if not found.
    """
    # Try exact rule_id match first
    if rule_id and rule_id in REMEDIATIONS:
        return REMEDIATIONS[rule_id][0]
    # Keyword fallback
    kw_map = {
        "SQL Injection":          "Use parameterised queries or prepared statements",
        "Command Injection":      "Avoid os.system with user input. Use subprocess.run(['cmd', arg], shell=False).",
        "Cross Site Scripting":   "Escape user input before rendering in HTML. Use textContent not innerHTML.",
        "Weak Cryptography":      "Replace MD5/SHA-1/DES/RC4 with SHA-256, AES-256-GCM, or bcrypt.",
        "Hardcoded Secret":       "Move secrets to environment variables or a vault (Vault, AWS SM, GCP SM).",
        "Path Traversal":         "Canonicalise paths with os.path.realpath() and validate against a base dir.",
        "SSRF":                   "Validate URL hostnames against an explicit allowlist.",
        "Insecure Deserialization": "Replace pickle/yaml.load/unserialize with json.loads() or yaml.safe_load().",
        "JWT":                    "Always specify allowed algorithms and never set verify=False.",
    }
    for key, fix in kw_map.items():
        if key.lower() in vulnerability_type.lower():
            return fix
    return "No automated remediation available — review security guidelines for this vulnerability type."


def get_detailed_fix(rule_id: str) -> str:
    """Return the multi-line detailed remediation for a rule_id."""
    entry = REMEDIATIONS.get(rule_id)
    return entry[1] if entry else get_fix(rule_id=rule_id)


def enrich_fixes(findings: list[dict]) -> list[dict]:
    """
    Post-process a list of findings: if a finding's 'fix' field is empty,
    populate it from the REMEDIATIONS table.
    """
    for f in findings:
        if not f.get("fix"):
            rid = f.get("id", "")
            short_fix = get_fix(rule_id=rid, vulnerability_type=f.get("rule", ""))
            if short_fix and short_fix != "No automated remediation available — review security guidelines for this vulnerability type.":
                f["fix"] = short_fix
    return findings


# ── Plugin stub ───────────────────────────────────────────────────────────────
class RemediationPlugin(BasePlugin):
    """
    Post-processor — enriches existing finding 'fix' fields from REMEDIATIONS.
    Does not generate new findings.
    """
    name        = "Auto Remediation"
    description = "Suggests secure fixes for every detected vulnerability type"
    engine_tag  = "Plugin-Remediation"

    FIXES = {
        "SQL Injection":        "Use parameterized queries or prepared statements",
        "Command Injection Risk": "Avoid os.system with user input. Use safe subprocess calls.",
        "Cross Site Scripting": "Escape user input before rendering in HTML",
        "Weak Cryptography":    "Use SHA256 or bcrypt instead of MD5/SHA1",
        "Hardcoded Secret":     "Move secrets to environment variables or secret manager",
    }

    def run(self, file_path: str, content: str, language: str = "auto") -> list[dict]:
        return []
