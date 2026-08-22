"""
Patch 7 — inject LANG_RULES dict and update _run_regex_scan to apply them.
SAFE TO RE-RUN: checks for existing patches.
"""
import sys, shutil, re

SRC = "/opt/vuln_intel/app/cyber_range/moduls/ui_sast.py"
shutil.copy(SRC, SRC + ".bak7")

with open(SRC) as f:
    content = f.read()

changed = False

# ── 1. Insert LANG_RULES after REGEX_RULES closing bracket ──────────────────
LANG_RULES_ANCHOR = "\n# ── OWASP Top 10 CWE Mapping"
LANG_RULES_BLOCK = '''
# ── Per-language rule sets (applied on top of REGEX_RULES) ───────────────────
LANG_RULES: dict = {
    "javascript": [
        {"id":"JS-SQL-001","name":"SQL String Concatenation (JS)","pattern":r'(?i)(SELECT|INSERT|UPDATE|DELETE).*\\+\\s*\\w|query\\s*[+=]+.*\\+\\s*(req\\.|request\\.)','severity':"HIGH","cwe":"CWE-89","message":"SQL query built with string concatenation — SQL injection. Use parameterised queries."},
        {"id":"JS-XSS-001","name":"innerHTML / outerHTML Assignment","pattern":r'\\.(?:inner|outer)HTML\\s*[+]?=','severity':"HIGH","cwe":"CWE-79","message":"innerHTML/outerHTML with untrusted data — XSS risk. Use textContent or DOMPurify."},
        {"id":"JS-XSS-002","name":"document.write() Usage","pattern":r'document\\.write\\s*\\(','severity':"HIGH","cwe":"CWE-79","message":"document.write() enables XSS. Use DOM manipulation methods."},
        {"id":"JS-EVAL-001","name":"eval() Dynamic Input","pattern":r'\\beval\\s*\\(','severity':"CRITICAL","cwe":"CWE-95","message":"eval() executes arbitrary code — remove or replace with safe alternatives."},
        {"id":"JS-CMD-001","name":"child_process.exec with Variable","pattern":r'(?:exec|execSync|spawn|spawnSync)\\s*\\(\\s*(?:req\\b|request\\b|`|\\w+\\s*\\+)','severity':"CRITICAL","cwe":"CWE-78","message":"child_process with dynamic input — command injection. Use execFile with args array."},
        {"id":"JS-SSRF-001","name":"fetch/axios with Variable URL","pattern":r'(?:fetch|axios\\.(?:get|post|put|delete))\\s*\\(\\s*(?:req\\b|request\\b|url\\b|target\\b|\\w+\\s*\\+|`)','severity':"HIGH","cwe":"CWE-918","message":"HTTP request with user-controlled URL — SSRF risk. Validate against an allowlist."},
        {"id":"JS-PATH-001","name":"fs.readFile with Variable Path","pattern":r'fs\\.(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream)\\s*\\(\\s*(?:req\\b|request\\b|\\w+\\s*\\+|`)','severity':"HIGH","cwe":"CWE-22","message":"File operation with dynamic path — path traversal. Use path.resolve() and validate."},
        {"id":"JS-SEC-001","name":"Hardcoded Credential (JS)","pattern":r'(?i)(?:const|let|var)\\s+(?:password|secret|api_?key|token|apikey)\\s*=\\s*["\\'\\'][^\\"\\'']{4,}["\\'\\']','severity':"CRITICAL","cwe":"CWE-798","message":"Hardcoded credential. Use process.env.SECRET"},
        {"id":"JS-PROTO-001","name":"Prototype Pollution","pattern":r'(?:__proto__|constructor\\.prototype)\\s*\\[','severity':"HIGH","cwe":"CWE-1321","message":"Prototype pollution vulnerability. Use Object.create(null)."},
        {"id":"JS-REDIR-001","name":"Open Redirect (Express)","pattern":r'res\\.redirect\\s*\\(\\s*(?:req\\.|request\\.)','severity':"MEDIUM","cwe":"CWE-601","message":"Redirect target from user input — open redirect. Validate against an allowlist."},
        {"id":"JS-CFG-001","name":"Debug/Development Mode (JS)","pattern":r'(?i)NODE_ENV\\s*[=:]\\s*["\\'\\']?(?:development|dev)["\\'\\']?|debug\\s*:\\s*true','severity':"MEDIUM","cwe":"CWE-94","message":"Development mode active. Ensure NODE_ENV=production in deployments."},
        {"id":"JS-CRYPTO-001","name":"Weak Hash (MD5/SHA1) — Node","pattern":r'createHash\\s*\\(\\s*["\\'\\'](?:md5|sha1)["\\'\\']','severity':"MEDIUM","cwe":"CWE-327","message":"MD5/SHA1 is cryptographically weak. Use SHA-256 or bcrypt."},
        {"id":"JS-NOSQL-001","name":"NoSQL Injection (MongoDB)","pattern":r'(?:find|findOne|update|remove|deleteOne)\\s*\\(\\s*(?:req\\.|request\\.','severity':"HIGH","cwe":"CWE-943","message":"MongoDB query with user input — NoSQL injection. Use mongo-sanitize."},
        {"id":"JS-JWT-001","name":"JWT Verify Disabled (JS)","pattern":r'algorithms.*["\\'\\']none["\\'\\']|verify\\s*:\\s*false','severity':"CRITICAL","cwe":"CWE-347","message":"JWT verification disabled — authentication bypass. Always verify with HS256/RS256."},
    ],
    "java": [
        {"id":"JV-SQL-001","name":"SQL Concatenation (Java)","pattern":r'(?i)(?:executeQuery|executeUpdate|execute|prepareStatement)\\s*\\(\\s*(?:".*"\\s*\\+|\\w+\\s*\\+)','severity':"CRITICAL","cwe":"CWE-89","message":"SQL with concatenation — SQL injection. Use PreparedStatement with bind params."},
        {"id":"JV-CMD-001","name":"Runtime.exec / ProcessBuilder","pattern":r'Runtime\\.getRuntime\\(\\)\\.exec\\s*\\(|new\\s+ProcessBuilder\\s*\\(','severity':"CRITICAL","cwe":"CWE-78","message":"Java command execution — OS injection if input is user-controlled."},
        {"id":"JV-DESER-001","name":"Java ObjectInputStream","pattern":r'new\\s+ObjectInputStream\\s*\\(|\\.readObject\\s*\\(','severity':"CRITICAL","cwe":"CWE-502","message":"Java deserialisation — arbitrary code execution with untrusted data."},
        {"id":"JV-XSS-001","name":"PrintWriter Output Unescaped","pattern":r'(?:out|response)\\.(?:print|println|write)\\s*\\(\\s*(?:request\\.)','severity':"HIGH","cwe":"CWE-79","message":"User input written to response without escaping — XSS. Use OWASP Java Encoder."},
        {"id":"JV-PATH-001","name":"File from Request Parameter","pattern":r'new\\s+File\\s*\\(\\s*(?:request\\.getParameter|req\\.getParameter)','severity':"HIGH","cwe":"CWE-22","message":"File from request parameter — path traversal. Use Paths.get().normalize()."},
        {"id":"JV-SEC-001","name":"Hardcoded Password (Java)","pattern":r'(?i)(?:String\\s+)?(?:password|passwd|secret|apiKey)\\s*=\\s*"[^"]{4,}"','severity':"CRITICAL","cwe":"CWE-798","message":"Hardcoded credential. Use environment variables or a secrets manager."},
        {"id":"JV-SSRF-001","name":"URL openConnection with User Input","pattern":r'new\\s+URL\\s*\\(\\s*(?:request\\.getParameter|req\\.getParameter)','severity':"HIGH","cwe":"CWE-918","message":"HTTP request to user-supplied URL — SSRF. Validate against allowlist."},
        {"id":"JV-XXE-001","name":"XML Parsing without XXE Protection","pattern":r'DocumentBuilderFactory\\.newInstance\\(\\)|SAXParserFactory\\.newInstance\\(\\)','severity':"HIGH","cwe":"CWE-611","message":"XML parser without XXE protection. Add FEATURE_SECURE_PROCESSING."},
        {"id":"JV-CRYPTO-001","name":"Weak Hash (Java)","pattern":r'MessageDigest\\.getInstance\\s*\\(\\s*"(?:MD5|SHA-1|SHA1)"','severity':"HIGH","cwe":"CWE-327","message":"MD5/SHA-1 is broken. Use SHA-256 or bcrypt."},
        {"id":"JV-RAND-001","name":"java.util.Random (not CSPRNG)","pattern":r'new\\s+Random\\s*\\(\\)|Math\\.random\\s*\\(','severity':"MEDIUM","cwe":"CWE-338","message":"java.util.Random is not cryptographically secure. Use SecureRandom."},
    ],
    "php": [
        {"id":"PHP-SQL-001","name":"Superglobal in SQL (PHP)","pattern":r'(?i)(SELECT|INSERT|UPDATE|DELETE).*\\$_(?:GET|POST|REQUEST|COOKIE)','severity':"CRITICAL","cwe":"CWE-89","message":"Superglobal in SQL — critical SQL injection. Use PDO prepared statements."},
        {"id":"PHP-CMD-001","name":"PHP Shell Execution","pattern":r'\\b(?:exec|shell_exec|system|passthru|popen)\\s*\\(\\s*\\$','severity':"CRITICAL","cwe":"CWE-78","message":"PHP shell function with variable — OS command injection. Use escapeshellarg()."},
        {"id":"PHP-XSS-001","name":"echo Superglobal (PHP)","pattern":r'(?:echo|print)\\s+\\$_(?:GET|POST|REQUEST|COOKIE|SERVER)','severity':"HIGH","cwe":"CWE-79","message":"Superglobal echoed without escaping — XSS. Use htmlspecialchars($var, ENT_QUOTES)."},
        {"id":"PHP-DESER-001","name":"PHP unserialize()","pattern":r'\\bunserialize\\s*\\(\\s*\\$','severity':"CRITICAL","cwe":"CWE-502","message":"PHP unserialize() with user data — RCE. Use json_decode()."},
        {"id":"PHP-INC-001","name":"Dynamic File Include (PHP)","pattern":r'\\b(?:include|require|include_once|require_once)\\s*(?:\\(|\\s+)\\s*\\$','severity':"CRITICAL","cwe":"CWE-98","message":"Dynamic file inclusion — RFI/LFI. Validate against a fixed allowlist."},
        {"id":"PHP-SEC-001","name":"Hardcoded Password (PHP)","pattern":r'(?i)\\$(?:password|passwd|secret|api_key)\\s*=\\s*["\\'\\'][^"\\'\\'']{4,}["\\'\\']','severity':"CRITICAL","cwe":"CWE-798","message":"Hardcoded credential. Use getenv(\\'SECRET\\')."},
        {"id":"PHP-SSRF-001","name":"SSRF via file_get_contents (PHP)","pattern":r'(?:file_get_contents|curl_setopt)\\s*\\(\\s*\\$_','severity':"HIGH","cwe":"CWE-918","message":"HTTP request to user-controlled URL — SSRF. Validate and restrict hosts."},
        {"id":"PHP-CRYPTO-001","name":"Weak Hash (PHP)","pattern":r'\\b(?:md5|sha1)\\s*\\(\\s*\\$','severity':"HIGH","cwe":"CWE-327","message":"MD5/SHA1 is weak for passwords. Use password_hash() with PASSWORD_BCRYPT."},
        {"id":"PHP-EVAL-001","name":"eval() in PHP","pattern":r'\\beval\\s*\\(','severity':"CRITICAL","cwe":"CWE-95","message":"PHP eval() — arbitrary code execution."},
        {"id":"PHP-REDIR-001","name":"Open Redirect (PHP)","pattern":r"header\\s*\\(\\s*['\\"']Location:.*\\$_",'severity':"HIGH","cwe":"CWE-601","message":"Open redirect via superglobal URL. Validate against an allowlist."},
    ],
    "go": [
        {"id":"GO-SQL-001","name":"SQL fmt.Sprintf (Go)","pattern":r'(?i)(?:Query|Exec|QueryRow)\\s*\\(\\s*(?:fmt\\.Sprintf|".*"\\s*\\+)','severity':"CRITICAL","cwe":"CWE-89","message":"SQL built with fmt.Sprintf — SQL injection. Use ? placeholders."},
        {"id":"GO-CMD-001","name":"exec.Command with User Input","pattern":r'exec\\.Command\\s*\\(\\s*(?:r\\.|req\\.|strings\\.)','severity':"CRITICAL","cwe":"CWE-78","message":"os/exec with user input — command injection."},
        {"id":"GO-SSRF-001","name":"http.Get with Variable URL","pattern":r'http\\.(?:Get|Post|Do)\\s*\\(\\s*(?:r\\.URL|req\\.|url\\b)','severity':"HIGH","cwe":"CWE-918","message":"HTTP request with user-supplied URL — SSRF."},
        {"id":"GO-SEC-001","name":"Hardcoded Credential (Go)","pattern":r'(?i)(?:password|secret|apiKey|token)\\s*:?=\\s*"[^"]{4,}"','severity':"CRITICAL","cwe":"CWE-798","message":"Hardcoded credential. Use os.Getenv()."},
        {"id":"GO-CRYPTO-001","name":"Weak Hash (Go)","pattern":r'(?:md5|sha1)\\.New\\(\\)','severity':"HIGH","cwe":"CWE-327","message":"MD5/SHA1 is weak. Use crypto/sha256."},
        {"id":"GO-TLS-001","name":"InsecureSkipVerify","pattern":r'InsecureSkipVerify\\s*:\\s*true','severity':"HIGH","cwe":"CWE-295","message":"TLS verification disabled — MITM vulnerability."},
    ],
    "ruby": [
        {"id":"RB-SQL-001","name":"SQL Interpolation (Ruby)","pattern":r'(?i)(?:execute|where|find_by_sql)\\s*\\(\\s*".*#\\{','severity':"CRITICAL","cwe":"CWE-89","message":"SQL with interpolation — SQL injection. Use ActiveRecord parameterised queries."},
        {"id":"RB-CMD-001","name":"Shell Execution (Ruby)","pattern":r'`[^`]*#\\{|system\\s*\\(|exec\\s*\\(|%x\\[','severity':"CRITICAL","cwe":"CWE-78","message":"Shell execution with interpolation — command injection."},
        {"id":"RB-EVAL-001","name":"eval() in Ruby","pattern":r'\\beval\\s*\\(','severity':"CRITICAL","cwe":"CWE-95","message":"Ruby eval() — arbitrary code execution."},
        {"id":"RB-DESER-001","name":"Marshal.load (Ruby)","pattern":r'Marshal\\.(?:load|restore)\\s*\\(','severity':"CRITICAL","cwe":"CWE-502","message":"Marshal.load with untrusted data — RCE. Use JSON.parse."},
        {"id":"RB-SEC-001","name":"Hardcoded Secret (Ruby)","pattern":r"(?i)(?:password|secret|api_key|token)\\s*=\\s*['\\"'][^'\\"']{4,}['\\"']",'severity':"CRITICAL","cwe":"CWE-798","message":"Hardcoded credential. Use ENV[\\'SECRET\\']."},
        {"id":"RB-MASS-001","name":"Mass Assignment (Rails)","pattern":r'\\.(?:update|create)\\s*\\(\\s*params\\s*\\)','severity':"HIGH","cwe":"CWE-915","message":"Mass assignment with unfiltered params. Use params.permit() allowlist."},
    ],
    "c_cpp": [
        {"id":"C-BUF-001","name":"Unsafe Buffer Function","pattern":r'\\b(?:gets|strcpy|strcat|sprintf|vsprintf)\\s*\\(','severity':"CRITICAL","cwe":"CWE-120","message":"Unsafe buffer function — buffer overflow. Use fgets(), strncpy(), snprintf()."},
        {"id":"C-FORMAT-001","name":"Format String Vulnerability","pattern":r'(?:printf|fprintf|syslog)\\s*\\(\\s*(?:argv\\[|user_input|\\w+\\s*[,)])','severity':"CRITICAL","cwe":"CWE-134","message":"Format string attack. Use printf(\\"%s\\", var)."},
        {"id":"C-CMD-001","name":"system() Call (C)","pattern":r'\\bsystem\\s*\\(\\s*(?!NULL|\\s*")','severity':"CRITICAL","cwe":"CWE-78","message":"system() with variable — command injection. Use execve() with args array."},
        {"id":"C-SEC-001","name":"Hardcoded Password (C)","pattern":r'(?i)char\\s+\\*?\\s*(?:password|passwd|secret)\\s*=\\s*"[^"]{4,}"','severity':"CRITICAL","cwe":"CWE-798","message":"Hardcoded credential. Load from environment at runtime."},
        {"id":"C-CRYPTO-001","name":"Weak Crypto (C/C++)","pattern":r'\\b(?:MD5_Init|SHA1_Init|DES_key_schedule)\\s*\\(','severity':"HIGH","cwe":"CWE-327","message":"Weak crypto. Use SHA-256 (EVP_sha256) or AES-GCM."},
    ],
}
LANG_RULES["typescript"] = LANG_RULES.get("typescript", []) + LANG_RULES.get("javascript", [])

'''

if "LANG_RULES" not in content:
    content = content.replace(LANG_RULES_ANCHOR, LANG_RULES_BLOCK + LANG_RULES_ANCHOR, 1)
    print("✅ Inserted LANG_RULES dict")
    changed = True
else:
    print("ℹ️  LANG_RULES already present — skipping")

# ── 2. Update _run_regex_scan to apply language-specific rules ────────────────
OLD_REGEX = (
    "def _run_regex_scan(code: str) -> list:\n"
    "    findings = []\n"
    "    lines = code.splitlines()\n"
    "    for rule in REGEX_RULES:\n"
    "        pat = re.compile(rule[\"pattern\"], re.IGNORECASE | re.MULTILINE)\n"
    "        for i, line in enumerate(lines, 1):\n"
    "            if pat.search(line):\n"
    "                findings.append({\n"
    "                    \"id\":       rule[\"id\"],\n"
    "                    \"rule\":     rule[\"name\"],\n"
    "                    \"severity\": rule[\"severity\"],\n"
    "                    \"cwe\":      rule[\"cwe\"],\n"
    "                    \"message\":  rule[\"message\"],\n"
    "                    \"line\":     i,\n"
    "                    \"code\":     line.strip()[:200],\n"
    "                    \"engine\":   \"Regex\",\n"
    "                    \"fix\":      \"\",\n"
    "                })\n"
    "    return findings"
)

NEW_REGEX = (
    "def _run_regex_scan(code: str, language: str = \"auto\") -> list:\n"
    "    findings = []\n"
    "    lines = code.splitlines()\n"
    "    # Universal rules + language-specific rules\n"
    "    active_rules = REGEX_RULES + LANG_RULES.get(language, [])\n"
    "    seen = set()  # deduplicate by (rule_id, line_no)\n"
    "    for rule in active_rules:\n"
    "        try:\n"
    "            pat = re.compile(rule[\"pattern\"], re.IGNORECASE | re.MULTILINE)\n"
    "        except re.error:\n"
    "            continue\n"
    "        for i, line in enumerate(lines, 1):\n"
    "            if pat.search(line):\n"
    "                key = (rule[\"id\"], i)\n"
    "                if key in seen:\n"
    "                    continue\n"
    "                seen.add(key)\n"
    "                findings.append({\n"
    "                    \"id\":       rule[\"id\"],\n"
    "                    \"rule\":     rule[\"name\"],\n"
    "                    \"severity\": rule[\"severity\"],\n"
    "                    \"cwe\":      rule.get(\"cwe\", \"\"),\n"
    "                    \"message\":  rule[\"message\"],\n"
    "                    \"line\":     i,\n"
    "                    \"code\":     line.strip()[:200],\n"
    "                    \"engine\":   \"Regex\",\n"
    "                    \"fix\":      \"\",\n"
    "                })\n"
    "    return findings"
)

if OLD_REGEX in content:
    content = content.replace(OLD_REGEX, NEW_REGEX, 1)
    print("✅ Updated _run_regex_scan to accept language parameter")
    changed = True
elif "active_rules = REGEX_RULES + LANG_RULES" in content:
    print("ℹ️  _run_regex_scan already updated — skipping")
else:
    print("⚠️  _run_regex_scan pattern not found")

# ── 3. Update t0() in _full_scan to pass language ────────────────────────────
OLD_T0 = "    def t0(): containers[0].extend(_run_regex_scan(code))"
NEW_T0 = "    def t0(): containers[0].extend(_run_regex_scan(code, language))"

if OLD_T0 in content:
    content = content.replace(OLD_T0, NEW_T0, 1)
    print("✅ Updated t0() to pass language to _run_regex_scan")
    changed = True
elif "_run_regex_scan(code, language)" in content:
    print("ℹ️  t0() already passes language — skipping")
else:
    print("⚠️  t0() pattern not found")

# ── Write + syntax check ──────────────────────────────────────────────────────
with open(SRC, "w") as f:
    f.write(content)

import subprocess
r = subprocess.run([sys.executable, "-m", "py_compile", SRC], capture_output=True, text=True)
if r.returncode == 0:
    print("\n✅ Syntax OK — multi-language detection active!")
else:
    print("\n❌ Syntax error:", r.stderr[:500])
    shutil.copy(SRC + ".bak7", SRC)
    print("⚠️  Restored from backup")

if not changed:
    print("\nℹ️  No changes needed — already up to date")
