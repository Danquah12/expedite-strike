<?php
/**
 * AEGIS VULNERABLE TEST TARGET
 * =============================
 * Deliberately vulnerable PHP app for testing the Aegis Exploit Database.
 * DO NOT EXPOSE TO THE INTERNET.
 *
 * Vulnerabilities included:
 * - SQL Injection (CWE-89)
 * - XSS Reflected (CWE-79)
 * - XSS Stored (CWE-79)
 * - OS Command Injection (CWE-78)
 * - LFI / Path Traversal (CWE-22)
 * - SSRF (CWE-918)
 * - Open Redirect (CWE-601)
 * - CSRF (no tokens) (CWE-352)
 * - File Upload (CWE-434)
 * - SSTI (CWE-94)
 * - Hardcoded credentials (CWE-798)
 * - Information disclosure (CWE-200)
 * - Weak session management (CWE-384)
 * - IDOR (CWE-639)
 * - XXE (CWE-611)
 */

// ─── Hardcoded creds (CWE-798) ────────────────────────────────────
$DB_PASSWORD = "SuperSecret123!";
$API_KEY = "sk-AEGISTEST1234567890abcdefghijklmnopqrstuvwxyz1234";
$AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// ─── No security headers (CWE-693) ────────────────────────────────
// Deliberately NOT setting: X-Frame-Options, CSP, HSTS, etc.

// ─── Weak session (CWE-384) ───────────────────────────────────────
session_start();
// No HttpOnly, no Secure, no SameSite flags set

$page = $_GET['page'] ?? 'home';

?><!DOCTYPE html>
<html>
<head>
    <title>Aegis Vuln Test Target</title>
    <style>
        body { font-family: monospace; background: #111; color: #0f0; padding: 20px; }
        h1 { color: #f00; }
        a { color: #0ff; }
        form { margin: 10px 0; }
        input, textarea { background: #222; color: #0f0; border: 1px solid #0f0; padding: 5px; }
        .vuln { background: #300; padding: 10px; margin: 10px 0; border: 1px solid #f00; }
        pre { background: #222; padding: 10px; overflow-x: auto; }
    </style>
</head>
<body>
<h1>⚠ AEGIS VULNERABLE TEST TARGET</h1>
<p>This app is <b>DELIBERATELY VULNERABLE</b>. Do not expose to the internet.</p>
<nav>
    <a href="?page=home">Home</a> |
    <a href="?page=sqli">SQLi</a> |
    <a href="?page=xss">XSS</a> |
    <a href="?page=cmdi">CMDi</a> |
    <a href="?page=lfi">LFI</a> |
    <a href="?page=ssrf">SSRF</a> |
    <a href="?page=redirect">Redirect</a> |
    <a href="?page=upload">Upload</a> |
    <a href="?page=xxe">XXE</a> |
    <a href="?page=idor">IDOR</a> |
    <a href="?page=ssti">SSTI</a> |
    <a href="?page=csrf">CSRF</a>
</nav>
<hr>
<?php

switch ($page) {

// ─── SQL Injection (CWE-89) ───────────────────────────────────────
case 'sqli':
    echo '<div class="vuln"><h2>SQL Injection (CWE-89)</h2>';
    echo '<form method="GET"><input type="hidden" name="page" value="sqli">';
    echo 'User ID: <input name="id" value="' . ($_GET['id'] ?? '1') . '">';
    echo '<input type="submit" value="Search"></form>';
    if (isset($_GET['id'])) {
        $db = new SQLite3('/tmp/aegis_test.db');
        $db->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT, email TEXT, password TEXT)");
        $db->exec("INSERT OR IGNORE INTO users VALUES (1,'admin','admin@test.com','password123')");
        $db->exec("INSERT OR IGNORE INTO users VALUES (2,'user','user@test.com','letmein')");
        $db->exec("INSERT OR IGNORE INTO users VALUES (3,'guest','guest@test.com','guest')");
        // VULNERABLE: Direct string concatenation
        $q = "SELECT * FROM users WHERE id = " . $_GET['id'];
        echo "<pre>Query: $q</pre>";
        $result = @$db->query($q);
        if ($result) {
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                echo "<pre>" . print_r($row, true) . "</pre>";
            }
        } else {
            echo "<pre>Error: " . $db->lastErrorMsg() . "</pre>";
        }
    }
    echo '</div>';
    break;

// ─── XSS Reflected (CWE-79) ──────────────────────────────────────
case 'xss':
    echo '<div class="vuln"><h2>XSS — Reflected (CWE-79)</h2>';
    echo '<form method="GET"><input type="hidden" name="page" value="xss">';
    echo 'Search: <input name="q" value="' . ($_GET['q'] ?? '') . '">';
    echo '<input type="submit" value="Search"></form>';
    if (isset($_GET['q'])) {
        // VULNERABLE: No output encoding
        echo "<p>Results for: " . $_GET['q'] . "</p>";
    }
    // Stored XSS form
    echo '<h3>Guestbook (Stored XSS)</h3>';
    echo '<form method="POST" action="?page=xss">';
    echo 'Name: <input name="name"><br>';
    echo 'Message: <textarea name="message"></textarea><br>';
    echo '<input type="submit" value="Post">';
    echo '</form>';
    // No CSRF token! (CWE-352)
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['message'])) {
        $f = '/tmp/aegis_guestbook.txt';
        file_put_contents($f, $_POST['name'] . ": " . $_POST['message'] . "\n", FILE_APPEND);
    }
    if (file_exists('/tmp/aegis_guestbook.txt')) {
        // VULNERABLE: No encoding on output
        echo "<pre>" . file_get_contents('/tmp/aegis_guestbook.txt') . "</pre>";
    }
    echo '</div>';
    break;

// ─── Command Injection (CWE-78) ──────────────────────────────────
case 'cmdi':
    echo '<div class="vuln"><h2>OS Command Injection (CWE-78)</h2>';
    echo '<form method="GET"><input type="hidden" name="page" value="cmdi">';
    echo 'Ping host: <input name="host" value="' . ($_GET['host'] ?? '127.0.0.1') . '">';
    echo '<input type="submit" value="Ping"></form>';
    if (isset($_GET['host'])) {
        // VULNERABLE: Direct shell execution
        $cmd = "ping -c 2 " . $_GET['host'];
        echo "<pre>$ $cmd\n" . shell_exec($cmd) . "</pre>";
    }
    echo '</div>';
    break;

// ─── LFI / Path Traversal (CWE-22) ───────────────────────────────
case 'lfi':
    echo '<div class="vuln"><h2>Local File Inclusion (CWE-22)</h2>';
    echo '<form method="GET"><input type="hidden" name="page" value="lfi">';
    echo 'File: <input name="file" value="' . ($_GET['file'] ?? '/etc/hostname') . '">';
    echo '<input type="submit" value="Read"></form>';
    if (isset($_GET['file'])) {
        // VULNERABLE: No path validation
        $content = @file_get_contents($_GET['file']);
        if ($content !== false) {
            echo "<pre>" . htmlspecialchars($content) . "</pre>";
        } else {
            echo "<p>File not found.</p>";
        }
    }
    echo '</div>';
    break;

// ─── SSRF (CWE-918) ──────────────────────────────────────────────
case 'ssrf':
    echo '<div class="vuln"><h2>SSRF (CWE-918)</h2>';
    echo '<form method="GET"><input type="hidden" name="page" value="ssrf">';
    echo 'Fetch URL: <input name="url" value="' . ($_GET['url'] ?? 'http://127.0.0.1:9010/') . '" size="50">';
    echo '<input type="submit" value="Fetch"></form>';
    if (isset($_GET['url'])) {
        // VULNERABLE: No URL validation
        $content = @file_get_contents($_GET['url']);
        if ($content !== false) {
            echo "<pre>" . htmlspecialchars(substr($content, 0, 2000)) . "</pre>";
        } else {
            echo "<p>Failed to fetch URL.</p>";
        }
    }
    echo '</div>';
    break;

// ─── Open Redirect (CWE-601) ─────────────────────────────────────
case 'redirect':
    echo '<div class="vuln"><h2>Open Redirect (CWE-601)</h2>';
    if (isset($_GET['redirect'])) {
        // VULNERABLE: No validation on redirect target
        header("Location: " . $_GET['redirect']);
        exit;
    }
    echo '<form method="GET"><input type="hidden" name="page" value="redirect">';
    echo 'Redirect to: <input name="redirect" value="https://example.com">';
    echo '<input type="submit" value="Go"></form>';
    echo '</div>';
    break;

// ─── File Upload (CWE-434) ───────────────────────────────────────
case 'upload':
    echo '<div class="vuln"><h2>Unrestricted File Upload (CWE-434)</h2>';
    echo '<form method="POST" enctype="multipart/form-data" action="?page=upload">';
    echo '<input type="file" name="uploaded_file"><br>';
    echo '<input type="submit" value="Upload">';
    echo '</form>';
    // No CSRF token!
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['uploaded_file'])) {
        $target = '/tmp/uploads/' . basename($_FILES['uploaded_file']['name']);
        @mkdir('/tmp/uploads', 0777, true);
        // VULNERABLE: No file type validation
        if (move_uploaded_file($_FILES['uploaded_file']['tmp_name'], $target)) {
            echo "<p>✅ Uploaded to: $target</p>";
        }
    }
    echo '</div>';
    break;

// ─── XXE (CWE-611) ───────────────────────────────────────────────
case 'xxe':
    echo '<div class="vuln"><h2>XXE — XML External Entity (CWE-611)</h2>';
    echo '<form method="POST" action="?page=xxe">';
    echo '<textarea name="xml" rows="6" cols="60">&lt;?xml version=&quot;1.0&quot;?&gt;
&lt;user&gt;&lt;name&gt;test&lt;/name&gt;&lt;/user&gt;</textarea><br>';
    echo '<input type="submit" value="Parse XML"></form>';
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['xml'])) {
        // VULNERABLE: External entities enabled
        libxml_disable_entity_loader(false);
        $doc = new DOMDocument();
        $doc->loadXML($_POST['xml'], LIBXML_NOENT | LIBXML_DTDLOAD);
        echo "<pre>Parsed: " . htmlspecialchars($doc->textContent) . "</pre>";
    }
    echo '</div>';
    break;

// ─── IDOR (CWE-639) ──────────────────────────────────────────────
case 'idor':
    echo '<div class="vuln"><h2>IDOR (CWE-639)</h2>';
    $users = [
        1 => ['name' => 'Admin', 'email' => 'admin@corp.com', 'salary' => '$150,000'],
        2 => ['name' => 'John', 'email' => 'john@corp.com', 'salary' => '$85,000'],
        3 => ['name' => 'Jane', 'email' => 'jane@corp.com', 'salary' => '$92,000'],
    ];
    $uid = $_GET['user_id'] ?? 1;
    // VULNERABLE: No authorization check
    if (isset($users[$uid])) {
        echo "<pre>" . print_r($users[$uid], true) . "</pre>";
    }
    echo '<p>Try: ?page=idor&user_id=1, 2, or 3</p>';
    echo '</div>';
    break;

// ─── SSTI (CWE-94) ───────────────────────────────────────────────
case 'ssti':
    echo '<div class="vuln"><h2>Template Injection (CWE-94)</h2>';
    echo '<form method="GET"><input type="hidden" name="page" value="ssti">';
    echo 'Name: <input name="name" value="' . ($_GET['name'] ?? 'World') . '">';
    echo '<input type="submit" value="Greet"></form>';
    if (isset($_GET['name'])) {
        $name = $_GET['name'];
        // VULNERABLE: eval-like behavior
        if (preg_match('/\{\{(.+?)\}\}/', $name, $m)) {
            $expr = $m[1];
            $result = @eval("return $expr;");
            $name = str_replace($m[0], $result, $name);
        }
        echo "<p>Hello, $name!</p>";
    }
    echo '</div>';
    break;

// ─── CSRF (CWE-352) ─────────────────────────────────────────────
case 'csrf':
    echo '<div class="vuln"><h2>CSRF — No Token (CWE-352)</h2>';
    echo '<form method="POST" action="?page=csrf">';
    echo 'New Password: <input type="password" name="password"><br>';
    echo '<input type="submit" value="Change Password">';
    echo '</form>';
    // No CSRF token!
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        echo "<p>✅ Password changed to: " . htmlspecialchars($_POST['password']) . "</p>";
    }
    echo '</div>';
    break;

// ─── Home ─────────────────────────────────────────────────────────
default:
    echo '<h2>Available Vulnerability Modules</h2>';
    echo '<table border="1" cellpadding="5" style="border-color:#0f0">';
    echo '<tr><th>Module</th><th>CWE</th><th>OWASP</th><th>Link</th></tr>';
    $mods = [
        ['SQL Injection', 'CWE-89', 'A03', '?page=sqli&id=1'],
        ['XSS Reflected', 'CWE-79', 'A03', '?page=xss&q=test'],
        ['Command Injection', 'CWE-78', 'A03', '?page=cmdi&host=127.0.0.1'],
        ['LFI / Path Traversal', 'CWE-22', 'A01', '?page=lfi&file=/etc/passwd'],
        ['SSRF', 'CWE-918', 'A10', '?page=ssrf&url=http://127.0.0.1:22'],
        ['Open Redirect', 'CWE-601', 'A01', '?page=redirect'],
        ['File Upload', 'CWE-434', 'A04', '?page=upload'],
        ['XXE', 'CWE-611', 'A05', '?page=xxe'],
        ['IDOR', 'CWE-639', 'A01', '?page=idor&user_id=1'],
        ['SSTI', 'CWE-94', 'A03', '?page=ssti&name={{7*7}}'],
        ['CSRF', 'CWE-352', 'A01', '?page=csrf'],
    ];
    foreach ($mods as $m) {
        echo "<tr><td>{$m[0]}</td><td>{$m[1]}</td><td>{$m[2]}</td><td><a href='{$m[3]}'>Test →</a></td></tr>";
    }
    echo '</table>';
    echo '<h3>Also vulnerable to:</h3><ul>';
    echo '<li>Missing security headers (CSP, HSTS, X-Frame-Options)</li>';
    echo '<li>Hardcoded credentials in source</li>';
    echo '<li>Weak session management</li>';
    echo '<li>Information disclosure (phpinfo, .env)</li>';
    echo '<li>Clickjacking (no X-Frame-Options)</li>';
    echo '<li>CORS misconfiguration</li>';
    echo '</ul>';
    break;
}
?>
<hr>
<p style="color:#666">AEGIS Test Target v1.0 | PHP <?= phpversion() ?> | <?= php_uname() ?></p>
</body>
</html>
