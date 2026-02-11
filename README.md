# WP-Hunter: Advanced WordPress SAST & Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-SAST-red.svg)](https://github.com/fazaroot)
[![Status](https://img.shields.io/badge/Status-Active-success.svg)]()

**WP-Hunter** is a next-generation static application security testing (SAST) tool specifically designed for WordPress plugins and themes. Unlike traditional scanners that rely solely on simple regex matching, WP-Hunter utilizes a **Deep-Hook Data Flow Analysis** engine to trace user input from source to sink, significantly reducing false positives.

Built for security researchers, bug bounty hunters, and developers who need to audit codebases for critical vulnerabilities like Unauthenticated RCE, SQL Injection, and Local File Disclosure (LFD).

---

## 🚀 Key Features

### 🧠 Deep-Hook Data Flow Analysis
The core engine traces variables from user inputs (`$_GET`, `$_POST`, `$_REQUEST`) to dangerous sinks (`query`, `eval`, `exec`). It detects if the data is sanitized before usage, ensuring that reported vulnerabilities are valid threats, not just random code matches.

### 🎭 Entropy-Based Backdoor Detection
Utilizes **Shannon Entropy** mathematics to identify obfuscated code blocks, hidden `base64` strings, and encrypted payloads often used in malware or backdoors.

### ⚡ Smart False Positive Filtering
Advanced context-aware filtering system that understands comments, safe functions (e.g., `wp_verify_nonce`, `current_user_can`), and dead code, keeping your report clean and actionable.

### 🔍 Automated Critical File Discovery
Automatically identifies exposed sensitive files such as `.env`, `debug.log`, database dumps (`.sql`), and backup configuration files often left by developers.

### 📡 Real-Time Discord Reporting
Integrated webhook support to send formatted, high-priority scan reports directly to your private Discord server for instant alerts during mass scanning operations.

---

## 🛠️ Detection Capabilities

WP-Hunter is optimized to detect over 20+ vulnerability classes, including but not limited to:

* **Critical:** Remote Code Execution (RCE) via `eval`/`exec`
* **Critical:** SQL Injection (SQLi) & Blind SQLi
* **Critical:** Local File Inclusion (LFI) & Disclosure (LFD)
* **Critical:** Arbitrary File Upload & Deletion
* **Critical:** Privilege Escalation (Insecure `update_option`)
* **Critical:** Authentication Bypass & Weak Nonce Verification
* **High:** Cross-Site Scripting (XSS) - Reflected & Stored
* **High:** Hardcoded Secrets (AWS Keys, API Tokens)
* **Medium:** Open Redirects & CSRF

---

## 📦 Installation

Clone the repository and run directly with Python 3. No complex dependencies required.

```bash
git clone [https://github.com/fazaroot/wp-hunter.git](https://github.com/fazaroot/wp-hunter.git)
cd wp-hunter

##💻 Usage
Basic Scan (Single Plugin):
python3 scanner.py plugin-name.zip

Scan with Custom Report Output:
python3 scanner.py target-plugin.zip report.json

Bulk Scanning:
You can automate this tool using bash loops to scan entire directories of downloaded plugins.
​##📊 Sample Output (Console)

╔═══════════════════════════════════════════════════════════════════════════════╗
║                            WP-Hunter Elite Scanner                            ║
║                Deep Analysis & Entropy-Based Detection Engine                 ║
╚═══════════════════════════════════════════════════════════════════════════════╝

[+] Extracting plugin...
[+] Scanning directory: /extracted/plugin-folder/
[+] Found 45 PHP files

[12/45] (26.6%) includes/db-query.php
    [!] CRITICAL: SQL Injection vulnerability detected
    Line: 124
    Code: $wpdb->query("SELECT * FROM table WHERE id = " . $_GET['id']);
    Status: TAINTED FLOW - No sanitization detected

[30/45] (66.6%) assets/js/upload-handler.php
    [!] CRITICAL: Arbitrary File Upload
    Line: 15
    Code: move_uploaded_file($_FILES['file']['tmp_name'], $target);

[✓] Report saved: scan_report.json
[✓] Sent summary to Discord

##⚠️ Disclaimer
​This tool is developed for educational purposes and authorized security research only. The author (fazaroot) is not responsible for any misuse of this tool or any damage caused by it.
​By using this software, you agree to:
​Only scan targets you own or have explicit permission to audit.
​Use the findings to improve security and report vulnerabilities responsibly (Responsible Disclosure).
​Comply with all local and international cyber laws.

​##🤝 Contribution
​Contributions are welcome! If you find a new vulnerability pattern or want to improve the analysis engine, feel free to submit a Pull Request.
​Author: fazaroot
Mail: fazastret9@gmail.com
```
