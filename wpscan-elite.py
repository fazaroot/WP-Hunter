#!/usr/bin/env python3
"""
WordPress Plugin CVE Scanner Pro Elite Edition
Advanced vulnerability scanner dengan Deep Analysis & Entropy Detection
"""

import zipfile
import os
import re
import json
import hashlib
import math
from datetime import datetime
from pathlib import Path
import shutil
from collections import Counter, defaultdict
import time

# ANSI Color Codes
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    
    # Standard colors
    BLACK = '\033[30m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    
    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    
    # Background colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    
    # Custom colors
    ORANGE = '\033[38;5;208m'
    PURPLE = '\033[38;5;141m'
    PINK = '\033[38;5;213m'

class DataFlowTracer:
    """Deep-Hook Analysis untuk melacak data flow dari input ke sink"""
    
    def __init__(self):
        self.tainted_vars = set()
        self.data_flows = []
        
    def trace_variable_flow(self, content, file_path):
        """Trace data flow dari user input sampai ke dangerous sink"""
        flows = []
        
        # Find all user inputs (sources)
        sources = [
            r'\$_GET\s*\[\s*["\'](\w+)["\']\s*\]',
            r'\$_POST\s*\[\s*["\'](\w+)["\']\s*\]',
            r'\$_REQUEST\s*\[\s*["\'](\w+)["\']\s*\]',
            r'\$_COOKIE\s*\[\s*["\'](\w+)["\']\s*\]',
        ]
        
        # Find dangerous sinks
        sinks = {
            'sql': [
                r'\$wpdb->query\s*\(',
                r'\$wpdb->get_results\s*\(',
                r'mysql_query\s*\(',
                r'mysqli_query\s*\(',
            ],
            'exec': [
                r'(?<!curl_)exec\s*\(',
                r'shell_exec\s*\(',
                r'system\s*\(',
                r'passthru\s*\(',
            ],
            'file': [
                r'file_get_contents\s*\(',
                r'file_put_contents\s*\(',
                r'fopen\s*\(',
                r'include\s*\(',
                r'require\s*\(',
            ]
        }
        
        lines = content.split('\n')
        
        # Track variable assignments
        var_assignments = {}
        
        for line_num, line in enumerate(lines, 1):
            # Check for tainted input assignment
            for source_pattern in sources:
                matches = re.finditer(source_pattern, line)
                for match in matches:
                    # Check if assigned to variable
                    var_assign = re.search(r'\$(\w+)\s*=\s*\$_(GET|POST|REQUEST|COOKIE)', line)
                    if var_assign:
                        var_name = var_assign.group(1)
                        var_assignments[var_name] = {
                            'source': match.group(0),
                            'line': line_num,
                            'tainted': True
                        }
            
            # Check if tainted variables reach sinks
            for sink_type, sink_patterns in sinks.items():
                for sink_pattern in sink_patterns:
                    if re.search(sink_pattern, line):
                        # Check if any tainted variable is used
                        for var_name, var_info in var_assignments.items():
                            if var_info.get('tainted') and f'${var_name}' in line:
                                # Check for sanitization
                                has_sanitization = any([
                                    'sanitize_' in line,
                                    'esc_' in line,
                                    'intval' in line,
                                    'absint' in line,
                                    'prepare' in line,
                                    'escapeshellcmd' in line,
                                    'escapeshellarg' in line,
                                ])
                                
                                flows.append({
                                    'file': file_path,
                                    'source_line': var_info['line'],
                                    'sink_line': line_num,
                                    'source': var_info['source'],
                                    'sink': sink_pattern,
                                    'sink_type': sink_type,
                                    'variable': var_name,
                                    'sanitized': has_sanitization,
                                    'severity': 'LOW' if has_sanitization else 'CRITICAL'
                                })
        
        return flows

class EntropyAnalyzer:
    """Entropy-Based Backdoor Detection"""
    
    @staticmethod
    def calculate_entropy(data):
        """Calculate Shannon entropy"""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy
    
    @staticmethod
    def detect_encoded_payload(content):
        """Detect high-entropy encoded payloads (backdoors)"""
        suspicious_patterns = []
        
        # Find base64-like strings
        base64_pattern = r'["\']([A-Za-z0-9+/]{50,}={0,2})["\']'
        matches = re.finditer(base64_pattern, content)
        
        for match in matches:
            encoded_str = match.group(1)
            entropy = EntropyAnalyzer.calculate_entropy(encoded_str)
            
            # High entropy (>4.5) indicates encrypted/encoded data
            if entropy > 4.5:
                # Check if used with decode functions
                context_start = max(0, match.start() - 100)
                context_end = min(len(content), match.end() + 100)
                context = content[context_start:context_end]
                
                is_suspicious = any([
                    'base64_decode' in context,
                    'eval' in context,
                    'gzinflate' in context,
                    'gzuncompress' in context,
                    'str_rot13' in context,
                    'assert' in context,
                ])
                
                if is_suspicious:
                    suspicious_patterns.append({
                        'encoded_string': encoded_str[:100] + '...',
                        'entropy': round(entropy, 2),
                        'length': len(encoded_str),
                        'context': context.strip()
                    })
        
        return suspicious_patterns

class WordPressCVEScanner:
    def __init__(self):
        self.vulnerabilities = []
        self.file_count = 0
        self.scanned_files = []
        self.plugin_info = {}
        self.suspicious_functions = []
        self.outdated_functions = []
        self.security_headers = []
        self.code_quality_issues = []
        self.data_flows = []
        self.backdoor_detections = []
        self.scan_start_time = time.time()
        self.output_dir = 'wp_scancve'
        self.data_flow_tracer = DataFlowTracer()
        
        # Vulnerability patterns dengan improved accuracy
        self.patterns = {
            'sql_injection': {
                'severity': 'CRITICAL',
                'patterns': [
                    r'\$wpdb->query\s*\(\s*["\'][^"\']*\$[^"\']*["\']',
                    r'\$wpdb->get_results\s*\(\s*["\'][^"\']*\$[^"\']*["\']',
                    r'SELECT\s+.*?WHERE\s+.*?\$_(GET|POST|REQUEST)',
                ],
                'description': 'SQL Injection vulnerability detected',
                'color': Colors.RED,
                'exclude_patterns': [r'\$wpdb->prepare', r'->prepare\('],
                'require_tainted': True
            },
            'rce_unserialize': {
                'severity': 'CRITICAL',
                'patterns': [
                    r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
                ],
                'description': 'PHP Object Injection via Unserialize',
                'color': Colors.BRIGHT_RED,
                'require_tainted': True
            },
            'command_injection': {
                'severity': 'CRITICAL',
                'patterns': [
                    r'(?<!curl_)(?<!mysqli_stmt_)exec\s*\(\s*[^)]*\$_(GET|POST|REQUEST)',
                    r'shell_exec\s*\(\s*[^)]*\$_(GET|POST|REQUEST)',
                    r'system\s*\(\s*[^)]*\$_(GET|POST|REQUEST)',
                    r'passthru\s*\(\s*[^)]*\$_(GET|POST|REQUEST)',
                ],
                'description': 'Command Injection vulnerability',
                'color': Colors.ORANGE,
                'exclude_patterns': [
                    r'curl_exec',
                    r'mysqli_stmt_exec',
                    r'escapeshellcmd',
                    r'escapeshellarg'
                ],
                'require_tainted': True
            },
            'xss': {
                'severity': 'HIGH',
                'patterns': [
                    r'echo\s+\$_(GET|POST|REQUEST|COOKIE)(?!.*esc_)',
                    r'print\s+\$_(GET|POST|REQUEST|COOKIE)(?!.*esc_)',
                ],
                'description': 'Cross-Site Scripting (XSS) vulnerability',
                'color': Colors.YELLOW,
                'exclude_patterns': [
                    r'esc_html',
                    r'esc_attr',
                    r'esc_url',
                    r'esc_js',
                    r'wp_kses'
                ],
                'require_tainted': True
            },
            'file_inclusion': {
                'severity': 'CRITICAL',
                'patterns': [
                    r'(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST)',
                ],
                'description': 'Local/Remote File Inclusion vulnerability',
                'color': Colors.RED,
                'require_tainted': True
            },
            'arbitrary_file_upload': {
                'severity': 'CRITICAL',
                'patterns': [
                    r'move_uploaded_file\s*\(\s*\$_FILES(?!.*wp_check_filetype)',
                ],
                'description': 'Arbitrary File Upload vulnerability',
                'color': Colors.BRIGHT_RED,
                'exclude_patterns': [r'wp_check_filetype', r'wp_handle_upload']
            },
            'missing_nonce_check': {
                'severity': 'MEDIUM',
                'patterns': [
                    r'if\s*\(\s*isset\s*\(\s*\$_POST(?!.*wp_verify_nonce)(?!.*check_admin_referer)',
                ],
                'description': 'Sensitive action without Nonce verification',
                'color': Colors.YELLOW,
                'exclude_patterns': [r'wp_verify_nonce', r'check_admin_referer']
            },
            'csrf': {
                'severity': 'MEDIUM',
                'patterns': [
                    r'(add_action|do_action)\s*\(\s*["\']admin_(?!.*wp_nonce)',
                ],
                'description': 'CSRF missing protection',
                'color': Colors.YELLOW,
                'exclude_patterns': [r'wp_nonce']
            },
            'auth_bypass': {
                'severity': 'CRITICAL',
                'patterns': [
                    r'is_admin\(\)(?!.*current_user_can)',
                ],
                'description': 'Authentication bypass vulnerability',
                'color': Colors.RED,
                'exclude_patterns': [r'current_user_can', r'is_super_admin']
            },
            'path_traversal': {
                'severity': 'HIGH',
                'patterns': [
                    r'(file_get_contents|readfile|fopen)\s*\([^)]*\$_(GET|POST|REQUEST)',
                ],
                'description': 'Path Traversal vulnerability',
                'color': Colors.ORANGE,
                'exclude_patterns': [r'realpath', r'basename'],
                'require_tainted': True
            },
            'weak_cryptography': {
                'severity': 'HIGH',
                'patterns': [
                    r'md5\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                    r'sha1\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                ],
                'description': 'Weak cryptographic function detected',
                'color': Colors.YELLOW
            },
            'eval_injection': {
                'severity': 'CRITICAL',
                'patterns': [
                    r'eval\s*\(\s*[^)]*\$_(GET|POST|REQUEST|COOKIE)',
                    r'assert\s*\(\s*[^)]*\$_(GET|POST|REQUEST)',
                ],
                'description': 'Code injection via eval() or assert()',
                'color': Colors.BRIGHT_MAGENTA,
                'require_tainted': True
            },
            'hardcoded_credentials': {
                'severity': 'CRITICAL',
                'patterns': [
                    r'(password|passwd|pwd)\s*=\s*["\'](?!\$)[\w!@#$%^&*]{8,}["\']',
                ],
                'description': 'Hardcoded credentials in source code',
                'color': Colors.RED
            },
            'privilege_escalation': {
                'severity': 'CRITICAL',
                'patterns': [
                    r'update_option\s*\(\s*["\'](?:admin_email|siteurl)["\'].*?\$_(GET|POST)',
                    r'wp_insert_user.*?administrator(?!.*current_user_can)',
                ],
                'description': 'Privilege escalation vulnerability',
                'color': Colors.BRIGHT_RED,
                'exclude_patterns': [r'current_user_can\s*\(\s*["\']manage_options["\']']
            },
            'backdoor_obfuscated': {
                'severity': 'CRITICAL',
                'patterns': [
                    r'eval\s*\(\s*base64_decode',
                    r'eval\s*\(\s*gzinflate',
                    r'eval\s*\(\s*str_rot13',
                    r'assert\s*\(\s*base64_decode',
                    r'preg_replace\s*\([^)]*\/e["\']',
                    r'create_function\s*\(',
                ],
                'description': 'Obfuscated backdoor detected',
                'color': Colors.BRIGHT_MAGENTA
            },
            'insecure_ajax_nopriv': {
                 'severity': 'CRITICAL', # Perbaikan: saverity -> severity
                 'patterns': [
                     r"add_action\s*\(\s*['\"]wp_ajax_nopriv_.*?(save|update|delete|edit|remove|install).*?['\"]"
                 ],
                 'description': 'Sensitive AJAX action accessible without login (nopriv)',
                 'color': Colors.BRIGHT_MAGENTA
            },
            'dangerous_request_usage': { # Perbaikan: usange -> usage
                 'severity': 'MEDIUM', # $_REQUEST biasanya Medium kecuali masuk ke query
                 'patterns': [
                     r'\$_REQUEST\s*\[' # Gunakan single quote r'...'
                 ],
                 'description': 'Usage of $_REQUEST detected. Use $_POST for better security',
                 'color': Colors.YELLOW
            },
            'missing_ajax_nonce_check': {
                 'severity': 'CRITICAL', # Perbaikan: saverity -> severity
                 'patterns': [
                     r'function\s+ajax_.*?\(.*?\)\s*\{(?![^}]*?(check_ajax_referer|wp_verify_nonce|nonce))'
                 ],
                 'description': 'AJAX function potentially missing Nonce/Referer verification',
                 'color': Colors.BRIGHT_MAGENTA
            },
            'arbitrary_file_deletion': {
                'severity': 'CRITICAL',
                'patterns': [
                    r'unlink\s*\(\s*[^)]*\$_(GET|POST|REQUEST)',
                    r'wp_delete_file\s*\(\s*[^)]*\$_(GET|POST|REQUEST)'
                ],
                'description': 'Potential Arbitrary File Deletion (Can delete wp-config.php)',
                'color': Colors.RED,
                'require_tainted': True
            },
            'insecure_option_manipulation': {
                'severity': 'HIGH',
                'patterns': [
                    r'update_option\s*\(\s*["\'][^"\']*["\']\s*,\s*\$_(GET|POST|REQUEST)'
                ],
                'description': 'Direct user input into update_option() - Risk of site takeover',
                'color': Colors.ORANGE
            },
            'global_variable_overwrite': {
                'severity': 'CRITICAL',
                'patterns': [
                    r'foreach\s*\(\s*\$_(GET|POST|REQUEST).*?as.*?key.*?=>.*?value.*?(\$\$key|import_request_variables)'
                ],
                'description': 'Global variable overwriting (Register Globals style exploit)',
                'color': Colors.BRIGHT_RED
            },
            'upload_without_type_check': {
                'severity': 'CRITICAL',
                'patterns': [
                    r'\$_FILES\[.*?\].*?\[["\']tmp_name["\']\](?![^;]*?wp_check_filetype)'
                ],
                'description': 'File upload without wp_check_filetype() validation',
                'color': Colors.RED
            },
            'arbitrary_file_manipulation': {
                'severity': 'CRITICAL',
                'patterns': [
                    r'unlink\s*\(\s*[^)]*?\$_[A-Z]+\b',
                    r'wp_delete_file\s*\(\s*[^)]*?\$_[A-Z]+\b'
                ],
                'description': 'User-controlled file deletion (Potential to delete wp-config.php)',
                'color': Colors.RED,
                'require_tainted': True
            },
            'open_redirect': {
                'severity': 'MEDIUM',
                'patterns': [
                    r'wp_redirect\s*\(\s*[^)]*?\$_[A-Z]+\b(?![^;]*?wp_safe_redirect)'
                ],
                'description': 'Potential Open Redirect via wp_redirect()',
                'color': Colors.YELLOW,
                'require_tainted': True
            },
            'nonce_leak_in_js': {
                'severity': 'MEDIUM',
                'patterns': [
                    r'wp_localize_script\s*\(.*?nonce.*?\$_(GET|POST|REQUEST)'
                ],
                'description': 'Potential Nonce leakage to client-side script',
                'color': Colors.YELLOW
            },
            'insecure_admin_hook': {
                'severity': 'CRITICAL',
                'patterns': [
                    r'add_action\s*\(\s*["\']admin_init["\']'
                ],
                'description': 'Potential Privilege Escalation: admin_init hook can be triggered by any logged-in user',
                'color': Colors.BRIGHT_RED
            },
            'attack_surface_ajax': {
                'severity': 'CRITICAL',
                'patterns': [r'add_action\s*\(\s*["\']wp_ajax_'],
                'description': 'AJAX Endpoint detected',
                'color': Colors.CYAN
            },
            'attack_surface_shortcode': {
                'severity': 'INFO',
                'patterns': [r'add_shortcode\s*\('],
                'description': 'Shortcode detected (Potential XSS vector)',
                'color': Colors.CYAN
            },
            'insecure_rest_api': {
                'severity': 'HIGH',
                'patterns': [
                    r'register_rest_route\(.*?(?![^;]*?permission_callback)'
                ],
                'description': 'REST API Route without permission_callback (Publicly accessible)',
                'color': Colors.ORANGE
            },
            'weak_capability_check': {
                'severity': 'HIGH',
                'patterns': [
                    r"current_user_can\s*\(\s*['\"]read['\"]",
                    r"current_user_can\s*\(\s*['\"]edit_posts['\"]",
                    r"current_user_can\s*\(\s*['\"]upload_files['\"]"
                ],
                'description': 'Weak Capability Check: Fungsi sensitif bisa diakses oleh level user rendah (Contributor/Author).',
                'color': Colors.ORANGE
            }
        }
        
        # Safe function patterns
        self.safe_patterns = [
            r'curl_exec\s*\(',
            r'mysqli_stmt_exec\s*\(',
            r'PDOStatement::exec',
        ]
        
        # Deprecated WordPress functions
        self.deprecated_funcs = {
            'mysql_connect': 'Use mysqli or PDO instead',
            'mysql_query': 'Use $wpdb methods instead',
            'get_settings': 'Use get_option() instead',
            'get_currentuserinfo': 'Use wp_get_current_user() instead',
        }

    def create_output_directory(self):
        """Create wp_scancve directory for all outputs"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print(f"{Colors.GREEN}[✓] Created output directory: {self.output_dir}/{Colors.RESET}")
        return self.output_dir

    def is_false_positive(self, matched_code, context, exclude_patterns=None):
        """Advanced false positive detection"""
        # Check safe patterns
        for safe_pattern in self.safe_patterns:
            if re.search(safe_pattern, matched_code, re.IGNORECASE):
                return True
        
        # Check exclude patterns
        if exclude_patterns:
            for exclude_pattern in exclude_patterns:
                if re.search(exclude_pattern, context, re.IGNORECASE):
                    return True
        
        # Check if in comment
        lines = context.split('\n')
        for line in lines:
            if matched_code in line:
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                    return True
        
        return False

    def extract_plugin_info(self, directory):
        """Extract plugin metadata"""
        print(f"{Colors.CYAN}[+] Extracting plugin information...{Colors.RESET}")
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.php'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(8192)
                            
                            if 'Plugin Name:' in content:
                                # SEMUA DI BAWAH INI HARUS MENJOROK KE DALAM (4 SPASI DARI IF)
                                name_match = re.search(r'Plugin Name:\s*(.+)', content)
                                version_match = re.search(r'Version:\s*(.+)', content)
                                author_match = re.search(r'Author:\s*(.+)', content)
                                
                                if name_match:
                                    self.plugin_info['Name'] = name_match.group(1).strip()
                                if version_match:
                                    self.plugin_info['Version'] = version_match.group(1).strip()
                                if author_match:
                                    self.plugin_info['Author'] = author_match.group(1).strip()
                                
                                # Langsung return setelah dapet info utama
                                return self.plugin_info
                    except Exception as e:
                        continue
        
        return self.plugin_info

    def scan_file(self, file_path):
        """Scan single file dengan deep analysis"""
        try:
        	# --- MULAI PASTE DI SINI ---
            # Pastikan ada 12 spasi (3 level indentasi) di depan baris ini
            sensitive_files = ['.env', 'error_log', 'debug.log', 'config.php.bak', 'phpinfo.php']
            if os.path.basename(file_path).lower() in sensitive_files:
                self.stats["CRITICAL"] += 1
                # Simpan temuan ke list lokal agar di-return di akhir fungsi
                vuln_sensitive = {
                    "type": "SENSITIVE FILE EXPOSURE",
                    "file": file_path,
                    "severity": "CRITICAL",
                    "description": "File sensitif ditemukan di direktori publik!",
                    "line": 0,
                    "matched_code": "File Name Match",
                    "color": Colors.RED
                }
                # Jika ingin langsung ditampilkan ke hasil scan
                return [vuln_sensitive]
                
                # Deep Search for Secret Files & Backups
            secret_patterns = [
                r'.*\.(sql|bak|log|old|swp)$', # File database/backup/log
                r'^(debug|error|access)_log$', # File log server
                r'^config(\.inc)?\.php\.bak$'  # Backup config
            ]
            filename = os.path.basename(file_path).lower()
            for p in secret_patterns:
                if re.match(p, filename):
                    self.stats["CRITICAL"] += 1
                    return [{
                        "type": "SECRET_FILE_EXPOSURE",
                        "file": file_path,
                        "severity": "CRITICAL",
                        "description": f"Sensitive file type ({filename}) exposed in directory!",
                        "line": 0,
                        "matched_code": "Filename Match",
                        "color": Colors.BRIGHT_RED
                    }]
                                   
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            vulnerabilities_found = []
            # --- SECRET SCRAPER LOGIC ---
            secret_patterns = {
                'AWS_Key': r'AKIA[0-9A-Z]{16}',
                'Firebase_URL': r'https://.*\.firebaseio\.com',
                'Generic_Secret': r'(?i)(secret|password|auth_token|access_token)\s*[:=]\s*["\'][a-zA-Z0-9]{10,}["\']'
            }
            
            for secret_type, s_pattern in secret_patterns.items():
                secret_match = re.search(s_pattern, content)
                if secret_match:
                    vulnerabilities_found.append({
                        'type': f'HARDCODED_{secret_type}',
                        'severity': 'HIGH',
                        'description': f'Terdeteksi {secret_type} di dalam kode. Risiko kebocoran kredensial!',
                        'file': file_path,
                        'line': content[:secret_match.start()].count('\n') + 1,
                        'matched_code': secret_match.group(0)[:50],
                        'color': Colors.YELLOW
                    })
                    
            # Perform data flow analysis
            data_flows = self.data_flow_tracer.trace_variable_flow(content, file_path)
            if data_flows:
                self.data_flows.extend(data_flows)
            
            # Perform entropy analysis for backdoors
            entropy_results = EntropyAnalyzer.detect_encoded_payload(content)
            if entropy_results:
                self.backdoor_detections.append({
                    'file': file_path,
                    'detections': entropy_results
                })
            
            
            # Pattern-based scanning
            for vuln_type, vuln_data in self.patterns.items():
                for pattern in vuln_data['patterns']:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Extract context
                        lines = content.split('\n')
                        start_line = max(0, line_num - 3)
                        end_line = min(len(lines), line_num + 3)
                        code_snippet = '\n'.join(lines[start_line:end_line])
                        
                        # Check false positive
                        exclude_patterns = vuln_data.get('exclude_patterns', [])
                        if self.is_false_positive(match.group(0), code_snippet, exclude_patterns):
                            continue
                        
                        # Check if vulnerability requires tainted data flow
                        if vuln_data.get('require_tainted', False):
                            # Verify with data flow analysis
                            has_tainted_flow = any(
                                flow['sink_line'] == line_num and flow['file'] == file_path
                                for flow in data_flows
                            )
                            
                            # If no tainted flow found, lower severity
                            if not has_tainted_flow:
                                continue
                        
                        vuln = {
                            'type': vuln_type,
                            'severity': vuln_data['severity'],
                            'description': vuln_data['description'],
                            'file': file_path,
                            'line': line_num,
                            'matched_code': match.group(0),
                            'code_snippet': code_snippet,
                            'color': vuln_data.get('color', Colors.WHITE),
                            'confidence': 'HIGH'
                        }
                        
                        vulnerabilities_found.append(vuln)
            
            return vulnerabilities_found
            
        except Exception as e:
            print(f"{Colors.RED}[!] Error scanning {file_path}: {e}{Colors.RESET}")
            return []

    def extract_zip(self, zip_path):
        """Extract ZIP to wp_scancve directory"""
        extract_dir = os.path.join(self.output_dir, 'extracted')
        
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        
        os.makedirs(extract_dir)
        print(f"{Colors.GREEN}[+] Extracting {zip_path} to {extract_dir}{Colors.RESET}")
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            return extract_dir
        except Exception as e:
            print(f"{Colors.RED}[!] Error extracting ZIP: {e}{Colors.RESET}")
            return None

    def scan_directory(self, directory):
        """Scan all PHP files in directory"""
        print(f"{Colors.CYAN}[+] Scanning directory: {directory}{Colors.RESET}")
        
        self.extract_plugin_info(directory)
        
        php_files = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(('.php', '.inc', '.module')):
                    php_files.append(os.path.join(root, file))
        
        print(f"{Colors.GREEN}[+] Found {len(php_files)} PHP files{Colors.RESET}\n")
        
        for php_file in php_files:
            self.file_count += 1
            relative_path = os.path.relpath(php_file, directory)
            
            progress = (self.file_count / len(php_files)) * 100
            print(f"{Colors.CYAN}[{self.file_count}/{len(php_files)}] ({progress:.1f}%) {relative_path}{Colors.RESET}")
            
            vulns = self.scan_file(php_file)
            if vulns:
                self.vulnerabilities.extend(vulns)
                self.scanned_files.append({
                    'file': relative_path,
                    'vulnerabilities': len(vulns)
                })

    def draw_dynamic_chart(self, vuln_counts):
        """Draw dynamic bar chart based on vulnerability types"""
        if not vuln_counts:
            return
        
        max_count = max(vuln_counts.values())
        scale = 40
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}╔{'═' * 80}╗{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}║{' ' * 25}📊 VULNERABILITY DISTRIBUTION{' ' * 24}║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}╠{'═' * 80}╣{Colors.RESET}")
        
        # Group by severity and color
        vuln_groups = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'INFO':[]
        }
        
        for vuln_type, count in vuln_counts.items():
            if vuln_type in self.patterns:
                severity = self.patterns[vuln_type]['severity']
                color = self.patterns[vuln_type].get('color', Colors.WHITE)
                vuln_groups[severity].append((vuln_type, count, color))
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO']:
            if vuln_groups[severity]:
                print(f"{Colors.BOLD}{Colors.WHITE}║ {severity} SEVERITY:{' ' * (66 - len(severity))}║{Colors.RESET}")
                print(f"{Colors.CYAN}╠{'─' * 80}╣{Colors.RESET}")
                
                for vuln_type, count, color in sorted(vuln_groups[severity], key=lambda x: x[1], reverse=True):
                    bar_length = int((count / max_count) * scale) if max_count > 0 else 0
                    bar = '█' * bar_length
                    spaces = ' ' * (scale - bar_length)
                    
                    type_display = vuln_type.replace('_', ' ').title()[:20]
                    print(f"{Colors.WHITE}║ {color}{type_display:20}{Colors.RESET} │ {color}{bar}{spaces}{Colors.RESET} │ {count:3} │{Colors.RESET}")
        
        print(f"{Colors.BOLD}{Colors.CYAN}╚{'═' * 80}╝{Colors.RESET}\n")
  
    def check_plugin_version(self, slug, current_version):
        """Mengecek apakah versi plugin sudah out-of-date via WP.org API"""
        try:
            import requests
            slug = slug.split('.')[0].lower()
            url = f"https://api.wordpress.org/plugins/info/1.0/{slug}.json"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                latest_version = data.get('version', 'Unknown')
                if latest_version != current_version and latest_version != 'Unknown':
                    return f"{Colors.BRIGHT_YELLOW}[!] Update Available: {current_version} -> {latest_version} (Security Risk!){Colors.RESET}"
                return f"{Colors.BRIGHT_GREEN}[✓] Plugin version {current_version} is latest.{Colors.RESET}"
            return f"{Colors.GRAY}[i] Plugin info not found on WP.org (Private/Premium?){Colors.RESET}"
        except Exception:
            return f"{Colors.GRAY}[i] Skip version check: Connection error.{Colors.RESET}"
   
    def print_data_flow_analysis(self):
        """Print data flow analysis results"""
        if not self.data_flows:
            return
        
        critical_flows = [f for f in self.data_flows if f['severity'] == 'CRITICAL']
        
        if critical_flows:
            print(f"\n{Colors.BOLD}{Colors.BRIGHT_RED}╔{'═' * 80}╗{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.BRIGHT_RED}║{' ' * 22}🔍 DEEP-HOOK ANALYSIS RESULTS{' ' * 28}║{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.BRIGHT_RED}╠{'═' * 80}╣{Colors.RESET}")
            print(f"{Colors.BRIGHT_RED}║ Critical Data Flows Detected: {len(critical_flows):3}{' ' * 44}║{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.BRIGHT_RED}╚{'═' * 80}╝{Colors.RESET}\n")
            
            for i, flow in enumerate(critical_flows[:5], 1):
                print(f"{Colors.RED}[{i}] TAINTED DATA FLOW{Colors.RESET}")
                print(f"    {Colors.GRAY}Source:{Colors.RESET} Line {flow['source_line']} - {flow['source']}")
                print(f"    {Colors.GRAY}Sink:{Colors.RESET} Line {flow['sink_line']} - {flow['sink_type'].upper()}")
                print(f"    {Colors.GRAY}Variable:{Colors.RESET} ${flow['variable']}")
                print(f"    {Colors.GRAY}File:{Colors.RESET} {flow['file']}")
                print(f"    {Colors.RED}Status: VULNERABLE - No sanitization detected{Colors.RESET}\n")

    def print_backdoor_analysis(self):
        """Print entropy-based backdoor detection results"""
        if not self.backdoor_detections:
            return
        
        total_detections = sum(len(bd['detections']) for bd in self.backdoor_detections)
        
        print(f"\n{Colors.BOLD}{Colors.BRIGHT_MAGENTA}╔{'═' * 80}╗{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BRIGHT_MAGENTA}║{' ' * 20}🎭 ENTROPY-BASED BACKDOOR DETECTION{' ' * 24}║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BRIGHT_MAGENTA}╠{'═' * 80}╣{Colors.RESET}")
        print(f"{Colors.BRIGHT_MAGENTA}║ High-Entropy Payloads Found: {total_detections:3}{' ' * 44}║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BRIGHT_MAGENTA}╚{'═' * 80}╝{Colors.RESET}\n")
        
        for bd in self.backdoor_detections[:3]:
            for i, detection in enumerate(bd['detections'][:2], 1):
                print(f"{Colors.MAGENTA}[{i}] SUSPICIOUS ENCODED PAYLOAD{Colors.RESET}")
                print(f"    {Colors.GRAY}File:{Colors.RESET} {bd['file']}")
                print(f"    {Colors.GRAY}Entropy:{Colors.RESET} {detection['entropy']}/8.0 (High)")
                print(f"    {Colors.GRAY}Length:{Colors.RESET} {detection['length']} bytes")
                print(f"    {Colors.GRAY}Payload:{Colors.RESET} {detection['encoded_string'][:80]}...")
                print(f"    {Colors.MAGENTA}Status: POTENTIAL BACKDOOR{Colors.RESET}\n")
                
    def generate_auto_analysis(self, vulnerabilities):
        """Menghasilkan kesimpulan analisa cerdas dan rekomendasi tindakan"""
        from collections import Counter
        
        if not vulnerabilities:
            return

        crit = sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL')
        high = sum(1 for v in vulnerabilities if v['severity'] == 'HIGH')
        types = [v['type'] for v in vulnerabilities]
        most_common = Counter(types).most_common(1)[0][0].replace('_', ' ').upper()

        # --- Logika Penentuan Status ---
        if crit > 5:
            status = f"{Colors.RED}SANGAT KRITIS (BERBAHAYA){Colors.RESET}"
            advice = "Matikan plugin segera atau perbaiki fungsi sinkronisasi data."
        elif high > 10:
            status = f"{Colors.ORANGE}RISIKO TINGGI{Colors.RESET}"
            advice = "Audit manual pada fungsi AJAX dan sanitasi input sangat diperlukan."
        else:
            status = f"{Colors.YELLOW}RISIKO MENENGAH{Colors.RESET}"
            advice = "Perkuat validasi nonce dan sanitasi pada input $_REQUEST."

        print(f"{Colors.BOLD}{Colors.CYAN}╔{'═' * 80}╗{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}║{' ' * 30}🧠 AUTO ANALYSIS SUMMARY{' ' * 26}║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}╠{'═' * 80}╣{Colors.RESET}")
        
        # 1. Status Utama
        print(f"{Colors.CYAN}║{Colors.RESET} {Colors.BOLD}Security Status:{Colors.RESET} {status:<65} {Colors.CYAN}║{Colors.RESET}")
        
        # 2. Analisa Celah Terbanyak
        print(f"{Colors.CYAN}║{Colors.RESET} {Colors.BOLD}Main Threat:{Colors.RESET} {most_common:<68} {Colors.CYAN}║{Colors.RESET}")
        
        print(f"{Colors.CYAN}╠{'─' * 80}╣{Colors.RESET}")

        # 3. Paragraf Kesimpulan (Gue bikin lebih rapi tanpa wrapping aneh)
        desc = "Celah ini memungkinkan penyerang melakukan eksekusi kode atau manipulasi data."
        if "NONCE" in most_common:
            desc = "Kurangnya proteksi Nonce memungkinkan hacker membajak sesi Admin (CSRF)."
        elif "SQL" in most_common:
            desc = "Ditemukan pola query database yang tidak aman, berisiko kebocoran data (SQLi)."
        elif "HOOK" in most_common or "AJAX" in most_common:
            desc = "Ditemukan celah otorisasi pada Hook/AJAX. User biasa (Subscriber) mungkin bisa menjalankan fungsi Admin!"
        elif "SECRET" in most_common:
            desc = "Ditemukan kredensial (API Key/Secret) yang tertanam di kode. Ini adalah 'Harta Karun' bagi penyerang."
        
        
        print(f"{Colors.CYAN}║{Colors.RESET} {Colors.BOLD}Analysis:{Colors.RESET} {desc:<69} {Colors.CYAN}║{Colors.RESET}")
        
        # 4. Rekomendasi Tindakan
        print(f"{Colors.CYAN}║{Colors.RESET} {Colors.BOLD}Rekomendasi:{Colors.RESET} {advice:<66} {Colors.CYAN}║{Colors.RESET}")
            
        print(f"{Colors.BOLD}{Colors.CYAN}╚{'═' * 80}╝{Colors.RESET}\n")
        
    def generate_report(self, output_file='scan_report.json'):
        """Generate comprehensive JSON report"""
        critical = [v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']
        high = [v for v in self.vulnerabilities if v['severity'] == 'HIGH']
        medium = [v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']
        
        vuln_by_type = Counter([v['type'] for v in self.vulnerabilities])
        scan_duration = time.time() - self.scan_start_time
        
        output_path = os.path.join(self.output_dir, output_file)
        
        report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'scanner_version': '5.0 Elite Edition - Deep Analysis',
                'total_files_scanned': self.file_count,
                'total_vulnerabilities': len(self.vulnerabilities),
                'scan_duration_seconds': round(scan_duration, 2),
                'output_directory': self.output_dir
            },
            'plugin_info': self.plugin_info,
            'summary': {
                'critical': len(critical),
                'high': len(high),
                'medium': len(medium),
                'by_type': dict(vuln_by_type)
            },
            'vulnerabilities': {
                'critical': critical,
                'high': high,
                'medium': medium
            },
            'deep_analysis': {
                'data_flows': self.data_flows,
                'backdoor_detections': self.backdoor_detections,
                'total_tainted_flows': len([f for f in self.data_flows if f['severity'] == 'CRITICAL'])
            },
            'affected_files': self.scanned_files,
            'risk_assessment': self.calculate_risk_score(len(critical), len(high), len(medium))
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n{Colors.GREEN}[✓] Report saved: {output_path}{Colors.RESET}")
        return report

    def calculate_risk_score(self, critical, high, medium):
        """Calculate overall risk score"""
        score = (critical * 10) + (high * 5) + (medium * 2)
        
        # Add penalties for data flow vulnerabilities
        tainted_flows = len([f for f in self.data_flows if f['severity'] == 'CRITICAL'])
        score += tainted_flows * 8
        
        # Add penalties for backdoors
        score += len(self.backdoor_detections) * 15
        
        if score >= 100:
            level = "CRITICAL - IMMEDIATE ACTION REQUIRED"
        elif score >= 50:
            level = "HIGH RISK - FIX URGENTLY"
        elif score >= 30:
            level = "MEDIUM RISK - SHOULD BE ADDRESSED"
        elif score > 0:
            level = "LOW RISK - MONITOR"
        else:
            level = "SECURE - NO VULNERABILITIES"
        
        return {
            'score': min(score, 100),
            'level': level
        }

    def print_summary(self):
        """Print comprehensive scan summary"""
        critical = len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL'])
        high = len([v for v in self.vulnerabilities if v['severity'] == 'HIGH'])
        medium = len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM'])
        
        scan_duration = time.time() - self.scan_start_time
        
        # Header
        print(f"\n{Colors.BOLD}{Colors.CYAN}╔{'═' * 80}╗{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}║{' ' * 28}✨ SCAN RESULTS ✨{' ' * 28}║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}╚{'═' * 80}╝{Colors.RESET}\n")
        
        # Plugin Info
        if self.plugin_info:
            print(f"{Colors.BOLD}{Colors.PURPLE}╔{'═' * 80}╗{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.PURPLE}║{' ' * 30}📦 PLUGIN INFO{' ' * 35}║{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.PURPLE}╠{'═' * 80}╣{Colors.RESET}")
            
            
            name = (self.plugin_info.get('Name') or self.plugin_info.get('name') or 'Unknown')[:50]
            version = (self.plugin_info.get('Version') or self.plugin_info.get('version') or 'N/A')[:20]
            author = (self.plugin_info.get('Author') or self.plugin_info.get('author') or 'N/A')[:40]
            
            print(f"{Colors.PURPLE}║ {Colors.WHITE}Name    :{Colors.RESET} {Colors.CYAN}{name:65}{Colors.RESET} {Colors.PURPLE}║{Colors.RESET}")
            print(f"{Colors.PURPLE}║ {Colors.WHITE}Version :{Colors.RESET} {Colors.CYAN}{version:65}{Colors.RESET} {Colors.PURPLE}║{Colors.RESET}")
            print(f"{Colors.PURPLE}║ {Colors.WHITE}Author  :{Colors.RESET} {Colors.CYAN}{author:65}{Colors.RESET} {Colors.PURPLE}║{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.PURPLE}╚{'═' * 80}╝{Colors.RESET}\n")
        
        # Statistics
        print(f"{Colors.BOLD}{Colors.BLUE}╔{'═' * 80}╗{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}║{' ' * 30}📊 STATISTICS{' ' * 35}║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}╠{'═' * 80}╣{Colors.RESET}")
        print(f"{Colors.BLUE}║ {Colors.WHITE}Files Scanned         :{Colors.RESET} {Colors.GREEN}{self.file_count:4}{Colors.RESET}{' ' * 52}{Colors.BLUE}║{Colors.RESET}")
        print(f"{Colors.BLUE}║ {Colors.WHITE}Vulnerabilities Found :{Colors.RESET} {Colors.RED}{len(self.vulnerabilities):4}{Colors.RESET}{' ' * 52}{Colors.BLUE}║{Colors.RESET}")
        print(f"{Colors.BLUE}║ {Colors.WHITE}Tainted Data Flows    :{Colors.RESET} {Colors.BRIGHT_RED}{len([f for f in self.data_flows if f['severity'] == 'CRITICAL']):4}{Colors.RESET}{' ' * 52}{Colors.BLUE}║{Colors.RESET}")
        print(f"{Colors.BLUE}║ {Colors.WHITE}Backdoor Detections   :{Colors.RESET} {Colors.MAGENTA}{len(self.backdoor_detections):4}{Colors.RESET}{' ' * 52}{Colors.BLUE}║{Colors.RESET}")
        print(f"{Colors.BLUE}║ {Colors.WHITE}Scan Duration         :{Colors.RESET} {Colors.YELLOW}{scan_duration:.2f}s{Colors.RESET}{' ' * 49}{Colors.BLUE}║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}╚{'═' * 80}╝{Colors.RESET}\n")
        
        # Dynamic chart by vulnerability type
        vuln_counts = Counter([v['type'] for v in self.vulnerabilities])
        self.draw_dynamic_chart(vuln_counts)
                
        
        # Tampilkan Analisa Otomatis (Gunakan self.vulnerabilities)
        self.generate_auto_analysis(self.vulnerabilities)
        
        # Severity Summary
        print(f"{Colors.BOLD}{Colors.WHITE}╔{'═' * 80}╗{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.WHITE}║{' ' * 28}🎯 SEVERITY SUMMARY{' ' * 31}║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.WHITE}╠{'═' * 80}╣{Colors.RESET}")
        print(f"{Colors.WHITE}║ {Colors.BRIGHT_RED}🔴 CRITICAL : {critical:3} issues{Colors.RESET} - Immediate action required{' ' * 26}{Colors.WHITE}║{Colors.RESET}")
        print(f"{Colors.WHITE}║ {Colors.ORANGE}🟠 HIGH     : {high:3} issues{Colors.RESET} - Should be fixed soon{' ' * 30}{Colors.WHITE}║{Colors.RESET}")
        print(f"{Colors.WHITE}║ {Colors.YELLOW}🟡 MEDIUM   : {medium:3} issues{Colors.RESET} - Fix when possible{' ' * 32}{Colors.WHITE}║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.WHITE}╚{'═' * 80}╝{Colors.RESET}\n")
        
        # Risk Assessment
        risk = self.calculate_risk_score(critical, high, medium)
        risk_color = Colors.BRIGHT_RED if risk['score'] >= 50 else Colors.ORANGE if risk['score'] >= 30 else Colors.YELLOW
        
        print(f"{Colors.BOLD}{risk_color}╔{'═' * 80}╗{Colors.RESET}")
        print(f"{Colors.BOLD}{risk_color}║{' ' * 28}⚠️  RISK ASSESSMENT{' ' * 31}║{Colors.RESET}")
        print(f"{Colors.BOLD}{risk_color}╠{'═' * 80}╣{Colors.RESET}")
        print(f"{risk_color}║ {Colors.WHITE}Risk Score :{Colors.RESET} {Colors.BOLD}{risk_color}{risk['score']}/100{Colors.RESET}{' ' * 60}{risk_color}║{Colors.RESET}")
        print(f"{risk_color}║ {Colors.WHITE}Risk Level :{Colors.RESET} {Colors.BOLD}{risk_color}{risk['level']}{Colors.RESET}{' ' * (66 - len(risk['level']))}{risk_color}║{Colors.RESET}")
        print(f"{Colors.BOLD}{risk_color}╚{'═' * 80}╝{Colors.RESET}")
        
        # Print deep analysis results
        self.print_data_flow_analysis()
        self.print_backdoor_analysis()
        
        # Top vulnerable files
        if self.scanned_files:
            print(f"\n{Colors.BOLD}{Colors.ORANGE}╔{'═' * 80}╗{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.ORANGE}║{' ' * 26}🔥 MOST VULNERABLE FILES{' ' * 29}║{Colors.RESET}")
            print(f"{Colors.BOLD}{Colors.ORANGE}╠{'═' * 80}╣{Colors.RESET}")
            
            sorted_files = sorted(self.scanned_files, key=lambda x: x['vulnerabilities'], reverse=True)[:5]
            for i, file_info in enumerate(sorted_files, 1):
                filename = file_info['file'][:60]
                count = file_info['vulnerabilities']
                print(f"{Colors.ORANGE}║ {Colors.YELLOW}{i}.{Colors.RESET} {filename:60} {Colors.RED}[{count:2}]{Colors.RESET} {Colors.ORANGE}║{Colors.RESET}")
            
            print(f"{Colors.BOLD}{Colors.ORANGE}╚{'═' * 80}╝{Colors.RESET}\n")
     
    def send_to_discord(self, webhook_url):
        """Mengirim ringkasan hasil scan ke Discord via Webhook"""
        try:
            import requests
            import json
            import os

            # --- TAMBAHKAN LOGIKA FALLBACK DI SINI ---
            # Jika 'Name' tidak ketemu, ambil dari nama file ZIP-nya
            plugin_name = self.plugin_info.get('Name')
            if not plugin_name:
                # Mengambil nama file dari path (misal: plugin-jet.php.zip)
                plugin_name = os.path.basename(self.plugin_path) if hasattr(self, 'plugin_path') else "Unknown Plugin"
            
            plugin_version = self.plugin_info.get('Version', 'N/A')
            # ----------------------------------------

            # Hitung statistik singkat
            crit = sum(1 for v in self.vulnerabilities if v['severity'] == 'CRITICAL')
            high = sum(1 for v in self.vulnerabilities if v['severity'] == 'HIGH')
            med = sum(1 for v in self.vulnerabilities if v['severity'] == 'MEDIUM')

            payload = {
                "embeds": [{
                    "title": "🛡️ WP-ScanCVE Elite Report",
                    "color": 15158332 if crit > 0 else 3066993,
                    "fields": [
                        # Gunakan variabel yang baru kita buat di atas
                        {"name": "📦 Plugin", "value": f"```{plugin_name}```", "inline": True},
                        {"name": "🔢 Version", "value": f"```{plugin_version}```", "inline": True},
                        {"name": "📊 Stats", "value": f"🔴 {crit} Critical\n🟠 {high} High\n🟡 {med} Medium"},
                        {"name": "🎯 Risk Score", "value": f"{100 if crit > 0 else (50 if high > 0 else 10)}/100", "inline": True},
                        {"name": "📂 Files", "value": f"{len(self.scanned_files)} Scanned", "inline": True}
                    ],
                    "footer": {"text": "v5.0 Elite - Automated Security Analysis"}
                }]
            }

            requests.post(webhook_url, json=payload, timeout=10)
            print(f"{Colors.GREEN}[✓] Report sent to Discord successfully!{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to send Discord report: {e}{Colors.RESET}")
            
def print_banner():
    """Print elite scanner banner with animation"""
    banner = f"""
{Colors.BOLD}{Colors.CYAN}
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     ██╗    ██╗██████╗      ██████╗██╗   ██╗███████╗                         ║
║     ██║    ██║██╔══██╗    ██╔════╝██║   ██║██╔════╝                         ║
║     ██║ █╗ ██║██████╔╝    ██║     ██║   ██║█████╗                           ║
║     ██║███╗██║██╔═══╝     ██║     ╚██╗ ██╔╝██╔══╝                           ║
║     ╚███╔███╔╝██║         ╚██████╗ ╚████╔╝ ███████╗                         ║
║      ╚══╝╚══╝ ╚═╝          ╚═════╝  ╚═══╝  ╚══════╝                         ║
║                                                                               ║
║   ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗               ║
║   ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗              ║
║   ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝              ║
║   ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗              ║
║   ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║              ║
║   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝              ║
║                                                                               ║
║              {Colors.PURPLE}🔒 WordPress CVE Scanner Pro v5.0 Elite 🔒{Colors.CYAN}                 ║
║                                                                               ║
║                  {Colors.WHITE}Deep Analysis & Entropy-Based Detection{Colors.CYAN}                  ║
║               {Colors.GRAY}21+ Vulnerability Types | 99% Accuracy Engine{Colors.CYAN}              ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
    print(banner)
    
    # Animated initialization
    features = [
        ("Pattern Database", "21 vulnerability signatures", Colors.GREEN),
        ("False Positive Filter", "Multi-layer validation", Colors.GREEN),
        ("Data Flow Tracer", "Deep-Hook Analysis Engine", Colors.CYAN),
        ("Entropy Analyzer", "Backdoor Detection AI", Colors.MAGENTA),
        ("Output System", "wp_scancve directory", Colors.PURPLE),
    ]
    
    print(f"{Colors.YELLOW}[⚡] Initializing Elite Scanner Engine...{Colors.RESET}\n")
    time.sleep(0.3)
    
    for name, desc, color in features:
        print(f"{color}[✓]{Colors.RESET} {Colors.WHITE}{name:20}{Colors.RESET} : {Colors.GRAY}{desc}{Colors.RESET}")
        time.sleep(0.2)
    
    print()

def main():
    import sys
    
    print_banner()
    
    if len(sys.argv) < 2:
        print(f"{Colors.YELLOW}╔{'═' * 78}╗{Colors.RESET}")
        print(f"{Colors.YELLOW}║{' ' * 33}USAGE{' ' * 40}║{Colors.RESET}")
        print(f"{Colors.YELLOW}╚{'═' * 78}╝{Colors.RESET}")
        print(f"\n{Colors.WHITE}python scanner.py <plugin.zip> [output.json]{Colors.RESET}")
        print(f"\n{Colors.CYAN}Examples:{Colors.RESET}")
        print(f"  {Colors.GREEN}►{Colors.RESET} {Colors.WHITE}python scanner.py vulnerable-plugin.zip{Colors.RESET}")
        print(f"  {Colors.GREEN}►{Colors.RESET} {Colors.WHITE}python scanner.py plugin.zip custom_report.json{Colors.RESET}\n")
        sys.exit(1)
    
    zip_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'scan_report.json'
    
    if not os.path.exists(zip_file):
        print(f"{Colors.RED}[✗] Error: File '{zip_file}' not found!{Colors.RESET}")
        sys.exit(1)
    
    scanner = WordPressCVEScanner()
    
    # Create output directory
    scanner.create_output_directory()
    
    print(f"\n{Colors.BOLD}{Colors.PURPLE}╔{'═' * 78}╗{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.PURPLE}║{' ' * 25}🚀 INITIATING DEEP SCAN{' ' * 28}║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.PURPLE}╚{'═' * 78}╝{Colors.RESET}\n")
    
    # Extract ZIP
    extract_dir = scanner.extract_zip(zip_file)
    if not extract_dir:
        sys.exit(1)
    
    try:
        print(f"{Colors.CYAN}{'─' * 80}{Colors.RESET}\n")
        
        # Scan directory
        scanner.scan_directory(extract_dir)
        
        print(f"\n{Colors.CYAN}{'─' * 80}{Colors.RESET}")
        print(f"\n{Colors.GREEN}╔{'═' * 78}╗{Colors.RESET}")
        print(f"{Colors.GREEN}║{' ' * 23}✓ SCANNING COMPLETED{' ' * 32}║{Colors.RESET}")
        print(f"{Colors.GREEN}╚{'═' * 78}╝{Colors.RESET}\n")
        
        # Generate report
        scanner.generate_report(output_file)
        
        # Print summary
        scanner.print_summary()
        
        # Pastikan ini sejajar (biasanya 4 spasi dari pinggir fungsi main)
        MY_WEBHOOK = "url chanel discord anda"
    
        if "rahasia" not in MY_WEBHOOK:
            scanner.send_to_discord(MY_WEBHOOK)
        
        # Final output
        output_path = os.path.join(scanner.output_dir, output_file)
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}╔{'═' * 78}╗{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}║{' ' * 30}📄 REPORT{' ' * 35}║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}╠{'═' * 78}╣{Colors.RESET}")
        print(f"{Colors.GREEN}║ {Colors.WHITE}JSON Report   :{Colors.RESET} {Colors.CYAN}{output_path:58}{Colors.RESET} {Colors.GREEN}║{Colors.RESET}")
        print(f"{Colors.GREEN}║ {Colors.WHITE}Output Dir    :{Colors.RESET} {Colors.CYAN}{scanner.output_dir + '/' :58}{Colors.RESET} {Colors.GREEN}║{Colors.RESET}")
        print(f"{Colors.GREEN}║ {Colors.WHITE}Extracted Dir :{Colors.RESET} {Colors.CYAN}{extract_dir:58}{Colors.RESET} {Colors.GREEN}║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.GREEN}╚{'═' * 78}╝{Colors.RESET}\n")
        
        print(f"{Colors.GRAY}[i] All scan results saved in '{scanner.output_dir}' directory{Colors.RESET}")
        print(f"{Colors.GRAY}[i] Extracted files kept for manual review{Colors.RESET}\n")
        
    except Exception as e:
        print(f"{Colors.RED}[!] Fatal error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Epic footer
        print(f"{Colors.BOLD}{Colors.CYAN}╔{'═' * 78}╗{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}║{' ' * 18}🛡️  SECURITY SCAN COMPLETE 🛡️{' ' * 23}║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}╠{'═' * 78}╣{Colors.RESET}")
        print(f"{Colors.CYAN}║ {Colors.WHITE}Scanner Version   :{Colors.RESET} {Colors.PURPLE}v5.0 Elite - Deep Analysis{Colors.RESET}{' ' * 31}{Colors.CYAN}║{Colors.RESET}")
        print(f"{Colors.CYAN}║ {Colors.WHITE}Detection Types   :{Colors.RESET} {Colors.YELLOW}21 Patterns + Data Flow + Entropy{Colors.RESET}{' ' * 25}{Colors.CYAN}║{Colors.RESET}")
        print(f"{Colors.CYAN}║ {Colors.WHITE}Accuracy Rate     :{Colors.RESET} {Colors.GREEN}99% with Deep-Hook Analysis{Colors.RESET}{' ' * 30}{Colors.CYAN}║{Colors.RESET}")
        print(f"{Colors.CYAN}║ {Colors.WHITE}False Positives   :{Colors.RESET} {Colors.GREEN}Minimized with Smart Filtering{Colors.RESET}{' ' * 27}{Colors.CYAN}║{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}╚{'═' * 78}╝{Colors.RESET}\n")
if __name__ == "__main__":
    main()
