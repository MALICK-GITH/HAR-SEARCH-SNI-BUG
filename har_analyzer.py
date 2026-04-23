#!/usr/bin/env python3
"""
HAR Advanced Analyzer - Security, Performance, and Pattern Detection
=====================================================================

Advanced analysis module for HAR files including:
- Security analysis (headers, cookies, vulnerabilities)
- Performance analysis (bottlenecks, slow requests)
- Pattern detection (suspicious activity, data leaks)
- Comparison and diff capabilities

Author: SOLITAIRE HACK
Version: 2.0.0
License: MIT
"""

import logging
import os
import ipaddress
import re
import requests
from urllib.parse import urlparse, parse_qs, quote_plus
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from collections import defaultdict, Counter


logger = logging.getLogger(__name__)


def get_default_inmux_timeout(default: int = 45) -> int:
    """Read the INMUX timeout from the environment."""
    raw_value = os.getenv('INMUX_REQUEST_TIMEOUT')
    if raw_value is None:
        return default

    try:
        return max(int(raw_value), 5)
    except ValueError:
        logger.warning("Invalid INMUX_REQUEST_TIMEOUT=%r. Falling back to %s seconds.", raw_value, default)
        return default


@dataclass
class SecurityIssue:
    """Represents a security issue found in HAR file."""
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    category: str
    title: str
    description: str
    entry_index: int = -1
    evidence: str = ""
    recommendation: str = ""


@dataclass
class PerformanceIssue:
    """Represents a performance issue found in HAR file."""
    severity: str
    category: str
    title: str
    description: str
    entry_index: int = -1
    value: float = 0.0
    threshold: float = 0.0
    recommendation: str = ""


@dataclass
class PatternMatch:
    """Represents a pattern match found in HAR file."""
    pattern_type: str
    description: str
    entry_index: int = -1
    matched_text: str = ""
    context: str = ""


@dataclass
class DomainInfo:
    """Represents information about a domain in HAR file."""
    domain: str
    request_count: int = 0
    total_size: int = 0
    avg_response_time: float = 0.0
    status_codes: Dict[str, int] = field(default_factory=dict)
    content_types: Dict[str, int] = field(default_factory=dict)
    is_https: bool = True
    first_seen: int = -1
    last_seen: int = -1


@dataclass
class JSVulnerability:
    """Represents a JavaScript vulnerability found in code."""
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    category: str
    title: str
    description: str
    line_number: int = -1
    code_snippet: str = ""
    recommendation: str = ""
    cwe_id: str = ""


@dataclass
class NetworkIssue:
    """Represents a network security issue found in HAR file."""
    severity: str  # 'critical', 'high', 'medium', 'low', 'info'
    category: str
    title: str
    description: str
    domain: str = ""
    entry_index: int = -1
    evidence: str = ""
    score: int = 0
    confidence: str = "low"
    indicators: List[str] = field(default_factory=list)
    recommendation: str = ""
    alert_recipient: str = ""  # Email or contact to alert


@dataclass
class PortInfo:
    """Represents information about a port used in network connections."""
    port: int
    protocol: str = ""
    domain: str = ""
    connection_count: int = 0
    is_standard: bool = True
    is_suspicious: bool = False
    security_risk: str = ""  # 'critical', 'high', 'medium', 'low', 'info'


@dataclass
class UserAgentInfo:
    """Represents information about a User Agent."""
    user_agent: str
    connection_count: int = 0
    is_bot: bool = False
    is_suspicious: bool = False
    browser: str = ""
    os: str = ""
    security_risk: str = ""


class HARAdvancedAnalyzer:
    """
    Advanced analyzer for HAR files with security, performance, and pattern detection.
    """

    # Security headers that should be present
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'Prevents MITM attacks',
        'X-Frame-Options': 'Prevents clickjacking',
        'X-Content-Type-Options': 'Prevents MIME sniffing',
        'Content-Security-Policy': 'Prevents XSS attacks',
        'X-XSS-Protection': 'XSS protection',
        'Referrer-Policy': 'Controls referrer information',
        'Permissions-Policy': 'Controls browser features'
    }

    # Suspicious patterns to detect - OWASP Top 10 focused
    SUSPICIOUS_PATTERNS = {
        # Broken Access Control & Authentication
        'api_key': r'(api[_-]?key|apikey|api[_-]?secret)[\s=:]+[\'"]?([a-zA-Z0-9_\-]{16,})[\'"]?',
        'token': r'(token|auth[_-]?token|access[_-]?token|jwt|bearer)[\s=:]+[\'"]?([a-zA-Z0-9_\-\.]{20,})[\'"]?',
        'password': r'(password|passwd|pwd|pass)[\s=:]+[\'"]?([^\'"\s]{6,})[\'"]?',
        'secret': r'(secret|private[_-]?key|client[_-]?secret|api[_-]?secret)[\s=:]+[\'"]?([a-zA-Z0-9_\-]{16,})[\'"]?',
        'session_id': r'(session[_-]?id|sessid|phpsessid|jsessionid)[\s=:]+[\'"]?([a-zA-Z0-9]{20,})[\'"]?',
        'auth_bypass': r'(admin|root|test|demo)[\s=:]+[\'"]?(admin|root|password|123456)[\'"]?',
        
        # Cryptographic Failures - PII Data
        'credit_card': r'\b(?:\d[ -]*?){13,16}\b',
        'ssn': r'\b\d{3}[-.]?\d{2}[-.]?\d{4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone_number': r'\b\+?[\d\s\-\(\)]{10,20}\b',
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'passport': r'[A-Z]{2}\d{6,9}',
        'bank_account': r'\b\d{8,17}\b',
        
        # Injection
        'sql_injection': r'UNION\s+SELECT|DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|OR\s+\d+\s*=\s*\d+|AND\s+\d+\s*=\s*\d+|\'\s+OR\s+|\'\s+AND\s+|;\s*DROP|;\s*DELETE|;\s*EXEC',
        'xss_attempt': r'<script[^>]*>.*?</script>|javascript:|on\w+\s*=|eval\s*\(|document\.cookie|document\.location|window\.location',
        'path_traversal': r'\.\./|\.\.\\|%2e%2e|%252e%252e|etc/passwd|etc/shadow|windows/system32',
        'command_injection': r'[;|&`$()]|\|\||&&|\$\(|\${|`[^`]*`',
        'ldap_injection': r'\*\)\(|\)\(|\)\)\(|\)\)\)\(',
        'xpath_injection': r'\'\]\s+or\s+|\'\]\s+and\s+',
        
        # Security Misconfiguration
        'debug_info': r'(debug|trace|stack[_-]?trace|error[_-]?report|phpinfo)[\s=:]+true',
        'default_creds': r'(admin|root|administrator|test)[\s=:]+(admin|password|123456|root)',
        'config_file': r'\.(config|ini|cfg|env|xml|json|yml|yaml)[\s=:]',
        
        # Data Exposure
        'jwt_token': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        'bearer_token': r'Bearer\s+[a-zA-Z0-9_\-\.]{20,}',
        'basic_auth': r'Basic\s+[a-zA-Z0-9+/=]{20,}',
        
        # Broken Access Control
        'id_or': r'id\s*=\s*\d+\s+or|\?id=\d+\s+or',
        'admin_panel': r'/admin|/administrator|/wp-admin|/dashboard|/console',
        'hidden_endpoint': r'/\.git|/\.env|/config|/backup|/old|/test|/debug',
        
        # Server-Side Request Forgery
        'ssrf_attempt': r'(url|dest|target|feed|proxy)[\s=:]+(http|https)://(127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0)',
        
        # XML External Entity
        'xxe_attempt': r'<!DOCTYPE|SYSTEM\s+[\'"]|ENTITY\s+[\'"]',
        
        # Insecure Deserialization
        'serialization': r'(rO0|H4sI|ACE|serialized|object|pickle|marshal)',
        
        # Security Headers Issues
        'missing_csp': r'(script|style|img)\s+src\s*=',
        'mixed_content': r'http://.*\.js|http://.*\.css',
        
        # Sensitive Information
        'api_endpoint': r'/api/|/v1/|/v2/|/rest/',
        'database_connection': r'(mysql|postgres|mongodb|redis|sqlserver)://',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'private_key': r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY',
        'ssh_key': r'ssh-rsa\s+[A-Za-z0-9+/=]+'
    }

    # Performance thresholds (in milliseconds)
    PERFORMANCE_THRESHOLDS = {
        'slow_request': 1000,
        'very_slow_request': 3000,
        'large_response': 1024 * 1024,  # 1MB
        'very_large_response': 5 * 1024 * 1024,  # 5MB
        'slow_dns': 200,
        'slow_connect': 200,
        'slow_ssl': 300,
        'slow_ttfb': 500,
        'slow_download': 1000
    }

    # Known vulnerable software versions (simplified database)
    VULNERABLE_VERSIONS = {
        'apache': {
            '2.4.49': 'CVE-2021-41773 (Path Traversal)',
            '2.4.50': 'CVE-2021-42013 (Path Traversal)',
            '2.4.48': 'CVE-2021-34798 (Request Smuggling)'
        },
        'nginx': {
            '0.7.64': 'Multiple CVEs',
            '0.8.41': 'Multiple CVEs',
            '1.18.0': 'CVE-2021-23017'
        },
        'php': {
            '7.3.0': 'Multiple CVEs',
            '7.4.0': 'Multiple CVEs',
            '8.0.0': 'Multiple CVEs',
            '8.1.0': 'Multiple CVEs'
        },
        'wordpress': {
            '5.0.0': 'CVE-2019-9978',
            '5.2.3': 'CVE-2020-14032',
            '5.4.0': 'CVE-2021-24862'
        },
        'jquery': {
            '1.6.0': 'CVE-2011-4969',
            '1.7.0': 'CVE-2012-6708',
            '3.0.0': 'CVE-2019-11358'
        },
        'react': {
            '0.14.0': 'CVE-2016-1000114',
            '15.0.0': 'CVE-2018-6341',
            '16.0.0': 'CVE-2019-16771'
        },
        'vue': {
            '2.0.0': 'CVE-2018-16388',
            '2.5.0': 'CVE-2019-11476'
        },
        'spring': {
            '4.3.0': 'CVE-2016-4977',
            '5.0.0': 'CVE-2018-1270',
            '5.1.0': 'CVE-2018-1271'
        },
        'node': {
            '8.0.0': 'Multiple CVEs',
            '10.0.0': 'Multiple CVEs',
            '12.0.0': 'Multiple CVEs',
            '14.0.0': 'Multiple CVEs'
        },
        'python': {
            '2.7.0': 'EOL - Multiple CVEs',
            '3.5.0': 'EOL - Multiple CVEs',
            '3.6.0': 'EOL - Multiple CVEs',
            '3.7.0': 'EOL - Multiple CVEs'
        }
    }

    # OWASP Top 10 2021 Categories
    OWASP_CATEGORIES = {
        'A01:2021-Broken Access Control': 'critical',
        'A02:2021-Cryptographic Failures': 'critical',
        'A03:2021-Injection': 'critical',
        'A04:2021-Insecure Design': 'high',
        'A05:2021-Security Misconfiguration': 'high',
        'A06:2021-Vulnerable and Outdated Components': 'high',
        'A07:2021-Identification and Authentication Failures': 'critical',
        'A08:2021-Software and Data Integrity Failures': 'medium',
        'A09:2021-Security Logging and Monitoring Failures': 'medium',
        'A10:2021-Server-Side Request Forgery': 'critical'
    }

    # JavaScript vulnerability patterns
    JS_VULNERABILITY_PATTERNS = {
        # XSS vulnerabilities
        'innerHTML': {
            'pattern': r'\.innerHTML\s*=',
            'severity': 'high',
            'category': 'xss',
            'title': 'Unsafe innerHTML Usage',
            'description': 'Using innerHTML can lead to XSS attacks if the content is user-controlled.',
            'recommendation': 'Use textContent or sanitize the input before using innerHTML.',
            'cwe': 'CWE-79'
        },
        'document.write': {
            'pattern': r'document\.write\s*\(',
            'severity': 'high',
            'category': 'xss',
            'title': 'Unsafe document.write Usage',
            'description': 'document.write can lead to XSS attacks.',
            'recommendation': 'Avoid document.write, use DOM manipulation methods instead.',
            'cwe': 'CWE-79'
        },
        'eval': {
            'pattern': r'\beval\s*\(',
            'severity': 'critical',
            'category': 'code_injection',
            'title': 'Unsafe eval() Usage',
            'description': 'eval() can execute arbitrary code, leading to code injection attacks.',
            'recommendation': 'Avoid eval(). Use JSON.parse() for JSON or other safe alternatives.',
            'cwe': 'CWE-95'
        },
        'Function': {
            'pattern': r'new\s+Function\s*\(',
            'severity': 'critical',
            'category': 'code_injection',
            'title': 'Unsafe Function Constructor',
            'description': 'Function constructor can execute arbitrary code.',
            'recommendation': 'Avoid Function constructor. Use arrow functions or regular functions.',
            'cwe': 'CWE-95'
        },
        'setTimeout_string': {
            'pattern': r'setTimeout\s*\(\s*[\'"]',
            'severity': 'medium',
            'category': 'code_injection',
            'title': 'setTimeout with String Argument',
            'description': 'setTimeout with string argument is similar to eval().',
            'recommendation': 'Pass a function instead of a string to setTimeout.',
            'cwe': 'CWE-95'
        },
        'setInterval_string': {
            'pattern': r'setInterval\s*\(\s*[\'"]',
            'severity': 'medium',
            'category': 'code_injection',
            'title': 'setInterval with String Argument',
            'description': 'setInterval with string argument is similar to eval().',
            'recommendation': 'Pass a function instead of a string to setInterval.',
            'cwe': 'CWE-95'
        },
        # Cryptographic issues
        'md5': {
            'pattern': r'\bmd5\s*\(',
            'severity': 'high',
            'category': 'weak_crypto',
            'title': 'Weak MD5 Hash',
            'description': 'MD5 is a weak hash algorithm vulnerable to collision attacks.',
            'recommendation': 'Use SHA-256 or stronger hash algorithms.',
            'cwe': 'CWE-327'
        },
        'sha1': {
            'pattern': r'\bsha1\s*\(',
            'severity': 'high',
            'category': 'weak_crypto',
            'title': 'Weak SHA-1 Hash',
            'description': 'SHA-1 is deprecated and vulnerable to collision attacks.',
            'recommendation': 'Use SHA-256 or stronger hash algorithms.',
            'cwe': 'CWE-327'
        },
        # Hardcoded secrets
        'api_key': {
            'pattern': r'(api[_-]?key|apikey)[\s=:]+[\'"]([a-zA-Z0-9_\-]{16,})[\'"]',
            'severity': 'critical',
            'category': 'hardcoded_secret',
            'title': 'Hardcoded API Key',
            'description': 'API key hardcoded in JavaScript source code.',
            'recommendation': 'Move API keys to environment variables or secure backend.',
            'cwe': 'CWE-798'
        },
        'secret': {
            'pattern': r'(secret|private[_-]?key|client[_-]?secret)[\s=:]+[\'"]([a-zA-Z0-9_\-]{16,})[\'"]',
            'severity': 'critical',
            'category': 'hardcoded_secret',
            'title': 'Hardcoded Secret',
            'description': 'Secret hardcoded in JavaScript source code.',
            'recommendation': 'Move secrets to environment variables or secure backend.',
            'cwe': 'CWE-798'
        },
        'password': {
            'pattern': r'(password|passwd|pwd)[\s=:]+[\'"]([^\'"\s]{6,})[\'"]',
            'severity': 'critical',
            'category': 'hardcoded_secret',
            'title': 'Hardcoded Password',
            'description': 'Password hardcoded in JavaScript source code.',
            'recommendation': 'Never hardcode passwords. Use authentication tokens.',
            'cwe': 'CWE-798'
        },
        # Debug/Development code
        'console_log': {
            'pattern': r'console\.log\s*\(',
            'severity': 'low',
            'category': 'debug_code',
            'title': 'console.log in Production',
            'description': 'console.log statements should be removed in production.',
            'recommendation': 'Remove or disable console.log statements in production builds.',
            'cwe': 'CWE-489'
        },
        'debugger': {
            'pattern': r'\bdebugger\b',
            'severity': 'medium',
            'category': 'debug_code',
            'title': 'debugger Statement',
            'description': 'debugger statement can halt execution in development mode.',
            'recommendation': 'Remove debugger statements before deployment.',
            'cwe': 'CWE-489'
        },
        # Insecure dependencies
        'jquery_old': {
            'pattern': r'jquery.*[1-2]\.[0-7]\.',
            'severity': 'high',
            'category': 'outdated_dependency',
            'title': 'Outdated jQuery Version',
            'description': 'jQuery version 1.x or 2.x may have known vulnerabilities.',
            'recommendation': 'Update to jQuery 3.x or newer.',
            'cwe': 'CWE-937'
        },
        # Sensitive data exposure
        'localstorage_sensitive': {
            'pattern': r'localStorage\.(setItem|getItem)\s*\(\s*[\'"]?(password|token|secret|api[_-]?key)',
            'severity': 'high',
            'category': 'sensitive_data',
            'title': 'Sensitive Data in localStorage',
            'description': 'Storing sensitive data in localStorage is insecure.',
            'recommendation': 'Use httpOnly cookies or secure session storage.',
            'cwe': 'CWE-922'
        },
        'sessionstorage_sensitive': {
            'pattern': r'sessionStorage\.(setItem|getItem)\s*\(\s*[\'"]?(password|token|secret|api[_-]?key)',
            'severity': 'high',
            'category': 'sensitive_data',
            'title': 'Sensitive Data in sessionStorage',
            'description': 'Storing sensitive data in sessionStorage is insecure.',
            'recommendation': 'Use httpOnly cookies or secure session storage.',
            'cwe': 'CWE-922'
        },
        # DOM-based vulnerabilities
        'location_hash': {
            'pattern': r'location\.hash',
            'severity': 'medium',
            'category': 'dom_xss',
            'title': 'Potential DOM XSS via location.hash',
            'description': 'Using location.hash without validation can lead to DOM XSS.',
            'recommendation': 'Validate and sanitize data from location.hash.',
            'cwe': 'CWE-79'
        },
        'document_url': {
            'pattern': r'document\.URL|document\.url',
            'severity': 'medium',
            'category': 'dom_xss',
            'title': 'Potential DOM XSS via document.URL',
            'description': 'Using document.URL without validation can lead to DOM XSS.',
            'recommendation': 'Validate and sanitize data from document.URL.',
            'cwe': 'CWE-79'
        }
    }

    # Network security patterns for SSL/TLS and certificate issues
    NETWORK_SECURITY_PATTERNS = {
        'http_only': {
            'check': lambda entry: not entry.is_https,
            'severity': 'high',
            'category': 'ssl_tls',
            'title': 'HTTP Only Connection',
            'description': 'Connection uses HTTP instead of HTTPS, exposing data to interception.',
            'recommendation': 'Use HTTPS for all connections.',
            'cwe': 'CWE-319'
        },
        'mixed_content': {
            'check': lambda entry: entry.is_https and 'http:' in entry.request.url,
            'severity': 'medium',
            'category': 'ssl_tls',
            'title': 'Mixed Content',
            'description': 'HTTPS page loading HTTP resources, breaking security.',
            'recommendation': 'Load all resources over HTTPS.',
            'cwe': 'CWE-319'
        },
        'self_signed_cert': {
            'pattern': r'self[-_]?signed|self[-_]?signed[-_]?certificate',
            'severity': 'critical',
            'category': 'ssl_tls',
            'title': 'Self-Signed Certificate',
            'description': 'Self-signed certificate detected, not trusted by browsers.',
            'recommendation': 'Use a certificate from a trusted CA.',
            'cwe': 'CWE-295'
        },
        'expired_cert': {
            'pattern': r'certificate[-_]?expired|cert[-_]?expired|expired[-_]?cert',
            'severity': 'critical',
            'category': 'ssl_tls',
            'title': 'Expired Certificate',
            'description': 'Certificate has expired, connection not secure.',
            'recommendation': 'Renew the certificate immediately.',
            'cwe': 'CWE-295'
        },
        'weak_cipher': {
            'pattern': r'(rc4|des|3des|md5|sha1|ssl[v2]?|tls1\.0|tls1\.1)',
            'severity': 'high',
            'category': 'ssl_tls',
            'title': 'Weak Cipher Suite',
            'description': 'Weak cipher suite detected, vulnerable to attacks.',
            'recommendation': 'Use strong cipher suites (AES-256, TLS 1.2+).',
            'cwe': 'CWE-327'
        },
        'free_ssl_provider': {
            'pattern': r'(letsencrypt|cloudflare[-_]?ssl|free[-_]?ssl|self[-_]?signed|self[-_]?signed[-_]?cert)',
            'severity': 'medium',
            'category': 'ssl_tls',
            'title': 'Free SSL Provider Detected',
            'description': 'Free SSL provider detected, may have limitations.',
            'recommendation': 'Consider using a paid SSL certificate for production.',
            'cwe': 'CWE-295'
        },
        'insecure_domain': {
            'pattern': r'\.onion|\.i2p|\.freedomain|\.freehost|\.tk|\.ml|\.ga|\.cf',
            'severity': 'high',
            'category': 'domain',
            'title': 'Insecure or Suspicious Domain',
            'description': 'Domain uses free hosting or anonymous network.',
            'recommendation': 'Use a legitimate domain and hosting provider.',
            'cwe': 'CWE-295'
        },
        # Free Surf and VPN services
        'free_surf_service': {
            'pattern': r'(free[-_]?surf|freesurf|free[-_]?vpn|freedns|dns[-_]?free|vpn[-_]?free|free[-_]?proxy|proxy[-_]?free)',
            'severity': 'high',
            'category': 'free_internet',
            'title': 'Free Surf/VPN Service Detected',
            'description': 'Free Surf or VPN service detected, may compromise privacy and security.',
            'recommendation': 'Use legitimate VPN services or direct internet connection.',
            'cwe': 'CWE-200'
        },
        'free_internet_provider': {
            'pattern': r'(free[-_]?internet|internet[-_]?gratis|gratis[-_]?internet|free[-_]?wifi|wifi[-_]?free|public[-_]?wifi|wifi[-_]?public)',
            'severity': 'medium',
            'category': 'free_internet',
            'title': 'Free Internet Provider Detected',
            'description': 'Free internet or public WiFi detected, may have security risks.',
            'recommendation': 'Use secure private connections or trusted ISPs.',
            'cwe': 'CWE-200'
        },
        'anonymizer_service': {
            'pattern': r'(anonymizer|anonymiseur|proxy[-_]?anonym|anonymous[-_]?proxy|tor[-_]?proxy|proxy[-_]?tor)',
            'severity': 'high',
            'category': 'free_internet',
            'title': 'Anonymizer Service Detected',
            'description': 'Anonymizer or anonymous proxy service detected, may intercept traffic.',
            'recommendation': 'Avoid anonymizer services, use direct secure connections.',
            'cwe': 'CWE-200'
        },
        'vpn_free_service': {
            'pattern': r'(vpn[-_]?gratis|gratis[-_]?vpn|free[-_]?tunnel|tunnel[-_]?free|free[-_]?access|access[-_]?free)',
            'severity': 'high',
            'category': 'free_internet',
            'title': 'Free VPN/Tunnel Service Detected',
            'description': 'Free VPN or tunnel service detected, may compromise security.',
            'recommendation': 'Use legitimate paid VPN services or direct connections.',
            'cwe': 'CWE-200'
        },
        'free_hosting': {
            'pattern': r'(free[-_]?hosting|hosting[-_]?free|free[-_]?web|web[-_]?free|free[-_]?site|site[-_]?free|000webhost|infinityfree|awardspace)',
            'severity': 'medium',
            'category': 'free_internet',
            'title': 'Free Hosting Service Detected',
            'description': 'Free hosting service detected, may have limitations and security risks.',
            'recommendation': 'Use paid hosting services for production applications.',
            'cwe': 'CWE-200'
        },
        'public_dns': {
            'pattern': r'(8\.8\.8\.8|1\.1\.1\.1|google[-_]?dns|cloudflare[-_]?dns|opendns|quad9|public[-_]?dns)',
            'severity': 'low',
            'category': 'free_internet',
            'title': 'Public DNS Service Detected',
            'description': 'Public DNS service detected, may be used for surveillance.',
            'recommendation': 'Use ISP DNS or private DNS servers for better privacy.',
            'cwe': 'CWE-200'
        }
    }

    # Suspicious ports (non-standard or commonly used by malware)
    SUSPICIOUS_PORTS = {
        21: 'FTP - File Transfer Protocol (unencrypted)',
        22: 'SSH - Secure Shell (potential brute force target)',
        23: 'Telnet - Unencrypted remote access',
        25: 'SMTP - Email transmission (potential spam)',
        53: 'DNS - Domain Name System',
        80: 'HTTP - Unencrypted web traffic',
        110: 'POP3 - Email retrieval (unencrypted)',
        135: 'Windows RPC - Remote Procedure Call',
        137: 'NetBIOS Name Service',
        138: 'NetBIOS Datagram Service',
        139: 'NetBIOS Session Service',
        143: 'IMAP - Email retrieval (unencrypted)',
        161: 'SNMP - Simple Network Management Protocol',
        389: 'LDAP - Lightweight Directory Access Protocol',
        443: 'HTTPS - Encrypted web traffic',
        445: 'SMB - Server Message Block',
        465: 'SMTPS - SMTP over SSL/TLS',
        587: 'SMTP Submission',
        993: 'IMAPS - IMAP over SSL/TLS',
        995: 'POP3S - POP3 over SSL/TLS',
        1080: 'SOCKS Proxy',
        1433: 'MSSQL - Microsoft SQL Server',
        1521: 'Oracle Database',
        3306: 'MySQL Database',
        3389: 'RDP - Remote Desktop Protocol',
        5432: 'PostgreSQL Database',
        5900: 'VNC - Virtual Network Computing',
        6379: 'Redis Database',
        8080: 'HTTP Alternate (often used for web servers)',
        8443: 'HTTPS Alternate',
        8888: 'HTTP Alternate (often used for proxies)',
        9000: 'HTTP Alternate (often used for web services)',
        27017: 'MongoDB Database',
        27018: 'MongoDB Shard Server',
        27019: 'MongoDB Config Server'
    }

    # Suspicious User Agent patterns
    SUSPICIOUS_USER_AGENTS = {
        'bot': r'(bot|crawler|spider|scraper|scan|harvest|extract)',
        'tool': r'(curl|wget|python-requests|java|httpclient|axios|fetch)',
        'vulnerability_scanner': r'(nessus|nikto|sqlmap|nmap|burp|owasp|metasploit|acunetix)',
        'suspicious': r'(hack|crack|exploit|inject|bypass|steal|phish)',
        'automated': r'(automated|script|headless|selenium|puppeteer|playwright)',
        'proxy': r'(proxy|vpn|tunnel|anonymizer|tor)',
        'unknown': r'(unknown|undefined|null|none)'
    }

    FREE_SURF_PORT_WEIGHTS = {
        # Standard proxy/tunnel ports
        1080: ('SOCKS proxy port observed', 30, 'transport'),
        3128: ('HTTP proxy port observed', 28, 'transport'),
        8118: ('Privoxy-style port observed', 30, 'transport'),
        9050: ('Tor SOCKS port observed', 35, 'transport'),
        9051: ('Tor control/proxy-related port observed', 30, 'transport'),
        10808: ('Proxy tunnel port observed', 28, 'transport'),
        8080: ('Common proxy port observed', 12, 'transport'),
        8081: ('Alternate proxy port observed', 10, 'transport'),
        8888: ('Alternate proxy port observed', 14, 'transport'),
        4443: ('TLS tunnel port observed', 8, 'transport'),
        # African-specific proxy ports
        8000: ('HTTP proxy port common in Africa', 15, 'transport'),
        8880: ('Alternate proxy port common in Africa', 12, 'transport'),
        9999: ('Proxy port observed', 10, 'transport'),
        10080: ('Proxy port observed', 12, 'transport'),
        # VPN/tunnel ports
        1194: ('OpenVPN port observed', 32, 'transport'),
        443: ('HTTPS tunnel port', 8, 'transport'),
        554: ('RTSP tunnel port', 10, 'transport'),
        1723: ('PPTP VPN port observed', 25, 'transport'),
        500: ('IKE VPN port observed', 20, 'transport'),
        4500: ('IPsec NAT-T port observed', 18, 'transport'),
        # African ISP-specific ports
        80: ('HTTP port (common for captive portals)', 5, 'transport'),
        443: ('HTTPS port (common for captive portals)', 5, 'transport'),
        # Shadowsocks/SSR ports
        8388: ('Shadowsocks port observed', 28, 'transport'),
        8389: ('Shadowsocks alternate port', 25, 'transport'),
        # V2Ray ports
        10086: ('V2Ray port observed', 25, 'transport'),
        10809: ('V2Ray alternate port', 22, 'transport'),
        # Trojan ports
        443: ('Trojan uses HTTPS port', 8, 'transport'),
        # WireGuard ports
        51820: ('WireGuard port observed', 30, 'transport'),
        # SSH tunnel ports
        22: ('SSH tunnel possible', 15, 'transport'),
        2222: ('SSH alternate port', 12, 'transport'),
    }

    FREE_SURF_TEXT_SIGNALS = {
        'vpn_proxy_branding': {
            'pattern': r'(^|[-_./\s])(vpn|proxy|anonymizer|anonymiseur|tunnel|socks5?|shadowsocks|wireguard|openvpn|softether|tor)([-_./\s]|$)',
            'weight': 16,
            'category': 'lexical',
            'reason': 'VPN/proxy branding detected in the traffic'
        },
        'captive_portal': {
            'pattern': r'(captive\s+portal|hotspot\s+login|login\s+to\s+(continue|access)|wifi\s+login|network\s+login|voucher|walled\s+garden|internet\s+access\s+required)',
            'weight': 28,
            'category': 'portal',
            'reason': 'Captive portal or hotspot login flow detected'
        },
        'free_access_branding': {
            'pattern': r'(free\s*(wifi|internet|surf)|internet\s*(gratis|gratuit)|wifi\s*(public|gratuit|free)|public\s+wifi)',
            'weight': 18,
            'category': 'portal',
            'reason': 'Free-access or public-WiFi branding detected'
        },
        'dns_over_https': {
            'pattern': r'(/dns-query\b|application/dns-message|application/dns-json)',
            'weight': 14,
            'category': 'dns_tunnel',
            'reason': 'DNS-over-HTTPS style traffic detected'
        },
        'proxy_error': {
            'pattern': r'(proxy\s+authentication\s+required|forward\s+proxy|transparent\s+proxy|upstream\s+proxy|squid\s+error)',
            'weight': 32,
            'category': 'transport',
            'reason': 'Explicit proxy gateway behavior detected'
        },
        'login_redirect': {
            'pattern': r'(/(hotspot|portal|wifi|login|auth|connect)(/|\?|$))',
            'weight': 12,
            'category': 'portal',
            'reason': 'Portal or access-control URL structure detected'
        },
        # Africa/Ivory Coast specific patterns
        'african_isp_branding': {
            'pattern': r'(mtn|airtel|orange|vodafone|safaricom|vodacom|telkom|celtel|moov|warid|etisalat|maroc\s+telecom|ooredoo|zain|sonatel|telecel|canal\+|afrihost|mweb|webafrica|cybersmart|africell|glo|9mobile|airtel\s+tigo|expresso|nexttel|camtel|viztel|gamtel|qcell|lintel|netone|telecel|yoomee|telma|blueline|telkom\s+sa)',
            'weight': 15,
            'category': 'african_isp',
            'reason': 'African ISP branding detected'
        },
        'ivory_coast_specific': {
            'pattern': r'(ci\.|cote\s+d\'ivoire|ivoire|abidjan|yamoussoukro|bouaké|san-pédro|korhogo|daloa|man|dimbokro|gagnoa|grand-bassam|bonoua|sassandra|tabou|dabou|bingerville|anyama|cocody|plateau|marcoussi|treichville|adjame|koumassi|yopougon|attécoubé|abobo|songon|bingerville)',
            'weight': 20,
            'category': 'african_geo',
            'reason': 'Ivory Coast geographic markers detected'
        },
        'african_free_wifi': {
            'pattern': r'(wifi\s+(gratuit|free|libre)|internet\s+(gratuit|free|libre)|connexion\s+gratuite|accès\s+gratuit|hotspot\s+gratuit|zone\s+wifi|wifi\s+zone|public\s+wifi|wifi\s+public)',
            'weight': 22,
            'category': 'portal',
            'reason': 'African free WiFi/access branding detected'
        },
        'african_cybercafe': {
            'pattern': r'(cybercafé|cyber\s+cafe|cybercafe|cyber|café\s+internet|internet\s+cafe|cafe\s+internet|cyber\s+espace|espace\s+cyber|telecentre|tele\s+centre|point\s+wifi|wifi\s+point)',
            'weight': 18,
            'category': 'portal',
            'reason': 'African cybercafe or public access point detected'
        },
        'african_mobile_data': {
            'pattern': r'(mobile\s+data|data\s+plan|internet\s+mobile|forfait\s+internet|forfait\s+data|data\s+bundle|bundle\s+data|airtime|crédit|recharge|top\s+up|rechargement)',
            'weight': 12,
            'category': 'mobile',
            'reason': 'African mobile data terminology detected'
        },
        'african_payment': {
            'pattern': r'(momo|mobile\s+money|orange\s+money|mtn\s+mobile\s+money|airtel\s+money|wave|flooz|moov\s+money|tmoney|wizall|paylib|e-money|electronic\s+money|argent\s+mobile|paiement\s+mobile)',
            'weight': 14,
            'category': 'payment',
            'reason': 'African mobile payment terminology detected'
        },
        'african_university': {
            'pattern': r'(université|university|enseignement\s+supérieur|higher\s+education|école|school|institut|institute|faculté|faculty|campus|étudiant|student|recherche|research)',
            'weight': 10,
            'category': 'education',
            'reason': 'African educational institution detected'
        },
        'african_government': {
            'pattern': r'(gouvernement|government|ministère|ministry|administration|public|publique|état|state|officiel|official|service\s+public|public\s+service)',
            'weight': 8,
            'category': 'government',
            'reason': 'African government/public service detected'
        },
    }

    # Standard ports that are generally safe
    STANDARD_PORTS = {80, 443, 8080, 8443}

    # African-specific POST payload patterns for Free Surf detection
    AFRICAN_PAYLOAD_PATTERNS = {
        'login_form': {
            'pattern': r'(username|user|email|telephone|phone|mobile|numero|msisdn|login|identifiant)(=|:)',
            'weight': 15,
            'category': 'authentication',
            'reason': 'African login form parameters detected'
        },
        'password_field': {
            'pattern': r'(password|pass|pwd|mot\s+de\s+passe|code|pin|secret)(=|:)',
            'weight': 20,
            'category': 'authentication',
            'reason': 'Password field detected in payload'
        },
        'mobile_money_payment': {
            'pattern': r'(momo|mobile\s+money|orange\s+money|mtn\s+money|airtel\s+money|wave|flooz|tmoney|amount|montant|receiver|beneficiary|phone|numero|msisdn)(=|:)',
            'weight': 25,
            'category': 'payment',
            'reason': 'African mobile money payment parameters detected'
        },
        'voucher_code': {
            'pattern': r'(voucher|code|ticket|coupon|pin|recharge|credit|crédit)(=|:)',
            'weight': 18,
            'category': 'portal',
            'reason': 'Voucher/coupon code parameter detected'
        },
        'wifi_hotspot_auth': {
            'pattern': r'(hotspot|wifi|portal|captive|mac|address|client|ip|session|token)(=|:)',
            'weight': 22,
            'category': 'portal',
            'reason': 'WiFi hotspot authentication parameters detected'
        },
        'african_isp_auth': {
            'pattern': r'(mtn|orange|airtel|vodacom|safaricom|moov|telecel|etisalat|zain|maroc\s+telecom|ooredoo)(=|:)',
            'weight': 16,
            'category': 'isp',
            'reason': 'African ISP authentication parameter detected'
        },
        'data_bundle_purchase': {
            'pattern': r'(bundle|data|forfait|plan|package|offer|internet|volume|gigabyte|mb|gb)(=|:)',
            'weight': 14,
            'category': 'mobile',
            'reason': 'Data bundle purchase parameters detected'
        },
        'airtime_topup': {
            'pattern': r'(airtime|topup|recharge|credit|crédit|amount|montant|phone|numero)(=|:)',
            'weight': 12,
            'category': 'mobile',
            'reason': 'Airtime top-up parameters detected'
        },
    }

    def __init__(self, request_timeout: Optional[int] = None):
        self.security_issues: List[SecurityIssue] = []
        self.performance_issues: List[PerformanceIssue] = []
        self.pattern_matches: List[PatternMatch] = []
        self.domains: Dict[str, DomainInfo] = {}
        self.js_vulnerabilities: List[JSVulnerability] = []
        self.network_issues: List[NetworkIssue] = []
        self.ports: Dict[int, PortInfo] = {}
        self.user_agents: Dict[str, UserAgentInfo] = {}
        self.request_timeout = request_timeout if request_timeout is not None else get_default_inmux_timeout()
        self.hackertarget_api_key = os.getenv('HACKERTARGET_API_KEY', '').strip()

    def _build_hackertarget_url(self, endpoint: str, target: str, *, require_api_key: bool = False) -> Optional[str]:
        """Build a HackerTarget API URL and inject the API key when required."""
        # HackerTarget allows free usage without API key for basic queries (with rate limits)
        # Only require API key for premium endpoints
        base_url = f"https://api.hackertarget.com/{endpoint}/?q={quote_plus(target)}"
        if self.hackertarget_api_key:
            return f"{base_url}&apikey={quote_plus(self.hackertarget_api_key)}"
        return base_url

    def _request_hackertarget(self, url: Optional[str], *, tool_name: str, require_api_key: bool = False) -> str:
        """Execute a HackerTarget request with explicit timeout and SSL handling."""
        if not url:
            return (
                f"ERROR: {tool_name} requires a HackerTarget API key. "
                "Set the HACKERTARGET_API_KEY environment variable and retry."
            )

        try:
            response = requests.get(url, timeout=self.request_timeout)
            response.raise_for_status()
            text = response.text.strip()
            if text.lower().startswith('error'):
                return f"ERROR: {text}"
            return text
        except requests.exceptions.SSLError as exc:
            logger.warning("SSL error while contacting HackerTarget: %s", url, exc_info=True)
            return f"ERROR: SSL error while contacting HackerTarget: {str(exc)}"
        except requests.exceptions.Timeout:
            logger.warning("HackerTarget request timed out after %s seconds: %s", self.request_timeout, url)
            return f"ERROR: Request to HackerTarget timed out after {self.request_timeout} seconds."
        except requests.exceptions.RequestException as exc:
            logger.warning("Network error while contacting HackerTarget: %s", url, exc_info=True)
            return f"ERROR: Network error while contacting HackerTarget: {str(exc)}"

    def analyze_ports(self, har_file) -> Dict[int, PortInfo]:
        """
        Analyze ports used in network connections.

        Args:
            har_file: HARFile object

        Returns:
            Dictionary mapping port numbers to PortInfo objects
        """
        self.ports = {}

        for entry in har_file.entries:
            try:
                # Extract port from URL
                parsed_url = urlparse(entry.request.url)
                port = parsed_url.port

                if not port:
                    # Use default port based on scheme
                    port = 443 if parsed_url.scheme == 'https' else 80

                if port not in self.ports:
                    port_info = PortInfo(
                        port=port,
                        protocol=parsed_url.scheme,
                        domain=parsed_url.hostname or "",
                        connection_count=1,
                        is_standard=port in self.STANDARD_PORTS,
                        is_suspicious=False,
                        security_risk=self._assess_port_security_risk(port)
                    )
                    self.ports[port] = port_info
                else:
                    self.ports[port].connection_count += 1

                # Check if port is suspicious
                if port in self.SUSPICIOUS_PORTS and port not in self.STANDARD_PORTS:
                    self.ports[port].is_suspicious = True

            except (AttributeError, TypeError, ValueError):
                logger.debug("Skipping malformed HAR entry during port analysis.", exc_info=True)
                continue

        return self.ports

    def analyze_user_agents(self, har_file) -> Dict[str, UserAgentInfo]:
        """
        Analyze User Agents in network requests.

        Args:
            har_file: HARFile object

        Returns:
            Dictionary mapping user agent strings to UserAgentInfo objects
        """
        self.user_agents = {}

        for entry in har_file.entries:
            try:
                user_agent = entry.request.get_header('user-agent') or 'unknown'

                if user_agent not in self.user_agents:
                    user_agent_info = UserAgentInfo(
                        user_agent=user_agent,
                        connection_count=1,
                        is_bot=self._detect_bot(user_agent),
                        is_suspicious=self._detect_suspicious_user_agent(user_agent),
                        browser=self._extract_browser(user_agent),
                        os=self._extract_os(user_agent),
                        security_risk=self._assess_user_agent_security_risk(user_agent)
                    )
                    self.user_agents[user_agent] = user_agent_info
                else:
                    self.user_agents[user_agent].connection_count += 1

            except (AttributeError, TypeError, ValueError):
                logger.debug("Skipping malformed HAR entry during user-agent analysis.", exc_info=True)
                continue

        return self.user_agents

    def _assess_port_security_risk(self, port: int) -> str:
        """
        Assess the security risk level of a port.

        Args:
            port: Port number

        Returns:
            Security risk level (critical, high, medium, low, info)
        """
        # Database ports
        if port in [1433, 1521, 3306, 5432, 6379, 27017, 27018, 27019]:
            return 'critical'
        # Remote access ports
        if port in [22, 23, 135, 3389, 5900]:
            return 'critical'
        # File transfer ports
        if port in [21, 445]:
            return 'high'
        # Email ports
        if port in [25, 110, 143]:
            return 'high'
        # Proxy/VPN ports
        if port in [1080, 8888]:
            return 'high'
        # Standard web ports
        if port in [80, 443, 8080, 8443]:
            return 'low'
        # Other known services
        if port in self.SUSPICIOUS_PORTS:
            return 'medium'
        return 'info'

    def _detect_bot(self, user_agent: str) -> bool:
        """
        Detect if User Agent is a bot.

        Args:
            user_agent: User agent string

        Returns:
            True if bot detected
        """
        bot_pattern = self.SUSPICIOUS_USER_AGENTS['bot']
        return bool(re.search(bot_pattern, user_agent, re.IGNORECASE))

    def _detect_suspicious_user_agent(self, user_agent: str) -> bool:
        """
        Detect if User Agent is suspicious.

        Args:
            user_agent: User agent string

        Returns:
            True if suspicious
        """
        for category, pattern in self.SUSPICIOUS_USER_AGENTS.items():
            if re.search(pattern, user_agent, re.IGNORECASE):
                return True
        return False

    def _extract_browser(self, user_agent: str) -> str:
        """
        Extract browser name from User Agent.

        Args:
            user_agent: User agent string

        Returns:
            Browser name
        """
        if 'chrome' in user_agent.lower():
            return 'Chrome'
        elif 'firefox' in user_agent.lower():
            return 'Firefox'
        elif 'safari' in user_agent.lower():
            return 'Safari'
        elif 'edge' in user_agent.lower():
            return 'Edge'
        elif 'opera' in user_agent.lower():
            return 'Opera'
        elif 'msie' in user_agent.lower() or 'trident' in user_agent.lower():
            return 'Internet Explorer'
        else:
            return 'Unknown'

    def _extract_os(self, user_agent: str) -> str:
        """
        Extract OS from User Agent.

        Args:
            user_agent: User agent string

        Returns:
            OS name
        """
        if 'windows' in user_agent.lower():
            return 'Windows'
        elif 'mac os x' in user_agent.lower() or 'macintosh' in user_agent.lower():
            return 'macOS'
        elif 'linux' in user_agent.lower():
            return 'Linux'
        elif 'android' in user_agent.lower():
            return 'Android'
        elif 'iphone' in user_agent.lower() or 'ipad' in user_agent.lower() or 'ios' in user_agent.lower():
            return 'iOS'
        else:
            return 'Unknown'

    def _assess_user_agent_security_risk(self, user_agent: str) -> str:
        """
        Assess the security risk level of a User Agent.

        Args:
            user_agent: User agent string

        Returns:
            Security risk level (critical, high, medium, low, info)
        """
        # Vulnerability scanners
        scanner_pattern = self.SUSPICIOUS_USER_AGENTS['vulnerability_scanner']
        if re.search(scanner_pattern, user_agent, re.IGNORECASE):
            return 'critical'
        # Suspicious activities
        suspicious_pattern = self.SUSPICIOUS_USER_AGENTS['suspicious']
        if re.search(suspicious_pattern, user_agent, re.IGNORECASE):
            return 'high'
        # Automated tools
        automated_pattern = self.SUSPICIOUS_USER_AGENTS['automated']
        if re.search(automated_pattern, user_agent, re.IGNORECASE):
            return 'medium'
        # Bots
        bot_pattern = self.SUSPICIOUS_USER_AGENTS['bot']
        if re.search(bot_pattern, user_agent, re.IGNORECASE):
            return 'medium'
        # Unknown user agents
        unknown_pattern = self.SUSPICIOUS_USER_AGENTS['unknown']
        if re.search(unknown_pattern, user_agent, re.IGNORECASE):
            return 'low'
        return 'info'

    def _normalize_network_domain(self, entry) -> str:
        """Extract a normalized hostname for network correlation."""
        parsed_url = urlparse(entry.request.url)
        return (parsed_url.hostname or entry.domain or '').lower()

    def _get_entry_port(self, entry) -> int:
        """Get the effective port used by an entry."""
        parsed_url = urlparse(entry.request.url)
        if parsed_url.port:
            return parsed_url.port
        return 443 if parsed_url.scheme == 'https' else 80

    def _headers_to_map(self, headers: List[Dict[str, str]]) -> Dict[str, str]:
        """Convert HAR headers to a lowercase dictionary."""
        header_map: Dict[str, str] = {}
        for header in headers:
            name = str(header.get('name', '')).lower()
            value = str(header.get('value', ''))
            if name:
                header_map[name] = value
        return header_map

    def _safe_entry_text(self, entry, limit: int = 1200) -> str:
        """Extract textual content from a HAR entry without decoding binary blobs."""
        text_parts = [entry.request.url]

        if entry.request.post_data and isinstance(entry.request.post_data, dict):
            post_text = entry.request.post_data.get('text')
            if isinstance(post_text, str) and post_text:
                text_parts.append(post_text[:limit])

        if entry.response.content and isinstance(entry.response.content, dict):
            content_text = entry.response.content.get('text')
            mime_type = str(entry.response.content.get('mimeType', '')).lower()
            encoding = str(entry.response.content.get('encoding', '')).lower()
            is_textual = any(token in mime_type for token in ['text', 'json', 'xml', 'javascript', 'html', 'x-www-form-urlencoded'])
            if isinstance(content_text, str) and content_text and (is_textual or not encoding):
                text_parts.append(content_text[:limit])

        return ' '.join(part for part in text_parts if part).lower()

    def _normalize_host_header(self, host_header: str) -> str:
        """Normalize a Host header to a bare lowercase hostname."""
        if not host_header:
            return ""

        try:
            parsed_host = urlparse(f"//{host_header}")
            return (parsed_host.hostname or "").lower()
        except ValueError:
            return host_header.strip().lower()

    def _is_ip_literal(self, host: str) -> bool:
        """Return True when the provided host string is an IP literal."""
        if not host:
            return False

        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _make_network_issue(
        self,
        *,
        severity: str,
        category: str,
        title: str,
        description: str,
        domain: str,
        entry_index: int,
        recommendation: str,
        alert_recipient: str,
        evidence: str = "",
        score: int = 0,
        confidence: str = "low",
        indicators: Optional[List[str]] = None,
    ) -> NetworkIssue:
        """Create a network issue with consistent defaults."""
        return NetworkIssue(
            severity=severity,
            category=category,
            title=title,
            description=description,
            domain=domain,
            entry_index=entry_index,
            evidence=evidence,
            score=score,
            confidence=confidence,
            indicators=indicators or [],
            recommendation=recommendation,
            alert_recipient=alert_recipient,
        )

    def _new_free_surf_profile(self, domain: str) -> Dict[str, Any]:
        """Create a mutable profile used to score free-surf indicators."""
        return {
            'domain': domain,
            'score': 0,
            'categories': set(),
            'indicators': [],
            'indicator_keys': set(),
            'evidence': [],
            'entry_indices': set(),
            'request_count': 0,
            'strong_indicator': False,
        }

    def _add_free_surf_signal(
        self,
        profile: Dict[str, Any],
        *,
        key: str,
        weight: int,
        category: str,
        reason: str,
        entry_index: int,
        evidence: str = "",
        strong: bool = False,
    ):
        """Add a weighted free-surf signal to a profile without double-counting the same reason."""
        profile['entry_indices'].add(entry_index)
        profile['categories'].add(category)

        if key in profile['indicator_keys']:
            return

        profile['indicator_keys'].add(key)
        profile['score'] += weight
        profile['indicators'].append(reason)
        if evidence:
            profile['evidence'].append(evidence[:180])
        if strong:
            profile['strong_indicator'] = True

    def _free_surf_severity(self, score: int) -> str:
        """Convert weighted score to severity."""
        if score >= 85:
            return 'critical'
        if score >= 60:
            return 'high'
        if score >= 35:
            return 'medium'
        return 'low'

    def _free_surf_confidence(self, score: int) -> str:
        """Convert weighted score to human-readable confidence."""
        if score >= 85:
            return 'very_high'
        if score >= 60:
            return 'high'
        if score >= 35:
            return 'medium'
        return 'low'

    def _build_free_surf_issue(self, profile: Dict[str, Any]) -> Optional[NetworkIssue]:
        """Finalize a scored free-surf profile into a network issue when evidence is strong enough."""
        raw_score = profile['score']
        score = min(raw_score, 100)
        category_count = len(profile['categories'])
        has_enough_signal = raw_score >= 60 or (raw_score >= 35 and (profile['strong_indicator'] or category_count >= 2))

        if not has_enough_signal:
            return None

        severity = self._free_surf_severity(score)
        confidence = self._free_surf_confidence(score)
        sorted_indicators = profile['indicators'][:6]
        evidence = ' | '.join(profile['evidence'][:4])
        description = (
            f"Correlated indicators suggest proxy/VPN/free-access traffic on {profile['domain']}. "
            f"Signals observed: {len(profile['indicators'])}, categories crossed: {category_count}, score: {score}/100."
        )

        return self._make_network_issue(
            severity=severity,
            category='free_internet',
            title='Suspicion de Free Surf / Proxy / VPN',
            description=description,
            domain=profile['domain'],
            entry_index=min(profile['entry_indices']) if profile['entry_indices'] else -1,
            evidence=evidence,
            score=score,
            confidence=confidence,
            indicators=sorted_indicators,
            recommendation=(
                'Inspect the related proxy/VPN endpoints, review CONNECT and 407 flows, '
                'verify hotspot portal behavior, and validate whether this traffic is authorized.'
            ),
            alert_recipient=self._extract_alert_recipient(profile['domain'])
        )

    def _detect_free_internet_services(self, har_file) -> List[NetworkIssue]:
        """Detect realistic free-surf, proxy, VPN, tunnel, and captive-portal behavior."""
        profiles: Dict[str, Dict[str, Any]] = {}

        for idx, entry in enumerate(har_file.entries):
            try:
                domain = self._normalize_network_domain(entry)
                if not domain:
                    continue

                profile = profiles.setdefault(domain, self._new_free_surf_profile(domain))
                parsed_url = urlparse(entry.request.url)
                request_headers = self._headers_to_map(entry.request.headers)
                response_headers = self._headers_to_map(entry.response.headers)
                entry_text = self._safe_entry_text(entry)
                user_agent = request_headers.get('user-agent', '')
                location_header = response_headers.get('location', '')
                port = self._get_entry_port(entry)
                profile['request_count'] += 1

                if entry.request.method.upper() == 'CONNECT':
                    self._add_free_surf_signal(
                        profile,
                        key='http_connect',
                        weight=45,
                        category='transport',
                        reason='HTTP CONNECT tunnel method observed',
                        entry_index=idx,
                        evidence=entry.request.url,
                        strong=True,
                    )

                if entry.response.status == 407:
                    self._add_free_surf_signal(
                        profile,
                        key='proxy_auth_status',
                        weight=45,
                        category='transport',
                        reason='HTTP 407 Proxy Authentication Required observed',
                        entry_index=idx,
                        evidence=f"status={entry.response.status}",
                        strong=True,
                    )

                header_signals = {
                    'proxy-authorization': (40, 'transport', 'Proxy authorization header observed', True),
                    'proxy-authenticate': (40, 'transport', 'Proxy authentication challenge observed', True),
                    'proxy-connection': (32, 'transport', 'Proxy connection header observed', True),
                    'via': (20, 'transport', 'Proxy traversal header observed', False),
                    'forwarded': (12, 'transport', 'Forwarded header observed', False),
                    'x-forwarded-for': (10, 'transport', 'Forwarded client IP header observed', False),
                    'x-forwarded-host': (8, 'transport', 'Forwarded host header observed', False),
                    'x-real-ip': (8, 'transport', 'Real client IP header observed', False),
                    'x-bluecoat-via': (25, 'transport', 'BlueCoat proxy header observed', True),
                    'x-squid-error': (25, 'transport', 'Squid proxy error header observed', True),
                }

                for header_name, (weight, category, reason, strong) in header_signals.items():
                    header_value = request_headers.get(header_name) or response_headers.get(header_name)
                    if header_value:
                        self._add_free_surf_signal(
                            profile,
                            key=f'header:{header_name}',
                            weight=weight,
                            category=category,
                            reason=reason,
                            entry_index=idx,
                            evidence=f'{header_name}: {str(header_value)[:80]}',
                            strong=strong,
                        )

                server_header = response_headers.get('server', '').lower()
                if any(token in server_header for token in ['squid', 'privoxy', 'tinyproxy', 'haproxy']):
                    self._add_free_surf_signal(
                        profile,
                        key='proxy_server_banner',
                        weight=24,
                        category='transport',
                        reason='Proxy-like server banner detected',
                        entry_index=idx,
                        evidence=server_header[:80],
                        strong=True,
                    )

                if port in self.FREE_SURF_PORT_WEIGHTS:
                    reason, weight, category = self.FREE_SURF_PORT_WEIGHTS[port]
                    self._add_free_surf_signal(
                        profile,
                        key=f'port:{port}',
                        weight=weight,
                        category=category,
                        reason=reason,
                        entry_index=idx,
                        evidence=f'port={port}',
                        strong=port in {1080, 3128, 8118, 9050, 9051, 10808},
                    )

                if location_header and re.search(self.FREE_SURF_TEXT_SIGNALS['login_redirect']['pattern'], location_header, re.IGNORECASE):
                    self._add_free_surf_signal(
                        profile,
                        key='portal_redirect',
                        weight=18,
                        category='portal',
                        reason='Access-control redirect detected',
                        entry_index=idx,
                        evidence=location_header[:120],
                        strong=True,
                    )

                for signal_name, signal in self.FREE_SURF_TEXT_SIGNALS.items():
                    if re.search(signal['pattern'], entry_text, re.IGNORECASE):
                        self._add_free_surf_signal(
                            profile,
                            key=f'text:{signal_name}',
                            weight=signal['weight'],
                            category=signal['category'],
                            reason=signal['reason'],
                            entry_index=idx,
                            evidence=(parsed_url.path or entry.request.url)[:120],
                            strong=signal_name in {'captive_portal', 'proxy_error'},
                        )

                if re.search(self.SUSPICIOUS_USER_AGENTS['proxy'], user_agent, re.IGNORECASE):
                    self._add_free_surf_signal(
                        profile,
                        key='ua_proxy',
                        weight=14,
                        category='lexical',
                        reason='User-Agent references proxy/VPN/tunnel tooling',
                        entry_index=idx,
                        evidence=user_agent[:120],
                        strong=False,
                    )

                if domain.endswith('.onion') or '.i2p' in domain:
                    self._add_free_surf_signal(
                        profile,
                        key='anonymous_network',
                        weight=35,
                        category='transport',
                        reason='Anonymous overlay network domain detected',
                        entry_index=idx,
                        evidence=domain,
                        strong=True,
                    )

                # Check POST payload patterns for African-specific indicators
                if entry.request.method.upper() == 'POST' and entry.request.post_data:
                    post_text = ''
                    if isinstance(entry.request.post_data, dict):
                        post_text = entry.request.post_data.get('text', '') or ''
                    elif isinstance(entry.request.post_data, str):
                        post_text = entry.request.post_data
                    
                    if post_text:
                        post_text_lower = post_text.lower()
                        for pattern_name, pattern_info in self.AFRICAN_PAYLOAD_PATTERNS.items():
                            if re.search(pattern_info['pattern'], post_text_lower, re.IGNORECASE):
                                self._add_free_surf_signal(
                                    profile,
                                    key=f'payload:{pattern_name}',
                                    weight=pattern_info['weight'],
                                    category=pattern_info['category'],
                                    reason=pattern_info['reason'],
                                    entry_index=idx,
                                    evidence=post_text[:150],
                                    strong=pattern_name in {'password_field', 'mobile_money_payment'},
                                )

            except (AttributeError, TypeError, ValueError, re.error):
                logger.debug("Skipping malformed HAR entry during free-surf detection.", exc_info=True)
                continue

        issues = []
        for profile in profiles.values():
            if profile['request_count'] >= 5 and profile['score'] >= 25:
                self._add_free_surf_signal(
                    profile,
                    key='traffic_volume',
                    weight=10,
                    category='behavior',
                    reason='Repeated suspicious traffic volume observed',
                    entry_index=min(profile['entry_indices']) if profile['entry_indices'] else -1,
                    evidence=f"requests={profile['request_count']}",
                    strong=False,
                )

            issue = self._build_free_surf_issue(profile)
            if issue:
                issues.append(issue)

        return sorted(issues, key=lambda issue: (-issue.score, issue.domain))

    def summarize_free_internet_issues(self, network_issues: Optional[List[NetworkIssue]] = None) -> Dict[str, Any]:
        """Build a concise summary focused on free-surf detection results."""
        issues = [
            issue for issue in (network_issues if network_issues is not None else self.network_issues)
            if issue.category == 'free_internet'
        ]

        if not issues:
            return {
                'detected': False,
                'total': 0,
                'domains': 0,
                'max_score': 0,
                'risk_level': 'none',
                'confidence': 'low',
                'verdict': 'Aucun indice solide de Free Surf détecté.',
                'top_targets': []
            }

        top_issue = max(issues, key=lambda issue: issue.score)
        verdict_map = {
            'critical': 'Suspicion très élevée de Free Surf / proxy / VPN.',
            'high': 'Suspicion élevée de Free Surf / proxy / VPN.',
            'medium': 'Suspicion modérée mais crédible de Free Surf / proxy / VPN.',
            'low': 'Quelques signaux faibles liés au Free Surf ont été vus.',
        }

        return {
            'detected': True,
            'total': len(issues),
            'domains': len({issue.domain for issue in issues if issue.domain}),
            'max_score': top_issue.score,
            'risk_level': top_issue.severity,
            'confidence': top_issue.confidence,
            'verdict': verdict_map.get(top_issue.severity, 'Détection Free Surf disponible.'),
            'top_targets': [
                {
                    'domain': issue.domain,
                    'score': issue.score,
                    'confidence': issue.confidence,
                    'severity': issue.severity,
                    'indicators': issue.indicators[:4],
                }
                for issue in sorted(issues, key=lambda issue: (-issue.score, issue.domain))[:5]
            ]
        }

    def _detect_host_proxy_tls_anomalies(self, har_file) -> List[NetworkIssue]:
        """Detect passive Host/Proxy/TLS anomalies that a HAR can realistically prove."""
        issues: List[NetworkIssue] = []
        seen_keys = set()
        domain_server_ips: Dict[str, set] = defaultdict(set)

        for idx, entry in enumerate(har_file.entries):
            try:
                parsed_url = urlparse(entry.request.url)
                url_host = (parsed_url.hostname or entry.domain or '').lower()
                url_port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
                if not url_host:
                    continue

                request_headers = self._headers_to_map(entry.request.headers)
                response_headers = self._headers_to_map(entry.response.headers)
                host_header = request_headers.get('host', '')
                normalized_host_header = self._normalize_host_header(host_header)
                evidence_prefix = f"url={entry.request.url}"

                if entry.server_ip_address:
                    domain_server_ips[url_host].add(entry.server_ip_address)

                def add_issue(title: str, description: str, severity: str, score: int, confidence: str,
                              recommendation: str, evidence: str, indicators: List[str]):
                    key = (title, url_host, evidence)
                    if key in seen_keys:
                        return
                    seen_keys.add(key)
                    issues.append(self._make_network_issue(
                        severity=severity,
                        category='host_proxy_tls',
                        title=title,
                        description=description,
                        domain=url_host,
                        entry_index=idx,
                        evidence=evidence,
                        score=score,
                        confidence=confidence,
                        indicators=indicators,
                        recommendation=recommendation,
                        alert_recipient=self._extract_alert_recipient(url_host)
                    ))

                if host_header and normalized_host_header and normalized_host_header != url_host:
                    add_issue(
                        title='Host Header / URL Host Mismatch',
                        description='The HTTP Host header differs from the URL host captured in the HAR.',
                        severity='high',
                        score=72,
                        confidence='high',
                        recommendation='Review whether a proxy, host rewrite rule, or access gateway is intentionally rewriting the destination host.',
                        evidence=f"{evidence_prefix}; host_header={host_header}",
                        indicators=['HTTP Host differs from URL host', 'Possible proxy or host rewrite']
                    )

                proxy_header_hits = []
                for header_name in [
                    'proxy-authorization',
                    'proxy-authenticate',
                    'proxy-connection',
                    'via',
                    'forwarded',
                    'x-forwarded-for',
                    'x-forwarded-host',
                    'x-real-ip',
                    'x-squid-error',
                    'x-bluecoat-via',
                ]:
                    header_value = request_headers.get(header_name) or response_headers.get(header_name)
                    if header_value:
                        proxy_header_hits.append(f"{header_name}={str(header_value)[:60]}")

                if proxy_header_hits:
                    add_issue(
                        title='Proxy Mediation Observed',
                        description='Proxy-related headers indicate that the traffic likely traversed an explicit or transparent intermediary.',
                        severity='high',
                        score=68,
                        confidence='high',
                        recommendation='Validate whether the proxy path is expected and whether traffic is being intentionally mediated.',
                        evidence=f"{evidence_prefix}; {'; '.join(proxy_header_hits[:4])}",
                        indicators=['Proxy headers present', 'Traffic likely traversed an intermediary']
                    )

                if entry.request.method.upper() == 'CONNECT':
                    add_issue(
                        title='Explicit HTTP Tunnel Observed',
                        description='The HAR contains an HTTP CONNECT request, which is typically used to tunnel traffic through a proxy.',
                        severity='critical',
                        score=88,
                        confidence='very_high',
                        recommendation='Inspect the target authority and confirm whether this tunnel is expected in your environment.',
                        evidence=evidence_prefix,
                        indicators=['HTTP CONNECT method', 'Explicit proxy tunnel behavior']
                    )

                tls_error_markers = [
                    'ssl handshake failed',
                    'tls handshake failed',
                    'certificate verify failed',
                    'unrecognized_name',
                    'unrecognized name',
                    'hostname mismatch',
                    'sni required',
                    'unknown ca',
                    'tls alert',
                ]
                response_blob = ' '.join([
                    str(entry.response.status),
                    str(entry.response.status_text or ''),
                    str(response_headers),
                    str(entry.response.content.get('text', '')[:300]) if isinstance(entry.response.content, dict) else '',
                ]).lower()

                if entry.response.status in {400, 421, 495, 496, 497, 525, 526} or any(marker in response_blob for marker in tls_error_markers):
                    add_issue(
                        title='TLS / Gateway Negotiation Failure',
                        description='The captured response looks like a TLS, certificate, host-routing, or gateway negotiation failure.',
                        severity='high',
                        score=70,
                        confidence='high',
                        recommendation='Check certificate validity, host routing, reverse proxy configuration, and upstream TLS expectations.',
                        evidence=f"{evidence_prefix}; status={entry.response.status}; status_text={entry.response.status_text}",
                        indicators=['TLS or gateway failure signature', 'Host routing or certificate issue']
                    )

                if entry.is_https and url_port not in {443, 8443}:
                    add_issue(
                        title='HTTPS on Non-Standard Port',
                        description='HTTPS traffic is using an unusual port, which can indicate alternate gateways, tunnels, or custom proxying.',
                        severity='medium',
                        score=42,
                        confidence='medium',
                        recommendation='Confirm whether this non-standard TLS endpoint is part of the expected architecture.',
                        evidence=f"{evidence_prefix}; port={url_port}",
                        indicators=['HTTPS observed on non-standard port']
                    )

                if entry.is_https and self._is_ip_literal(url_host):
                    add_issue(
                        title='HTTPS Request to IP Literal',
                        description='The HTTPS request targets an IP address directly rather than a hostname.',
                        severity='medium',
                        score=48,
                        confidence='medium',
                        recommendation='Check whether the endpoint is intentionally addressed by IP and whether certificate validation still makes sense.',
                        evidence=evidence_prefix,
                        indicators=['TLS endpoint addressed by IP literal']
                    )

            except (AttributeError, TypeError, ValueError):
                logger.debug("Skipping malformed HAR entry during Host/Proxy/TLS anomaly detection.", exc_info=True)
                continue

        for domain, ip_set in domain_server_ips.items():
            if len(ip_set) >= 4:
                evidence = f"domain={domain}; server_ips={', '.join(sorted(ip_set)[:6])}"
                key = ('High Backend IP Churn', domain, evidence)
                if key not in seen_keys:
                    seen_keys.add(key)
                    issues.append(self._make_network_issue(
                        severity='medium',
                        category='host_proxy_tls',
                        title='High Backend IP Churn',
                        description='Several different server IP addresses were observed for the same domain in one capture.',
                        domain=domain,
                        entry_index=-1,
                        evidence=evidence,
                        score=36,
                        confidence='medium',
                        indicators=['Multiple backend IPs for one host'],
                        recommendation='Confirm whether this domain is expected to sit behind a CDN, load balancer, or rotating gateway fleet.',
                        alert_recipient=self._extract_alert_recipient(domain)
                    ))

        return sorted(issues, key=lambda issue: (-issue.score, issue.domain, issue.title))

    def summarize_host_proxy_tls_issues(self, network_issues: Optional[List[NetworkIssue]] = None) -> Dict[str, Any]:
        """Summarize passive Host/Proxy/TLS anomalies that a HAR can support."""
        issues = [
            issue for issue in (network_issues if network_issues is not None else self.network_issues)
            if issue.category == 'host_proxy_tls'
        ]

        if not issues:
            return {
                'detected': False,
                'total': 0,
                'max_score': 0,
                'confidence': 'low',
                'verdict': 'Aucune anomalie Host / Proxy / TLS forte détectée.',
                'limitation': 'Le HAR ne contient pas le ClientHello TLS brut. Cette vue signale des anomalies passives, mais ne peut pas prouver un SNI bug à elle seule.',
                'by_type': {},
                'top_findings': [],
            }

        highest = max(issues, key=lambda issue: issue.score)
        verdict = (
            'Anomalies Host / Proxy / TLS fortement suspectes observées.'
            if highest.score >= 70 else
            'Quelques anomalies Host / Proxy / TLS méritent une revue.'
        )

        return {
            'detected': True,
            'total': len(issues),
            'max_score': highest.score,
            'confidence': highest.confidence,
            'verdict': verdict,
            'limitation': 'Le HAR ne contient pas le ClientHello TLS brut. Cette vue signale des anomalies passives, mais ne peut pas prouver un SNI bug à elle seule.',
            'by_type': dict(Counter(issue.title for issue in issues)),
            'top_findings': [
                {
                    'title': issue.title,
                    'domain': issue.domain,
                    'score': issue.score,
                    'confidence': issue.confidence,
                    'evidence': issue.evidence,
                    'indicators': issue.indicators[:4],
                }
                for issue in sorted(issues, key=lambda issue: (-issue.score, issue.domain, issue.title))[:8]
            ],
        }

    def analyze_domains(self, har_file) -> Dict[str, DomainInfo]:
        """
        Analyze unique domains contacted in the HAR file with detailed information.
        Similar to performance.getEntriesByType("resource").map(r => new URL(r.name).hostname)

        Args:
            har_file: HARFile object

        Returns:
            Dictionary mapping domain names to DomainInfo objects
        """
        self.domains = {}

        for idx, entry in enumerate(har_file.entries):
            try:
                domain = entry.domain

                if domain not in self.domains:
                    self.domains[domain] = DomainInfo(
                        domain=domain,
                        first_seen=idx,
                        last_seen=idx,
                        is_https=entry.is_https
                    )

                # Update domain information
                domain_info = self.domains[domain]
                domain_info.request_count += 1
                domain_info.last_seen = idx
                domain_info.total_size += entry.response.body_size if entry.response.body_size else 0
                domain_info.is_https = domain_info.is_https and entry.is_https

                # Track status codes
                status_code = str(entry.response.status)
                domain_info.status_codes[status_code] = domain_info.status_codes.get(status_code, 0) + 1

                # Track content types
                content_type = entry.response.get_header('content-type') or 'unknown'
                content_type_main = content_type.split(';')[0].strip()
                domain_info.content_types[content_type_main] = domain_info.content_types.get(content_type_main, 0) + 1

            except (AttributeError, TypeError, ValueError):
                logger.debug("Skipping malformed HAR entry during domain analysis.", exc_info=True)
                continue

        # Calculate average response times
        for domain_info in self.domains.values():
            total_time = 0
            count = 0
            for idx, entry in enumerate(har_file.entries):
                if entry.domain == domain_info.domain:
                    total_time += entry.time if entry.time else 0
                    count += 1
            domain_info.avg_response_time = total_time / count if count > 0 else 0

        return self.domains

    def analyze_javascript(self, js_code: str) -> List[JSVulnerability]:
        """
        Analyze JavaScript code for security vulnerabilities.

        Args:
            js_code: JavaScript source code as string

        Returns:
            List of JSVulnerability objects
        """
        self.js_vulnerabilities = []

        lines = js_code.split('\n')

        for line_num, line in enumerate(lines, start=1):
            for pattern_name, pattern_info in self.JS_VULNERABILITY_PATTERNS.items():
                try:
                    pattern = pattern_info['pattern']
                    matches = re.finditer(pattern, line, re.IGNORECASE)

                    for match in matches:
                        vulnerability = JSVulnerability(
                            severity=pattern_info['severity'],
                            category=pattern_info['category'],
                            title=pattern_info['title'],
                            description=pattern_info['description'],
                            line_number=line_num,
                            code_snippet=line.strip()[:200],
                            recommendation=pattern_info['recommendation'],
                            cwe_id=pattern_info['cwe']
                        )
                        self.js_vulnerabilities.append(vulnerability)
                except re.error:
                    logger.debug("Skipping invalid JavaScript vulnerability regex %s.", pattern_name, exc_info=True)
                    continue

        return self.js_vulnerabilities

    def analyze_network(self, har_file) -> List[NetworkIssue]:
        """
        Analyze network security issues including SSL/TLS certificates and domain security.

        Args:
            har_file: HARFile object

        Returns:
            List of NetworkIssue objects
        """
        self.network_issues = []

        for idx, entry in enumerate(har_file.entries):
            try:
                # Check HTTP only connections
                if not entry.is_https:
                    issue = self._make_network_issue(
                        severity='high',
                        category='ssl_tls',
                        title='HTTP Only Connection',
                        description='Connection uses HTTP instead of HTTPS, exposing data to interception.',
                        domain=entry.domain,
                        entry_index=idx,
                        recommendation='Use HTTPS for all connections.',
                        alert_recipient=self._extract_alert_recipient(entry.domain)
                    )
                    self.network_issues.append(issue)

                # Check for mixed content
                if entry.is_https and 'http:' in entry.request.url:
                    issue = self._make_network_issue(
                        severity='medium',
                        category='ssl_tls',
                        title='Mixed Content',
                        description='HTTPS page loading HTTP resources, breaking security.',
                        domain=entry.domain,
                        entry_index=idx,
                        recommendation='Load all resources over HTTPS.',
                        alert_recipient=self._extract_alert_recipient(entry.domain)
                    )
                    self.network_issues.append(issue)

                # Check for self-signed certificates in headers
                headers_text = str(entry.response.headers).lower()
                for pattern_name, pattern_info in self.NETWORK_SECURITY_PATTERNS.items():
                    if 'pattern' in pattern_info and pattern_info.get('category') == 'ssl_tls':
                        pattern = pattern_info['pattern']
                        if re.search(pattern, headers_text, re.IGNORECASE):
                            issue = self._make_network_issue(
                                severity=pattern_info['severity'],
                                category=pattern_info['category'],
                                title=pattern_info['title'],
                                description=pattern_info['description'],
                                domain=entry.domain,
                                entry_index=idx,
                                recommendation=pattern_info['recommendation'],
                                alert_recipient=self._extract_alert_recipient(entry.domain)
                            )
                            self.network_issues.append(issue)

                # Check for insecure domains
                for pattern_name, pattern_info in self.NETWORK_SECURITY_PATTERNS.items():
                    if pattern_name == 'insecure_domain':
                        pattern = pattern_info['pattern']
                        if re.search(pattern, entry.domain, re.IGNORECASE):
                            issue = self._make_network_issue(
                                severity=pattern_info['severity'],
                                category=pattern_info['category'],
                                title=pattern_info['title'],
                                description=pattern_info['description'],
                                domain=entry.domain,
                                entry_index=idx,
                                recommendation=pattern_info['recommendation'],
                                alert_recipient=self._extract_alert_recipient(entry.domain)
                            )
                            self.network_issues.append(issue)

            except (AttributeError, TypeError, ValueError, re.error):
                logger.debug("Skipping malformed HAR entry during network analysis.", exc_info=True)
                continue

        self.network_issues.extend(self._detect_free_internet_services(har_file))
        self.network_issues.extend(self._detect_host_proxy_tls_anomalies(har_file))

        return self.network_issues

    def _extract_alert_recipient(self, domain: str) -> str:
        """
        Extract alert recipient email from domain (common patterns).
        
        Args:
            domain: Domain name
            
        Returns:
            Potential alert recipient email
        """
        # Common patterns for abuse/security contact emails
        common_patterns = [
            f'abuse@{domain}',
            f'security@{domain}',
            f'admin@{domain}',
            f'webmaster@{domain}',
            f'hostmaster@{domain}'
        ]
        return common_patterns[0]  # Return first pattern as default

    def generate_network_alert_report(self, network_issues: List[NetworkIssue]) -> str:
        """
        Generate a network alert report for notifying network administrators.

        Args:
            network_issues: List of NetworkIssue objects

        Returns:
            Formatted alert report string
        """
        if not network_issues:
            return "No network security issues found."

        free_surf_summary = self.summarize_free_internet_issues(network_issues)

        # Group issues by category
        by_category = {}
        for issue in network_issues:
            if issue.category not in by_category:
                by_category[issue.category] = []
            by_category[issue.category].append(issue)

        report_lines = [
            "=" * 80,
            "NETWORK SECURITY ALERT REPORT - FREE SURF & INTERNET GRATOS",
            "=" * 80,
            f"Total Issues: {len(network_issues)}",
            f"Critical: {sum(1 for i in network_issues if i.severity == 'critical')}",
            f"High: {sum(1 for i in network_issues if i.severity == 'high')}",
            f"Medium: {sum(1 for i in network_issues if i.severity == 'medium')}",
            f"Low: {sum(1 for i in network_issues if i.severity == 'low')}",
            f"Free Surf Verdict: {free_surf_summary['verdict']}",
            f"Free Surf Score: {free_surf_summary['max_score']}/100",
            "=" * 80,
            "",
            "ISSUES BY CATEGORY:",
            "-" * 80
        ]

        for category, issues in by_category.items():
            report_lines.extend([
                f"\n📊 {category.upper()}: {len(issues)} issues",
                "-" * 80
            ])
            for issue in issues[:10]:  # Limit to 10 per category
                report_lines.extend([
                    f"\n[{issue.severity.upper()}] {issue.title}",
                    f"Domain: {issue.domain}",
                    f"Description: {issue.description}",
                    f"Confidence: {issue.confidence}",
                    f"Score: {issue.score}/100",
                    f"Indicators: {', '.join(issue.indicators[:4]) if issue.indicators else 'n/a'}",
                    f"Evidence: {issue.evidence or 'n/a'}",
                    f"Recommendation: {issue.recommendation}",
                    f"Alert Recipient: {issue.alert_recipient}"
                ])

        report_lines.extend([
            "",
            "=" * 80,
            "FREE INTERNET SERVICES DETECTED:",
            "-" * 80,
            f"Free Surf/VPN: {len(by_category.get('free_internet', []))} issues",
            f"Free Surf Domains: {free_surf_summary['domains']}",
            f"Free Surf Confidence: {free_surf_summary['confidence']}",
            f"SSL/TLS Issues: {len(by_category.get('ssl_tls', []))} issues",
            f"Domain Issues: {len(by_category.get('domain', []))} issues",
            "=" * 80,
            "",
            "END OF REPORT",
            "=" * 80
        ])

        return "\n".join(report_lines)

    # INMUX Integration - HackerTarget API Methods
    def dns_lookup(self, target: str) -> str:
        """
        Perform DNS lookup using HackerTarget API.

        Args:
            target: Domain or IP address

        Returns:
            DNS lookup results
        """
        try:
            url = self._build_hackertarget_url('dnslookup', target)
            return self._request_hackertarget(url, tool_name='DNS lookup')
        except ValueError as e:
            return f"Error: {str(e)}"

    def reverse_dns_lookup(self, target: str) -> str:
        """
        Perform reverse DNS lookup using HackerTarget API.

        Args:
            target: IP address

        Returns:
            Reverse DNS lookup results
        """
        try:
            url = self._build_hackertarget_url('reversedns', target)
            return self._request_hackertarget(url, tool_name='Reverse DNS lookup')
        except ValueError as e:
            return f"Error: {str(e)}"

    def whois_lookup(self, target: str) -> str:
        """
        Perform Whois lookup using HackerTarget API.

        Args:
            target: Domain or IP address

        Returns:
            Whois lookup results
        """
        try:
            url = self._build_hackertarget_url('whois', target)
            return self._request_hackertarget(url, tool_name='Whois lookup')
        except ValueError as e:
            return f"Error: {str(e)}"

    def geoip_lookup(self, target: str) -> str:
        """
        Perform GeoIP lookup using HackerTarget API.

        Args:
            target: IP address or domain

        Returns:
            GeoIP lookup results
        """
        try:
            url = self._build_hackertarget_url('geoip', target)
            return self._request_hackertarget(url, tool_name='GeoIP lookup')
        except ValueError as e:
            return f"Error: {str(e)}"

    def host_finder(self, target: str) -> str:
        """
        Find subdomains using HackerTarget API.

        Args:
            target: Domain

        Returns:
            Host finder results
        """
        try:
            url = self._build_hackertarget_url('hostsearch', target)
            return self._request_hackertarget(url, tool_name='Host finder')
        except ValueError as e:
            return f"Error: {str(e)}"

    def http_headers(self, target: str) -> str:
        """
        Get HTTP headers using HackerTarget API.

        Args:
            target: Domain or URL

        Returns:
            HTTP headers results
        """
        try:
            url = self._build_hackertarget_url('httpheaders', target)
            return self._request_hackertarget(url, tool_name='HTTP headers lookup')
        except ValueError as e:
            return f"Error: {str(e)}"

    def host_dns_finder(self, target: str) -> str:
        """
        Perform host DNS finder using HackerTarget API.

        Args:
            target: Domain

        Returns:
            Host DNS finder results
        """
        try:
            url = self._build_hackertarget_url('findshareddns', target)
            return self._request_hackertarget(url, tool_name='Shared DNS finder')
        except ValueError as e:
            return f"Error: {str(e)}"

    def port_scan(self, target: str) -> str:
        """
        Perform port scan using HackerTarget API.

        Args:
            target: Domain or IP address

        Returns:
            Port scan results
        """
        try:
            url = self._build_hackertarget_url('nmap', target, require_api_key=True)
            return self._request_hackertarget(url, tool_name='TCP port scan', require_api_key=True)
        except ValueError as e:
            return f"Error: {str(e)}"

    def subnet_lookup(self, target: str) -> str:
        """
        Perform subnet calculation using HackerTarget API.

        Args:
            target: IP address

        Returns:
            Subnet calculation results
        """
        try:
            url = self._build_hackertarget_url('subnetcalc', target)
            return self._request_hackertarget(url, tool_name='Subnet lookup')
        except ValueError as e:
            return f"Error: {str(e)}"

    def zone_transfer(self, target: str) -> str:
        """
        Perform zone transfer using HackerTarget API.

        Args:
            target: Domain

        Returns:
            Zone transfer results
        """
        try:
            url = self._build_hackertarget_url('zonetransfer', target)
            return self._request_hackertarget(url, tool_name='Zone transfer')
        except ValueError as e:
            return f"Error: {str(e)}"

    def extract_links(self, target: str) -> str:
        """
        Extract links from a website using HackerTarget API.

        Args:
            target: Domain or URL

        Returns:
            Extracted links results
        """
        try:
            url = self._build_hackertarget_url('pagelinks', target)
            return self._request_hackertarget(url, tool_name='Link extraction')
        except ValueError as e:
            return f"Error: {str(e)}"

    def active_port_scan(self, target: str) -> str:
        """
        Perform active port scan on a target using HackerTarget API.

        Args:
            target: Domain or IP address

        Returns:
            Port scan results with open/closed ports
        """
        try:
            url = self._build_hackertarget_url('nmap', target, require_api_key=True)
            return self._request_hackertarget(url, tool_name='Active TCP port scan', require_api_key=True)
        except ValueError as e:
            return f"Error: {str(e)}"

    def active_port_scan_african(self, target: str) -> Dict[str, Any]:
        """
        Perform active port scan focused on African-specific ports.

        Args:
            target: Domain or IP address

        Returns:
            Structured port scan results with African context
        """
        try:
            url = self._build_hackertarget_url('nmap', target, require_api_key=True)
            result = self._request_hackertarget(url, tool_name='African-focused port scan', require_api_key=True)
            
            # Parse the result to identify African-specific ports
            lines = result.split('\n') if isinstance(result, str) else []
            african_ports = {}
            standard_ports = {}
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('ERROR') or line.startswith('No open ports'):
                    continue
                
                # Parse port information (format: "PORT STATE SERVICE")
                parts = line.split()
                if len(parts) >= 3:
                    port_str, state, service = parts[0], parts[1], parts[2]
                    try:
                        port_num = int(port_str.split('/')[0])
                        
                        if port_num in self.FREE_SURF_PORT_WEIGHTS:
                            reason, weight, category = self.FREE_SURF_PORT_WEIGHTS[port_num]
                            african_ports[port_num] = {
                                'port': port_num,
                                'state': state,
                                'service': service,
                                'reason': reason,
                                'weight': weight,
                                'category': category,
                                'is_african_specific': category == 'transport' and 'Africa' in reason.lower()
                            }
                        else:
                            standard_ports[port_num] = {
                                'port': port_num,
                                'state': state,
                                'service': service
                            }
                    except (ValueError, IndexError):
                        continue
            
            return {
                'target': target,
                'raw_result': result,
                'african_ports': african_ports,
                'standard_ports': standard_ports,
                'total_african_ports': len(african_ports),
                'total_standard_ports': len(standard_ports),
                'high_risk_ports': [p for p in african_ports.values() if p['weight'] >= 25]
            }
        except Exception as e:
            logger.error("Error during African-focused port scan: %s", e, exc_info=True)
            return {
                'target': target,
                'error': str(e),
                'african_ports': {},
                'standard_ports': {},
                'total_african_ports': 0,
                'total_standard_ports': 0,
                'high_risk_ports': []
            }

    def analyze_security(self, har_file) -> List[SecurityIssue]:
        """
        Perform comprehensive security analysis.
        
        Args:
            har_file: HARFile object
            
        Returns:
            List of SecurityIssue objects
        """
        self.security_issues = []

        for idx, entry in enumerate(har_file.entries):
            self._check_security_headers(entry, idx)
            self._check_cookie_security(entry, idx)
            self._check_https_usage(entry, idx)
            self._check_sensitive_data_in_url(entry, idx)
            self._check_sensitive_data_in_body(entry, idx)
            self._check_vulnerable_versions(entry, idx)
            self._check_authentication_failures(entry, idx)
            self._check_data_leaks(entry, idx)

        return self.security_issues

    def _check_vulnerable_versions(self, entry, idx: int):
        """Check for vulnerable software versions in headers and responses."""
        # Check Server header
        server = entry.response.get_header('Server') or ''
        x_powered_by = entry.response.get_header('X-Powered-By') or ''
        
        headers_to_check = [server, x_powered_by]
        
        for header in headers_to_check:
            header_lower = header.lower()
            
            for software, versions in self.VULNERABLE_VERSIONS.items():
                if software in header_lower:
                    # Extract version number
                    import re
                    version_match = re.search(rf'{software}[/-]?(\d+\.\d+\.?\d*)', header_lower)
                    if version_match:
                        version = version_match.group(1)
                        if version in versions:
                            self.security_issues.append(SecurityIssue(
                                severity='critical',
                                category='vulnerable_component',
                                title=f'Vulnerable {software} Version',
                                description=f'{software} version {version} has known vulnerabilities: {versions[version]}',
                                entry_index=idx,
                                evidence=header,
                                recommendation=f'Update {software} to the latest stable version.'
                            ))

    def _check_authentication_failures(self, entry, idx: int):
        """Check for authentication and authorization failures."""
        # Check for weak authentication mechanisms
        auth_header = entry.request.get_header('Authorization') or ''
        
        # Check for Basic Auth without HTTPS
        if 'Basic' in auth_header and not entry.is_https:
            self.security_issues.append(SecurityIssue(
                severity='critical',
                category='weak_authentication',
                title='Basic Auth over HTTP',
                description='Basic authentication sent over unencrypted HTTP connection.',
                entry_index=idx,
                evidence=auth_header[:20] + '...',
                recommendation='Use HTTPS or implement OAuth2/JWT with proper encryption.'
            ))

        # Check for JWT without proper validation indicators
        if 'Bearer' in auth_header or 'eyJ' in auth_header:
            # Check if JWT has proper expiration (heuristic)
            if len(auth_header) < 50:
                self.security_issues.append(SecurityIssue(
                    severity='medium',
                    category='weak_jwt',
                    title='Suspicious JWT Token',
                    description='JWT token appears malformed or too short.',
                    entry_index=idx,
                    evidence=auth_header[:30] + '...',
                    recommendation='Validate JWT structure and ensure proper expiration claims.'
                ))

        # Check for session IDs in URLs
        if any(keyword in entry.request.url.lower() for keyword in ['sessionid', 'jsessionid', 'phpsessid', 'sid=']):
            self.security_issues.append(SecurityIssue(
                severity='high',
                category='session_fixation',
                title='Session ID in URL',
                description='Session identifier exposed in URL query string.',
                entry_index=idx,
                evidence=entry.request.url,
                recommendation='Store session IDs in HTTP-only cookies only.'
            ))

    def _check_data_leaks(self, entry, idx: int):
        """Check for potential data leaks and PII exposure."""
        # Check response content type for potential data exposure
        content_type = entry.response.get_header('content-type') or ''
        
        # Check if sensitive data is returned in error responses
        if entry.response.status >= 400:
            try:
                body = entry.response.get_decoded_body()
                if body:
                    body_str = body.decode('utf-8', errors='ignore') if isinstance(body, bytes) else str(body)
                    
                    # Check for stack traces
                    if any(keyword in body_str.lower() for keyword in ['stack trace', 'exception', 'error at line', 'traceback']):
                        self.security_issues.append(SecurityIssue(
                            severity='high',
                            category='information_disclosure',
                            title='Stack Trace in Error Response',
                            description='Detailed error information (stack trace) exposed in response.',
                            entry_index=idx,
                            evidence='Stack trace detected',
                            recommendation='Disable detailed error messages in production.'
                        ))

                    # Check for database errors
                    if any(keyword in body_str.lower() for keyword in ['sql syntax', 'mysql error', 'postgresql error', 'oracle error']):
                        self.security_issues.append(SecurityIssue(
                            severity='high',
                            category='information_disclosure',
                            title='Database Error Exposed',
                            description='Database error details exposed in response.',
                            entry_index=idx,
                            evidence='Database error detected',
                            recommendation='Implement proper error handling without exposing database details.'
                        ))

                    # Check for file paths
                    if re.search(r'[A-Z]:\\|/home/|/var/|/etc/|C:\\Windows', body_str):
                        self.security_issues.append(SecurityIssue(
                            severity='medium',
                            category='information_disclosure',
                            title='File Path Exposed',
                            description='Server file paths exposed in response.',
                            entry_index=idx,
                            evidence='File path detected',
                            recommendation='Remove absolute file paths from error messages.'
                        ))
            except (AttributeError, TypeError, UnicodeDecodeError, ValueError):
                logger.debug("Skipping malformed payload during information disclosure checks.", exc_info=True)

    def _check_security_headers(self, entry, idx: int):
        """Check for missing security headers."""
        response_headers = {h['name'].lower(): h['value'] for h in entry.response.headers}

        for header, description in self.SECURITY_HEADERS.items():
            if header.lower() not in response_headers:
                self.security_issues.append(SecurityIssue(
                    severity='medium',
                    category='missing_security_header',
                    title=f'Missing Security Header: {header}',
                    description=f'The response is missing the {header} header. {description}',
                    entry_index=idx,
                    recommendation=f'Add the {header} header to your server configuration.'
                ))

    def _check_cookie_security(self, entry, idx: int):
        """Check cookie security attributes."""
        for cookie in entry.response.cookies:
            issues = []

            if not cookie.get('secure', False) and entry.is_https:
                issues.append('missing Secure flag')

            if not cookie.get('httpOnly', False):
                issues.append('missing HttpOnly flag')

            if cookie.get('sameSite') not in ['Strict', 'Lax']:
                issues.append('missing or weak SameSite attribute')

            if issues:
                self.security_issues.append(SecurityIssue(
                    severity='high',
                    category='insecure_cookie',
                    title=f'Insecure Cookie: {cookie.get("name", "unknown")}',
                    description=f'Cookie has security issues: {", ".join(issues)}',
                    entry_index=idx,
                    evidence=cookie.get('name', ''),
                    recommendation='Set Secure, HttpOnly, and SameSite attributes on cookies.'
                ))

    def _check_https_usage(self, entry, idx: int):
        """Check for HTTP usage instead of HTTPS."""
        if not entry.is_https:
            self.security_issues.append(SecurityIssue(
                severity='high',
                category='insecure_protocol',
                title='Insecure HTTP Request',
                description='Request is using HTTP instead of HTTPS.',
                entry_index=idx,
                evidence=entry.request.url,
                recommendation='Use HTTPS for all requests to prevent data interception.'
            ))

    def _check_sensitive_data_in_url(self, entry, idx: int):
        """Check for sensitive data in URLs."""
        parsed = urlparse(entry.request.url)
        query_params = parse_qs(parsed.query)

        sensitive_params = ['password', 'token', 'api_key', 'secret', 'credit_card', 'ssn']
        
        for param in sensitive_params:
            if param.lower() in [p.lower() for p in query_params.keys()]:
                self.security_issues.append(SecurityIssue(
                    severity='critical',
                    category='sensitive_data_in_url',
                    title=f'Sensitive Data in URL: {param}',
                    description=f'Sensitive parameter "{param}" found in URL query string.',
                    entry_index=idx,
                    evidence=parsed.query,
                    recommendation='Move sensitive data to request body or use proper authentication headers.'
                ))

    def _check_sensitive_data_in_body(self, entry, idx: int):
        """Check for sensitive data in request/response bodies."""
        try:
            # Check request body
            if entry.request.post_data and 'text' in entry.request.post_data:
                self._detect_patterns(entry.request.post_data['text'], idx, 'request_body')

            # Check response body
            if entry.response.content and 'text' in entry.response.content:
                self._detect_patterns(entry.response.content['text'], idx, 'response_body')
        except (AttributeError, TypeError, KeyError):
            logger.debug("Skipping malformed request or response body during sensitive-data checks.", exc_info=True)

    def analyze_performance(self, har_file) -> List[PerformanceIssue]:
        """
        Perform comprehensive performance analysis.
        
        Args:
            har_file: HARFile object
            
        Returns:
            List of PerformanceIssue objects
        """
        self.performance_issues = []

        for idx, entry in enumerate(har_file.entries):
            self._check_request_timing(entry, idx)
            self._check_response_size(entry, idx)
            self._check_network_timing(entry, idx)

        # Check overall patterns
        self._check_duplicate_requests(har_file)
        self._check_chained_requests(har_file)

        return self.performance_issues

    def _check_request_timing(self, entry, idx: int):
        """Check for slow requests."""
        if entry.time > self.PERFORMANCE_THRESHOLDS['very_slow_request']:
            self.performance_issues.append(PerformanceIssue(
                severity='critical',
                category='slow_request',
                title='Very Slow Request',
                description=f'Request took {entry.time:.2f}ms to complete.',
                entry_index=idx,
                value=entry.time,
                threshold=self.PERFORMANCE_THRESHOLDS['very_slow_request'],
                recommendation='Optimize server-side processing or consider caching.'
            ))
        elif entry.time > self.PERFORMANCE_THRESHOLDS['slow_request']:
            self.performance_issues.append(PerformanceIssue(
                severity='medium',
                category='slow_request',
                title='Slow Request',
                description=f'Request took {entry.time:.2f}ms to complete.',
                entry_index=idx,
                value=entry.time,
                threshold=self.PERFORMANCE_THRESHOLDS['slow_request'],
                recommendation='Consider optimizing this endpoint.'
            ))

    def _check_response_size(self, entry, idx: int):
        """Check for large responses."""
        size = entry.response.body_size
        if size > self.PERFORMANCE_THRESHOLDS['very_large_response']:
            self.performance_issues.append(PerformanceIssue(
                severity='high',
                category='large_response',
                title='Very Large Response',
                description=f'Response size is {size / 1024 / 1024:.2f}MB.',
                entry_index=idx,
                value=size,
                threshold=self.PERFORMANCE_THRESHOLDS['very_large_response'],
                recommendation='Consider compression, pagination, or reducing payload size.'
            ))
        elif size > self.PERFORMANCE_THRESHOLDS['large_response']:
            self.performance_issues.append(PerformanceIssue(
                severity='medium',
                category='large_response',
                title='Large Response',
                description=f'Response size is {size / 1024:.2f}KB.',
                entry_index=idx,
                value=size,
                threshold=self.PERFORMANCE_THRESHOLDS['large_response'],
                recommendation='Consider response compression.'
            ))

    def _check_network_timing(self, entry, idx: int):
        """Check network timing issues."""
        timing = entry.timing

        if timing.dns > self.PERFORMANCE_THRESHOLDS['slow_dns']:
            self.performance_issues.append(PerformanceIssue(
                severity='medium',
                category='slow_dns',
                title='Slow DNS Resolution',
                description=f'DNS resolution took {timing.dns:.2f}ms.',
                entry_index=idx,
                value=timing.dns,
                threshold=self.PERFORMANCE_THRESHOLDS['slow_dns'],
                recommendation='Check DNS configuration or consider using a faster DNS server.'
            ))

        if timing.connect > self.PERFORMANCE_THRESHOLDS['slow_connect']:
            self.performance_issues.append(PerformanceIssue(
                severity='medium',
                category='slow_connect',
                title='Slow Connection',
                description=f'TCP connection took {timing.connect:.2f}ms.',
                entry_index=idx,
                value=timing.connect,
                threshold=self.PERFORMANCE_THRESHOLDS['slow_connect'],
                recommendation='Check network latency or server response time.'
            ))

        if timing.ssl > self.PERFORMANCE_THRESHOLDS['slow_ssl']:
            self.performance_issues.append(PerformanceIssue(
                severity='medium',
                category='slow_ssl',
                title='Slow SSL Handshake',
                description=f'SSL handshake took {timing.ssl:.2f}ms.',
                entry_index=idx,
                value=timing.ssl,
                threshold=self.PERFORMANCE_THRESHOLDS['slow_ssl'],
                recommendation='Optimize SSL/TLS configuration or consider HTTP/2.'
            ))

        if timing.wait > self.PERFORMANCE_THRESHOLDS['slow_ttfb']:
            self.performance_issues.append(PerformanceIssue(
                severity='high',
                category='slow_ttfb',
                title='Slow Time to First Byte (TTFB)',
                description=f'TTFB took {timing.wait:.2f}ms.',
                entry_index=idx,
                value=timing.wait,
                threshold=self.PERFORMANCE_THRESHOLDS['slow_ttfb'],
                recommendation='Optimize server-side processing and database queries.'
            ))

    def _check_duplicate_requests(self, har_file):
        """Check for duplicate requests to the same endpoint."""
        url_counter = Counter()
        for entry in har_file.entries:
            url_counter[entry.request.url] += 1

        for url, count in url_counter.items():
            if count > 3:
                self.performance_issues.append(PerformanceIssue(
                    severity='medium',
                    category='duplicate_requests',
                    title=f'Duplicate Requests: {count} times',
                    description=f'The same URL was requested {count} times.',
                    evidence=url,
                    recommendation='Consider caching or batching duplicate requests.'
                ))

    def _check_chained_requests(self, har_file):
        """Check for request chaining dependencies."""
        # Simple heuristic: sequential requests to same domain
        domain_sequences = defaultdict(list)
        
        for idx, entry in enumerate(har_file.entries):
            domain_sequences[entry.domain].append(idx)

        for domain, indices in domain_sequences.items():
            if len(indices) > 5:
                # Check if they're sequential (potential waterfall issue)
                sequential = True
                for i in range(1, len(indices)):
                    if indices[i] != indices[i-1] + 1:
                        sequential = False
                        break
                
                if sequential:
                    self.performance_issues.append(PerformanceIssue(
                        severity='low',
                        category='request_chaining',
                        title='Sequential Request Chain',
                        description=f'{len(indices)} sequential requests to {domain}.',
                        evidence=domain,
                        recommendation='Consider parallelizing independent requests.'
                    ))

    def detect_patterns(self, har_file, patterns: Optional[Dict[str, str]] = None) -> List[PatternMatch]:
        """
        Detect suspicious patterns in HAR file.
        
        Args:
            har_file: HARFile object
            patterns: Optional custom patterns dictionary
            
        Returns:
            List of PatternMatch objects
        """
        self.pattern_matches = []
        pattern_dict = patterns or self.SUSPICIOUS_PATTERNS

        for idx, entry in enumerate(har_file.entries):
            # Check URL
            self._detect_patterns(entry.request.url, idx, 'url', pattern_dict)

            # Check headers
            for header in entry.request.headers:
                self._detect_patterns(header['value'], idx, f'header_{header["name"]}', pattern_dict)

            # Check body
            if entry.request.post_data and 'text' in entry.request.post_data:
                self._detect_patterns(entry.request.post_data['text'], idx, 'request_body', pattern_dict)

            # Check response
            if entry.response.content and 'text' in entry.response.content:
                self._detect_patterns(entry.response.content['text'], idx, 'response_body', pattern_dict)

        return self.pattern_matches

    def _detect_patterns(self, text: str, idx: int, context: str, patterns: Dict[str, str]) -> None:
        """Detect patterns in text."""
        if not text or not isinstance(text, str):
            return

        for pattern_name, pattern_regex in patterns.items():
            try:
                matches = re.finditer(pattern_regex, text, re.IGNORECASE)
                for match in matches:
                    matched_text = match.group(0)
                    # Limit matched text length
                    if len(matched_text) > 100:
                        matched_text = matched_text[:100] + '...'

                    self.pattern_matches.append(PatternMatch(
                        pattern_type=pattern_name,
                        description=f'Potential {pattern_name} detected',
                        entry_index=idx,
                        matched_text=matched_text,
                        context=context
                    ))
            except re.error:
                # Invalid regex, skip
                pass

    def compare_har_files(self, har_file1, har_file2) -> Dict[str, Any]:
        """
        Compare two HAR files and find differences.
        
        Args:
            har_file1: First HARFile object
            har_file2: Second HARFile object
            
        Returns:
            Dictionary containing comparison results
        """
        comparison = {
            'summary': {
                'file1_entries': len(har_file1.entries),
                'file2_entries': len(har_file2.entries),
                'entries_difference': len(har_file2.entries) - len(har_file1.entries)
            },
            'domains': {
                'only_in_file1': list(set(e.domain for e in har_file1.entries) - 
                                     set(e.domain for e in har_file2.entries)),
                'only_in_file2': list(set(e.domain for e in har_file2.entries) - 
                                     set(e.domain for e in har_file1.entries)),
                'common': list(set(e.domain for e in har_file1.entries) & 
                              set(e.domain for e in har_file2.entries))
            },
            'performance': {
                'file1_avg_time': sum(e.time for e in har_file1.entries) / len(har_file1.entries) if har_file1.entries else 0,
                'file2_avg_time': sum(e.time for e in har_file2.entries) / len(har_file2.entries) if har_file2.entries else 0,
                'time_difference': 0
            },
            'new_entries': [],
            'removed_entries': []
        }

        comparison['performance']['time_difference'] = (
            comparison['performance']['file2_avg_time'] - 
            comparison['performance']['file1_avg_time']
        )

        # Find new and removed URLs
        urls1 = {e.request.url for e in har_file1.entries}
        urls2 = {e.request.url for e in har_file2.entries}

        comparison['new_entries'] = list(urls2 - urls1)
        comparison['removed_entries'] = list(urls1 - urls2)

        return comparison

    def search(self, har_file, query: str, search_type: str = 'url') -> List[int]:
        """
        Search for entries matching a query.
        
        Args:
            har_file: HARFile object
            query: Search query
            search_type: Type of search ('url', 'method', 'header', 'body', 'all')
            
        Returns:
            List of entry indices matching the query
        """
        matches = []
        query_lower = query.lower()

        for idx, entry in enumerate(har_file.entries):
            match = False

            if search_type in ['url', 'all']:
                if query_lower in entry.request.url.lower():
                    match = True

            if not match and search_type in ['method', 'all']:
                if query_lower in entry.request.method.lower():
                    match = True

            if not match and search_type in ['header', 'all']:
                for header in entry.request.headers + entry.response.headers:
                    if query_lower in header['name'].lower() or query_lower in header['value'].lower():
                        match = True
                        break

            if not match and search_type in ['body', 'all']:
                if entry.request.post_data and 'text' in entry.request.post_data:
                    if query_lower in str(entry.request.post_data['text']).lower():
                        match = True
                if not match and entry.response.content and 'text' in entry.response.content:
                    if query_lower in str(entry.response.content['text']).lower():
                        match = True

            if match:
                matches.append(idx)

        return matches

    def generate_report(self, har_file) -> Dict[str, Any]:
        """
        Generate a comprehensive analysis report.
        
        Args:
            har_file: HARFile object
            
        Returns:
            Dictionary containing complete analysis report
        """
        security_issues = self.analyze_security(har_file)
        performance_issues = self.analyze_performance(har_file)
        pattern_matches = self.detect_patterns(har_file)

        # Count issues by severity
        security_by_severity = Counter(i.severity for i in security_issues)
        performance_by_severity = Counter(i.severity for i in performance_issues)

        # Calculate security score (0-100)
        security_score = self._calculate_security_score(security_issues, len(har_file.entries))

        return {
            'security': {
                'total_issues': len(security_issues),
                'score': security_score,
                'grade': self._get_security_grade(security_score),
                'by_severity': dict(security_by_severity),
                'by_category': Counter(i.category for i in security_issues),
                'owasp_mapping': self._map_to_owasp(security_issues),
                'issues': [
                    {
                        'severity': i.severity,
                        'category': i.category,
                        'title': i.title,
                        'description': i.description,
                        'entry_index': i.entry_index,
                        'recommendation': i.recommendation
                    }
                    for i in security_issues
                ]
            },
            'performance': {
                'total_issues': len(performance_issues),
                'by_severity': dict(performance_by_severity),
                'issues': [
                    {
                        'severity': i.severity,
                        'category': i.category,
                        'title': i.title,
                        'description': i.description,
                        'entry_index': i.entry_index,
                        'value': i.value,
                        'recommendation': i.recommendation
                    }
                    for i in performance_issues
                ]
            },
            'patterns': {
                'total_matches': len(pattern_matches),
                'by_type': Counter(m.pattern_type for m in pattern_matches),
                'matches': [
                    {
                        'pattern_type': m.pattern_type,
                        'description': m.description,
                        'entry_index': m.entry_index,
                        'matched_text': m.matched_text,
                        'context': m.context
                    }
                    for m in pattern_matches[:100]  # Limit to 100
                ]
            }
        }

    def _calculate_security_score(self, security_issues: List[SecurityIssue], total_entries: int) -> int:
        """
        Calculate security score (0-100) based on detected issues.
        
        Args:
            security_issues: List of security issues
            total_entries: Total number of HAR entries
            
        Returns:
            Security score (0-100)
        """
        if total_entries == 0:
            return 0

        # Base score
        score = 100

        # Deduct points based on severity
        severity_weights = {
            'critical': 25,
            'high': 15,
            'medium': 8,
            'low': 3,
            'info': 1
        }

        for issue in security_issues:
            weight = severity_weights.get(issue.severity, 5)
            score -= weight

        # Normalize score (minimum 0)
        score = max(0, score)

        # Adjust based on entry count (more entries = more tolerance)
        if total_entries > 100:
            # Reduce penalty for large HAR files
            penalty_reduction = min(20, (total_entries - 100) // 10)
            score = min(100, score + penalty_reduction)

        return int(score)

    def _get_security_grade(self, score: int) -> str:
        """
        Get security grade based on score.
        
        Args:
            score: Security score (0-100)
            
        Returns:
            Grade letter (A-F)
        """
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        elif score >= 50:
            return 'E'
        else:
            return 'F'

    def _map_to_owasp(self, security_issues: List[SecurityIssue]) -> Dict[str, int]:
        """
        Map security issues to OWASP Top 10 categories.
        
        Args:
            security_issues: List of security issues
            
        Returns:
            Dictionary mapping OWASP categories to issue counts
        """
        owasp_mapping = {
            'A01:2021-Broken Access Control': 0,
            'A02:2021-Cryptographic Failures': 0,
            'A03:2021-Injection': 0,
            'A04:2021-Insecure Design': 0,
            'A05:2021-Security Misconfiguration': 0,
            'A06:2021-Vulnerable and Outdated Components': 0,
            'A07:2021-Identification and Authentication Failures': 0,
            'A08:2021-Software and Data Integrity Failures': 0,
            'A09:2021-Security Logging and Monitoring Failures': 0,
            'A10:2021-Server-Side Request Forgery': 0
        }

        # Simple heuristic mapping based on category
        for issue in security_issues:
            category = issue.category.lower()
            
            if 'access' in category or 'session' in category or 'auth' in category:
                owasp_mapping['A01:2021-Broken Access Control'] += 1
                owasp_mapping['A07:2021-Identification and Authentication Failures'] += 1
            elif 'cryptographic' in category or 'ssl' in category or 'tls' in category or 'password' in category:
                owasp_mapping['A02:2021-Cryptographic Failures'] += 1
            elif 'injection' in category or 'sql' in category or 'xss' in category or 'path' in category:
                owasp_mapping['A03:2021-Injection'] += 1
            elif 'header' in category or 'config' in category or 'debug' in category:
                owasp_mapping['A05:2021-Security Misconfiguration'] += 1
            elif 'vulnerable' in category or 'component' in category or 'version' in category:
                owasp_mapping['A06:2021-Vulnerable and Outdated Components'] += 1
            elif 'information' in category or 'disclosure' in category or 'leak' in category:
                owasp_mapping['A09:2021-Security Logging and Monitoring Failures'] += 1
            elif 'ssrf' in category:
                owasp_mapping['A10:2021-Server-Side Request Forgery'] += 1

        return owasp_mapping
