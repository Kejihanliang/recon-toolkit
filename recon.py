#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Penetration Testing Reconnaissance Toolkit
Version: 1.0
Author: Security Tools Lab

Usage:
    python recon.py --target example.com --full --export json
"""

import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import argparse
import asyncio
import csv
import concurrent.futures
import json
import os
import socket
import time
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[!] requests library not found. Install with: pip install requests")

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = True
    class Fore:
        RED = WHITE = GREEN = YELLOW = CYAN = MAGENTA = BLUE = ''
    class Style:
        RESET_ALL = BRIGHT = ''

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
TIMEOUT = 10

BANNER = """
======================================================
   [RECON TOOLKIT v1.0]
   Automated Reconnaissance for Security Testers
======================================================
"""

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
             1723, 3306, 3389, 5900, 8080, 8443, 8888, 10000]

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns", "webdisk",
    "ns1", "dns", "news", "pop3", "dev", "www2", "admin", "forum", "news",
    "new", "images", "img", "www1", "intranet", "portal", "spam", "mirrors",
    "gateway", "secure", "api", "cdn", "blog", "staging", "shop", "pay",
    "vpn", "doc", "docs", "support", "status", "home", "office", "remote", "ssh"
]

CORS_DANGEROUS_PATTERNS = ["*", "null", "https://null"]

WAF_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "aws": "AWS WAF",
    "imperva": "Imperva",
    "incapsula": "Incapsula",
    "modsecurity": "ModSecurity",
    "f5": "F5 ASM",
    "fortiweb": "FortiWeb",
    "palo alto": "Palo Alto",
    "sucuri": "Sucuri"
}

CMS_SIGNATURES = {
    "wp-content": "WordPress",
    "wp-includes": "WordPress",
    "joomla": "Joomla",
    "drupal": "Drupal",
    "magento": "Magento",
    "shopify": "Shopify",
    "prestashop": "PrestaShop",
    "opencart": "OpenCart",
    "wp-json": "WordPress"
}

C = Fore
S = Style

def log(level, message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    symbols = {"info": "[*]", "success": "[+]", "warning": "[!]", "error": "[-]", "scan": "[~]"}
    colors = {"info": C.CYAN, "success": C.GREEN, "warning": C.YELLOW, "error": C.RED, "scan": C.BLUE}
    print(f"{colors.get(level, C.WHITE)}{symbols.get(level, '[-]')} {C.RESET}{message}")


class ReconToolkit:
    def __init__(self, target, output_dir="results"):
        self.target = target
        self.domain = self._extract_domain(target)
        self.output_dir = output_dir
        self.results = {
            "target": self.domain,
            "timestamp": datetime.now().isoformat(),
            "subdomains": [],
            "ports": [],
            "web_tech": {},
            "cors": [],
            "waf": None,
            "cms": None
        }
        os.makedirs(output_dir, exist_ok=True)

    def _extract_domain(self, target):
        if target.startswith(("http://", "https://")):
            return urlparse(target).netloc.split(":")[0].split("/")[0]
        return target.split(":")[0].split("/")[0]

    def enumerate_subdomains(self):
        log("info", f"Starting subdomain enumeration for {self.domain}")
        found = set()
        
        log("scan", "Checking common subdomains...")
        for sub in SUBDOMAIN_WORDLIST:
            subdomain = f"{sub}.{self.domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                found.add(subdomain)
                log("success", f"Found: {subdomain} -> {ip}")
            except socket.gaierror:
                pass
        
        if DNS_AVAILABLE:
            srv_services = ["_sip._tcp", "_ldap._tcp", "_kerberos._tcp", "_http._tcp"]
            log("scan", "Checking SRV records...")
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 5
            for srv in srv_services:
                try:
                    answers = resolver.resolve(f"{srv}.{self.domain}", 'SRV')
                    for answer in answers:
                        target = str(answer.target).rstrip('.')
                        found.add(target)
                        log("success", f"SRV: {srv}.{self.domain} -> {target}")
                except:
                    pass
        
        self.results["subdomains"] = list(found)
        log("success", f"Subdomain enum complete. Found {len(found)} subdomains.")
        return found

    def scan_ports(self, ports=None):
        if ports is None:
            ports = TOP_PORTS
        
        try:
            target_ip = socket.gethostbyname(self.domain)
        except:
            log("error", f"Cannot resolve {self.domain}")
            return []
        
        log("info", f"Starting port scan on {target_ip} ({len(ports)} ports)")
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                if result == 0:
                    service = self._identify_service(port)
                    return (port, service)
            except:
                pass
            return None
        
        log("scan", "Scanning ports...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(check_port, ports)
            for result in results:
                if result:
                    open_ports.append({"port": result[0], "service": result[1]})
                    log("success", f"Open port: {result[0]} ({result[1]})")
        
        self.results["ports"] = open_ports
        log("success", f"Port scan complete. Found {len(open_ports)} open ports.")
        return open_ports

    def _identify_service(self, port):
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
            995: "POP3S", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
            5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
            8888: "HTTP-Alt", 10000: "Webmin"
        }
        return services.get(port, "Unknown")

    def analyze_web(self):
        if not REQUESTS_AVAILABLE:
            log("error", "requests library required for web analysis")
            return
        
        log("info", f"Analyzing web technology for {self.domain}")
        base_urls = [f"http://{self.domain}", f"https://{self.domain}"]
        
        for base_url in base_urls:
            try:
                resp = requests.get(base_url, timeout=TIMEOUT, verify=False, 
                                  allow_redirects=True, headers={"User-Agent": USER_AGENT})
                
                content = resp.text.lower()
                for pattern, cms in CMS_SIGNATURES.items():
                    if pattern in content:
                        self.results["cms"] = cms
                        log("success", f"CMS Detected: {cms}")
                
                headers_str = str(resp.headers).lower()
                for sig, waf_name in WAF_SIGNATURES.items():
                    if sig in headers_str:
                        self.results["waf"] = waf_name
                        log("warning", f"WAF Detected: {waf_name}")
                
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao:
                    is_dangerous = acao in CORS_DANGEROUS_PATTERNS or acao == "*"
                    if is_dangerous or acac.lower() == "true":
                        log("error", f"CORS Misconfiguration: ACAO={acao}, ACAC={acac}")
                        self.results["cors"].append({
                            "url": base_url,
                            "ACAO": acao,
                            "ACAC": acac,
                            "risk": "HIGH" if (is_dangerous and acac.lower() == "true") else "MEDIUM"
                        })
                
                server = resp.headers.get("Server", "Unknown")
                self.results["web_tech"]["server"] = server
                log("success", f"Server: {server}")
                self.results["web_tech"]["status_code"] = resp.status_code
                
            except Exception as e:
                log("warning", f"Failed to analyze {base_url}: {e}")

    def export(self, format="json"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/{self.domain}_{timestamp}"
        
        if format == "json":
            filepath = f"{filename}.json"
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            log("success", f"Results saved to {filepath}")
        
        elif format == "csv":
            filepath = f"{filename}_subdomains.csv"
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                if self.results["subdomains"]:
                    writer = csv.writer(f)
                    writer.writerow(["Subdomain"])
                    for sub in self.results["subdomains"]:
                        writer.writerow([sub])
            log("success", f"Subdomains saved to {filepath}")
            
            filepath = f"{filename}_ports.csv"
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                if self.results["ports"]:
                    writer = csv.writer(f)
                    writer.writerow(["Port", "Service"])
                    for p in self.results["ports"]:
                        writer.writerow([p["port"], p["service"]])
            log("success", f"Ports saved to {filepath}")
        
        elif format == "txt":
            filepath = f"{filename}.txt"
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(f"Reconnaissance Results for {self.domain}\n")
                f.write(f"Timestamp: {self.results['timestamp']}\n")
                f.write("=" * 50 + "\n\n")
                f.write("SUBDOMAINS:\n")
                for sub in self.results["subdomains"]:
                    f.write(f"  - {sub}\n")
                f.write("\nOPEN PORTS:\n")
                for p in self.results["ports"]:
                    f.write(f"  - {p['port']} ({p['service']})\n")
                f.write(f"\nCMS: {self.results.get('cms', 'N/A')}\n")
                f.write(f"WAF: {self.results.get('waf', 'N/A')}\n")
                if self.results.get("cors"):
                    f.write("\nCORS FINDINGS:\n")
                    for c in self.results["cors"]:
                        f.write(f"  - {c['url']}: {c['risk']} risk\n")
            log("success", f"Results saved to {filepath}")
        
        return filepath

    def run(self, modules=None, export_format="json"):
        print(BANNER)
        
        log("info", f"Target: {self.domain}")
        log("info", f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
        if modules is None or "subdomains" in modules:
            self.enumerate_subdomains()
        
        if modules is None or "ports" in modules:
            self.scan_ports()
        
        if modules is None or "web" in modules:
            self.analyze_web()
        
        print()
        log("info", "=" * 50)
        log("info", "RECON COMPLETE")
        log("info", f"Found {len(self.results['subdomains'])} subdomains")
        log("info", f"Found {len(self.results['ports'])} open ports")
        if self.results.get("cms"):
            log("info", f"Detected CMS: {self.results['cms']}")
        if self.results.get("waf"):
            log("info", f"Detected WAF: {self.results['waf']}")
        if self.results.get("cors"):
            log("warning", f"Found {len(self.results['cors'])} CORS issues")
        
        self.export(export_format)
        
        return self.results


def main():
    parser = argparse.ArgumentParser(description="Penetration Testing Recon Toolkit v1.0")
    parser.add_argument("--target", "-t", required=True, help="Target domain or URL")
    parser.add_argument("--subdomains", "-s", action="store_true", help="Run subdomain enumeration only")
    parser.add_argument("--ports", "-p", action="store_true", help="Run port scan only")
    parser.add_argument("--web", "-w", action="store_true", help="Run web analysis only")
    parser.add_argument("--full", "-f", action="store_true", help="Run all modules")
    parser.add_argument("--export", "-e", choices=["json", "csv", "txt"], default="json", 
                       help="Export format (default: json)")
    parser.add_argument("--output", "-o", default="results", help="Output directory (default: results)")
    
    args = parser.parse_args()
    
    modules = []
    if args.subdomains:
        modules.append("subdomains")
    if args.ports:
        modules.append("ports")
    if args.web:
        modules.append("web")
    if args.full:
        modules = None
    
    toolkit = ReconToolkit(args.target, args.output)
    results = toolkit.run(modules=modules, export_format=args.export)
    
    print("\nDone!")
    return results


if __name__ == "__main__":
    main()
