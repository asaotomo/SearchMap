#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse, urlunparse

import colorama
import dns.exception
import dns.resolver
import requests
import whois
from requests.adapters import HTTPAdapter
from tqdm import tqdm


requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

VERSION = "1.2.0"
LAST_UPDATED = "2026.05.25"

DEFAULT_RESOLVERS = {
    "Google": "8.8.8.8",
    "Cloudflare": "1.1.1.1",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
    "AliDNS": "223.5.5.5",
    "DNSPod": "119.29.29.29",
    "NTT": "129.250.35.250",
    "CleanBrowsing": "185.228.168.9",
}

DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA")

FAST_PORTS = (
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
    79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
    465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
    646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
    1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
    2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
    6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
    9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
)

HIGH_VALUE_PORTS = (
    1, 3, 5, 17, 19, 20, 24, 49, 69, 70, 82, 83, 84, 85, 89, 90, 99,
    109, 115, 118, 123, 137, 138, 161, 162, 177, 194, 264, 280, 311,
    389, 406, 407, 416, 417, 443, 445, 500, 512, 593, 623, 625, 636,
    666, 691, 700, 705, 711, 714, 720, 722, 749, 765, 777, 783, 787,
    800, 801, 808, 843, 880, 888, 898, 900, 901, 902, 903, 981, 987,
    992, 993, 995, 999, 1000, 1024, 1025, 1026, 1027, 1028, 1029, 1030,
    1031, 1032, 1033, 1034, 1035, 1080, 1099, 11211, 1194, 1214, 1241,
    1311, 1352, 1433, 1434, 1521, 1583, 1720, 1723, 1883, 1900, 2049,
    2082, 2083, 2086, 2087, 2095, 2096, 2181, 2375, 2376, 2483, 2484,
    2601, 2604, 3000, 3001, 3306, 3389, 3690, 4369, 4443, 4567, 5000,
    5001, 5005, 5009, 5044, 5060, 5061, 5432, 5601, 5672, 5900, 5901,
    5984, 5985, 5986, 6000, 6379, 6443, 6666, 6667, 7001, 7002, 7070,
    7199, 7474, 7547, 7676, 7777, 8000, 8001, 8008, 8009, 8010, 8069,
    8080, 8081, 8082, 8083, 8086, 8088, 8090, 8091, 8098, 8123, 8161,
    8200, 8222, 8333, 8443, 8500, 8530, 8531, 8834, 8880, 8888, 8983,
    9000, 9001, 9042, 9090, 9091, 9200, 9300, 9418, 9443, 9600, 9999,
    10000, 10250, 10255, 27017, 27018, 28017, 32768, 49152, 49153, 49154,
    49155, 49156, 49157,
)

SMART_PORTS = tuple(sorted(set(FAST_PORTS) | set(HIGH_VALUE_PORTS)))
COMMON_PORTS = tuple(sorted(set(range(1, 1025)) | set(HIGH_VALUE_PORTS)))

WEB_PORTS = {
    80, 81, 82, 83, 84, 85, 88, 89, 90, 443, 591, 593, 800, 801, 808,
    880, 888, 981, 1311, 2082, 2083, 2086, 2087, 2095, 2096, 3000, 3001,
    4567, 5000, 5001, 5601, 5984, 7001, 7002, 7070, 7474, 7547, 8000,
    8001, 8008, 8009, 8010, 8069, 8080, 8081, 8082, 8083, 8086, 8088,
    8090, 8091, 8123, 8161, 8200, 8333, 8443, 8500, 8834, 8880, 8888,
    8983, 9000, 9001, 9090, 9091, 9200, 9443, 10000,
}
TLS_PORTS = {443, 465, 563, 587, 636, 853, 989, 990, 992, 993, 995, 2083, 2087, 2096, 2376, 4443, 5001, 5986, 6443, 8443, 8834, 9443}
INTERESTING_DIR_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405}
DEFAULT_DIR_EXTENSIONS = ("php", "asp", "aspx", "jsp", "jspx", "do", "action", "html", "htm", "js", "json", "txt", "bak", "zip")
DEFAULT_MAX_BODY = 65536

SMART_DIR_SEEDS = (
    "robots.txt", "sitemap.xml", ".well-known/security.txt", ".git/HEAD",
    ".env", ".env.local", ".env.production", ".svn/entries", "WEB-INF/web.xml",
    "swagger-ui/", "swagger.json", "api-docs", "v2/api-docs", "v3/api-docs",
    "openapi.json", "graphql", "graphiql", "actuator", "actuator/health",
    "server-status", "phpinfo.php", "info.php", "admin", "admin/", "login",
    "login/", "manager/html", "jolokia", "console", "wp-login.php",
    "wp-admin/", "phpmyadmin/", "pma/", "backup", "backup/", "db.sql",
    "dump.sql", "config.php.bak", "config.yml", "config.json",
)

BACKUP_SUFFIXES = (".bak", ".old", ".orig", ".save", ".swp", "~", ".zip", ".tar.gz")
RECURSIVE_DIR_WORDS = (
    "admin", "login", "upload", "uploads", "backup", "api", "config",
    "assets", "static", "files", "manager", "console", "debug",
)

BANNER_HINTS = (
    (r"^SSH-([\w.-]+)", "ssh", "SSH"),
    (r"(?i)^220.*ftp", "ftp", "FTP"),
    (r"(?i)^220.*smtp", "smtp", "SMTP"),
    (r"(?i)mysql_native_password|mariadb", "mysql", "MySQL/MariaDB"),
    (r"(?i)postgresql", "postgresql", "PostgreSQL"),
    (r"(?i)^\+PONG|^-NOAUTH", "redis", "Redis"),
    (r"(?i)mongodb", "mongodb", "MongoDB"),
    (r"(?i)memcached", "memcached", "Memcached"),
    (r"(?i)elasticsearch", "elasticsearch", "Elasticsearch"),
    (r"(?i)HTTP/\d", "http", "HTTP"),
)

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

CDN_HINTS = (
    "akamai", "alicdn", "azureedge", "baiduyun", "cachefly", "cdn",
    "cloudflare", "cloudfront", "dnsv1", "edgecast", "edgekey",
    "edgesuite", "fastly", "incapdns", "kunlun", "qiniu", "tcdn",
    "tencent", "yunjiasu",
)

COMMON_MULTI_PART_SUFFIXES = {
    "ac.cn", "ah.cn", "bj.cn", "com.cn", "cq.cn", "edu.cn", "fj.cn",
    "gd.cn", "gov.cn", "gs.cn", "gx.cn", "gz.cn", "ha.cn", "hb.cn",
    "he.cn", "hi.cn", "hk.cn", "hl.cn", "hn.cn", "jl.cn", "js.cn",
    "jx.cn", "ln.cn", "mo.cn", "net.cn", "nm.cn", "nx.cn", "org.cn",
    "qh.cn", "sc.cn", "sd.cn", "sh.cn", "sn.cn", "sx.cn", "tj.cn",
    "tw.cn", "xj.cn", "xz.cn", "yn.cn", "zj.cn", "co.jp", "ne.jp",
    "or.jp", "ac.jp", "go.jp", "co.kr", "ne.kr", "or.kr", "re.kr",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "com.au",
    "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz",
}


def banner():
    colorama.init(autoreset=True)
    print(colorama.Fore.CYAN + rf"""
 ____                      _     __  __
/ ___|  ___  __ _ _ __ ___| |__ |  \/  | __ _ _ __
\___ \ / _ \/ _` | '__/ __| '_ \| |\/| |/ _` | '_ \
 ___) |  __/ (_| | | | (__| | | | |  | | (_| | |_) |
|____/ \___|\__,_|_|  \___|_| |_|_|  |_|\__,_| .__/
                                             |_|    V{VERSION}
    """)
    print(colorama.Fore.GREEN + "# Coded by Asaotomo")
    print(colorama.Fore.GREEN + f"# Last Updated: {LAST_UPDATED}")
    print(colorama.Fore.YELLOW + "# Pure Python reconnaissance, no nmap or third-party data API required")


class Logger(object):
    """将输出同时打印到控制台和文件，并在日志中移除 ANSI 颜色控制符。"""

    def __init__(self, filename="Default.log"):
        self.terminal = sys.stdout
        self.ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
        try:
            self.log = open(filename, "w", encoding="utf-8")
        except IOError as exc:
            print(colorama.Fore.RED + f"[Error] Cannot open log file {filename}: {exc}")
            self.log = None

    def write(self, message):
        self.terminal.write(message)
        if self.log:
            self.log.write(self.ansi_escape.sub("", message))
            self.log.flush()

    def flush(self):
        self.terminal.flush()
        if self.log:
            self.log.flush()


@dataclass
class TargetInfo:
    raw: str
    host: str
    scheme: Optional[str]
    port: Optional[int]
    path: str
    query: str


class SearchMap:
    def __init__(
        self,
        target,
        threads=20,
        timeout=5.0,
        ports=None,
        dir_dict="dict/fuzz.txt",
        dir_mode="smart",
        dir_extensions=None,
        dir_statuses=None,
        dir_depth=0,
        dir_all_web=False,
        sub_dict="dict/subdomain.txt",
        resolvers=None,
        max_body=DEFAULT_MAX_BODY,
    ):
        self.target = self._parse_target(target)
        self.threads = max(1, min(int(threads), 256))
        self.timeout = max(0.5, float(timeout))
        self.port_spec = ports or "smart"
        self.dir_dict = dir_dict
        self.dir_mode = (dir_mode or "smart").lower()
        self.dir_extensions = dir_extensions or DEFAULT_DIR_EXTENSIONS
        self.dir_statuses = dir_statuses or INTERESTING_DIR_STATUS
        if dir_depth is None:
            dir_depth = 1 if self.dir_mode == "deep" else 0
        self.dir_depth = max(0, min(int(dir_depth), 3))
        self.dir_all_web = dir_all_web
        self.sub_dict = sub_dict
        self.resolvers = resolvers or DEFAULT_RESOLVERS
        self.max_body = max(4096, int(max_body))
        self.headers = self._get_random_header()
        self._thread_local = threading.local()
        self.ip_list = []
        self.working_web_url = None
        self.results = {
            "target": self.target.raw,
            "host": self.target.host,
            "scan_time": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "basic": {},
            "dns_records": {},
            "http": [],
            "tls": [],
            "cdn": {},
            "ports": [],
            "directories": [],
            "subdomains": [],
            "fingerprints": [],
            "errors": [],
        }

    @staticmethod
    def _get_random_header():
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
        ]
        return {"User-Agent": random.choice(user_agents), "Accept": "*/*"}

    @staticmethod
    def _parse_target(raw):
        target = raw.strip()
        if not target:
            raise ValueError("empty target")

        has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target))
        parsed = urlparse(target if has_scheme else f"//{target}")
        host = parsed.hostname
        if not host:
            raise ValueError(f"cannot parse host from target: {raw}")

        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError(f"invalid port in target: {raw}") from exc

        return TargetInfo(
            raw=target,
            host=host.strip("[]").lower(),
            scheme=parsed.scheme.lower() if has_scheme else None,
            port=port,
            path=parsed.path or "/",
            query=parsed.query or "",
        )

    @staticmethod
    def _is_ip(address):
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    @staticmethod
    def _format_host_for_url(host):
        if SearchMap._is_ip(host) and ":" in host:
            return f"[{host}]"
        return host

    @staticmethod
    def _ip_profile(ip):
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            return "unknown"
        flags = []
        if obj.is_private:
            flags.append("private")
        if obj.is_global:
            flags.append("global")
        if obj.is_loopback:
            flags.append("loopback")
        if obj.is_reserved:
            flags.append("reserved")
        if obj.is_multicast:
            flags.append("multicast")
        return ", ".join(flags) or "public"

    @staticmethod
    def _registrable_domain(host):
        if SearchMap._is_ip(host):
            return None
        parts = [part for part in host.strip(".").lower().split(".") if part]
        if len(parts) < 2:
            return None
        suffix2 = ".".join(parts[-2:])
        if suffix2 in COMMON_MULTI_PART_SUFFIXES and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    @staticmethod
    def _strip_control(value, max_len=220):
        text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]+", " ", value or "")
        text = re.sub(r"\s+", " ", text).strip()
        return text[:max_len]

    @staticmethod
    def _response_signature(response):
        body = response.text or ""
        title = SearchMap._extract_title(body)
        normalized = re.sub(r"\d{4,}", "N", body)
        normalized = re.sub(r"[a-f0-9]{16,}", "H", normalized, flags=re.I)
        digest = hashlib.sha1(normalized[:8192].encode("utf-8", "ignore")).hexdigest()
        return {
            "status": response.status_code,
            "length": len(response.content or b""),
            "title": title,
            "hash": digest,
        }

    @staticmethod
    def _extract_title(html):
        match = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
        if not match:
            return ""
        title = re.sub(r"\s+", " ", match.group(1)).strip()
        return SearchMap._strip_control(title, 160)

    @staticmethod
    def _extract_generator(html):
        match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
            html or "",
            re.I,
        )
        if match:
            return SearchMap._strip_control(match.group(1), 120)
        return ""

    def _print_info(self, key, value, color=colorama.Fore.CYAN, indent=0):
        if value in (None, "", [], {}):
            return
        indent_space = " " * indent
        if isinstance(value, list):
            value = ", ".join(map(str, value))
        print(f"{indent_space}{colorama.Fore.GREEN}[{key}]: {color}{value}")

    def _remember_fingerprint(self, source, data):
        item = {"source": source}
        item.update({key: value for key, value in data.items() if value not in (None, "", [], {})})
        signature = json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
        for existing in self.results["fingerprints"]:
            if json.dumps(existing, sort_keys=True, ensure_ascii=False, default=str) == signature:
                return
        self.results["fingerprints"].append(item)

    def _build_url(self, scheme, path="/"):
        host = self._format_host_for_url(self.target.host)
        port = f":{self.target.port}" if self.target.port else ""
        if not path.startswith("/"):
            path = f"/{path}"
        return f"{scheme}://{host}{port}{path}"

    def _target_full_url(self):
        if not self.target.scheme:
            return None
        netloc = self._format_host_for_url(self.target.host)
        if self.target.port:
            netloc = f"{netloc}:{self.target.port}"
        return urlunparse(
            (
                self.target.scheme,
                netloc,
                self.target.path or "/",
                "",
                self.target.query,
                "",
            )
        )

    def _web_candidates(self):
        if self.target.scheme:
            return [self._target_full_url()]
        if self.target.port:
            schemes = ["https", "http"] if self.target.port in TLS_PORTS else ["http", "https"]
            return [self._build_url(scheme, self.target.path or "/") for scheme in schemes]
        return [
            self._build_url("https", self.target.path or "/"),
            self._build_url("http", self.target.path or "/"),
        ]

    def _web_root_candidates(self):
        roots = []
        for url in self._web_candidates():
            parsed = urlparse(url)
            roots.append(urlunparse((parsed.scheme, parsed.netloc, "/", "", "", "")))
        return list(dict.fromkeys(roots))

    def _get_session(self):
        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update(self.headers)
            adapter = HTTPAdapter(
                pool_connections=self.threads,
                pool_maxsize=self.threads,
                max_retries=0,
            )
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self._thread_local.session = session
        return session

    def _request(self, method, url, allow_redirects=True, max_body=None):
        response = self._get_session().request(
            method,
            url,
            timeout=self.timeout,
            verify=False,
            allow_redirects=allow_redirects,
            stream=max_body is not None,
        )
        if max_body is not None:
            response._content = self._read_limited_body(response, max_body)
            response._content_consumed = True
            response.close()
        return response

    @staticmethod
    def _read_limited_body(response, max_body):
        chunks = []
        total = 0
        try:
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                remaining = max_body - total
                if remaining <= 0:
                    break
                chunks.append(chunk[:remaining])
                total += len(chunk[:remaining])
                if total >= max_body:
                    break
        except requests.RequestException:
            return b""
        return b"".join(chunks)

    def _resolve_addresses(self, host=None):
        host = host or self.target.host
        if self._is_ip(host):
            return [host]
        addresses = set()
        try:
            for item in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
                addresses.add(item[4][0])
        except socket.gaierror as exc:
            self.results["errors"].append(f"resolve {host}: {exc}")
        return sorted(addresses, key=lambda value: (":" in value, value))

    def _resolve_record(self, qtype, nameserver=None, host=None):
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        if nameserver:
            resolver.nameservers = [nameserver]
        try:
            answers = resolver.resolve(host or self.target.host, qtype)
            return sorted({answer.to_text().strip('"') for answer in answers})
        except (dns.exception.DNSException, OSError):
            return []

    def get_base_info(self):
        print("\n" + "=" * 20 + " Basic Information " + "=" * 20)
        self._print_info("Target", self.target.raw)
        self._print_info("Host", self.target.host)
        self._print_info("Target Type", "IP address" if self._is_ip(self.target.host) else "Domain")

        self.ip_list = self._resolve_addresses()
        self.results["basic"]["ips"] = self.ip_list
        if self.ip_list:
            enriched = []
            for ip in self.ip_list:
                ptr = self._reverse_dns(ip)
                label = f"{ip}({self._ip_profile(ip)})"
                if ptr:
                    label = f"{label} PTR={ptr}"
                enriched.append(label)
            self._print_info("Resolved IPs", enriched)
            if len(self.ip_list) > 1:
                print(colorama.Fore.YELLOW + "[Ps] Multiple IPs found; CDN or load balancing may be in use.")
        else:
            self._print_info("Domain Resolution Error", "No address records found", colorama.Fore.RED)

        if not self._is_ip(self.target.host):
            self.dns_record_scan()
            self._whois_lookup()
        else:
            self._reverse_ip_ptrs()

        self.http_fingerprint()
        self.tls_fingerprint()

    def _reverse_dns(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return ""

    def _reverse_ip_ptrs(self):
        print(colorama.Fore.GREEN + "\n[Reverse DNS]:")
        for ip in self.ip_list or [self.target.host]:
            ptr = self._reverse_dns(ip)
            if ptr:
                print(colorama.Fore.CYAN + f"  - {ip} -> {ptr}")
            else:
                print(colorama.Fore.YELLOW + f"  - {ip}: no PTR record")

    def _whois_lookup(self):
        print(colorama.Fore.GREEN + "\n[WHOIS Information]:")
        try:
            whois_info = whois.whois(self.target.host)
            compact = {}
            for key, value in whois_info.items():
                if value in (None, "", [], {}):
                    continue
                compact[key] = value
                self._print_info(key.capitalize(), value, indent=2)
            self.results["basic"]["whois"] = compact
        except Exception as exc:
            self._print_info("WHOIS Error", str(exc), colorama.Fore.RED, indent=2)
            self.results["errors"].append(f"whois: {exc}")

    def dns_record_scan(self):
        print("\n" + "=" * 20 + " DNS Records " + "=" * 20)
        if self._is_ip(self.target.host):
            print(colorama.Fore.YELLOW + "[Skip] DNS record scan is for domain targets.")
            return

        records = {}
        for qtype in DNS_RECORD_TYPES:
            values = self._resolve_record(qtype)
            if values:
                records[qtype] = values
                self._print_info(qtype, values)

        if not records:
            print(colorama.Fore.YELLOW + "[Info] No DNS records returned by the default resolver.")
        self.results["dns_records"] = records

    def http_fingerprint(self):
        print("\n" + "=" * 20 + " HTTP Fingerprint " + "=" * 20)
        findings = []

        for url in self._web_candidates():
            try:
                result = self._fingerprint_http_url(url)
            except requests.RequestException as exc:
                self._print_info("HTTP Probe Failed", f"{url} -> {exc}", colorama.Fore.YELLOW)
                continue

            parsed_final = urlparse(result["final_url"])
            self.working_web_url = urlunparse((parsed_final.scheme, parsed_final.netloc, "/", "", "", ""))
            result["well_known"] = self._probe_well_known(self.working_web_url)
            findings.append(result)
            self._remember_fingerprint("http", {
                "url": result["final_url"],
                "status": result["status"],
                "title": result["title"],
                "server": result["server"],
                "technologies": result["technologies"],
                "favicon_hash": result.get("favicon_hash", ""),
            })

            self._print_info("URL", result["final_url"])
            self._print_info("Status", result["status"])
            self._print_info("Title", result["title"] or "No Title Found")
            self._print_info("Server", result["server"])
            self._print_info("X-Powered-By", result["powered_by"])
            self._print_info("Content-Type", result["content_type"])
            self._print_info("Content-Length", result["content_length"])
            self._print_info("Generator", result["generator"])
            self._print_info("Technologies", result["technologies"])
            self._print_info("Favicon Hash", result.get("favicon_hash"))
            self._print_info("Security Headers Present", result["security_headers_present"])
            self._print_info("Security Headers Missing", result["security_headers_missing"], colorama.Fore.YELLOW)
            for item in result["well_known"]:
                print(colorama.Fore.BLUE + f"  - {item['path']} -> {item['status']} {item['url']}")
            break

        if not findings:
            print(colorama.Fore.YELLOW + "[Info] No HTTP service responded on the candidate URL(s).")
        self.results["http"] = findings

    def _fingerprint_http_url(self, url):
        response = self._request("GET", url, allow_redirects=True, max_body=self.max_body)
        headers = {key.lower(): value for key, value in response.headers.items()}
        html = response.text
        title = self._extract_title(html)
        generator = self._extract_generator(html)
        technologies = self._detect_technologies(headers, html)
        present_security = [header for header in SECURITY_HEADERS if header in headers]
        missing_security = [header for header in SECURITY_HEADERS if header not in headers]
        return {
            "url": url,
            "final_url": response.url,
            "status": response.status_code,
            "title": title,
            "server": response.headers.get("Server", ""),
            "powered_by": response.headers.get("X-Powered-By", ""),
            "content_type": response.headers.get("Content-Type", ""),
            "content_length": len(response.content or b""),
            "redirects": [item.status_code for item in response.history],
            "generator": generator,
            "technologies": technologies,
            "security_headers_present": present_security,
            "security_headers_missing": missing_security,
            "favicon_hash": self._favicon_hash(response.url),
        }

    def _favicon_hash(self, final_url):
        parsed = urlparse(final_url)
        favicon_url = urlunparse((parsed.scheme, parsed.netloc, "/favicon.ico", "", "", ""))
        try:
            response = self._request("GET", favicon_url, allow_redirects=True, max_body=65536)
        except requests.RequestException:
            return ""
        content_type = response.headers.get("Content-Type", "").lower()
        if response.status_code >= 400 or ("image" not in content_type and len(response.content or b"") < 32):
            return ""
        return str(zlib.crc32(response.content or b"") & 0xFFFFFFFF)

    def _detect_technologies(self, headers, html):
        tech = set()
        server = headers.get("server", "").lower()
        powered_by = headers.get("x-powered-by", "").lower()
        cookies = headers.get("set-cookie", "").lower()
        body = (html or "").lower()

        header_map = {
            "nginx": "nginx",
            "openresty": "OpenResty",
            "apache": "Apache",
            "iis": "Microsoft IIS",
            "cloudflare": "Cloudflare",
            "tengine": "Tengine",
            "gunicorn": "Gunicorn",
            "werkzeug": "Werkzeug",
            "envoy": "Envoy",
            "varnish": "Varnish",
        }
        for needle, label in header_map.items():
            if needle in server:
                tech.add(label)

        if powered_by:
            tech.add(f"X-Powered-By: {self._strip_control(headers.get('x-powered-by', ''), 80)}")
        if "cf-ray" in headers or "cf-cache-status" in headers:
            tech.add("Cloudflare")
        if "x-cache" in headers or "via" in headers:
            tech.add("Reverse Proxy/Cache")
        if "x-generator" in headers:
            tech.add(self._strip_control(headers.get("x-generator", ""), 80))
        if "x-redirect-by" in headers:
            tech.add(self._strip_control(headers.get("x-redirect-by", ""), 80))
        if "phpsessid" in cookies or ".php" in body:
            tech.add("PHP")
        if "jsessionid" in cookies:
            tech.add("Java")
        if "asp.net_sessionid" in cookies or "x-aspnet-version" in headers:
            tech.add("ASP.NET")
        if "wp-content" in body or "wp-json" in body:
            tech.add("WordPress")
        if "drupal.settings" in body or "/sites/default/" in body:
            tech.add("Drupal")
        if "joomla" in body or "/media/system/js/" in body:
            tech.add("Joomla")
        if "laravel_session" in cookies or "csrf-token" in body:
            tech.add("Laravel")
        if "thinkphp" in body:
            tech.add("ThinkPHP")
        if "django" in cookies or "csrftoken" in cookies:
            tech.add("Django")
        if "rails" in cookies or "csrf-param" in body:
            tech.add("Ruby on Rails")
        if "swagger-ui" in body or "openapi" in body:
            tech.add("Swagger/OpenAPI")
        if "actuator" in body and "spring" in body:
            tech.add("Spring Boot")
        if "__next_data__" in body:
            tech.add("Next.js")
        if "nuxt" in body:
            tech.add("Nuxt")
        if "vite" in body:
            tech.add("Vite")
        if "angular" in body or "ng-version" in body:
            tech.add("Angular")
        if "react" in body:
            tech.add("React")
        if "vue" in body:
            tech.add("Vue")
        if "jquery" in body:
            tech.add("jQuery")
        if "bootstrap" in body:
            tech.add("Bootstrap")
        return sorted(tech)

    def _probe_well_known(self, root_url):
        findings = []
        for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
            url = root_url.rstrip("/") + path
            try:
                response = self._request("GET", url, allow_redirects=False, max_body=self.max_body)
            except requests.RequestException:
                continue
            if response.status_code in INTERESTING_DIR_STATUS:
                findings.append({"path": path, "status": response.status_code, "url": url})
        return findings

    def tls_fingerprint(self):
        print("\n" + "=" * 20 + " TLS Certificate " + "=" * 20)
        targets = []
        if self.target.scheme == "https":
            targets.append((self.target.host, self.target.port or 443))
        elif self.target.port in TLS_PORTS:
            targets.append((self.target.host, self.target.port))
        elif not self.target.port:
            targets.append((self.target.host, 443))

        seen = set()
        results = []
        for host, port in targets:
            if (host, port) in seen:
                continue
            seen.add((host, port))
            result = self._read_tls_certificate(host, port)
            if result:
                results.append(result)
                self._print_info("Endpoint", f"{host}:{port}")
                self._print_info("TLS Version", result.get("tls_version"))
                self._print_info("Cipher", result.get("cipher"))
                self._print_info("Subject", result.get("subject"))
                self._print_info("Issuer", result.get("issuer"))
                self._print_info("Not Before", result.get("not_before"))
                self._print_info("Not After", result.get("not_after"))
                self._print_info("SAN Count", result.get("san_count"))
                self._print_info("SHA256", result.get("sha256"))

        if not results:
            print(colorama.Fore.YELLOW + "[Info] No TLS certificate could be collected.")
        self.results["tls"] = results

    def _read_tls_certificate(self, host, port, server_name=None):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            sni_name = server_name if server_name and not self._is_ip(server_name) else None
            if not sni_name and not self._is_ip(host):
                sni_name = host
            with context.wrap_socket(sock, server_hostname=sni_name) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
                tls_version = tls_sock.version()
                cipher = tls_sock.cipher()
        except (OSError, ssl.SSLError):
            if sock:
                sock.close()
            return None

        sha256 = hashlib.sha256(der_cert).hexdigest() if der_cert else ""
        decoded = self._decode_certificate(ssl.DER_cert_to_PEM_cert(der_cert)) if der_cert else {}
        sans = [item[1] for item in decoded.get("subjectAltName", []) if item[0].lower() == "dns"]
        return {
            "host": host,
            "port": port,
            "tls_version": tls_version,
            "cipher": cipher[0] if cipher else "",
            "subject": self._format_cert_name(decoded.get("subject")),
            "issuer": self._format_cert_name(decoded.get("issuer")),
            "not_before": decoded.get("notBefore", ""),
            "not_after": decoded.get("notAfter", ""),
            "san_count": len(sans),
            "sans": sans[:50],
            "sha256": sha256,
        }

    @staticmethod
    def _decode_certificate(pem):
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="ascii", delete=False) as tmp:
                tmp.write(pem)
                tmp_path = tmp.name
            return ssl._ssl._test_decode_cert(tmp_path)
        except Exception:
            return {}
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    @staticmethod
    def _format_cert_name(value):
        if not value:
            return ""
        parts = []
        for group in value:
            for key, item in group:
                parts.append(f"{key}={item}")
        return ", ".join(parts)

    def multi_location_dns_check(self):
        print("\n" + "=" * 20 + " Multi-Resolver DNS/CDN Check " + "=" * 20)
        if self._is_ip(self.target.host):
            print(colorama.Fore.YELLOW + "[Skip] CDN check is for domain targets.")
            return

        all_ips = set()
        resolver_results = {}
        cname_values = self._resolve_record("CNAME")
        with ThreadPoolExecutor(max_workers=min(len(self.resolvers), self.threads)) as executor:
            future_map = {
                executor.submit(self._dns_resolver_worker, name, ip): name
                for name, ip in self.resolvers.items()
            }
            with tqdm(total=len(future_map), desc="DNS Checking", ncols=100) as pbar:
                for future in as_completed(future_map):
                    name = future_map[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {"ips": [], "error": str(exc)}
                    resolver_results[name] = result
                    if result.get("ips"):
                        all_ips.update(result["ips"])
                        pbar.write(colorama.Fore.BLUE + f"  - {name:<14}: {', '.join(result['ips'])}")
                    else:
                        pbar.write(colorama.Fore.YELLOW + f"  - {name:<14}: no response")
                    pbar.update(1)

        cname_hit = any(any(hint in cname.lower() for hint in CDN_HINTS) for cname in cname_values)
        likely_cdn = len(all_ips) > 1 or cname_hit
        conclusion = "LIKELY using CDN/load balancing" if likely_cdn else "LIKELY direct origin"
        self.results["cdn"] = {
            "unique_ips": sorted(all_ips),
            "cname": cname_values,
            "resolver_results": resolver_results,
            "likely_cdn": likely_cdn,
            "reason": "multiple resolver IPs or CDN-like CNAME" if likely_cdn else "single IP and no CDN-like CNAME",
        }

        print("\n" + colorama.Fore.GREEN + "[Conclusion]:")
        self._print_info("Total Unique IPs Found", len(all_ips), indent=2)
        self._print_info("CNAME", cname_values, indent=2)
        print(colorama.Fore.CYAN + f"  -> {conclusion}.")

    def _dns_resolver_worker(self, name, nameserver):
        ips = []
        for qtype in ("A", "AAAA"):
            ips.extend(self._resolve_record(qtype, nameserver=nameserver))
        return {"resolver": name, "nameserver": nameserver, "ips": sorted(set(ips))}

    def port_scan(self):
        print("\n" + "=" * 20 + " Smart Port Scan " + "=" * 20)
        if not self.ip_list:
            self.ip_list = self._resolve_addresses()
        if not self.ip_list:
            print(colorama.Fore.RED + "[Error] No IP addresses to scan.")
            return

        ports = self._parse_ports(self.port_spec)
        self._print_info("Port Set", f"{self.port_spec} ({len(ports)} ports)")
        self._print_info("Scanner", "TCP connect scan with service, banner, HTTP and TLS fingerprinting")

        tasks = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for ip in self.ip_list:
                for port in ports:
                    tasks.append(executor.submit(self._scan_one_port, ip, port))
            with tqdm(total=len(tasks), desc="Scanning Ports", ncols=100) as pbar:
                for future in as_completed(tasks):
                    result = future.result()
                    if result:
                        self.results["ports"].append(result)
                        pbar.write(colorama.Fore.BLUE + f"[Open] {result['ip']}:{result['port']} ({result['service']})")
                    pbar.update(1)

        if not self.results["ports"]:
            print(colorama.Fore.YELLOW + "[Info] No open TCP ports found in selected port set.")
            return

        self.results["ports"].sort(key=lambda item: (item["ip"], item["port"]))
        self._print_port_table(self.results["ports"])

    @staticmethod
    def _parse_ports(spec):
        if not spec:
            return list(SMART_PORTS)
        lowered = spec.lower()
        if lowered in ("fast", "top100"):
            return list(FAST_PORTS)
        if lowered in ("smart", "default"):
            return list(SMART_PORTS)
        if lowered in ("common", "top1000"):
            return list(COMMON_PORTS)
        if lowered == "web":
            return sorted(WEB_PORTS)
        if lowered in ("full", "all"):
            return list(range(1, 65536))

        ports = set()
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                start, end = part.split("-", 1)
                start, end = int(start), int(end)
                if start > end:
                    start, end = end, start
                ports.update(range(max(1, start), min(65535, end) + 1))
            else:
                ports.add(int(part))
        return sorted(port for port in ports if 1 <= port <= 65535)

    def _scan_one_port(self, ip, port):
        start = time.monotonic()
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                pass
        except OSError:
            return None

        latency_ms = int((time.monotonic() - start) * 1000)
        service = self._service_name(port)
        banner, tls_version = self._grab_banner(ip, port)
        fingerprint = self._fingerprint_open_port(ip, port, service, banner, tls_version)
        if fingerprint.get("service"):
            service = fingerprint["service"]
        return {
            "ip": ip,
            "port": port,
            "service": service,
            "latency_ms": latency_ms,
            "banner": banner,
            "tls_version": tls_version,
            "fingerprint": fingerprint,
        }

    def _print_port_table(self, ports):
        print("\n" + colorama.Fore.GREEN + "[Open Ports]:")
        header = f"{'IP':<22} {'PORT':<7} {'SERVICE':<14} {'RTT':<8} {'FINGERPRINT'}"
        print(colorama.Fore.CYAN + header)
        print(colorama.Fore.CYAN + "-" * min(len(header) + 40, 120))
        for item in ports:
            fp = item.get("fingerprint", {})
            summary = fp.get("summary") or item.get("banner") or ""
            tls = f"TLS {item['tls_version']} " if item.get("tls_version") else ""
            summary = self._strip_control(f"{tls}{summary}", 90)
            print(
                f"{item['ip']:<22} {item['port']:<7} "
                f"{item['service']:<14} {str(item['latency_ms']) + 'ms':<8} {summary}"
            )

    @staticmethod
    def _service_name(port):
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "unknown"

    def _grab_banner(self, ip, port):
        use_tls_first = port in TLS_PORTS
        for use_tls in (use_tls_first, not use_tls_first):
            try:
                return self._grab_banner_once(ip, port, use_tls)
            except (OSError, ssl.SSLError, TimeoutError):
                continue
        return "", ""

    def _grab_banner_once(self, ip, port, use_tls):
        tls_version = ""
        with socket.create_connection((ip, port), timeout=self.timeout) as sock:
            sock.settimeout(min(self.timeout, 2.0))
            conn = sock
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                server_name = None if self._is_ip(self.target.host) else self.target.host
                conn = context.wrap_socket(sock, server_hostname=server_name)
                tls_version = conn.version() or ""

            try:
                if port in WEB_PORTS or use_tls:
                    host_header = self.target.host
                    request = (
                        f"HEAD / HTTP/1.1\r\nHost: {host_header}\r\n"
                        f"User-Agent: {self.headers['User-Agent']}\r\n"
                        "Connection: close\r\n\r\n"
                    )
                    conn.sendall(request.encode("ascii", "ignore"))
                else:
                    try:
                        data = conn.recv(512)
                        banner = self._strip_control(data.decode("utf-8", "ignore"))
                        if banner:
                            return banner, tls_version
                    except socket.timeout:
                        pass
                    conn.sendall(b"\r\n")

                data = conn.recv(1024)
                banner = self._strip_control(data.decode("utf-8", "ignore"))
                first_line = banner.split("  ")[0] if "  " in banner else banner.splitlines()[0] if banner else ""
                return first_line[:180], tls_version
            finally:
                if use_tls:
                    conn.close()

    def _fingerprint_open_port(self, ip, port, service, banner, tls_version):
        fingerprint = {
            "service": service,
            "banner": banner,
            "tls_version": tls_version,
            "summary": "",
        }

        for pattern, service_name, product in BANNER_HINTS:
            if banner and re.search(pattern, banner):
                fingerprint["service"] = service_name
                fingerprint["product"] = product
                break

        should_http_probe = port in WEB_PORTS or tls_version or self._looks_like_http_banner(banner)
        if should_http_probe:
            for url in self._port_web_urls(port, tls_first=bool(tls_version or port in TLS_PORTS)):
                try:
                    http_fp = self._fingerprint_http_url(url)
                except requests.RequestException:
                    continue
                fingerprint.update({
                    "service": "https" if url.startswith("https://") else "http",
                    "url": http_fp["final_url"],
                    "status": http_fp["status"],
                    "title": http_fp["title"],
                    "server": http_fp["server"],
                    "technologies": http_fp["technologies"],
                    "favicon_hash": http_fp.get("favicon_hash", ""),
                })
                parts = [
                    str(http_fp["status"]),
                    http_fp["server"],
                    http_fp["title"],
                    ", ".join(http_fp["technologies"][:4]),
                ]
                fingerprint["summary"] = " | ".join(part for part in parts if part)
                self._remember_fingerprint("port-http", {
                    "endpoint": f"{ip}:{port}",
                    "url": http_fp["final_url"],
                    "title": http_fp["title"],
                    "server": http_fp["server"],
                    "technologies": http_fp["technologies"],
                    "favicon_hash": http_fp.get("favicon_hash", ""),
                })
                return fingerprint

        if tls_version:
            cert = self._read_tls_certificate(
                ip,
                port,
                server_name=self.target.host if not self._is_ip(self.target.host) else None,
            )
            if cert:
                fingerprint["cert_issuer"] = cert.get("issuer", "")
                fingerprint["cert_subject"] = cert.get("subject", "")
                fingerprint["cert_sha256"] = cert.get("sha256", "")
                fingerprint["summary"] = f"TLS {tls_version} | {cert.get('subject', '')}"
                self._remember_fingerprint("port-tls", {
                    "endpoint": f"{ip}:{port}",
                    "tls_version": tls_version,
                    "issuer": cert.get("issuer", ""),
                    "subject": cert.get("subject", ""),
                })

        if not fingerprint["summary"]:
            fingerprint["summary"] = banner or fingerprint.get("product", "")
        if fingerprint.get("product"):
            self._remember_fingerprint("port", {
                "endpoint": f"{ip}:{port}",
                "service": fingerprint["service"],
                "product": fingerprint["product"],
                "banner": banner,
            })
        return fingerprint

    @staticmethod
    def _looks_like_http_banner(banner):
        lowered = (banner or "").lower()
        return lowered.startswith("http/") or "server:" in lowered or "<html" in lowered

    def _port_web_urls(self, port, tls_first=False):
        host = self._format_host_for_url(self.target.host)
        first = "https" if tls_first else "http"
        second = "http" if tls_first else "https"

        def build(scheme):
            default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
            netloc = host if default_port else f"{host}:{port}"
            return f"{scheme}://{netloc}/"

        urls = [build(first)]
        if port in WEB_PORTS:
            urls.append(build(second))
        return list(dict.fromkeys(urls))

    def dir_scan(self):
        print("\n" + "=" * 20 + " Smart Directory Scan " + "=" * 20)
        roots = self._directory_roots()
        if not roots:
            print(colorama.Fore.RED + "[Error] No HTTP service available for directory scan.")
            return

        wordlist = self._load_wordlist(self.dir_dict)
        if not wordlist:
            print(colorama.Fore.RED + f"[Error] Dictionary is empty or missing: {self.dir_dict}")
            return

        self._print_info("Mode", self.dir_mode)
        self._print_info("Status Filter", sorted(self.dir_statuses))
        self._print_info("Target Roots", roots)
        self._print_info("Dictionary Items", len(wordlist))

        for root_url in roots:
            paths = self._prepare_dir_paths(wordlist, root_url)
            baselines = self._build_soft404_baselines(root_url)
            self._print_info("Base URL", root_url)
            self._print_info("Expanded Paths", len(paths))
            if baselines:
                self._print_info("Soft 404 Baselines", len(baselines))
            self._scan_dir_root(root_url, paths, baselines)

        self.results["directories"].sort(key=lambda item: (item["url"], item["status"]))

    def _scan_dir_root(self, root_url, paths, baselines):
        seen_urls = set()
        current = [(root_url, path) for path in paths]
        for depth in range(self.dir_depth + 1):
            if not current:
                break
            next_roots = []
            futures = []
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                for base_url, path in current:
                    clean_path = path.strip().lstrip("/")
                    url = base_url.rstrip("/") + "/" + clean_path
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)
                    futures.append(executor.submit(self._dir_worker, base_url, clean_path, baselines))
                desc = "Scanning Dirs" if depth == 0 else f"Recursive Dirs d{depth}"
                with tqdm(total=len(futures), desc=desc, ncols=100) as pbar:
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            self.results["directories"].append(result)
                            tag_text = f" [{', '.join(result['tags'])}]" if result.get("tags") else ""
                            title = f" | {result['title']}" if result.get("title") else ""
                            pbar.write(
                                colorama.Fore.BLUE
                                + f"[Found] {result['status']} {result['length']:<7} "
                                + f"{result['url']}{tag_text}{title}"
                            )
                            if depth < self.dir_depth and self._is_directory_candidate(result):
                                next_roots.append(result["url"].rstrip("/") + "/")
                        pbar.update(1)
            current = []
            recursive_words = list(RECURSIVE_DIR_WORDS)
            if self.dir_mode == "deep":
                recursive_words.extend(paths[:80])
            for next_root in list(dict.fromkeys(next_roots)):
                current.extend((next_root, word) for word in recursive_words)

    def _directory_roots(self):
        roots = []
        root = self._pick_web_root()
        if root:
            roots.append(root)
        if self.dir_all_web:
            for item in self.results.get("ports", []):
                fp = item.get("fingerprint", {})
                if fp.get("url"):
                    parsed = urlparse(fp["url"])
                    roots.append(urlunparse((parsed.scheme, parsed.netloc, "/", "", "", "")))
                elif item.get("port") in WEB_PORTS:
                    for url in self._port_web_urls(item["port"], tls_first=bool(item.get("tls_version"))):
                        roots.append(url)
        return list(dict.fromkeys(roots))

    def _prepare_dir_paths(self, wordlist, root_url):
        raw_items = list(wordlist)
        mode = self.dir_mode.lower()
        if mode in ("smart", "deep"):
            raw_items.extend(SMART_DIR_SEEDS)
            raw_items.extend(self._discover_seed_paths(root_url))

        expanded = []
        for item in raw_items:
            expanded.extend(self._expand_dir_item(item, mode))
        return list(dict.fromkeys(path for path in expanded if path))

    def _expand_dir_item(self, item, mode):
        raw = item.strip()
        if not raw or raw.startswith("#"):
            return []
        if raw.startswith("http://") or raw.startswith("https://"):
            parsed = urlparse(raw)
            raw = parsed.path or "/"
        raw = raw.lstrip("/")

        items = []
        if "%EXT%" in raw:
            for ext in self.dir_extensions:
                items.append(raw.replace("%EXT%", ext.lstrip(".")))
        else:
            items.append(raw)

        if mode in ("smart", "deep"):
            for candidate in list(items):
                if self._looks_like_dir_path(candidate) and not candidate.endswith("/"):
                    items.append(candidate + "/")
                if mode == "deep" and self._looks_like_file_path(candidate):
                    for suffix in BACKUP_SUFFIXES:
                        items.append(candidate + suffix)
        return items

    @staticmethod
    def _looks_like_dir_path(path):
        tail = path.rstrip("/").split("/")[-1]
        return "." not in tail and not path.endswith((".txt", ".xml", ".json"))

    @staticmethod
    def _looks_like_file_path(path):
        tail = path.rstrip("/").split("/")[-1]
        return "." in tail and not tail.endswith(BACKUP_SUFFIXES)

    def _discover_seed_paths(self, root_url):
        seeds = []
        robots_url = root_url.rstrip("/") + "/robots.txt"
        try:
            response = self._request("GET", robots_url, allow_redirects=False, max_body=self.max_body)
            if response.status_code < 400:
                for match in re.finditer(r"(?im)^(?:allow|disallow):\s*([^\s#]+)", response.text):
                    path = match.group(1).strip()
                    if path and path != "/":
                        seeds.append(path.lstrip("/"))
        except requests.RequestException:
            pass

        sitemap_url = root_url.rstrip("/") + "/sitemap.xml"
        try:
            response = self._request("GET", sitemap_url, allow_redirects=False, max_body=self.max_body)
            if response.status_code < 400:
                root_host = urlparse(root_url).netloc
                for loc in re.findall(r"<loc>\s*(.*?)\s*</loc>", response.text, re.I | re.S):
                    parsed = urlparse(loc.strip())
                    if parsed.netloc and parsed.netloc != root_host:
                        continue
                    if parsed.path and parsed.path != "/":
                        seeds.append(parsed.path.lstrip("/"))
        except requests.RequestException:
            pass

        return seeds[:200]

    def _is_directory_candidate(self, result):
        if result["status"] in (401, 403):
            return False
        if result["url"].endswith("/"):
            return True
        location = result.get("location", "")
        return location.endswith("/")

    def _pick_web_root(self):
        if self.working_web_url:
            return self.working_web_url
        for url in self._web_root_candidates():
            try:
                response = self._request("GET", url, max_body=self.max_body)
            except requests.RequestException:
                continue
            if response.status_code < 500:
                parsed = urlparse(response.url)
                self.working_web_url = urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))
                return self.working_web_url
        return None

    @staticmethod
    def _load_wordlist(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                items = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            return []
        return list(dict.fromkeys(items))

    def _build_soft404_baselines(self, root_url):
        baselines = []
        for _ in range(2):
            token = "searchmap-" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16))
            url = root_url.rstrip("/") + "/" + token
            try:
                response = self._request("GET", url, allow_redirects=False, max_body=self.max_body)
            except requests.RequestException:
                continue
            baselines.append(self._response_signature(response))
        return baselines

    def _dir_worker(self, root_url, path, baselines):
        clean_path = path.strip().lstrip("/")
        if not clean_path:
            return None
        url = root_url.rstrip("/") + "/" + clean_path
        try:
            response = self._request("GET", url, allow_redirects=False, max_body=self.max_body)
        except requests.RequestException:
            return None
        if response.status_code not in self.dir_statuses:
            return None
        signature = self._response_signature(response)
        if self._looks_like_soft404(signature, baselines):
            return None
        tags = self._classify_directory_finding(clean_path, response, signature)
        if tags:
            self._remember_fingerprint("directory", {
                "url": url,
                "status": response.status_code,
                "tags": tags,
                "title": signature["title"],
            })
        return {
            "url": url,
            "path": "/" + clean_path,
            "status": response.status_code,
            "length": len(response.content or b""),
            "title": signature["title"],
            "location": response.headers.get("Location", ""),
            "content_type": response.headers.get("Content-Type", ""),
            "tags": tags,
        }

    @staticmethod
    def _looks_like_soft404(signature, baselines):
        for baseline in baselines:
            if signature["status"] != baseline["status"]:
                continue
            if signature["hash"] == baseline["hash"]:
                return True
            base_len = max(baseline["length"], 1)
            length_delta = abs(signature["length"] - baseline["length"]) / base_len
            same_title = signature["title"] and signature["title"] == baseline["title"]
            if same_title and length_delta < 0.25:
                return True
            if not signature["title"] and not baseline["title"] and length_delta < 0.02:
                return True
        return False

    def _classify_directory_finding(self, path, response, signature):
        lowered = path.lower()
        body = (response.text or "").lower()
        tags = []
        if response.status_code in (401, 403):
            tags.append("access-controlled")
        if lowered.startswith(".git/") or "ref: refs/heads" in body:
            tags.append("git-exposure")
        if ".env" in lowered or re.search(r"(?m)^(?:aws_|secret|password|token|api[_-]?key)", body):
            tags.append("secret/config")
        if lowered.endswith((".sql", ".db", ".mdb", ".sqlite")):
            tags.append("database-dump")
        if lowered.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z", ".bak", ".old", "~")):
            tags.append("backup-file")
        if "swagger" in lowered or "openapi" in lowered or "api-docs" in lowered:
            tags.append("api-docs")
        if "graphql" in lowered or "graphiql" in lowered:
            tags.append("graphql")
        if "phpmyadmin" in lowered or "/pma" in f"/{lowered}":
            tags.append("db-admin")
        if "wp-login" in lowered or "wp-admin" in lowered:
            tags.append("wordpress")
        if "admin" in lowered or "login" in lowered or "manager" in lowered:
            tags.append("admin/auth")
        if "actuator" in lowered or "jolokia" in lowered or "server-status" in lowered:
            tags.append("ops-endpoint")
        if signature["title"]:
            tech = self._detect_technologies(
                {key.lower(): value for key, value in response.headers.items()},
                response.text,
            )
            tags.extend([f"tech:{item}" for item in tech[:3]])
        return list(dict.fromkeys(tags))

    def sub_scan(self):
        print("\n" + "=" * 20 + " Subdomain Scan " + "=" * 20)
        base_domain = self._registrable_domain(self.target.host)
        if not base_domain:
            print(colorama.Fore.RED + "[Error] Subdomain scan can only be performed on a valid domain.")
            return

        names = self._load_wordlist(self.sub_dict)
        if not names:
            print(colorama.Fore.RED + f"[Error] Dictionary is empty or missing: {self.sub_dict}")
            return

        wildcard_ips = self._detect_wildcard_dns(base_domain)
        self._print_info("Base Domain", base_domain)
        self._print_info("Dictionary Items", len(names))
        if wildcard_ips:
            self._print_info("Wildcard DNS", sorted(wildcard_ips), colorama.Fore.YELLOW)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [
                executor.submit(self._sub_worker, name, base_domain, wildcard_ips)
                for name in names
            ]
            with tqdm(total=len(futures), desc="Scanning Subs", ncols=100) as pbar:
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        self.results["subdomains"].append(result)
                        pbar.write(
                            colorama.Fore.BLUE
                            + f"[Found] {result['domain']} -> {', '.join(result['ips'])}"
                        )
                    pbar.update(1)

    def _detect_wildcard_dns(self, base_domain):
        wildcard_ips = set()
        for _ in range(2):
            label = "searchmap-" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(16))
            wildcard_ips.update(self._resolve_addresses(f"{label}.{base_domain}"))
        return wildcard_ips

    def _sub_worker(self, subname, base_domain, wildcard_ips):
        label = subname.strip().strip(".")
        if not label:
            return None
        domain = f"{label}.{base_domain}"
        ips = self._resolve_addresses(domain)
        if not ips:
            return None
        if wildcard_ips and set(ips).issubset(wildcard_ips):
            return None
        return {"domain": domain, "ips": ips}

    def run(self, do_port_scan, do_noping, do_dir_scan, do_sub_scan, do_full_scan):
        self.get_base_info()

        if do_full_scan:
            self.dir_all_web = True
            self.port_scan()
            self.multi_location_dns_check()
            self.dir_scan()
            self.sub_scan()
            self._print_fingerprint_summary()
            return

        if do_port_scan:
            self.port_scan()
        if do_noping:
            self.multi_location_dns_check()
        if do_dir_scan:
            self.dir_scan()
        if do_sub_scan:
            self.sub_scan()
        self._print_fingerprint_summary()

    def _print_fingerprint_summary(self):
        print("\n" + "=" * 20 + " Fingerprint Summary " + "=" * 20)
        technologies = set()
        web_targets = []
        sensitive_paths = []

        for item in self.results.get("http", []):
            web_targets.append(item.get("final_url", ""))
            technologies.update(item.get("technologies", []))

        for item in self.results.get("ports", []):
            fp = item.get("fingerprint", {})
            technologies.update(fp.get("technologies", []))
            if fp.get("url"):
                web_targets.append(fp["url"])

        for item in self.results.get("directories", []):
            tags = item.get("tags", [])
            if tags:
                sensitive_paths.append(f"{item['status']} {item['path']} [{', '.join(tags[:4])}]")
            for tag in tags:
                if tag.startswith("tech:"):
                    technologies.add(tag.split(":", 1)[1])

        open_ports = [f"{item['ip']}:{item['port']}/{item['service']}" for item in self.results.get("ports", [])]
        self._print_info("Open Ports", open_ports[:40])
        self._print_info("Web Targets", list(dict.fromkeys(web_targets))[:20])
        self._print_info("Technologies", sorted(technologies))
        self._print_info("Interesting Paths", sensitive_paths[:30], colorama.Fore.YELLOW)
        if not any([open_ports, web_targets, technologies, sensitive_paths]):
            print(colorama.Fore.YELLOW + "[Info] No fingerprint signals collected.")


def write_json(path, results):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, ensure_ascii=False, indent=2, default=str)


def write_csv(path, results):
    rows = []
    result_list = results if isinstance(results, list) else [results]
    for item in result_list:
        target = item.get("target", "")
        for ip in item.get("basic", {}).get("ips", []):
            rows.append({"target": target, "module": "basic", "key": "ip", "value": ip})
        for qtype, values in item.get("dns_records", {}).items():
            for value in values:
                rows.append({"target": target, "module": "dns", "key": qtype, "value": value})
        for http in item.get("http", []):
            rows.append({"target": target, "module": "http", "key": "url", "value": http.get("final_url", "")})
            rows.append({"target": target, "module": "http", "key": "title", "value": http.get("title", "")})
        for port in item.get("ports", []):
            rows.append({
                "target": target,
                "module": "port",
                "key": f"{port.get('ip')}:{port.get('port')}",
                "value": port.get("service", ""),
            })
        for directory in item.get("directories", []):
            rows.append({
                "target": target,
                "module": "directory",
                "key": str(directory.get("status", "")),
                "value": " | ".join(filter(None, [
                    directory.get("url", ""),
                    ", ".join(directory.get("tags", [])),
                    directory.get("title", ""),
                ])),
            })
        for fp in item.get("fingerprints", []):
            rows.append({
                "target": target,
                "module": "fingerprint",
                "key": fp.get("source", ""),
                "value": json.dumps(fp, ensure_ascii=False, default=str),
            })
        for sub in item.get("subdomains", []):
            rows.append({
                "target": target,
                "module": "subdomain",
                "key": sub.get("domain", ""),
                "value": ", ".join(sub.get("ips", [])),
            })

    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["target", "module", "key", "value"])
        writer.writeheader()
        writer.writerows(rows)


def parse_csv_values(value):
    return tuple(item.strip().lstrip(".") for item in (value or "").split(",") if item.strip())


def parse_status_values(value):
    statuses = set()
    for part in (value or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            statuses.update(range(start, end + 1))
        else:
            statuses.add(int(part))
    return {status for status in statuses if 100 <= status <= 599}


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "SearchMap v1.2.0 - Pure Python information collection tool for "
            "authorized security assessment."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Scan a single target URL, domain, or IP")
    group.add_argument("-r", "--read", help="Batch scan targets from a file")

    parser.add_argument("-p", "--port", help="Run pure Python TCP port scan", action="store_true")
    parser.add_argument("-n", "--noping", help="Multi-resolver DNS/CDN detection", action="store_true")
    parser.add_argument("-d", "--dirscan", help="Scan web directories with soft-404 filtering", action="store_true")
    parser.add_argument("-s", "--subscan", help="Bruteforce subdomains with wildcard DNS filtering", action="store_true")
    parser.add_argument("-a", "--fullscan", help="Run all modules", action="store_true")

    parser.add_argument("-o", "--outlog", help="Output console results to a log file")
    parser.add_argument("--json-out", help="Write structured JSON results")
    parser.add_argument("--csv-out", help="Write flattened CSV findings")
    parser.add_argument("-t", "--threads", help="Concurrent threads (default: 20, max: 256)", type=int, default=20)
    parser.add_argument("--timeout", help="Network timeout in seconds (default: 5)", type=float, default=5.0)
    parser.add_argument(
        "--ports",
        help="Port set for -p: fast/top100, smart, common/top1000, web, full, 80,443,8000-8100",
        default="smart",
    )
    parser.add_argument("--dict", dest="dir_dict", help="Directory wordlist path", default="dict/fuzz.txt")
    parser.add_argument(
        "--dir-mode",
        choices=("fast", "smart", "deep"),
        default="smart",
        help="Directory scan strategy: fast, smart with expansion, or deep with backups/recursion",
    )
    parser.add_argument(
        "--dir-ext",
        default=",".join(DEFAULT_DIR_EXTENSIONS),
        help="Extensions used for %%EXT%% directory entries",
    )
    parser.add_argument(
        "--dir-status",
        default="200,201,204,301,302,307,308,401,403,405",
        help="Interesting directory HTTP statuses, e.g. 200,301,401,403 or 200-403",
    )
    parser.add_argument("--dir-depth", type=int, default=None, help="Recursive directory depth (default: 0, deep: 1)")
    parser.add_argument("--dir-all-web", action="store_true", help="Scan all web services found by port scan")
    parser.add_argument("--max-body", type=int, default=DEFAULT_MAX_BODY, help="Max bytes to read per HTTP response")
    parser.add_argument("--subdict", help="Subdomain wordlist path", default="dict/subdomain.txt")
    parser.add_argument(
        "--resolver",
        action="append",
        default=[],
        help="Custom DNS resolver IP. Can be used multiple times.",
    )
    return parser


def run_single_target(target, args):
    resolvers = DEFAULT_RESOLVERS
    if args.resolver:
        resolvers = {f"custom-{i + 1}": ip for i, ip in enumerate(args.resolver)}
    dir_statuses = parse_status_values(args.dir_status) or INTERESTING_DIR_STATUS
    scanner = SearchMap(
        target,
        threads=args.threads,
        timeout=args.timeout,
        ports=args.ports,
        dir_dict=args.dir_dict,
        dir_mode=args.dir_mode,
        dir_extensions=parse_csv_values(args.dir_ext) or DEFAULT_DIR_EXTENSIONS,
        dir_statuses=dir_statuses,
        dir_depth=args.dir_depth,
        dir_all_web=args.dir_all_web,
        sub_dict=args.subdict,
        resolvers=resolvers,
        max_body=args.max_body,
    )
    scanner.run(args.port, args.noping, args.dirscan, args.subscan, args.fullscan)
    return scanner.results


def main():
    banner()
    parser = build_parser()
    args = parser.parse_args()

    if args.outlog:
        sys.stdout = Logger(args.outlog)

    all_results = []
    if args.read:
        try:
            with open(args.read, "r", encoding="utf-8") as handle:
                targets = [line.strip() for line in handle if line.strip()]
        except FileNotFoundError:
            print(colorama.Fore.RED + f"[Error] Input file not found: {args.read}")
            return

        print(colorama.Fore.GREEN + f"[Info] Total tasks: {len(targets)}")
        for index, target in enumerate(targets, 1):
            print("\n" + "#" * 20 + f" Task {index}/{len(targets)}: {target} " + "#" * 20)
            try:
                all_results.append(run_single_target(target, args))
            except Exception as exc:
                print(colorama.Fore.RED + f"[Task Error] {target}: {exc}")
                all_results.append({"target": target, "errors": [str(exc)]})
    else:
        try:
            print(colorama.Fore.GREEN + f"[Info] Starting scan for: {args.url}")
            all_results = run_single_target(args.url, args)
        except Exception as exc:
            print(colorama.Fore.RED + f"[Task Error] An unexpected error occurred: {exc}")
            all_results = {"target": args.url, "errors": [str(exc)]}

    if args.json_out:
        write_json(args.json_out, all_results)
        print(colorama.Fore.GREEN + f"[Info] JSON results written to: {args.json_out}")
    if args.csv_out:
        write_csv(args.csv_out, all_results)
        print(colorama.Fore.GREEN + f"[Info] CSV findings written to: {args.csv_out}")


if __name__ == "__main__":
    main()
