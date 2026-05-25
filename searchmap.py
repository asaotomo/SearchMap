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
from tqdm import tqdm


requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

VERSION = "1.1.0"
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

TOP_100_PORTS = (
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

WEB_PORTS = {80, 81, 443, 8000, 8008, 8080, 8081, 8443, 8888, 10000}
TLS_PORTS = {443, 465, 636, 990, 993, 995, 8443}
INTERESTING_DIR_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405}

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
        sub_dict="dict/subdomain.txt",
        resolvers=None,
    ):
        self.target = self._parse_target(target)
        self.threads = max(1, min(int(threads), 256))
        self.timeout = max(0.5, float(timeout))
        self.port_spec = ports or "top100"
        self.dir_dict = dir_dict
        self.sub_dict = sub_dict
        self.resolvers = resolvers or DEFAULT_RESOLVERS
        self.headers = self._get_random_header()
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

    def _request(self, method, url, allow_redirects=True):
        return requests.request(
            method,
            url,
            headers=self.headers,
            timeout=self.timeout,
            verify=False,
            allow_redirects=allow_redirects,
        )

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
                response = self._request("GET", url, allow_redirects=True)
            except requests.RequestException as exc:
                self._print_info("HTTP Probe Failed", f"{url} -> {exc}", colorama.Fore.YELLOW)
                continue

            parsed_final = urlparse(response.url)
            self.working_web_url = urlunparse((parsed_final.scheme, parsed_final.netloc, "/", "", "", ""))
            headers = {key.lower(): value for key, value in response.headers.items()}
            title = self._extract_title(response.text)
            generator = self._extract_generator(response.text)
            technologies = self._detect_technologies(headers, response.text)
            present_security = [header for header in SECURITY_HEADERS if header in headers]
            missing_security = [header for header in SECURITY_HEADERS if header not in headers]

            result = {
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
                "well_known": self._probe_well_known(self.working_web_url),
            }
            findings.append(result)

            self._print_info("URL", response.url)
            self._print_info("Status", response.status_code)
            self._print_info("Title", title or "No Title Found")
            self._print_info("Server", result["server"])
            self._print_info("X-Powered-By", result["powered_by"])
            self._print_info("Content-Type", result["content_type"])
            self._print_info("Content-Length", result["content_length"])
            self._print_info("Generator", generator)
            self._print_info("Technologies", technologies)
            self._print_info("Security Headers Present", present_security)
            self._print_info("Security Headers Missing", missing_security, colorama.Fore.YELLOW)
            for item in result["well_known"]:
                print(colorama.Fore.BLUE + f"  - {item['path']} -> {item['status']} {item['url']}")
            break

        if not findings:
            print(colorama.Fore.YELLOW + "[Info] No HTTP service responded on the candidate URL(s).")
        self.results["http"] = findings

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
        }
        for needle, label in header_map.items():
            if needle in server:
                tech.add(label)

        if powered_by:
            tech.add(f"X-Powered-By: {self._strip_control(headers.get('x-powered-by', ''), 80)}")
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
        if "__next_data__" in body:
            tech.add("Next.js")
        if "nuxt" in body:
            tech.add("Nuxt")
        if "vite" in body:
            tech.add("Vite")
        if "react" in body:
            tech.add("React")
        if "vue" in body:
            tech.add("Vue")
        return sorted(tech)

    def _probe_well_known(self, root_url):
        findings = []
        for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
            url = root_url.rstrip("/") + path
            try:
                response = self._request("GET", url, allow_redirects=False)
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

    def _read_tls_certificate(self, host, port):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            server_name = None if self._is_ip(host) else host
            with context.wrap_socket(sock, server_hostname=server_name) as tls_sock:
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
        print("\n" + "=" * 20 + " Pure Python Port Scan " + "=" * 20)
        if not self.ip_list:
            self.ip_list = self._resolve_addresses()
        if not self.ip_list:
            print(colorama.Fore.RED + "[Error] No IP addresses to scan.")
            return

        ports = self._parse_ports(self.port_spec)
        self._print_info("Port Set", f"{len(ports)} ports")
        self._print_info("Scanner", "TCP connect scan with banner probing")

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
                        banner = f" | {result['banner']}" if result.get("banner") else ""
                        tls = f" | TLS {result['tls_version']}" if result.get("tls_version") else ""
                        pbar.write(
                            colorama.Fore.BLUE
                            + f"[Open] {result['ip']}:{result['port']} "
                            + f"({result['service']}){tls}{banner}"
                        )
                    pbar.update(1)

        if not self.results["ports"]:
            print(colorama.Fore.YELLOW + "[Info] No open TCP ports found in selected port set.")

    @staticmethod
    def _parse_ports(spec):
        if not spec or spec.lower() == "top100":
            return list(TOP_100_PORTS)
        if spec.lower() == "web":
            return sorted(WEB_PORTS)

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
        return {
            "ip": ip,
            "port": port,
            "service": service,
            "latency_ms": latency_ms,
            "banner": banner,
            "tls_version": tls_version,
        }

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

    def dir_scan(self):
        print("\n" + "=" * 20 + " Directory Scan " + "=" * 20)
        root_url = self._pick_web_root()
        if not root_url:
            print(colorama.Fore.RED + "[Error] No HTTP service available for directory scan.")
            return

        paths = self._load_wordlist(self.dir_dict)
        if not paths:
            print(colorama.Fore.RED + f"[Error] Dictionary is empty or missing: {self.dir_dict}")
            return

        baselines = self._build_soft404_baselines(root_url)
        self._print_info("Base URL", root_url)
        self._print_info("Dictionary Items", len(paths))
        if baselines:
            self._print_info("Soft 404 Baselines", len(baselines))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._dir_worker, root_url, path, baselines) for path in paths]
            with tqdm(total=len(futures), desc="Scanning Dirs", ncols=100) as pbar:
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        self.results["directories"].append(result)
                        pbar.write(
                            colorama.Fore.BLUE
                            + f"[Found] {result['url']} "
                            + f"(Status: {result['status']}, Length: {result['length']})"
                        )
                    pbar.update(1)

    def _pick_web_root(self):
        if self.working_web_url:
            return self.working_web_url
        for url in self._web_root_candidates():
            try:
                response = self._request("GET", url)
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
                response = self._request("GET", url, allow_redirects=False)
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
            response = self._request("GET", url, allow_redirects=False)
        except requests.RequestException:
            return None
        if response.status_code not in INTERESTING_DIR_STATUS:
            return None
        signature = self._response_signature(response)
        if self._looks_like_soft404(signature, baselines):
            return None
        return {
            "url": url,
            "path": "/" + clean_path,
            "status": response.status_code,
            "length": len(response.content or b""),
            "title": signature["title"],
            "location": response.headers.get("Location", ""),
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
            if length_delta < 0.05 or same_title:
                return True
        return False

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
            self.port_scan()
            self.multi_location_dns_check()
            self.dir_scan()
            self.sub_scan()
            return

        if do_port_scan:
            self.port_scan()
        if do_noping:
            self.multi_location_dns_check()
        if do_dir_scan:
            self.dir_scan()
        if do_sub_scan:
            self.sub_scan()


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
                "value": directory.get("url", ""),
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


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "SearchMap v1.1.0 - Pure Python information collection tool for "
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
    parser.add_argument("--ports", help="Port set for -p: top100, web, 80,443,8000-8100", default="top100")
    parser.add_argument("--dict", dest="dir_dict", help="Directory wordlist path", default="dict/fuzz.txt")
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
    scanner = SearchMap(
        target,
        threads=args.threads,
        timeout=args.timeout,
        ports=args.ports,
        dir_dict=args.dir_dict,
        sub_dict=args.subdict,
        resolvers=resolvers,
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
