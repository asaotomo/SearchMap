#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import requests
import socket
import re
import whois
import nmap
import json
import zlib
import random
import string
import colorama
import sys
import os
import dns.resolver
import tldextract
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# 禁用requests的InsecureRequestWarning警告
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# --- 工具信息 ---
def banner():
    """打印Banner和版本信息"""
    colorama.init(autoreset=True)
    print(colorama.Fore.CYAN + """
 ____                      _     __  __             
/ ___|  ___  __ _ _ __ ___| |__ |  \/  | __ _ _ __  
\___ \ / _ \/ _` | '__/ __| '_ \| |\/| |/ _` | '_ \ 
 ___) |  __/ (_| | | | (__| | | | |  | | (_| | |_) |
|____/ \___|\__,_|_|  \___|_| |_|_|  |_|\__,_| .__/ 
                                             |_|    V1.0.3
    """)
    print(colorama.Fore.GREEN + "# Coded by Asaotomo")
    print(colorama.Fore.GREEN + "# Last Updated: 2025.07.22")


# --- 日志记录类 ---
class Logger(object):
    """将输出同时打印到控制台和文件"""
    def __init__(self, filename="Default.log"):
        self.terminal = sys.stdout
        self.ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        try:
            self.log = open(filename, "w", encoding='utf-8')
        except IOError as e:
            print(colorama.Fore.RED + f"[Error] Cannot open log file {filename}: {e}")
            self.log = None

    def write(self, message):
        self.terminal.write(message)
        if self.log:
            self.log.write(self.ansi_escape.sub('', message))
            self.log.flush()

    def flush(self):
        self.terminal.flush()
        if self.log:
            self.log.flush()

# --- 主扫描类 ---
class SearchMap:
    def __init__(self, target, threads=20):
        self.target_raw = target
        self.target_url = self._normalize_url(target) # This will be used for domain targets
        self.target_domain = self._get_domain_from_url(self.target_url)
        self.threads = threads
        self.headers = self._get_random_header()
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.ip_list = []
        self.results = {}

    # --- 内部辅助方法 ---
    @staticmethod
    def _get_random_header():
        lib = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.109 Safari/537.36",
               "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0"]
        return {"User-Agent": random.choice(lib)}

    @staticmethod
    def _normalize_url(url):
        if not re.match(r'http(s)?://', url):
            # For IP addresses, this default might be overridden later by smart check
            return "https://" + url
        return url

    @staticmethod
    def _get_domain_from_url(url):
        netloc_part = url.split("://")[1].split("/")[0]
        if ":" in netloc_part:
            return netloc_part.split(":")[0]
        else:
            return netloc_part

    @staticmethod
    def _is_ip(address):
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False

    def _get_ip_location(self, ip):
        """获取单个IP的地理位置 (使用ipinfo.io API)"""
        try:
            api_url = f"https://ipinfo.io/{ip}/json"
            res = self.session.get(api_url, timeout=3)
            res.raise_for_status()
            data = res.json()
            city = data.get('city', '')
            region = data.get('region', '')
            country = data.get('country', '')
            location_parts = [part for part in [city, region, country] if part]
            if location_parts:
                return ", ".join(location_parts)
            else:
                return "Location data not found"
        except (requests.RequestException, json.JSONDecodeError):
            return "Lookup Failed"

    def _print_info(self, key, value, color=colorama.Fore.CYAN, indent=0):
        indent_space = " " * indent
        if value:
            if isinstance(value, list):
                if len(value) > 0:
                    if isinstance(value[0], datetime):
                        value_str = ", ".join([item.strftime('%Y-%m-%d %H:%M:%S') for item in value])
                    else:
                        value_str = ", ".join(map(str, value))
                    print(f"{indent_space}{colorama.Fore.GREEN}[{key}]: {color}{value_str}")
            else:
                print(f"{indent_space}{colorama.Fore.GREEN}[{key}]: {color}{value}")

    # --- 核心扫描功能 ---
    def get_base_info(self):
        print("\n" + "="*20 + " Basic Information " + "="*20)
        try:
            addrs = socket.getaddrinfo(self.target_domain, None)
            self.ip_list = sorted(list(set(item[4][0] for item in addrs)))
        except socket.gaierror as e:
            self._print_info("Domain Resolution Error", str(e), color=colorama.Fore.RED)
            return

        if self.ip_list:
            ip_to_location = {}
            with ThreadPoolExecutor(max_workers=len(self.ip_list) or 1) as executor:
                future_to_ip = {executor.submit(self._get_ip_location, ip): ip for ip in self.ip_list}
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        location = future.result()
                        ip_to_location[ip] = location
                    except Exception:
                        ip_to_location[ip] = "Lookup Failed"

            ips_with_location = [f"{ip}({ip_to_location.get(ip, 'N/A')})" for ip in self.ip_list]
            if len(ips_with_location) > 1:
                self._print_info("IP Addresses", ", ".join(ips_with_location))
                print(colorama.Fore.YELLOW + "[Ps] Multiple IPs found, CDN may be in use.")
            elif ips_with_location:
                self._print_info("IP Address", ips_with_location[0])
        
        # --- 智能获取网站标题 ---
        url_for_title = None
        netloc = self.target_url.split("://")[1].split("/")[0]

        if self._is_ip(self.target_domain):
            # The target is an IP. Check if a port was specified in the original input.
            if ":" in netloc:
                # A port was specified (e.g., "10.204.1.249:65000"). Use the full URL directly.
                url_for_title = self.target_url
            else:
                # No port was specified (it was a pure IP). Check common web ports.
                print(colorama.Fore.YELLOW + "[Info] Target is an IP, checking for web ports (80, 443)...")
                s_443 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s_443.settimeout(1.0)
                if s_443.connect_ex((self.target_domain, 443)) == 0:
                    url_for_title = f"https://{self.target_domain}"
                s_443.close()
                
                if not url_for_title:
                    s_80 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s_80.settimeout(1.0)
                    if s_80.connect_ex((self.target_domain, 80)) == 0:
                        url_for_title = f"http://{self.target_domain}"
                    s_80.close()
        else:
            # For domain names, use the normalized URL from initialization.
            url_for_title = self.target_url

        # --- 获取标题 ---
        if url_for_title:
            try:
                res = self.session.get(url_for_title, verify=False, timeout=5)
                res.encoding = res.apparent_encoding
                title_match = re.search("<title>(.*?)</title>", res.text, re.S)
                title = title_match.group(1).strip() if title_match else "No Title Found"
                self._print_info("Website Title", title)
            except requests.RequestException as e:
                self._print_info("Website Title", f"Failed to fetch title from {url_for_title}: {e}", color=colorama.Fore.RED)
        else:
            self._print_info("Website Title", "No web service found on common ports (80, 443)", color=colorama.Fore.YELLOW)

        
        # --- IP反查或WHOIS ---
        if self._is_ip(self.target_domain):
            print(colorama.Fore.GREEN + "\n[Bound Domains on IP (Reverse IP Lookup)]:")
            try:
                rev_url = f"https://site.ip138.com/{self.target_domain}/"
                res = self.session.get(rev_url, timeout=10)
                domains = re.findall('<span class="date">(.*?)</span><a href="/(.*?)/" target="_blank">(.*?)</a>', res.text, re.S)
                if domains:
                    for date, domain, _ in domains:
                        print(colorama.Fore.CYAN + f"  - {domain} ({date})")
                else:
                    print(colorama.Fore.YELLOW + "  No bound domains found.")
            except requests.RequestException:
                print(colorama.Fore.RED + "  Failed to perform reverse IP lookup.")
        else:
            print(colorama.Fore.GREEN + "\n[WHOIS Information]:")
            try:
                whois_info = whois.whois(self.target_domain)
                for key, value in whois_info.items():
                    self._print_info(f"{key.capitalize()}", value, indent=2)
            except Exception as e:
                self._print_info("WHOIS Error", str(e), color=colorama.Fore.RED, indent=2)

    def port_scan(self):
        if not self.ip_list:
            print(colorama.Fore.RED + "[Error] No IP addresses to scan. Run basic info scan first.")
            return
        
        print("\n" + "="*20 + " Port Scan " + "="*20)
        arguments = '-sS -T4 -Pn'
        nm = nmap.PortScanner()
        
        try:
            is_root = (os.getuid() == 0)
        except AttributeError:
            is_root = True
            
        if not is_root:
            print(colorama.Fore.YELLOW + "[Warning] Not running as root. SYN scan (-sS) may fail or require password.")
            print(colorama.Fore.YELLOW + "         Falling back to TCP connect scan (-sT).")
            arguments = '-sT -T4 -Pn'

        for ip in self.ip_list:
            self._print_info("Scanning Ports for", ip)
            try:
                nm.scan(hosts=ip, arguments=arguments)
                if ip not in nm.all_hosts():
                    print(colorama.Fore.RED + f"  Nmap scan failed for {ip}. Host might be down or blocking scans.")
                    continue
                scan_info = nm[ip]
                if 'tcp' in scan_info:
                    for port, port_info in scan_info['tcp'].items():
                        service_info = f"{port_info['name']} {port_info.get('version', '')}"
                        print(f"  - Port {port:<5} ({port_info['state']:<7}): {service_info.strip()}")
                else:
                    print(colorama.Fore.YELLOW + "  No open TCP ports found.")
            except nmap.nmap.PortScannerError as e:
                print(colorama.Fore.RED + f"  Nmap error: {e}")
    
    def _dns_worker(self, resolver_ip):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [resolver_ip]
        resolver.timeout = 5
        resolver.lifetime = 5
        try:
            answers = resolver.resolve(self.target_domain, 'A')
            results_with_location = []
            with ThreadPoolExecutor(max_workers=len(answers) or 1) as executor:
                future_to_ip = {executor.submit(self._get_ip_location, answer.to_text()): answer.to_text() for answer in answers}
                ip_to_location = {}
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        location = future.result()
                        ip_to_location[ip] = location
                    except Exception:
                        ip_to_location[ip] = "Lookup Failed"
            for ip, loc in ip_to_location.items():
                results_with_location.append((ip, loc))
            return sorted(results_with_location)
        except Exception:
            return None

    def multi_location_dns_check(self):
        print("\n" + "="*20 + " Multi-Location DNS Check " + "="*20)
        
        resolvers = {
            "Google (USA)": "8.8.8.8",
            "Cloudflare (Global)": "1.1.1.1",
            "OpenDNS (USA)": "208.67.222.222",
            "Quad9 (Global)": "9.9.9.9",
            "AliDNS (China)": "223.5.5.5",
            "DNSPod (China)": "119.29.29.29",
            "NTT (Japan)": "129.250.35.250",
            "Comodo (Europe)": "8.26.56.26",
        }
        
        all_found_ips = set()
        with ThreadPoolExecutor(max_workers=len(resolvers)) as executor:
            with tqdm(total=len(resolvers), desc="DNS Checking", ncols=100) as pbar:
                future_to_resolver = {executor.submit(self._dns_worker, ip): name for name, ip in resolvers.items()}
                for future in as_completed(future_to_resolver):
                    resolver_name = future_to_resolver[future]
                    try:
                        result_tuples = future.result()
                        if result_tuples:
                            formatted_output = ", ".join([f"{ip}({loc})" for ip, loc in result_tuples])
                            pbar.write(colorama.Fore.BLUE + f"  - From {resolver_name:<20}: {formatted_output}")
                            all_found_ips.update([ip for ip, loc in result_tuples])
                        else:
                            pbar.write(colorama.Fore.YELLOW + f"  - From {resolver_name:<20}: No response or failed")
                    except Exception as e:
                        pbar.write(colorama.Fore.RED + f"  - From {resolver_name:<20}: Error - {e}")
                    pbar.update(1)
        
        print("\n" + colorama.Fore.GREEN + "[Conclusion]:")
        self._print_info("Total Unique IPs Found", len(all_found_ips), indent=2)
        if len(all_found_ips) > 1:
            print(colorama.Fore.CYAN + "  -> This domain is LIKELY using a CDN or load balancing.")
        else:
            print(colorama.Fore.CYAN + "  -> This domain is LIKELY NOT using a CDN.")

    def _dir_worker(self, path):
        # Determine the base URL for dir scan, which needs a scheme
        base_url_for_dir = self.target_url
        if self._is_ip(self.target_domain):
            # If the main target was an IP, we must have determined a working scheme
            if "http" not in base_url_for_dir: # Check if it was already fixed
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((self.target_domain, 443)) == 0:
                    base_url_for_dir = f"https://{self.target_domain}"
                elif s.connect_ex((self.target_domain, 80)) == 0:
                     base_url_for_dir = f"http://{self.target_domain}"
                else:
                    return None # No web service to scan dirs
                s.close()
        
        try:
            url_to_check = f"{base_url_for_dir.rstrip('/')}/{path.strip()}"
            res = self.session.get(url_to_check, timeout=3, verify=False, allow_redirects=False)
            if res.status_code == 200:
                return f"[Found] {url_to_check} (Status: 200)"
        except requests.RequestException:
            pass
        return None

    def dir_scan(self):
        print("\n" + "="*20 + " Directory Scan " + "="*20)
        try:
            with open("dict/fuzz.txt", "r", encoding='utf-8') as f:
                dir_dict = f.readlines()
        except FileNotFoundError:
            print(colorama.Fore.RED + "[Error] Dictionary file not found: dict/fuzz.txt")
            return
            
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            with tqdm(total=len(dir_dict), desc="Scanning Dirs", ncols=100) as pbar:
                futures = [executor.submit(self._dir_worker, path) for path in dir_dict]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        pbar.write(colorama.Fore.BLUE + result)
                    pbar.update(1)

    def _sub_worker(self, subname, base_domain):
        subname = subname.strip()
        if not subname:
            return None
        
        domain_to_check = f"{subname}.{base_domain}"
        try:
            socket.gethostbyname(domain_to_check)
            return domain_to_check
        except socket.gaierror:
            return None

    def sub_scan(self):
        print("\n" + "="*20 + " Subdomain Scan " + "="*20)
        extracted = tldextract.extract(self.target_domain)
        base_domain = f"{extracted.domain}.{extracted.suffix}"
        if not extracted.domain:
            print(colorama.Fore.RED + "[Error] Subdomain scan can only be performed on a valid domain, not an IP address.")
            return

        print(colorama.Fore.YELLOW + f"[Info] Starting scan for base domain: {base_domain}")
        try:
            with open("dict/subdomain.txt", "r", encoding='utf-8') as f:
                sub_dict = f.readlines()
        except FileNotFoundError:
            print(colorama.Fore.RED + "[Error] Dictionary file not found: dict/subdomain.txt")
            return
            
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            with tqdm(total=len(sub_dict), desc="Scanning Subs", ncols=100) as pbar:
                futures = [executor.submit(self._sub_worker, subname, base_domain) for subname in sub_dict]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        try:
                            ips = sorted(list(set(item[4][0] for item in socket.getaddrinfo(result, None))))
                            pbar.write(colorama.Fore.BLUE + f"[Found] {result} -> IPs: {', '.join(ips)}")
                        except Exception:
                            pbar.write(colorama.Fore.BLUE + f"[Found] {result} (Could not resolve IP)")
                    pbar.update(1)

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

# --- 主程序入口 ---
def main():
    banner()
    parser = argparse.ArgumentParser(
        description="SearchMap v1.0.3 - An automatic information collection tool for penetration testing.",
        formatter_class=argparse.RawTextHelpFormatter)
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Scan a single target URL or IP (e.g., https://example.com or 8.8.8.8)')
    group.add_argument('-r', '--read', help='Batch scan targets from a file')

    parser.add_argument('-p', '--port', help='Scan target port(s)', action='store_true')
    parser.add_argument('-n', '--noping', help='Multi-location DNS check for CDN detection', action='store_true')
    parser.add_argument('-d', '--dirscan', help='Scan target directory', action='store_true')
    parser.add_argument('-s', '--subscan', help='Scan target subdomain', action='store_true')
    parser.add_argument('-a', '--fullscan', help='Run all scan modules (port, dir, sub, noping)', action='store_true')

    parser.add_argument('-o', '--outlog', help='Output results to a log file')
    parser.add_argument('-t', '--threads', help='Number of concurrent threads (default: 20)', type=int, default=20)
    
    args = parser.parse_args()

    if args.outlog:
        sys.stdout = Logger(args.outlog)

    if args.read:
        try:
            with open(args.read, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            print(colorama.Fore.GREEN + f"[Info] Total tasks: {len(urls)}")
            for i, url in enumerate(urls):
                print("\n" + "#"*20 + f" Task {i+1}/{len(urls)}: {url} " + "#"*20)
                try:
                    scanner = SearchMap(url, args.threads)
                    scanner.run(args.port, args.noping, args.dirscan, args.subscan, args.fullscan)
                except Exception as e:
                    print(colorama.Fore.RED + f"[Task Error] An unexpected error occurred while scanning {url}: {e}")

        except FileNotFoundError:
            print(colorama.Fore.RED + f"[Error] Input file not found: {args.read}")
    
    else:
        try:
            print(colorama.Fore.GREEN + f"[Info] Starting scan for: {args.url}")
            scanner = SearchMap(args.url, args.threads)
            scanner.run(args.port, args.noping, args.dirscan, args.subscan, args.fullscan)
        except Exception as e:
            print(colorama.Fore.RED + f"[Task Error] An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()
