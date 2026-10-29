# scanner.py - FULL VERSION
import requests
import re
import time
import socket
import threading
import random
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse
from config import Config

# Import untuk SOCKS5 support
try:
    import socks
    import socket as socks_socket
    SOCKS_SUPPORT = True
except ImportError:
    SOCKS_SUPPORT = False
    print("[!] SOCKS5 support not available. Install: pip install PySocks")

# Nonaktifkan warning SSL
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ============================================================
# DNS resolve with timeout — fix blocking getaddrinfo
# ============================================================
_DNS_TIMEOUT = 4  # detik

def _dns_resolve_with_timeout(hostname, port=80, timeout=_DNS_TIMEOUT):
    """
    Resolve hostname via socket.getaddrinfo di thread terpisah
    dengan timeout. Mengembalikan hasil (AF_INET, dst port) atau None.
    """
    result = []

    def _do():
        try:
            addrs = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
            result.extend(addrs)
        except Exception:
            pass

    t = threading.Thread(target=_do, daemon=True)
    t.start()
    t.join(timeout)

    if result:
        return result[0]  # ambil entry pertama
    return None


class MovableTypeScanner:
    def __init__(self, proxy_manager, cache_manager, main_reference=None):
        self.ua = UserAgent()
        self.proxy_manager = proxy_manager
        self.cache_manager = cache_manager
        self.main = main_reference  # Referensi ke main untuk update counter
        # PATCH MEMORY 10-28: found_urls jadi LRU bounded (OrderedDict) —
        # dulu set() tak terbatas, grow selama scanner jalan berhari-hari
        self.found_urls = OrderedDict()  # key -> True, LRU evict oldest
        self.found_urls_max = Config.FOUND_URLS_MAX
        self.lock = threading.Lock()
        
        # Headers
        self.headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "DNT": "1",
            "Connection": "close"
        }
        
        # PATCH PROXY 10-28:
        # Session shared utk scan domain TANPA proxy.
        # Connection header sudah "close" -> tidak ada keep-alive pooling.
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=1, pool_maxsize=1,
            max_retries=0, pool_block=False
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        # PATCH PROXY 10-28:
        # Request PROXIED pakai _proxied_request() (per-request session fresh,
        # pool size 1, tanpa keep-alive) -> bebas ProxyError "Cannot connect
        # to proxy" / pool exhaustion yang dulu bikin reverse IP di-skip.

        # Output files
        self.output_files = Config.OUTPUT_FILES

    def _proxied_request(self, method, url, proxy_dict, timeout, headers=None):
        """PATCH PROXY 10-28: per-request session, TANPA connection pooling.
        Session fresh per proxy call -> bebas pool exhaustion & 'Cannot connect to proxy'.
        Dipakai utk semua proxied GET (reverse IP via tntcode/hackertarget)."""
        import requests as _rq
        s = _rq.Session()
        try:
            # Pool size 1 per scheme, tanpa keep-alive -> tidak numpuk idle conn
            adapter = _rq.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=1,
                                                max_retries=0)
            s.mount('http://', adapter)
            s.mount('https://', adapter)
            hdrs = (headers if headers is not None else self.headers.copy())
            hdrs = dict(hdrs)
            hdrs.setdefault("User-Agent", self.ua.random)
            kwargs = dict(timeout=timeout, verify=False, headers=hdrs)
            if proxy_dict:
                kwargs['proxies'] = proxy_dict
            if method.lower() == 'get':
                return s.get(url, **kwargs)
            else:
                return s.post(url, **kwargs)
        finally:
            s.close()
    
    def get_base_url_with_www(self, domain, session=None):
        """
        Test domain dengan www, biarkan redirect handle HTTP->HTTPS
        Return final URL setelah redirect
        session: bila tidak diberikan, pakai self.session
        """
        sess = session or self.session
        cache_key = f"base_{domain}"
        cached = self.cache_manager.get_reverse_cache(cache_key)
        if cached:
            return cached
        
        try:
            # Pre-resolve DNS dengan timeout 4s — blocking getaddrinfo
            # tidak kena parameter timeout di requests, bisa hang 30-120 detik
            resolved = _dns_resolve_with_timeout(f"www.{domain}")
            if not resolved:
                return None
            # Address: (family, type, proto, canonname, (ip, port))
            ip_addr = resolved[4][0]

            # Request langsung ke IP + spoof Host — hindari DNS blocking di
            # loop berikutnya (requests.get("http://hostname") = getaddrinfo lagi).
            url_ip = f"http://{ip_addr}"
            response = sess.get(
                url_ip,
                timeout=5,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": self.ua.random, "Host": f"www.{domain}"}
            )

            if response.status_code < 400:
                # response.url = IP + path (karena request ke IP) —
                # ganti host-nya kembali ke domain asli utk cache
                resp_parsed = urlparse(response.url)
                final_url = f"{resp_parsed.scheme}://www.{domain}{resp_parsed.path}"
                if resp_parsed.query:
                    final_url += f"?{resp_parsed.query}"
                self.cache_manager.save_reverse_cache(cache_key, final_url, 'base')
                return final_url
        except Exception as e:
            pass

        return None
    
    def check_rsd_xml(self, domain, session=None):
        """
        Cek rsd.xml dengan auto-detection
        Hanya test 1 variasi (www), redirect handle sisanya
        session: bila tidak diberikan, pakai self.session
        """
        sess = session or self.session
        paths = ['/rsd.xml', '/blog/rsd.xml', '/news/rsd.xml', '/blog1/rsd.xml', 
                 '/diary/rsd.xml', '/mt/rsd.xml', '/kanri/rsd.xml']
        
        # Auto-detection: dapatkan base URL dengan www
        base_url = self.get_base_url_with_www(domain, session=sess)
        if not base_url:
            return None, None
        
        # Parse base URL
        parsed = urlparse(base_url)
        base_domain = parsed.netloc
        protocol = parsed.scheme
        
        # Test RSD paths (tanpa loop protocol)
        # Pre-resolve DNS 1x di awal — semua path berikutnya langsung ke IP
        rsd_ip = None
        try:
            _resolved = _dns_resolve_with_timeout(base_domain)
            if _resolved:
                rsd_ip = _resolved[4][0]
        except Exception:
            pass

        for path in paths:
            try:
                url = f"{protocol}://{base_domain}{path}"
                headers = self.headers.copy()
                headers["User-Agent"] = self.ua.random

                if rsd_ip:
                    # DNS sudah resolved — request ke IP, spoof Host header.
                    # Ini menghilangkan blocking getaddrinfo dari loop
                    # (setiap iteration masih DNS resolve 4s x 7 paths = 28s hang).
                    url_ip = f"{protocol}://{rsd_ip}{path}"
                    headers["Host"] = base_domain
                    response = sess.get(
                        url_ip, headers=headers,
                        timeout=Config.TIMEOUT_SCAN,
                        verify=False,
                        allow_redirects=False
                    )
                else:
                    response = sess.get(
                        url, headers=headers,
                        timeout=Config.TIMEOUT_SCAN,
                        verify=False,
                        allow_redirects=False
                    )

                if response.status_code == 200 and 'rsd' in response.text.lower():
                    return response.text, url
            except:
                continue

        return None, None
    
    def make_request_with_retry(self, url, method='get', **kwargs):
        """Make request dengan retry dan proxy berbeda setiap kali"""
        last_proxy = None
        
        for attempt in range(Config.MAX_RETRIES):
            try:
                # Dapatkan proxy berbeda untuk setiap attempt
                proxy_dict = self.proxy_manager.get_proxy_for_retry(attempt, last_proxy)
                if proxy_dict:
                    last_proxy = list(proxy_dict.values())[0] if proxy_dict else None
                else:
                    proxy_dict = None
                
                proxy_used = last_proxy
                start_time = time.time()
                
                headers = self.headers.copy()
                headers["User-Agent"] = self.ua.random
                
                if 'headers' in kwargs:
                    headers.update(kwargs['headers'])
                    del kwargs['headers']
                
                kwargs['headers'] = headers
                kwargs['proxies'] = proxy_dict
                kwargs['timeout'] = kwargs.get('timeout', Config.TIMEOUT_REVERSE)
                kwargs['verify'] = False
                
                if method.lower() == 'get':
                    response = self.session.get(url, **kwargs)
                else:
                    response = self.session.post(url, **kwargs)
                
                response_time = time.time() - start_time
                
                if proxy_used:
                    self.proxy_manager.update_stats(proxy_used, True, response_time)
                
                return response
                
            except Exception as e:
                if proxy_used:
                    self.proxy_manager.update_stats(proxy_used, False)
                
                if attempt < Config.MAX_RETRIES - 1:
                    delay = Config.RETRY_DELAY * (attempt + 1) + random.uniform(0, 1)
                    time.sleep(delay)
                    continue
        
        return None
    
    def _reverse_url(self, ip, source):
        """PATCH PROXY 10-28: URL reverse lookup per sumber"""
        if source == 'tntcode':
            return f"https://domains.tntcode.com/ip/{ip}"
        return f"https://api.hackertarget.com/reverseiplookup/?q={ip}"

    def _reverse_loop(self, fetch_domains, cache_key, source, ip):
        """PATCH PROXY 10-28: retry sampai dapat domain (TIDAK skip).
        - fetch_domains(response) -> list domain (kosong/None = belum dapat)
        - Pakai _proxied_request (per-request session, TANPA connection pool)
        - Backoff exponential, coba proxy BERBEDA tiap attempt
        - Henti saat: (a) dapat domain, (b) REVERSE_MAX_ATTEMPTS habis,
                      (c) deadline total REVERSE_RETRY_TOTAL_BUDGET habis
        - Timeout dihitung juga: tiap attempt pakai Config.TIMEOUT_REVERSE,
          deadline global mencegah stuck selamanya"""
        cached = self.cache_manager.get_reverse_cache(cache_key)
        if cached:
            return cached

        deadline = time.time() + Config.REVERSE_RETRY_TOTAL_BUDGET
        attempt = 0
        last_proxy = None
        base_delay = Config.REVERSE_RETRY_BASE_DELAY
        max_delay = Config.REVERSE_RETRY_MAX_DELAY

        while attempt < Config.REVERSE_MAX_ATTEMPTS and time.time() < deadline:
            proxy_dict = self.proxy_manager.get_proxy_for_retry(attempt, last_proxy)
            if proxy_dict:
                last_proxy = list(proxy_dict.values())[0]
            else:
                proxy_dict = None

            # PATCH HANG-FIX 10-28: proxy_used = proxy yang SEBENARNYA dipakai
            # di attempt ini (dari get_proxy_for_retry), BUKAN last_proxy lama.
            # Bug sebelumnya: statistik update ke proxy yang salah.
            proxy_used = last_proxy
            start_time = time.time()

            headers = self.headers.copy()
            headers["User-Agent"] = self.ua.random

            try:
                response = self._proxied_request(
                    'get', self._reverse_url(ip, source),
                    proxy_dict, Config.REVERSE_PROXY_TIMEOUT, headers,
                )
                domains = fetch_domains(response)
            except Exception:
                domains = None
                if proxy_used:
                    self.proxy_manager.update_stats(proxy_used, False)

            if domains:
                rt = time.time() - start_time
                if proxy_used:
                    self.proxy_manager.update_stats(proxy_used, True, rt)
                self.cache_manager.save_reverse_cache(cache_key, domains, source)
                print(f"[+] {source} {ip}: {len(domains)} domains (attempt {attempt+1})")
                return domains

            # Belum dapat domain / request gagal (termasuk timeout) ->
            # backoff lalu coba proxy BERBEDA lagi (di retry, bukan skip)
            delay = min(base_delay * (2 ** attempt), max_delay) + random.uniform(0, 1)
            delay = min(delay, max(0, deadline - time.time()))
            attempt += 1
            if attempt < Config.REVERSE_MAX_ATTEMPTS and delay > 0:
                time.sleep(delay)

        print(f"[-] {source} {ip}: belum dapat domain setelah {attempt} attempt (budget habis)")
        return []

    # tntcode DICABUT (10-28): Cloudflare captcha di tntcode.com,
    # 403 utk semua request -> tidak bisa dipakai lagi.
    # Satu-satunya sumber reverse IP sekarang = hackertarget.

    def reverse_ip_hackertarget(self, ip):
        """PATCH PROXY 10-28: reverse IP via hackertarget — retry sampai dapat domain"""
        cache_key = f"ht_{ip}"
        def fetch(response):
            if response.text and "error" not in response.text.lower():
                domains = [d.strip() for d in response.text.strip().split('\n') if d.strip()]
                return domains
            return []
        return self._reverse_loop(fetch, cache_key, 'hackertarget', ip)

    def extract_mt_info(self, rsd_content):
        """Ekstrak info Movable Type"""
        info = {'engine': None, 'api_link': None, 'version': None}
        
        engine_match = re.search(r'<engineName>(.+?)</engineName>', rsd_content, re.IGNORECASE)
        if engine_match:
            info['engine'] = engine_match.group(1)
            if 'movable type' in info['engine'].lower():
                version_match = re.search(r'(\d+\.\d+)', info['engine'])
                if version_match:
                    info['version'] = version_match.group(1)
        
        api_match = re.search(r'<api[^>]*apiLink="([^"]+)"[^>]*>', rsd_content, re.IGNORECASE)
        if api_match:
            info['api_link'] = api_match.group(1).strip()
            
        return info
    
    def check_mt_endpoints(self, domain, mt_info, session=None):
        """Cek endpoint Movable Type"""
        sess = session or self.session
        results = []
        
        if mt_info['api_link']:
            xmlrpc_urls = []
            
            if mt_info['api_link'].startswith('http'):
                xmlrpc_urls.append(mt_info['api_link'])
            else:
                # Gunakan base URL yang sudah dideteksi
                base_url = self.get_base_url_with_www(domain, session=sess)
                if base_url:
                    parsed = urlparse(base_url)
                    protocol = parsed.scheme
                    base_domain = parsed.netloc
                    xmlrpc_urls.append(f"{protocol}://{base_domain}{mt_info['api_link']}")

            # Pre-resolve DNS utk semua url — hindari blocking getaddrinfo
            # di loop per-endpoint (7 paths x 4s = 28s hang per thread)
            resolved_map = {}  # url -> (ip, host_header)
            for u in xmlrpc_urls:
                try:
                    p = urlparse(u)
                    host = p.netloc
                    _r = _dns_resolve_with_timeout(host)
                    if _r:
                        resolved_map[u] = (_r[4][0], host)
                except Exception:
                    pass

            for xmlrpc_url in xmlrpc_urls:
                try:
                    headers = self.headers.copy()
                    headers["User-Agent"] = self.ua.random

                    if xmlrpc_url in resolved_map:
                        ip, host_hdr = resolved_map[xmlrpc_url]
                        p = urlparse(xmlrpc_url)
                        url_ip = f"{p.scheme}://{ip}{p.path}"
                        headers["Host"] = host_hdr
                        response = sess.get(
                            url_ip, headers=headers,
                            timeout=Config.TIMEOUT_SCAN,
                            allow_redirects=False,
                            verify=False
                        )
                    else:
                        response = sess.get(
                            xmlrpc_url, headers=headers,
                            timeout=Config.TIMEOUT_SCAN,
                            allow_redirects=False,
                            verify=False
                        )
                    
                    is_v4 = mt_info.get('version') and mt_info['version'].startswith('4')
                    
                    if response.status_code in [403, 411, 405]:
                        url_key = f"{xmlrpc_url}|{response.status_code}"
                        with self.lock:
                            if url_key not in self.found_urls:
                                self.found_urls[url_key] = True
                                self.found_urls.move_to_end(url_key)
                                while len(self.found_urls) > self.found_urls_max:
                                    self.found_urls.popitem(last=False)
                                
                                # Simpan ke file
                                with open(self.output_files['movable_type'], 'a') as f:
                                    f.write(f"{xmlrpc_url}\n")
                                
                                if self.main:
                                    self.main.increment_mt()
                                
                                display_url = xmlrpc_url.replace('http://', '').replace('https://', '')
                                print(f"\n[+] MT ditemukan: {display_url} ({response.status_code})")
                                
                                results.append({
                                    'domain': domain,
                                    'xmlrpc_url': xmlrpc_url,
                                    'xmlrpc_status': response.status_code,
                                    'version': mt_info.get('version'),
                                    'is_v4': is_v4
                                })
                    
                    # Cek mt-upgrade.cgi untuk v4
                    if is_v4 and 'mt-xmlrpc.cgi' in xmlrpc_url:
                        upgrade_url = xmlrpc_url.replace('mt-xmlrpc.cgi', 'mt-upgrade.cgi')
                        if upgrade_url != xmlrpc_url:
                            try:
                                upgrade_response = sess.get(
                                    upgrade_url, headers=headers,
                                    timeout=Config.TIMEOUT_SCAN,
                                    allow_redirects=False,
                                    verify=False
                                )
                                
                                if upgrade_response.status_code == 200:
                                    upgrade_key = f"{upgrade_url}|200"
                                    with self.lock:
                                        if upgrade_key not in self.found_urls:
                                            self.found_urls[upgrade_key] = True
                                            self.found_urls.move_to_end(upgrade_key)
                                            while len(self.found_urls) > self.found_urls_max:
                                                self.found_urls.popitem(last=False)
                                            
                                            with open(self.output_files['movable_type_v4'], 'a') as f:
                                                f.write(f"{upgrade_url}\n")
                                            
                                            if self.main:
                                                self.main.increment_mtv4()
                                            
                                            display_upgrade = upgrade_url.replace('http://', '').replace('https://', '')
                                            print(f"\n[!] MT v4 upgrade.cgi: {display_upgrade}")
                            except:
                                pass
                                
                except:
                    continue
        
        return results
    
    def scan_domain(self, domain, session=None):
        """
        Scan satu domain dengan auto-detection.
        session: thread-local requests.Session bila dipanggil dari
                 ThreadPoolExecutor (100 thread) — hindari race condition
                 di self.session yang pool_maxsize=1.
        """
        try:
            rsd_content, rsd_url = self.check_rsd_xml(domain, session=session)

            if rsd_content:
                mt_info = self.extract_mt_info(rsd_content)

                if mt_info['engine'] and 'movable type' in mt_info['engine'].lower():
                    return self.check_mt_endpoints(domain, mt_info, session=session)
        except:
            pass
        return []

    def process_ip(self, ip):
        """Proses satu IP"""
        # Cek apakah IP sudah diproses
        if self.cache_manager.is_ip_processed(ip):
            print(f"[↺] Skipping cached IP: {ip}")
            return

        print(f"\n[*] Processing IP: {ip}")

        # PATCH PROXY 10-28: tntcode dicabut (Cloudflare captcha),
        # hackertarget = satu-satunya sumber reverse IP
        domains_ht = self.reverse_ip_hackertarget(ip)

        all_domains = domains_ht

        if all_domains:
            print(f"[+] Total domains: {len(all_domains)} (HT: {len(domains_ht)})")

            # Scan domains
            found_count = 0
            with ThreadPoolExecutor(max_workers=Config.MAX_THREADS_SCAN) as executor:

                def _scan_with_session(domain):
                    """Worker: buat thread-local session + pre-resolve DNS
                    dengan timeout agar blocking getaddrinfo tidak nge-freeze
                    thread selama 30-120 detik.
                    """
                    sess = requests.Session()
                    adapter = requests.adapters.HTTPAdapter(
                        pool_connections=1, pool_maxsize=1,
                        max_retries=0, pool_block=False
                    )
                    sess.mount('http://', adapter)
                    sess.mount('https://', adapter)
                    try:
                        return self.scan_domain(domain, session=sess)
                    finally:
                        sess.close()

                futures = [executor.submit(_scan_with_session, domain)
                           for domain in all_domains]
                for future in as_completed(futures):
                    results = future.result()
                    if results:
                        found_count += len(results)

            print(f"[+] IP {ip}: {found_count} MT found")

            # Tandai IP sudah diproses
            self.cache_manager.mark_ip_processed(ip, 'success' if found_count else 'empty')
        else:
            # NEGATIVE CACHE (patch 10-28): 0 domain = mark 'empty' ->
            # is_ip_processed() akan skip IP ini selama NEGATIVE_CACHE_TTL (24 jam).
            # Hemat proxy/jatah HT: IP yang memang tidak punya PTR/domain
            # tidak di-request ulang tiap cycle.
            self.cache_manager.mark_ip_processed(ip, 'empty')
            print(f"[-] No domains for IP {ip} (negative cache {Config.NEGATIVE_CACHE_TTL//3600} jam, tidak di-request ulang)")