# config.py
import os
import tempfile

# Konfigurasi Scanner
class Config:
    # Thread settings
    MAX_THREADS_REVERSE = 30  # Thread untuk reverse IP (pakai proxy)
    MAX_THREADS_SCAN = 100     # Thread untuk scan domain (tanpa proxy)
    
    # Proxy settings
    PREFER_SOCKS5 = True
    SOCKS5_PRIORITY = 0.7
    # PATCH 10-29 ADAPTIVE REFRESH: interval refresh list proxy kini DINAMIS,
    # menyesuaikan perubahan konten (content-hash blake2b):
    # - list BARU berubah  -> cek PROXY_REFRESH_MIN (cepat notice)
    # - N cycle stabil     -> naik bertahap sampai PROXY_REFRESH_MAX (hemat)
    # PROXY_REFRESH_INTERVAL lama (8 jam kaku) tetap dipakai sebagai MAX.
    PROXY_REFRESH_MAX = 28800       # 8 jam — plafon interval saat list stabil
    PROXY_REFRESH_MIN = 3600        # 1 jam  — floor saat list baru berubah
    PROXY_REFRESH_DEFAULT = 7200    # 2 jam  — interval pertama (belum ada data)
    PROXY_STREAK_MAX = 4            # N cycle 'tidak berubah' sebelum cap MAX
    PROXY_REFRESH_INTERVAL = 28800  # 8 jam dalam detik (sebagian list TheSpeedX
                                      # statis, refresh terlalu sering buang bandwidth)
    PROXY_URL = "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/all/data.txt"
    # PATCH PROXY 10-28: sumber proxy utama (TheSpeedX) — terverifikasi bisa tembus
    # ke api.hackertarget.com (hit ±10%/30 proxy, 0% utk proxifly). Refresh 8 jam.
    # PATCH 10-28: Mirror jsDelivr ditambahkan sebagai sumber kedua untuk
    # TheSpeedX — jika raw.githubusercontent.com stuck di CDN cache (max-age 300s),
    # jsDelivr (cache-nya sendiri, TTL pendek, revalidate lebih sering) tetap bisa
    # serve konten yang lebih fresh. download_proxies sudah dedup antar sumber,
    # jadi mirror tidak menambah duplikat.
    PROXY_LISTS = [
        # GitHub raw (source utama)
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks5.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks4.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt",
        # jsDelivr mirror (sumber kedua — revalidate lebih agresif, anti-CDN-stuck)
        "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks5.txt",
        "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/socks4.txt",
        "https://cdn.jsdelivr.net/gh/TheSpeedX/PROXY-List@master/http.txt",
    ]
    # ====== TIER PROXY (patch 10-28, desain akhir) ======
    # Tier 1: TheSpeedX (PROXY_LISTS, refresh PROXY_REFRESH_INTERVAL=8 jam)
    # Tier 3: last-known-good pool (proxy TheSpeedX lama yang terbukti work)
    #         Persisten di PROXY_CACHE_FILE. Dipakai SEMBARI MENUNGGU Tier 1
    #         refresh — proxy lama yang masih work dipakai dulu agar tools
    #         tidak stuck saat list TheSpeedX tidak berubah / refresh lambat.
    # Tier 2 (proxifly fallback) DICABUT 10-28 — hit rate 0% utk hackertarget.
    PROXY_MIN_T1_ALIVE = 50
    # Jika proxy non-dead di pool aktif (Tier 1) < threshold, libatkan
    # Tier 3 (proxy lama di proxy_stats yang tidak ada di list aktif).
    TIER3_RECOVERY_WINDOW = 1800  # 30 menit: proxy mati/recovery window
    # Persist cache: proxy + stats disimpan ke file, muat lagi saat boot /
    # kalau download TheSpeedX gagal. Bisa jalan berhari-hari.
    PROXY_CACHE_FILE = "proxy_cache.json"
    
    # RNG settings
    MAX_VALID_RNG = 50
    MAX_VALID_RNG_LIMIT = 200  # Batas maksimal
    
    # Cache settings
    MAX_CACHE_SIZE = 10000  # Maksimal entries di cache
    CACHE_CLEANUP_INTERVAL = 3600  # Bersihkan cache setiap 1 jam
    
    # Memory management
    TEMP_DIR = os.path.expanduser("~/.mt_scanner_cache/")
    MAX_MEMORY_ITEMS = 5000  # Maksimal item dalam memory
    
    # ====== MEMORY OPTIMIZATION (patch 10-28) ======
    # Tier L1 in-memory cache (LRU) — hit sebelum SQLite
    L1_REVERSE_CACHE_MAX = 2000        # entry reverse-ip cache in-memory
    L1_PROCESSED_MAX = 20000          # IP diproses in-memory (set LRU)
    L1_WRITEBACK_BATCH = 500          # simpan ke SQLite tiap N entri baru
    L1_PURGE_CHECK_INTERVAL = 5000    # cek purge tiap N operasi
    REVERSE_CACHE_TTL = 21600         # 6 jam — domain reverse IP basi cepat;
                                      # lebih lama malah tabrakan dgn skip-logic
    PROCESSED_TTL = 0                 # 0 = permanen (untuk status success)
    # NEGATIVE CACHE (patch 10-28): IP yang 0 domain (status 'empty') di-skip
    # selama N detik — irit proxy, jangan bakar jatah HT lagi utk IP yg memang
    # tidak punya PTR/domain. Status 'success' tetap permanen (PROCESSED_TTL=0).
    NEGATIVE_CACHE_TTL = 86400        # 24 jam utk hasil 0 domain
    PROCESSED_FILE_FLUSH = 500        # buffer flush ke processed_ips.txt
    FOUND_URLS_MAX = 10000            # bound set found_urls (LRU)
    PROXY_STATS_MAX = 500             # bound stats per-proxy (LRU by last_used)

    # ====== PROXY NO-POOL & RETRY (patch 10-28) ======
    # Per-request session utk proxied requests — TIDAK pakai pool shared,
    # menghindari ProxyError "Cannot connect to proxy" akibat pool exhaustion
    PROXY_REQUEST_PER_SESSION = True   # True = buat session baru per proxied request
    # Retry: coba proxy berbeda sampai dapat domain, atau mencapai limit.
    # Hit rate proxy TheSpeedX ke hackertarget ±10%/30 proxy (tes nyata 10-28),
    # jadi 30 attempt ≈ 96% IP dapat domain. 50 attempt ≈ 99.4%.
    REVERSE_MAX_ATTEMPTS = 50          # banyak proxy berbeda yg dicoba utk 1 reverse IP
    REVERSE_RETRY_BASE_DELAY = 2       # delay awal antar retry (detik, backoff exponential)
    REVERSE_RETRY_MAX_DELAY = 30       # cap delay max per retry
    # PATCH PROXY 10-28: timeout per attempt proxy (8s cukup utk proxy mati/keblokir,
    # proxy hidup ke hackertarget = 2-8s. 30s = buang waktu saat proxy dead).
    REVERSE_PROXY_TIMEOUT = 8
    # Total budget waktu utk SEMUA attempt 1 IP reverse (detik).
    # 300s = 5 menit/IP worst case. Dengan REVERSE_MAX_ATTEMPTS=50 & 
    # REVERSE_RETRY_BASE_DELAY=2s, budget 300s ≈ cukup utk 45-50 attempt.
    REVERSE_RETRY_TOTAL_BUDGET = 300
    # Domain scan tanpa proxy: retry loop terbatas
    DOMAIN_MAX_ATTEMPTS = 5
    
    # File output
    OUTPUT_FILES = {
        'movable_type': 'mv.txt',
        'movable_type_v4': 'mv4.txt',
        'processed_ips': 'processed_ips.txt',
        'cache': 'cache.db'
    }
    
    # Retry settings
    MAX_RETRIES = 3
    RETRY_DELAY = 2
    
    # Timeout settings
    TIMEOUT_REVERSE = 30
    TIMEOUT_SCAN = 10
    
    # ========== LEVEL 2 SMART SCAN SETTINGS ==========
    SAMPLE_SIZE = 10  # Jumlah sample IP untuk testing base
    MIN_DOMAINS_PER_IP = 20  # Minimal domain dari reverse IP
    MIN_GOOD_SAMPLES = 1
    
    @staticmethod
    def ensure_temp_dir():
        """Pastikan direktori temporary ada"""
        if not os.path.exists(Config.TEMP_DIR):
            os.makedirs(Config.TEMP_DIR)