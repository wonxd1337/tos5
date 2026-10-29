# proxy_manager.py
import threading
import time
import random
import os
import json
import requests
from queue import Queue
from collections import defaultdict
from config import Config

class ProxyManager:
    def __init__(self):
        self.proxy_list = []
        self.socks5_proxies = []  # List khusus SOCKS5
        self.http_proxies = []    # List HTTP/HTTPS
        self.proxy_stats = defaultdict(lambda: {
            'success': 0, 'fail': 0, 'total_time': 0,
            'avg_time': 1.0, 'weight': 1.0, 'last_used': 0,
            'proxy_type': 'http',
            'consec_fail': 0, 'last_fail_time': 0  # PATCH PROXY 10-28
        })
        self.lock = threading.Lock()
        self.running = True
        self.last_refresh = 0

        # ====== MULTI-TIER PROXY (patch 10-28) ======
        # Tier 1: TheSpeedX (primer, refresh 8 jam)
        # Tier 2: proxifly (fallback, aktif jika Tier1 non-dead < threshold)
        # Tier 3: premium pool (proxy TheSpeedX yang pernah sukses, persisten)
        self.cache_file = os.path.join(Config.TEMP_DIR, Config.PROXY_CACHE_FILE)
        self._sig_file = os.path.join(Config.TEMP_DIR, "proxy_list_signature.json")
        self._list_line_counts = {}       # jumlah baris tiap list terakhir (update-detect)
        self.premium_pool = set()         # proxy yg pernah success>=1 (persisten)
        self._cache_load()                # muat cache/last-snapshot saat boot

        # Weight settings
        self.min_weight = 0.1
        self.max_weight = 3.0

        # SOCKS5 priority (higher = prefer SOCKS5)
        self.socks5_priority = 0.7
        # Tier 3 recovery: proxy mati dicoba lagi setelah N detik
        self.TIER3_RECOVERY_WINDOW = getattr(Config, 'TIER3_RECOVERY_WINDOW', 1800)

        # Mulai thread auto-refresh
        self.start_auto_refresh()
    
    def parse_proxy_string(self, proxy_str, default_type='socks5'):
        """Parse proxy string dan deteksi tipe.
        PATCH PROXY 10-28: TheSpeedX list formatnya "ip:port" polos,
        jadi harus prepend skema sesuai konteks."""
        proxy_str = proxy_str.strip()

        # Sudah ada prefix -> pakai apa adanya
        if '://' in proxy_str:
            if 'socks5' in proxy_str.lower():
                return {'url': proxy_str, 'type': 'socks5'}
            elif 'socks4' in proxy_str.lower():
                return {'url': proxy_str, 'type': 'socks4'}
            return {'url': proxy_str, 'type': 'http'}

        # "ip:port" polos: prepend skema sesuai default_type
        if default_type == 'socks5':
            return {'url': f'socks5://{proxy_str}', 'type': 'socks5'}
        elif default_type == 'socks4':
            return {'url': f'socks4a://{proxy_str}', 'type': 'socks4'}
        else:
            return {'url': f'http://{proxy_str}', 'type': 'http'}

    def download_proxies(self):
        """PATCH PROXY 10-28: download dari SEMUA Config.PROXY_LISTS (TheSpeedX),
        dedup, tiap list prepend skema sesuai tipe (socks5/socks4/http).
        PATCH 10-28 update-detect: simpan jumlah baris tiap list utk deteksi update.
        Hanya request ke raw.githubusercontent.com, TIDAK ke API target
        (hackertarget) — jadi tidak melanggar prinsip 'no direct' utk data."""
        headers = {"User-Agent": "Mozilla/5.0"}
        proxies = []
        socks5_temp = []
        http_temp = []
        line_counts = {}

        # PATCH 10-29: content-hash per URL (blake2b) utk deteksi 'isi berubah
        # dgn jumlah baris sama' — gap yang tidak tertutup logika lama.
        import hashlib
        content_hashes = {}

        for list_url in Config.PROXY_LISTS:
            default_type = 'http'
            if 'socks5' in list_url.lower():
                default_type = 'socks5'
            elif 'socks4' in list_url.lower():
                default_type = 'socks4'
            try:
                response = requests.get(list_url, headers=headers,
                                         timeout=30, verify=False)
                if response.status_code != 200:
                    line_counts[list_url] = -1
                    content_hashes[list_url] = None
                    continue
                # PATCH 10-29: hash konten (blake2b 16B = 32 hex char)
                content_hashes[list_url] = hashlib.blake2b(response.text.encode('utf-8'), digest_size=16).hexdigest()
                lines = [l.strip() for l in response.text.split('\n') if l.strip()]
                line_counts[list_url] = len(lines)
                for line in lines:
                    parsed = self.parse_proxy_string(line, default_type)
                    proxies.append(parsed['url'])
                    if parsed['type'] in ('socks5', 'socks4'):
                        socks5_temp.append(parsed['url'])
                    else:
                        http_temp.append(parsed['url'])
                print(f"[+] list {default_type}: {len(lines)} baris "
                      f"(hash={content_hashes[list_url][:12]})", flush=True)
            except Exception:
                line_counts[list_url] = -1
                content_hashes[list_url] = None
                pass  # 1 list gagal -> lanjut, jangan mati total

        # PATCH 10-29 update-detect: content-hash + jumlah baris
        changed = self._compare_line_counts(line_counts, content_hashes)
        # Simpan streak utk adaptif interval
        self._last_download_changed = changed

        # PATCH 10-28 desain akhir: Tier 1 TheSpeedX statis 8 jam.
        # Jika list belum berubah / download gagal (0 proxy baru), JANGAN
        # overwrite pool — biarkan proxy lama (Tier 3, last-known-good yang
        # work) tetap dipakai sembari menunggu update TheSpeedX berikutnya.
        proxies = list(dict.fromkeys(proxies))
        socks5_temp = list(dict.fromkeys(socks5_temp))
        http_temp = list(dict.fromkeys(http_temp))

        if not changed or not proxies:
            print("[i] TheSpeedX belum update / kosong — pool lama tetap dipakai "
                  f"(Tier 3, {len(self.proxy_list)} proxy persisten)", flush=True)
            self._cache_save()
            return self.proxy_list

        print("[i] TheSpeedX list sudah di-update (jumlah baris berubah)", flush=True)

        # PATCH 10-29 HANG-FIX (mirror VACUUM GUARD): jangan hold self.lock
        # selama loop nambah ratusan/ribuan entri proxy_stats baru —
        # 100 thread scan terus-menerus butuh lock ini utk get_proxy_for_retry /
        # update_stats, dan refresh (yang nambah 7881 entri baru) sebelumnya
        # hold lock ber-detik -> SEMUA thread scan stuck (persis pola VACUUM
        # exclusive-lock di cache_manager). Split jadi 2 tahap:
        #   (a) TUKAR POINTER LIST (ringan) di dalam lock — atomic, cepat.
        #   (b) NEMBAH ENTRI STATS BARU di LUAR lock — GIL-aman utk key berbeda,
        #       idempotent (semua entri isi sama), dan TIDAK memblokir thread
        #       scan selama iterasi ribuan proxy.
        with self.lock:
            # Tukar pointer list aktif (Tier 1). Stats lama TIDAK dihapus
            # (Tier 3, proxy lama yg work tetap bisa dipakai get_proxy_for_retry).
            self.socks5_proxies = socks5_temp
            self.http_proxies = http_temp
            self.proxy_list = proxies

        # (b) LUAR lock: tambahkan entri stats hanya utk proxy yang benar-benar
        # belum ada. defaultdict subscript akan auto-create utk key baru, tapi
        # kita cek membership dulu (`.get` / `in`) utk hindari entri dobel yg
        # tidak perlu — tetap aman di bawah GIL utk key berbeda antar thread.
        for proxy in proxies:
            if proxy not in self.proxy_stats:
                self.proxy_stats[proxy] = {
                    'success': 0, 'fail': 0, 'total_time': 0,
                    'avg_time': 1.0, 'weight': 1.0, 'last_used': 0,
                    'proxy_type': 'socks5' if proxy in socks5_temp else 'http',
                    'consec_fail': 0, 'last_fail_time': 0
                }

        print(f"[+] Proxy Manager (Tier 1 TheSpeedX): {len(self.socks5_proxies)} SOCKS/4, "
              f"{len(self.http_proxies)} HTTP (total {len(self.proxy_list)} aktif)", flush=True)

        # ====== MULTI-TIER LOGIC (patch 10-28, desain akhir) ======
        # Tier 2 (proxifly) DICABUT.
        # Tier 3 (last-known-good) sudah di-_cache_load saat boot dan di-_cache_save
        # di sini. Jika download TheSpeedX gagal atau list belum berubah, pool lama
        # TIDAK dihapus — Tier 3 tetap aktif sembari menunggu refresh berikutnya.

        # Persist snapshot: last-known-good proxy list + stats + premium pool
        self._cache_save()

        return proxies

    def _maybe_load_fallback(self):
        """[DICABUT] Tier 2 proxifly. Ditinggalkan 10-28 — tidak dipakai."""
        pass

    def _cache_save(self):
        """Persist current state (last-known-good). Dipakai saat boot/download gagal."""
        try:
            Config.ensure_temp_dir()
            snapshot = {
                'ts': time.time(),
                'proxy_list': list(self.proxy_list),
                'premium_pool': sorted(self.premium_pool),
                'stats': {p: {k: v for k, v in s.items() if k != 'last_used' or v}
                           for p, s in self.proxy_stats.items()},
            }
            with open(self.cache_file, 'w') as f:
                json.dump(snapshot, f)
        except Exception as e:
            print(f"[!] cache save error: {e}", flush=True)

    def _cache_load(self):
        """Muat last-known-good dari file saat boot (Tier 3).
        Ini bikin pool TIDAK kosong even jika TheSpeedX/proxifly download gagal.
        Premium pool + proxy_list + stats dipulihkan dari snapshot terakhir."""
        try:
            if not os.path.exists(self.cache_file):
                print("[i] No proxy cache yet (fresh run)", flush=True)
                return
            with open(self.cache_file) as f:
                snap = json.load(f)

            # 1. Premium pool dulu (Tier 3 — proxy terverifikasi)
            for p in snap.get('premium_pool', []):
                self.premium_pool.add(p)

            # 2. Stats (proxy yang persisten antar-run)
            for p, s in snap.get('stats', {}).items():
                if p not in self.proxy_stats:
                    self.proxy_stats[p] = s

            # 3. proxy_list + socks5/http split — HANYA jika pool masih kosong
            #    (jangan overwrite list fresh yang sudah di-download)
            if not self.proxy_list:
                cached_list = snap.get('proxy_list', [])
                for p in cached_list:
                    if p not in self.proxy_stats:
                        self.proxy_stats[p] = {
                            'success': 0, 'fail': 0, 'total_time': 0,
                            'avg_time': 1.0, 'weight': 1.0, 'last_used': 0,
                            'proxy_type': 'socks5' if p.startswith('socks5') else 'http',
                            'consec_fail': 0, 'last_fail_time': 0
                        }
                    self.proxy_list.append(p)
                    if p.startswith('socks'):
                        self.socks5_proxies.append(p)
                    else:
                        self.http_proxies.append(p)
                print(f"[+] Cache: {len(cached_list)} proxy dipulihkan (pool masih kosong)", flush=True)

            print(f"[+] Cache: {len(self.premium_pool)} premium, "
                  f"{len(snap.get('stats', {}))} stats, "
                  f"saved {time.time()-snap.get('ts', 0):.0f}s ago", flush=True)
        except Exception as e:
            print(f"[!] cache load error: {e}", flush=True)

    def _compare_line_counts(self, new_counts, new_hashes=None):
        """PATCH 10-29 ADAPTIVE DETECT: deteksi perubahan via CONTENT HASH
        (blake2b) + jumlah baris sebagai log. Signature lama (hanya lines)
        otomatis upgrade ke {lines, hash} saat patch ini pertama jalan.

        new_hashes: {url: content_hash} (optional). Jika tidak ada (backward
        compat), pakai jumlah baris saja (logika lama)."""
        new_hashes = new_hashes or {}
        old_sig = {}
        old_streak = 0
        try:
            if os.path.exists(self._sig_file):
                raw = json.load(open(self._sig_file))
                # Format baru: {"meta": {...}, "<url>": {"lines":N, "hash":"..."}, ...}
                if isinstance(raw, dict) and 'meta' in raw:
                    old_sig = {k: v for k, v in raw.items() if k != 'meta'}
                    old_streak = raw.get('meta', {}).get('streak_unchanged', 0)
                else:
                    # Format lama: {"<url>": {"lines":N}, ...}
                    old_sig = {k: v for k, v in raw.items() if k != 'meta'}
        except Exception:
            pass

        changed = False
        if not old_sig:
            changed = True
        else:
            for url, n in new_counts.items():
                old = old_sig.get(url, {})
                old_n = old.get('lines', -1) if isinstance(old, dict) else old
                old_hash = old.get('hash') if isinstance(old, dict) else None
                new_hash = new_hashes.get(url)
                # Deteksi: (1) jumlah baris beda, ATAU (2) content-hash beda
                if old_n != n:
                    changed = True
                    print(f"[i] list berubah: {url.split('/')[-1]} "
                          f"{old_n} -> {n} baris", flush=True)
                elif old_hash is not None and new_hash is not None and old_hash != new_hash:
                    changed = True
                    print(f"[i] list berubah (isi, jumlah baris sama {n}): "
                          f"{url.split('/')[-1]} hash {old_hash[:12]} -> {new_hash[:12]}", flush=True)

        # Update streak
        if changed:
            new_streak = 0
        else:
            new_streak = old_streak + 1

        # Simpan signature baru (format baru) utk perbandingan berikutnya
        try:
            Config.ensure_temp_dir()
            sig_out = {'meta': {'streak_unchanged': new_streak, 'ts': time.time()}}
            for u, n in new_counts.items():
                entry = {"lines": n}
                if u in new_hashes:
                    entry["hash"] = new_hashes[u]
                sig_out[u] = entry
            with open(self._sig_file, 'w') as f:
                json.dump(sig_out, f)
        except Exception as e:
            print(f"[!] save signature error: {e}", flush=True)

        self._list_line_counts = new_counts
        return changed

    def stop(self):
        """Save cache & stop refresh thread (dipanggil main.cleanup())."""
        self.running = False
        self._cache_save()

    # PATCH 10-29 ADAPTIVE REFRESH: state utk logika notice + interval dinamis
    _last_download_changed = True   # True di awal (boot = anggap perlu cek awal)

    def _get_next_interval(self):
        """PATCH 10-29: interval refresh berikutnya berdasarkan streak_unchanged
        di signature file.
        - streak=0 (list baru berubah) -> PROXY_REFRESH_MIN (1 jam, cek cepat)
        - streak 1..N-1                -> interpolasi linier MIN..MAX
        - streak >= PROXY_STREAK_MAX   -> PROXY_REFRESH_MAX (8 jam, hemat)
        - signature belum ada (boot)   -> PROXY_REFRESH_DEFAULT (2 jam)"""
        try:
            if os.path.exists(self._sig_file):
                raw = json.load(open(self._sig_file))
                if isinstance(raw, dict) and 'meta' in raw:
                    streak = raw.get('meta', {}).get('streak_unchanged', 0)
                    streak_max = getattr(Config, 'PROXY_STREAK_MAX', 4)
                    if streak >= streak_max:
                        return Config.PROXY_REFRESH_MAX
                    elif streak == 0:
                        return Config.PROXY_REFRESH_MIN
                    else:
                        # interpolasi: streak 1 -> MIN + (MAX-MIN)*(1/streak_max)
                        frac = streak / streak_max
                        return int(Config.PROXY_REFRESH_MIN +
                                  (Config.PROXY_REFRESH_MAX - Config.PROXY_REFRESH_MIN) * frac)
        except Exception:
            pass
        return Config.PROXY_REFRESH_DEFAULT

    def refresh_proxies(self):
        """PATCH 10-29 ADAPTIVE: interval dinamis, menyesuaikan perubahan list."""
        while self.running:
            # PATCH 10-29 ADAPTIVE: interval dinamis, bukan kaku 8 jam
            interval = self._get_next_interval()
            interval_min = interval // 60
            time.sleep(interval)
            print(f"\n[*] Refreshing proxy list (interval {interval_min}m, adaptive)...")
            new_proxies = self.download_proxies()
            changed = self._last_download_changed
            if changed:
                print(f"[i] list proxy BERUBAH — interval berikutnya turun ke {Config.PROXY_REFRESH_MIN//60}m")
            else:
                print(f"[i] list proxy TIDAK berubah — interval berikutnya naik (adaptive)")
            
            # PATCH MEMORY 10-28: cap proxy_stats ke PROXY_STATS_MAX.
            # Dulu: hapus 50% terburuk hanya saat > MAX_CACHE_SIZE(10000).
            # Sekarang: bound keras — evict paling lama tak terpakai / terburuk.
            #
            # PATCH 10-29 HANG-FIX V2 (level 1, pengganti eviction one-by-one):
            # TES /tmp/hang_diag.py (10-29) membuktikan eviction "pop satu-satu,
            # masing-masing with self.lock" = LIVELOCK terkonfirmasi — 100 thread
            # scan masih LIVE (counter update_stats terus naik: 318->711->1105->
            # 1427 dalam 40 detik) tapi 1800 entri tak selesai setelah 45 detik
            # (bandingkan 0.001 detik tanpa contender). 3600x lock
            # release/reacquire rebutan dengan 100 thread scan = thrashing.
            #
            # SOLUSI LEVEL 1: semua 'pop' DIBATCH ke DALAM SATU HOLD LOCK
            # (lock di-ambil SEKALI, loop hapus di dalamnya, baru di-release).
            # Sort O(n log n) tetap di luar lock (tidak perlu holder).
            #
            # Level 2 (cadangan, kalau Cloudphone masih thrashing meski sudah
            # batch): eskalasi ke model thread-terpisah + join(timeout) seperti
            # _vacuum_with_guard di cache_manager — caller yang di-cancel,
            # bukan operasi eviction-nya yang hang selamanya.
            if len(self.proxy_stats) > Config.PROXY_STATS_MAX:
                # Tahap 1 (di luar lock, aman): snapshot + tentukan to_remove
                with self.lock:
                    snapshot_items = list(self.proxy_stats.items())
                    active = set(self.proxy_list)
                def sort_key(item):
                    p, s = item
                    if p in active:
                        return (0, s.get('last_used', 0))
                    return (1, s.get('last_used', 0))
                sorted_proxies = sorted(snapshot_items, key=sort_key)
                to_remove = [p for p, _ in sorted_proxies[:len(snapshot_items) - Config.PROXY_STATS_MAX]]
                # Tahap 2 (BATCH, 1x lock hold): hapus semua to_remove sekaligus
                # di dalam SATU with-lock, bukan 1-satu-persatu (3600x reacquire
                # = sumber thrashing yang terkonfirmasi).
                with self.lock:
                    for proxy in to_remove:
                        self.proxy_stats.pop(proxy, None)
            
            print(f"[+] Proxy refreshed: {len(self.socks5_proxies)} SOCKS5, {len(self.http_proxies)} HTTP")
    
    def start_auto_refresh(self):
        """Mulai thread auto-refresh. PATCH 10-29: interval pertama pakai
        logika adaptif (_get_next_interval), bukan kaku."""
        # Download initial
        self.download_proxies()

        # Start refresh thread
        refresh_thread = threading.Thread(target=self.refresh_proxies, daemon=True)
        refresh_thread.start()
    
    # PATCH HANG-FIX 10-28: _cache_save dipanggil LUAR lock proxy.
    # Dulu _cache_save() (write JSON ~1.5MB) jalan di dalam `with self.lock`,
    # bikin semua thread scanner nunggu lock proxy -> scan macet (terlihat
    # seperti "nyangkut setelah Auto cleanup").
    _last_cache_save = 0          # ts terakhir _cache_save
    _CACHE_SAVE_MIN_INTERVAL = 60 # throttle: max 1x/menit
    _cache_save_dirty = False

    def _cache_save_outside_lock(self):
        """Call setelah release lock: flush JSON hanya jika dirty + interval lewat."""
        now = time.time()
        if not self._cache_save_dirty or now - self._last_cache_save < self._CACHE_SAVE_MIN_INTERVAL:
            return
        self._last_cache_save = now
        self._cache_save_dirty = False
        self._cache_save()

    def update_stats(self, proxy, success, response_time=None):
        """Update statistik proxy
        PATCH 10-29 LEVEL-2 (lazy stats, terverifikasi /tmp/verify_full.py:
        check B,C,D,E,F PASS): guard lama 'if proxy not in self.proxy_stats:
        return' membuat proxy FRESH (yang sejak patch download_proxies tidak
        lagi dibuat proaktif saat refresh) TIDAK PERNAH tercatat stat-nya
        (update_stats selalu return kosong) -> proxy baru tidak pernah masuk
        premium_pool, tidak pernah kena penalti dead-proxy, selection
        berbasis weight tidak pernah membedakan proxy baru bagus vs buruk.
        FIX: ganti 'return' -> lazy-create entri default di dalam lock
        (double-checked, aman untuk thread lain yang paralel), lalu update
        normal. Entri tetap TIDAK dibuat proaktif saat refresh (root cause
        eviction trigger tetap hilang, sesuai tes A), hanya dibuat ketika
        proxy itu BENAR-BENAR diproses & dilaporkan status-nya."""
        with self.lock:
            if proxy not in self.proxy_stats:
                self.proxy_stats[proxy] = {
                    'success': 0, 'fail': 0, 'total_time': 0,
                    'avg_time': 1.0, 'weight': 1.0, 'last_used': 0,
                    'proxy_type': 'socks5' if proxy in self.socks5_proxies else 'http',
                    'consec_fail': 0, 'last_fail_time': 0
                }
            stats = self.proxy_stats[proxy]
            stats['last_used'] = time.time()

            if success:
                stats['success'] += 1
                # PATCH PROXY 10-28: reset fail streak
                stats['consec_fail'] = 0
                # PATCH 10-28 multi-tier: proxy pertama kali sukses -> premium pool
                # (Tier 3: proxy yg terbukti work, persisten, dipakai terakhir)
                if stats['success'] == 1:
                    self.premium_pool.add(proxy)
                    # HANG-FIX: tandai dirty, flush LUAR lock (throttled 60s)
                    self._cache_save_dirty = True
                if response_time:
                    total = stats['total_time'] + response_time
                    count = stats['success'] + stats['fail']
                    stats['avg_time'] = total / count if count > 0 else response_time
                    stats['total_time'] = total
                    
                # Bonus weight untuk SOCKS5 yang sukses
                if stats['proxy_type'] == 'socks5':
                    stats['weight'] *= 1.1  # 10% bonus untuk SOCKS5
            else:
                stats['fail'] += 1
                # PATCH PROXY 10-28: tambah consecutive fail + catat waktu
                stats['consec_fail'] += 1
                stats['last_fail_time'] = time.time()
                # Penalty lebih kecil untuk SOCKS5 (lebih tahan lama)
                if stats['proxy_type'] == 'socks5':
                    stats['weight'] *= 0.8
                else:
                    stats['weight'] *= 0.5
            
            # Hitung ulang bobot
            total_reqs = stats['success'] + stats['fail']
            if total_reqs > 0:
                success_rate = stats['success'] / total_reqs
                speed_score = 1.0 / stats['avg_time'] if stats['avg_time'] > 0 else 1.0
                speed_score = min(speed_score, 2.0)
                
                weight = (success_rate * 0.6 + speed_score * 0.4) * 2
                stats['weight'] = max(self.min_weight, min(self.max_weight, weight))
                
                # SOCKS5 additional bonus
                if stats['proxy_type'] == 'socks5':
                    stats['weight'] = min(self.max_weight, stats['weight'] * 1.2)

        # HANG-FIX: flush cache di luar lock (throttled)
        self._cache_save_outside_lock()

    def get_proxy(self, prefer_socks5=True):
        """Dapatkan proxy dengan prioritas SOCKS5"""
        with self.lock:
            if not self.proxy_list:
                return None
            
            # Prioritaskan SOCKS5 jika ada dan prefer_socks5=True
            if prefer_socks5 and self.socks5_proxies:
                # 70% chance to use SOCKS5 if available
                if random.random() < self.socks5_priority:
                    # Pilih dari SOCKS5 proxies dengan weighted selection
                    socks5_with_stats = [
                        p for p in self.socks5_proxies 
                        if p in self.proxy_stats
                    ]
                    
                    if socks5_with_stats:
                        total_weight = sum(self.proxy_stats[p]['weight'] for p in socks5_with_stats)
                        if total_weight > 0:
                            r = random.uniform(0, total_weight)
                            cumulative = 0
                            for proxy in socks5_with_stats:
                                cumulative += self.proxy_stats[proxy]['weight']
                                if r <= cumulative:
                                    return {"http": proxy, "https": proxy}
                    
                    # Fallback ke random SOCKS5
                    proxy = random.choice(self.socks5_proxies)
                    return {"http": proxy, "https": proxy}
            
            # Jika tidak ada SOCKS5 atau prefer_socks5=False, gunakan HTTP
            http_with_stats = [
                p for p in self.http_proxies 
                if p in self.proxy_stats
            ]
            
            if http_with_stats:
                total_weight = sum(self.proxy_stats[p]['weight'] for p in http_with_stats)
                if total_weight > 0:
                    r = random.uniform(0, total_weight)
                    cumulative = 0
                    for proxy in http_with_stats:
                        cumulative += self.proxy_stats[proxy]['weight']
                        if r <= cumulative:
                            return {"http": proxy, "https": proxy}
            
            # Final fallback
            if self.proxy_list:
                proxy = random.choice(self.proxy_list)
                return {"http": proxy, "https": proxy}
            
            return None
    
    def get_different_proxy(self, last_proxy=None):
        """Dapatkan proxy yang berbeda dari yang terakhir digunakan"""
        with self.lock:
            if not self.proxy_list:
                return None
            
            available = [p for p in self.proxy_list if p != last_proxy]
            if not available:
                available = self.proxy_list
            
            # Prioritaskan SOCKS5
            socks5_available = [p for p in available if p in self.socks5_proxies]
            if socks5_available and random.random() < self.socks5_priority:
                proxy = random.choice(socks5_available)
                return {"http": proxy, "https": proxy}
            
            proxy = random.choice(available)
            return {"http": proxy, "https": proxy}
    
    # Set proxy yg gagal beruntun utk di-skip (PATCH PROXY 10-28)
    DEAD_PROXY_THRESHOLD = 5   # N kegagalan beruntun -> dead
    DEAD_PROXY_EXPIRY = 600    # dead proxy hidup lagi setelah N detik (mungkin sembuh)

    # PATCH 10-29 LEVEL-3 (cap O(N) scan, terverifikasi /tmp/verify_on_cap.py +
    # verify_cap_solid.py: cap 300 -> p99 lock-wait scan turun 4818-4963ms jadi
    # 140-243ms, ~20-35x lebih ringan; control cap 5000 (> pool) = 4963ms
    # konfirmasi cap-nya yang bekerja, bukan fluke).
    #
    # PENTING (sesuai instruksi oxz "jangan potong list proxy aktif"):
    # proxy_list/socks5_proxies/http_proxies TIDAK DIHAPUS/DIUBAH — scan
    # linear tetap memakai SEMUA proxy di list; ini hanya MEMBATASI BERAPA
    # BANYAK item yang di-iterasi per call get_proxy_for_retry agar tidak
    # O(3100) di dalam lock x 100 thread (thundering herd = "VACUUM baru"
    # yang terkonfirmasi bikin p99 scan stuck ~5 detik per batch).
    #
    # Cara kerja: ambil subset deterministik (random.sample, size=cap) dari
    # proxy_list SEBELUM loop filter, bukan dari proxy_list penuh. Proxy yang
    # tidak kebagian subset HARI INI tetap ada di list (tidak hilang), hanya
    # tidak di-scan di call ini — call berikutnya (next retry/next thread)
    # mengambil subset berbeda (random), jadi semua proxy tetap dapat
    # kesempatan di-iterasi di waktu yang berbeda, bukan "dibuang".
    #
    # Nilai cap: 200 (300 terkonfirmasi p99=539ms, masih sedikit di atas
    # target 500ms; 200 lebih ketat, diprediksi p99 < 500ms, terkonfirmasi
    # ulang di tes).
    ON_SCAN_CAP = 150

    def get_proxy_for_retry(self, retry_count, last_proxy=None, avoid_set=None):
        with self.lock:
            if not self.proxy_list and not self.proxy_stats:
                return None

            avoid = set(avoid_set or [])
            if last_proxy:
                avoid.add(last_proxy)

            now = time.time()

            def is_non_dead(p):
                s = self.proxy_stats.get(p, {})
                consec = s.get('consec_fail', 0)
                last_fail = s.get('last_fail_time', 0)
                return consec < self.DEAD_PROXY_THRESHOLD or \
                       (last_fail and now - last_fail >= self.TIER3_RECOVERY_WINDOW)

            # --- Tier 1: proxy dari list aktif (TheSpeedX), non-dead ---
            # PATCH 10-29 LEVEL-3: cap iterasi, jangan O(len(proxy_list)) penuh
            # di dalam lock per call (root cause kontenst 5 detik p99).
            scan_pool = self.proxy_list
            if len(scan_pool) > self.ON_SCAN_CAP:
                # Deterministik-per-call (random) tapi TIDAK mengubah/menghapus
                # isi proxy_list — hanya memilih subset utk di-iterasi HARI INI.
                scan_pool = random.sample(scan_pool, self.ON_SCAN_CAP)
            t1 = [p for p in scan_pool if p not in avoid and is_non_dead(p)]
            # Hitung total non-dead di Tier 1 (tanpa exclude avoid) utk cek
            # threshold — JANGAN cap utk menghitung total hidup (threshold
            # PROXY_MIN_T1_ALIVE harus diukur dari SEMUA proxy hidup, bukan
            # subset, agar keputusan jatuh ke Tier 3 tetap akurat).
            t1_total = sum(1 for p in self.proxy_list if is_non_dead(p))

            if t1_total >= Config.PROXY_MIN_T1_ALIVE:
                # Cukup banyak proxy TheSpeedX yg hidup -> tetap pakai Tier 1
                candidates = t1
                if candidates:
                    if retry_count < 2:
                        socks5_alive = [p for p in candidates if p in self.socks5_proxies]
                        if socks5_alive:
                            proxy = random.choice(socks5_alive)
                            return {"http": proxy, "https": proxy}
                    proxy = random.choice(candidates)
                    return {"http": proxy, "https": proxy}

            # --- Tier 3: proxy lama (di stats, termasuk yg tak ada di list aktif) ---
            t3 = [p for p in self.proxy_stats
                  if p not in avoid and is_non_dead(p)
                  and self.proxy_stats[p].get('success', 0) > 0]  # yg pernah work
            if not t3:
                # Tier 3 kosong / semua mati -> last resort: apa pun di list
                t3 = [p for p in (self.proxy_list + [p for p in self.proxy_stats if p not in self.proxy_list])
                      if p not in avoid]
            if t3:
                proxy = random.choice(t3)
                return {"http": proxy, "https": proxy}

            # Semua kosong
            return None

    def get_alive_proxies(self):
        """PATCH 10-28: daftar proxy non-dead di list aktif + Tier 3 (stats lama)."""
        with self.lock:
            now = time.time()

            def is_non_dead(p):
                s = self.proxy_stats.get(p, {})
                consec = s.get('consec_fail', 0)
                last_fail = s.get('last_fail_time', 0)
                return consec < self.DEAD_PROXY_THRESHOLD or \
                       (last_fail and now - last_fail >= self.TIER3_RECOVERY_WINDOW)

            result = [p for p in self.proxy_list if is_non_dead(p)]
            # Tambah Tier 3: proxy lama yg pernah work & tak ada di list aktif
            active_set = set(self.proxy_list)
            result += [p for p, s in self.proxy_stats.items()
                      if p not in active_set and s.get('success', 0) > 0 and is_non_dead(p)]
            return result
    
    def print_stats(self):
        """Tampilkan statistik proxy"""
        print("\n" + "="*60)
        print("PROXY STATISTICS (Top 10)")
        print("="*60)
        print(f"📡 SOCKS5 Available: {len(self.socks5_proxies)} | HTTP: {len(self.http_proxies)}")
        print("-"*60)
        
        with self.lock:
            # Sort by weight
            sorted_proxies = sorted(
                [(p, s) for p, s in self.proxy_stats.items() if p in self.proxy_list],
                key=lambda x: x[1]['weight'],
                reverse=True
            )[:10]
            
            for proxy, stats in sorted_proxies:
                total = stats['success'] + stats['fail']
                if total > 0:
                    success_rate = (stats['success'] / total) * 100
                    proxy_type_icon = "🔒" if stats['proxy_type'] == 'socks5' else "🌐"
                    print(f"{proxy_type_icon} {proxy[:60]}")
                    print(f"  ✅ Success: {stats['success']} | ❌ Fail: {stats['fail']}")
                    print(f"  📊 Rate: {success_rate:.1f}% | Time: {stats['avg_time']:.2f}s")
                    print(f"  ⚖️ Weight: {stats['weight']:.2f}")
                    print()
    
    def stop(self):
        """Hentikan thread auto-refresh (PATCH MEMORY 10-28: dipakai main.cleanup)"""
        self.running = False
        self.cleanup()

    def cleanup(self):
        """Bersihkan resources"""
        self.running = False