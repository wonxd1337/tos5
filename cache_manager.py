# cache_manager.py - FULL VERSION FOR TERMUX (patch memory 10-28:
#   - koneksi SQLite per-thread (threading.local), bukan per-call
#   - WAL mode + synchronous=NORMAL
#   - tier L1 in-memory LRU (reverse cache + processed IPs) -> hemat I/O fsync
#   - write-back batch ke SQLite (tiap L1_WRITEBACK_BATCH entri baru)
#   - buffer flush processed_ips.txt
#   - auto-purge in-memory tiap L1_PURGE_CHECK_INTERVAL ops
import sqlite3
import json
import time
import os
import threading
import shutil
from collections import OrderedDict
from config import Config

class _ThreadLocalDB:
    """Koneksi SQLite per-thread + WAL. Koneksi tidak pernah close selama process.
    sqlite3 object tetap thread-safe karena hanya thread yang membuatnya yang pakai."""
    def __init__(self, db_path):
        self.db_path = db_path
        self.local = threading.local()

    def conn(self):
        c = getattr(self.local, 'conn', None)
        if c is None:
            c = sqlite3.connect(self.db_path, timeout=30)
            cur = c.cursor()
            cur.execute('PRAGMA journal_mode=WAL')
            cur.execute('PRAGMA synchronous=NORMAL')
            cur.execute('PRAGMA temp_store=MEMORY')
            cur.execute('PRAGMA cache_size=-8192')  # 8MB per-thread
            self.local.conn = c
        return c

    def close_all(self):
        c = getattr(self.local, 'conn', None)
        if c is not None:
            try:
                c.close()
            except Exception:
                pass
            self.local.conn = None


def _lru_purge(od: OrderedDict, max_size: int):
    """Purge LRU: hapus item terlama sampai <= max_size."""
    while len(od) > max_size:
        od.popitem(last=False)


class CacheManager:
    def __init__(self):
        # Gunakan full path untuk Termux
        self.temp_dir = self._get_full_temp_dir()
        self.db_path = os.path.join(self.temp_dir, Config.OUTPUT_FILES['cache'])
        self.processed_ips_path = os.path.join(self.temp_dir, Config.OUTPUT_FILES['processed_ips'])
        self.lock = threading.Lock()

        # Per-thread SQLite connection + WAL
        self.db = _ThreadLocalDB(self.db_path)

        # ====== TIER L1: in-memory LRU ======
        # reverse cache: key = cache_key (mis. "tnt_1.2.3.4"), value = list domain
        #OrderedDict = LRU (move_to_end saat akses)
        self.l1_reverse = OrderedDict()      # key -> (domains, timestamp, source)
        self.l1_reverse_dirty = set()        # key yang belum write-back ke SQLite
        self.l1_processed = OrderedDict()    # ip -> (timestamp, status)
        self._l1_processed_dirty = set()

        # Buffer flush processed_ips.txt
        self._processed_file_buf = []
        self._processed_file_lock = threading.Lock()

        # Counter ops untuk trigger auto-purge
        self._ops_count = 0

        # Inisialisasi database (via thread ini)
        self.init_database()

        # Prewarm L1: muat data penting dari SQLite ke memori sekali saat boot
        self._prewarm_l1()

        # Mulai thread cleanup
        self.start_cleanup_thread()
    
    def _get_full_temp_dir(self):
        """Dapatkan full path temporary directory untuk Termux"""
        temp_dir = Config.TEMP_DIR
        
        # Expand user home jika perlu
        temp_dir = os.path.expanduser(temp_dir)
        
        # Convert ke absolute path
        temp_dir = os.path.abspath(temp_dir)
        
        # Pastikan direktori ada
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir, exist_ok=True)
        
        return temp_dir
    
    def init_database(self):
        """Inisialisasi database SQLite dengan full path + WAL"""
        Config.ensure_temp_dir()
        
        # Pastikan direktori temp ada
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # Koneksi setup via thread ini (per-thread conn dipakai utk operasi)
        conn = self.db.conn()
        cursor = conn.cursor()
        
        # Enable foreign keys; auto_vacuum dinonaktifkan (10-29):
        # auto_vacuum=1 membuat VACUUM membESARKAN file (0.3->0.8MB, teramati
        # di Cloudphone). auto_vacuum=0 (default) + VACUUM terjadwal (DB besar
        # saja) = file mengecil dengan benar.
        cursor.execute('PRAGMA foreign_keys = ON')
        cursor.execute('PRAGMA auto_vacuum = 0')
        cursor.execute('PRAGMA journal_mode=WAL')
        cursor.execute('PRAGMA synchronous=NORMAL')
        
        # Tabel untuk cache reverse IP
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reverse_ip_cache (
                ip TEXT PRIMARY KEY,
                domains TEXT,
                timestamp REAL,
                source TEXT
            )
        ''')
        
        # Tabel untuk hasil scan
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                domain TEXT PRIMARY KEY,
                result TEXT,
                timestamp REAL
            )
        ''')
        
        # Tabel untuk tracking IP diproses
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed_ips (
                ip TEXT PRIMARY KEY,
                timestamp REAL,
                status TEXT
            )
        ''')
        
        # Index untuk performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON reverse_ip_cache(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_proc_timestamp ON processed_ips(timestamp)')
        
        conn.commit()
        # JANGAN close — koneksi ini jadi milik thread init, dipergunakan seterusnya
        
        print(f"[✓] Database initialized at: {self.db_path} (WAL, per-thread conn)")
    
    def _ops_maybe_purge(self):
        """Auto-purge L1 tiap N ops: buang item basi + evict LRU + write-back batch"""
        self._ops_count += 1
        if self._ops_count % Config.L1_PURGE_CHECK_INTERVAL != 0:
            return
        now = time.time()
        with self.lock:
            # Purge reverse cache: TTL habis
            stale = [k for k, (d, ts, s) in self.l1_reverse.items()
                     if now - ts > Config.REVERSE_CACHE_TTL]
            for k in stale:
                self.l1_reverse.pop(k, None)
            # Purge processed: TTL per status
            # - 'empty' (negative cache): NEGATIVE_CACHE_TTL (24 jam)
            # - success/lain: PROCESSED_TTL (0 = permanen)
            stale_p = []
            for k, ent in self.l1_processed.items():
                ts, status = ent if isinstance(ent, tuple) else (ent, 'success')
                ttl = (Config.NEGATIVE_CACHE_TTL if status == 'empty'
                       else Config.PROCESSED_TTL)
                if ttl > 0 and now - ts > ttl:
                    stale_p.append(k)
            for k in stale_p:
                self.l1_processed.pop(k, None)
                self._l1_processed_dirty.discard(k)
            # Evict LRU overflow
            _lru_purge(self.l1_reverse, Config.L1_REVERSE_CACHE_MAX)
            _lru_purge(self.l1_processed, Config.L1_PROCESSED_MAX)
            # Write-back batch entri dirty ke SQLite
            if len(self.l1_reverse_dirty) >= Config.L1_WRITEBACK_BATCH or \
               len(self._l1_processed_dirty) >= Config.L1_WRITEBACK_BATCH:
                self._writeback_locked(now)
        if stale:
            print(f"[~] L1 purge: {len(stale)} reverse cache basi dibuang, L1 rev={len(self.l1_reverse)} proc={len(self.l1_processed)}")

    def _writeback_locked(self, now=None):
        """Write entri L1 dirty ke SQLite (dipanggil dengan self.lock sudah dipegang)"""
        try:
            conn = self.db.conn()
            cur = conn.cursor()
            if self.l1_reverse_dirty:
                cur.executemany(
                    'INSERT OR REPLACE INTO reverse_ip_cache (ip, domains, timestamp, source) VALUES (?, ?, ?, ?)',
                    [(k, json.dumps(d), ts, s)
                     for k, (d, ts, s) in ((k, self.l1_reverse[k]) for k in self.l1_reverse_dirty)]
                )
                self.l1_reverse_dirty.clear()
            if self._l1_processed_dirty:
                cur.executemany(
                    'INSERT OR REPLACE INTO processed_ips (ip, timestamp, status) VALUES (?, ?, ?)',
                    [(k, ts, status) for k, (ts, status) in
                     ((k, self.l1_processed[k]) for k in self._l1_processed_dirty)]
                )
                self._l1_processed_dirty.clear()
            conn.commit()
        except Exception as e:
            print(f"[-] Write-back error (data aman di L1, akan dicoba lagi): {e}")

    def _prewarm_l1(self):
        """Muat SQLite -> L1 saat boot, agar hot-start tidak re-scan IP lama"""
        try:
            conn = self.db.conn()
            cur = conn.cursor()
            cur.execute(
                f"SELECT ip, domains, timestamp FROM reverse_ip_cache "
                f"WHERE timestamp > ? ORDER BY timestamp DESC LIMIT ?",
                (time.time() - Config.REVERSE_CACHE_TTL, Config.L1_REVERSE_CACHE_MAX)
            )
            for ip, dom, ts in cur.fetchall():
                try:
                    self.l1_reverse[ip] = (json.loads(dom), ts, '')
                except Exception:
                    pass
            _lru_purge(self.l1_reverse, Config.L1_REVERSE_CACHE_MAX)

            cur.execute(
                "SELECT ip, timestamp, status FROM processed_ips ORDER BY timestamp DESC LIMIT ?",
                (Config.L1_PROCESSED_MAX,)
            )
            for ip, ts, status in cur.fetchall():
                self.l1_processed[ip] = (ts, (status or 'success'))
            _lru_purge(self.l1_processed, Config.L1_PROCESSED_MAX)
            print(f"[~] L1 prewarm: {len(self.l1_reverse)} reverse, {len(self.l1_processed)} processed")
        except Exception as e:
            print(f"[!] L1 prewarm error (lanjut tanpa prewarm): {e}")

    def get_reverse_cache(self, ip):
        """Ambil cache reverse IP — cek L1 dulu, baru SQLite"""
        with self.lock:
            entri = self.l1_reverse.get(ip)
            if entri is not None:
                domains, ts, _src = entri
                self.l1_reverse.move_to_end(ip)
                if time.time() - ts < Config.REVERSE_CACHE_TTL:
                    return domains
                # basi: buang
                self.l1_reverse.pop(ip, None)
                self.l1_reverse_dirty.discard(ip)
            self._ops_maybe_purge()
        # L1 miss -> SQLite (tanpa global lock, conn per-thread)
        try:
            cur = self.db.conn().cursor()
            cur.execute(
                'SELECT domains, timestamp FROM reverse_ip_cache WHERE ip = ?',
                (ip,)
            )
            row = cur.fetchone()
            if row:
                domains, timestamp = row
                if time.time() - timestamp < Config.REVERSE_CACHE_TTL:
                    with self.lock:
                        self.l1_reverse[ip] = (json.loads(domains), timestamp, '')
                        self.l1_reverse.move_to_end(ip)
                        _lru_purge(self.l1_reverse, Config.L1_REVERSE_CACHE_MAX)
                    return json.loads(domains)
        except Exception as e:
            print(f"[-] Error reading cache: {e}")
        return None

    def save_reverse_cache(self, ip, domains, source):
        """Simpan cache reverse IP — L1 dulu, write-back SQLite via batch"""
        with self.lock:
            now = time.time()
            self.l1_reverse[ip] = (list(domains) if domains else [], now, source)
            self.l1_reverse.move_to_end(ip)
            self.l1_reverse_dirty.add(ip)
            _lru_purge(self.l1_reverse, Config.L1_REVERSE_CACHE_MAX)
            # Jika buffer penuh sekarang, flush
            if len(self.l1_reverse_dirty) >= Config.L1_WRITEBACK_BATCH:
                self._writeback_locked()
            self._ops_maybe_purge()

    def is_ip_processed(self, ip):
        """Cek apakah IP sudah diproses — L1 dulu (SET LRU), fallback SQLite.
        NEGATIVE CACHE: status 'empty' dianggap 'diproses' hanya selama
        NEGATIVE_CACHE_TTL; status success/lain permanen (PROCESSED_TTL=0)."""
        with self.lock:
            ent = self.l1_processed.get(ip)
            if ent is not None:
                ts, status = ent if isinstance(ent, tuple) else (ent, 'success')
                self.l1_processed.move_to_end(ip)
                ttl = (Config.NEGATIVE_CACHE_TTL if status == 'empty'
                       else Config.PROCESSED_TTL)
                if ttl <= 0 or time.time() - ts < ttl:
                    return True
                # basi: buang
                self.l1_processed.pop(ip, None)
                self._l1_processed_dirty.discard(ip)
        try:
            cur = self.db.conn().cursor()
            cur.execute('SELECT timestamp, status FROM processed_ips WHERE ip = ?', (ip,))
            row = cur.fetchone()
            if row:
                ts, status = row[0], (row[1] or 'success')
                ttl = (Config.NEGATIVE_CACHE_TTL if status == 'empty'
                       else Config.PROCESSED_TTL)
                if ttl <= 0 or time.time() - ts < ttl:
                    with self.lock:
                        self.l1_processed[ip] = (ts, status)
                        self.l1_processed.move_to_end(ip)
                        _lru_purge(self.l1_processed, Config.L1_PROCESSED_MAX)
                    return True
        except Exception as e:
            print(f"[-] Error checking processed IP: {e}")
        return False

    def mark_ip_processed(self, ip, status='success'):
        """Tandai IP sudah diproses — L1 + buffer file + SQLite batch.
        status: 'success' (permanen) / 'empty' (negative cache, NEGATIVE_CACHE_TTL)"""
        now = time.time()
        with self.lock:
            self.l1_processed[ip] = (now, status)
            self.l1_processed.move_to_end(ip)
            self._l1_processed_dirty.add(ip)
            _lru_purge(self.l1_processed, Config.L1_PROCESSED_MAX)
            self._processed_file_buf.append(ip)
            flush_file = len(self._processed_file_buf) >= Config.PROCESSED_FILE_FLUSH
            self._ops_maybe_purge()
        if flush_file:
            self._flush_processed_file()

    def _flush_processed_file(self):
        """Flush buffer IP ke processed_ips.txt (append, batch)"""
        with self._processed_file_lock:
            if not self._processed_file_buf:
                return
            try:
                with open(self.processed_ips_path, 'a') as f:
                    f.write('\n'.join(self._processed_file_buf) + '\n')
            except Exception as e:
                print(f"[-] Error flushing processed_ips.txt: {e}")
                return
            self._processed_file_buf.clear()

    def flush_all(self):
        """Paksa write-back semua buffer (dipanggil saat shutdown/cleanup)"""
        try:
            with self.lock:
                self._writeback_locked()
            self._flush_processed_file()
        except Exception as e:
            print(f"[-] flush_all error: {e}")
    
    def _vacuum_with_guard(self, db_path, timeout=300):
        """PATCH 10-29 VACUUM GUARD: VACUUM dengan koneksi DEDICATED.

        VACUUM mem-block seluruh DB (rewrite total file). Untuk mengurangi
        blocking scan thread:
        1. Pakai koneksi DEDICATED (bukan per-thread conn yang dipakai thread
           lain), supaya cursor VACUUM tidak bersaing dengan cursor thread lain.
        2. timeout 300s di pihak caller (VACUUM thread bersifat daemon,
           mati saat process mati; jika stuck, cleanup lanjut).
        3. VACUUM atomik: sukses atau DB tidak berubah — tidak ada data hilang.

        Return: (status, new_size_mb) dimana status = 'ok'|'timeout'|'error'."""
        new_size_mb = 0.0
        try:
            # Koneksi dedicated untuk VACUUM (bukan self.db.conn() milik thread
            # cleanup, supaya tidak ada persaingan cursor dgn thread lain).
            vac_conn = sqlite3.connect(db_path, timeout=30)
            vac_cur = vac_conn.cursor()
            t0 = time.time()
            vac_cur.execute('VACUUM')
            vac_conn.commit()
            vac_conn.close()
            new_size_mb = os.path.getsize(db_path) / (1024 * 1024)
            print(f"[✓] Auto vacuum: {new_size_mb:.1f}MB ({time.time()-t0:.1f}s)", flush=True)
            return ('ok', new_size_mb)
        except Exception as ve:
            print(f"[!] VACUUM error: {ve} (DB tetap jalan)", flush=True)
            return ('error', new_size_mb)

    def cleanup_old_cache(self):
        """Bersihkan cache lama + L1 (running di background thread) - FIXED FOR TERMUX
        PATCH 10-29 VACUUM GUARD: VACUUM hanya di-jalankan jika DB >= 50 MB
        (guard timeout 300s). DB kecil (kasus Cloudphone, 0.8MB) TIDAK di-vacuum
        — hanya DELETE, tidak ada exclusive lock, scan tetap jalan."""
        VACUUM_TIMEOUT = 300
        while True:
            try:
                # Tunggu sesuai interval
                time.sleep(Config.CACHE_CLEANUP_INTERVAL)

                # Gunakan full path untuk cek database
                db_full_path = os.path.abspath(self.db_path)

                # Cek database size
                if os.path.exists(db_full_path):
                    db_size = os.path.getsize(db_full_path) / (1024 * 1024)  # MB
                else:
                    db_size = 0

                # Koneksi per-thread (thread ini buat conn sendiri)
                conn = self.db.conn()
                cursor = conn.cursor()

                # Hapus cache reverse IP > TTL (basis cepat, tak perlu disimpan lama)
                cursor.execute(
                    'DELETE FROM reverse_ip_cache WHERE timestamp < ?',
                    (time.time() - Config.REVERSE_CACHE_TTL,)
                )
                rev_count = cursor.rowcount

                # Hapus processed IP > 30 hari
                cursor.execute(
                    'DELETE FROM processed_ips WHERE timestamp < ?',
                    (time.time() - 2592000,)
                )
                proc_count = cursor.rowcount

                # Hapus scan results > 30 hari (jika ada)
                cursor.execute(
                    'DELETE FROM scan_results WHERE timestamp < ?',
                    (time.time() - 2592000,)
                )
                scan_count = cursor.rowcount

                # Commit perubahan
                conn.commit()

                total_removed = rev_count + proc_count + scan_count
                if total_removed > 0:
                    print(f"[✓] Auto cleanup: {total_removed} entries removed (rev:{rev_count}, proc:{proc_count}, scan:{scan_count})")

                # PATCH 10-29 VACUUM GUARD: VACUUM TIDAK di-jalankan di cleanup 1-jam.
                # VACUUM = exclusive lock seluruh DB -> semua thread scan (read/write
                # SQLite: is_ip_processed, mark_ip_processed, write-back) TERBLOKIR
                # selamanya VACUUM selesai. Di filesystem Cloudphone (lambat), VACUUM
                # kecil (739 entri) pun bisa makan ber-menit -> "SEMUA PROSES berhenti
                # total" yang kamu alami.
                #
                # Strategi baru:
                # - DB < 50 MB  -> VACUUM TIDAK perlu (SQLite tidak leak, DB kecil
                #   tetap kecil; free pages di-recycle). HANYA DELETE.
                # - DB >= 50 MB  -> VACUUM di-jalankan dengan GUARD:
                #     * timeout 300s (jangan biarkan hang)
                #     * log awal + akhir supaya jelas status
                #     * error tidak menghentikan cleanup berikutnya
                if db_size >= 50:
                    old_size = db_size
                    print(f"[i] DB {old_size:.1f}MB >= 50MB, VACUUM mulai (guard 300s)...", flush=True)
                    # PATCH 10-29: VACUUM di thread terpisah dengan DEDICATED conn
                    # + timeout di pihak caller. VACUUM SQLite tidak bisa di-cancel,
                    # jadi thread yang di-join(timeout) = caller-nya. VACUUM thread
                    # bersifat daemon: jika stuck, cleanup lanjut, VACUUM thread
                    # mati bareng process. Data aman (VACUUM atomik).
                    vac_result = None
                    t0 = time.time()
                    def _run_vacuum():
                        nonlocal vac_result
                        status, _ = self._vacuum_with_guard(db_full_path, timeout=VACUUM_TIMEOUT)
                        vac_result = status
                    vac_thread = threading.Thread(target=_run_vacuum, daemon=True)
                    vac_thread.start()
                    vac_thread.join(timeout=VACUUM_TIMEOUT + 60)  # +60s buffer utk conn close
                    if vac_thread.is_alive():
                        print(f"[!] VACUUM stuck >{VACUUM_TIMEOUT+60}s, cleanup lanjut (DB still alive)", flush=True)
                    else:
                        print(f"[i] VACUUM selesai: {vac_result} ({time.time()-t0:.1f}s)", flush=True)
                else:
                    # DB kecil — skip VACUUM, hanya DELETE. Ini yang seharusnya
                    # terjadi di Cloudphone-mu: 739 entri dihapus, DB tetap 0.8MB,
                    # tidak ada exclusive lock, scan tetap jalan.
                    pass

                # Purge L1 in-memory: buang entry yang sudah dihapus di SQLite / basi
                now = time.time()
                with self.lock:
                    for k in [k for k, (d, ts, s) in self.l1_reverse.items()
                              if now - ts > Config.REVERSE_CACHE_TTL]:
                        self.l1_reverse.pop(k, None)
                        self.l1_reverse_dirty.discard(k)
                    _lru_purge(self.l1_reverse, Config.L1_REVERSE_CACHE_MAX)
                    # Purge processed: TTL per status ('empty' = NEGATIVE_CACHE_TTL,
                    # success = PROCESSED_TTL permanen)
                    for k, ent in list(self.l1_processed.items()):
                        ts, status = ent if isinstance(ent, tuple) else (ent, 'success')
                        ttl = (Config.NEGATIVE_CACHE_TTL if status == 'empty'
                               else Config.PROCESSED_TTL)
                        if ttl > 0 and now - ts > ttl:
                            self.l1_processed.pop(k, None)
                            self._l1_processed_dirty.discard(k)
                    _lru_purge(self.l1_processed, Config.L1_PROCESSED_MAX)
                    print(f"[~] L1 memory purged: rev={len(self.l1_reverse)} proc={len(self.l1_processed)}")

                # Jangan close — conn per-thread tetap dipakai

            except Exception as e:
                print(f"[-] Auto cleanup error: {e}")

    def close(self):
        """Flush semua + tutup koneksi (dipanggil saat shutdown)"""
        try:
            self.flush_all()
        except Exception:
            pass
        # Tutup koneksi thread ini; thread lain punya conn masing-masing (daemon, mati bareng)
        try:
            c = getattr(self.db.local, 'conn', None)
            if c is not None:
                c.close()
                self.db.local.conn = None
        except Exception:
            pass
    
    def start_cleanup_thread(self):
        """Mulai thread cleanup cache"""
        cleanup_thread = threading.Thread(target=self.cleanup_old_cache, daemon=True)
        cleanup_thread.start()
        print(f"[*] Cache cleanup thread started (interval: {Config.CACHE_CLEANUP_INTERVAL}s)")
        print(f"[*] Cache location: {self.temp_dir}")
    
    def get_stats(self):
        """Dapatkan statistik cache + ukuran L1"""
        try:
            conn = self.db.conn()
            cursor = conn.cursor()
            
            stats = {}
            tables = ['reverse_ip_cache', 'scan_results', 'processed_ips']
            
            for table in tables:
                cursor.execute(f'SELECT COUNT(*) FROM {table}')
                stats[table] = cursor.fetchone()[0]
            
            # Dapatkan ukuran database
            if os.path.exists(self.db_path):
                stats['db_size_mb'] = os.path.getsize(self.db_path) / (1024 * 1024)
            else:
                stats['db_size_mb'] = 0
            
            stats['db_path'] = os.path.abspath(self.db_path)
            stats['temp_dir'] = self.temp_dir
            stats['l1_reverse'] = len(self.l1_reverse)
            stats['l1_processed'] = len(self.l1_processed)
            
            return stats
        except Exception as e:
            print(f"[-] Error getting stats: {e}")
            return {}
    
    def clear_all_cache(self):
        """Bersihkan semua cache (manual)"""
        with self.lock:
            try:
                conn = self.db.conn()
                cursor = conn.cursor()
                
                # Hapus semua data
                cursor.execute('DELETE FROM reverse_ip_cache')
                cursor.execute('DELETE FROM scan_results')
                cursor.execute('DELETE FROM processed_ips')
                
                conn.commit()
                cursor.execute('VACUUM')
                
                # Kosongkan L1 juga
                self.l1_reverse.clear()
                self.l1_reverse_dirty.clear()
                self.l1_processed.clear()
                self._l1_processed_dirty.clear()
                
                print(f"[✓] All cache cleared at: {self.db_path} (L1 direset)")
                return True
            except Exception as e:
                print(f"[-] Error clearing cache: {e}")
                return False
    
    def optimize_database(self):
        """Optimasi database manual"""
        try:
            conn = self.db.conn()
            cursor = conn.cursor()
            
            # Rebuild indexes
            cursor.execute('REINDEX')
            
            # Vacuum database
            cursor.execute('VACUUM')
            
            # Analyze untuk query optimizer
            cursor.execute('ANALYZE')
            
            print(f"[✓] Database optimized: {self.db_path}")
            return True
        except Exception as e:
            print(f"[-] Error optimizing database: {e}")
            return False
    
    def delete_database_file(self):
        """Hapus file database (untuk reset total)"""
        try:
            if os.path.exists(self.db_path):
                size = os.path.getsize(self.db_path) / (1024 * 1024)
                os.remove(self.db_path)
                print(f"[✓] Database file deleted: {self.db_path} ({size:.2f} MB)")
                
                # Re-init database
                self.init_database()
                return True
        except Exception as e:
            print(f"[-] Error deleting database: {e}")
            return False