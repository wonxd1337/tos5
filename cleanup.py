# cleanup.py
import os
import shutil
import sqlite3
import time
from config import Config

def cleanup_temp_files():
    """Bersihkan file temporary + VACUUM DB (jika DB masih ada setelah rmtree)."""
    print("[*] Cleaning up temporary files...")
    
    # Hapus seluruh TEMP_DIR (cache.db, proxy_cache.json, L1 snapshot, dll.)
    if os.path.exists(Config.TEMP_DIR):
        size = sum(
            os.path.getsize(os.path.join(dp, f))
            for dp, _, fs in os.walk(Config.TEMP_DIR)
            for f in fs
        )
        size_mb = size / (1024 * 1024)
        shutil.rmtree(Config.TEMP_DIR, ignore_errors=True)
        print(f"[✓] Removed {Config.TEMP_DIR} ({size_mb:.2f} MB)")
    
    # VACUUM database HANYA jika file DB masih ada (belum di-rmtree)
    db_path = os.path.join(Config.TEMP_DIR, Config.OUTPUT_FILES['cache'])
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        conn.execute('VACUUM')
        conn.close()
        print("[✓] Database optimized")
    else:
        print("[i] Database sudah dihapus, skip VACUUM")

def cleanup_old_entries():
    """Hapus entri cache yang sudah BASI (TTL habis).
    - reverse_ip_cache: > REVERSE_CACHE_TTL (6 jam)
    - processed_ips 'empty' (negative cache): > NEGATIVE_CACHE_TTL (24 jam)
    - processed_ips 'success': PERMANEN, tidak dihapus (biar scan tidak re-process)
    """
    db_path = os.path.join(Config.TEMP_DIR, Config.OUTPUT_FILES['cache'])
    if not os.path.exists(db_path):
        print("[!] Database not found, skip")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    now = time.time()
    
    # Hapus reverse cache > REVERSE_CACHE_TTL
    cursor.execute(
        'DELETE FROM reverse_ip_cache WHERE timestamp < ?',
        (now - Config.REVERSE_CACHE_TTL,)
    )
    rev_count = cursor.rowcount
    
    # Hapus negative cache ('empty') yang sudah lewat NEGATIVE_CACHE_TTL
    cursor.execute(
        "DELETE FROM processed_ips WHERE status = 'empty' AND timestamp < ?",
        (now - Config.NEGATIVE_CACHE_TTL,)
    )
    empty_count = cursor.rowcount
    
    # Hitung entri 'success' (tidak dihapus, hanya info)
    cursor.execute("SELECT COUNT(*) FROM processed_ips WHERE status != 'empty'")
    success_count = cursor.fetchone()[0]
    
    conn.commit()
    conn.close()
    
    print(f"[✓] Removed {rev_count} stale reverse cache entries (> {Config.REVERSE_CACHE_TTL//3600} jam)")
    print(f"[✓] Removed {empty_count} expired negative-cache entries (> {Config.NEGATIVE_CACHE_TTL//3600} jam)")
    print(f"[i] Kept {success_count} permanent 'success' entries (tidak dihapus)")

if __name__ == "__main__":
    import time
    
    print("""
    ╔══════════════════════════════════════╗
    ║     Movable Type Scanner Cleanup     ║
    ╚══════════════════════════════════════╝
    """)
    
    print("1. Hapus semua file temporary (rmtree TEMP_DIR + VACUUM)")
    print("2. Hapus entri cache BASI (reverse cache TTL + negative cache TTL)")
    print("3. Both (hapus semua + bersihkan basi)")
    
    choice = input("\nChoice: ").strip()
    
    if choice in ['1', '3']:
        cleanup_temp_files()
    
    if choice in ['2', '3']:
        cleanup_old_entries()
    
    print("\n[✓] Cleanup completed")
