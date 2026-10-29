# ip_generator.py - FULL VERSION WITH IP VALIDATION
import random
import socket
import time
import threading
from queue import Queue
from threading import Thread
from config import Config

class IPGenerator:
    def __init__(self, cache_manager):
        self.cache_manager = cache_manager
        self.valid_ips = Queue()
        self.running = True

    def check_ip_valid(self, ip, timeout=4):
        """Cek validitas IP dengan timeout (ada PTR record / reverse DNS)

        HANG-FIX: socket.gethostbyaddr blocking tanpa timeout di Termux
        bisa macet 30+ detik per IP mati. 254 IP sekuensial = berjam-jam
        tanpa output. Pakai thread + join(timeout)."""
        result = {}
        def _dns():
            try:
                socket.gethostbyaddr(ip)
                result['ok'] = True
            except Exception:
                result['ok'] = False
        t = threading.Thread(target=_dns, daemon=True)
        t.start()
        t.join(timeout)
        return result.get('ok', False)
    
    def check_ip_active(self, ip, timeout=2):
        """Cek apakah IP aktif/responsive dengan connection test ke port 80"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 80))
            sock.close()
            return result == 0
        except:
            return False
    
    def generate_ips_level1_full(self, base_ip):
        """
        LEVEL 1: Scan SEMUA 254 kemungkinan IP
        base_ip: 3 oktet + .1 (contoh: 157.7.44.1)
        Menghasilkan semua IP dari 1-254 (tidak pakai max_valid)
        """
        base_parts = base_ip.split('.')
        if len(base_parts) != 4:
            print("[!] Level 1: Need 4 octets (e.g., 157.7.44.1)")
            return
        
        base_three_octets = '.'.join(base_parts[:3]) + '.'
        valid_count = 0
        
        print(f"[*] LEVEL 1: Scanning ALL 254 IPs from {base_three_octets}[1-254]...")
        
        for last_octet in range(1, 255):
            ip = base_three_octets + str(last_octet)
            
            if self.check_ip_valid(ip):
                valid_count += 1
                yield ip
                print(f"[+] L1 Valid IP: {ip} ({valid_count}/254)")
            
            # Small delay to prevent overwhelming
            if last_octet % 50 == 0:
                time.sleep(0.5)
        
        print(f"[*] LEVEL 1 completed: {valid_count}/254 valid IPs found")
    
    def generate_ips_level2_explore(self, base_two_octets, max_valid=50):
        """
        LEVEL 2 EXPLORE: Mencari base 3 oktet baru
        base_two_octets: contoh "157.7."
        Mencari IP valid dengan random oktet ke-3 dan ke-4
        HANYA IP VALID yang akan di-yield (cek PTR record)
        """
        valid_count = 0
        attempted = set()
        
        print(f"[*] LEVEL 2 (Explore): Mencari base baru dari {base_two_octets}[1-254].[1-254]...")
        print(f"[*] Hanya IP VALID (ada PTR record) yang akan diproses")
        
        while valid_count < max_valid:
            third_octet = random.randint(1, 254)
            fourth_octet = random.randint(1, 254)
            ip = base_two_octets + str(third_octet) + '.' + str(fourth_octet)
            
            ip_key = f"{third_octet}.{fourth_octet}"
            if ip_key in attempted:
                continue
            
            attempted.add(ip_key)
            
            # VALIDASI: cek apakah IP valid (ada PTR record)
            if self.check_ip_valid(ip):
                valid_count += 1
                yield ip
                print(f"[+] L2 Explore Valid IP: {ip} ({valid_count}/{max_valid})")
            else:
                # Optional: tampilkan progress untuk IP tidak valid
                if valid_count == 0 and len(attempted) % 100 == 0:
                    print(f"[*] L2 Explore: {len(attempted)} IPs checked, {valid_count} valid found...")
            
            # Small delay
            if valid_count % 10 == 0 and valid_count > 0:
                time.sleep(0.1)
        
        print(f"[*] LEVEL 2 Explore completed: {valid_count}/{max_valid} valid IPs found")
    
    def generate_ips_level2_exploit_full(self, base_three_octets):
        """
        LEVEL 2 EXPLOIT: Scan SEMUA 254 kemungkinan dari base 3 oktet yang ditemukan
        base_three_octets: contoh "157.7.89."
        Menghasilkan semua IP VALID dari 1-254 (cek PTR record)
        """
        valid_count = 0
        
        print(f"[*] LEVEL 2 (Exploit): Scanning ALL 254 IPs from {base_three_octets}[1-254]...")
        print(f"[*] Hanya IP VALID (ada PTR record) yang akan diproses")
        
        for last_octet in range(1, 255):
            ip = base_three_octets + str(last_octet)
            
            if self.check_ip_valid(ip):
                valid_count += 1
                yield ip
                print(f"[+] L2 Exploit Valid IP: {ip} ({valid_count}/254)")
            
            if last_octet % 50 == 0:
                time.sleep(0.5)
        
        print(f"[*] LEVEL 2 Exploit completed: {valid_count}/254 valid IPs found from {base_three_octets}")
    
    def get_valid_ips_from_base(self, base_three_octets, max_ips=10, max_attempts=500):
        """
        Cari IP VALID dari base 3 oktet tertentu
        
        Args:
            base_three_octets: contoh "157.7.109."
            max_ips: jumlah maksimal IP valid yang dicari
            max_attempts: maksimal percobaan sebelum berhenti
        
        Returns:
            list of valid IPs
        """
        valid_ips = []
        attempted = set()
        
        print(f"[*] Mencari {max_ips} IP valid dari base {base_three_octets}x...")
        
        for attempt in range(max_attempts):
            if len(valid_ips) >= max_ips:
                break
            
            last_octet = random.randint(1, 254)
            
            if last_octet in attempted:
                continue
            
            attempted.add(last_octet)
            ip = base_three_octets + str(last_octet)
            
            if self.check_ip_valid(ip):
                valid_ips.append(ip)
                print(f"[+] Found valid IP: {ip} ({len(valid_ips)}/{max_ips})")
        
        print(f"[*] Found {len(valid_ips)} valid IPs from {len(attempted)} attempts")
        return valid_ips
    
    # Legacy methods untuk backward compatibility
    def generate_ips(self, base_ip, max_valid=None):
        """Legacy method"""
        return self.generate_ips_level1_full(base_ip)
    
    def stream_ips(self, base_ip, callback, max_valid=None):
        """Stream IP dan proses dengan callback"""
        for ip in self.generate_ips_level1_full(base_ip):
            if not self.cache_manager.is_ip_processed(ip):
                callback(ip)
            else:
                print(f"[↺] Skipping cached IP: {ip}")