import threading
import time
import socket
import struct
import os
import pandas as pd
import tkinter as tk
from tkinter import ttk, messagebox
import joblib
from typing import Dict, List, Tuple
import ipaddress

# --- CẤU HÌNH ---
CSV_FILE = "data/live_flow.csv"
FEATURE_PATH = os.path.join("models", "cnn_lite_feature_names.pkl")

if not os.path.exists(FEATURE_PATH):
    print("⚠️ Warning: Không tìm thấy feature names. Dùng danh sách mặc định.")
    FEATURE_NAMES = [
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
        "Flow IAT Mean", "Fwd IAT Mean", "Fwd Header Length",
        "Flow IAT Std", "Flow Bytes/s"
    ]
else:
    FEATURE_NAMES = joblib.load(FEATURE_PATH)


class Flow:
    """Flow class để lưu trữ thông tin flow"""
    def __init__(self, start_time):
        self.start_time = start_time
        self.last_time = start_time
        self.pkts = 0
        self.bytes = 0
        self.lengths = []
        self.iats = []
        self.header_len = 0
        self.flushed = False

    def update(self, length, header_len, now):
        iat = (now - self.last_time) * 1_000_000  # Microseconds
        if self.pkts > 0:
            self.iats.append(iat)
        self.last_time = now
        self.pkts += 1
        self.bytes += length
        self.lengths.append(length)
        self.header_len += header_len

    def to_features(self):
        duration = (self.last_time - self.start_time) * 1_000_000  # Microseconds
        if duration <= 0:
            duration = 1.0  # Tránh chia cho 0
        
        mean_iat = sum(self.iats) / len(self.iats) if self.iats else 0.0
        std_iat = pd.Series(self.iats).std() if len(self.iats) > 1 else 0.0
        
        return {
            "Flow Duration": duration,
            "Total Fwd Packets": self.pkts,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": self.bytes,
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Max": max(self.lengths) if self.lengths else 0,
            "Fwd Packet Length Min": min(self.lengths) if self.lengths else 0,
            "Fwd Packet Length Mean": sum(self.lengths) / len(self.lengths) if self.lengths else 0,
            "Flow IAT Mean": mean_iat,
            "Fwd IAT Mean": mean_iat,
            "Fwd Header Length": self.header_len,
            "Flow IAT Std": std_iat,
            "Flow Bytes/s": (self.bytes * 1_000_000) / duration 
        }


# Cache cho local IPs để tránh detect lại nhiều lần
_local_ips_cache = None
_local_ips_cache_time = 0
_CACHE_TIMEOUT = 30  # Cache trong 30 giây


def get_local_ips(use_cache: bool = True) -> List[str]:
    """Lấy danh sách tất cả IP addresses của máy (có cache)"""
    global _local_ips_cache, _local_ips_cache_time
    
    # Kiểm tra cache
    if use_cache and _local_ips_cache is not None:
        if time.time() - _local_ips_cache_time < _CACHE_TIMEOUT:
            return _local_ips_cache.copy()
    
    ips = []
    try:
        # Lấy hostname
        hostname = socket.gethostname()
        # Lấy tất cả IP addresses
        for addr_info in socket.getaddrinfo(hostname, None):
            ip = addr_info[4][0]
            # Chỉ lấy IPv4, bỏ qua loopback
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                if not ip_obj.is_loopback:
                    ips.append(ip)
            except (ValueError, ipaddress.AddressValueError):
                continue
    except Exception:
        pass
    
    # Fallback: Thử kết nối để lấy IP chính (với timeout)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)  # Timeout 0.5s để tránh block
        s.connect(("8.8.8.8", 80))
        main_ip = s.getsockname()[0]
        s.close()
        if main_ip not in ips:
            ips.insert(0, main_ip)
    except Exception:
        pass
    
    result = list(dict.fromkeys(ips))  # Remove duplicates while keeping order
    _local_ips_cache = result
    _local_ips_cache_time = time.time()
    return result.copy()


def validate_ip(ip: str, local_ips: List[str] = None) -> Tuple[bool, str]:
    """Validate IP address và kiểm tra xem có phải IP của máy không"""
    if not ip or not ip.strip():
        return False, "IP address không được để trống"
    
    ip = ip.strip()
    
    # Kiểm tra format IP
    try:
        ip_obj = ipaddress.IPv4Address(ip)
    except (ValueError, ipaddress.AddressValueError):
        return False, f"'{ip}' không phải là địa chỉ IPv4 hợp lệ"
    
    # Cho phép 0.0.0.0 (bind all interfaces)
    if ip == "0.0.0.0":
        return True, "OK"
    
    # Kiểm tra xem IP có phải của máy không (dùng cache nếu có)
    if local_ips is None:
        local_ips = get_local_ips(use_cache=True)
    
    if ip not in local_ips:
        return False, f"IP '{ip}' không phải là IP của máy này.\nIP có sẵn: {', '.join(local_ips) if local_ips else 'Không tìm thấy'}"
    
    return True, "OK"


class FastSniffer:
    """Fast Sniffer sử dụng raw socket (nhanh hơn Scapy)"""
    def __init__(self, bind_ip, gui_callback=None):
        self.bind_ip = bind_ip
        self.flows = {}  # Key: (src, dst, sport, dport, proto)
        self.lock = threading.Lock()
        self.running = False
        self.sniffer_socket = None
        self.packet_count = 0
        self.gui_callback = gui_callback  # Callback để update GUI

    def start(self):
        """Khởi động sniffer với raw socket"""
        # Validate IP trước (dùng cache để nhanh hơn)
        local_ips = get_local_ips(use_cache=True)
        is_valid, error_msg = validate_ip(self.bind_ip, local_ips=local_ips)
        if not is_valid:
            full_error = f"❌ IP Validation Error: {error_msg}\n\n⚠️ Lưu ý:\n- Trên Windows, cần quyền Admin để sử dụng raw socket\n- IP phải là IP của interface local hoặc 0.0.0.0"
            if self.gui_callback:
                self.gui_callback("log", full_error)
                self.gui_callback("error", full_error)
            return
        
        try:
            self.sniffer_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.sniffer_socket.bind((self.bind_ip, 0))
            self.sniffer_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            self.running = True
            
            if self.gui_callback:
                self.gui_callback("log", f"🚀 Fast Sniffer started on {self.bind_ip}")
        except OSError as e:
            if e.winerror == 10049:  # Address not valid
                error_msg = (
                    f"❌ Socket Error: IP '{self.bind_ip}' không hợp lệ!\n\n"
                    f"Nguyên nhân: IP này không phải là IP của interface local.\n\n"
                    f"Giải pháp:\n"
                    f"1. Click nút '🔍 Auto-detect' để tự động lấy IP\n"
                    f"2. Hoặc nhập IP của máy bạn (xem bằng: ipconfig)\n"
                    f"3. Hoặc dùng '0.0.0.0' để bind tất cả interfaces\n\n"
                    f"⚠️ Lưu ý: Cần quyền Admin trên Windows!"
                )
            elif e.winerror == 10013:  # Permission denied
                error_msg = (
                    f"❌ Permission Error: Không có quyền truy cập raw socket!\n\n"
                    f"Giải pháp:\n"
                    f"1. Chạy chương trình với quyền Administrator\n"
                    f"   (Right-click → Run as administrator)\n"
                    f"2. Hoặc sử dụng gui_sniffer_final.py (dùng Scapy, không cần admin)"
                )
            else:
                error_msg = f"❌ Socket Error: {e}\n\n⚠️ Cần quyền Admin để sử dụng raw socket trên Windows!"
            
            if self.gui_callback:
                self.gui_callback("log", error_msg)
                self.gui_callback("error", error_msg)
            return
        except Exception as e:
            error_msg = f"❌ Unexpected Error: {e}\n\n⚠️ Cần quyền Admin để sử dụng raw socket!"
            if self.gui_callback:
                self.gui_callback("log", error_msg)
                self.gui_callback("error", error_msg)
            return

        # Thread ghi CSV định kỳ (Mỗi 1s)
        threading.Thread(target=self._flush_loop, daemon=True).start()

        # Capture Loop
        while self.running:
            try:
                raw_buffer = self.sniffer_socket.recvfrom(65535)[0]
                self._process_packet(raw_buffer)
                self.packet_count += 1
            except Exception:
                pass

        # Cleanup
        try:
            self.sniffer_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.sniffer_socket.close()
        except:
            pass

    def _process_packet(self, buffer):
        """Parse và xử lý packet"""
        try:
            # Parse IP Header (20 bytes)
            ip_header = buffer[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            
            protocol = iph[6]
            src_addr = socket.inet_ntoa(iph[8])
            dst_addr = socket.inet_ntoa(iph[9])
            
            total_len = len(buffer)
            payload_len = total_len - iph_length
            
            # Parse TCP/UDP để lấy Port
            src_port = 0
            dst_port = 0
            header_len = 0
            
            if protocol == 6:  # TCP
                t = iph_length
                tcp_header = buffer[t:t+20]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                src_port = tcph[0]
                dst_port = tcph[1]
                header_len = (tcph[4] >> 4) * 4
            elif protocol == 17:  # UDP
                u = iph_length
                udph = struct.unpack('!HHHH', buffer[u:u+8])
                src_port = udph[0]
                dst_port = udph[1]
                header_len = 8
            
            # Key flow
            flow_key = (src_addr, dst_addr, 0, 0, protocol)
            now = time.time()
            
            with self.lock:
                if flow_key not in self.flows:
                    self.flows[flow_key] = Flow(now)
                
                self.flows[flow_key].update(payload_len, header_len, now)
                
        except Exception:
            pass

    def _flush_loop(self):
        """Ghi flows vào CSV mỗi giây"""
        # Init CSV
        if not os.path.exists(os.path.dirname(CSV_FILE)):
            os.makedirs(os.path.dirname(CSV_FILE))
        pd.DataFrame(columns=FEATURE_NAMES).to_csv(CSV_FILE, index=False)
        
        flush_count = 0
        while self.running:
            time.sleep(1.0)  # Ghi mỗi giây
            rows = []
            flows_to_clear = []
            
            with self.lock:
                # Lấy các flow active để ghi
                keys_to_delete = []
                for key, flow in self.flows.items():
                    feat = flow.to_features()
                    row = {col: feat.get(col, 0) for col in FEATURE_NAMES}
                    rows.append(row)
                    flows_to_clear.append(key)
                    
                    # Flow cũ quá (>5s) thì xóa
                    if time.time() - flow.last_time > 5:
                        keys_to_delete.append(key)
                
                # Xóa flows cũ
                for k in keys_to_delete:
                    if k in self.flows:
                        del self.flows[k]
                
                # Clear flows sau khi ghi (snapshot 1s) - nhưng chỉ clear những flows đã ghi
                for k in flows_to_clear:
                    if k in self.flows:
                        del self.flows[k]

            if rows:
                try:
                    df = pd.DataFrame(rows)
                    df.to_csv(CSV_FILE, mode='a', header=False, index=False)
                    flush_count += 1
                    # Log mỗi lần flush để người dùng biết sniffer đang hoạt động
                    if self.gui_callback:
                        example_pkts = rows[0].get('Total Fwd Packets', 0)
                        self.gui_callback("log", f"Flushed {len(rows)} flows. Example: {example_pkts:.0f} pkts")
                except Exception as e:
                    # Log error
                    if self.gui_callback:
                        self.gui_callback("log", f"⚠️ Error writing CSV: {e}")
            else:
                # Log khi không có flows (để biết sniffer vẫn đang chạy)
                flush_count += 1
                if flush_count % 10 == 0:  # Log mỗi 10 giây nếu không có flows
                    if self.gui_callback:
                        with self.lock:
                            active_count = len(self.flows)
                        self.gui_callback("log", f"Waiting for flows... (Active: {active_count}, Packets: {self.packet_count:,})")

    def stop(self):
        """Dừng sniffer"""
        self.running = False


class App:
    """GUI Application cho Fast Sniffer"""
    def __init__(self, root):
        self.root = root
        self.root.title("DDoS Fast Sniffer - Raw Socket Version")
        self.root.geometry("650x550")

        self.is_running = False
        self.sniffer = None
        self.sniffer_thread = None
        self.packet_count = 0
        self.last_packet_count = 0
        self.last_update_time = time.time()

        # UI Setup
        frame_top = ttk.LabelFrame(root, text="Configuration", padding=10)
        frame_top.pack(fill="x", padx=10, pady=5)

        ttk.Label(frame_top, text="Bind IP:").pack(side="left", padx=5)
        self.ip_entry = ttk.Entry(frame_top, width=20)
        self.ip_entry.insert(0, "192.168.1.111")  # Default IP
        self.ip_entry.pack(side="left", padx=5)
        
        ttk.Label(frame_top, text="(0.0.0.0 = all interfaces)").pack(side="left", padx=5)
        
        # Button để auto-detect IP
        btn_detect = ttk.Button(frame_top, text="🔍 Auto-detect", command=self.auto_detect_ip)
        btn_detect.pack(side="left", padx=5)
        
        # Button để list tất cả IPs
        btn_list = ttk.Button(frame_top, text="📋 List IPs", command=self.list_all_ips)
        btn_list.pack(side="left", padx=5)

        frame_btn = ttk.Frame(root, padding=10)
        frame_btn.pack(fill="x", padx=10)
        self.btn_start = ttk.Button(frame_btn, text="🔥 START MONITORING", command=self.start_sniffing)
        self.btn_start.pack(side="left", padx=5, expand=True, fill="x")
        self.btn_stop = ttk.Button(frame_btn, text="⏹ STOP", command=self.stop_sniffing, state="disabled")
        self.btn_stop.pack(side="left", padx=5, expand=True, fill="x")

        frame_stats = ttk.LabelFrame(root, text="Real-time Stats", padding=10)
        frame_stats.pack(fill="both", expand=True, padx=10, pady=5)

        self.lbl_status = ttk.Label(frame_stats, text="Status: Ready", font=("Arial", 10, "bold"), foreground="gray")
        self.lbl_status.pack(pady=5)
        self.lbl_packets = ttk.Label(frame_stats, text="Packets Captured: 0", font=("Arial", 12))
        self.lbl_packets.pack(pady=5)
        self.lbl_pps = ttk.Label(frame_stats, text="Packet/s (Raw Socket): 0", font=("Arial", 12))
        self.lbl_pps.pack(pady=5)
        self.lbl_flows = ttk.Label(frame_stats, text="Active Flows: 0", font=("Arial", 12))
        self.lbl_flows.pack(pady=5)

        self.log_text = tk.Text(frame_stats, height=10, state="disabled", bg="#1e1e1e", fg="#00ff00", font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True, pady=5)

    def log(self, message):
        """Thêm message vào log"""
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"> {message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def gui_callback(self, callback_type, message):
        """Callback từ sniffer để update GUI (thread-safe)"""
        # Schedule GUI update từ main thread để tránh block
        if callback_type == "log":
            self.root.after(0, lambda: self.log(message))
        elif callback_type == "error":
            self.root.after(0, lambda: messagebox.showerror("Error", message))

    def auto_detect_ip(self):
        """Tự động detect IP của máy"""
        try:
            local_ips = get_local_ips()
            if local_ips:
                # Lấy IP đầu tiên (thường là IP chính)
                main_ip = local_ips[0]
                self.ip_entry.delete(0, tk.END)
                self.ip_entry.insert(0, main_ip)
                if len(local_ips) > 1:
                    self.log(f"Auto-detected IP: {main_ip}")
                    self.log(f"Other available IPs: {', '.join(local_ips[1:])}")
                else:
                    self.log(f"Auto-detected IP: {main_ip}")
            else:
                self.log("⚠️ Could not auto-detect IP. Please enter manually.")
        except Exception as e:
            self.log(f"⚠️ Could not auto-detect IP: {e}")

    def list_all_ips(self):
        """Hiển thị tất cả IP addresses có sẵn"""
        try:
            local_ips = get_local_ips()
            if local_ips:
                ip_list = "\n".join([f"  • {ip}" for ip in local_ips])
                message = f"Available IP addresses on this machine:\n\n{ip_list}\n\n(Click 'Auto-detect' to use the first one)"
                messagebox.showinfo("Available IPs", message)
                self.log(f"Available IPs: {', '.join(local_ips)}")
            else:
                messagebox.showwarning("No IPs Found", "Could not detect any IP addresses.\nPlease check your network configuration.")
                self.log("⚠️ No IP addresses found")
        except Exception as e:
            messagebox.showerror("Error", f"Could not list IPs: {e}")
            self.log(f"❌ Error listing IPs: {e}")

    def start_sniffing(self):
        """Khởi động sniffer"""
        bind_ip = self.ip_entry.get().strip()
        
        if not bind_ip:
            messagebox.showerror("Error", "Please enter a valid IP address!")
            return
        
        # Validate IP trước khi start
        is_valid, error_msg = validate_ip(bind_ip)
        if not is_valid:
            messagebox.showerror("IP Validation Error", error_msg)
            self.log(f"❌ {error_msg}")
            return
        
        self.is_running = True
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.lbl_status.config(text=f"Sniffing on {bind_ip}...", foreground="green")
        self.packet_count = 0
        self.last_packet_count = 0
        self.last_update_time = time.time()
        
        self.log(f"Starting Fast Sniffer on {bind_ip}...")
        self.log("⚠️ Note: Raw socket requires Admin privileges on Windows!")
        
        # Tạo sniffer với callback
        self.sniffer = FastSniffer(bind_ip, gui_callback=self.gui_callback)
        
        # Chạy sniffer trong thread riêng
        self.sniffer_thread = threading.Thread(target=self.sniffer.start, daemon=True)
        self.sniffer_thread.start()
        
        # Start UI update loop
        self.update_ui_loop()

    def stop_sniffing(self):
        """Dừng sniffer"""
        self.is_running = False
        if self.sniffer:
            self.sniffer.stop()
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.lbl_status.config(text="Stopped", foreground="red")
        self.log("Sniffer stopped.")

    def update_ui_loop(self):
        """Update UI stats định kỳ"""
        if self.is_running and self.sniffer:
            now = time.time()
            dt = now - self.last_update_time
            if dt >= 1.0:
                # Lấy packet count từ sniffer
                current_packets = self.sniffer.packet_count
                pps = (current_packets - self.last_packet_count) / dt if dt > 0 else 0
                
                self.lbl_packets.config(text=f"Packets Captured: {current_packets:,}")
                self.lbl_pps.config(text=f"Packet/s (Raw Socket): {pps:,.1f}")
                
                # Lấy số flows active
                with self.sniffer.lock:
                    active_flows = len(self.sniffer.flows)
                self.lbl_flows.config(text=f"Active Flows: {active_flows}")
                
                self.last_packet_count = current_packets
                self.last_update_time = now
            
            self.root.after(500, self.update_ui_loop)
        else:
            # Reset khi dừng
            self.lbl_packets.config(text="Packets Captured: 0")
            self.lbl_pps.config(text="Packet/s (Raw Socket): 0")
            self.lbl_flows.config(text="Active Flows: 0")


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()