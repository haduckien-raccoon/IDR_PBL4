// app/static/js/ssh.js

document.addEventListener("DOMContentLoaded", () => {
  const terminalContainer = document.getElementById("terminal");
  const btnConnect = document.getElementById("btn-connect-ssh");
  
  // Khai báo biến toàn cục để quản lý kết nối
  let socket = null;
  let term = null;

  // Hàm khởi tạo Terminal (chưa kết nối)
  function initTerminal() {
      if (term) term.dispose(); // Xóa cái cũ nếu có
      term = new Terminal({
          cursorBlink: true,
          fontSize: 14,
          theme: { background: "#000000", foreground: "#e5e5e5", cursor: "#ffffff" }
      });
      term.open(terminalContainer);
      fitTerminal();
  }

  // Hàm resize terminal
  function fitTerminal() {
      if (!term) return;
      const cols = Math.floor(terminalContainer.clientWidth / 9);
      const rows = Math.floor(terminalContainer.clientHeight / 17);
      if (cols > 0 && rows > 0) term.resize(cols, rows);
  }
  window.addEventListener("resize", fitTerminal);

  // --- SỰ KIỆN BẤM NÚT CONNECT ---
  btnConnect.addEventListener("click", () => {
      // 1. Nếu đang kết nối thì ngắt kết nối
      if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
          socket.close();
          btnConnect.innerHTML = '<i class="fa-solid fa-plug"></i> Connect SSH';
          btnConnect.style.background = "#4d79ff"; // Màu xanh
          return;
      }

      // 2. Lấy dữ liệu từ ô input
      const host = document.getElementById("ssh-host").value.trim();
      const port = document.getElementById("ssh-port").value.trim();
      const user = document.getElementById("ssh-user").value.trim();
      const pass = document.getElementById("ssh-password").value; // Lấy password

      if (!host || !user || !pass) {
          alert("Vui lòng nhập đầy đủ Host, User và Password!");
          return;
      }

      // 3. Khởi tạo Terminal mới
      terminalContainer.innerHTML = ""; // Xóa nội dung cũ
      initTerminal();
      term.writeln("\x1b[33mConnecting to " + user + "@" + host + "...\x1b[0m\r\n");

      // 4. Tạo URL WebSocket có kèm Query Params
      const protocol = window.location.protocol === "https:" ? "wss" : "ws";
      // Truyền thông tin qua URL query string
      const wsUrl = `${protocol}://${window.location.host}/api/ssh/terminal?host=${host}&port=${port}&user=${user}&password=${encodeURIComponent(pass)}`;

      socket = new WebSocket(wsUrl);

      // 5. Xử lý các sự kiện WebSocket
      socket.addEventListener("open", () => {
          term.writeln("\x1b[32m*** Socket Connected ***\x1b[0m\r\n");
          // Đổi nút thành Disconnect
          btnConnect.innerHTML = '<i class="fa-solid fa-power-off"></i> Disconnect';
          btnConnect.style.background = "#e94560"; // Màu đỏ
      });

      socket.addEventListener("message", (event) => {
          term.write(event.data);
      });

      socket.addEventListener("close", () => {
          term.writeln("\r\n\x1b[31m*** Disconnected ***\x1b[0m");
          btnConnect.innerHTML = '<i class="fa-solid fa-plug"></i> Connect SSH';
          btnConnect.style.background = "#4d79ff";
          socket = null;
      });

      socket.addEventListener("error", () => {
          term.writeln("\r\n\x1b[31m*** Connection Error ***\x1b[0m");
      });

      // Gửi phím gõ lên server
      term.onData(data => {
          if (socket && socket.readyState === WebSocket.OPEN) {
              socket.send(data);
          }
      });
  });

  // Các nút Quick Commands
  document.querySelectorAll(".btn-snippet").forEach(btn => {
      btn.addEventListener("click", () => {
          const cmd = btn.textContent.trim();
          if (socket && socket.readyState === WebSocket.OPEN && cmd) {
              socket.send(cmd + "\n");
          }
      });
  });
});