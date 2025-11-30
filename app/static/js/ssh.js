// app/static/js/ssh.js

document.addEventListener("DOMContentLoaded", () => {
  const terminalContainer = document.getElementById("terminal");
  if (!terminalContainer) {
    console.error("Không tìm thấy #terminal trong DOM");
    return;
  }

  const term = new Terminal({
    cursorBlink: true,
    fontSize: 14,
    theme: {
      background: "#000000",
      foreground: "#e5e5e5",
      cursor: "#ffffff"
    }
  });

  term.open(terminalContainer);

  // Tự động resize terminal theo kích thước div
  function fitTerminal() {
    const cols = Math.floor(terminalContainer.clientWidth / 8);   // 8px/char approx
    const rows = Math.floor(terminalContainer.clientHeight / 16); // 16px/row approx
    if (cols > 0 && rows > 0) {
      term.resize(cols, rows);
    }
  }
  window.addEventListener("resize", fitTerminal);
  setTimeout(fitTerminal, 100);

  // Tạo WebSocket tới backend
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const wsUrl = `${protocol}://${window.location.host}/api/ssh/terminal`;
  const socket = new WebSocket(wsUrl);

  socket.addEventListener("open", () => {
    term.writeln("\x1b[32m*** Connected to SSH server ***\x1b[0m\r\n");
  });

  socket.addEventListener("message", (event) => {
    term.write(event.data);
  });

  socket.addEventListener("close", () => {
    term.writeln("\r\n\x1b[31m*** Disconnected from SSH server ***\x1b[0m");
  });

  socket.addEventListener("error", (err) => {
    console.error("WebSocket error", err);
    term.writeln("\r\n\x1b[31m*** WebSocket error ***\x1b[0m");
  });

  // Gửi mọi phím người dùng gõ lên WebSocket
  term.onData(data => {
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(data);
    }
  });

  // Quick commands (btn-snippet) -> gửi luôn vào SSH
  document.querySelectorAll(".btn-snippet").forEach(btn => {
    btn.addEventListener("click", () => {
      const cmd = btn.textContent.trim();
      if (socket.readyState === WebSocket.OPEN && cmd) {
        socket.send(cmd + "\n");
        term.write(cmd + "\r\n");
      }
    });
  });
});
