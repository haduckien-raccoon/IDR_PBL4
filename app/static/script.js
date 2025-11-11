// script.js
document.addEventListener("DOMContentLoaded", () => {
  const API_BASE = (window.__CONFIG__ && window.__CONFIG__.API_BASE) || "";
  // [ĐÃ SỬA] Biến này giờ sẽ nhận '/ws' từ index.html
  const WS_PATH  = (window.__CONFIG__ && window.__CONFIG__.WS_PATH)  || "/ws";

  // Helpers
  const $  = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);
  const fmt = new Intl.NumberFormat('en-US');

  async function getJSON(path) {
    const url = API_BASE + path;
    const res = await fetch(url, { headers: { "Accept": "application/json" } });
    if (!res.ok) {
        const errText = await res.text();
        throw new Error(`API ${path} failed: ${res.status} ${res.statusText} - ${errText}`);
    }
    return res.json();
  }

  // [CẢI TIẾN] Hàm showToast nên được implement
  function showToast(msg, isError = false) {
    console.log("[Dashboard Toast]", msg);
    if (isError) console.error(msg);
    
    // TODO: Thêm code để tạo một div thông báo thực tế
    // Ví dụ:
    // const toast = document.createElement("div");
    // toast.className = isError ? "toast toast-error" : "toast";
    // toast.textContent = msg;
    // document.body.appendChild(toast);
    // setTimeout(() => toast.remove(), 3000);
  }

  // [ĐÃ SỬA] Hàm formatTimeAgo đã được chuyển ra ngoài (giữ nguyên)
  function formatTimeAgo(timestamp) {
      if (!timestamp) return 'unknown';
      const now = new Date();
      const past = new Date(timestamp);
      const secondsAgo = Math.round((now - past) / 1000);
      if (isNaN(secondsAgo)) return '...';
      if (secondsAgo < 10) return 'just now';
      if (secondsAgo < 60) return `${secondsAgo}s ago`;
      const intervals = [
          { value: 31536000, short: 'y' },
          { value: 2592000,  short: 'mo' },
          { value: 86400,    short: 'd' },
          { value: 3600,     short: 'h' },
          { value: 60,       short: 'm' }
      ];
      for (let i = 0; i < intervals.length; i++) {
          const interval = intervals[i];
          const count = Math.floor(secondsAgo / interval.value);
          if (count >= 1) return `${count}${interval.short} ago`;
      }
      return `${Math.floor(secondsAgo)}s ago`;
  }
  
  // [CẢI TIẾN] Helper map class cho severity
  function clsStatus(s) {
    const t = (s || "").toLowerCase();
    if (t === "critical" || t === "high") return "status-blocked";
    if (t === "medium") return "status-investigating";
    if (t === "low") return "status-monitoring";
    if (t === "new") return "status-new";
    if (t === "resolved") return "status-resolved";
    // Fallback
    if (t.includes("critical") || t.includes("high")) return "status-blocked";
    if (t.includes("medium")) return "status-investigating";
    return "status-monitoring";
  }

  // ===== Summary (API) =====
  async function loadSummary() {
    try {
      const { data } = await getJSON("/api/alerts/metrics");
      
      const critical = data?.by_severity?.critical || 0;
      const anomalies = data?.by_status?.new || 0;
      const investigating = data?.by_status?.investigating || 0;

      $("#critical-count").textContent = fmt.format(critical);
      $("#anomaly-count").textContent  = fmt.format(anomalies + investigating);
      
      // Dữ liệu này vẫn thiếu từ API /metrics, cần API riêng
      $("#blocked-count").textContent  = "N/A";
      $("#safe-count").textContent     = "N/A";

      // Chỉ hiển thị "new" nếu có, nếu không thì ẩn đi
      $("#critical-new").textContent = critical > 0 ? "new" : "";
      $("#anomaly-new").textContent  = (anomalies + investigating) > 0 ? "new" : "";
      
    } catch (e) {
      showToast("Cannot load summary: " + e.message, true);
    }
  }

  // ===== Timeline (API) =====
  function renderTimeline(items) {
    const ul = $("#timeline-list");
    ul.innerHTML = "";
    
    items.forEach(it => {
      const li = document.createElement("li");
      li.innerHTML = `
        <span class="incident-name">${it.alert_message || "New Alert"}</span>
        <span class="incident-time">${formatTimeAgo(it.sent_at)}</span> <span class="${clsStatus(it.severity || it.alert_level)}">${it.severity || it.alert_level}</span>
      `;
      ul.appendChild(li);
    });
  }

  async function loadTimeline() {
    try {
      const { data } = await getJSON("/api/alerts?page=1&page_size=10");
      renderTimeline(data || []);
    } catch (e) {
      showToast("Cannot load timeline: " + e.message, true);
    }
  }

  // ===== Top IPs (API) =====
  // (Giữ nguyên logic loadTopIPs, renderTopIPs, loadCharts, ensureAttackChart, ensureTrafficChart)
  // ... (Các hàm này vẫn sẽ báo lỗi API not found cho đến khi bạn tạo chúng ở backend)
  function renderTopIPs(rows) {
    const ul = $("#ip-list");
    ul.innerHTML = "";
    if (rows.length === 0) {
        ul.innerHTML = "<li>(API /api/dashboard/top-ips not found)</li>";
    }
    rows.forEach(r => {
      const li = document.createElement("li");
      li.innerHTML = `
        <span><i class="fa-solid fa-flag"></i> ${r.ip} <span class="ip-country">${r.country || ""}</span></span>
        <button class="btn-block-ip" data-ip="${r.ip}">Block</button>
      `;
      ul.appendChild(li);
    });
    $$(".btn-block-ip").forEach(btn => {
      btn.addEventListener("click", async () => {
        const ip = btn.getAttribute("data-ip");
        if (!confirm(`Block IP ${ip}? (Lưu ý: Yêu cầu API /api/ips/block phía backend)`)) return;
        try {
          const res = await fetch(`${API_BASE}/api/ips/block`, {
              method:"POST", 
              headers:{"Content-Type":"application/json"}, 
              body: JSON.stringify({ ip: ip, reason: "Blocked from dashboard" })
          });
          if (!res.ok) {
              const err = await res.json();
              throw new Error(err.message || "Failed to block");
          }
          btn.textContent = "Blocked";
          btn.disabled = true;
          btn.style.backgroundColor = "#555";
          showToast(`Block request sent for ${ip}`);
        } catch (e) {
          alert("Block failed: " + e.message);
        }
      });
    });
  }
  async function loadTopIPs() {
    try {
      const { data } = await getJSON("/api/dashboard/top-ips?limit=10");
      renderTopIPs(data || []);
    } catch (e) {
      showToast("Cannot load top IPs: API /api/dashboard/top-ips not found.", true);
      renderTopIPs([]);
    }
  }
  Chart.defaults.color = '#a0a0b8';
  Chart.defaults.borderColor = '#40405c';
  let attackChart, trafficChart;
  function ensureAttackChart(labels = [], counts = []) {
    const ctx = document.getElementById('attackTypeChart').getContext('2d');
    if (attackChart) {
      attackChart.data.labels = labels;
      attackChart.data.datasets[0].data = counts;
      attackChart.update();
      return;
    }
    attackChart = new Chart(ctx, {
      type: 'bar',
      data: { labels, datasets: [{ label: 'Số vụ tấn công', data: counts, backgroundColor: ['#e94560','#f0a050','#4d79ff','#9a50f0','#30e3ca','#ffd166'], borderRadius: 4 }] },
      options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, title: { text: (labels.length === 0 ? "API /api/dashboard/attack-types not found" : ""), display: true } } } }
    });
  }
  function ensureTrafficChart(labels = [], allowed = [], blocked = []) {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    if (trafficChart) {
      trafficChart.data.labels = labels;
      trafficChart.data.datasets[0].data = allowed;
      trafficChart.data.datasets[1].data = blocked;
      trafficChart.update();
      return;
    }
    trafficChart = new Chart(ctx, {
      type: 'line',
      data: { labels, datasets: [ { label: 'Request Hợp lệ', data: allowed, borderColor: '#30e3ca', backgroundColor: 'rgba(48,227,202,.1)', fill: true, tension: .3 }, { label: 'Request Bị chặn', data: blocked, borderColor: '#e94560', backgroundColor: 'rgba(233,69,96,.1)', fill: true, tension: .3 } ] },
      options: { responsive: true, plugins: { legend: { position: 'top' } }, scales: { y: { beginAtZero: true, title: { text: (labels.length === 0 ? "API /api/dashboard/traffic not found" : ""), display: true } } } }
    });
  }
  async function loadCharts() {
    try {
      const atk = await getJSON("/api/dashboard/attack-types?window=24h");
      ensureAttackChart(atk.labels || [], atk.counts || []);
    } catch (e) {
      showToast("Cannot load attack types: API not found.", true);
      ensureAttackChart([], []);
    }
    try {
      const tr = await getJSON("/api/dashboard/traffic?window=24h");
      ensureTrafficChart(tr.labels || [], tr.allowed || [], tr.blocked || []);
    } catch (e) {
      showToast("Cannot load traffic: API not found.", true);
      ensureTrafficChart([], [], []);
    }
  }

  // ===============================================
  // ===== WebSocket (Cải tiến Realtime) =====
  // ===============================================

  // [CẢI TIẾN] Helper: Tăng số đếm trên UI
  function incrementUICount(selector) {
    const el = $(selector);
    if (!el) return;
    
    // Tìm nhãn "new" bên cạnh (nếu có)
    const newLabel = el.querySelector(".new-alert") || el.nextElementSibling;
    
    // Lấy số hiện tại, dọn dẹp (xóa dấu phẩy), + 1
    const currentCount = parseInt((el.textContent || "0").replace(/[,\.]/g, "")) || 0;
    el.textContent = fmt.format(currentCount + 1);

    // Thêm lại nhãn "new" nếu nó bị ghi đè
    if (newLabel && !el.querySelector(".new-alert")) {
        el.appendChild(newLabel);
    }
    if (newLabel) {
        newLabel.textContent = "new";
    }
  }
  
  // [CẢI TIẾN] Helper: Cập nhật Timeline
  function updateTimelineRealtime(data) {
      const ul = $("#timeline-list");
      if (!ul) return;

      const li = document.createElement("li");
      li.innerHTML = `
        <span class="incident-name">${data.brief || "New Alert"} (IP: ${data.src_ip || 'N/A'})</span>
        <span class="incident-time">${formatTimeAgo(data.ts)}</span>
        <span class="${clsStatus(data.severity)}">${data.severity || "New"}</span>
      `;
      ul.prepend(li);
      
      // Giới hạn số lượng mục timeline
      while (ul.children.length > 20) {
          ul.removeChild(ul.lastChild);
      }
  }
  
  // [CẢI TIẾN] Helper: Cập nhật các ô Summary
  function updateSummaryRealtime(data) {
      const severity = (data.severity || "").toLowerCase();

      if (severity === "critical" || severity === "high") {
          incrementUICount("#critical-count");
      }
      
      // Giả định: Mọi cảnh báo mới (new) đều là "anomaly"
      // (Bạn có thể cần thay đổi logic này nếu "new" không phải lúc nào cũng là anomaly)
      incrementUICount("#anomaly-count");
      
      // LƯU Ý: API "metrics" không có "blocked". 
      // Nếu "alert.new" có thể là "blocked", bạn cần thêm logic ở đây.
      // Ví dụ: if (data.status === 'blocked') { incrementUICount("#blocked-count"); }
  }


  function connectWS() {
    try {
      const proto = (location.protocol === "https:") ? "wss://" : "ws://";
      // [ĐÃ SỬA] wsUrl giờ sẽ dùng WS_PATH (là /ws)
      const wsUrl = proto + location.host + WS_PATH;
      console.log(`Connecting WS to: ${wsUrl}`); // Thêm log để debug
      
      const ws = new WebSocket(wsUrl);
      
      ws.onopen = () => {
          showToast("Realtime connection established");
          $("#system-status").textContent = "ONLINE";
          $("#system-status").className = "status-online";
      };
      
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data);

          // Xử lý tin nhắn Heartbeat từ backend (nếu có)
          if (msg.name === "Heartbeat") {
              // console.log("WS Heartbeat received");
              return;
          }

          // Xử lý tin nhắn cảnh báo mới
          if (msg.type === "alert.new") {
            const data = msg.data;

            // [CẢI TIẾN] Gọi các hàm helper
            updateTimelineRealtime(data);
            updateSummaryRealtime(data);
            
            // Hiển thị thông báo
            showToast(`New Alert [${data.severity}]: ${data.brief}`);
            
            // TODO: Bạn cũng có thể gọi loadTopIPs() hoặc loadCharts()
            // nhưng làm vậy sẽ spam API. Tốt hơn là để setInterval xử lý.
          }
          
        } catch (e) {
            console.error("WS message parse error:", e, ev.data);
        }
      };
      
      ws.onclose = () => {
          showToast("Realtime connection lost. Reconnecting...", true);
          $("#system-status").textContent = "OFFLINE";
          $("#system-status").className = "status-offline";
          setTimeout(connectWS, 3000); // tự reconnect
      };
      
      ws.onerror = (err) => {
          console.error("WS error:", err);
          showToast("WS connection error.", true);
          ws.close(); // Kích hoạt onclose để reconnect
      };
      
    } catch (e) {
      showToast("WS failed to init: " + e.message, true);
    }
  }

  // ===== Buttons =====
  // (Giữ nguyên logic các nút)
  $("#btn-investigate").addEventListener("click", () => window.location.href = "/alerts?alert_level=critical");
  $("#btn-view-logs").addEventListener("click", () => window.location.href = "/alerts?status=resolved");
  $("#btn-analyze").addEventListener("click", () => window.location.href = "/alerts?status=new");
  $("#btn-monitor").addEventListener("click", () => window.location.href = "/alerts?alert_level=info");

  // ===== Initial load & auto refresh =====
  function withLoading(fn, nodes = []) {
    nodes.forEach(n => n && n.classList.add("loading"));
    return fn().finally(() => nodes.forEach(n => n && n.classList.remove("loading")));
  }

  const firstLoad = async () => {
    await Promise.all([
      withLoading(loadSummary,  [$("#critical-threats"), $("#blocked-requests"), $("#suspicious-anomalies"), $("#safe-requests")]),
      withLoading(loadTimeline,  [$("#incident-timeline")]),
      withLoading(loadTopIPs,   [$("#top-ips")]),
      withLoading(loadCharts,   [$(".widget-row")])
    ]);
  };

  // Khởi chạy
  firstLoad();
  connectWS(); // Khởi chạy WebSocket

  // Refresh định kỳ (vẫn giữ lại để đảm bảo dữ liệu đồng bộ)
  // WebSocket chỉ xử lý "tin nhắn mới", không xử lý "dữ liệu cũ"
  setInterval(loadSummary,  30_000); // Tăng thời gian lên 30s vì đã có WS
  setInterval(loadTimeline, 60_000); // Tăng thời gian lên 60s
  setInterval(loadTopIPs,   60_000); // Sẽ tiếp tục thất bại trừ khi bạn tạo API
  setInterval(loadCharts,   60_000); // Sẽ tiếp tục thất bại trừ khi bạn tạo API
});