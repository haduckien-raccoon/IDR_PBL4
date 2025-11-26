// dashboard.js
document.addEventListener("DOMContentLoaded", () => {
    console.log("Dashboard script loaded!");
  
    const API_BASE = (window.__CONFIG__ && window.__CONFIG__.API_BASE) || "";
    const WS_PATH  = (window.__CONFIG__ && window.__CONFIG__.WS_PATH)  || "/ws";
  
    // Helpers
    const $  = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);
    const fmt = new Intl.NumberFormat('en-US');
  
    async function getJSON(path) {
      const url = API_BASE + path;
      console.log(`[API] Fetching: ${url}`);
      const res = await fetch(url, { headers: { "Accept": "application/json" } });
      if (!res.ok) {
          const errText = await res.text();
          console.error(`[API] Failed: ${url}`, res.status, errText);
          throw new Error(`API ${path} failed: ${res.status} ${res.statusText} - ${errText}`);
      }
      return res.json();
    }
  
    function showToast(msg, isError = false) {
      if (isError) {
        console.error("[Toast]", msg);
      } else {
        console.log("[Toast]", msg);
      }
      // Thêm logic hiển thị UI cho toast ở đây nếu bạn muốn
    }
  
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
    
    function clsStatus(s) {
      const t = (s || "").toLowerCase();
      if (t === "critical" || t === "high") return "status-blocked";
      if (t === "medium") return "status-investigating";
      if (t === "low") return "status-monitoring";
      if (t === "new") return "status-new";
      if (t === "resolved") return "status-resolved";
      if (t.includes("critical") || t.includes("high")) return "status-blocked";
      if (t.includes("medium")) return "status-investigating";
      return "status-monitoring";
    }
  
    // ===== Summary (API) =====
    async function loadSummary() {
      let data = {};
      try {
        const res = await getJSON("/api/dashboard/summary");
        data = (res && typeof res === "object") ? res : {};
        console.log("[Data] Summary data loaded:", data);
      } catch (e) {
        console.error("Cannot load summary:", e);
      }
      const critical  = Number(data.critical)  || 0;
      const blocked   = Number(data.blocked)   || 0;
      const anomalies = Number(data.anomalies) || 0;
      const safe      = Number(data.safe)      || 0;
      
      // Sửa lỗi: Cập nhật giá trị vào các span có ID mới
      $("#critical-count-value").textContent  = fmt.format(critical);
      $("#blocked-count-value").textContent   = fmt.format(blocked);
      $("#anomaly-count-value").textContent   = fmt.format(anomalies);
      $("#safe-count-value").textContent      = fmt.format(safe); // Cập nhật safe count
      
      // Hiển thị/ẩn "new" alert
      $("#critical-new").textContent  = critical  > 0 ? "new" : "";
      $("#blocked-new").textContent   = blocked   > 0 ? "new" : "";
      $("#anomaly-new").textContent   = anomalies > 0 ? "new" : "";
      $("#safe-new").textContent      = ""; // Safe requests thường không có "new" alert
    }
  
    // ===== Timeline (API) =====
    function renderTimeline(items) {
      const ul = $("#timeline-list");
      ul.innerHTML = "";
      if (items.length === 0) {
        ul.innerHTML = "<li>No recent incidents found.</li>";
      }
      items.forEach(it => {
        const li = document.createElement("li");
        li.innerHTML = `
          <span class="incident-name">${it.name || "New Alert"}</span>
          <span class="incident-time">${it.time_ago || "just now"}</span> 
          <span class="${clsStatus(it.status)}">${it.status || "new"}</span>
        `;
        ul.appendChild(li);
      });
    }
  
    async function loadTimeline() {
      try {
        const items = await getJSON("/api/dashboard/timeline?limit=10"); 
        console.log("[Data] Timeline data loaded:", items);
        renderTimeline(items || []);
      } catch (e) {
        showToast("Cannot load timeline: " + e.message, true);
        renderTimeline([]); 
      }
    }
  
    // ===== Top IPs (API) =====
    function renderTopIPs(rows) {
      const ul = $("#ip-list");
      ul.innerHTML = "";
      if (rows.length === 0 || !rows) {
          ul.innerHTML = "<li>No attack IP data yet.</li>";
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
        const rows = await getJSON("/api/dashboard/top-ips?limit=10");
        console.log("[Data] Top IPs data loaded:", rows);
        renderTopIPs(rows || []);
      } catch (e) {
        showToast("Cannot load top IPs: " + e.message, true);
        renderTopIPs([]);
      }
    }
  
    // ===== Charts (API) =====
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
        console.log("[Data] Attack types data loaded:", atk);
        ensureAttackChart(atk.labels || [], atk.counts || []);
      } catch (e) {
        showToast("Cannot load attack types: API not found.", true);
        ensureAttackChart([], []);
      }
      try {
        const tr = await getJSON("/api/dashboard/traffic?window=24h");
        console.log("[Data] Traffic data loaded:", tr);
        ensureTrafficChart(tr.labels || [], tr.allowed || [], tr.blocked || []);
      } catch (e) {
        showToast("Cannot load traffic: API not found.", true);
        ensureTrafficChart([], [], []);
      }
    }
  
    // ===== WebSocket (Realtime) =====
    // Sửa lỗi: `selector` bây giờ là ID của phần tử chứa giá trị (ví dụ: '#critical-count-value')
    // `newAlertSelector` là ID của phần tử "new" (ví dụ: '#critical-new')
    function incrementUICount(valueSelector, newAlertSelector) {
      const el = $(valueSelector);
      const newAlertEl = $(newAlertSelector);
      if (!el) {
          console.warn(`Element with selector ${valueSelector} not found.`);
          return;
      }
      
      const currentCount = parseInt((el.textContent || "0").replace(/[,\.]/g, "")) || 0;
      el.textContent = fmt.format(currentCount + 1);
      
      if (newAlertEl) {
          newAlertEl.textContent = "new";
      }
    }
    
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
        while (ul.children.length > 20) {
            ul.removeChild(ul.lastChild);
        }
    }
    
    function updateSummaryRealtime(data) {
        const severity = (data.severity || "").toLowerCase();
        if (severity === "critical" || severity === "high") {
            incrementUICount("#critical-count-value", "#critical-new");
        }
        // Giả sử tất cả alerts mới đều tăng Anomalies
        incrementUICount("#anomaly-count-value", "#anomaly-new");
        // Bạn có thể thêm logic cho blocked nếu có dữ liệu tương ứng trong WS message
        // incrementUICount("#blocked-count-value", "#blocked-new"); 
    }
  
    function connectWS() {
      try {
        const proto = (location.protocol === "https:") ? "wss://" : "ws://";
        const wsUrl = proto + location.host + WS_PATH;
        console.log(`[WS] Connecting to: ${wsUrl}`);
        
        const ws = new WebSocket(wsUrl);
        
        ws.onopen = () => {
            showToast("Realtime connection established");
            $("#system-status").textContent = "ONLINE";
            $("#system-status").className = "status-online";
            console.log("[WS] Connected");
        };
        
        ws.onmessage = (ev) => {
          try {
            const msg = JSON.parse(ev.data);
            console.log("[WS] Received message:", msg);
  
            if (msg.name === "Heartbeat") {
                return;
            }
            if (msg.type === "alert.new") {
              const data = msg.data;
              updateTimelineRealtime(data);
              updateSummaryRealtime(data);
              showToast(`New Alert [${data.severity}]: ${data.brief}`);
            }
          } catch (e) {
              console.error("WS message parse error:", e, ev.data);
          }
        };
        
        ws.onclose = () => {
            showToast("Realtime connection lost. Reconnecting...", true);
            $("#system-status").textContent = "OFFLINE";
            $("#system-status").className = "status-offline";
            console.log("[WS] Closed. Reconnecting...");
            setTimeout(connectWS, 3000); 
        };
        
        ws.onerror = (err) => {
            console.error("[WS] Error:", err);
            showToast("WS connection error.", true);
            ws.close(); 
        };
        
      } catch (e) {
        showToast("WS failed to init: " + e.message, true);
      }
    }
  
    // ===== Buttons =====
    // Sửa các đường dẫn để khớp với routes trong main.py
    $("#btn-investigate").addEventListener("click", () => window.location.href = "/incidents");
    $("#btn-view-logs").addEventListener("click", () => window.location.href = "/incidents"); 
    $("#btn-analyze").addEventListener("click", () => window.location.href = "/view_alert?status=new");
    $("#btn-monitor").addEventListener("click", () => window.location.href = "/api/logs/traffic");
  
    // ===== Initial load & auto refresh =====
    function withLoading(fn, nodes = []) {
      nodes.forEach(n => n && n.classList.add("loading"));
      return fn().finally(() => nodes.forEach(n => n && n.classList.remove("loading")));
    }
  
    const firstLoad = async () => {
      console.log("Performing first data load...");
      await Promise.all([
        withLoading(loadSummary,  [$("#critical-threats"), $("#blocked-requests"), $("#suspicious-anomalies"), $("#safe-requests")]),
        withLoading(loadTimeline,  [$("#incident-timeline")]),
        withLoading(loadTopIPs,   [$("#top-ips")]),
        withLoading(loadCharts,   [$(".widget-row")])
      ]);
      console.log("First data load complete.");
    };
  
    // Khởi chạy
    firstLoad();
    connectWS(); 
  
    // Refresh định kỳ
    setInterval(loadSummary,  30_000); 
    setInterval(loadTimeline, 60_000); 
    setInterval(loadTopIPs,   60_000); 
    setInterval(loadCharts,   60_000); 
});