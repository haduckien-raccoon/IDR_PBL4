// static/js/analytics.js
document.addEventListener("DOMContentLoaded", () => {
    const API_BASE = (window.__CONFIG__ && window.__CONFIG__.API_BASE) || "";
    
    // Helpers
    const $ = (id) => document.getElementById(id);
    
    // Chart instances (để destroy trước khi vẽ lại)
    let charts = {
        trend: null,
        severity: null,
        country: null
    };

    // Hàm gọi API
    async function fetchData(endpoint, params = {}) {
        const url = new URL(API_BASE + endpoint, window.location.origin);
        Object.keys(params).forEach(key => {
            if (params[key]) url.searchParams.append(key, params[key]);
        });

        try {
            const res = await fetch(url);
            if (!res.ok) throw new Error("API Error");
            return await res.json();
        } catch (e) {
            console.error(`Fetch error ${endpoint}:`, e);
            return null;
        }
    }

    // --- 1. Lấy tham số Filter ---
    function getFilterParams() {
        const mode = $("range-mode").value;
        const fromDate = $("range-from").value;
        const toDate = $("range-to").value;
        
        // Update UI text status
        let label = "LAST 30 DAYS";
        if (mode === '7d') label = "LAST 7 DAYS";
        if (mode === '90d') label = "LAST 90 DAYS";
        if (mode === 'custom') label = `FROM ${fromDate} TO ${toDate}`;
        $("status-period").textContent = label;

        return { mode, from_date: fromDate, to_date: toDate };
    }

    // --- 2. Vẽ Chart: Trend (Line) ---
    async function renderTrendChart(params) {
        const data = await fetchData("/api/analytics/trend", params);
        if (!data) return;

        const ctx = $("trendChart").getContext("2d");
        if (charts.trend) charts.trend.destroy();

        charts.trend = new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.labels,
                datasets: [{
                    label: 'Attacks',
                    data: data.data,
                    borderColor: '#4d79ff',
                    backgroundColor: 'rgba(77, 121, 255, 0.1)',
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: { 
                    x: { grid: { color: '#333' } },
                    y: { grid: { color: '#333' }, beginAtZero: true } 
                }
            }
        });
    }

    // --- 3. Vẽ Chart: Severity (Doughnut/Radar) ---
    async function renderSeverityChart(params) {
        const data = await fetchData("/api/analytics/severity", params);
        if (!data) return;

        // Map data object {critical: 5, low: 10} sang array
        const labels = ["Critical", "High", "Medium", "Low"];
        const values = [
            data.critical || 0,
            data.high || 0,
            data.medium || 0,
            data.low || 0
        ];
        const colors = ['#e94560', '#f0a050', '#ffd166', '#30e3ca'];

        const ctx = $("severityChart").getContext("2d");
        if (charts.severity) charts.severity.destroy();

        charts.severity = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: colors,
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '60%',
                plugins: { legend: { position: 'bottom' } }
            }
        });
    }

    // --- 4. Vẽ Chart: Top Countries (Bar) ---
    async function renderCountryChart(params) {
        const data = await fetchData("/api/analytics/top-countries", params);
        if (!data) return;

        const ctx = $("countryChart").getContext("2d");
        if (charts.country) charts.country.destroy();

        charts.country = new Chart(ctx, {
            type: 'bar',
            indexAxis: 'y', // Biểu đồ ngang
            data: {
                labels: data.labels,
                datasets: [{
                    label: 'Events',
                    data: data.data,
                    backgroundColor: '#30e3ca',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { display: false } },
                scales: { x: { grid: { color: '#333' } }, y: { grid: { display: false } } }
            }
        });
    }

    // --- 5. Render Heatmap (Thủ công) ---
    async function renderHeatmap(params) {
        const data = await fetchData("/api/analytics/heatmap", params);
        const container = $("heatmap-container");
        container.innerHTML = ""; // Clear old

        // 1. Vẽ Header giờ (0-23)
        container.appendChild(document.createElement("div")); // Empty corner
        for(let h=0; h<24; h++) {
            const div = document.createElement("div");
            div.className = "hm-label-x";
            div.textContent = h;
            container.appendChild(div);
        }

        // 2. Vẽ Các hàng thứ (Mon-Sun)
        const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
        
        // Tạo map lookup nhanh: key="day-hour", val=count
        const lookup = {};
        if (data) {
            data.forEach(item => { lookup[`${item.day}-${item.hour}`] = item.value; });
        }

        for(let d=0; d<7; d++) {
            // Label thứ
            const label = document.createElement("div");
            label.className = "hm-label-y";
            label.textContent = days[d];
            container.appendChild(label);

            // 24 ô trong ngày
            for(let h=0; h<24; h++) {
                const cell = document.createElement("div");
                cell.className = "hm-cell";
                const val = lookup[`${d}-${h}`] || 0;
                
                // Color scale logic đơn giản
                if (val > 50) cell.classList.add("hm-l5");
                else if (val > 20) cell.classList.add("hm-l4");
                else if (val > 10) cell.classList.add("hm-l3");
                else if (val > 0) cell.classList.add("hm-l2");
                else cell.classList.add("hm-l1"); // Empty/Low

                cell.title = `${days[d]} ${h}:00 - ${val} attacks`;
                container.appendChild(cell);
            }
        }
    }

    // --- 6. Main Logic ---
    function updateAllCharts() {
        const params = getFilterParams();
        renderTrendChart(params);
        renderSeverityChart(params);
        renderCountryChart(params);
        renderHeatmap(params);
    }

    // Event Listeners
    $("btn-update-stats").addEventListener("click", updateAllCharts);
    
    $("range-mode").addEventListener("change", (e) => {
        const isCustom = e.target.value === "custom";
        $("custom-date-row").style.display = isCustom ? "flex" : "none";
        if (!isCustom) updateAllCharts(); // Auto update if not custom
    });

    // Init
    Chart.defaults.color = '#a0a0b8';
    Chart.defaults.borderColor = '#40405c';
    updateAllCharts();
});