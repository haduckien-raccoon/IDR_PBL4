// static/js/incident.js (Đã sửa lỗi cú pháp và logic filter)

document.addEventListener("DOMContentLoaded", () => {
    // Lấy API base URL từ biến cấu hình trong incident.html
    const API_BASE = window.__CONFIG__.API_BASE || '/api';

    // Lưu lại event đang được chọn (để reload sau khi block/unblock, đổi status)
    let currentEventId = null;
    let currentSourceIp = null;

    // --- HELPER FUNCTIONS ---

    // Hàm gọi API
    async function fetchData(endpoint, options = {}) {
        try {
            const response = await fetch(`${API_BASE}${endpoint}`, options);
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`HTTP error! status: ${response.status} - ${errorText}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`Error fetching data from ${endpoint}:`, error);
            return null;
        }
    }

    // Hàm định dạng thời gian
    function formatTime(isoString) {
        if (!isoString) return '';
        const date = new Date(isoString);
        return date.toLocaleString('sv-SE', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        }).replace(' ', ' ');
    }

    // Hàm tạo badge (tag màu) dựa trên severity
    function createSeverityBadge(severity) {
        if (!severity) return '';
        const severityClass = severity.toLowerCase(); // critical, high, medium, low
        return `<span class="badge badge-${severityClass}">${severity.charAt(0).toUpperCase() + severity.slice(1)}</span>`;
    }

    // Hàm tạo status tag
    function createStatusTag(status) {
        let statusClass;
        if (status === 'new') statusClass = 'status-monitoring';
        else if (status === 'investigating') statusClass = 'status-investigating';
        else if (status === 'resolved') statusClass = 'status-resolved';
        else statusClass = 'status-monitoring';

        const displayStatus = (status || '').toUpperCase();
        return `<span class="${statusClass}">${displayStatus}</span>`;
    }

    // Function to collect all filter values
    function getFilters() {
        const filters = {};
        
        // Read all filter inputs
        const dateFrom = document.getElementById('from-date').value;
        if (dateFrom) filters.from_date = dateFrom;
        
        const dateTo = document.getElementById('to-date').value;
        if (dateTo) filters.to_date = dateTo;

        const attackTypeId = document.getElementById('attack-type').value;
        if (attackTypeId) filters.attack_type_id = parseInt(attackTypeId);

        const severity = document.getElementById('severity').value;
        if (severity) filters.severity = severity;
        
        // Status filter
        const status = document.getElementById('status-filter')?.value; 
        if (status) filters.status = status; 

        return filters;
    }

    // --- LOAD DATA FUNCTIONS ---

    // 1. Load các giá trị Enum cho Bộ lọc (Loại tấn công)
    async function loadFilters() {
        const attackSelect = document.getElementById('attack-type');
        attackSelect.innerHTML = '<option value="">All</option>';

        const data = await fetchData('/attack-types');

        if (data && data.length > 0) {
            data.forEach(item => {
                const option = document.createElement('option');
                option.value = item.attack_id;
                option.textContent = item.attack_name;
                attackSelect.appendChild(option);
            });
        }
    }

    // 2. Load Thống kê nhanh
    async function loadQuickStats() {
        const data = await fetchData('/stats/quick');
        if (data) {
            document.getElementById('incident-today').textContent = data.incident_today;
            document.getElementById('incident-open').textContent = data.incident_open;
            document.getElementById('blocked-ip-count').textContent = data.blocked_ip_count;
        } else {
            document.getElementById('incident-today').textContent = '—';
            document.getElementById('incident-open').textContent = '—';
            document.getElementById('blocked-ip-count').textContent = '—';
        }
    }

    // 3. Load Danh sách sự kiện
    // ĐÃ SỬA: Bỏ tham số `filters` không cần thiết trong định nghĩa hàm
    async function loadIncidents() {
        const tbody = document.querySelector('#incident-table tbody');

        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;">Loading data...</td></tr>';

        // Lấy filters và xây dựng query string
        const filters = getFilters();
        const queryString = new URLSearchParams(filters).toString();
        const url = `/events${queryString ? '?' + queryString : ''}`;
        
        const events = await fetchData(url);

        if (events && events.length > 0) {
            tbody.innerHTML = ''; 
            events.forEach(event => {
                const row = tbody.insertRow();
                row.insertCell().textContent = formatTime(event.timestamp);
                row.insertCell().textContent = event.source_ip;
                row.insertCell().textContent = event.destination_ip;
                row.insertCell().textContent = event.attack_type.attack_name;

                row.insertCell().innerHTML = createSeverityBadge(event.severity);
                row.insertCell().innerHTML = createStatusTag(event.status);

                const actionCell = row.insertCell();
                actionCell.style.textAlign = 'right';
                const button = document.createElement('button');
                button.className = 'btn btn-secondary btn-sm details-btn';
                button.innerHTML = '<i class="fa-solid fa-eye"></i> Details';
                button.setAttribute('data-event-id', event.event_id);
                button.addEventListener('click', () => loadIncidentDetails(event.event_id, event.source_ip));
                actionCell.appendChild(button);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;">No incidents found.</td></tr>';
        }
        
        // Clear details nếu không có sự kiện
        if (events === null || events.length === 0) {
            currentEventId = null;
            currentSourceIp = null;
            // Xóa chi tiết sự kiện
            document.getElementById('incident-detail').innerHTML = '<li><strong>Source IP:</strong> –</li><li><strong>Destination IP:</strong> –</li><li><strong>Attack Type:</strong> –</li><li><strong>Severity:</strong> –</li><li><strong>Detected By:</strong> –</li><li><strong>Payload:</strong> –</li>';
            document.getElementById('log-viewer').textContent = 'Select an event to view the log.';
            document.getElementById('action-buttons').innerHTML = '<p style="font-size:0.85rem;color:var(--text-secondary);">Select an event to view the action.</p>';
        }
    }

    // 4. Load Chi tiết sự kiện
    async function loadIncidentDetails(eventId, sourceIp) {
        const detailList = document.getElementById('incident-detail');
        const logViewer = document.getElementById('log-viewer');
        const actionButtonsDiv = document.getElementById('action-buttons');

        // Lưu lại event hiện tại
        currentEventId = eventId;
        currentSourceIp = sourceIp;

        detailList.innerHTML = '<li><strong>Loading...</strong></li>';
        logViewer.textContent = 'Loading log...';
        actionButtonsDiv.innerHTML = '<p style="font-size:0.85rem;color:var(--text-secondary);">Loading actions...</p>';

        const event = await fetchData(`/events/${eventId}`);
        // Dùng Promise.all để lấy ipStatus (như trong các bản sửa lỗi trước)
        const ipStatus = await fetchData(`/ip/status/${sourceIp}`); 

        // ĐÃ SỬA: Chỉ chạy logic khi cả event và ipStatus (hoặc event) được tải thành công
        if (event) {
            detailList.innerHTML = `
                <li><strong>Event ID:</strong> ${event.event_id}</li>
                <li><strong>Source IP:</strong> ${event.source_ip}</li>
                <li><strong>Destination IP:</strong> ${event.destination_ip}</li>
                <li><strong>Attack Type:</strong> ${event.attack_type.attack_name}</li>
                <li><strong>Severity:</strong> ${createSeverityBadge(event.severity)}</li>
                <li><strong>Detected By:</strong> ${event.detected_by}</li>
                <li><strong>Payload mẫu:</strong> ${event.description || 'N/A'}</li>
            `;
            logViewer.textContent =
                `# Log cho Event ID: ${eventId}\n` +
                `[${formatTime(event.timestamp)}] ${event.source_ip} -> ${event.destination_ip} [${event.attack_type.attack_name}]\n` +
                `Payload: ${event.description || 'No detailed log.'}`;

            actionButtonsDiv.innerHTML = '';
            
            // Nút IP Block / Unblock
            // Đã sửa lỗi: Kiểm tra ipStatus trước khi sử dụng
            const isBlocked = ipStatus && ipStatus.status === 'blocked';
            const ipBlockButton = document.createElement('button');

            if (isBlocked) {
                ipBlockButton.className = 'btn btn-success ip-unblock-btn';
                ipBlockButton.innerHTML = `<i class="fa-solid fa-unlock-alt"></i> UNBLOCK IP`;
                ipBlockButton.addEventListener('click', () => unblockIP(sourceIp));
            } else {
                ipBlockButton.className = 'btn btn-danger ip-block-btn';
                ipBlockButton.innerHTML = `<i class="fa-solid fa-user-slash"></i> BLOCK IP`;
                ipBlockButton.addEventListener('click', () => blockIP(sourceIp));
            }
            actionButtonsDiv.appendChild(ipBlockButton);

            // Nút Send Email
            const emailBtn = document.createElement('button');
            emailBtn.className = 'btn btn-secondary';
            emailBtn.innerHTML = `<i class="fa-solid fa-envelope"></i> Send Email`;
            // Gắn sự kiện
            emailBtn.addEventListener('click', () => sendIncidentEmail(eventId)); 
            actionButtonsDiv.appendChild(emailBtn);

            // Nút đổi trạng thái
            let targetStatus = '';

            if (event.status === 'new') {
                // INVESTIGATING
                const investigatingBtn = document.createElement('button');
                investigatingBtn.className = 'btn btn-secondary status-change-btn';
                investigatingBtn.innerHTML = `<i class="fa-solid fa-search"></i> INVESTIGATING`;
                investigatingBtn.addEventListener('click', () => changeIncidentStatus(event.event_id, 'investigating', event.source_ip));
                actionButtonsDiv.appendChild(investigatingBtn);
                
                // RESOLVED
                const resolvedBtn = document.createElement('button');
                resolvedBtn.className = 'btn btn-secondary resolve-btn';
                resolvedBtn.innerHTML = `<i class="fa-solid fa-check"></i> RESOLVED`;
                resolvedBtn.addEventListener('click', () => changeIncidentStatus(event.event_id, 'resolved', event.source_ip));
                actionButtonsDiv.appendChild(resolvedBtn);

            } else if (event.status === 'investigating') {
                targetStatus = 'resolved';
                const statusBtn = document.createElement('button');
                statusBtn.className = 'btn btn-secondary status-change-btn';
                statusBtn.innerHTML = `<i class="fa-solid fa-check"></i> RESOLVED`;
                statusBtn.addEventListener('click', () => changeIncidentStatus(event.event_id, targetStatus, event.source_ip));
                actionButtonsDiv.appendChild(statusBtn);

            } else if (event.status === 'resolved') {
                targetStatus = 'investigating';
                const statusBtn = document.createElement('button');
                statusBtn.className = 'btn btn-secondary status-change-btn';
                statusBtn.innerHTML = `<i class="fa-solid fa-search"></i> INVESTIGATING`;
                statusBtn.addEventListener('click', () => changeIncidentStatus(event.event_id, targetStatus, event.source_ip));
                actionButtonsDiv.appendChild(statusBtn);
            }
        } else {
            detailList.innerHTML = '<li><strong>Error loading data or incident not found.</strong></li>';
            logViewer.textContent = 'Failed to load log.';
            actionButtonsDiv.innerHTML =
                '<p style="font-size:0.85rem;color:var(--text-secondary);">Error loading actions.</p>';
        }
    }

    // 5. Chức năng Block IP
    async function blockIP(ipAddress) {
        if (!confirm(`Are you sure you want to block IP ${ipAddress}?`)) return;

        try {
            const response = await fetch(`${API_BASE}/action/block-ip`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ip_address: ipAddress,
                    reason: 'Manual Block from Incident Page'
                })
            });

            if (!response.ok) throw new Error("API failed");

            alert(`Success: Blocked IP ${ipAddress} for 15 minutes.`);
            await loadQuickStats();
            await loadIncidents();
            if (currentEventId && currentSourceIp) {
                await loadIncidentDetails(currentEventId, currentSourceIp);
            }
        } catch (e) {
            console.error(e);
            alert('Error: Unable to block IP.');
        }
    }

    // 6. Xử lý chuyển trạng thái
    async function changeIncidentStatus(eventId, newStatus, sourceIp) {
        if (!confirm(`Are you sure you want to change the status of Incident ID ${eventId} to '${newStatus.toUpperCase()}'?`)) return;

        try {
            const response = await fetch(`${API_BASE}/action/update-status/${eventId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus })
            });

            if (!response.ok) throw new Error("API failed");

            alert(`Success: Incident ID ${eventId} status changed to ${newStatus.toUpperCase()}.`);
            await loadIncidents();
            await loadQuickStats();
            await loadIncidentDetails(eventId, sourceIp);
        } catch (e) {
            console.error(e);
            alert('Error: Could not update status.');
        }
    }

    // 7. Gỡ chặn IP
    async function unblockIP(ipAddress) {
        if (!confirm(`Are you sure you want to UNBLOCK IP ${ipAddress}?`)) return;

        try {
            const response = await fetch(`${API_BASE}/action/unblock-ip`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip_address: ipAddress })
            });

            if (!response.ok) throw new Error("API failed");

            alert(`Success: IP ${ipAddress} has been unblocked.`);
            await loadQuickStats();
            await loadIncidents();
            if (currentEventId && currentSourceIp) {
                await loadIncidentDetails(currentEventId, currentSourceIp);
            }
        } catch (e) {
            console.error(e);
            alert('Error: Could not unblock IP.');
        }
    }

    // 8. Chức năng Gửi Email
    async function sendIncidentEmail(eventId) {
        if (!confirm(`Are you sure you want to send an email for Incident ID ${eventId}?`)) return;

        try {
            const response = await fetch(`${API_BASE}/action/send-email/${eventId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            if (!response.ok) {
                // Đọc lỗi từ API (có thể là lỗi 503 nếu cấu hình SMTP bị thiếu)
                const errorBody = await response.json();
                throw new Error(`API failed: ${errorBody.detail || response.statusText}`);
            }

            alert(`Success: Email for Incident ID ${eventId} has been sent.`);
        } catch (e) {
            console.error(e);
            alert(`Error: Unable to send email. Detail: ${e.message}`);
        }
    }

    // --- KHỞI CHẠY ---

    loadFilters();
    loadQuickStats();
    loadIncidents();

    // Nút "Refresh" trên widget List of attack events
    const refreshBtn = document.querySelector('.widget-controls span');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            loadQuickStats();
            loadIncidents();
        });
    }

    // Nút "Apply filter"
    const applyFilterBtn = document.querySelector('.btn-secondary[style*="width:100%"]');
    if (applyFilterBtn) {
        applyFilterBtn.addEventListener('click', () => {
            loadIncidents(); // Gọi hàm loadIncidents, hàm này tự động gọi getFilters()
        });
    }
});