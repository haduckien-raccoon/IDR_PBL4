// app/static/js/rules.js

const API_URL = '/api/rules';
const STATS_URL = '/api/rules/stats';

// Lưu trạng thái filter hiện tại
let currentFilters = {
    severity: '',
    proto: '',
    groupName: ''
};

// Đang edit rule nào (uuid). null = đang thêm mới
let editingUuid = null;

/* ===== HELPER ===== */

function splitCommaString(str) {
    if (!str) return [];
    return str
        .split(',')
        .map(s => s.trim())
        .filter(s => s.length > 0);
}

function getInputValue(id) {
    const el = document.getElementById(id);
    return el ? el.value.trim() : '';
}

/* ===== LOAD RULES + STATS ===== */

async function loadAndRenderRules(newFilters = null) {
    console.log("[rules.js] Loading rules data...");

    if (newFilters) {
        currentFilters = {
            severity: newFilters.severity || '',
            proto: newFilters.proto || '',
            groupName: newFilters.groupName || ''
        };
    }

    try {
        const params = new URLSearchParams();
        if (currentFilters.severity) params.append('severity', currentFilters.severity);
        if (currentFilters.proto) params.append('proto', currentFilters.proto);
        if (currentFilters.groupName) params.append('group_name', currentFilters.groupName);

        const rulesUrl = `${API_URL}${params.toString() ? '?' + params.toString() : ''}`;
        console.log("[rules.js] Fetch URL:", rulesUrl);

        const [rulesResponse, statsResponse] = await Promise.all([
            fetch(rulesUrl),
            fetch(STATS_URL)
        ]);

        if (!rulesResponse.ok || !statsResponse.ok) {
            throw new Error(`HTTP error! status: ${rulesResponse.status} / ${statsResponse.status}`);
        }

        const rules = await rulesResponse.json();
        const stats = await statsResponse.json();

        updateQuickStatistics(stats);
        populateGroupNameFilters(stats.group_names || []);
        renderRulesTable(rules);

    } catch (error) {
        console.error("Error loading rules:", error);
        const tableBody = document.getElementById('rules-table').querySelector('tbody');
        tableBody.innerHTML = `<tr><td colspan="13" style="text-align:center; color:red;">Không thể tải dữ liệu Rules. Vui lòng kiểm tra API.</td></tr>`;

        document.getElementById('rule-total').textContent = 'Error';
        document.getElementById('rule-low-stat').textContent = 'Error';
        document.getElementById('rule-medium-stat').textContent = 'Error';
        document.getElementById('rule-high-stat').textContent = 'Error';
        document.getElementById('rule-critical').textContent = 'Error';
    }
}

/* ===== QUICK STATS + FILTER DROPDOWN ===== */

function updateQuickStatistics(stats) {
    document.getElementById('rule-total').textContent       = stats.total    ?? 0;
    document.getElementById('rule-low-stat').textContent    = stats.low      ?? 0;
    document.getElementById('rule-medium-stat').textContent = stats.medium   ?? 0;
    document.getElementById('rule-high-stat').textContent   = stats.high     ?? 0;
    document.getElementById('rule-critical').textContent    = stats.critical ?? 0;
}

function populateGroupNameFilters(groupNames) {
    const filterSelect  = document.getElementById('rule-groupname');
    const addRuleSelect = document.getElementById('rule-groupname-add');

    if (filterSelect) {
        filterSelect.innerHTML = '<option value="">All</option>';
        groupNames.forEach(name => {
            const opt = document.createElement('option');
            opt.value = name;
            opt.textContent = name;
            filterSelect.appendChild(opt);
        });
    }

    if (addRuleSelect) {
        addRuleSelect.innerHTML = '';
        groupNames.forEach(name => {
            const opt = document.createElement('option');
            opt.value = name;
            opt.textContent = name;
            addRuleSelect.appendChild(opt);
        });
        if (groupNames.length > 0) {
            addRuleSelect.value = groupNames[0];
        }
    }
}

/* ===== RENDER TABLE ===== */

function renderRulesTable(rules) {
    const tableBody = document.getElementById('rules-table').querySelector('tbody');
    tableBody.innerHTML = '';

    if (!rules || rules.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="13" style="text-align:center;">No rules found.</td></tr>`;
        return;
    }

    const formatField = (field) => Array.isArray(field) ? field.join(', ') : (field || 'N/A');

    rules.forEach(rule => {
        const row = tableBody.insertRow();

        const severity = (rule.severity || rule.severty || 'low').toLowerCase();
        let badgeClass = '';
        if (severity === 'critical') badgeClass = 'badge-critical';
        else if (severity === 'high') badgeClass = 'badge-high';
        else if (severity === 'medium') badgeClass = 'badge-medium';
        else if (severity === 'low') badgeClass = 'badge-low';
        else badgeClass = 'badge-unknown';

        const severityBadge = `<span class="badge ${badgeClass}">${severity}</span>`;

        row.insertCell().textContent = rule.uuid || 'N/A';
        row.insertCell().textContent = rule.group_id || 'N/A';

        let msg = rule.message || 'N/A';
        if (msg.length > 60) msg = msg.substring(0, 60) + "...";
        row.insertCell().textContent = msg;

        row.insertCell().innerHTML   = severityBadge;
        row.insertCell().textContent = rule.proto || 'Any';
        row.insertCell().textContent = rule.dst_port || 'Any';

        const regex = rule.pcre || 'N/A';
        row.insertCell().textContent = regex.length > 40 ? regex.substring(0, 40) + '...' : regex;

        row.insertCell().textContent = rule.fast_pattern || 'N/A';
        row.insertCell().textContent = formatField(rule.field);
        row.insertCell().textContent = formatField(rule.flow);

        let contentText = formatField(rule.content);
        if (contentText.length > 30) {
            contentText = contentText.substring(0, 30) + "...";
        }
        row.insertCell().textContent = contentText;

        row.insertCell().textContent = rule.action || 'alert';

        const actionsCell = row.insertCell();
        actionsCell.style.textAlign = 'right';
        actionsCell.innerHTML = `
            <button class="btn-xs btn-edit" data-uuid="${rule.uuid}">Edit</button>
            <button class="btn-xs btn-delete" data-uuid="${rule.uuid}">Delete</button>
        `;
    });
}

/* ===== FILTER BUTTON ===== */

function applyFilter() {
    const severity = document.getElementById('rule-severity-filter').value || '';
    const proto    = document.getElementById('rule-proto-filter').value || '';
    const groupName= document.getElementById('rule-groupname').value || '';

    const filters = { severity, proto, groupName };
    loadAndRenderRules(filters);
}

/* ===== FORM XỬ LÝ ADD / EDIT ===== */

function buildRulePayload() {
    const message = getInputValue('rule-message');
    const severity = getInputValue('rule-severity') || 'medium';
    const group_id = getInputValue('rule-groupname-add');
    const action   = getInputValue('rule-action') || 'alert';

    const proto    = getInputValue('rule-proto') || 'TCP';
    const dst_port_raw = getInputValue('rule-dport');
    const fast_pattern = getInputValue('rule-fast-pattern');

    const fieldStr  = getInputValue('rule-field');
    const flowStr   = getInputValue('rule-flow');
    const contentStr= getInputValue('rule-content');
    const pcre      = getInputValue('rule-pattern');

    const dst_port = dst_port_raw ? Number(dst_port_raw) : 'any';

    return {
        message,
        severity,
        group_id,
        action,
        proto,
        dst_port,
        fast_pattern,
        field: splitCommaString(fieldStr),
        flow: splitCommaString(flowStr),
        content: splitCommaString(contentStr),
        pcre
    };
}

function resetRuleForm() {
    editingUuid = null;

    // Reset các ô input về rỗng
    document.getElementById('rule-message').value = '';
    document.getElementById('rule-severity').value = 'medium';
    document.getElementById('rule-action').value = 'alert';
    document.getElementById('rule-proto').value = '';
    document.getElementById('rule-dport').value = '';
    document.getElementById('rule-fast-pattern').value = '';
    document.getElementById('rule-field').value = '';
    document.getElementById('rule-flow').value = '';
    document.getElementById('rule-content').value = '';
    document.getElementById('rule-pattern').value = '';

    // Lấy nút Add và nút Cancel
    const btn = document.getElementById('add-rule-btn');
    const cancelBtn = document.getElementById('cancel-edit-btn');

    if (btn) {
        // Đổi lại chữ và icon thành "Add Rule"
        btn.innerHTML = `<i class="fa-solid fa-plus"></i> Add Rule`;
        
        // Đổi màu về đỏ (btn-danger)
        btn.classList.remove('btn-edit'); // Bỏ màu xanh edit
        btn.classList.add('btn-danger');  // Thêm màu đỏ
        // Reset style inline nếu có
        btn.style.backgroundColor = ""; 
        btn.style.color = "";
    }
    const headerTitle = document.getElementById('form-header-title');
    if (headerTitle) {
        // Trả lại icon cộng và text Add Rule
        headerTitle.innerHTML = '<i class="fa-solid fa-plus-circle"></i> Add Rule';
    }

    // Ẩn nút Cancel đi
    if (cancelBtn) {
        cancelBtn.style.display = 'none';
    }
}

// [rules.js] Thay thế hàm fillFormForEdit cũ bằng hàm này
function fillFormForEdit(rule) {
    editingUuid = rule.uuid;

    // Đổ dữ liệu vào form (Code cũ của bạn)
    document.getElementById('rule-message').value = rule.message || '';
    document.getElementById('rule-severity').value = (rule.severity || rule.severty || 'medium').toLowerCase();
    document.getElementById('rule-groupname-add').value = rule.group_id || '';
    document.getElementById('rule-action').value = rule.action || 'alert';
    document.getElementById('rule-proto').value = rule.proto || '';
    document.getElementById('rule-dport').value = rule.dst_port || '';
    document.getElementById('rule-fast-pattern').value = rule.fast_pattern || '';
    document.getElementById('rule-field').value = Array.isArray(rule.field) ? rule.field.join(', ') : (rule.field || '');
    document.getElementById('rule-flow').value = Array.isArray(rule.flow) ? rule.flow.join(', ') : (rule.flow || '');
    document.getElementById('rule-content').value = Array.isArray(rule.content) ? rule.content.join(', ') : (rule.content || '');
    document.getElementById('rule-pattern').value = rule.pcre || '';

    // --- LOGIC MỚI: ĐỔI GIAO DIỆN NÚT ---
    const btn = document.getElementById('add-rule-btn');
    const cancelBtn = document.getElementById('cancel-edit-btn');

    if (btn) {
        // Đổi chữ thành "Save Changes"
        btn.innerHTML = `<i class="fa-solid fa-floppy-disk"></i> Save Changes`;

        // Đổi màu từ Đỏ sang Xanh (để người dùng biết đang sửa)
        btn.classList.remove('btn-danger');
        btn.classList.add('btn-edit'); 
        // Force màu xanh giống nút edit trong bảng (nếu class chưa đủ)
        btn.style.backgroundColor = "#26c6da"; 
        btn.style.color = "#081018";
    }
    const headerTitle = document.getElementById('form-header-title');
    if (headerTitle) {
        // Đổi icon thành cái bút và text thành Edit Rule
        headerTitle.innerHTML = '<i class="fa-solid fa-pen-to-square"></i> Edit Rule';
    }

    // Hiện nút Cancel lên
    if (cancelBtn) {
        cancelBtn.style.display = 'inline-flex';
    }

    // Tự động cuộn màn hình lên form để người dùng thấy
    const widget = document.querySelector('.rule-form-row').closest('.widget');
    if(widget) widget.scrollIntoView({ behavior: 'smooth' });
}

/* ===== CALL API ADD / UPDATE / DELETE ===== */

async function handleAddOrUpdateRule() {
    const payload = buildRulePayload();

    if (!payload.message || !payload.group_id) {
        alert("Message và Group Name không được để trống!");
        return;
    }

    try {
        let url = API_URL;
        let method = 'POST';

        if (editingUuid) {
            url = `${API_URL}/${encodeURIComponent(editingUuid)}`;
            method = 'PUT';
        }

        const res = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }

        await loadAndRenderRules();
        resetRuleForm();
    } catch (e) {
        console.error("Error saving rule:", e);
        alert("Lỗi khi lưu rule. Xem console để biết chi tiết.");
    }
}

async function handleDeleteRule(uuid) {
    if (!confirm(`Bạn có chắc muốn xóa rule với UUID:\n${uuid}?`)) return;

    try {
        const res = await fetch(`${API_URL}/${encodeURIComponent(uuid)}`, {
            method: 'DELETE'
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }

        await loadAndRenderRules();
        if (editingUuid === uuid) {
            resetRuleForm();
        }
    } catch (e) {
        console.error("Error deleting rule:", e);
        alert("Lỗi khi xóa rule. Xem console để biết chi tiết.");
    }
}

/* ===== INIT ===== */

document.addEventListener('DOMContentLoaded', () => {
    // Lần đầu load không filter
    loadAndRenderRules();

    // Nút "Apply Filter"
    const applyFilterButton = document.getElementById('apply-filter-btn');
    if (applyFilterButton) {
        applyFilterButton.addEventListener('click', applyFilter);
    }

    // Nút Add / Update Rule
    const addRuleBtn = document.getElementById('add-rule-btn');
    if (addRuleBtn) {
        addRuleBtn.addEventListener('click', handleAddOrUpdateRule);
    }

    // Delegation cho Edit / Delete trong bảng
    const table = document.getElementById('rules-table');
    if (table) {
        table.addEventListener('click', async (evt) => {
            const target = evt.target;

            if (target.classList.contains('btn-delete')) {
                const uuid = target.getAttribute('data-uuid');
                await handleDeleteRule(uuid);
            }

            if (target.classList.contains('btn-edit')) {
                const uuid = target.getAttribute('data-uuid');
                try {
                    const res = await fetch(API_URL);
                    const rules = await res.json();
                    const rule = rules.find(r => r.uuid === uuid);
                    if (rule) {
                        fillFormForEdit(rule);
                    } else {
                        alert("Không tìm thấy rule để sửa (có thể vừa bị xóa).");
                    }
                } catch (e) {
                    console.error("Error loading rule to edit:", e);
                    alert("Lỗi khi load rule để sửa.");
                }
            }
        });
    }
    const cancelBtn = document.getElementById('cancel-edit-btn');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', (e) => {
            e.preventDefault(); // Chặn reload trang
            resetRuleForm();    // Xóa form, đưa nút về trạng thái Add Rule
        });
    }

    // Client-side search
    const searchInput = document.getElementById('rule-search');
    if (searchInput) {
        searchInput.addEventListener('input', () => {
            const keyword = searchInput.value.toLowerCase();
            const tbody = document.getElementById('rules-table').querySelector('tbody');
            Array.from(tbody.rows).forEach(row => {
                const text = row.innerText.toLowerCase();
                row.style.display = text.includes(keyword) ? '' : 'none';
            });
        });
    }
});
