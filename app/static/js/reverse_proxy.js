// static/js/reverse_proxy.js

document.addEventListener("DOMContentLoaded", () => {
    const API_BASE = (window.__CONFIG__ && window.__CONFIG__.API_BASE) || "";
    const $ = (id) => document.getElementById(id);

    // --- 1. Load Config ---
    async function loadConfig() {
        const viewer = $("config-viewer");
        const input = $("target-input");
        
        try {
            // Hiệu ứng loading
            viewer.style.opacity = "0.5";
            
            const res = await fetch(`${API_BASE}/api/reverse-proxy/config`);
            if (!res.ok) throw new Error("Failed to load config");
            
            const data = await res.json();
            
            // Điền dữ liệu
            viewer.textContent = data.content;
            if (data.target) {
                input.value = data.target;
            }

        } catch (e) {
            viewer.textContent = "Error loading config: " + e.message;
            viewer.style.color = "#e94560";
        } finally {
            viewer.style.opacity = "1";
        }
    }

    // --- 2. Handle Update ---
    async function handleUpdate(e) {
        e.preventDefault(); // Chặn reload form
        
        const btn = $("btn-update");
        const statusBox = $("status-box");
        const targetVal = $("target-input").value;
        
        // Reset trạng thái UI
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Processing...`;
        statusBox.style.display = "none";
        statusBox.className = "status-msg";

        try {
            // Gửi Form Data
            const formData = new FormData();
            formData.append("target", targetVal);

            const res = await fetch(`${API_BASE}/api/reverse-proxy/update`, {
                method: "POST",
                body: formData
            });
            
            const data = await res.json();

            // Hiển thị kết quả
            statusBox.style.display = "block";
            statusBox.textContent = data.message;

            if (data.status === "success") {
                statusBox.classList.add("success");
                // Cập nhật lại khung view config
                if (data.new_content) {
                    $("config-viewer").textContent = data.new_content;
                }
            } else {
                statusBox.classList.add("error");
            }

        } catch (e) {
            statusBox.style.display = "block";
            statusBox.classList.add("error");
            statusBox.textContent = "Network Error: " + e.message;
        } finally {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-rotate"></i> Update & Reload Nginx`;
        }
    }

    // --- 3. Events ---
    $("proxy-form").addEventListener("submit", handleUpdate);
    $("btn-refresh").addEventListener("click", loadConfig);

    // Init
    loadConfig();
});