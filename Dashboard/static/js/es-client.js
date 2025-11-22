// static/js/es-client.js
// Shared ES client and UI render helpers
// Requires Chart.js to be loaded by the page

// Fetch logs from server
async function fetchLogs(attackKey) {
    const resp = await fetch(`/es-query?type=${encodeURIComponent(attackKey)}`);
    if (!resp.ok) {
        const err = await resp.text();
        throw new Error("ES query failed: " + err);
    }
    return resp.json();
}

// Format timestamps
function formatTimestamp(ts) {
    try {
        const d = new Date(ts);
        return d.toLocaleString();
    } catch (e) { return ts; }
}

// Build top cards
function buildCards(container, logs) {
    if (!container) return;
    const total = logs.length;
    const uniqueSrc = new Set(logs.map(l => l.src_mac).filter(Boolean)).size;
    const uniqueBssid = new Set(logs.map(l => l.bssid).filter(Boolean)).size;
    const lastSeen = logs.length ? formatTimestamp(logs[0].timestamp) : 'n/a';

    container.innerHTML = `
        <div style="display:flex;gap:12px;margin-bottom:16px;">
            <div class="card" style="flex:1;padding:12px;">
                <div style="font-size:20px;font-weight:700">${total}</div>
                <div style="font-size:12px;color:#888">Total attacks</div>
            </div>
            <div class="card" style="flex:1;padding:12px;">
                <div style="font-size:20px;font-weight:700">${uniqueSrc}</div>
                <div style="font-size:12px;color:#888">Unique source MACs</div>
            </div>
            <div class="card" style="flex:1;padding:12px;">
                <div style="font-size:20px;font-weight:700">${uniqueBssid}</div>
                <div style="font-size:12px;color:#888">Unique BSSIDs</div>
            </div>
            <div class="card" style="flex:1;padding:12px;">
                <div style="font-size:20px;font-weight:700">${lastSeen}</div>
                <div style="font-size:12px;color:#888">Last seen</div>
            </div>
        </div>
    `;
}

// Build charts
function buildCharts(ctxFreq, ctxSeverity, logs) {
    if (!logs || !logs.length) return;

    // Frequency by attack_type
    const freqMap = {};
    const severityMap = { critical:0, high:0, medium:0, low:0, unknown:0 };

    logs.forEach(l => {
        freqMap[l.attack_type] = (freqMap[l.attack_type] || 0) + 1;
        const sev = (l.severity || "unknown").toLowerCase();
        severityMap[sev] = (severityMap[sev] || 0) + 1;
    });

    const freqLabels = Object.keys(freqMap);
    const freqData = freqLabels.map(k => freqMap[k]);

    if (ctxFreq) {
        if (window.freqChart && window.freqChart.data && window.freqChart.data.datasets && window.freqChart.data.datasets[0]) {
            window.freqChart.data.labels = freqLabels;
            window.freqChart.data.datasets[0].data = freqData;
            window.freqChart.update();
        } else {
            window.freqChart = new Chart(ctxFreq, {
                type: 'bar',
                data: {
                    labels: freqLabels,
                    datasets: [{
                        label: 'Attacks',
                        data: freqData,
                        backgroundColor: 'rgba(59,130,246,0.7)'
                    }]
                },
                options: { responsive: true, plugins: { legend:{display:false} } }
            });
        }
    }

    const sevLabels = Object.keys(severityMap);
    const sevData = sevLabels.map(k => severityMap[k]);

    if (ctxSeverity) {
        if (window.sevChart && window.sevChart.data && window.sevChart.data.datasets && window.sevChart.data.datasets[0]) {
            window.sevChart.data.labels = sevLabels;
            window.sevChart.data.datasets[0].data = sevData;
            window.sevChart.update();
        } else {
            window.sevChart = new Chart(ctxSeverity, {
                type: 'pie',
                data: {
                    labels: sevLabels,
                    datasets: [{
                        label: 'Severity',
                        data: sevData,
                        backgroundColor: [
                            '#ef4444','#f97316','#facc15','#22c55e','#94a3b8'
                        ]
                    }]
                },
                options: { responsive: true }
            });
        }
    }
}

// Build table
function buildTable(tbody, logs) {
    if (!tbody) return;
    tbody.innerHTML = '';
    logs.forEach(l => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${formatTimestamp(l.timestamp)}</td>
            <td>${l.attack_type || ''}</td>
            <td>${l.severity || ''}</td>
            <td>${l.src_mac || ''}</td>
            <td>${l.bssid || ''}</td>
            <td>${l.channel || ''}</td>
            <td>${l.frame_count || ''}</td>
            <td>${(l.details||'').slice(0,120)}</td>
            <td><button class="json-toggle" data-json='${escapeHtml(JSON.stringify(l))}'>View JSON</button></td>
        `;
        tbody.appendChild(tr);
    });
    attachJSONButtons();
}

// Escape HTML
function escapeHtml(str) {
    return str.replace(/</g,'&lt;').replace(/>/g,'&gt;')
              .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// Unescape HTML
function unescapeHtml(s) {
    return s.replace(/&lt;/g,'<').replace(/&gt;/g,'>')
            .replace(/&quot;/g,'"').replace(/&#39;/g,"'");
}

// JSON toggle buttons
function attachJSONButtons() {
    document.querySelectorAll('.json-toggle').forEach(btn => {
        btn.onclick = () => {
            const payload = btn.getAttribute('data-json');
            let existing = btn.nextElementSibling;
            if (existing && existing.classList.contains('json-block')) {
                existing.remove();
                return;
            }
            const pre = document.createElement('pre');
            pre.className = 'json-block';
            pre.style = "background:#0b1220;color:#d6f8fa;padding:8px;border-radius:6px;margin-top:8px;";
            try {
                const obj = JSON.parse(unescapeHtml(payload));
                pre.textContent = JSON.stringify(obj,null,2);
            } catch(e) {
                pre.textContent = payload;
            }
            btn.parentNode.appendChild(pre);
        };
    });
}

// Page init
async function initPage(attackKey, title) {
    document.addEventListener('DOMContentLoaded', async () => {
        const titleEl = document.getElementById('page-title');
        if(titleEl) titleEl.textContent = title;

        const cardsEl = document.getElementById('cards');
        const tbody = document.getElementById('log-table-body');

        const freqCanvas = document.getElementById('freqChart');
        const severityCanvas = document.getElementById('severityChart');

        const ctxFreq = freqCanvas ? freqCanvas.getContext('2d') : null;
        const ctxSeverity = severityCanvas ? severityCanvas.getContext('2d') : null;

        try {
            const logs = await fetchLogs(attackKey);
            if (!Array.isArray(logs)) {
                const errEl = document.getElementById('error');
                if(errEl) errEl.textContent = JSON.stringify(logs);
                return;
            }
            buildCards(cardsEl, logs);
            buildCharts(ctxFreq, ctxSeverity, logs);
            buildTable(tbody, logs);
        } catch (err) {
            const errEl = document.getElementById('error');
            if(errEl) errEl.textContent = err.message;
        }
    });
}
