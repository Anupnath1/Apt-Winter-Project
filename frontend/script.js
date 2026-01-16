document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const targetInput = document.getElementById('targetUrl');
    const resultsDiv = document.getElementById('results');
    const filterBox = document.getElementById('filterBox');
    const riskFilter = document.getElementById('riskFilter');
    const scanOptions = document.querySelectorAll('.scan-option');

    // Auth fields
    const authFields = document.getElementById('authFields');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const tenantInput = document.getElementById('tenant');

    const modal = document.getElementById("activeScanModal");
    const confirmBtn = document.getElementById("confirmActiveScan");
    const cancelBtn = document.getElementById("cancelActiveScan");
    
    let currentScanType = 'passive';
    let currentReport = null;
    const API_BASE = "http://127.0.0.1:8000";

    let pendingOption = null;

    // ensure modal is hidden on load
    modal.classList.add("hidden");

    scanOptions.forEach(opt => {
        opt.addEventListener("click", () => {
            // If clicking active, show warning
            if (opt.dataset.type === "active" && !opt.classList.contains("active")) {
                pendingOption = opt;
                modal.classList.remove("hidden");
                return;
            }
            
            // If switching back to passive
            if (opt.dataset.type === "passive") {
                scanOptions.forEach(o => o.classList.remove("active"));
                opt.classList.add("active");
                currentScanType = "passive";
                authFields.classList.add("hidden");
            }
        });
    });

    confirmBtn.addEventListener("click", () => {
        if (!pendingOption) return;

        modal.classList.add("hidden");

        scanOptions.forEach(o => o.classList.remove("active"));
        pendingOption.classList.add("active");
        currentScanType = "active";
        
        // Show auth fields for active scan
        authFields.classList.remove("hidden");

        pendingOption = null;
    });

    cancelBtn.addEventListener("click", () => {
        modal.classList.add("hidden");
        pendingOption = null;
    });

    // --- FILTER LOGIC ---
    riskFilter.addEventListener('change', () => {
        const selected = riskFilter.value.toUpperCase(); 
        const cards = document.querySelectorAll('.result-card');

        cards.forEach(card => {
            const severity = card.getAttribute('data-severity');
            
            if (selected === "ALL" || severity === selected || severity.includes(selected) || selected.includes(severity)) {
                card.style.display = "block";
            } else {
                card.style.display = "none";
            }
        });
    });


    scanBtn.addEventListener('click', async () => {
        const url = targetInput.value.trim();
        if (!url) return alert("Please enter a URL");

        resultsDiv.innerHTML = '<div class="card info">Scanning in progress... please wait.</div>';
        filterBox.classList.add('hidden');
        scanBtn.disabled = true;

        const payload = { 
            target: url 
        };

        // If active scan, attach credentials
        if (currentScanType === 'active') {
            payload.username = usernameInput.value.trim() || null;
            payload.password = passwordInput.value.trim() || null;
            payload.tenant = tenantInput.value.trim() || null;
        }

        try {
            const response = await fetch(`${API_BASE}/scan/${currentScanType}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (!response.ok) throw new Error("Scan failed to start");

            const data = await response.json();
            currentReport = data.report;
            displayResults(currentReport);

        } catch (err) {
            resultsDiv.innerHTML = `<div class="card high">Error: ${err.message}</div>`;
        } finally {
            scanBtn.disabled = false;
        }
    });

    function displayResults(report) {
        filterBox.classList.remove('hidden');
        riskFilter.value = 'ALL';
        
        let summaryHtml = `
            <div class="card info" style="border-left-color: #2563eb;">
                <h2>Scan Complete: ${report.meta.target}</h2>
                <p>Risk Level: <strong>${report.meta.risk_level}</strong></p>
                <div style="display:flex; gap:15px; margin-top:10px;">
                    <span style="color:#dc2626">High: ${report.summary.HIGH}</span>
                    <span style="color:#f59e0b">Medium: ${report.summary.MEDIUM}</span>
                    <span style="color:#22c55e">Low: ${report.summary.LOW}</span>
                </div>
            </div>
        `;

        const findings = currentScanType === 'passive' 
            ? report.scans.passive.findings 
            : report.scans.active.findings;

        if (!findings || findings.length === 0) {
            resultsDiv.innerHTML = summaryHtml + '<div class="card">No vulnerabilities found in this category.</div>';
            return;
        }

        let cardsHtml = findings.map(f => {
            const rawSev = (f.severity || 'INFO').toUpperCase();
            const sevClass = rawSev.toLowerCase();
            
            // --- NEW: Handle URL List vs Single URL ---
            let urlSection = '';
            
            // Check if 'urls' exists and is a non-empty array (Active Scan)
            if (f.urls && Array.isArray(f.urls) && f.urls.length > 0) {
                const urlListItems = f.urls.map(u => 
                    `<li><a href="${u}" target="_blank">${u}</a></li>`
                ).join('');
                
                urlSection = `
                    <div style="margin: 10px 0;">
                        <strong>Affected URLs:</strong>
                        <ul>${urlListItems}</ul>
                    </div>
                `;
            } else {
                // Fallback for Passive Scan or Single URL
                const singleUrl = f.url || 'N/A';
                urlSection = `<p><strong>URL:</strong> <a href="${singleUrl}" target="_blank" style="color: #60a5fa;">${singleUrl}</a></p>`;
            }

            return `
                <div class="card result-card ${sevClass}" data-severity="${rawSev}">
                    <h3>${f.name}</h3>
                    <p><strong>Type:</strong> ${f.type}</p>
                    <p><strong>Severity:</strong> ${rawSev}</p>
                    
                    <p><strong>Impact:</strong> ${f.impact || 'No description provided'}</p>
                    
                    ${urlSection}

                    <p><strong>Evidence:</strong> <code style="background:#333; padding:2px 4px; border-radius:3px;">${f.evidence || 'N/A'}</code></p>
                    <p><strong>Fix:</strong> ${f.recommendation}</p>
                    <p style="font-size: 0.8em; color: #888; margin-top: 10px;">Source: ${f.source || 'Unknown'}</p>
                </div>
            `;
        }).join('');

        resultsDiv.innerHTML = summaryHtml + cardsHtml;
    }
});