document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const targetInput = document.getElementById('targetUrl');
    const resultsDiv = document.getElementById('results');
    const filterBox = document.getElementById('filterBox');
    const riskFilter = document.getElementById('riskFilter');
    const scanOptions = document.querySelectorAll('.scan-option');

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

            if (opt.dataset.type === "active" && !opt.classList.contains("active")) {
                pendingOption = opt;
                modal.classList.remove("hidden");
                return;
            }
            scanOptions.forEach(o => o.classList.remove("active"));
            opt.classList.add("active");
            currentScanType = opt.dataset.type;
        });
    });

    confirmBtn.addEventListener("click", () => {
        if (!pendingOption) return;

        modal.classList.add("hidden");

        scanOptions.forEach(o => o.classList.remove("active"));
        pendingOption.classList.add("active");
        currentScanType = "active";
        
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
            const severity = card.getAttribute('data-severity'); // This is already Uppercase
            
            // Check for exact match OR partial match (e.g., INFO matching INFORMATIONAL)
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

        try {
            const response = await fetch(`${API_BASE}/scan/${currentScanType}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: url })
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

        if (findings.length === 0) {
            resultsDiv.innerHTML = summaryHtml + '<div class="card">No vulnerabilities found in this category.</div>';
            return;
        }

        let cardsHtml = findings.map(f => {
            const rawSev = (f.severity || 'INFO').toUpperCase();
            const sevClass = rawSev.toLowerCase();
            
            return `
                <div class="card result-card ${sevClass}" data-severity="${rawSev}">
                    <h3>${f.name}</h3>
                    <p><strong>Type:</strong> ${f.type}</p>
                    <p><strong>Severity:</strong> ${rawSev}</p>
                    
                    <p><strong>Impact:</strong> ${f.impact || 'No description provided'}</p>
                    <p><strong>URL:</strong> <a href="${f.url}" target="_blank" style="color: #60a5fa;">${f.url || 'N/A'}</a></p>

                    <p><strong>Evidence:</strong> <code style="background:#333; padding:2px 4px; border-radius:3px;">${f.evidence || 'N/A'}</code></p>
                    <p><strong>Fix:</strong> ${f.recommendation}</p>
                    <p style="font-size: 0.8em; color: #888; margin-top: 10px;">Source: ${f.source || 'Unknown'}</p>
                </div>
            `;
        }).join('');

        resultsDiv.innerHTML = summaryHtml + cardsHtml;
    }
});