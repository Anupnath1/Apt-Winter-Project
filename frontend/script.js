document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const targetInput = document.getElementById('targetUrl');
    const resultsDiv = document.getElementById('results');
    const filterBox = document.getElementById('filterBox');
    const scanOptions = document.querySelectorAll('.scan-option');

    let currentScanType = 'passive';
    let currentReport = null;
    const API_BASE = "http://127.0.0.1:8000";

    scanOptions.forEach(opt => {
        opt.addEventListener('click', () => {
            scanOptions.forEach(b => b.classList.remove('active'));
            opt.classList.add('active');
            currentScanType = opt.dataset.type;
            
            if (currentReport) {
                displayResults(currentReport);
            }
        });
    });

    riskFilter.addEventListener('change', () => {
        filterResults(riskFilter.value);
    });

    scanBtn.addEventListener('click', async () => {
        const url = targetInput.value.trim();
        if (!url) return alert("Please enter a URL");

        resultsDiv.innerHTML = '<div class="card info">Scanning in progress... please wait.</div>';
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
            const sevClass = (f.severity || 'info').toLowerCase();
            return `
                <div class="card ${sevClass}">
                    <h3>${f.name}</h3>
                    <p><strong>Type:</strong> ${f.type}</p>
                    <p><strong>Severity:</strong> ${f.severity}</p>
                    <p><strong>Evidence:</strong> <code style="background:#333; padding:2px 4px; border-radius:3px;">${f.evidence || 'N/A'}</code></p>
                    <p><strong>Fix:</strong> ${f.recommendation}</p>
                </div>
            `;
        }).join('');

        resultsDiv.innerHTML = summaryHtml + cardsHtml;
    }
});