const scanBtn = document.getElementById("scanBtn");
const resultsDiv = document.getElementById("results");
const riskFilter = document.getElementById("riskFilter");
const filterBox = document.getElementById("filterBox");

let allFindings = [];

scanBtn.addEventListener("click", startScan);
riskFilter.addEventListener("change", applyFilter);

let selectedScanType = "passive";

const scanOptions = document.querySelectorAll(".scan-option");

scanOptions.forEach(btn => {
    btn.addEventListener("click", () => {
        scanOptions.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        selectedScanType = btn.dataset.type;
    });
});

async function startScan() {
    const url = document.getElementById("targetUrl").value.trim();

    if (!url) {
        alert("Please enter a target URL");
        return;
    }

    resultsDiv.innerHTML = "Scanning...";
    filterBox.classList.add("hidden");   // HIDE filter on new scan

    const endpoint =
        selectedScanType === "passive"
            ? "http://localhost:8000/scan/passive"
            : "http://localhost:8000/scan/active";

    try {
        const res = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target: url })
        });

        const data = await res.json();

        allFindings = data.report.findings || [];

        renderResults(allFindings);

        if (allFindings.length > 0) {
            filterBox.classList.remove("hidden"); 
        }

    } catch (err) {
        resultsDiv.innerHTML = "Scan failed";
        console.error(err);
    }
}


function renderResults(findings) {
    resultsDiv.innerHTML = "";

    if (findings.length === 0) {
        resultsDiv.innerHTML = "No vulnerabilities found";
        return;
    }

    findings.forEach(f => {
        const severity = (f.severity || f.risk || "INFO").toUpperCase();

        const card = document.createElement("div");
        card.className = `card ${severity.toLowerCase()}`;

        card.innerHTML = `
            <h3>${f.type || f.name || "Vulnerability"}</h3>
            <p><b>Severity:</b> ${severity}</p>
            <p><b>Description:</b> ${f.description || "N/A"}</p>
            <p><b>Recommendation:</b> ${f.recommendation || "N/A"}</p>
            <p><b>URL:</b> ${f.url || "N/A"}</p>
        `;

        resultsDiv.appendChild(card);
    });
}

function applyFilter() {
    const level = riskFilter.value;

    if (level === "ALL") {
        renderResults(allFindings);
        return;
    }

    const filtered = allFindings.filter(f => {
        const sev = (f.severity || f.risk || "INFO").toUpperCase();
        return sev === level;
    });

    renderResults(filtered);
}
