console.log("DevTools panel loaded");

// Regex patterns for XSS detection
const XSS_PATTERNS = [
    /<script\b[^>]*>(.*?)<\/script>/gi,
    /javascript:/gi,
    /\bon\w+=\s*(['"]).*?\1/gi,
    /\beval\s*\(/gi,
    /\bdocument\.cookie\b/gi
];

// Function to detect XSS
function detectXSS(text) {
    let issues = [];
    const decodedText = decodeURIComponent(text);

    [text, decodedText].forEach(body => {
        XSS_PATTERNS.forEach(pattern => {
            if (pattern.test(body)) {
                issues.push(pattern.toString());
            }
        });
    });
    return issues;
}

// Filter logic
function applyFilters() {
    const requestTypeFilter = document.getElementById("requestTypeFilter").value;
    const xssFilter = document.getElementById("xssFilter").value;

    document.querySelectorAll(".network-entry").forEach(entry => {
        const requestType = entry.getAttribute("data-request-type");
        const xssStatus = entry.getAttribute("data-xss-status");

        let show = true;
        if (requestTypeFilter !== "all" && requestTypeFilter !== requestType) {
            show = false;
        }
        if (xssFilter === "xss" && xssStatus !== "xss-detected") {
            show = false;
        } else if (xssFilter === "no-xss" && xssStatus !== "no-xss") {
            show = false;
        }

        entry.style.display = show ? "table-row" : "none";
    });
}

// Add event listeners for dropdown filters
document.getElementById("requestTypeFilter").addEventListener("change", applyFilters);
document.getElementById("xssFilter").addEventListener("change", applyFilters);

// Event listener for all network requests
chrome.devtools.network.onRequestFinished.addListener((request) => {
    const entryRow = document.createElement("tr");
    entryRow.classList.add("network-entry");

    // Set data attributes for filtering
    entryRow.setAttribute("data-request-type", request.request.method);
    entryRow.setAttribute("data-xss-status", "no-xss");

    // First column: Request type
    const typeCol = document.createElement("td");
    typeCol.textContent = request.request.method;
    typeCol.classList.add(request.request.method.toLowerCase() + "-color");
    entryRow.appendChild(typeCol);

    // Second column: Limited Details (expandable)
    const detailsCol = document.createElement("td");
    const limitedDetails = document.createElement("span");
    limitedDetails.textContent = `URL: ${request.request.url.substring(0, 50)}...`;
    detailsCol.appendChild(limitedDetails);

    const expandButton = document.createElement("button");
    expandButton.textContent = "Expand";
    detailsCol.appendChild(expandButton);

    const detailsContent = document.createElement("div");
    detailsContent.classList.add("details-content");
    detailsContent.style.display = "none";

    expandButton.addEventListener("click", () => {
        detailsContent.style.display = detailsContent.style.display === "none" ? "block" : "none";
    });

    const requestHeaders = request.request.headers.map(header => `${header.name}: ${header.value}`).join("<br>");
    const responseHeaders = request.response.headers.map(header => `${header.name}: ${header.value}`).join("<br>");
    const postData = request.request.postData ? request.request.postData.text : "No body";

    request.getContent((content) => {
        detailsContent.innerHTML = `
            <strong>URL:</strong> ${request.request.url}<br>
            <strong>Method:</strong> ${request.request.method}<br>
            <strong>Status:</strong> ${request.response.status}<br>
            <strong>Request Headers:</strong><br>${requestHeaders}<br>
            <strong>Response Headers:</strong><br>${responseHeaders}<br>
            <strong>Request Body:</strong><br>${postData}<br>
            <strong>Response Body:</strong><br>${content || "No content"}
        `;
    });

    detailsCol.appendChild(detailsContent);
    entryRow.appendChild(detailsCol);

    // Third column: XSS Detection
    const xssCol = document.createElement("td");
    request.getContent((content) => {
        const bodyToCheck = decodeURIComponent(content || "");
        const postBodyToCheck = decodeURIComponent(postData || "");

        // Check both request body and response body for XSS
        const xssIssues = detectXSS(postBodyToCheck) || detectXSS(bodyToCheck);

        if (xssIssues.length > 0) {
            xssCol.innerHTML = `Detected: ${xssIssues.join(", ")}`;
            xssCol.classList.add("xss-issue");
            entryRow.setAttribute("data-xss-status", "xss-detected");
        } else {
            xssCol.textContent = "No XSS detected";
        }
    });

    entryRow.appendChild(xssCol);

    // Add new entry at the top
    const networkEntries = document.getElementById("network-entries");
    networkEntries.insertBefore(entryRow, networkEntries.firstChild);

    // Apply filters after adding new entry
    applyFilters();
});
