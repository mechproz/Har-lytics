console.log("DevTools panel loaded");

// XSS detection patterns
const XSS_PATTERNS = [
    /<script\b[^>]*>(.*?)<\/script>/gi,
    /javascript:/gi,
    /\bon\w+=\s*(['"]).*?\1/gi,
    /\beval\s*\(/gi,
    /\bdocument\.cookie\b/gi
];

// Function to detect XSS patterns in text
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

// Wait until the DOM is fully loaded
document.addEventListener("DOMContentLoaded", () => {
    // Function to toggle views
    function showView(viewId) {
        // Hide all views
        document.querySelectorAll('.view-section').forEach(section => {
            section.classList.remove('active');
        });

        // Remove active class from all buttons
        document.querySelectorAll('.tab-button').forEach(button => {
            button.classList.remove('active');
        });

        // Show the selected view
        document.getElementById(viewId).classList.add('active');
        document.getElementById(`${viewId}-tab`).classList.add('active');
    }

    // Event listeners for each tab
    document.getElementById('overview-tab').addEventListener('click', () => showView('overview'));
    document.getElementById('network-requests-tab').addEventListener('click', () => showView('network-requests'));
    document.getElementById('xss-detection-tab').addEventListener('click', () => showView('xss-detection'));
    document.getElementById('threat-correlation-tab').addEventListener('click', () => showView('threat-correlation'));
    document.getElementById('flow-diagrams-tab').addEventListener('click', () => showView('flow-diagrams'));
    document.getElementById('analysis-overview-tab').addEventListener('click', () => showView('analysis-overview'));
    document.getElementById('report-config-tab').addEventListener('click', () => showView('report-config'));

    // Placeholder content for each tab

    // Overview Tab - Display high-level statistics
    document.getElementById("network-entries-overview").innerHTML = `
        <p>Placeholder: Overview of network activity with basic stats.</p>
        <p>Example: Total requests, breakdown by HTTP method, and status codes.</p>
    `;

    // Network Requests Tab - Display individual network requests
    chrome.devtools.network.onRequestFinished.addListener((request) => {
        // Only show in the network-requests view
        if (!document.getElementById("network-requests").classList.contains("active")) return;
        console.log("Request captured:", request);
        const entryDiv = document.createElement("div");
        entryDiv.classList.add("network-entry");

        // Placeholder for request data display
        const requestHeaders = request.request.headers.map(header => `${header.name}: ${header.value}`).join("<br>");
        const responseHeaders = request.response.headers.map(header => `${header.name}: ${header.value}`).join("<br>");
        const postData = request.request.postData ? request.request.postData.text : "No body";
        const responseBody = request.response.content ? request.response.content.text : "No content";

        // Timing data
        const timings = request.timings;
        const dnsTime = timings ? timings.dns : "N/A";
        const connectTime = timings ? timings.connect : "N/A";
        const sendTime = timings ? timings.send : "N/A";
        const receiveTime = timings ? timings.receive : "N/A";

        // Header with summary and collapsible content
        const headerDiv = document.createElement("div");
        headerDiv.classList.add("network-header");
        headerDiv.innerHTML = `
            <strong>URL:</strong> ${request.request.url}<br>
            <strong>Method:</strong> ${request.request.method}<br>
            <strong>Status:</strong> ${request.response.status}<br>
            <strong>Time:</strong> ${request.time.toFixed(2)} ms
        `;

        // Collapsible content with detailed data
        const contentDiv = document.createElement("div");
        contentDiv.classList.add("network-content");
        contentDiv.style.display = "none";
        contentDiv.innerHTML = `
            <strong>DNS Time:</strong> ${dnsTime} ms<br>
            <strong>Connect Time:</strong> ${connectTime} ms<br>
            <strong>Send Time:</strong> ${sendTime} ms<br>
            <strong>Receive Time:</strong> ${receiveTime} ms<br>
            <strong>Request Headers:</strong><br>${requestHeaders}<br>
            <strong>Response Headers:</strong><br>${responseHeaders}<br>
            <strong>Request Body:</strong><br>${postData}<br>
            <strong>Response Body:</strong><br>${responseBody}<br>
        `;

        headerDiv.addEventListener("click", () => {
            contentDiv.style.display = contentDiv.style.display === "block" ? "none" : "block";
        });

        entryDiv.appendChild(headerDiv);
        entryDiv.appendChild(contentDiv);
        document.getElementById("network-entries").appendChild(entryDiv);
    });

    // XSS Detection Tab
    chrome.devtools.network.onRequestFinished.addListener((request) => {
        if (!document.getElementById("xss-detection").classList.contains("active")) return;

        request.getContent((content) => {
            const xssIssues = detectXSS(content || "") || detectXSS(request.request.postData?.text || "");

            if (xssIssues.length > 0) {
                const entryRow = document.createElement("tr");

                // URL Column
                const urlCol = document.createElement("td");
                urlCol.textContent = request.request.url;
                entryRow.appendChild(urlCol);

                // Detected Patterns Column
                const xssCol = document.createElement("td");
                xssCol.innerHTML = `Patterns: ${xssIssues.join(", ")}`;
                xssCol.classList.add("xss-issue");
                entryRow.appendChild(xssCol);

                // Details Column with Toggle
                const detailsCol = document.createElement("td");
                const detailsContent = document.createElement("div");
                detailsContent.classList.add("details-content");
                detailsContent.style.display = "none";

                detailsContent.innerHTML = `
                    <strong>Request URL:</strong> ${request.request.url}<br>
                    <strong>Request Method:</strong> ${request.request.method}<br>
                    <strong>Request Headers:</strong> ${request.request.headers.map(header => `${header.name}: ${header.value}`).join("<br>")}<br>
                    <strong>Response Headers:</strong> ${request.response.headers.map(header => `${header.name}: ${header.value}`).join("<br>")}<br>
                    <strong>Request Body:</strong> ${request.request.postData?.text || "No body"}<br>
                    <strong>Response Body:</strong> ${content || "No content"}
                `;

                const expandButton = document.createElement("button");
                expandButton.textContent = "Expand";
                expandButton.addEventListener("click", () => {
                    detailsContent.style.display = detailsContent.style.display === "none" ? "block" : "none";
                });

                detailsCol.appendChild(expandButton);
                detailsCol.appendChild(detailsContent);
                entryRow.appendChild(detailsCol);

                document.getElementById("xss-entries").appendChild(entryRow);
            }
        });
    });

    // Threat Correlation Tab - Placeholder for threat intelligence matches
    document.getElementById("network-entries-threat").innerHTML = `
        <p>Placeholder: List of requests matched with threat intelligence data.</p>
        <p>Implement: Cross-reference IPs and domains with a blacklist or threat feed.</p>
    `;

    // Flow Diagrams Tab - Placeholder for flow diagram visualization
    document.getElementById("network-entries-flow").innerHTML = `
        <p>Placeholder: Request flow diagram for visualizing the sequence of network requests.</p>
        <p>Implement: Sequence or flow visualization to map out the request-response flow.</p>
    `;

    // Analysis Overview Tab - Placeholder for aggregated analysis results
    document.getElementById("network-entries-analysis").innerHTML = `
        <p>Placeholder: Summary of key findings from all analyses (e.g., XSS, Threat Correlation).</p>
        <p>Implement: Aggregate important metrics from each tab.</p>
    `;

    // Report Config Tab - Placeholder for report generation options
    document.getElementById("report-config").innerHTML += `
        <p>Placeholder: Options to select which sections to include in the final report.</p>
        <p>Implement: Gather data from each selected section and format it for download.</p>
    `;

    // Placeholder function for report generation button
    document.getElementById("export-full-report").addEventListener("click", () => {
        console.log("Generate Full Report button clicked");
    });
});
