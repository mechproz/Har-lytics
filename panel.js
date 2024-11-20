// ====================================================
// DevTools Panel Initialization
// ====================================================

console.log("DevTools panel loaded");

// ====================================================
// Global Variables and Initialization
// ====================================================

// Array to store network requests for HAR saving
const networkRequests = [];
// Array to store data for flow diagrams and other custom purposes
const flowData = [];
// Global array to store detected XSS issues
const xssIssuesGlobal = [];
// Variable to store the inspected page's hostname
let inspectedHostname = null;

// Fetch the hostname of the inspected window
chrome.devtools.inspectedWindow.eval("window.location.hostname", function(result, isException) {
    if (!isException) {
        inspectedHostname = result;
    } else {
        console.error('Failed to get inspected window hostname:', isException);
    }
});

// ====================================================
// XSS Detection Setup
// ====================================================

// Regular expressions to detect potential XSS patterns
const XSS_PATTERNS = [
    /<script\b[^>]*>(.*?)<\/script>/gi,
    /javascript:/gi,
    /\bon\w+=\s*(['"]).*?\1/gi,
    /\beval\s*\(/gi,
    /\bdocument\.cookie\b/gi
];

// Function to detect XSS patterns in a given text
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

// ====================================================
// Malicious IP Detection Setup
// ====================================================

// Path to the malicious IPs file
const maliciousIPsPath = chrome.runtime.getURL("data/malicious_ips.txt");

// Function to fetch and parse the malicious IPs from the file
async function fetchMaliciousIPs() {
    try {
        const response = await fetch(maliciousIPsPath);
        const text = await response.text();
        return text.split("\n").map(ip => ip.trim()).filter(ip => ip);
    } catch (error) {
        console.error("Error fetching malicious IPs:", error);
        return [];
    }
}

// Initialize malicious IP list and a Map to track detected IPs and their associated requests
let maliciousIPs = [];
const detectedIPs = new Map(); // Map to group requests by IP

// Fetch malicious IPs on script load
fetchMaliciousIPs().then(ips => {
    maliciousIPs = ips;
    console.log("Loaded Malicious IPs:", maliciousIPs);
});

// Function to display the malicious IPs, methods, and URLs in the HTML
function displayMaliciousIps() {
    const maliciousList = document.getElementById('malicious-list');
    const maliciousAlertDiv = document.getElementById('malicious-alert');
    if (!maliciousList || !maliciousAlertDiv) return;

    // Show or hide the alert based on detected IPs
    if (detectedIPs.size > 0) {
        maliciousAlertDiv.style.display = 'block';
        maliciousList.innerHTML = ""; // Clear previous entries

        detectedIPs.forEach((requests, ip) => {
            // Create a collapsible section for each malicious IP
            const ipContainer = document.createElement('div');
            ipContainer.className = 'ip-container';

            const ipHeader = document.createElement('div');
            ipHeader.className = 'ip-header';
            ipHeader.innerHTML = `
                <span class="ip-icon">⚠️</span>
                <strong>Malicious IP:</strong> ${ip}
                <span class="toggle-icon">▼</span>
            `;

            const ipDetails = document.createElement('div');
            ipDetails.className = 'ip-details';
            ipDetails.style.display = 'none'; // Initially collapsed

            // requests.forEach(({ method, url }) => {
            //     const requestItem = document.createElement('div');
            //     requestItem.className = 'request-item';
            //     requestItem.innerHTML = `
            //         <p><strong>Method:</strong> ${method}</p>
            //         <p><strong>URL:</strong> ${url}</p>
            //     `;
            //     ipDetails.appendChild(requestItem);
            // });

             // Create a table for the details
             const table = document.createElement('table');
             table.className = 'ip-details-table';
             table.innerHTML = `
                 <thead>
                     <tr>
                         <th>HTTP Method</th>
                         <th>Request URL</th>
                     </tr>
                 </thead>
                 <tbody>
                 ${requests.map(({ method, url }) => `
                     <tr>
                         <td>${method}</td>
                         <td>${url}</td>
                     </tr>
                 `).join('')}
                 </tbody>
             `;
 
             ipDetails.appendChild(table);
 
             // Toggle visibility of the details
             ipHeader.addEventListener('click', () => {
                 const isHidden = ipDetails.style.display === 'none';
                 ipDetails.style.display = isHidden ? 'block' : 'none';
                 ipHeader.querySelector('.toggle-icon').textContent = isHidden ? '▲' : '▼';
             });
 
             ipContainer.appendChild(ipHeader);
             ipContainer.appendChild(ipDetails);
             maliciousList.appendChild(ipContainer);
         });
    } else {
        maliciousAlertDiv.style.display = 'none';
    }
}

// Add listener for network requests
chrome.devtools.network.onRequestFinished.addListener((request) => {
    const remoteIPAddress = request.serverIPAddress || "N/A"; // Get the remote IP address
    const method = request.request.method; // Get the HTTP method
    const url = request.request.url; // Get the URL

    console.log("Request captured:", { url, remoteIPAddress, method });

    // Check if the IP is in the malicious list
    if (maliciousIPs.includes(remoteIPAddress)) {
        console.warn("Malicious IP detected:", remoteIPAddress);

        // Add the request details to the Map under the specific IP
        if (!detectedIPs.has(remoteIPAddress)) {
            detectedIPs.set(remoteIPAddress, []); // Initialize array for new IP
        }
        detectedIPs.get(remoteIPAddress).push({ method, url });

        // Update the display with the grouped malicious IPs and their requests
        displayMaliciousIps();
    }
});



// ====================================================
// HAR File Saving Functions
// ====================================================

// Initialize variables for automatic saving
let autoSaveIntervalId = null;

// Function to save HAR file
function saveHAR(isAutoSave = false) {
    // Check if there are any requests to save
    if (networkRequests.length === 0) {
        console.warn("No network requests to save.");
        return;
    }

    const harData = {
        log: {
            version: "1.2",
            creator: { name: "HAR Data Viewer", version: "1.0" },
            entries: networkRequests.map(request => ({
                startedDateTime: new Date(request.startedDateTime).toISOString(),
                time: request.time,
                request: {
                    method: request.request.method,
                    url: request.request.url,
                    headers: request.request.headers
                },
                response: {
                    status: request.response.status,
                    statusText: request.response.statusText,
                    headers: request.response.headers,
                    content: {
                        mimeType: request.response.content.mimeType,
                        size: request.response.content.size
                    }
                }
            }))
        }
    };

    // Adjust time to Singapore timezone (GMT+8)
    const now = new Date();
    now.setHours(now.getHours() + 8);

    // Format filename
    const saveType = isAutoSave ? "auto" : "manual";
    const timestamp = now.toISOString().replace("T", "_").replace(/[:.]/g, "-").slice(0, 19);
    const filename = `traffic_${saveType}_${timestamp}.har`;

    // Create and download the HAR file
    const blob = new Blob([JSON.stringify(harData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);

    // Clear network data after saving
    networkRequests.length = 0;
}

// Function to start automatic saving
function startAutoSave(interval) {
    stopAutoSave(); // Clear existing interval
    autoSaveIntervalId = setInterval(() => saveHAR(true), interval * 1000);
    console.log(`Auto-save started with interval ${interval} seconds.`);
}

// Function to stop automatic saving
function stopAutoSave() {
    if (autoSaveIntervalId) {
        clearInterval(autoSaveIntervalId);
        autoSaveIntervalId = null;
        console.log("Auto-save stopped.");
    }
}

// ====================================================
// DOM Event Listeners and Interaction Setup
// ====================================================

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

        // Special handling for Flow Diagrams tab
        if (viewId === 'flow-diagrams') {
            renderDiagram(); // Render the diagram when the tab is activated
        }
    }

    // Event listeners for each tab
    document.getElementById('overview-tab').addEventListener('click', () => showView('overview'));
    document.getElementById('network-requests-tab').addEventListener('click', () => showView('network-requests'));
    document.getElementById('xss-detection-tab').addEventListener('click', () => showView('xss-detection'));
    document.getElementById('threat-correlation-tab').addEventListener('click', () => showView('threat-correlation'));
    document.getElementById('flow-diagrams-tab').addEventListener('click', () => showView('flow-diagrams'));
    document.getElementById('report-config-tab').addEventListener('click', () => showView('report-config'));

    // ====================================================
    // HAR Saving Event Listeners
    // ====================================================

    // Event listener for manual save button
    const saveHarButton = document.getElementById("save-har");
    if (saveHarButton) {
        saveHarButton.addEventListener("click", () => {
            console.log("Save Traffic button clicked");
            saveHAR(false);
        });
    }

    // Event listener for auto-save toggle
    const toggleAutoSave = document.getElementById("toggle-auto-save");
    const intervalInput = document.getElementById("auto-save-interval");
    if (toggleAutoSave && intervalInput) {
        toggleAutoSave.addEventListener("change", () => {
            const interval = parseInt(intervalInput.value, 10) || 30;
            if (toggleAutoSave.checked) {
                startAutoSave(interval);
            } else {
                stopAutoSave();
            }
        });

        // Event listener for interval input change
        intervalInput.addEventListener("change", () => {
            const interval = parseInt(intervalInput.value, 10) || 30;
            if (toggleAutoSave.checked) {
                startAutoSave(interval);
                console.log(`Auto-save interval updated to ${interval} seconds.`);
            }
        });

        // Start auto-save if enabled on load
        if (toggleAutoSave.checked) {
            const interval = parseInt(intervalInput.value, 10) || 30;
            startAutoSave(interval);
        }
    }

    // ====================================================
    // Network Request Capture and Processing
    // ====================================================

    // Capture network requests
    chrome.devtools.network.onRequestFinished.addListener((request) => {
        // Store the full request object for HAR saving
        networkRequests.push(request);

        // Store the custom data for flow diagrams or other purposes
        flowData.push({
            source: inspectedHostname || "unknown",
            target: new URL(request.request.url).hostname,
            count: 1, // Initialize a count property to track requests
            destIP: request.serverIPAddress || "N/A" // Capture destination IP if available
        });

        // ====================================================
        // Network Requests Tab Display
        // ====================================================

        // Network Requests Tab - Display individual network requests
        if (document.getElementById("network-requests").classList.contains("active")) {
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
        }

        // ====================================================
        // XSS Detection Processing
        // ====================================================

        // XSS Detection Tab
        if (document.getElementById("xss-detection").classList.contains("active")) {
            request.getContent((content) => {
                const xssIssues = detectXSS(content || "") || detectXSS(request.request.postData?.text || "");

                if (xssIssues.length > 0) {
                    // Push the issue into the global array
                    xssIssuesGlobal.push({
                        url: request.request.url,
                        patterns: xssIssues
                    });
                    console.log("XSS Issue Detected:", xssIssuesGlobal);

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
                        <strong>Request Body:</strong><br>${request.request.postData?.text || "No body"}<br>
                        <strong>Response Body:</strong><br>${content || "No content"}
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
        }

        // ====================================================
        // Threat Detection
        // ====================================================

        // Malicious IP detection
        const remoteIPAddress = request.serverIPAddress || "N/A";
        const method = request.request.method;
        const url = request.request.url;

        if (maliciousIPs.includes(remoteIPAddress)) {
            console.warn("Malicious IP detected:", remoteIPAddress);

            // Add to detectedIPs Map
            if (!detectedIPs.has(remoteIPAddress)) {
                detectedIPs.set(remoteIPAddress, []);
            }
            detectedIPs.get(remoteIPAddress).push({ method, url });

            // Show the alert message
            const maliciousAlertDiv = document.getElementById('malicious-alert');
            if (maliciousAlertDiv) {
                maliciousAlertDiv.style.display = 'block';
            }

            // Update the display
            displayMaliciousIps();
        }
    });

    // ====================================================
    // Flow Diagram Preparation and Rendering
    // ====================================================

    // Function to process data into nodes and links for D3.js
    function prepareData() {
        const nodesMap = {};
        const linksMap = {};

        // Process unique nodes and links
        flowData.forEach(req => {
            const sourceHost = req.source;
            const targetHost = req.target;

            // Add source and target to nodes map if not already present
            if (!nodesMap[sourceHost]) {
                nodesMap[sourceHost] = { id: sourceHost };
            }
            if (!nodesMap[targetHost]) {
                nodesMap[targetHost] = { id: targetHost };
            }

            // Create a unique key for each link between source and target
            const linkKey = `${sourceHost}->${targetHost}`;

            // Track link counts by unique source-target pair
            if (linksMap[linkKey]) {
                linksMap[linkKey].count += 1;
            } else {
                linksMap[linkKey] = {
                    source: sourceHost, // Use IDs (hostnames) as references
                    target: targetHost,
                    count: 1,
                    destIP: req.destIP
                };
            }
        });

        // Convert maps to arrays
        const nodes = Object.values(nodesMap);
        const links = Object.values(linksMap);

        return { nodes, links };
    }

    // Function to render the flow diagram
    function renderDiagram() {
        const { nodes, links } = prepareData();

        // Clear previous diagram
        d3.select("#diagram-container").selectAll("*").remove();

        const width = document.getElementById("diagram-container").clientWidth;
        const height = document.getElementById("diagram-container").clientHeight;

        const svg = d3.select("#diagram-container")
            .append("svg")
            .attr("width", width)
            .attr("height", height);

        // Create simulation for force-directed graph
        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(links).id(d => d.id).distance(150))
            .force("charge", d3.forceManyBody().strength(-500))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(50)); // Prevent nodes from overlapping

        // Draw links (lines) with variable thickness based on request count
        const link = svg.append("g")
            .attr("class", "links")
            .selectAll("line")
            .data(links)
            .enter().append("line")
            .attr("stroke", "#999")
            .attr("stroke-opacity", 0.6)
            .attr("stroke-width", d => Math.sqrt(d.count));

        // Draw nodes (circles)
        const node = svg.append("g")
            .attr("class", "nodes")
            .selectAll("circle")
            .data(nodes)
            .enter().append("circle")
            .attr("r", 15)
            .attr("fill", "#4285f4")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));

        // Display labels on nodes
        const text = svg.append("g")
            .attr("class", "labels")
            .selectAll("text")
            .data(nodes)
            .enter().append("text")
            .attr("dy", -20)
            .attr("text-anchor", "middle")
            .text(d => d.id);

        // Update positions on each tick
        simulation.on("tick", () => {
            nodes.forEach(d => {
                d.x = Math.max(30, Math.min(width - 30, d.x));
                d.y = Math.max(30, Math.min(height - 30, d.y));
            });

            link.attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            node.attr("cx", d => d.x)
                .attr("cy", d => d.y);

            text.attr("x", d => d.x)
                .attr("y", d => d.y);
        });

        // Drag functions
        function dragstarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }

        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }

        function dragended(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }

        // Populate #data-display with textual data
        const display = document.getElementById("data-display");
        display.innerHTML = "<h3>Network Request Details</h3>";

        links.forEach(link => {
            const linkInfo = document.createElement("div");
            linkInfo.classList.add("link-info");
            linkInfo.innerHTML = `
                <p><strong>Origin:</strong> ${link.source.id}</p>
                <p><strong>Destination:</strong> ${link.target.id}</p>
                <p><strong>Destination IP:</strong> ${link.destIP}</p>
                <p><strong>Request Count:</strong> ${link.count}</p>
            `;
            display.appendChild(linkInfo);
        });
    }

    // Refresh button to re-render the diagram with new data
    document.getElementById("refresh-diagram").addEventListener("click", renderDiagram);

    // ====================================================
    // Report Generation Functionality
    // ====================================================

    // Report Generation Tab
    document.getElementById("report-config").innerHTML += `
        <p>Select which sections to include in the report.</p>
    `;

    function generateReport() {
        try {
            // Collect user preferences for report sections
            const includeNetworkRequests = document.getElementById('include-network-requests').checked; // Corrected ID for the Network Requests tab
            const includeXSS = document.getElementById('include-xss').checked;
            const includeThreats = document.getElementById('include-threats').checked;
            const includeFlow = document.getElementById('include-flow').checked;

            // Initialize the report content
            let reportContent = `
            <html>
            <head>
                <title>Network Analysis Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h1, h2, h3 { color: #333; }
                    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
                    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
                    th { background-color: #f5f5f5; }
                    ul { list-style-type: none; padding: 0; }
                    li { margin-bottom: 5px; }
                </style>
            </head>
            <body>
            <h1>Network Analysis Report</h1>
            <p>Generated on: ${new Date().toLocaleString()}</p>
            `;

            // Include Network Requests Summary
            if (includeNetworkRequests) {
                const totalRequests = networkRequests.length;

                // Aggregate data for HTTP methods and status codes
                const methodCounts = {};
                const statusCounts = {};
                networkRequests.forEach(request => {
                    const method = request.request.method;
                    const status = request.response.status;

                    methodCounts[method] = (methodCounts[method] || 0) + 1;
                    statusCounts[status] = (statusCounts[status] || 0) + 1;
                });

                reportContent += `<h2>Network Requests</h2>`;
                reportContent += `<p>Total Requests: ${totalRequests}</p>`;
                reportContent += `<h3>HTTP Methods</h3><ul>`;
                for (const [method, count] of Object.entries(methodCounts)) {
                    reportContent += `<li>${method}: ${count}</li>`;
                }
                reportContent += `</ul><h3>Status Codes</h3><ul>`;
                for (const [status, count] of Object.entries(statusCounts)) {
                    reportContent += `<li>${status}: ${count}</li>`;
                }
                reportContent += `</ul>`;
            }

            // Include XSS Detection
            if (includeXSS) {
                const xssIssues = networkRequests.flatMap(request => detectXSS(request.request.postData?.text || ""));

                if (xssIssuesGlobal.length > 0) {
                    reportContent += `<h2>XSS Detection</h2>`;
                    reportContent += `<table>
                        <tr>
                            <th>URL</th>
                            <th>Detected Patterns</th>
                        </tr>`;
                    xssIssuesGlobal.forEach(issue => {
                        reportContent += `<tr>
                            <td>${issue.url}</td>
                            <td>${issue.patterns.join(", ")}</td>
                        </tr>`;
                    });
                    reportContent += `</table>`;
                } else {
                    reportContent += `<p>No XSS issues detected.</p>`;
                }
            }

            // Include Malicious IPs
            if (includeThreats) {
                reportContent += `<h2>Malicious IPs</h2>`;
                if (detectedIPs.size > 0) {
                    reportContent += `<ul>`;
                    detectedIPs.forEach((requests, ip) => {
                        reportContent += `<li><strong>${ip}</strong><ul>`;
                        requests.forEach(req => {
                            reportContent += `<li>${req.method}: ${req.url}</li>`;
                        });
                        reportContent += `</ul></li>`;
                    });
                    reportContent += `</ul>`;
                } else {
                    reportContent += `<p>No malicious IPs detected.</p>`;
                }
            }

            // Include Flow Diagrams
            if (includeFlow) {
                reportContent += `<h2>Flow Diagram Data</h2>`;
                const { nodes, links } = prepareData();

                reportContent += `<h3>Nodes</h3><ul>`;
                nodes.forEach(node => {
                    reportContent += `<li>${node.id}</li>`;
                });
                reportContent += `</ul><h3>Links</h3><table>
                <tr><th>Source</th><th>Target</th><th>Request Count</th><th>Destination IP</th></tr>`;
                links.forEach(link => {
                    reportContent += `<tr>
                        <td>${link.source}</td>
                        <td>${link.target}</td>
                        <td>${link.count}</td>
                        <td>${link.destIP}</td>
                    </tr>`;
                });
                reportContent += `</table>`;
            }

            // Finalize and close the HTML content
            reportContent += `</body></html>`;

            // Create and download the report as an HTML file
            const blob = new Blob([reportContent], { type: "text/html" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "network_analysis_report.html";
            a.click();
            URL.revokeObjectURL(url);
        } catch (error) {
            console.error("Error generating report:", error);
            alert("An error occurred while generating the report. Check the console for details.");
        }
    }

    // Event listener for report generation button
    document.getElementById("export-full-report").addEventListener("click", generateReport);
});
