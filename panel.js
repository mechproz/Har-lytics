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
    /<style[^>]*>.*?[{}]/gi,
    /<img[^>]+src=['"]?javascript:.*?['"]/gi,
    /\bon[a-z]+\s*=\s*['"]?[^'"]*(alert|eval|prompt|confirm|document\.cookie|window\.open)['"]/gi,
    /\bstyle\s*=\s*['"].*expression.*['"]/gi,
    /\bsrc\s*=\s*['"]javascript:.*['"]/gi,
    /\bon[a-z]+\s*=\s*['"]?.*?(alert|eval|prompt|document\.cookie|window\.open).*?['"]/gi,
];

// Function to detect XSS patterns in a given text
function detectXSS(text) {

    if (!text || typeof text !== "string") {
        return []; // Return an empty array if the input is invalid
    }

    let issues = [];
    let decodedText = "";

    try {
        // Attempt to decode the text; fallback to original text if decoding fails
        decodedText = decodeURIComponent(text);
    } catch (error) {
        console.warn("decodeURIComponent failed:", error);
        decodedText = text; // Fallback to the raw text
    }

    [text, decodedText].forEach(body => {
        XSS_PATTERNS.forEach(pattern => {
            if (pattern.test(body)) {
                issues.push(pattern.toString());
            }
        });
    });
    return issues;
}

// Function to escape HTML for safe rendering
function escapeHTML(html) {
    const div = document.createElement("div");
    div.innerText = html;
    return div.innerHTML;
}

// Function to truncate long text
function truncateText(text, maxLength = 500) {
    return text.length > maxLength ? `${text.slice(0, maxLength)}...` : text;
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
// Filtering Functions
// ====================================================

function isUnwantedType(request) {
    const unwantedExtensions = /\.(svg|ico|png|jpg|jpeg|woff|woff2|ttf|css|js)$/i;
    const contentTypeHeader = request.response.headers.find(
        header => header.name.toLowerCase() === "content-type"
    );
    const contentType = contentTypeHeader ? contentTypeHeader.value : null;

    return unwantedExtensions.test(request.request.url) ||
           (contentType && /image|font|text\/css|javascript/.test(contentType));
}

// Function to fetch and parse multiple blocklists
async function fetchBlocklists(urls) {
    const blocklist = new Set();
    for (const url of urls) {
        try {
            const response = await fetch(url);
            const text = await response.text();
            // Process each line of the blocklist, ignoring comments
            text.split("\n").forEach(domain => {
                const trimmedDomain = domain.trim();
                if (trimmedDomain && !trimmedDomain.startsWith("#")) {
                    blocklist.add(trimmedDomain); // Add the domain to the set
                }
            });
            console.log(`Loaded ${url}: ${blocklist.size} entries`);
        } catch (error) {
            console.error("Error fetching blocklist from:", url, error);
        }
    }
    return blocklist;
}

// URLs for blocklist sources
const blocklistSources = [
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=plain&showintro=0",
    "https://easylist.to/easylist/easylist.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt"
];

// Set to store merged blocklist
let blockedDomainsSet = new Set();

// Initialize blocklist on load
fetchBlocklists(blocklistSources).then(blocklist => {
    blockedDomainsSet = blocklist;
    console.log("Merged Blocklist Loaded:", blockedDomainsSet.size, "entries");
});

// Function to check if a request is in the blocklist
function isBlockedDomain(request) {
    try {
        const hostname = new URL(request.request.url).hostname;
        return blockedDomainsSet.has(hostname);
    } catch (error) {
        console.error("Error parsing URL:", request.request.url, error);
        return false;
    }
}

function matchesUnwantedPattern(request) {
    const unwantedPatterns = [
        "/fonts/",
        "/logo/",
        "/icon/",
        "/assets/",
        "/async/",
        "/gen_204",
        "/client_204"
    ];

    return unwantedPatterns.some(pattern => request.request.url.includes(pattern));
}

// Combine all filters into one function
function isUnwantedRequest(request) {
    return (
        (isBlockedDomain(request) ||
        isUnwantedType(request) ||
        matchesUnwantedPattern(request))
    );
}

// ====================================================
// Analysis Functions
// ====================================================

// Define timing thresholds for anomaly detection (in milliseconds)
const TIMING_THRESHOLDS = {
    dns: 2000,         // DNS resolution time
    connect: 5000,     // Connection time
    totalTime: 15000   // Total request time
};

// Function to detect timing anomalies in network requests
function detectTimingAnomalies(request) {
    const { timings } = request;
    const totalTime = request.time; // Use the precomputed total time

    console.log("Total Request Time:", totalTime);

    // Check against thresholds
    const isSlowTotal = totalTime > TIMING_THRESHOLDS.totalTime;

    if (isSlowTotal) {
        console.warn("Timing anomaly detected:", {
            url: request.request.url,
            totalTime
        });

        // Display timing anomaly alert
        displayMitmAlert(
            "Timing Anomaly",
            `Request to ${request.request.url} took too long. Total Time: ${totalTime}ms`
        );
    } else {
        console.log("Request time within acceptable limits:", {
            url: request.request.url,
            totalTime
        });
    }
}

// Function to display MITM alerts
function displayMitmAlert(issueType, details) {
    const mitmList = document.getElementById("mitm-list");
    const alertDiv = document.createElement("div");
    alertDiv.className = "mitm-alert";

    alertDiv.innerHTML = `
        <strong>${issueType}:</strong> ${details}
    `;
    mitmList.appendChild(alertDiv);
}

// ====================================================
// DOM Event Listeners and Interaction Setup
// ====================================================

// Wait until the DOM is fully loaded
document.addEventListener("DOMContentLoaded", () => {

    // ====================================================
    // Search Bar
    // ====================================================

    // Get references to search bar, filter type dropdown, and results container
    const searchBar = document.getElementById("search-bar");
    const filterType = document.getElementById("filter-type");
    const filteredResultsContainer = document.getElementById("filtered-results");

    // Function to filter requests based on search criteria
    function filterRequests() {
        const searchQuery = searchBar.value.trim().toLowerCase(); // Trim and normalize query
        const filter = filterType.value;

        // If the search query is empty, clear the filtered results and return
        if (searchQuery === "") {
            clearFilteredResults(); // Remove any search-related data
            return;
        }

        // Filter networkRequests based on the query and selected filter type
        const filteredRequests = networkRequests.filter(request => {
            const url = request.request.url.toLowerCase();
            const method = request.request.method.toLowerCase();
            const status = String(request.response.status).toLowerCase();
            const timestamp = new Date(request.startedDateTime).toISOString().toLowerCase();

            switch (filter) {
                case "url":
                    return url.includes(searchQuery);
                case "method":
                    return method.includes(searchQuery);
                case "status":
                    return status.includes(searchQuery);
                case "timestamp":
                    return timestamp.includes(searchQuery);
                default: // "all"
                    return (
                        url.includes(searchQuery) ||
                        method.includes(searchQuery) ||
                        status.includes(searchQuery) ||
                        timestamp.includes(searchQuery)
                    );
            }
        });

        renderFilteredResults(filteredRequests); // Render filtered results
    }

    // Function to render filtered results with expand/collapse feature
    function renderFilteredResults(filteredRequests) {
        filteredResultsContainer.innerHTML = ""; // Clear previous results

        // Display a message if no results match the search criteria
        if (filteredRequests.length === 0) {
            filteredResultsContainer.innerHTML = "<h1>No matching results found.</h1>";
            return;
        }

        // Create and append entries for each filtered request
        filteredRequests.forEach(request => {
            const timestamp = new Date(request.startedDateTime).toISOString();

            // Create container for the request entry
            const entryDiv = document.createElement("div");
            entryDiv.classList.add("network-entry");

            // Create header with summary
            const headerDiv = document.createElement("div");
            headerDiv.classList.add("network-header");
            headerDiv.innerHTML = `
                <strong>Timestamp:</strong> ${timestamp}<br>
                <strong>URL:</strong> ${request.request.url}<br>
                <strong>Method:</strong> ${request.request.method}<br>
                <strong>Status:</strong> ${request.response.status}<br>
                <strong>Time:</strong> ${request.time.toFixed(2)} ms
            `;

            // Create detailed content (initially hidden)
            const contentDiv = document.createElement("div");
            contentDiv.classList.add("network-content");
            contentDiv.style.display = "none";
            contentDiv.innerHTML = `
                <strong>Request Headers:</strong><br>
                ${request.request.headers.map(header => `${header.name}: ${header.value}`).join("<br>")}<br>
                <strong>Response Headers:</strong><br>
                ${request.response.headers.map(header => `${header.name}: ${header.value}`).join("<br>")}<br>
                <strong>Request Body:</strong><br>${request.request.postData?.text || "No body"}<br>
                <strong>Response Body:</strong><br>${request.response.content?.text || "No content"}<br>
            `;

            // Add click event for expanding/collapsing details
            headerDiv.addEventListener("click", () => {
                contentDiv.style.display = contentDiv.style.display === "none" ? "block" : "none";
            });

            // Append header and content to the entry
            entryDiv.appendChild(headerDiv);
            entryDiv.appendChild(contentDiv);

            // Append entry to the filtered results container
            filteredResultsContainer.appendChild(entryDiv);
        });

        // Add a separator to indicate the end of filtered results
        addSeparator();
    }

    // Function to clear filtered results
    function clearFilteredResults() {
        filteredResultsContainer.innerHTML = ""; // Clear all search-related content
    }

    // Function to add a separator for end of filtered results
    function addSeparator() {
        const separatorDiv = document.createElement("div");
        separatorDiv.classList.add("separator");
        separatorDiv.style.borderTop = "2px dashed #ccc";
        separatorDiv.style.borderBottom = "2px dashed #ccc";
        separatorDiv.style.margin = "20px 0";
        separatorDiv.style.textAlign = "center";
        separatorDiv.innerHTML = "<h1>End of filtered results</h1>";

        filteredResultsContainer.appendChild(separatorDiv);
    }

    // Add event listeners to the search bar and filter dropdown
    searchBar.addEventListener("input", filterRequests);
    filterType.addEventListener("change", filterRequests);

    // Trigger filtering initially only if search query exists
    if (searchBar.value.trim() !== "") {
        filterRequests();
    } else {
        clearFilteredResults(); // Ensure no unnecessary data is shown on initial load
    }

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
    document.getElementById('analysis-tab').addEventListener('click', () => showView('analysis-section'));

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

    // Event listener for auto-save toggle and interval input
    const toggleAutoSave = document.getElementById("toggle-auto-save");
    const intervalInput = document.getElementById("auto-save-interval");
    const saveAutoSaveButton = document.getElementById("save-auto-save-settings"); // Save button

    // Ensure the checkbox is unchecked by default
    toggleAutoSave.checked = false;

    // Listener for "Save Auto Save Settings" button
    if (saveAutoSaveButton) {
        saveAutoSaveButton.addEventListener("click", () => {
            const isAutoSaveEnabled = toggleAutoSave.checked;
            const interval = parseInt(intervalInput.value, 10) || 1; // Default to 1 minute

            if (isAutoSaveEnabled) {
                startAutoSave(interval * 60); // Convert minutes to seconds
                console.log(`Auto-save started with interval: ${interval} minutes.`);
            } else {
                stopAutoSave();
                console.log("Auto-save is disabled. No action taken.");
            }
        });
    }

    // Additional listeners (optional, for user feedback)
    if (toggleAutoSave && intervalInput) {
        toggleAutoSave.addEventListener("change", () => {
            console.log(`Auto-save ${toggleAutoSave.checked ? "enabled" : "disabled"} (not yet applied).`);
        });

        intervalInput.addEventListener("change", () => {
            const interval = parseInt(intervalInput.value, 10) || 1; // Default to 1 minute
            console.log(`Auto-save interval set to ${interval} minutes (not yet applied).`);
        });
    }


    // ====================================================
    // Network Request Capture and Processing
    // ====================================================

    // Capture network requests
    chrome.devtools.network.onRequestFinished.addListener((request) => {
        // Check if the request should be filtered out
        if (isUnwantedRequest(request)) {
            return; // Skip this request
        }

        // Store the full request object for HAR saving
        networkRequests.push(request);

        // Detect timing anomalies for MITM
        detectTimingAnomalies(request);

        // Store the custom data for flow diagrams or other purposes
        flowData.push({
            source: inspectedHostname || "unknown",
            target: new URL(request.request.url).hostname,
            timestamp: request.startedDateTime,
            count: 1, // Initialize a count property to track requests
            destIP: request.serverIPAddress || "N/A" // Capture destination IP if available
        });

        // ====================================================
        // Network Requests Tab Display
        // ====================================================

        // Network Requests Tab - Display individual network requests
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
        const timestamp = new Date(request.startedDateTime).toISOString();
        headerDiv.innerHTML = `
            <strong>Timestamp:</strong> ${timestamp}<br>
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

        // Append to the Network Requests container
        const networkEntriesContainer = document.getElementById("network-entries");
        if (networkEntriesContainer) {
            networkEntriesContainer.appendChild(entryDiv);
        }

        // ====================================================
        // XSS Detection Processing
        // ====================================================

        // XSS Detection Tab
        request.getContent((content) => {
            // Content-Type Filtering (specific to XSS detection)
            const contentTypeHeader = request.response.headers.find(
                header => header.name.toLowerCase() === "content-type"
            );
            const contentType = contentTypeHeader ? contentTypeHeader.value : null;

            console.log("XSS Detection - Detected Content-Type:", contentType); // Debugging: Log Content-Type

            // Skip XSS detection if Content-Type is not relevant
            if (contentType && !/text\/html|application\/javascript|text\/javascript/.test(contentType)) {
                console.warn("XSS Detection skipped due to irrelevant Content-Type:", contentType);
                return; // Exit XSS detection for this request
            }

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

                // Escape and truncate content for safe rendering
                const truncatedBody = truncateText(content || "No content");
                const escapedBody = escapeHTML(truncatedBody);

                detailsContent.innerHTML = `
                    <strong>Request URL:</strong> ${escapeHTML(request.request.url)}<br>
                    <strong>Request Method:</strong> ${escapeHTML(request.request.method)}<br>
                    <strong>Request Headers:</strong> ${escapeHTML(request.request.headers.map(header => `${header.name}: ${header.value}`).join("<br>"))}<br>
                    <strong>Response Headers:</strong> ${escapeHTML(request.response.headers.map(header => `${header.name}: ${header.value}`).join("<br>"))}<br>
                    <strong>Request Body:</strong><br>${escapeHTML(request.request.postData?.text || "No body")}<br>
                    <strong>Response Body:</strong><br><pre>${escapedBody}</pre>
                `;

                // Add optional iframe for debugging full response (sandboxed)
                const iframeToggleButton = document.createElement("button");
                iframeToggleButton.textContent = "View Full Response in iFrame";
                iframeToggleButton.addEventListener("click", () => {
                    const iframe = document.createElement("iframe");
                    iframe.srcdoc = content || "No content";
                    iframe.style.width = "100%";
                    iframe.style.height = "400px";
                    iframe.style.border = "1px solid #ddd";
                    detailsContent.appendChild(iframe);
                    iframeToggleButton.style.display = "none"; // Hide button after adding iframe
                });

                detailsContent.appendChild(iframeToggleButton);

                const expandButton = document.createElement("button");
                expandButton.textContent = "Expand";
                expandButton.addEventListener("click", () => {
                    detailsContent.style.display = detailsContent.style.display === "none" ? "block" : "none";
                });

                detailsCol.appendChild(expandButton);
                detailsCol.appendChild(detailsContent);
                entryRow.appendChild(detailsCol);

                // Append entry to the XSS Detection container
                const xssEntriesContainer = document.getElementById("xss-entries");
                if (xssEntriesContainer) {
                    xssEntriesContainer.appendChild(entryRow);
                }
            }
        });

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
// Function to process and get top connections
function prepareTopConnections(topN = 5) {
    const linksMap = {};

    // Count connections between source and target
    flowData.forEach(req => {
        const linkKey = `${req.source}->${req.target}`;
        if (linksMap[linkKey]) {
            linksMap[linkKey].count += 1;
        } else {
            linksMap[linkKey] = {
                source: req.source,
                target: req.target,
                count: 1
            };
        }
    });

    // Convert links map to an array and sort by count
    const sortedLinks = Object.values(linksMap).sort((a, b) => b.count - a.count);

    // Return only the top N connections
    return sortedLinks.slice(0, topN);
}

// Function to render the bar chart
function renderBarChart() {
    const topConnections = prepareTopConnections();

    // Clear previous chart
    d3.select("#diagram-container").selectAll("*").remove();

    const width = document.getElementById("diagram-container").clientWidth;
    const height = document.getElementById("diagram-container").clientHeight;
    const margin = { top: 20, right: 20, bottom: 50, left: 60 };
    const chartWidth = width - margin.left - margin.right;
    const chartHeight = height - margin.top - margin.bottom;

    const svg = d3.select("#diagram-container")
        .append("svg")
        .attr("width", width)
        .attr("height", height);

    const chart = svg.append("g")
        .attr("transform", `translate(${margin.left},${margin.top})`);

    // Set up scales
    const x = d3.scaleBand()
        .domain(topConnections.map(d => `${d.source}->${d.target}`))
        .range([0, chartWidth])
        .padding(0.2);

    const y = d3.scaleLinear()
        .domain([0, d3.max(topConnections, d => d.count)])
        .nice()
        .range([chartHeight, 0]);

    // Add axes
    chart.append("g")
        .attr("transform", `translate(0,${chartHeight})`)
        .call(d3.axisBottom(x))
        .selectAll("text")
        .attr("transform", "rotate(-45)")
        .style("text-anchor", "end");

    chart.append("g")
        .call(d3.axisLeft(y));

    // Add bars
    chart.selectAll(".bar")
        .data(topConnections)
        .enter().append("rect")
        .attr("class", "bar")
        .attr("x", d => x(`${d.source}->${d.target}`))
        .attr("y", d => y(d.count))
        .attr("width", x.bandwidth())
        .attr("height", d => chartHeight - y(d.count))
        .attr("fill", "#4285f4");

    // Add labels to bars
    chart.selectAll(".label")
        .data(topConnections)
        .enter().append("text")
        .attr("x", d => x(`${d.source}->${d.target}`) + x.bandwidth() / 2)
        .attr("y", d => y(d.count) - 5)
        .attr("text-anchor", "middle")
        .attr("fill", "#333")
        .text(d => d.count);
}


// Function to prepare the time data, binned by minute
function prepareTimeData() {
    const trafficByMinute = new Map();

    // Aggregate data by minute
    flowData.forEach((req) => {
        const timestamp = new Date(req.timestamp); // Parse ISO string to Date object
        const minute = timestamp.toISOString().substring(0, 16); // Extract "YYYY-MM-DDTHH:mm"

        if (trafficByMinute.has(minute)) {
            trafficByMinute.set(minute, trafficByMinute.get(minute) + 1); // Increment count for the minute
        } else {
            trafficByMinute.set(minute, 1); // Initialize count if this minute is new
        }
    });

    // Convert Map to array and sort by timestamp
    const aggregatedTimeData = Array.from(trafficByMinute.entries())
        .map(([minute, count]) => ({
            timestamp: new Date(minute), // Convert back to Date object
            count
        }))
        .sort((a, b) => a.timestamp - b.timestamp); // Sort by timestamp

    return aggregatedTimeData;
}

// Function to render the traffic graph
function renderTrafficGraph() {
    const timeData = prepareTimeData(); // Get aggregated data

    if (!timeData || timeData.length === 0) {
        console.error("No traffic data available");
        return;
    }

    const width = document.getElementById("traffic-graph").clientWidth;
    const height = document.getElementById("traffic-graph").clientHeight;

    const margin = { top: 20, right: 20, bottom: 30, left: 50 };
    const chartWidth = width - margin.left - margin.right;
    const chartHeight = height - margin.top - margin.bottom;

    // Clear previous graph
    d3.select("#traffic-graph").selectAll("*").remove();

    const svg = d3.select("#traffic-graph")
        .append("svg")
        .attr("width", width)
        .attr("height", height)
        .append("g")
        .attr("transform", `translate(${margin.left},${margin.top})`);

    // Set up scales for x (time) and y (request count)
    const x = d3.scaleTime()
        .domain(d3.extent(timeData, d => d.timestamp)) // Min and max timestamps
        .range([0, chartWidth]);

    const y = d3.scaleLinear()
        .domain([0, d3.max(timeData, d => d.count) || 1]) // Ensure y-domain has a max of at least 1
        .nice()
        .range([chartHeight, 0]);

    // Add x-axis (local time formatting)
    const timeFormat = d3.timeFormat("%H:%M"); // Display as "HH:mm"
    svg.append("g")
        .attr("transform", `translate(0,${chartHeight})`)
        .call(d3.axisBottom(x).tickFormat(d => timeFormat(d)));

    // Add y-axis
    svg.append("g")
        .call(d3.axisLeft(y));

    // Line generator for the graph
    const line = d3.line()
        .x(d => x(d.timestamp))
        .y(d => y(d.count));

    // Draw the line
    svg.append("path")
        .datum(timeData)
        .attr("fill", "none")
        .attr("stroke", "steelblue")
        .attr("stroke-width", 2)
        .attr("d", line);

    // Add data points (circles)
    svg.selectAll(".dot")
        .data(timeData)
        .enter().append("circle")
        .attr("class", "dot")
        .attr("cx", d => x(d.timestamp))
        .attr("cy", d => y(d.count))
        .attr("r", 3)
        .attr("fill", "steelblue");
}

// Auto-update the graph every 10 seconds
let autoUpdateInterval;
function startAutoUpdate() {
    clearInterval(autoUpdateInterval);
    autoUpdateInterval = setInterval(renderTrafficGraph, 10000);
}
startAutoUpdate();

// Manual update button
const manualUpdateButton = document.getElementById("manual-update");
if (manualUpdateButton) {
    manualUpdateButton.addEventListener("click", renderTrafficGraph);
}

// Stop auto-update button
const stopAutoUpdateButton = document.getElementById("stop-auto-update");
if (stopAutoUpdateButton) {
    stopAutoUpdateButton.addEventListener("click", () => {
        clearInterval(autoUpdateInterval);
    });
}

// Refresh button to re-render the bar chart
const refreshButton = document.getElementById("refresh-diagram");
if (refreshButton) {
    refreshButton.addEventListener("click", renderBarChart);
}

// Refresh button to re-render the bar chart
document.getElementById("refresh-diagram").addEventListener("click", renderBarChart);

    // ====================================================
    // Report Generation Functionality
    // ====================================================

    // Report Generation Tab
    function generateReport() {
        try {
            // Collect user preferences for report sections
            const includeNetworkRequests = document.getElementById('include-network-requests').checked; // Corrected ID for the Network Requests tab
            const includeXSS = document.getElementById('include-xss').checked;
            const includeThreats = document.getElementById('include-threats').checked;
            const includeFlow = document.getElementById('include-flow').checked;
            const includeMitm = true; // Always include analysis

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

                // Include Top Connections Summary
                const topConnections = prepareTopConnections(5); // Get top 5 connections
                reportContent += `<h3>Top Connections</h3>`;
                if (topConnections.length > 0) {
                    reportContent += `<table>
                        <tr><th>Source</th><th>Target</th><th>Request Count</th></tr>`;
                    topConnections.forEach(connection => {
                        reportContent += `<tr>
                            <td>${connection.source}</td>
                            <td>${connection.target}</td>
                            <td>${connection.count}</td>
                        </tr>`;
                    });
                    reportContent += `</table>`;
                } else {
                    reportContent += `<p>No connections found.</p>`;
                }

                // Include Traffic Over Time Summary
                const trafficData = prepareTimeData(); // Aggregate traffic data by minute
                reportContent += `<h3>Traffic Over Time</h3>`;
                if (trafficData.length > 0) {
                    reportContent += `<table>
                        <tr><th>Timestamp</th><th>Request Count</th></tr>`;
                    trafficData.forEach(entry => {
                        reportContent += `<tr>
                            <td>${entry.timestamp.toLocaleString()}</td>
                            <td>${entry.count}</td>
                        </tr>`;
                    });
                    reportContent += `</table>`;
                } else {
                    reportContent += `<p>No traffic data available.</p>`;
                }
            }

            // Include MITM Anomalies
            if (includeMitm) {
                const mitmList = document.querySelectorAll(".mitm-alert");
                if (mitmList.length > 0) {
                    reportContent += `<h2>MITM Anomalies</h2>`;
                    reportContent += `<table>
                        <tr>
                            <th>Issue Type</th>
                            <th>Details</th>
                        </tr>`;
                    mitmList.forEach(alert => {
                        const issueType = alert.querySelector("strong").textContent;
                        const details = alert.textContent.replace(issueType, "").trim();
                        reportContent += `<tr>
                            <td>${issueType}</td>
                            <td>${details}</td>
                        </tr>`;
                    });
                    reportContent += `</table>`;
                } else {
                    reportContent += `<p>No MITM anomalies detected.</p>`;
                }
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
