console.log("DevTools panel loaded");

// Array to store network requests
const networkRequests = [];

// Variable to store the inspected page's hostname
let inspectedHostname = null;

// Get the hostname of the inspected window
chrome.devtools.inspectedWindow.eval("window.location.hostname", function(result, isException) {
    if (!isException) {
        inspectedHostname = result;
    } else {
        console.error('Failed to get inspected window hostname:', isException);
    }
});

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
    document.getElementById('analysis-overview-tab').addEventListener('click', () => showView('analysis-overview'));
    document.getElementById('report-config-tab').addEventListener('click', () => showView('report-config'));

    // Placeholder content for each tab

    // Overview Tab - Display high-level statistics
    document.getElementById("network-entries-overview").innerHTML = `
        <p>Placeholder: Overview of network activity with basic stats.</p>
        <p>Example: Total requests, breakdown by HTTP method, and status codes.</p>
    `;

    // Capture network requests
    chrome.devtools.network.onRequestFinished.addListener((request) => {
        // Store the request in the networkRequests array
        networkRequests.push({
            source: inspectedHostname || "unknown",
            target: new URL(request.request.url).hostname, // Destination host
            count: 1, // Initialize a count property to track requests
            destIP: request.serverIPAddress || "N/A" // Capture destination IP if available
        });

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

        // XSS Detection Tab
        if (document.getElementById("xss-detection").classList.contains("active")) {
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
    });

    // Function to process data into nodes and links for D3.js
    function prepareData() {
        const nodesMap = {};
        const linksMap = {};

        // Process unique nodes and links
        networkRequests.forEach(req => {
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

    // Threat Correlation Tab - Placeholder for threat intelligence matches
    document.getElementById("network-entries-threat").innerHTML = `
        <p>Placeholder: List of requests matched with threat intelligence data.</p>
        <p>Implement: Cross-reference IPs and domains with a blacklist or threat feed.</p>
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
