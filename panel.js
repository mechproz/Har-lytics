// Array to store network requests
const networkRequests = [];

// Capture network requests
chrome.devtools.network.onRequestFinished.addListener((request) => {
    console.log("Request captured:", request);

    // Capture the source as the current document's hostname and the target from the request URL
    networkRequests.push({
        source: document.location.hostname, // Source page, or customize to capture a specific origin
        target: new URL(request.request.url).hostname, // Destination host
        count: 1 // Initialize a count property to track requests
    });
});

// Function to process data into nodes and links for D3.js
function prepareData() {
    const nodes = [];
    const linksMap = {};

    // Process unique nodes and links
    networkRequests.forEach(req => {
        const sourceHost = req.source;
        const targetHost = req.target;

        // Add source and target to nodes array if not already present
        if (!nodes.includes(sourceHost)) {
            nodes.push(sourceHost);
        }
        if (!nodes.includes(targetHost)) {
            nodes.push(targetHost);
        }

        // Create a unique key for each link between source and target
        const linkKey = `${sourceHost}->${targetHost}`;
        
        // Track link counts by unique source-target pair
        if (linksMap[linkKey]) {
            linksMap[linkKey].count += 1;
        } else {
            linksMap[linkKey] = { source: sourceHost, target: targetHost, count: 1 };
        }
    });

    // Convert linksMap to an array for D3 rendering
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
    const simulation = d3.forceSimulation(nodes.map(d => ({ id: d })))
        .force("link", d3.forceLink(links).id(d => d.id).distance(100))
        .force("charge", d3.forceManyBody().strength(-300))
        .force("center", d3.forceCenter(width / 2, height / 2));

    // Draw links (lines) with variable thickness based on request count
    const link = svg.append("g")
        .attr("class", "links")
        .selectAll("line")
        .data(links)
        .enter().append("line")
        .attr("stroke", "#999")
        .attr("stroke-opacity", 0.6)
        .attr("stroke-width", d => Math.sqrt(d.count)); // Thickness based on request count

    // Draw nodes (circles)
    const node = svg.append("g")
        .attr("class", "nodes")
        .selectAll("circle")
        .data(simulation.nodes())
        .enter().append("circle")
        .attr("r", 10)
        .attr("fill", "#4285f4")
        .call(d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended));

    // Display labels on nodes
    svg.append("g")
        .selectAll("text")
        .data(simulation.nodes())
        .enter().append("text")
        .attr("dx", 12)
        .attr("dy", ".35em")
        .text(d => d.id);

    // Update positions on each tick
    simulation.on("tick", () => {
        link.attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);

        node.attr("cx", d => d.x)
            .attr("cy", d => d.y);

        svg.selectAll("text")
            .attr("x", d => d.x)
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
            <p><strong>Origin:</strong> ${link.source}</p>
            <p><strong>Destination:</strong> ${link.target}</p>
            <p><strong>Request Count:</strong> ${link.count}</p>
        `;
        display.appendChild(linkInfo);
    });
}

// Refresh button to re-render the diagram with new data
document.getElementById("refresh-diagram").addEventListener("click", renderDiagram);
