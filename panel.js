console.log("DevTools panel loaded"); // Log when panel loads

// Add listener for network requests
chrome.devtools.network.onRequestFinished.addListener((request) => {
    console.log("Request captured:", request); // Log each captured request

    // Create a div to display the request data
    const entryDiv = document.createElement("div");
    entryDiv.classList.add("network-entry");

    // Prepare detailed request and response data
    const requestHeaders = request.request.headers.map(header => `${header.name}: ${header.value}`).join("<br>");
    const responseHeaders = request.response.headers.map(header => `${header.name}: ${header.value}`).join("<br>");
    const postData = request.request.postData ? request.request.postData.text : "No body";
    const responseBody = request.response.content ? request.response.content.text : "No content";

    // Capture timing data
    const timings = request.timings;
    const dnsTime = timings ? timings.dns : "N/A";
    const connectTime = timings ? timings.connect : "N/A";
    const sendTime = timings ? timings.send : "N/A";
    const receiveTime = timings ? timings.receive : "N/A";

    // Create collapsible header
    const headerDiv = document.createElement("div");
    headerDiv.classList.add("network-header");
    headerDiv.innerHTML = `
        <strong>URL:</strong> ${request.request.url}<br>
        <strong>Method:</strong> ${request.request.method}<br>
        <strong>Status:</strong> ${request.response.status}<br>
        <strong>Time:</strong> ${request.time.toFixed(2)} ms
    `;
    
    // Create collapsible content
    const contentDiv = document.createElement("div");
    contentDiv.classList.add("network-content");
    contentDiv.style.display = "none"; // Hide content by default

    // Add detailed info to collapsible content
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

    // Add click event to toggle content visibility
    headerDiv.addEventListener("click", () => {
        const isVisible = contentDiv.style.display === "block";
        contentDiv.style.display = isVisible ? "none" : "block";
    });

    // Append header and content to entry div
    entryDiv.appendChild(headerDiv);
    entryDiv.appendChild(contentDiv);

    // Append the entry to the panel
    document.getElementById("network-entries").appendChild(entryDiv); 
});




