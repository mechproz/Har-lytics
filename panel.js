// Path to the malicious IPs file
const maliciousIPsPath = chrome.runtime.getURL("data/malicious_ips.txt");

// Function to fetch and parse the malicious IPs from the file
async function fetchMaliciousIPs() {
    try {
        const response = await fetch(maliciousIPsPath);
        const text = await response.text();
        return text.split("\n").map(ip => ip.trim()); // Split and trim each IP line
    } catch (error) {
        console.error("Error fetching malicious IPs:", error);
        return [];
    }
}

// Initialize malicious IP list and a Map to track detected IPs and their associated requests
let maliciousIPs = [];
const detectedIPs = new Map();  // Map to group requests by IP

// Fetch malicious IPs on script load
fetchMaliciousIPs().then(ips => {
    maliciousIPs = ips;
    console.log("Loaded Malicious IPs:", maliciousIPs);  // Log malicious IPs
});

// Function to display the malicious IPs, methods, and URLs in the HTML
function displayMaliciousIps() {
    const maliciousList = document.getElementById('malicious-list');
    maliciousList.innerHTML = ""; // Clear previous entries

    detectedIPs.forEach((requests, ip) => {
        const ipHeader = document.createElement('li');
        ipHeader.innerHTML = `<strong>IP:</strong> ${ip}`;
        ipHeader.style.marginTop = '10px';
        maliciousList.appendChild(ipHeader);

        requests.forEach(({ method, url }) => {
            const requestItem = document.createElement('li');
            requestItem.innerHTML = `&nbsp;&nbsp;<strong>Method:</strong> ${method}<br>&nbsp;&nbsp;<strong>URL:</strong> ${url}<br><br>`;
            maliciousList.appendChild(requestItem);
        });

        const gap = document.createElement('br');
        maliciousList.appendChild(gap);
    });
}

// Add listener for network requests
chrome.devtools.network.onRequestFinished.addListener((request) => {
    const remoteIPAddress = request.serverIPAddress || "N/A"; // Get the remote IP address
    const method = request.request.method; // Get the HTTP method
    const url = request.request.url; // Get the URL

    console.log("Request captured:", url, "IP:", remoteIPAddress, "Method:", method);

    // Check if the IP is in the malicious list
    if (maliciousIPs.includes(remoteIPAddress)) {
        console.warn("Malicious IP detected:", remoteIPAddress);
        
        // Add the request details to the Map under the specific IP
        if (!detectedIPs.has(remoteIPAddress)) {
            detectedIPs.set(remoteIPAddress, []); // Initialize array for new IP
        }
        detectedIPs.get(remoteIPAddress).push({ method, url });

        // Show the alert message only when the first malicious IP is detected
        const maliciousAlertDiv = document.getElementById('malicious-alert');
        if (detectedIPs.size === 1) { // Show alert only on the first detection
            maliciousAlertDiv.style.display = 'block';
        }

        // Update the display with the grouped malicious IPs and their requests
        displayMaliciousIps();
    }

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
        <strong>URL:</strong> ${url}<br>
        <strong>Method:</strong> ${method}<br>
        <strong>Status:</strong> ${request.response.status}<br>
        <strong>Remote IP:</strong> ${remoteIPAddress}<br>
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
