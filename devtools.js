// Array to store network request data captured by the DevTools
let networkData = [];

// ID to store the interval for automatic saving, allowing us to clear it when needed
let autoSaveIntervalId = null; 

// Modified saveHAR function to include isAutoSave parameter and Singapore time formatting
function saveHAR(isAutoSave = false) {
    const harData = {
        log: {
            version: "1.2",
            creator: {
                name: "HAR Data Viewer",
                version: "1.0"
            },
            entries: networkData.map(request => {
                return {
                    startedDateTime: request.startedDateTime,
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
                };
            })
        }
    };

    // Get current date and time adjusted to Singapore timezone (GMT+8)
    const now = new Date();
    now.setHours(now.getHours() + 8); // Adjust to Singapore time (GMT+8)

    // Format date and time for the filename in a Singapore timezone-friendly format
    const saveType = isAutoSave ? "auto" : "manual";
    const timestamp = now.toISOString().replace("T", "_").replace(/[:.]/g, "-").slice(0, 19); // Format timestamp

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
    networkData = [];
}

// Function to start automatic saving at the specified interval (in seconds)
function startAutoSave(interval) {
    stopAutoSave(); // Clear any existing interval first
    autoSaveIntervalId = setInterval(() => saveHAR(true), interval * 1000); // Set interval in milliseconds, passing true for isAutoSave
    console.log(`Automatic save started with an interval of ${interval} seconds.`);
}

// Function to stop automatic saving by clearing the interval
function stopAutoSave() {
    if (autoSaveIntervalId) {
        clearInterval(autoSaveIntervalId);
        autoSaveIntervalId = null;
        console.log("Automatic save stopped.");
    }
}

// Create the DevTools panel
chrome.devtools.panels.create(
    "HAR Viewer", // Panel title
    "assets/icon.png", // Panel icon
    "panel.html", // HTML file for the custom panel
    function(panel) {
        console.log("HAR Viewer panel created");

        // Set up network request capture
        chrome.devtools.network.onRequestFinished.addListener((request) => {
            networkData.push(request);
            console.log("Request captured:", request);
        });

        // Wait for the panel to be fully shown
        panel.onShown.addListener((window) => {
            const saveHarButton = window.document.getElementById("save-har");
            const intervalInput = window.document.getElementById("auto-save-interval");
            const toggleAutoSave = window.document.getElementById("toggle-auto-save");

            // Manual save button
            if (saveHarButton) {
                saveHarButton.addEventListener("click", () => {
                    console.log("Save Traffic button clicked");
                    saveHAR(false); // Manual save, passing false for isAutoSave
                });
            } else {
                console.error("Save Traffic button not found in DOM.");
            }

            // Start auto-save with default settings if enabled on load
            const defaultInterval = parseInt(intervalInput.value, 10) || 30; // Set default interval to 30 seconds
            if (toggleAutoSave && toggleAutoSave.checked) {
                startAutoSave(defaultInterval);
            }

            // Auto-save toggle to enable/disable auto-saving
            if (toggleAutoSave) {
                toggleAutoSave.addEventListener("change", () => {
                    const interval = parseInt(intervalInput.value, 10) || 30; // Use the interval from the input or default to 30
                    if (toggleAutoSave.checked) {
                        startAutoSave(interval);
                    } else {
                        stopAutoSave();
                    }
                });
            }
        });
    }
);
