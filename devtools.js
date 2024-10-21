chrome.devtools.panels.create(
    "HAR Viewer", // Panel title
    "assets/icon.png", // Panel icon (make sure the path is correct)
    "panel.html", // HTML file for the custom panel
    function(panel) {
      console.log("HAR Viewer panel created");
    }
  );
  