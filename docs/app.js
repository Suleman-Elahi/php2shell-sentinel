(function () {
  "use strict";

  function detectDefaultBaseUrl() {
    var loc = window.location;
    if (loc.protocol === "http:" || loc.protocol === "https:") {
      var path = loc.pathname.replace(/\/index\.html$/, "").replace(/\/+$/, "");
      return loc.origin + path;
    }
    return "https://suleman-elahi.github.io/php2shell-sentinel";
  }

  var baseUrlInput = document.getElementById("base-url-input");
  var initialUrl = detectDefaultBaseUrl();
  if (baseUrlInput) {
    baseUrlInput.value = initialUrl;
    baseUrlInput.addEventListener("input", function () {
      updateCommands(baseUrlInput.value.trim().replace(/\/+$/, ""));
    });
  }

  function updateCommands(baseUrl) {
    if (!baseUrl) {
      baseUrl = detectDefaultBaseUrl();
    }

    var linuxOneLiner = document.getElementById("cmd-linux-oneliner");
    if (linuxOneLiner) {
      linuxOneLiner.textContent =
        'curl -fsSL "' +
        baseUrl +
        '/install.sh" | sudo SENTINEL_BASE_URL="' +
        baseUrl +
        '" sh';
    }

    var linuxCurlBin = document.getElementById("cmd-linux-curl-bin");
    if (linuxCurlBin) {
      linuxCurlBin.textContent =
        "# 1. Download static Linux binary\n" +
        'curl -fsSL "' +
        baseUrl +
        '/downloads/sentinel-linux-amd64" -o sentinel\n' +
        "chmod +x sentinel\n" +
        "sudo mv sentinel /usr/local/bin/sentinel\n\n" +
        "# 2. Audit PHP installation & apply php.ini virtual patches\n" +
        "sentinel check\n" +
        "sudo sentinel harden\n\n" +
        "# 3. Install & start as a persistent systemd service\n" +
        "sudo sentinel install\n" +
        "sudo sentinel start";
    }

    var winOneLiner = document.getElementById("cmd-win-oneliner");
    if (winOneLiner) {
      winOneLiner.textContent =
        '$env:SENTINEL_BASE_URL="' +
        baseUrl +
        '"; irm "' +
        baseUrl +
        '/install.ps1" | iex';
    }

    var winManual = document.getElementById("cmd-win-manual");
    if (winManual) {
      winManual.textContent =
        "# 1. Download static Windows binary (Run in Elevated PowerShell)\n" +
        'New-Item -ItemType Directory -Force -Path "C:\\Program Files\\PHP2ShellSentinel" | Out-Null\n' +
        'Invoke-WebRequest -Uri "' +
        baseUrl +
        '/downloads/sentinel-windows-amd64.exe" -OutFile "C:\\Program Files\\PHP2ShellSentinel\\sentinel.exe"\n\n' +
        "# 2. Audit PHP installation & apply php.ini virtual patches\n" +
        '& "C:\\Program Files\\PHP2ShellSentinel\\sentinel.exe" check\n' +
        '& "C:\\Program Files\\PHP2ShellSentinel\\sentinel.exe" harden\n\n' +
        "# 3. Install & start as a Windows Background Service (Auto-Start via SCM)\n" +
        '& "C:\\Program Files\\PHP2ShellSentinel\\sentinel.exe" install\n' +
        '& "C:\\Program Files\\PHP2ShellSentinel\\sentinel.exe" start';
    }
  }

  updateCommands(initialUrl);

  // Tab switching
  var tabButtons = document.querySelectorAll(".tab-btn");
  tabButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      var target = btn.getAttribute("data-tab");
      tabButtons.forEach(function (b) {
        b.classList.remove("active");
      });
      document.querySelectorAll(".tab-panel").forEach(function (panel) {
        panel.classList.remove("active");
      });
      btn.classList.add("active");
      var activePanel = document.getElementById(target);
      if (activePanel) {
        activePanel.classList.add("active");
      }
    });
  });

  // Copy to clipboard buttons
  var copyButtons = document.querySelectorAll(".copy-btn");
  copyButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      var targetId = btn.getAttribute("data-copy-target");
      var codeEl = document.getElementById(targetId);
      if (!codeEl) return;
      var text = codeEl.textContent;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () {
          var orig = btn.textContent;
          btn.textContent = "Copied!";
          setTimeout(function () {
            btn.textContent = orig;
          }, 1400);
        });
      }
    });
  });
})();
