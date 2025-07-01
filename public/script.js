document.addEventListener('DOMContentLoaded', () => {
  const landingPage = document.getElementById('landing-page');
  const dashboard = document.getElementById('dashboard');
  const loginButton = document.getElementById('login-button');
  const scanModeSelect = document.getElementById('scan-mode');
  const loadingIndicator = document.getElementById('loading-indicator');
  const resultsContainer = document.getElementById('results-container');

  // 👇 FIXED typo: UserisLoggedIn -> isLoggedIn
  const handleAppFlow = () => {
    const urlParams = new URLSearchParams(window.location.search);
    const isLoggedIn = urlParams.get('loggedin') === 'true';
    const scanMode = urlParams.get('mode');

    if (isLoggedIn && scanMode) {
      window.location.href = "/dashboard.html";
      fetchScanResults(scanMode);
    } else {
      showLandingPage();
    }
  };

  const showLandingPage = () => {
    if (landingPage) landingPage.classList.remove('hidden');
    if (dashboard) dashboard.classList.add('hidden');
    setupLoginButton();
  };

  const showDashboard = () => {
    if (landingPage) landingPage.classList.add('hidden');
    if (dashboard) dashboard.classList.remove('hidden');
    if (loadingIndicator) loadingIndicator.classList.remove('hidden');
  };

  const setupLoginButton = () => {
    if (loginButton) {
      loginButton.addEventListener('click', (e) => {
        e.preventDefault();
        const selectedMode = scanModeSelect.value;
        window.location.href = `/auth?mode=${selectedMode}`;
      });
    }
  };

  const fetchScanResults = async (mode = 'inbox') => {
    try {
      const response = await fetch(`/scan?state=${mode}:`);
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

      const data = await response.json();
      updateDashboardCards(data);
    } catch (error) {
      console.error("⚠️ Scan fetch failed:", error);
    }
  };

  // ✅ Update dashboard card content
  const updateDashboardCards = (emails) => {
    const recentScansEl = document.getElementById('recent-scans');
    const threatStatsEl = document.getElementById('threat-summary');
    const threatLogEl = document.getElementById('threat-log');

    if (!emails || emails.length === 0) {
      if (recentScansEl) recentScansEl.innerHTML = "<li>No recent emails scanned.</li>";
      return;
    }

    // 💌 Recent Scans
    recentScansEl.innerHTML = emails.slice(0, 3).map(email => `
      <li><strong>From:</strong> ${escapeHtml(email.from)} — ${email.status}</li>
    `).join('');

    // 📊 Stats Summary
    const total = emails.length;
    const blocked = emails.filter(e => e.status.includes("⚠️")).length;
    const safe = emails.filter(e => e.status.includes("✅")).length;

    if (threatStatsEl) {
      threatStatsEl.innerHTML = `
        <p>Total Scanned: <strong>${total}</strong></p>
        <p>Threats Blocked: <strong>${blocked}</strong></p>
        <p>Risk Level: <strong style="color: orange;">${blocked > 2 ? 'High' : 'Medium'}</strong></p>
        <p>Last Scan: <strong>${new Date().toLocaleTimeString()}</strong></p>
      `;
    }

    // 📓 Threat Log
    const blockedEmails = emails.filter(e => e.status.includes("⚠️"));
    if (threatLogEl) {
      threatLogEl.innerHTML = blockedEmails.length
        ? blockedEmails.map(e => `<li>${e.subject} — Blocked</li>`).join('')
        : "<li>No threats found.</li>";
    }

    // 📈 Optional: Load fake chart
    if (window.loadFakeChart) loadFakeChart(blocked, safe);
  };

  // ✨ HTML Safe
  const escapeHtml = (unsafe = '') => {
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  };

  handleAppFlow();
});
