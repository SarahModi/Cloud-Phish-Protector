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

  // 📈 Load real Chart.js donut chart
const ctx = document.getElementById('riskPieChart')?.getContext('2d');
if (ctx) {
  if (window.riskChart) window.riskChart.destroy(); // 🔁 Prevent overlap

  window.riskChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Safe', 'Phishing'],
      datasets: [{
        data: [safe, blocked],
        backgroundColor: ['#cc77f2', '#f08aff'], // 💜 Safe, 💗 Phishing
        borderWidth: 0
      }]
    },
    options: {
      cutout: '70%',
      plugins: {
        legend: {
          labels: {
            color: '#eee',
            font: {
              size: 12
            }
          }
        }
      }
    }
  });
}

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
  
const drawThreatFrequencyChart = (emails) => {
  const ctx = document.getElementById('threatBarChart')?.getContext('2d');
  if (!ctx) return;

  const frequency = {};

  emails.forEach(email => {
    if (email.status.includes('Phishing')) {
      const date = new Date(email.timestamp || Date.now()).toISOString().split('T')[0];
      frequency[date] = (frequency[date] || 0) + 1;
    }
  });

  const labels = Object.keys(frequency).sort();
  const data = labels.map(date => frequency[date]);

  if (window.threatChart) window.threatChart.destroy(); // prevent overlapping chart

  window.threatChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Phishing Emails',
        data,
        backgroundColor: 'rgba(240, 138, 255, 0.7)', // 💗 soft pink
        borderColor: 'rgba(204, 119, 242, 1)',       // 💜 soft purple
        borderWidth: 2,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      scales: {
        x: { ticks: { color: '#eee' } },
        y: { beginAtZero: true, ticks: { color: '#eee' } }
      },
      plugins: {
        legend: { labels: { color: '#eee' } }
      }
    }
  });
};

  handleAppFlow();
});
