document.addEventListener('DOMContentLoaded', () => {
  const landingPage = document.getElementById('landing-page');
  const dashboard = document.getElementById('dashboard');
  const loginButton = document.getElementById('login-button');
  const scanModeSelect = document.getElementById('scan-mode');
  const loadingIndicator = document.getElementById('loading-indicator');
  const resultsContainer = document.getElementById('results-container');

  const handleAppFlow = () => {
    const urlParams = new URLSearchParams(window.location.search);
    const isLoggedIn = urlParams.get('loggedin') === 'true';
    const scanMode = urlParams.get('mode');

    if (isLoggedIn && scanMode) {
      window.location.href = "/dashboard.html";
    } else {
      showLandingPage();
    }

    // 💡 Always check if we're on dashboard page
    if (window.location.pathname.includes('/dashboard.html')) {
      fetchScanResults('inbox');
    }
  };

  const showLandingPage = () => {
    if (landingPage) landingPage.classList.remove('hidden');
    if (dashboard) dashboard.classList.add('hidden');
    setupLoginButton();
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
      document.getElementById('scan-results').innerHTML = "<li>Error loading scan results.</li>";
    }
  };

  const updateDashboardCards = (emails) => {
    const recentScansEl = document.getElementById('scan-results');
    const scanCount = document.getElementById('scan-count');
    const phishingCount = document.getElementById('phishing-count');
    const riskLevel = document.getElementById('risk-level');
    const lastScan = document.getElementById('last-scan-time');
    const threatStatsEl = document.getElementById('threat-summary');
    const threatLogEl = document.getElementById('threat-log');

    if (!emails || emails.length === 0) {
      if (recentScansEl) recentScansEl.innerHTML = "<li>No recent emails scanned.</li>";
      return;
    }

    // 💌 Recent Scans
    recentScansEl.innerHTML = '';
    let phishing = 0;

    emails.slice(0, 3).forEach(email => {
      const li = document.createElement('li');
      li.innerHTML = `<strong>From:</strong> ${escapeHtml(email.from)} — ${email.status}`;
      recentScansEl.appendChild(li);
      if (email.status.includes("Phishing") || email.status.includes("⚠️")) phishing++;
    });

    // 📊 Update values
    scanCount.textContent = emails.length;
    phishingCount.textContent = phishing;
    riskLevel.textContent = phishing >= 3 ? 'High' : phishing === 0 ? 'Low' : 'Medium';
    riskLevel.style.color = phishing >= 3 ? 'red' : phishing === 0 ? 'green' : 'orange';
    lastScan.textContent = new Date().toLocaleString();

    // 🧠 Optional extra stats section
    if (threatStatsEl) {
      threatStatsEl.innerHTML += `
        <p>Threats Blocked: <strong>${phishing}</strong></p>
      `;
    }

    // 📓 Threat Log
    const blockedEmails = emails.filter(e => e.status.includes("⚠️"));
    if (threatLogEl) {
      threatLogEl.innerHTML = blockedEmails.length
        ? blockedEmails.map(e => `<li>${e.subject} — Blocked</li>`).join('')
        : "<li>No threats found.</li>";
    }

    drawRiskChart(emails.length, phishing);
    drawThreatFrequencyChart(emails);
  };

  const drawRiskChart = (total, phishing) => {
    const safe = total - phishing;
    const ctx = document.getElementById('riskPieChart')?.getContext('2d');
    if (!ctx) return;

    if (window.riskChart) window.riskChart.destroy();

    window.riskChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Safe', 'Phishing'],
        datasets: [{
          data: [safe, phishing],
          backgroundColor: ['#cc77f2', '#f08aff'], // 💜 Safe, 💗 Phishing
          borderWidth: 0
        }]
      },
      options: {
        cutout: '70%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#eee',
              font: { size: 12 }
            }
          }
        }
      }
    });
  };

  const drawThreatFrequencyChart = (emails) => {
    const ctx = document.getElementById('threatBarChart')?.getContext('2d');
    if (!ctx) return;

    const frequency = {};
    emails.forEach(email => {
      if (email.status.includes("Phishing") || email.status.includes("⚠️")) {
        const date = new Date(email.timestamp || Date.now()).toISOString().split('T')[0];
        frequency[date] = (frequency[date] || 0) + 1;
      }
    });

    const labels = Object.keys(frequency).sort();
    const data = labels.map(date => frequency[date]);

    if (window.threatChart) window.threatChart.destroy();

    window.threatChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Phishing Emails',
          data,
          backgroundColor: 'rgba(240, 138, 255, 0.7)',
          borderColor: 'rgba(204, 119, 242, 1)',
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

