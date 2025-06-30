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

        if (UserisLoggedIn && scanMode) {
           window.location.href = "/dashboard.html"; // or wherever your dashboard is
            fetchScanResults(scanMode);
        } else {
            showLandingPage();
        }
    };

    const showLandingPage = () => {
        landingPage.classList.remove('hidden');
        dashboard.classList.add('hidden');
        setupLoginButton();
    };

    const showDashboard = () => {
        landingPage.classList.add('hidden');
        dashboard.classList.remove('hidden');
        loadingIndicator.classList.remove('hidden');
    };

    const setupLoginButton = () => {
        loginButton.addEventListener('click', (e) => {
            e.preventDefault();
            const selectedMode = scanModeSelect.value;
            window.location.href = `/auth?mode=${selectedMode}`;
        });
    };

    const fetchScanResults = async (mode) => {
        try {
           const response = await fetch(`/scan?mode=${mode}`);
if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
}
const data = await response.json();

            renderResults(data);
        } catch (error) {
            console.error("Failed to fetch scan results:", error);
            resultsContainer.innerHTML = `<p class="error">Could not load scan results. Please try again later.</p>`;
        } finally {
            loadingIndicator.classList.add('hidden');
        }
    };

    const renderResults = (emails) => {
        if (!emails || emails.length === 0) {
            resultsContainer.innerHTML = `<p class="no-results">No emails found to scan for the selected mode.</p>`;
            return;
        }

        resultsContainer.innerHTML = '';
        emails.forEach(email => {
            const card = createEmailCard(email);
            resultsContainer.insertAdjacentHTML('beforeend', card);
        });

        setupScrollAnimations();
    };

    const createEmailCard = (email) => {
        const riskClass = `risk-${email.riskLevel.toLowerCase()}`;

        const linksHtml = email.links && email.links.length > 0
            ? `<ul>${email.links.map(link => `<li>${link}</li>`).join('')}</ul>`
            : `<p class="no-links">No links found in this email.</p>`;

        return `
            <div class="email-card" data-observe>
                <div class="risk-indicator ${riskClass}"></div>
                <div class="email-content">
                    <h3>${email.subject}</h3>
                    <p class="sender">From: ${escapeHtml(email.from)}</p>
                    <div class="risk-label ${riskClass}">${email.riskLevel}</div>
                    <div class="links-list">
                        <h4>Scanned Links:</h4>
                        ${linksHtml}
                    </div>
                </div>
            </div>
        `;
    };

    const setupScrollAnimations = () => {
        const observer = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('visible');
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.1 });

        document.querySelectorAll('[data-observe]').forEach(el => {
            observer.observe(el);
        });
    };

    const escapeHtml = (unsafe) => {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    handleAppFlow();
});
