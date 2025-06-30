/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

// --- DOM Elements ---
const sidebarEl = document.getElementById('sidebar') as HTMLElement;
const mainContentEl = document.getElementById('main-content') as HTMLElement;

// --- SVG Icons ---
const ICONS = {
    home: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>`,
    scan: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 10.5a2.5 2.5 0 1 1 5 0 2.5 2.5 0 0 1-5 0Z"></path><path d="M17 17s-2-2-5-2-5 2-5 2"></path><path d="M22 17v-3.5a9 9 0 0 0-18 0V17"></path></svg>`,
    learn: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"></path><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"></path></svg>`,
    settings: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 0 2l-.15.08a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.38a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1 0-2l.15-.08a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"></path><circle cx="12" cy="12" r="3"></circle></svg>`,
    shield: `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`
};

// --- View Templates ---
const renderHome = (): string => `
  <div class="header">
    <h1>Dashboard</h1>
    <p>Welcome back, Jane Doe. Here's a summary of your account's protection.</p>
  </div>
  <div class="grid-container">
    <div class="card">
      <h2>My Profile</h2>
      <ul>
        <li class="setting-item">
            <label>Name</label>
            <span>Jane Doe</span>
        </li>
        <li class="setting-item">
            <label>Email</label>
            <span>jane.d@examplecorp.com</span>
        </li>
        <li class="setting-item">
            <label>Plan</label>
            <span>Enterprise Shield</span>
        </li>
      </ul>
    </div>
    <div class="card">
      <h2>Recent Scans</h2>
      <ul>
        <li class="email-item">
          <div>
            <span>FW: Quarterly Results</span>
            <div class="text-muted" style="font-size: 0.8rem">From: john.smith@partner.com</div>
          </div>
          <span class="status safe">Safe</span>
        </li>
        <li class="email-item">
          <div>
            <span>URGENT: Invoice Overdue</span>
            <div class="text-muted" style="font-size: 0.8rem">From: payments@billing-service.io</div>
          </div>
          <span class="status threat">Threat</span>
        </li>
        <li class="email-item">
          <div>
            <span>Team Outing Details</span>
            <div class="text-muted" style="font-size: 0.8rem">From: hr@examplecorp.com</div>
          </div>
          <span class="status safe">Safe</span>
        </li>
      </ul>
    </div>
  </div>
`;

const renderLearn = (): string => `
  <div class="header">
    <h1>Learn</h1>
    <p>Stay updated with the latest in cyber threat intelligence.</p>
  </div>
  <div class="grid-container">
    <div class="card">
      <h2>Recent Blog Posts</h2>
        <div class="blog-post">
            <h3>The Rise of AI-Powered Phishing Attacks</h3>
            <p>Hackers are now using sophisticated AI to craft convincing phishing emails. Learn how to spot them...</p>
        </div>
        <div class="blog-post">
            <h3>Zero-Day Vulnerabilities: What You Need to Know</h3>
            <p>Understand what a zero-day exploit is and how our cloud protection keeps you safe even from unknown threats...</p>
        </div>
        <div class="blog-post">
            <h3>Securing Your Digital Supply Chain</h3>
            <p>Your security is only as strong as your weakest link. We explore the risks in your digital supply chain...</p>
        </div>
    </div>
  </div>
`;

const renderSettings = (): string => `
  <div class="header">
    <h1>Settings</h1>
    <p>Manage your profile and notification preferences.</p>
  </div>
  <div class="grid-container">
    <div class="card">
        <h2>Edit Profile</h2>
        <ul>
            <li class="setting-item">
                <label>Name</label>
                <span>Jane Doe</span>
            </li>
            <li class="setting-item">
                <label>Email Address</label>
                <span>jane.d@examplecorp.com</span>
            </li>
            <li class="setting-item">
                <label>Mobile Number</label>
                <span>(555) 123-4567</span>
            </li>
             <li class="setting-item">
                <label>Password</label>
                <span>••••••••••</span>
            </li>
        </ul>
    </div>
  </div>
`;

// --- App Logic ---
const views: { [key: string]: () => string } = {
  home: renderHome,
  learn: renderLearn,
  settings: renderSettings,
};

const renderSidebar = () => {
  sidebarEl.innerHTML = `
    <div class="sidebar-header">
        <span class="logo-icon">${ICONS.shield}</span>
        <span>Threat Protector</span>
    </div>
    <ul class="nav-list">
      <li class="nav-item active" data-view="home">
        <span class="nav-icon">${ICONS.home}</span> Home
      </li>
      <li class="nav-item" id="scan-nav-item" aria-haspopup="true" aria-expanded="false">
        <span class="nav-icon">${ICONS.scan}</span> Scan
      </li>
      <ul class="submenu" id="scan-submenu">
        <li><a href="#" class="submenu-item">Scan Inbox</a></li>
        <li><a href="#" class="submenu-item">Scan Junk</a></li>
        <li><a href="#" class="submenu-item">Scan Last 5 Inbox</a></li>
        <li><a href="#" class="submenu-item">Scan Last 10 Inbox</a></li>
        <li><a href="#" class="submenu-item">Scan Last 15 Inbox</a></li>
        <li><a href="mailto:?subject=Scan Request" class="submenu-item">Scan Specific Email...</a></li>
      </ul>
      <li class="nav-item" data-view="learn">
        <span class="nav-icon">${ICONS.learn}</span> Learn
      </li>
      <li class="nav-item" data-view="settings">
        <span class="nav-icon">${ICONS.settings}</span> Settings
      </li>
    </ul>
  `;
};

const renderView = (view: string) => {
  if (views[view]) {
    mainContentEl.innerHTML = views[view]();
  }
};

const handleNavClick = (e: Event) => {
  const target = e.target as HTMLElement;
  const navItem = target.closest<HTMLElement>('.nav-item');

  if (!navItem) return;

  // Handle Scan dropdown
  if (navItem.id === 'scan-nav-item') {
    const submenu = document.getElementById('scan-submenu') as HTMLElement;
    const isExpanded = navItem.getAttribute('aria-expanded') === 'true';
    navItem.setAttribute('aria-expanded', String(!isExpanded));
    submenu.classList.toggle('show');
    return;
  }
  
  const view = navItem.dataset.view;
  if (view) {
    // Update active class
    sidebarEl.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
    navItem.classList.add('active');
    
    // Render the new view
    renderView(view);
  }
};

// --- Initialization ---
const initialize = () => {
  renderSidebar();
  renderView('home'); // Initial view
  sidebarEl.addEventListener('click', handleNavClick);
};

initialize();
