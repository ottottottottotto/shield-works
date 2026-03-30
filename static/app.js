document.addEventListener('DOMContentLoaded', () => {

    // --- STATE MANAGEMENT ---
    const State = {
        currentUser: localStorage.getItem('shieldworks_user') || null,
        currentView: 'overview',
        scans: [],
        isScanning: false
    };

    // --- AUTHENTICATION & WELCOME ANIMATION ---
    const authOverlay = document.getElementById('auth-overlay');
    const authFormsContainer = document.getElementById('auth-forms-container');
    const loginView = document.getElementById('login-view');
    const signupView = document.getElementById('signup-view');
    const mainApp = document.getElementById('main-app');
    const landingHero = document.getElementById('landing-hero');
    const welcomeSeq = document.getElementById('welcome-sequence');
    const switchToSignup = document.getElementById('switch-to-signup');
    if (switchToSignup) {
        switchToSignup.addEventListener('click', (e) => {
            e.preventDefault();
            loginView.classList.replace('active-form', 'hidden');
            signupView.classList.replace('hidden', 'active-form');
        });
    }
    const switchToLogin = document.getElementById('switch-to-login');
    if (switchToLogin) {
        switchToLogin.addEventListener('click', (e) => {
            e.preventDefault();
            signupView.classList.replace('active-form', 'hidden');
            loginView.classList.replace('hidden', 'active-form');
        });
    }

    // Step 1: After 2s, kill splash and show landing page
    setTimeout(() => {
        if (welcomeSeq) welcomeSeq.style.display = 'none';
        if (landingHero) {
            landingHero.style.display = 'flex';
            setTimeout(() => { landingHero.style.opacity = '1'; }, 50);
        }
    }, 2000);

    // Step 2: "Get Started" button shows login form
    const startBtn = document.getElementById('start-discovery-btn');
    if (startBtn) {
        startBtn.addEventListener('click', () => {
            if (authFormsContainer) {
                authFormsContainer.style.display = 'flex';
            }
        });
    }


    // Form Submissions
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const u = document.getElementById('login-username').value;
            const p = document.getElementById('login-password').value;
            const err = document.getElementById('login-error');
            err.classList.add('hidden');
            
            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username: u, password: p})
                });
                const data = await res.json();
                if (!res.ok) throw new Error();
                State.currentUser = data.username;
                localStorage.setItem('shieldworks_user', data.username);
                await fetchUserScans();
                unlockDashboard();
            } catch {
                err.classList.remove('hidden');
                err.textContent = "Unable to connect to server backend.";
            }
        });
    }

    const signupForm = document.getElementById('signup-form');
    if (signupForm) {
        signupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const u = document.getElementById('signup-username').value;
            const p = document.getElementById('signup-password').value;
            const r = document.getElementById('signup-role').value;
            const err = document.getElementById('signup-error');
            err.classList.add('hidden');
            
            try {
                const res = await fetch('/api/auth/signup', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username: u, password: p, role: r})
                });
                const data = await res.json();
                if (!res.ok) throw new Error();
                State.currentUser = data.username;
                localStorage.setItem('shieldworks_user', data.username);
                await fetchUserScans();
                unlockDashboard();
            } catch {
                err.classList.remove('hidden');
            }
        });
    }


    function unlockDashboard(skipAnim = false) {
        if (!authOverlay) return;
        
        if (skipAnim) {
            authOverlay.style.display = 'none';
            if (landingHero) landingHero.style.display = 'none';
            if (welcomeSeq) welcomeSeq.style.display = 'none';
            if (mainApp) {
                mainApp.style.display = 'flex';
                mainApp.style.opacity = '1';
                mainApp.style.pointerEvents = 'auto';
            }
        } else {
            authOverlay.classList.add('fade-out');
            
            // Also fade out the landing specific content
            const landing = document.getElementById('landing-hero');
            if (landing) landing.style.opacity = '0';

            setTimeout(() => {
                authOverlay.style.display = 'none';
                if (mainApp) {
                    mainApp.style.display = 'flex';
                    requestAnimationFrame(() => {
                        requestAnimationFrame(() => {
                            mainApp.style.opacity = '1';
                            mainApp.style.pointerEvents = 'auto';
                        });
                    });
                }
            }, 1000);
        }
    }
    
    // --- DOM ELEMENTS ---
    const elements = {
        navItems: document.querySelectorAll('.nav-item, .mobile-nav-item'),
        views: document.querySelectorAll('.view'),
        tabBtns: document.querySelectorAll('.tab-btn'),
        tabContents: document.querySelectorAll('.tab-content'),
        
        // Forms
        forms: {
            url: document.getElementById('url-form'),
            github: document.getElementById('github-form'),
            local: document.getElementById('local-form'),
            software: document.getElementById('software-form')
        },
        
        // Stats
        stats: {
            totalScans: document.getElementById('stat-total-scans'),
            avgScore: document.getElementById('stat-avg-score'),
            criticalCount: document.getElementById('stat-critical-count'),
            recentList: document.getElementById('recent-scans-list')
        },
        
        // History
        historyList: document.getElementById('history-list'),
        clearHistoryBtn: document.getElementById('clear-history-btn'),
        
        // Results & Scan Flow
        viewResults: document.getElementById('view-results'),
        viewLoading: document.getElementById('view-loading'),
        inputSection: document.getElementById('input-section'),
        newScanBtn: document.getElementById('new-scan-btn'),
        downloadPdfBtn: document.getElementById('download-pdf-btn'),
        advisorModal: document.getElementById('advisor-modal'),
        closeAdvisorBtn: document.getElementById('close-advisor-btn')
    };

    // Initialization flow
    init();

    // Session persistence check: If already logged in, skip splash and show dashboard
    if (State.currentUser) {
        unlockDashboard(true); // true means skip animation
    }

    // --- INITIALIZATION ---
    async function init() {
        setupNavigation();
        setupForms();
        setupThemeSettings();
        checkApiStatus();
        
        if (State.currentUser) {
            await fetchUserScans();
        }
        
        handleInitialView();
    }

    async function fetchUserScans() {
        if (!State.currentUser) return;
        try {
            const res = await fetch(`/api/scans/${State.currentUser}`);
            if (res.ok) {
                const rawScans = await res.json();
                // Ensure severity_counts exists for every scan
                State.scans = rawScans.map(s => {
                    if (!s.severity_counts) {
                        const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
                        (s.findings || []).forEach(f => {
                            if (counts[f.severity] !== undefined) counts[f.severity]++;
                        });
                        return { ...s, severity_counts: counts };
                    }
                    return s;
                });
                updateDashboardMetrics();
                if (State.currentView === 'history') renderHistory();
            }
        } catch (e) {
            console.error("Failed to fetch scans", e);
        }
    }

    function setupThemeSettings() {
        const themeWheel = document.getElementById('theme-color-wheel');
        const presets = document.querySelectorAll('.preset-btn');
        const savedColor = localStorage.getItem('shieldworks_theme_color') || '#38bdf8';

        applyThemeColor(savedColor);
        if (themeWheel) themeWheel.value = savedColor;

        if (themeWheel) {
            themeWheel.addEventListener('input', (e) => {
                applyThemeColor(e.target.value);
            });
        }

        presets.forEach(btn => {
            btn.addEventListener('click', () => {
                const color = btn.getAttribute('data-color');
                applyThemeColor(color);
                if (themeWheel) themeWheel.value = color;
            });
        });
    }

    function applyThemeColor(color) {
        document.documentElement.style.setProperty('--primary-blue', color);
        localStorage.setItem('shieldworks_theme_color', color);
    }

    // --- NAVIGATION LOGIC ---
    function setupNavigation() {
        elements.navItems.forEach(item => {
            item.addEventListener('click', () => {
                const viewId = item.dataset.view;
                switchView(viewId);
            });
        });

        // Sub-tabs (New Scan section)
        elements.tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                elements.tabBtns.forEach(b => b.classList.remove('active'));
                elements.tabContents.forEach(c => {
                    c.classList.remove('active');
                    c.classList.add('hidden');
                });
                
                btn.classList.add('active');
                const target = document.getElementById(btn.dataset.target);
                target.classList.remove('hidden');
                target.classList.add('active');
            });
        });

        elements.newScanBtn.addEventListener('click', () => {
            resetScanUI();
        });
        
        if (elements.clearHistoryBtn) {
            elements.clearHistoryBtn.addEventListener('click', clearHistory);
        }

        if (elements.downloadPdfBtn) {
            elements.downloadPdfBtn.addEventListener('click', () => {
                window.print();
            });
        }

        if (elements.closeAdvisorBtn) {
            elements.closeAdvisorBtn.addEventListener('click', () => {
                elements.advisorModal.classList.remove('active');
                setTimeout(() => elements.advisorModal.classList.add('hidden'), 400);
            });
        }
    }

    function switchView(viewId) {
        State.currentView = viewId;
        
        // Update Sidebars and Mobile Navs
        elements.navItems.forEach(item => {
            item.classList.toggle('active', item.dataset.view === viewId);
        });

        // Update View Visibility
        elements.views.forEach(view => {
            view.classList.toggle('active', view.id === `view-${viewId}`);
            view.classList.toggle('hidden', view.id !== `view-${viewId}`);
        });

        if (viewId === 'overview') updateDashboardMetrics();
        if (viewId === 'history') renderHistory();
    }

    function handleInitialView() {
        switchView('overview');
    }

    // --- FORM HANDLING ---
    function setupForms() {
        elements.forms.url.addEventListener('submit', (e) => {
            e.preventDefault();
            runScan('/api/scan/url', { url: document.getElementById('url-input').value });
        });

        elements.forms.github.addEventListener('submit', (e) => {
            e.preventDefault();
            runScan('/api/scan/github', { repo_url: document.getElementById('repo-input').value });
        });

        elements.forms.local.addEventListener('submit', (e) => {
            e.preventDefault();
            runScan('/api/scan/local', { directory: document.getElementById('local-path').value });
        });

        if (elements.forms.software) {
            elements.forms.software.addEventListener('submit', (e) => {
                e.preventDefault();
                const fileInput = document.getElementById('software-file');
                if (!fileInput || fileInput.files.length === 0) return;
                
                const formData = new FormData();
                formData.append('file', fileInput.files[0]);
                
                runFileScan('/api/scan/software', formData);
            });
            
            // File Drag & Drop UI Setup
            const dropZone = document.getElementById('file-drop-zone');
            const fileInput = document.getElementById('software-file');
            const label = document.getElementById('upload-label');
            
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, preventDefaults, false);
            });

            function preventDefaults(e) {
                e.preventDefault();
                e.stopPropagation();
            }

            ['dragenter', 'dragover'].forEach(eventName => {
                dropZone.addEventListener(eventName, () => dropZone.classList.add('drag-active'), false);
            });

            ['dragleave', 'drop'].forEach(eventName => {
                dropZone.addEventListener(eventName, () => dropZone.classList.remove('drag-active'), false);
            });

            dropZone.addEventListener('drop', (e) => {
                const dt = e.dataTransfer;
                const files = dt.files;
                if(files && files.length) {
                    fileInput.files = files;
                    updateFileLabel(files[0].name);
                }
            }, false);
            
            fileInput.addEventListener('change', function() {
                if (this.files && this.files.length > 0) {
                    updateFileLabel(this.files[0].name);
                }
            });

            function updateFileLabel(name) {
                const textSpan = label.querySelector('.upload-text');
                textSpan.innerHTML = `<span style="color:var(--primary-blue);font-weight:bold;">${name}</span> selected.`;
            }
        }
    }

    // --- CORE SCAN LOGIC ---
    async function runScan(endpoint, payload) {
        if (!State.currentUser) return;
        switchView('loading');
        
        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail || 'Scan failed');

            await saveScanToHistory(data);
            renderResults(data);
            switchView('results');
            setTimeout(() => showAdvisorModal(data), 1500);

        } catch (error) {
            alert(`Error:\n${error.message}`);
            switchView('new-scan');
        }
    }

    async function runFileScan(endpoint, formData) {
        if (!State.currentUser) return;
        switchView('loading');

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                body: formData
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail || 'File analysis failed');

            await saveScanToHistory(data);
            renderResults(data);
            switchView('results');
            setTimeout(() => showAdvisorModal(data), 1500);

        } catch (error) {
            alert(`Error:\n${error.message}`);
            switchView('new-scan');
        }
    }

    // --- PERSISTENCE ---
    async function saveScanToHistory(scanData) {
        if (!State.currentUser) return;
        
        try {
            await fetch('/api/scans', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: State.currentUser,
                    target: scanData.target,
                    scan_type: scanData.scan_type,
                    score: scanData.score,
                    findings: JSON.stringify(scanData.findings),
                    scanned_at: scanData.scanned_at
                })
            });
            // Refresh local state
            await fetchUserScans();
        } catch (e) {
            console.error("Failed to persist scan", e);
        }
    }

    async function clearHistory() {
        if (!State.currentUser) return;
        if (confirm('Are you sure you want to delete all scan records? This cannot be undone.')) {
            try {
                const res = await fetch(`/api/scans/${State.currentUser}`, { method: 'DELETE' });
                if (res.ok) {
                    State.scans = [];
                    renderHistory();
                    updateDashboardMetrics();
                } else {
                    alert('Backend failed to clear history.');
                }
            } catch (e) {
                console.error("Failed to clear history", e);
            }
        }
    }

    // --- RENDERING ---
    function renderResults(data) {
        // Since switchView handles visibility, we just populate data here
        // Header Population
        document.getElementById('scan-target').textContent = data.target;
        document.getElementById('scan-time').textContent = new Date(data.scanned_at).toLocaleString();

        // Score Wheel Animation
        const score = data.score;
        let color = "var(--info)";
        if (score < 50) color = "var(--critical)";
        else if (score < 75) color = "var(--medium)";
        else if (score < 90) color = "var(--low)";
        
        const circle = document.querySelector('.progress-ring__circle.fg');
        const radius = circle.r.baseVal.value;
        const circumference = radius * 2 * Math.PI;
        
        circle.style.strokeDasharray = `${circumference} ${circumference}`;
        circle.style.stroke = color;

        // Animate counting up
        let startScore = 0;
        const scoreEl = document.getElementById('score-number');
        scoreEl.textContent = "0";
        
        const duration = 1000;
        const step = score / (duration / 16); // 60fps approx
        
        function animate() {
            startScore += step;
            if (startScore >= score) {
                startScore = score;
                scoreEl.textContent = Math.round(startScore);
                const offset = circumference - (startScore / 100) * circumference;
                circle.style.strokeDashoffset = offset;
                return;
            }
            scoreEl.textContent = Math.round(startScore);
            const offset = circumference - (startScore / 100) * circumference;
            circle.style.strokeDashoffset = offset;
            requestAnimationFrame(animate);
        }
        animate();

        // Badges
        document.getElementById('count-critical').textContent = data.severity_counts.critical;
        document.getElementById('count-high').textContent = data.severity_counts.high;
        document.getElementById('count-medium').textContent = data.severity_counts.medium;
        document.getElementById('count-low').textContent = data.severity_counts.low;
        document.getElementById('count-info').textContent = data.severity_counts.info;

        // List Population
        const list = document.getElementById('findings-list');
        list.innerHTML = '';

        data.findings.forEach((finding, index) => {
            const card = document.createElement('div');
            card.className = `finding-card ${finding.severity}`;
            card.style.animationDelay = `${index * 0.05}s`;
            
            card.innerHTML = `
                <div class="finding-header">
                    <span class="finding-title">${finding.title}</span>
                    <span class="finding-category">${finding.category}</span>
                </div>
                <div class="finding-desc">${finding.description}</div>
                <div class="finding-rec">💡 <strong>Fix:</strong> ${finding.recommendation}</div>
            `;
            list.appendChild(card);
        });
    }

    function showAdvisorModal(data) {
        const modal = elements.advisorModal;
        const iconEl = document.getElementById('advisor-icon');
        const titleEl = document.getElementById('advisor-title');
        const textEl = document.getElementById('advisor-text');
        const priorityEl = document.getElementById('advisor-priority-text');
        
        const score = data.score;
        let advice, icon, title, priority;

        if (score < 50) {
            icon = '🚨'; title = 'Critical Security Alert';
            advice = 'Your system has severe vulnerabilities that require immediate attention. Access should be restricted until patched.';
        } else if (score < 75) {
            icon = '⚠️'; title = 'Security Warnings';
            advice = 'Several security gaps were detected. While not immediately exploitable by all, they represent significant risk.';
        } else if (score < 90) {
            icon = '🛡️'; title = 'Good Protection';
            advice = 'Your security posture is strong. Implementing the remaining recommendations will bring you to elite status.';
        } else {
            icon = '✅'; title = 'Elite Security';
            advice = 'Excellent configuration! Your perimeter follows industry best practices for modern security standards.';
        }

        // Find top priority fix (highest severity finding)
        const topFinding = data.findings.find(f => f.severity === 'critical') || 
                           data.findings.find(f => f.severity === 'high') || 
                           data.findings[0];
        
        priority = topFinding ? topFinding.recommendation : 'No urgent threats detected.';

        iconEl.textContent = icon;
        titleEl.textContent = title;
        textEl.textContent = advice;
        priorityEl.textContent = priority;

        modal.classList.remove('hidden');
        setTimeout(() => modal.classList.add('active'), 10);
    }

    function updateDashboardMetrics() {
        const scans = State.scans;
        elements.stats.totalScans.textContent = scans.length;
        
        if (scans.length > 0) {
            const avg = Math.round(scans.reduce((acc, s) => acc + s.score, 0) / scans.length);
            elements.stats.avgScore.textContent = `${avg}%`;
            
            const criticals = scans.reduce((acc, s) => acc + (s.severity_counts?.critical || 0), 0);
            elements.stats.criticalCount.textContent = criticals;
            elements.stats.criticalCount.classList.toggle('danger', criticals > 0);
        } else {
            elements.stats.avgScore.textContent = '0%';
            elements.stats.criticalCount.textContent = '0';
        }

        // Recent Activity Feed
        elements.stats.recentList.innerHTML = '';
        if (scans.length === 0) {
            elements.stats.recentList.innerHTML = '<p class="empty-msg">No recent activity detected.</p>';
        } else {
            scans.slice(0, 5).forEach(scan => {
                const item = document.createElement('div');
                item.className = 'activity-item clickable';
                item.innerHTML = `
                    <div class="activity-icon ${scan.score >= 80 ? 'good' : 'bad'}"></div>
                    <div class="activity-info">
                        <span class="activity-title">${scan.target}</span>
                        <span class="activity-meta">${new Date(scan.scanned_at).toLocaleDateString()} • Score: ${scan.score}%</span>
                    </div>
                `;
                item.onclick = () => {
                    switchView('new-scan');
                    setTimeout(() => renderResults(scan), 100);
                };
                elements.stats.recentList.appendChild(item);
            });
        }
    }

    function renderHistory() {
        elements.historyList.innerHTML = '';
        if (State.scans.length === 0) {
            elements.historyList.innerHTML = '<div class="glass-card" style="grid-column: 1/-1; text-align: center;">No scan history found. Start a new scan to see results here.</div>';
            return;
        }

        State.scans.forEach(scan => {
            const card = document.createElement('div');
            card.className = 'history-card clay';
            card.innerHTML = `
                <div class="history-card-header">
                    <span class="history-type">${scan.scan_type.toUpperCase()}</span>
                    <span class="history-score ${getScoreClass(scan.score)}">${scan.score}%</span>
                </div>
                <h4 class="history-target">${scan.target}</h4>
                <div class="history-meta">
                    <span>${new Date(scan.scanned_at).toLocaleDateString()}</span>
                    <span>${scan.findings.length} findings</span>
                </div>
            `;
            card.onclick = () => {
                switchView('new-scan');
                setTimeout(() => renderResults(scan), 100);
            };
            elements.historyList.appendChild(card);
        });
    }

    function getScoreClass(score) {
        if (score < 50) return 'critical';
        if (score < 75) return 'medium';
        if (score < 90) return 'low';
        return 'info';
    }

    async function checkApiStatus() {
        const widget = document.getElementById('api-status-widget');
        if (!widget) return;
        try {
            const resp = await fetch('/api/status');
            const data = await resp.json();
            if (data.status === 'online') {
                widget.querySelector('.status-dot').style.background = '#10b981';
                widget.querySelector('.status-text').textContent = 'Scanner Online';
            }
        } catch (e) {
            if (widget.querySelector('.status-dot')) widget.querySelector('.status-dot').style.background = '#ef4444';
            if (widget.querySelector('.status-text')) widget.querySelector('.status-text').textContent = 'Scanner Offline';
        }
    }

    function resetScanUI() {
        switchView('new-scan');
        
        // Reset inputs safely
        const urlInput = document.getElementById('url-input');
        const repoInput = document.getElementById('repo-input');
        const localPath = document.getElementById('local-path');
        const softwareFile = document.getElementById('software-file');
        if (urlInput) urlInput.value = '';
        if (repoInput) repoInput.value = '';
        if (localPath) localPath.value = '';
        if (softwareFile) {
            softwareFile.value = '';
            const uploadText = document.querySelector('#upload-label .upload-text');
            if (uploadText) uploadText.innerHTML = `Drag & Drop your binary file here<br/>or <span class="browse-link" style="color: var(--primary-blue); font-weight: bold; cursor: pointer;">Browse Local Files</span>`;
        }
    }

    // Run init 
});
