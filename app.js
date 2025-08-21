// Minimal client-only admin for GitHub Pages.
// Uses: localStorage password gate + GitHub Contents API to read JSON files under `User Database/`.

const config = {
    // Public Pages repo (where admin is hosted)
    public: {
        owner: 'HarleyTG-O',
        repo: 'harleys-flight-bay.',
        branch: 'main',
    },
    // Private data repo (where JSON database lives)
    data: {
        owner: 'HarleyTG-O',
        repo: 'harleys-flight-bay',
        branch: 'main',
    },
    // Optional explicit accounts URL (raw JSON), if set this will be used first
    accountsUrl: 'https://raw.githubusercontent.com/HarleyTG-O/harleys-flight-bay/refs/heads/main/admin/users.json?token=GHSAT0AAAAAADIMPH77DIPXNVDAAE3C3KHI2FGQW4Q',
    dataDir: 'User Database',
    ownerUsername: null,
};

function inferRepoFromLocation() {
    const host = location.host.toLowerCase();
    const path = location.pathname.replace(/^\/+/, '');
    // host like owner.github.io, path like REPO/admin/
    if (host.endsWith('github.io')) {
        const owner = host.split('.')[0];
        const repo = path.split('/')[0] || null;
        if (owner && repo) return { owner, repo };
    }
    return null;
}

function sha256(message) {
    const enc = new TextEncoder();
    return crypto.subtle.digest('SHA-256', enc.encode(message)).then(buf =>
        Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
    );
}

function setText(el, text) { el.textContent = text; }
function $(sel) { return document.querySelector(sel); }

function getSession() {
    try { return JSON.parse(sessionStorage.getItem('hfb_session') || 'null'); } catch { return null; }
}

function setSession(session) {
    sessionStorage.setItem('hfb_session', JSON.stringify(session));
}

function clearSession() { sessionStorage.removeItem('hfb_session'); }

async function isAuthenticated() { return Boolean(getSession()); }

async function loginWithAccount(username, password, users) {
    const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) return false;
    const hash = await sha256(password);
    if (hash !== user.passwordHash) return false;
    setSession({ username: user.username, role: user.role });
    return true;
}

function logout() { clearSession(); }

function ghHeaders() {
    const headers = { 'Accept': 'application/vnd.github.v3+json' };
    // Optional: if you place a token in localStorage (read-only repo token), it will use it to avoid rate limits
    const token = localStorage.getItem('hfb_admin_token');
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
}

async function ghJson(url) {
    const res = await fetch(url, { headers: ghHeaders() });
    if (!res.ok) throw new Error(`GitHub API error ${res.status}`);
    return res.json();
}

// Read a file's content via GitHub Contents API and decode to text
async function ghGetContent(owner, repo, path, ref) {
    const url = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(ref)}`;
    const res = await fetch(url, { headers: ghHeaders() });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`GitHub API error ${res.status}`);
    const meta = await res.json();
    if (!meta.content) return null;
    const binary = atob(meta.content.replace(/\n/g, ''));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    const text = new TextDecoder().decode(bytes);
    return text;
}

// Direct fetch from explicit URL (e.g., raw.githubusercontent.com with token query)
async function fetchAccountsFromUrl(url) {
    const res = await fetch(url, { headers: { 'Accept': 'application/json' } });
    if (!res.ok) throw new Error(`Accounts URL error ${res.status}`);
    return res.json();
}

async function listUserFolders(owner, repo, branch, dataDir) {
    const base = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(dataDir)}?ref=${encodeURIComponent(branch)}`;
    const items = await ghJson(base);
    return items.filter(x => x.type === 'dir').map(x => x.name);
}

async function fetchUserProfile(owner, repo, branch, dataDir, folder) {
    const path = `${dataDir}/${folder}/profile.json`;
    try {
        const text = await ghGetContent(owner, repo, path, branch);
        if (!text) return null;
        return JSON.parse(text);
    } catch (e) {
        console.warn('Failed to fetch profile via API, fallback raw:', path, e);
        const url = `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch)}/${encodeURIComponent(dataDir)}/${encodeURIComponent(folder)}/profile.json`;
        const res = await fetch(url, { headers: { 'Accept': 'application/json' } });
        if (!res.ok) return null;
        return res.json();
    }
}

async function collectAllUsers(owner, repo, branch, dataDir) {
    const folders = await listUserFolders(owner, repo, branch, dataDir);
    const profiles = await Promise.all(
        folders.map(f => fetchUserProfile(owner, repo, branch, dataDir, f).then(p => ({ folder: f, profile: p })))
    );
    return profiles.filter(p => p.profile);
}

// Accounts storage
async function fetchAccounts(owner, repo, branch) {
    const path = `admin/users.json`;
    const text = await ghGetContent(owner, repo, path, branch);
    if (text === null) return { users: [] };
    return JSON.parse(text);
}

async function saveAccounts(owner, repo, branch, accounts, token) {
    if (!token) throw new Error('Missing token: set read/write repo token in localStorage as hfb_admin_token');
    const getUrl = `https://api.github.com/repos/${owner}/${repo}/contents/admin/users.json?ref=${encodeURIComponent(branch)}`;
    const getRes = await fetch(getUrl, { headers: ghHeaders() });
    let sha = null;
    if (getRes.ok) {
        const meta = await getRes.json();
        sha = meta.sha;
    }
    const putUrl = `https://api.github.com/repos/${owner}/${repo}/contents/admin/users.json`;
    const content = btoa(unescape(encodeURIComponent(JSON.stringify(accounts, null, 2))));
    const body = {
        message: 'Update admin users.json via Admin UI',
        content,
        branch,
        sha,
    };
    const res = await fetch(putUrl, { method: 'PUT', headers: ghHeaders(), body: JSON.stringify(body) });
    if (!res.ok) throw new Error(`Failed to save users.json (${res.status})`);
    return res.json();
}

function renderStats(users) {
    const totals = users.reduce((acc, { profile }) => {
        acc.totalUsers += 1;
        acc.totalOrders += profile.total_orders || 0;
        acc.totalCompleted += profile.total_completed || 0;
        acc.totalCancelled += profile.total_cancelled || 0;
        acc.totalSpent += profile.total_spent || 0;
        return acc;
    }, { totalUsers: 0, totalOrders: 0, totalCompleted: 0, totalCancelled: 0, totalSpent: 0 });

    const fmt = new Intl.NumberFormat();
    const statsEl = document.getElementById('stats');
    statsEl.innerHTML = '';
    const entries = [
        ['Users', fmt.format(totals.totalUsers)],
        ['Orders', fmt.format(totals.totalOrders)],
        ['Completed', fmt.format(totals.totalCompleted)],
        ['Total Spent (aUEC)', fmt.format(totals.totalSpent)],
    ];
    for (const [label, value] of entries) {
        const div = document.createElement('div');
        div.className = 'stat';
        div.innerHTML = `<div style="color: var(--muted); font-size: 12px;">${label}</div><div style="font-size: 22px; font-weight: 700;">${value}</div>`;
        statsEl.appendChild(div);
    }
}

function renderTable(users) {
    const tbody = document.querySelector('#users-table tbody');
    tbody.innerHTML = '';

    const fmtDate = (s) => s ? new Date(s).toLocaleString() : '';
    const fmtNum = (n) => (n || n === 0) ? new Intl.NumberFormat().format(n) : '';

    for (const { folder, profile } of users) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${profile.username || ''}</td>
            <td>${profile.user_id || ''}</td>
            <td>${fmtDate(profile.created_at)}</td>
            <td>${fmtNum(profile.total_orders)}</td>
            <td>${fmtNum(profile.total_completed)}</td>
            <td>${fmtNum(profile.total_cancelled)}</td>
            <td>${fmtNum(profile.total_spent)}</td>
            <td>${fmtDate(profile.last_order_completed_at)}</td>
            <td>${profile.last_order_id || ''}</td>
            <td><code>${folder}</code></td>
        `;
        tbody.appendChild(tr);
    }
}

function attachSearch(allUsers) {
    const input = document.getElementById('search');
    function filter() {
        const q = (input.value || '').toLowerCase().trim();
        if (!q) { renderTable(allUsers); return; }
        const res = allUsers.filter(({ folder, profile }) =>
            folder.toLowerCase().includes(q) ||
            String(profile.user_id || '').includes(q) ||
            String(profile.username || '').toLowerCase().includes(q)
        );
        renderTable(res);
    }
    input.addEventListener('input', filter);
}

function exportCSV(rows) {
    const headers = ['username','user_id','created_at','total_orders','total_completed','total_cancelled','total_spent','last_order_completed_at','last_order_id','folder'];
    const lines = [headers.join(',')];
    for (const { folder, profile } of rows) {
        const vals = [
            profile.username,
            profile.user_id,
            profile.created_at,
            profile.total_orders,
            profile.total_completed,
            profile.total_cancelled,
            profile.total_spent,
            profile.last_order_completed_at,
            profile.last_order_id,
            folder,
        ].map(v => v == null ? '' : String(v).replaceAll('"', '""'));
        lines.push(vals.map(v => /[",\n]/.test(v) ? `"${v}"` : v).join(','));
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'hfb-users.csv';
    a.click();
    URL.revokeObjectURL(url);
}

async function main() {
    const inferred = inferRepoFromLocation();
    if (inferred) {
        config.public.owner = config.public.owner || inferred.owner;
        config.public.repo = config.public.repo || inferred.repo;
    }
    // If data repo not configured, default to public repo for convenience
    if (!config.data.owner) config.data.owner = config.public.owner;
    if (!config.data.repo) config.data.repo = config.public.repo;
    const label = document.getElementById('repo-label');
    if (config.data.owner && config.data.repo) setText(label, `${config.data.owner}/${config.data.repo}@${config.data.branch}`);

    const welcomeView = document.getElementById('welcome-view');
    const loginView = document.getElementById('login-view');
    const dashView = document.getElementById('dashboard-view');
    const loginForm = document.getElementById('login-form');
    const loginError = document.getElementById('login-error');
    const usernameInput = document.getElementById('username');

    if (await isAuthenticated()) {
        if (welcomeView) welcomeView.classList.add('hidden');
        loginView.classList.add('hidden');
        dashView.classList.remove('hidden');
    }

    // Token controls
    const tokenInput = document.getElementById('gh-token');
    const saveTokenBtn = document.getElementById('save-token');
    const clearTokenBtn = document.getElementById('clear-token');
    if (tokenInput && saveTokenBtn && clearTokenBtn) {
        const existing = localStorage.getItem('hfb_admin_token');
        if (existing) tokenInput.value = existing;
        saveTokenBtn.addEventListener('click', () => {
            localStorage.setItem('hfb_admin_token', tokenInput.value.trim());
            alert('Token saved locally.');
        });
        clearTokenBtn.addEventListener('click', () => {
            localStorage.removeItem('hfb_admin_token');
            tokenInput.value = '';
            alert('Token cleared.');
        });
    }

    // Welcome → Login transition
    const goToLogin = document.getElementById('go-to-login');
    if (goToLogin) {
        goToLogin.addEventListener('click', () => {
            if (welcomeView) welcomeView.classList.add('hidden');
            loginView.classList.remove('hidden');
        });
    }

    // Preload accounts for login (try explicit URL, then private repo, then public fallback)
    let accounts = { users: [] };
    if (config.accountsUrl) {
        try { accounts = await fetchAccountsFromUrl(config.accountsUrl); } catch (e) { console.warn('accounts (url) error:', e); }
    }
    if (!accounts.users || accounts.users.length === 0) {
        try { accounts = await fetchAccounts(config.data.owner, config.data.repo, config.data.branch); } catch (e) { console.warn('accounts (private) error:', e); }
    }
    if (!accounts.users || accounts.users.length === 0) {
        try { accounts = await fetchAccounts(config.public.owner, config.public.repo, config.public.branch); } catch (e) { console.warn('accounts (public) error:', e); }
    }

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loginError.textContent = '';
        const username = usernameInput.value.trim();
        const password = document.getElementById('password').value;
        const ok = await loginWithAccount(username, password, accounts.users);
        if (!ok) {
            loginError.textContent = 'Invalid password.';
            return;
        }
        if (welcomeView) welcomeView.classList.add('hidden');
        loginView.classList.add('hidden');
        dashView.classList.remove('hidden');
        initDashboard(accounts);
    });

    document.getElementById('logout').addEventListener('click', () => { logout(); location.reload(); });
    document.getElementById('export-csv').addEventListener('click', () => exportCSV(window.__ALL_USERS__ || []));

    if (welcomeView && !welcomeView.classList.contains('hidden')) return; // still on welcome
    if (!loginView.classList.contains('hidden')) return; // still on login
    await initDashboard(accounts);
}

async function initDashboard(preloadedAccounts) {
    try {
        if (!config.data.owner || !config.data.repo) {
            throw new Error('Repo not set. Set config.owner and config.repo in admin/app.js or host on GitHub Pages under OWNER.github.io/REPO');
        }
        const session = getSession();
        const role = session?.role || 'support';
        // Load accounts if not provided
        let accounts = preloadedAccounts;
        if (!accounts) {
            if (config.accountsUrl) {
                try { accounts = await fetchAccountsFromUrl(config.accountsUrl); } catch (e) { console.warn('accounts (url) error:', e); }
            }
            if (!accounts || !accounts.users || accounts.users.length === 0) {
                try { accounts = await fetchAccounts(config.data.owner, config.data.repo, config.data.branch); } catch (e) { console.warn('accounts (private) error:', e); }
            }
            if (!accounts || !accounts.users || accounts.users.length === 0) {
                try { accounts = await fetchAccounts(config.public.owner, config.public.repo, config.public.branch); } catch (e) { console.warn('accounts (public) error:', e); }
            }
        }
        setupUserAdminUI(accounts, role);
        const allUsers = await collectAllUsers(config.data.owner, config.data.repo, config.data.branch, config.dataDir);
        window.__ALL_USERS__ = allUsers;
        renderStats(allUsers);
        renderTable(allUsers);
        attachSearch(allUsers);
    } catch (err) {
        alert('Failed to load users: ' + err.message);
        console.error(err);
    }
}

function setupUserAdminUI(accounts, role) {
    const section = document.getElementById('user-admin');
    if (!section) return;
    if (role !== 'admin' && role !== 'owner') { section.classList.add('hidden'); return; }
    section.classList.remove('hidden');

    // Render table
    const tbody = document.querySelector('#users-admin-table tbody');
    function render() {
        tbody.innerHTML = '';
        for (const u of accounts.users) {
            const tr = document.createElement('tr');
            tr.innerHTML = `<td>${u.username}</td><td>${u.role}</td>`;
            tbody.appendChild(tr);
        }
    }
    render();

    const form = document.getElementById('add-user-form');
    const errEl = document.getElementById('user-admin-error');
    const okEl = document.getElementById('user-admin-success');
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        errEl.textContent = '';
        okEl.textContent = '';
        const username = document.getElementById('new-username').value.trim();
        const role = document.getElementById('new-role').value;
        const pw1 = document.getElementById('new-password').value;
        const pw2 = document.getElementById('new-password2').value;
        if (!username || !pw1 || !pw2) { errEl.textContent = 'All fields are required.'; return; }
        if (pw1 !== pw2) { errEl.textContent = 'Passwords do not match.'; return; }
        if (accounts.users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
            errEl.textContent = 'Username already exists.'; return;
        }
        const passwordHash = await sha256(pw1);
        accounts.users.push({ username, role, passwordHash });
        try {
            const token = localStorage.getItem('hfb_admin_token');
            await saveAccounts(config.data.owner, config.data.repo, config.data.branch, accounts, token);
            okEl.textContent = 'User added and saved to repo.';
            render();
            form.reset();
        } catch (err) {
            console.error(err);
            okEl.textContent = '';
            errEl.textContent = 'Saved locally, but failed to write to repo: ' + err.message;
            render();
        }
    });
}

main();


