// ============================================
// Family Bank — Application Logic
// ============================================

import { auth, db } from './firebase-config.js';
import {
    onAuthStateChanged,
    signInWithEmailAndPassword,
    createUserWithEmailAndPassword,
    sendEmailVerification,
    signOut
} from "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";
import {
    doc, getDoc, setDoc, updateDoc, getDocs, deleteDoc,
    collection, query, where, orderBy, limit,
    runTransaction, addDoc, serverTimestamp, Timestamp
} from "https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js";

// ============================================
// UTILITY HELPERS
// ============================================

const PAGE = (() => {
    const p = window.location.pathname;
    if (p.includes('admin')) return 'admin';
    if (p.includes('dashboard')) return 'dashboard';
    return 'index';
})();

// Pure JS SHA-256 (no crypto.subtle needed — works on plain HTTP)
function sha256(message) {
    function rr(n, x) { return (x >>> n) | (x << (32 - n)); }
    function ch(x, y, z) { return (x & y) ^ (~x & z); }
    function maj(x, y, z) { return (x & y) ^ (x & z) ^ (y & z); }
    function s0(x) { return rr(2, x) ^ rr(13, x) ^ rr(22, x); }
    function s1(x) { return rr(6, x) ^ rr(11, x) ^ rr(25, x); }
    function g0(x) { return rr(7, x) ^ rr(18, x) ^ (x >>> 3); }
    function g1(x) { return rr(17, x) ^ rr(19, x) ^ (x >>> 10); }
    const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    const bytes = new TextEncoder().encode(message);
    const len = bytes.length;
    const bitLen = len * 8;
    const padded = new Uint8Array(((len + 9 + 63) & ~63));
    padded.set(bytes);
    padded[len] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 4, bitLen, false);
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a, h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    for (let off = 0; off < padded.length; off += 64) {
        const w = new Array(64);
        for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
        for (let i = 16; i < 64; i++) w[i] = (g1(w[i - 2]) + w[i - 7] + g0(w[i - 15]) + w[i - 16]) | 0;
        let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
        for (let i = 0; i < 64; i++) {
            const t1 = (h + s1(e) + ch(e, f, g) + K[i] + w[i]) | 0;
            const t2 = (s0(a) + maj(a, b, c)) | 0;
            h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
        }
        h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
    }
    return [h0, h1, h2, h3, h4, h5, h6, h7].map(v => (v >>> 0).toString(16).padStart(8, '0')).join('');
}

// Toast notifications
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const icons = { success: '✅', danger: '❌', warning: '⚠️', info: 'ℹ️' };
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <span class="toast-message">${message}</span>
        <button class="toast-close" onclick="this.parentElement.classList.add('toast-out');setTimeout(()=>this.parentElement.remove(),300)">✕</button>
    `;
    container.appendChild(toast);
    setTimeout(() => {
        toast.classList.add('toast-out');
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// Loading overlay
function showLoading(text = 'Loading...') {
    const el = document.getElementById('loadingOverlay');
    if (el) { el.classList.remove('hidden'); const t = el.querySelector('.loading-text, #loadingText'); if (t) t.textContent = text; }
}
function hideLoading() {
    const el = document.getElementById('loadingOverlay');
    if (el) el.classList.add('hidden');
}

// Format currency
function fmtCurrency(amount) {
    return 'Rs. ' + Number(amount || 0).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

// Format date
function fmtDate(ts) {
    if (!ts) return '—';
    const d = ts.toDate ? ts.toDate() : new Date(ts);
    return d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }) + ' ' +
        d.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
}

// Get PIN from pin-input-group
function getPinFromGroup(containerId) {
    const inputs = document.querySelectorAll(`#${containerId} .pin-input`);
    let pin = '';
    inputs.forEach(i => pin += i.value);
    return pin;
}

// Clear PIN inputs
function clearPinGroup(containerId) {
    const inputs = document.querySelectorAll(`#${containerId} .pin-input`);
    inputs.forEach(i => { i.value = ''; });
    if (inputs[0]) inputs[0].focus();
}

// Setup PIN input auto-advance
function setupPinInputs(containerId) {
    const inputs = document.querySelectorAll(`#${containerId} .pin-input`);
    inputs.forEach((input, idx) => {
        input.addEventListener('input', () => {
            if (input.value.length === 1 && idx < inputs.length - 1) inputs[idx + 1].focus();
        });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && !input.value && idx > 0) inputs[idx - 1].focus();
        });
    });
}

// Device ID
function getDeviceId() {
    let id = localStorage.getItem('fb_device_id');
    if (!id) {
        // Pure JS UUID v4 — works without secure context
        id = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
            const r = Math.random() * 16 | 0;
            return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
        });
        localStorage.setItem('fb_device_id', id);
    }
    return id;
}

// ============================================
// THEME TOGGLE
// ============================================

function initTheme() {
    const saved = localStorage.getItem('fb_theme');
    if (saved === 'light') document.body.classList.add('light-theme');
    updateThemeLabel();
}

function toggleTheme() {
    document.body.classList.toggle('light-theme');
    localStorage.setItem('fb_theme', document.body.classList.contains('light-theme') ? 'light' : 'dark');
    updateThemeLabel();
}

function updateThemeLabel() {
    const isLight = document.body.classList.contains('light-theme');
    const label = document.getElementById('themeLabel');
    if (label) label.textContent = isLight ? 'Dark Mode' : 'Light Mode';
    const icon = document.querySelector('#themeToggleNav .nav-icon');
    if (icon) icon.textContent = isLight ? '🌙' : '☀️';
}

// ============================================
// SIDEBAR NAVIGATION
// ============================================

function initSidebar() {
    document.querySelectorAll('[data-section]').forEach(btn => {
        btn.addEventListener('click', () => {
            const section = btn.getAttribute('data-section');
            switchSection(section);
            closeMobileSidebar();
        });
    });

    const toggle = document.getElementById('menuToggle');
    const overlay = document.getElementById('sidebarOverlay');
    if (toggle) toggle.addEventListener('click', () => {
        document.getElementById('sidebar')?.classList.toggle('open');
        overlay?.classList.toggle('active');
    });
    if (overlay) overlay.addEventListener('click', closeMobileSidebar);

    const themeNav = document.getElementById('themeToggleNav');
    if (themeNav) themeNav.addEventListener('click', toggleTheme);

    const logoutNav = document.getElementById('logoutNav');
    if (logoutNav) logoutNav.addEventListener('click', async () => { await signOut(auth); window.location.href = 'index.html'; });
}

function switchSection(name) {
    document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
    const target = document.getElementById('section-' + name);
    if (target) target.classList.add('active');
    document.querySelectorAll('.nav-item[data-section]').forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('data-section') === name);
    });
    if (name === 'all-users' && PAGE === 'admin') loadAllUsers();
    if (name === 'all-transactions' && PAGE === 'admin') loadAdminTransactions();
    if (name === 'overview' && PAGE === 'admin') loadAdminOverview();
    if (name === 'interest' && PAGE === 'admin') loadInterestSettings();
    if (name === 'new-account' && PAGE === 'admin') generateNextAccountNumber();
    if (name === 'transactions' && PAGE === 'dashboard') loadUserTransactions();
}

function closeMobileSidebar() {
    document.getElementById('sidebar')?.classList.remove('open');
    document.getElementById('sidebarOverlay')?.classList.remove('active');
}

// ============================================
// INACTIVITY AUTO-LOGOUT (20 min)
// ============================================

let inactivityTimer = null;
let countdownTimer = null;
const INACTIVITY_LIMIT = 20 * 60 * 1000;
const COUNTDOWN_START = 60;

function initInactivityTimer() {
    if (PAGE === 'index') return;
    resetInactivityTimer();
    ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach(evt => {
        document.addEventListener(evt, resetInactivityTimer, { passive: true });
    });
    const stayBtn = document.getElementById('stayActiveBtn');
    if (stayBtn) stayBtn.addEventListener('click', resetInactivityTimer);
}

function resetInactivityTimer() {
    const bar = document.getElementById('inactivityBar');
    if (bar) bar.classList.add('hidden');
    if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }
    if (inactivityTimer) clearTimeout(inactivityTimer);
    inactivityTimer = setTimeout(startInactivityCountdown, INACTIVITY_LIMIT - COUNTDOWN_START * 1000);
}

function startInactivityCountdown() {
    let remaining = COUNTDOWN_START;
    const bar = document.getElementById('inactivityBar');
    const span = document.getElementById('inactivityCountdown');
    if (bar) bar.classList.remove('hidden');
    if (span) span.textContent = remaining;
    countdownTimer = setInterval(async () => {
        remaining--;
        if (span) span.textContent = remaining;
        if (remaining <= 0) {
            clearInterval(countdownTimer);
            await signOut(auth);
            window.location.href = 'index.html';
        }
    }, 1000);
}

// ============================================
// CURRENT USER DATA
// ============================================

let currentUser = null;
let currentUserDoc = null;

// FIX: Query by uid field instead of using document ID,
// because admin-created member docs have auto-generated IDs
async function loadCurrentUserDoc(uid) {
    // First try direct document ID (works for admin, whose doc ID = uid)
    const directSnap = await getDoc(doc(db, 'users', uid));
    if (directSnap.exists()) {
        currentUserDoc = { id: directSnap.id, ...directSnap.data() };
        return currentUserDoc;
    }
    // Fallback: query by uid field (for members whose doc ID ≠ uid)
    const q = query(collection(db, 'users'), where('uid', '==', uid));
    const snap = await getDocs(q);
    if (!snap.empty) {
        const d = snap.docs[0];
        currentUserDoc = { id: d.id, ...d.data() };
        return currentUserDoc;
    }
    currentUserDoc = null;
    return null;
}

// ============================================
// AUTH STATE HANDLER
// ============================================

onAuthStateChanged(auth, async (user) => {
    if (PAGE === 'index') {
        hideLoading();
        if (user && user.emailVerified) {
            const uDoc = await loadCurrentUserDoc(user.uid);
            if (uDoc && uDoc.isSetupComplete && uDoc.isActive) {
                const deviceId = getDeviceId();
                if (uDoc.approvedDevices && uDoc.approvedDevices.includes(deviceId)) {
                    showLpinView();
                } else {
                    showDeviceVerifyView();
                }
            } else if (uDoc && uDoc.isSetupComplete && !uDoc.isActive) {
                showToast('Your account has been frozen. Contact admin.', 'danger');
                await signOut(auth);
            }
        }
        return;
    }

    // Dashboard / Admin pages
    if (!user) { window.location.href = 'index.html'; return; }

    currentUser = user;
    const uDoc = await loadCurrentUserDoc(user.uid);

    if (!uDoc || !uDoc.isSetupComplete) { window.location.href = 'index.html'; return; }
    if (!uDoc.isActive) {
        showToast('Account frozen. Contact admin.', 'danger');
        await signOut(auth);
        window.location.href = 'index.html';
        return;
    }
    if (!user.emailVerified) {
        showToast('Please verify your email first.', 'warning');
        await signOut(auth);
        window.location.href = 'index.html';
        return;
    }

    if (PAGE === 'admin') {
        if (uDoc.role !== 'admin') { window.location.href = 'dashboard.html'; return; }
        initAdminPage();
    } else {
        initDashboardPage();
    }
});

// ============================================
// INDEX PAGE — LOGIN FLOW
// ============================================

if (PAGE === 'index') {
    initTheme();

    ['lpinInputs', 'deviceTpinInputs',
        'actLpinInputs', 'actLpinConfirmInputs', 'actTpinInputs', 'actTpinConfirmInputs'
    ].forEach(id => { if (document.getElementById(id)) setupPinInputs(id); });

    const authToggle = document.getElementById('authThemeToggle');
    if (authToggle) authToggle.addEventListener('click', toggleTheme);

    // Show activation / login links
    document.getElementById('showActivation')?.addEventListener('click', () => {
        document.getElementById('loginView').classList.add('hidden');
        document.getElementById('activationView').classList.remove('hidden');
    });
    document.getElementById('showLogin')?.addEventListener('click', () => {
        document.getElementById('activationView').classList.add('hidden');
        document.getElementById('loginView').classList.remove('hidden');
    });

    // ── Login Form ──
    document.getElementById('loginForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('loginEmail').value.trim();
        const password = document.getElementById('loginPassword').value;
        const btn = document.getElementById('loginBtn');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Signing in...';
        try {
            const cred = await signInWithEmailAndPassword(auth, email, password);
            const user = cred.user;
            if (!user.emailVerified) {
                showToast('Please verify your email before logging in.', 'warning');
                btn.disabled = false; btn.textContent = 'Sign In';
                return;
            }
            const uDoc = await loadCurrentUserDoc(user.uid);
            if (!uDoc) { showToast('Account not found in system.', 'danger'); btn.disabled = false; btn.textContent = 'Sign In'; return; }
            if (!uDoc.isActive) { showToast('Your account is frozen. Contact admin.', 'danger'); await signOut(auth); btn.disabled = false; btn.textContent = 'Sign In'; return; }
            if (!uDoc.isSetupComplete) { showToast('Please complete account setup first.', 'warning'); btn.disabled = false; btn.textContent = 'Sign In'; return; }

            const deviceId = getDeviceId();
            if (uDoc.approvedDevices && uDoc.approvedDevices.includes(deviceId)) {
                showLpinView();
            } else {
                await sendEmailVerification(user);
                showDeviceVerifyView();
            }
        } catch (err) {
            showToast(mapAuthError(err.code), 'danger');
        }
        btn.disabled = false;
        btn.textContent = 'Sign In';
    });

    // ── LPIN Verification ──
    document.getElementById('lpinForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const pin = getPinFromGroup('lpinInputs');
        if (pin.length !== 4) { showToast('Enter all 4 digits', 'warning'); return; }
        const btn = document.getElementById('lpinBtn');
        btn.disabled = true;
        try {
            const hash = await sha256(pin);
            if (hash === currentUserDoc.pinHash) {
                if (currentUserDoc.role === 'admin') {
                    window.location.href = 'admin.html';
                } else {
                    window.location.href = 'dashboard.html';
                }
            } else {
                showToast('Incorrect PIN. Try again.', 'danger');
                clearPinGroup('lpinInputs');
            }
        } catch (err) {
            showToast('Error verifying PIN', 'danger');
        }
        btn.disabled = false;
    });

    // ── LPIN Logout ──
    document.getElementById('lpinLogout')?.addEventListener('click', async () => {
        await signOut(auth);
        currentUserDoc = null;
        document.getElementById('lpinView').classList.add('hidden');
        document.getElementById('loginView').classList.remove('hidden');
    });

    // ── Device Verification ──
    document.getElementById('deviceVerifyForm')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const pin = getPinFromGroup('deviceTpinInputs');
        if (pin.length !== 4) { showToast('Enter all 4 digits', 'warning'); return; }
        const btn = document.getElementById('deviceVerifyBtn');
        btn.disabled = true;
        try {
            await auth.currentUser.reload();
            if (!auth.currentUser.emailVerified) {
                showToast('Please verify your email first.', 'warning');
                btn.disabled = false;
                return;
            }
            const hash = await sha256(pin);
            if (hash === currentUserDoc.tpinHash) {
                const deviceId = getDeviceId();
                const devices = currentUserDoc.approvedDevices || [];
                devices.push(deviceId);
                await updateDoc(doc(db, 'users', currentUserDoc.id), { approvedDevices: devices });
                currentUserDoc.approvedDevices = devices;
                showToast('Device verified!', 'success');
                showLpinView();
            } else {
                const attempts = (currentUserDoc.failedPinAttempts || 0) + 1;
                await updateDoc(doc(db, 'users', currentUserDoc.id), { failedPinAttempts: attempts, ...(attempts >= 3 ? { isActive: false } : {}) });
                if (attempts >= 3) {
                    showToast('Account frozen due to 3 failed TPIN attempts!', 'danger');
                    await signOut(auth);
                    window.location.href = 'index.html';
                } else {
                    showToast(`Wrong TPIN. ${3 - attempts} attempts remaining.`, 'danger');
                    clearPinGroup('deviceTpinInputs');
                }
            }
        } catch (err) {
            showToast('Verification error: ' + err.message, 'danger');
        }
        btn.disabled = false;
    });

    document.getElementById('deviceResendEmail')?.addEventListener('click', async () => {
        try { await sendEmailVerification(auth.currentUser); showToast('Verification email resent!', 'success'); } catch (e) { showToast('Error sending email: ' + e.message, 'danger'); }
    });

    // ══════════════════════════════════════════
    // ACCOUNT ACTIVATION FLOW (FIXED)
    // ══════════════════════════════════════════

    // ── Step 1: Verify Account ──
    // FIX: Use separate queries instead of compound query to avoid needing composite index
    document.getElementById('activationStep1Form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const accNum = document.getElementById('actAccountNumber').value.trim().toUpperCase();
        const email = document.getElementById('actEmail').value.trim().toLowerCase();
        showLoading('Verifying account...');
        try {
            // Query by accountNumber only (no composite index needed)
            const q = query(collection(db, 'users'), where('accountNumber', '==', accNum));
            const snap = await getDocs(q);

            if (snap.empty) {
                showToast('Account not found.', 'danger');
                hideLoading();
                return;
            }

            const userDoc = snap.docs[0].data();
            const docId = snap.docs[0].id;

            // Manually check email match
            if (userDoc.email !== email) {
                showToast('Email does not match this account number.', 'danger');
                hideLoading();
                return;
            }
            if (!userDoc.isActive) {
                showToast('This account is not active. Contact admin.', 'danger');
                hideLoading();
                return;
            }
            if (userDoc.isSetupComplete) {
                showToast('This account is already activated. Try logging in.', 'warning');
                hideLoading();
                return;
            }

            // Store for later steps
            window._activationDocId = docId;
            window._activationData = userDoc;
            window._activationEmail = email;

            setActivationStep(2);
            hideLoading();
        } catch (err) {
            showToast('Error: ' + err.message, 'danger');
            hideLoading();
        }
    });

    // ── Step 2: Continue ──
    document.getElementById('activationStep2Btn')?.addEventListener('click', () => setActivationStep(3));

    // ── Step 3: Create Password & Send Verification ──
    document.getElementById('activationStep3Form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = document.getElementById('actPassword').value;
        const confirm = document.getElementById('actPasswordConfirm').value;
        if (password !== confirm) { showToast('Passwords do not match.', 'danger'); return; }
        if (password.length < 8) { showToast('Password must be at least 8 characters.', 'danger'); return; }
        showLoading('Creating your account...');
        try {
            const cred = await createUserWithEmailAndPassword(auth, window._activationEmail, password);
            // Update the Firestore doc with the auth UID
            await updateDoc(doc(db, 'users', window._activationDocId), { uid: cred.user.uid });
            await sendEmailVerification(cred.user);
            setActivationStep(4);
            hideLoading();
        } catch (err) {
            showToast(mapAuthError(err.code), 'danger');
            hideLoading();
        }
    });

    // ── Step 4: Check Verification ──
    document.getElementById('activationCheckVerified')?.addEventListener('click', async () => {
        showLoading('Checking verification...');
        try {
            await auth.currentUser.reload();
            if (auth.currentUser.emailVerified) {
                setActivationStep(5);
            } else {
                showToast('Email not yet verified. Check your inbox.', 'warning');
            }
        } catch (err) {
            showToast('Error: ' + err.message, 'danger');
        }
        hideLoading();
    });

    document.getElementById('activationResendEmail')?.addEventListener('click', async () => {
        try { await sendEmailVerification(auth.currentUser); showToast('Email resent!', 'success'); } catch (e) { showToast(e.message, 'danger'); }
    });

    // ── Step 5: Set PINs ──
    document.getElementById('activationStep5Form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const lpin = getPinFromGroup('actLpinInputs');
        const lpinC = getPinFromGroup('actLpinConfirmInputs');
        const tpin = getPinFromGroup('actTpinInputs');
        const tpinC = getPinFromGroup('actTpinConfirmInputs');
        if (lpin.length !== 4 || tpin.length !== 4) { showToast('All PINs must be 4 digits.', 'warning'); return; }
        if (lpin !== lpinC) { showToast('Login PINs do not match.', 'danger'); return; }
        if (tpin !== tpinC) { showToast('Transaction PINs do not match.', 'danger'); return; }
        showLoading('Securing your account...');
        try {
            const pinHash = await sha256(lpin);
            const tpinHash = await sha256(tpin);
            const deviceId = getDeviceId();
            await updateDoc(doc(db, 'users', window._activationDocId), {
                pinHash, tpinHash,
                isSetupComplete: true,
                approvedDevices: [deviceId],
                failedPinAttempts: 0
            });
            showToast('Account activated! Redirecting...', 'success');
            setTimeout(() => { window.location.href = 'dashboard.html'; }, 1500);
        } catch (err) {
            showToast('Error: ' + err.message, 'danger');
        }
        hideLoading();
    });
}

// ── Activation step navigation ──
function setActivationStep(step) {
    for (let i = 1; i <= 5; i++) {
        const el = document.getElementById('activationStep' + i);
        if (el) el.classList.toggle('hidden', i !== step);
    }
    document.querySelectorAll('#activationSteps .step-dot').forEach(dot => {
        const s = parseInt(dot.dataset.step);
        dot.classList.toggle('active', s === step);
        dot.classList.toggle('completed', s < step);
    });
    document.querySelectorAll('#activationSteps .step-line').forEach((line, idx) => {
        line.classList.toggle('completed', idx < step - 1);
    });
}

// ── View switches ──
function showLpinView() {
    document.getElementById('loginView')?.classList.add('hidden');
    document.getElementById('activationView')?.classList.add('hidden');
    document.getElementById('deviceVerifyView')?.classList.add('hidden');
    document.getElementById('lpinView')?.classList.remove('hidden');
    clearPinGroup('lpinInputs');
}

function showDeviceVerifyView() {
    document.getElementById('loginView')?.classList.add('hidden');
    document.getElementById('activationView')?.classList.add('hidden');
    document.getElementById('lpinView')?.classList.add('hidden');
    document.getElementById('deviceVerifyView')?.classList.remove('hidden');
    clearPinGroup('deviceTpinInputs');
}

function mapAuthError(code) {
    const map = {
        'auth/user-not-found': 'No account found with this email.',
        'auth/wrong-password': 'Incorrect password.',
        'auth/invalid-credential': 'Invalid email or password.',
        'auth/email-already-in-use': 'This email is already registered.',
        'auth/weak-password': 'Password is too weak (min 6 chars).',
        'auth/too-many-requests': 'Too many attempts. Try again later.',
        'auth/invalid-email': 'Invalid email address.'
    };
    return map[code] || 'Authentication error. Please try again.';
}

// ============================================
// DASHBOARD PAGE
// ============================================

async function initDashboardPage() {
    initTheme();
    initSidebar();
    initInactivityTimer();
    setupPinInputs('transferTpinInputs');

    const nameEl = document.getElementById('userName');
    const avatarEl = document.getElementById('userAvatar');
    const roleEl = document.getElementById('userRole');
    if (nameEl) nameEl.textContent = currentUserDoc.fullName || 'User';
    if (avatarEl) avatarEl.textContent = (currentUserDoc.fullName || 'U')[0].toUpperCase();
    if (roleEl) roleEl.textContent = currentUserDoc.role === 'admin' ? 'Administrator' : 'Member';

    await loadDashboardData();

    document.getElementById('transferForm')?.addEventListener('submit', handleTransfer);
    document.getElementById('txFilterType')?.addEventListener('change', () => loadUserTransactions());

    hideLoading();
}

async function loadDashboardData() {
    await loadCurrentUserDoc(auth.currentUser.uid);
    const d = currentUserDoc;

    document.getElementById('dashGreetName').textContent = d.fullName?.split(' ')[0] || 'User';
    document.getElementById('dashBalance').textContent = fmtCurrency(d.balance);
    document.getElementById('dashAccountNo').textContent = d.accountNumber;
    document.getElementById('transferBalance').textContent = fmtCurrency(d.balance);

    try {
        const settingsSnap = await getDoc(doc(db, 'settings', 'bankSettings'));
        const rate = d.interestRate ?? settingsSnap.data()?.monthlyInterestRate ?? 0;
        document.getElementById('dashInterestRate').textContent = rate;
    } catch (e) {
        document.getElementById('dashInterestRate').textContent = '0';
    }

    const acc = d.accountNumber;
    let allTx = [];
    try {
        const txSnap = await getDocs(query(collection(db, 'transactions'), orderBy('timestamp', 'desc'), limit(100)));
        txSnap.forEach(d => allTx.push({ id: d.id, ...d.data() }));
    } catch (e) {
        // If index not ready, fall back to unordered
        const txSnap = await getDocs(collection(db, 'transactions'));
        txSnap.forEach(d => allTx.push({ id: d.id, ...d.data() }));
        allTx.sort((a, b) => (b.timestamp?.toMillis?.() || 0) - (a.timestamp?.toMillis?.() || 0));
    }
    const myTx = allTx.filter(t => t.fromAccount === acc || t.toAccount === acc);

    let totalIn = 0, totalOut = 0;
    myTx.forEach(t => {
        if (t.toAccount === acc) totalIn += t.amount;
        if (t.fromAccount === acc && t.type === 'transfer') totalOut += t.amount;
    });
    document.getElementById('dashTotalIn').textContent = fmtCurrency(totalIn);
    document.getElementById('dashTotalOut').textContent = fmtCurrency(totalOut);
    document.getElementById('dashTxCount').textContent = myTx.length;

    renderTxTable('dashRecentTx', myTx.slice(0, 5), acc);
    generateQR(acc);
}

function renderTxTable(tbodyId, txList, myAccount) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;
    if (txList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state"><div class="empty-icon">📭</div><p>No transactions found</p></div></td></tr>';
        return;
    }
    tbody.innerHTML = txList.map(t => {
        const isCredit = t.toAccount === myAccount;
        const typeMap = { transfer: '💸 Transfer', deposit: '💰 Deposit', withdraw: '💳 Withdraw', interest: '📈 Interest' };
        const badge = t.type === 'deposit' || (t.type === 'transfer' && isCredit) ? 'badge-success' : t.type === 'withdraw' || (t.type === 'transfer' && !isCredit) ? 'badge-danger' : 'badge-info';
        const sign = isCredit || t.type === 'deposit' || t.type === 'interest' ? '+' : '-';
        return `<tr>
            <td>${fmtDate(t.timestamp)}</td>
            <td><span class="badge ${badge}">${typeMap[t.type] || t.type}</span></td>
            <td>${t.fromAccount || '—'}</td>
            <td>${t.toAccount || '—'}</td>
            <td class="${sign === '+' ? 'text-success' : 'text-danger'}">${sign} ${fmtCurrency(t.amount)}</td>
            <td>${t.performedBy || '—'}</td>
        </tr>`;
    }).join('');
}

async function loadUserTransactions() {
    const acc = currentUserDoc.accountNumber;
    const filterType = document.getElementById('txFilterType')?.value || 'all';
    let txs = [];
    try {
        const txSnap = await getDocs(query(collection(db, 'transactions'), orderBy('timestamp', 'desc')));
        txSnap.forEach(d => txs.push({ id: d.id, ...d.data() }));
    } catch (e) {
        const txSnap = await getDocs(collection(db, 'transactions'));
        txSnap.forEach(d => txs.push({ id: d.id, ...d.data() }));
        txs.sort((a, b) => (b.timestamp?.toMillis?.() || 0) - (a.timestamp?.toMillis?.() || 0));
    }
    let myTx = txs.filter(t => t.fromAccount === acc || t.toAccount === acc);
    if (filterType !== 'all') myTx = myTx.filter(t => t.type === filterType);
    renderTxTable('allTxBody', myTx, acc);
}

function generateQR(accountNumber) {
    const container = document.getElementById('qrCanvas');
    if (!container || typeof QRCode === 'undefined') return;
    container.innerHTML = '';
    new QRCode(container, {
        text: accountNumber,
        width: 180,
        height: 180,
        colorDark: '#6366f1',
        colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.H
    });
    const label = document.getElementById('qrAccountLabel');
    if (label) label.textContent = accountNumber;
}

// ── Transfer Handler ──
async function handleTransfer(e) {
    e.preventDefault();
    const toAcc = document.getElementById('transferTo').value.trim().toUpperCase();
    const amount = parseFloat(document.getElementById('transferAmount').value);
    const tpin = getPinFromGroup('transferTpinInputs');
    const btn = document.getElementById('transferBtn');

    if (!toAcc || !amount || amount <= 0) { showToast('Enter valid details.', 'warning'); return; }
    if (tpin.length !== 4) { showToast('Enter 4-digit TPIN.', 'warning'); return; }
    if (toAcc === currentUserDoc.accountNumber) { showToast('Cannot transfer to yourself.', 'warning'); return; }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Processing...';

    try {
        const hash = await sha256(tpin);
        await loadCurrentUserDoc(auth.currentUser.uid);

        if (hash !== currentUserDoc.tpinHash) {
            const attempts = (currentUserDoc.failedPinAttempts || 0) + 1;
            await updateDoc(doc(db, 'users', currentUserDoc.id), {
                failedPinAttempts: attempts,
                ...(attempts >= 3 ? { isActive: false } : {})
            });
            if (attempts >= 3) {
                showToast('Account FROZEN! 3 wrong TPIN attempts.', 'danger');
                await signOut(auth);
                window.location.href = 'index.html';
                return;
            }
            showToast(`Wrong TPIN! ${3 - attempts} attempts left.`, 'danger');
            clearPinGroup('transferTpinInputs');
            btn.disabled = false; btn.textContent = 'Send Money';
            return;
        }

        if (currentUserDoc.failedPinAttempts > 0) {
            await updateDoc(doc(db, 'users', currentUserDoc.id), { failedPinAttempts: 0 });
        }

        // Find receiver
        const recSnap = await getDocs(query(collection(db, 'users'), where('accountNumber', '==', toAcc)));
        if (recSnap.empty) { showToast('Receiver account not found.', 'danger'); btn.disabled = false; btn.textContent = 'Send Money'; return; }
        const receiverDoc = recSnap.docs[0];
        const receiverData = receiverDoc.data();
        if (!receiverData.isActive) { showToast('Receiver account is not active.', 'danger'); btn.disabled = false; btn.textContent = 'Send Money'; return; }

        // Atomic transaction
        await runTransaction(db, async (transaction) => {
            const senderRef = doc(db, 'users', currentUserDoc.id);
            const receiverRef = doc(db, 'users', receiverDoc.id);
            const senderSnap = await transaction.get(senderRef);
            const receiverSnap = await transaction.get(receiverRef);

            const senderBal = senderSnap.data().balance;
            if (senderBal < amount) throw new Error('Insufficient balance.');

            transaction.update(senderRef, { balance: senderBal - amount });
            transaction.update(receiverRef, { balance: receiverSnap.data().balance + amount });
        });

        await addDoc(collection(db, 'transactions'), {
            fromAccount: currentUserDoc.accountNumber,
            toAccount: toAcc,
            amount,
            type: 'transfer',
            timestamp: serverTimestamp(),
            performedBy: currentUserDoc.fullName
        });

        showToast(`Rs. ${amount.toFixed(2)} sent to ${toAcc} successfully!`, 'success');
        document.getElementById('transferForm').reset();
        clearPinGroup('transferTpinInputs');
        await loadDashboardData();
    } catch (err) {
        showToast('Transfer failed: ' + err.message, 'danger');
    }
    btn.disabled = false;
    btn.textContent = 'Send Money';
}

// ============================================
// ADMIN PAGE
// ============================================

async function initAdminPage() {
    initTheme();
    initSidebar();
    initInactivityTimer();

    const nameEl = document.getElementById('userName');
    const avatarEl = document.getElementById('userAvatar');
    if (nameEl) nameEl.textContent = currentUserDoc.fullName || 'Admin';
    if (avatarEl) avatarEl.textContent = (currentUserDoc.fullName || 'A')[0].toUpperCase();

    generateNextAccountNumber();

    document.getElementById('newAccountForm')?.addEventListener('submit', handleNewAccount);
    document.getElementById('depositForm')?.addEventListener('submit', (e) => handleDepositWithdraw(e, 'deposit'));
    document.getElementById('withdrawForm')?.addEventListener('submit', (e) => handleDepositWithdraw(e, 'withdraw'));
    document.getElementById('globalRateForm')?.addEventListener('submit', handleUpdateGlobalRate);
    document.getElementById('userRateForm')?.addEventListener('submit', handleUpdateUserRate);
    document.getElementById('applyInterestAll')?.addEventListener('click', () => applyInterest('all'));
    document.getElementById('applyInterestUserForm')?.addEventListener('submit', (e) => { e.preventDefault(); applyInterest(document.getElementById('interestUserAccount').value.trim().toUpperCase()); });
    document.getElementById('adminTxFilter')?.addEventListener('change', loadAdminTransactions);

    await loadAdminOverview();
    hideLoading();
}

async function generateNextAccountNumber() {
    try {
        const snap = await getDocs(collection(db, 'users'));
        let maxNum = 0;
        snap.forEach(d => {
            const acc = d.data().accountNumber || '';
            const num = parseInt(acc.replace('FAM-', ''));
            if (!isNaN(num) && num > maxNum) maxNum = num;
        });
        const next = 'FAM-' + String(maxNum + 1).padStart(4, '0');
        const el = document.getElementById('newAccountNumber');
        if (el) el.value = next;
    } catch (e) { /* silently fail */ }
}

async function handleNewAccount(e) {
    e.preventDefault();
    const fullName = document.getElementById('newFullName').value.trim();
    const email = document.getElementById('newEmail').value.trim().toLowerCase();
    const accountNumber = document.getElementById('newAccountNumber').value.trim();
    const balance = parseFloat(document.getElementById('newBalance').value) || 0;
    const btn = document.getElementById('createAccountBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Creating...';
    try {
        const existCheck = await getDocs(query(collection(db, 'users'), where('email', '==', email)));
        if (!existCheck.empty) { showToast('An account with this email already exists.', 'danger'); btn.disabled = false; btn.textContent = 'Create Account'; return; }

        await addDoc(collection(db, 'users'), {
            uid: '',
            fullName,
            email,
            accountNumber,
            balance,
            pinHash: '',
            tpinHash: '',
            role: 'member',
            isActive: true,
            isSetupComplete: false,
            approvedDevices: [],
            failedPinAttempts: 0,
            createdAt: serverTimestamp()
        });
        showToast(`Account ${accountNumber} created for ${fullName}!`, 'success');
        document.getElementById('newAccountForm').reset();
        generateNextAccountNumber();
    } catch (err) {
        showToast('Error: ' + err.message, 'danger');
    }
    btn.disabled = false;
    btn.textContent = 'Create Account';
}

async function loadAdminOverview() {
    try {
        const usersSnap = await getDocs(collection(db, 'users'));
        let totalBalance = 0, totalUsers = 0, active = 0, inactive = 0;
        usersSnap.forEach(d => {
            const u = d.data();
            totalUsers++;
            totalBalance += u.balance || 0;
            if (u.isActive) active++; else inactive++;
        });
        document.getElementById('adminTotalBalance').textContent = fmtCurrency(totalBalance);
        document.getElementById('adminTotalUsers').textContent = totalUsers;
        document.getElementById('adminActiveUsers').textContent = active;
        document.getElementById('adminInactiveUsers').textContent = inactive;

        const txSnap = await getDocs(collection(db, 'transactions'));
        document.getElementById('adminTotalTx').textContent = txSnap.size;

        const settingsSnap = await getDoc(doc(db, 'settings', 'bankSettings'));
        const rate = settingsSnap.exists() ? (settingsSnap.data().monthlyInterestRate || 0) : 0;
        document.getElementById('adminGlobalRate').textContent = rate + '%';

        // Recent transactions
        let recent = [];
        try {
            const recentSnap = await getDocs(query(collection(db, 'transactions'), orderBy('timestamp', 'desc'), limit(5)));
            recentSnap.forEach(d => recent.push({ id: d.id, ...d.data() }));
        } catch (e) {
            const recentSnap = await getDocs(collection(db, 'transactions'));
            recentSnap.forEach(d => recent.push({ id: d.id, ...d.data() }));
            recent.sort((a, b) => (b.timestamp?.toMillis?.() || 0) - (a.timestamp?.toMillis?.() || 0));
            recent = recent.slice(0, 5);
        }
        renderAdminTxTable('adminRecentTx', recent);
    } catch (err) {
        showToast('Failed to load overview: ' + err.message, 'danger');
    }
}

function renderAdminTxTable(tbodyId, txList) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;
    if (txList.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state"><div class="empty-icon">📭</div><p>No transactions</p></div></td></tr>';
        return;
    }
    tbody.innerHTML = txList.map(t => {
        const typeMap = { transfer: '💸 Transfer', deposit: '💰 Deposit', withdraw: '💳 Withdraw', interest: '📈 Interest' };
        const badge = t.type === 'deposit' ? 'badge-success' : t.type === 'withdraw' ? 'badge-danger' : t.type === 'interest' ? 'badge-info' : 'badge-warning';
        return `<tr>
            <td>${fmtDate(t.timestamp)}</td>
            <td><span class="badge ${badge}">${typeMap[t.type] || t.type}</span></td>
            <td>${t.fromAccount || '—'}</td>
            <td>${t.toAccount || '—'}</td>
            <td>${fmtCurrency(t.amount)}</td>
            <td>${t.performedBy || '—'}</td>
        </tr>`;
    }).join('');
}

async function loadAllUsers() {
    const tbody = document.getElementById('allUsersBody');
    if (!tbody) return;
    try {
        const snap = await getDocs(collection(db, 'users'));
        const users = [];
        snap.forEach(d => users.push({ id: d.id, ...d.data() }));
        if (users.length === 0) { tbody.innerHTML = '<tr><td colspan="7"><div class="empty-state"><div class="empty-icon">👥</div><p>No users</p></div></td></tr>'; return; }
        tbody.innerHTML = users.map(u => `<tr>
            <td><strong>${u.accountNumber}</strong></td>
            <td>${u.fullName}</td>
            <td>${u.email}</td>
            <td>${fmtCurrency(u.balance)}</td>
            <td>${u.isActive ? '<span class="badge badge-success">Active</span>' : '<span class="badge badge-danger">Frozen</span>'}</td>
            <td>${u.isSetupComplete ? '<span class="badge badge-success">Yes</span>' : '<span class="badge badge-warning">No</span>'}</td>
            <td>
                ${u.role !== 'admin' ? `
                    <button class="btn btn-sm ${u.isActive ? 'btn-warning' : 'btn-success'}" onclick="window._toggleFreeze('${u.id}', ${u.isActive})">${u.isActive ? 'Freeze' : 'Unfreeze'}</button>
                    ${u.isActive ? `<button class="btn btn-sm btn-danger" onclick="window._closeAccount('${u.id}')" style="margin-left:4px;">Close</button>` : ''}
                ` : '<span class="badge badge-info">Admin</span>'}
            </td>
        </tr>`).join('');
    } catch (err) {
        showToast('Error loading users: ' + err.message, 'danger');
    }
}

window._toggleFreeze = async (docId, isCurrentlyActive) => {
    try {
        await updateDoc(doc(db, 'users', docId), { isActive: !isCurrentlyActive, failedPinAttempts: 0 });
        showToast(isCurrentlyActive ? 'Account frozen.' : 'Account unfrozen.', 'success');
        loadAllUsers();
    } catch (err) { showToast(err.message, 'danger'); }
};

window._closeAccount = async (docId) => {
    if (!confirm('Are you sure you want to close this account?')) return;
    try {
        await updateDoc(doc(db, 'users', docId), { isActive: false });
        showToast('Account closed.', 'success');
        loadAllUsers();
    } catch (err) { showToast(err.message, 'danger'); }
};

async function handleDepositWithdraw(e, type) {
    e.preventDefault();
    const accField = type === 'deposit' ? 'depositAccount' : 'withdrawAccount';
    const amtField = type === 'deposit' ? 'depositAmount' : 'withdrawAmount';
    const accNum = document.getElementById(accField).value.trim().toUpperCase();
    const amount = parseFloat(document.getElementById(amtField).value);
    if (!accNum || !amount || amount <= 0) { showToast('Enter valid details.', 'warning'); return; }

    try {
        const snap = await getDocs(query(collection(db, 'users'), where('accountNumber', '==', accNum)));
        if (snap.empty) { showToast('Account not found.', 'danger'); return; }
        const userRef = doc(db, 'users', snap.docs[0].id);

        await runTransaction(db, async (transaction) => {
            const userSnap = await transaction.get(userRef);
            const bal = userSnap.data().balance;
            if (type === 'withdraw' && bal < amount) throw new Error('Insufficient balance.');
            const newBal = type === 'deposit' ? bal + amount : bal - amount;
            transaction.update(userRef, { balance: newBal });
        });

        await addDoc(collection(db, 'transactions'), {
            fromAccount: type === 'withdraw' ? accNum : 'BANK',
            toAccount: type === 'deposit' ? accNum : 'BANK',
            amount,
            type,
            timestamp: serverTimestamp(),
            performedBy: currentUserDoc.fullName + ' (Admin)'
        });

        showToast(`${type === 'deposit' ? 'Deposited' : 'Withdrawn'} Rs. ${amount.toFixed(2)} ${type === 'deposit' ? 'to' : 'from'} ${accNum}`, 'success');
        e.target.reset();
        loadAdminOverview();
    } catch (err) {
        showToast(err.message, 'danger');
    }
}

async function loadInterestSettings() {
    try {
        const snap = await getDoc(doc(db, 'settings', 'bankSettings'));
        if (snap.exists()) {
            const data = snap.data();
            document.getElementById('currentGlobalRate').textContent = (data.monthlyInterestRate || 0) + '%';
            document.getElementById('globalRate').value = data.monthlyInterestRate || 0;
            const lastDate = data.lastInterestAppliedDate;
            document.getElementById('lastInterestDate').textContent = lastDate ? fmtDate(lastDate) : 'Never';
        }
    } catch (e) { /* ignore */ }
}

async function handleUpdateGlobalRate(e) {
    e.preventDefault();
    const rate = parseFloat(document.getElementById('globalRate').value);
    try {
        await setDoc(doc(db, 'settings', 'bankSettings'), { monthlyInterestRate: rate }, { merge: true });
        showToast(`Global interest rate set to ${rate}%`, 'success');
        loadInterestSettings();
    } catch (err) { showToast(err.message, 'danger'); }
}

async function handleUpdateUserRate(e) {
    e.preventDefault();
    const accNum = document.getElementById('userRateAccount').value.trim().toUpperCase();
    const rate = parseFloat(document.getElementById('userRate').value);
    try {
        const snap = await getDocs(query(collection(db, 'users'), where('accountNumber', '==', accNum)));
        if (snap.empty) { showToast('Account not found.', 'danger'); return; }
        await updateDoc(doc(db, 'users', snap.docs[0].id), { interestRate: rate });
        showToast(`Interest rate for ${accNum} set to ${rate}%`, 'success');
    } catch (err) { showToast(err.message, 'danger'); }
}

async function applyInterest(target) {
    try {
        const settingsSnap = await getDoc(doc(db, 'settings', 'bankSettings'));
        const settings = settingsSnap.exists() ? settingsSnap.data() : {};
        const globalRate = settings.monthlyInterestRate || 0;
        const lastApplied = settings.lastInterestAppliedDate?.toDate ? settings.lastInterestAppliedDate.toDate() : null;

        if (target === 'all' && lastApplied) {
            const now = new Date();
            if (lastApplied.getMonth() === now.getMonth() && lastApplied.getFullYear() === now.getFullYear()) {
                showToast('Interest already applied this month!', 'warning');
                return;
            }
        }

        showLoading('Applying interest...');
        const usersSnap = await getDocs(collection(db, 'users'));
        let applied = 0;

        for (const userDoc of usersSnap.docs) {
            const u = userDoc.data();
            if (u.role === 'admin') continue;
            if (!u.isActive) continue;
            if (target !== 'all' && u.accountNumber !== target) continue;

            const rate = u.interestRate ?? globalRate;
            if (rate <= 0) continue;

            const interest = u.balance * (rate / 100);
            if (interest <= 0) continue;

            await runTransaction(db, async (transaction) => {
                const ref = doc(db, 'users', userDoc.id);
                const snap = await transaction.get(ref);
                const bal = snap.data().balance;
                transaction.update(ref, { balance: bal + (bal * rate / 100) });
            });

            await addDoc(collection(db, 'transactions'), {
                fromAccount: 'BANK',
                toAccount: u.accountNumber,
                amount: interest,
                type: 'interest',
                timestamp: serverTimestamp(),
                performedBy: currentUserDoc.fullName + ' (Admin)'
            });
            applied++;
        }

        if (target === 'all') {
            await setDoc(doc(db, 'settings', 'bankSettings'), { lastInterestAppliedDate: serverTimestamp() }, { merge: true });
        }

        hideLoading();
        showToast(`Interest applied to ${applied} account(s).`, 'success');
        loadAdminOverview();
        loadInterestSettings();
    } catch (err) {
        hideLoading();
        showToast('Error: ' + err.message, 'danger');
    }
}

async function loadAdminTransactions() {
    const filter = document.getElementById('adminTxFilter')?.value || 'all';
    try {
        let txs = [];
        try {
            const txSnap = await getDocs(query(collection(db, 'transactions'), orderBy('timestamp', 'desc')));
            txSnap.forEach(d => txs.push({ id: d.id, ...d.data() }));
        } catch (e) {
            const txSnap = await getDocs(collection(db, 'transactions'));
            txSnap.forEach(d => txs.push({ id: d.id, ...d.data() }));
            txs.sort((a, b) => (b.timestamp?.toMillis?.() || 0) - (a.timestamp?.toMillis?.() || 0));
        }
        if (filter !== 'all') txs = txs.filter(t => t.type === filter);
        renderAdminTxTable('adminAllTxBody', txs);
    } catch (err) {
        showToast('Error loading transactions', 'danger');
    }
}
