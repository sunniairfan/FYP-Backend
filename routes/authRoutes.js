const express = require("express");
const router = express.Router();
const {
  ensureAdminAuthIndices,
  queuePendingSignup,
  verifyPendingSignup,
  loginAdmin,
  getAdminByEmail,
  listAdmins,
  requestPasswordResetOrConfirmDelete,
  verifyDeleteCode,
  requestForgotPasswordCode,
  verifyForgotPasswordCodeAndReset,
  changeAdminPassword,
  softDeleteAdminAccount,
  sanitizeEmail,
} = require("../utils/adminAuth");
const { requireAdminApi, requireAdminSession } = require("../middleware/authAccess");
const { createTokenPair, refreshAccessToken, revokeRefreshToken, verifyJWT } = require("../utils/oauth2Auth");

const buildAuthPage = (title, body) => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title} — Android Malware Detection System</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: #05090f;
      color: #e2e8f0;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 24px 16px;
    }
    .brand {
      display: flex; align-items: center; gap: 10px;
      margin-bottom: 20px; text-align: center;
    }
    .brand-icon {
      width: 42px; height: 42px; background: linear-gradient(135deg,#3b82f6,#2563eb);
      border-radius: 10px; display: flex; align-items: center; justify-content: center;
      font-size: 20px;
      box-shadow: 0 4px 14px rgba(59, 130, 246, 0.4);
    }
    .brand-name { font-size: 15px; font-weight: 600; color: #94a3b8; letter-spacing: .5px; }
    .card {
      width: min(480px, 100%);
      background: #0b1120;
      border: 1px solid #1a2332;
      border-radius: 18px;
      padding: 32px 28px;
      box-shadow: 0 20px 60px rgba(0,0,0,.5), 0 0 0 1px rgba(255,255,255,.04);
    }
    .card-header { margin-bottom: 24px; }
    .card-header h1 { font-size: 24px; font-weight: 700; color: #f1f5f9; }
    .card-header p { font-size: 13px; color: #64748b; margin-top: 5px; }
    label {
      display: block; font-size: 13px; font-weight: 500; color: #94a3b8;
      margin-bottom: 6px; margin-top: 14px;
    }
    label:first-of-type { margin-top: 0; }
    input[type="text"], input[type="email"], input[type="password"] {
      width: 100%; padding: 11px 14px;
      background: #070d1a; color: #e2e8f0;
      border: 1px solid #1e293b; border-radius: 10px;
      font-size: 14px; outline: none; transition: border-color .2s, box-shadow .2s;
    }
    input:focus {
      border-color: #2563eb;
      box-shadow: 0 0 0 3px rgba(37,99,235,.15);
    }
    input.input-error { border-color: #ef4444 !important; }
    input.input-ok   { border-color: #22c55e !important; }
    .pw-wrap { position: relative; }
    .pw-wrap input { padding-right: 44px; }
    .pw-toggle {
      position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
      background: none; border: none; color: #64748b; cursor: pointer;
      font-size: 16px; padding: 4px; width: auto;
    }
    .pw-toggle:hover { color: #94a3b8; }
    .btn {
      width: 100%; padding: 12px; margin-top: 20px;
      background: linear-gradient(135deg,#1d4ed8,#2563eb);
      color: #fff; border: none; border-radius: 10px;
      font-size: 15px; font-weight: 600; cursor: pointer;
      transition: opacity .2s, transform .1s;
      letter-spacing: .3px;
    }
    .btn:hover:not(:disabled) { opacity: .92; }
    .btn:active:not(:disabled) { transform: scale(.99); }
    .btn:disabled { opacity: .5; cursor: not-allowed; }
    .btn-secondary {
      background: #1e293b; color: #94a3b8;
      border: 1px solid #334155; margin-top: 10px;
    }
    .btn-secondary:hover:not(:disabled) { background: #263248; }
    .status-msg {
      font-size: 13px; min-height: 18px; margin-top: 10px;
      padding: 8px 12px; border-radius: 8px; display: none;
    }
    .status-msg.show { display: block; }
    .status-msg.error { background: rgba(239,68,68,.1); color: #fca5a5; border: 1px solid rgba(239,68,68,.2); }
    .status-msg.success { background: rgba(34,197,94,.1); color: #86efac; border: 1px solid rgba(34,197,94,.2); }
    .status-msg.info { background: rgba(59,130,246,.1); color: #93c5fd; border: 1px solid rgba(59,130,246,.2); }
    .hint-text { font-size: 12px; color: #94a3b8; margin-top: 5px; line-height: 1.5; }
    .pw-rules { margin-top: 6px; }
    .pw-rules div { font-size: 12px; line-height: 1.8; }
    .divider { border: none; border-top: 1px solid #1e293b; margin: 20px 0; }
    .links { text-align: center; margin-top: 18px; }
    .links a { color: #3b82f6; text-decoration: none; font-size: 13px; }
    .links a:hover { text-decoration: underline; color: #60a5fa; }
    .links span { color: #64748b; margin: 0 8px; }
    .alert-box {
      padding: 12px 14px; border-radius: 10px; font-size: 13px;
      margin-bottom: 16px; line-height: 1.5;
    }
    .alert-box.info { background: rgba(30,58,138,.3); border: 1px solid rgba(37,99,235,.4); color: #93c5fd; }
    .alert-box.warning { background: rgba(120,53,15,.3); border: 1px solid rgba(217,119,6,.4); color: #fcd34d; }
    .alert-box.danger { background: rgba(127,29,29,.3); border: 1px solid rgba(239,68,68,.4); color: #fca5a5; }
    .alert-box.success { background: rgba(6,78,59,.3); border: 1px solid rgba(34,197,94,.4); color: #86efac; }
    .step-bar { display: flex; gap: 6px; margin-bottom: 20px; }
    .step-bar div {
      flex: 1; height: 3px; background: #1e293b; border-radius: 4px;
      transition: background .3s;
    }
    .step-bar div.active { background: #2563eb; }
    .step-bar div.done { background: #22c55e; }
    .badge {
      display: inline-block; padding: 2px 8px;
      border-radius: 99px; font-size: 11px; font-weight: 600;
    }
    .badge-blue { background: rgba(37,99,235,.2); color: #60a5fa; }
    .badge-green { background: rgba(34,197,94,.2); color: #86efac; }
  </style>
</head>
<body>
  <div class="brand">
    <div class="brand-icon">🛡</div>
    <div class="brand-name">Android Malware Detection System</div>
  </div>
  <div class="card">${body}</div>
</body>
</html>`;

router.use(async (req, res, next) => {
  const esClient = req.app.get("esClient");
  if (esClient) {
    try {
      await ensureAdminAuthIndices(esClient);
    } catch (err) {
      console.error("Admin auth index setup failed:", err.message);
    }
  }
  next();
});

router.post("/api/auth/signup/request-code", async (req, res) => {
  const esClient = req.app.get("esClient");
  const { name, email, password } = req.body || {};

  try {
    const result = await queuePendingSignup(esClient, {
      name,
      email,
      password,
    });

    if (!result.ok) {
      return res.status(400).json({ success: false, error: result.error });
    }

    const verified = await verifyPendingSignup(esClient, {
      email: result.email,
      code: result.code,
    });
    if (!verified.ok) {
      return res.status(400).json({ success: false, error: verified.error });
    }

    req.session.authenticated = true;
    req.session.user = {
      id: verified.userId,
      email: verified.email,
      name: verified.name,
      role: "admin",
      status: "active",
    };

    return res.json({
      success: true,
      message: "Account created and logged in",
      user: req.session.user,
    });
  } catch (err) {
    console.error("Signup request error:", err.message);
    return res.status(500).json({
      success: false,
      error: err?.message || "Failed to start signup",
    });
  }
});

router.post("/api/auth/signup/verify-code", async (req, res) => {
  const esClient = req.app.get("esClient");
  const { email, code } = req.body || {};

  try {
    const result = await verifyPendingSignup(esClient, { email, code });
    if (!result.ok) {
      return res.status(400).json({ success: false, error: result.error });
    }

    req.session.authenticated = true;
    req.session.user = {
      id: result.userId,
      email: result.email,
      name: result.name,
      role: "admin",
      status: "active",
    };

    return res.json({
      success: true,
      message: "Account verified and logged in",
      user: req.session.user,
    });
  } catch (err) {
    console.error("Signup verification error:", err.message);
    return res.status(500).json({ success: false, error: "Failed to verify signup" });
  }
});

router.post("/api/auth/login", async (req, res) => {
  const esClient = req.app.get("esClient");
  const { email, password } = req.body || {};

  try {
    const result = await loginAdmin(esClient, {
      email,
      password,
      ipAddress: req.ip,
    });

    if (!result.ok) {
      return res.status(401).json({ success: false, error: result.error });
    }

    req.session.authenticated = true;
    req.session.user = {
      ...result.user,
      status: "active",
    };

    const acceptsHeader = String(req.headers.accept || "");
    const contentType = String(req.headers["content-type"] || "");
    const browserFormRequest = acceptsHeader.includes("text/html")
      || contentType.includes("application/x-www-form-urlencoded");

    if (browserFormRequest) {
      return res.redirect("/");
    }

    return res.json({
      success: true,
      authenticated: true,
      message: "Login successful",
      user: req.session.user,
    });
  } catch (err) {
    console.error("Login error:", err.message);
    return res.status(500).json({ success: false, error: "Failed to login" });
  }
});

router.get("/api/auth/status", (req, res) => {
  const user = req.session?.user || null;
  res.json({
    success: true,
    authenticated: !!(req.session?.authenticated && user),
    user,
  });
});

router.get("/api/auth/me", async (req, res) => {
  const esClient = req.app.get("esClient");
  const email = sanitizeEmail(req.query?.email || req.session?.user?.email);
  if (!email) {
    return res.status(400).json({ success: false, error: "Email is required" });
  }
  const user = await getAdminByEmail(esClient, email);

  if (!user?._source || user._source.status === "deleted") {
    return res.status(404).json({ success: false, error: "Account not found" });
  }

  return res.json({
    success: true,
    user: {
      id: user._id,
      email: user._source.email,
      name: user._source.name,
      role: user._source.role,
      status: user._source.status,
      isVerified: user._source.isVerified,
      createdAt: user._source.createdAt,
      lastLoginAt: user._source.lastLoginAt || null,
    },
  });
});

router.post("/api/auth/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Session destruction error:", err);
      return res.status(500).json({ success: false, error: "Logout failed" });
    }

    return res.json({ success: true, authenticated: false, message: "Logout successful" });
  });
});

router.post("/api/auth/password/forgot/request-code", async (req, res) => {
  const esClient = req.app.get("esClient");
  const { email } = req.body || {};

  if (!email || !String(email).trim()) {
    return res.status(400).json({ success: false, error: "Email is required" });
  }

  try {
    const result = await requestForgotPasswordCode(esClient, email);
    if (!result.ok) {
      return res.status(400).json({ success: false, error: result.error });
    }

    const response = {
      success: true,
      message: result.emailSent
        ? "Verification code sent to your email. It expires in 10 minutes."
        : "Verification code generated. Check the server console (development mode).",
      email: result.email,
      nextStep: "verify-code-and-reset-password",
    };
    // Only expose the code in development/fallback mode
    if (result.devCode) response.devCode = result.devCode;

    return res.json(response);
  } catch (err) {
    console.error("Forgot password request error:", err.message);
    return res.status(500).json({ success: false, error: err?.message || "Failed to request password reset" });
  }
});

router.post("/api/auth/password/forgot/verify-code", async (req, res) => {
  const esClient = req.app.get("esClient");
  const { email, code, newPassword } = req.body || {};

  try {
    const result = await verifyForgotPasswordCodeAndReset(esClient, { email, code, newPassword });
    if (!result.ok) {
      return res.status(400).json({ success: false, error: result.error });
    }

    return res.json({
      success: true,
      message: "Password reset successful. You can now login with your new password.",
    });
  } catch (err) {
    console.error("Forgot password verify error:", err.message);
    return res.status(500).json({ success: false, error: "Failed to reset password" });
  }
});

router.post("/api/auth/password/change", requireAdminApi, async (req, res) => {
  const esClient = req.app.get("esClient");
  const { email, currentPassword, newPassword } = req.body || {};

  try {
    const result = await changeAdminPassword(esClient, {
      email: sanitizeEmail(email || req.session?.user?.email || req.jwtUser?.email),
      currentPassword,
      newPassword,
    });
    if (!result.ok) {
      return res.status(400).json({ success: false, error: result.error });
    }

    return res.json({ success: true, message: "Password changed successfully" });
  } catch (err) {
    console.error("Change password error:", err.message);
    return res.status(500).json({ success: false, error: "Failed to change password" });
  }
});

router.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

router.post("/api/auth/delete/request-code", requireAdminApi, async (req, res) => {
  const esClient = req.app.get("esClient");
  const email = sanitizeEmail(req.body?.email || req.session?.user?.email || req.jwtUser?.email);
  if (!email) {
    return res.status(400).json({ success: false, error: "Email is required" });
  }

  try {
    const result = await requestPasswordResetOrConfirmDelete(esClient, email);
    if (!result.ok) {
      return res.status(400).json({ success: false, error: result.error });
    }

    const response = {
      success: true,
      message: "Delete confirmation code sent to your email.",
      nextStep: "confirm-delete-code",
    };
    if (result.code) response.code = result.code; // devMode only
    return res.json(response);
  } catch (err) {
    console.error("Delete request error:", err.message);
    return res.status(500).json({ success: false, error: "Failed to request delete code" });
  }
});

router.delete("/api/auth/delete/confirm", requireAdminApi, async (req, res) => {
  const esClient = req.app.get("esClient");
  const { email, code } = req.body || {};
  const deleteEmail = sanitizeEmail(email || req.session?.user?.email);
  if (!deleteEmail) {
    return res.status(400).json({ success: false, error: "Email is required" });
  }

  try {
    const result = await verifyDeleteCode(esClient, { email: deleteEmail, code });
    if (!result.ok) {
      return res.status(400).json({ success: false, error: result.error });
    }

    req.session.destroy(() => {});
    return res.json({ success: true, message: "Account deleted" });
  } catch (err) {
    console.error("Delete confirm error:", err.message);
    return res.status(500).json({ success: false, error: "Failed to delete account" });
  }
});

router.get("/api/auth/admin/users", requireAdminApi, async (req, res) => {
  const esClient = req.app.get("esClient");
  try {
    const users = await listAdmins(esClient);
    return res.json({ success: true, total: users.length, users });
  } catch (err) {
    console.error("List users error:", err.message);
    return res.status(500).json({ success: false, error: "Failed to list users" });
  }
});

router.delete("/api/auth/admin/users/:userId", requireAdminApi, async (req, res) => {
  const esClient = req.app.get("esClient");
  const { userId } = req.params;

  try {
    const actor = {
      actorId: req.session?.user?.id,
      actorEmail: req.session?.user?.email,
      selfDelete: req.session?.user?.id === userId,
    };

    const result = await softDeleteAdminAccount(esClient, userId, actor);
    if (!result.ok) {
      return res.status(404).json({ success: false, error: result.error });
    }

    return res.json({ success: true, message: "Account deleted" });
  } catch (err) {
    console.error("Admin delete user error:", err.message);
    return res.status(500).json({ success: false, error: "Failed to delete user" });
  }
});

router.get("/login", (req, res) => {
  // Already logged in? Redirect to homepage
  if (req.session?.authenticated && req.session?.user?.role === "admin") {
    return res.redirect("/");
  }
  const nextUrl = String(req.query.next || "").replace(/[^a-zA-Z0-9/_-]/g, "").substring(0, 200);
  const redirected = req.query.redirected === "1";
  return res.send(buildAuthPage("Admin Login", `
    <div class="card-header">
      <h1>Welcome Back</h1>
      <p>Sign in to your admin account to continue.</p>
    </div>
    ${redirected ? `<div class="alert-box danger">🔒 You must be logged in to access that page. Please sign in below.</div>` : ""}
    <div id="loginAlert" class="status-msg" role="alert" aria-live="polite"></div>
    <form id="loginForm" novalidate>
      <input type="hidden" name="next" value="${nextUrl}" />
      <label for="loginEmail">Email Address</label>
      <input type="email" id="loginEmail" name="email" required autocomplete="email"
             placeholder="admin@example.com"
             title="Enter your registered admin email address" />
      <label for="loginPassword">Password</label>
      <div class="pw-wrap">
        <input type="password" id="loginPassword" name="password" required autocomplete="current-password"
               placeholder="Your password"
               title="Enter your account password" />
        <button type="button" class="pw-toggle" onclick="togglePw('loginPassword',this)" tabindex="-1" title="Show/hide password">👁</button>
      </div>
      <button type="submit" class="btn" id="loginBtn">Sign In</button>
    </form>
    <div class="links">
      <a href="/forgot-password">Forgot password?</a>
      <span>|</span>
      <a href="/signup">Create account</a>
    </div>
    <script>
      function togglePw(id, btn) {
        const inp = document.getElementById(id);
        if (inp.type === 'password') { inp.type = 'text'; btn.textContent = '🙈'; }
        else { inp.type = 'password'; btn.textContent = '👁'; }
      }
      function showAlert(msg, type) {
        const a = document.getElementById('loginAlert');
        a.textContent = msg; a.className = 'status-msg show ' + type;
      }
      document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('loginEmail').value.trim();
        const password = document.getElementById('loginPassword').value;
        if (!email) { showAlert('Please enter your email address.', 'error'); return; }
        if (!password) { showAlert('Please enter your password.', 'error'); return; }
        const btn = document.getElementById('loginBtn');
        btn.disabled = true; btn.textContent = 'Signing in…';
        try {
          const resp = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
          });
          const data = await resp.json();
          if (!resp.ok) {
            showAlert(data.error || 'Login failed. Please check your credentials.', 'error');
            btn.disabled = false; btn.textContent = 'Sign In'; return;
          }
          showAlert('✓ Login successful! Redirecting…', 'success');
          setTimeout(() => { window.location.href = '/'; }, 700);
        } catch (err) {
          showAlert('Network error. Please try again.', 'error');
          btn.disabled = false; btn.textContent = 'Sign In';
        }
      });
    </script>
  `));
});

router.get("/signup", (req, res) => {
  // Already logged in? Go to dashboard
  if (req.session?.authenticated && req.session?.user?.role === "admin") {
    return res.redirect("/");
  }
  return res.send(buildAuthPage("Admin Signup", `
    <div class="card-header">
      <h1>Create Admin Account</h1>
      <p>Register a new admin account for the security dashboard.</p>
    </div>
    <div id="signupAlert" class="status-msg" role="alert" aria-live="polite"></div>
    <form id="signupForm" novalidate autocomplete="off">
      <label for="sigName">Full Name</label>
      <input type="text" id="sigName" name="name" required autocomplete="name"
             placeholder="John Doe"
             title="Enter your full name (at least 2 characters)" />
      <label for="sigEmail">Email Address</label>
      <input type="email" id="sigEmail" name="email" required autocomplete="email"
             placeholder="admin@example.com"
             title="Use a valid email address — you may need it for password recovery" />
      <label for="sigPassword">Password
        <span style="color: #94a3b8;font-size:11px;margin-left:6px;" title="Requirements: 6+ characters, 1 uppercase, 1 number, 1 dollar sign">ⓘ hover for rules</span>
      </label>
      <div class="pw-wrap">
        <input type="password" id="sigPassword" name="password" required autocomplete="new-password"
               placeholder="Create a strong password"
               title="Must be 6+ characters and include: 1 uppercase letter, 1 number, 1 dollar sign ($)" />
        <button type="button" class="pw-toggle" onclick="togglePw('sigPassword',this)" tabindex="-1" title="Show/hide password">👁</button>
      </div>
      <div class="pw-rules" id="pwRules"></div>
      <label for="sigConfirm">Confirm Password</label>
      <div class="pw-wrap">
        <input type="password" id="sigConfirm" name="confirmPassword" required autocomplete="new-password"
               placeholder="Repeat your password" />
        <button type="button" class="pw-toggle" onclick="togglePw('sigConfirm',this)" tabindex="-1" title="Show/hide password">👁</button>
      </div>
      <div id="confirmHint" class="hint-text"></div>
      <button type="submit" class="btn" id="sigBtn">Create Account</button>
    </form>
    <div class="links">
      Already have an account? <a href="/login">Sign in</a>
    </div>
    <script>
      function togglePw(id, btn) {
        const inp = document.getElementById(id);
        if (inp.type === 'password') { inp.type = 'text'; btn.textContent = '🙈'; }
        else { inp.type = 'password'; btn.textContent = '👁'; }
      }
      function showAlert(msg, type) {
        const a = document.getElementById('signupAlert');
        a.textContent = msg; a.className = 'status-msg show ' + type;
      }
      const rules = { minLen: 6, upper: /[A-Z]/, num: /[0-9]/, dollar: /\$/ };
      const ruleEl = document.getElementById('pwRules');
      const ok = (c, l) => '<div><span style="color:' + (c ? '#86efac' : '#fca5a5') + '">' + (c ? '✓' : '✗') + '</span> ' + l + '</div>';
      function renderRules(v) {
        ruleEl.innerHTML = ok(v.length >= rules.minLen,'6+ characters') + ok(rules.upper.test(v),'one uppercase letter') + ok(rules.num.test(v),'one number') + ok(rules.dollar.test(v),'one \$ symbol');
        return v.length >= rules.minLen && rules.upper.test(v) && rules.num.test(v) && rules.dollar.test(v);
      }
      const sigPw = document.getElementById('sigPassword');
      const sigCf = document.getElementById('sigConfirm');
      const cfHint = document.getElementById('confirmHint');
      sigPw.addEventListener('input', () => {
        renderRules(sigPw.value);
        if (sigCf.value) { cfHint.textContent = sigPw.value === sigCf.value ? '✓ Passwords match' : '✗ Passwords do not match'; cfHint.style.color = sigPw.value === sigCf.value ? '#86efac' : '#fca5a5'; }
      });
      sigCf.addEventListener('input', () => {
        cfHint.textContent = sigPw.value === sigCf.value ? '✓ Passwords match' : '✗ Passwords do not match';
        cfHint.style.color = sigPw.value === sigCf.value ? '#86efac' : '#fca5a5';
      });
      renderRules('');
      document.getElementById('signupForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('sigName').value.trim();
        const email = document.getElementById('sigEmail').value.trim();
        const password = sigPw.value;
        const confirm = sigCf.value;
        if (name.length < 2) { showAlert('Please enter your full name (at least 2 characters).', 'error'); return; }
        if (!email.includes('@')) { showAlert('Please enter a valid email address.', 'error'); return; }
        if (!renderRules(password)) { showAlert('Password does not meet all the required rules. Check the checklist above.', 'error'); return; }
        if (password !== confirm) { showAlert('Passwords do not match.', 'error'); return; }
        const btn = document.getElementById('sigBtn');
        btn.disabled = true; btn.textContent = 'Creating account…';
        try {
          const resp = await fetch('/api/auth/signup/request-code', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, password }),
          });
          const data = await resp.json();
          if (!resp.ok) { throw new Error(data.error || 'Signup failed'); }
          showAlert('✓ Account created successfully! Redirecting to login…', 'success');
          setTimeout(() => { window.location.href = '/login'; }, 1200);
        } catch (err) {
          showAlert(err.message, 'error');
          btn.disabled = false; btn.textContent = 'Create Account';
        }
      });
    </script>
  `));
});

router.get("/forgot-password", (req, res) => {
  return res.send(buildAuthPage("Forgot Password", `
    <div class="card-header">
      <h1>Reset Password</h1>
      <p>Follow the steps below to reset your admin account password.</p>
    </div>

    <!-- Step indicator -->
    <div class="step-bar" id="stepBar">
      <div id="step1ind" class="active"></div>
      <div id="step2ind"></div>
      <div id="step3ind"></div>
    </div>

    <!-- Step 1: Enter email -->
    <div id="step1">
      <p style="font-size:13px;color:#64748b;margin-bottom:14px;">Step 1 of 3 — Enter the email address associated with your admin account.</p>
      <form id="forgotForm" novalidate>
        <label for="forgotEmail">Email Address</label>
        <input type="email" id="forgotEmail" name="email" required autocomplete="email"
               placeholder="admin@example.com"
               title="Enter the email address you used to register your admin account" />
        <button type="submit" class="btn" id="forgotBtn">Send Verification Code</button>
        <div id="forgotStatus" class="status-msg" role="alert" aria-live="polite"></div>
      </form>
    </div>

    <!-- Step 2: Enter the code (hidden until step 1 succeeds) -->
    <div id="step2" style="display:none;">
      <p style="font-size:13px;color:#64748b;margin-bottom:12px;" id="codeInstructions">Step 2 of 3 — Enter the 6-digit verification code.</p>
      <!-- Dev-mode banner (shown only when server returns devCode) -->
      <div id="devBanner" class="alert-box warning" style="display:none;">
        <strong>⚠ Development Mode — SMTP not configured</strong><br/>
        Verification code: <code id="devCodeDisplay" style="font-size:18px;letter-spacing:4px;font-weight:700;color:#fde68a;"></code><br/>
        <span style="font-size:11px;opacity:.8;">Set SMTP credentials in .env and disable ALLOW_EMAIL_CONSOLE_FALLBACK in production.</span>
      </div>
      <div id="emailSentBanner" class="alert-box info" style="display:none;">
        📧 A 6-digit code was sent to <strong id="sentToEmail"></strong>.<br/>
        <span style="font-size:12px;">Check your inbox and spam/junk folder. Code expires in 10 minutes.</span>
      </div>
      <label for="codeInput">Verification Code
        <span style="color: #94a3b8;font-size:11px;margin-left:6px;" title="Enter the 6-digit numeric code from your email.">ⓘ</span>
      </label>
      <input type="text" id="codeInput" inputmode="numeric" maxlength="6" pattern="[0-9]{6}"
             placeholder="1 2 3 4 5 6"
             title="Enter the 6-digit numeric code from your email"
             autocomplete="one-time-code"
             style="letter-spacing:6px;font-size:22px;font-weight:600;text-align:center;" />
      <button type="button" class="btn" id="verifyCodeBtn">Verify Code →</button>
      <div id="codeStatus" class="status-msg" role="alert" aria-live="polite"></div>
      <div class="links" style="margin-top:14px;">
        <a href="#" id="resendLink" title="Click to request a new verification code">↩ Resend code</a>
        <span>|</span>
        <a href="/login">Back to login</a>
      </div>
    </div>

    <!-- Step 3: Set new password (hidden until step 2 succeeds) -->
    <div id="step3" style="display:none;">
      <p style="font-size:13px;color:#64748b;margin-bottom:12px;">Step 3 of 3 — Set your new password.</p>
      <label for="newPw">New Password
        <span style="color: #94a3b8;font-size:11px;margin-left:6px;" title="Min 6 characters, 1 uppercase letter, 1 number, 1 dollar sign ($)">ⓘ</span>
      </label>
      <div class="pw-wrap">
        <input type="password" id="newPw" required autocomplete="new-password"
               placeholder="New password"
               title="Must be 6+ chars with at least one uppercase letter, one number and one $ symbol" />
        <button type="button" class="pw-toggle" onclick="togglePw('newPw',this)" tabindex="-1">👁</button>
      </div>
      <div id="pwHint" class="pw-rules" style="margin-bottom:6px;"></div>
      <label for="confirmPw">Confirm New Password</label>
      <div class="pw-wrap">
        <input type="password" id="confirmPw" required autocomplete="new-password"
               placeholder="Repeat new password" />
        <button type="button" class="pw-toggle" onclick="togglePw('confirmPw',this)" tabindex="-1">👁</button>
      </div>
      <div id="confirmHint" class="hint-text" style="margin-bottom:8px;"></div>
      <button type="button" class="btn" id="resetBtn">Reset Password</button>
      <div id="resetStatus" class="status-msg" role="alert" aria-live="polite"></div>
    </div>

    <div class="links" style="margin-top:16px;">
      <a href="/login">← Back to login</a>
    </div>

    <script>
      const pwRules = { minLen: 6, upper: /[A-Z]/, num: /[0-9]/, dollar: /\\$/ };
      let _email = '', _verifiedCode = '';

      const el = (id) => document.getElementById(id);

      const setStatus = (id, msg, ok) => {
        const e = el(id);
        e.textContent = msg;
        e.style.color = ok === true ? '#86efac' : ok === false ? '#fca5a5' : '#94a3b8';
      };

      const setStepColor = (stepId, active) => {
        el(stepId).style.background = active ? '#2563eb' : '#334155';
      };

      const showStep = (n) => {
        el('step1').style.display = n === 1 ? '' : 'none';
        el('step2').style.display = n === 2 ? '' : 'none';
        el('step3').style.display = n === 3 ? '' : 'none';
        setStepColor('step1ind', n >= 1);
        setStepColor('step2ind', n >= 2);
        setStepColor('step3ind', n >= 3);
      };

      const pwOk = (v) =>
        v.length >= pwRules.minLen && pwRules.upper.test(v) && pwRules.num.test(v) && pwRules.dollar.test(v);

      const renderPwHint = (v) => {
        const ok = (cond, label) =>
          '<div>' + (cond ? '<span style="color:#86efac">✓</span>' : '<span style="color:#fca5a5">✗</span>') + ' ' + label + '</div>';
        el('pwHint').innerHTML =
          ok(v.length >= pwRules.minLen, '6+ characters') +
          ok(pwRules.upper.test(v), 'one uppercase letter') +
          ok(pwRules.num.test(v), 'one number') +
          ok(pwRules.dollar.test(v), 'one $ symbol');
      };

      el('newPw').addEventListener('input', () => {
        renderPwHint(el('newPw').value);
        const match = el('newPw').value === el('confirmPw').value && el('confirmPw').value.length > 0;
        el('confirmHint').textContent = el('confirmPw').value.length ? (match ? '✓ Passwords match' : '✗ Passwords do not match') : '';
        el('confirmHint').style.color = match ? '#86efac' : '#fca5a5';
      });
      el('confirmPw').addEventListener('input', () => {
        const match = el('newPw').value === el('confirmPw').value && el('confirmPw').value.length > 0;
        el('confirmHint').textContent = match ? '✓ Passwords match' : '✗ Passwords do not match';
        el('confirmHint').style.color = match ? '#86efac' : '#fca5a5';
      });

      // Step 1: send code
      el('forgotForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = el('forgotEmail').value.trim();
        if (!email) { setStatus('forgotStatus', 'Please enter your email address.', false); return; }
        el('forgotBtn').disabled = true;
        setStatus('forgotStatus', 'Sending code…', null);

        try {
          const resp = await fetch('/api/auth/password/forgot/request-code', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email }),
          });
          const data = await resp.json();
          if (!resp.ok) throw new Error(data.error || 'Failed to send code');

          _email = data.email || email;
          setStatus('forgotStatus', '', null);

          // Dev mode: show the code in a highlighted banner
          if (data.devCode) {
            el('devBanner').style.display = 'block';
            el('devCodeDisplay').textContent = data.devCode;
            el('codeInstructions').textContent = 'Step 2 of 3 — Code shown below (development mode).';
          } else {
            el('codeInstructions').textContent =
              'Step 2 of 3 — A 6-digit code was sent to ' + _email + '. Check your inbox (and spam folder).';
          }
          showStep(2);
          el('codeInput').focus();
        } catch (err) {
          setStatus('forgotStatus', err.message, false);
          el('forgotBtn').disabled = false;
        }
      });

      // Resend link
      el('resendLink').addEventListener('click', (e) => {
        e.preventDefault();
        showStep(1);
        el('forgotBtn').disabled = false;
        setStatus('forgotStatus', '', null);
        el('forgotEmail').value = _email;
      });

      // Step 2: verify code (just check the code, move to step 3)
      // We delay the actual reset until step 3 so the user enters their new password
      el('verifyCodeBtn').addEventListener('click', () => {
        const code = el('codeInput').value.trim();
        if (!/^[0-9]{6}$/.test(code)) {
          setStatus('codeStatus', 'Enter the 6-digit numeric code from your email.', false);
          return;
        }
        _verifiedCode = code;
        setStatus('codeStatus', '✓ Code accepted. Now set your new password.', true);
        showStep(3);
        renderPwHint('');
        el('newPw').focus();
      });

      // Step 3: reset password
      el('resetBtn').addEventListener('click', async () => {
        const newPassword = el('newPw').value;
        const confirmPw = el('confirmPw').value;

        if (!pwOk(newPassword)) {
          setStatus('resetStatus', 'Password does not meet the required rules.', false);
          return;
        }
        if (newPassword !== confirmPw) {
          setStatus('resetStatus', 'Passwords do not match.', false);
          return;
        }

        el('resetBtn').disabled = true;
        setStatus('resetStatus', 'Resetting password…', null);

        try {
          const resp = await fetch('/api/auth/password/forgot/verify-code', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: _email, code: _verifiedCode, newPassword }),
          });
          const data = await resp.json();
          if (!resp.ok) {
            // If the code was wrong (race condition), go back to step 2
            if (data.error && data.error.toLowerCase().includes('code')) {
              showStep(2);
              setStatus('codeStatus', data.error + ' — please re-enter the code.', false);
            } else {
              throw new Error(data.error || 'Failed to reset password');
            }
            el('resetBtn').disabled = false;
            return;
          }
          setStepColor('step3ind', true);
          setStatus('resetStatus', '✓ ' + (data.message || 'Password reset successfully!') + ' Redirecting to login…', true);
          setTimeout(() => { window.location.href = '/login'; }, 1800);
        } catch (err) {
          setStatus('resetStatus', err.message, false);
          el('resetBtn').disabled = false;
        }
      });

      // Init
      renderPwHint('');
    </script>
  `));
});

// ─────────────────────────────────────────────────────────────────────────────
// OAuth2-style token endpoints
// These let API clients (Postman, scripts, etc.) obtain JWT Bearer tokens
// without browser sessions. The web dashboard continues to use cookies.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * POST /api/oauth/token
 * Supported grant types:
 *   password      – exchange email+password for access+refresh tokens
 *   refresh_token – exchange a valid refresh token for a new access token
 */
router.post("/api/oauth/token", async (req, res) => {
  const esClient = req.app.get("esClient");
  const { grant_type, email, password, refresh_token } = req.body || {};

  if (grant_type === "password") {
    if (!email || !password) {
      return res.status(400).json({ success: false, error: "email and password are required" });
    }
    try {
      const result = await loginAdmin(esClient, { email, password, ipAddress: req.ip });
      if (!result.ok) {
        return res.status(401).json({ success: false, error: result.error });
      }
      const tokens = createTokenPair(result.user);
      return res.json({ success: true, ...tokens });
    } catch (err) {
      console.error("OAuth token (password grant) error:", err.message);
      return res.status(500).json({ success: false, error: "Token generation failed" });
    }
  }

  if (grant_type === "refresh_token") {
    if (!refresh_token) {
      return res.status(400).json({ success: false, error: "refresh_token is required" });
    }
    const payload = verifyJWT(refresh_token);
    if (!payload || payload.type !== "refresh") {
      return res.status(401).json({ success: false, error: "Invalid or expired refresh token" });
    }
    try {
      const user = await getAdminByEmail(esClient, payload.email || "");
      const userSource = user?._source;
      if (!userSource || userSource.status === "deleted") {
        return res.status(401).json({ success: false, error: "Account not found or deleted" });
      }
      const userObj = { id: payload.sub, email: userSource.email, name: userSource.name, role: userSource.role || "admin" };
      const tokens = refreshAccessToken(refresh_token, userObj);
      if (!tokens) {
        return res.status(401).json({ success: false, error: "Refresh token has been revoked" });
      }
      return res.json({ success: true, ...tokens });
    } catch (err) {
      console.error("OAuth token (refresh grant) error:", err.message);
      return res.status(500).json({ success: false, error: "Token refresh failed" });
    }
  }

  return res.status(400).json({
    success: false,
    error: "Unsupported grant_type. Use 'password' or 'refresh_token'.",
  });
});

/**
 * POST /api/oauth/revoke
 * Revoke a refresh token (logout for API clients).
 */
router.post("/api/oauth/revoke", (req, res) => {
  const { token } = req.body || {};
  if (!token) {
    return res.status(400).json({ success: false, error: "token is required" });
  }
  const revoked = revokeRefreshToken(token);
  return res.json({ success: true, revoked });
});

/**
 * GET /api/oauth/config
 * Returns OAuth2 configuration info (for API clients to discover endpoints).
 */
router.get("/api/oauth/config", (req, res) => {
  const base = `${req.protocol}://${req.get("host")}`;
  return res.json({
    issuer: base,
    token_endpoint: `${base}/api/oauth/token`,
    revocation_endpoint: `${base}/api/oauth/revoke`,
    grant_types_supported: ["password", "refresh_token"],
    token_endpoint_auth_methods_supported: ["client_secret_post"],
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Improved change-password page (requires active session)
// ─────────────────────────────────────────────────────────────────────────────

router.get("/change-password", requireAdminSession, (req, res) => {
  const displayName = String(req.session?.user?.name || req.jwtUser?.name || "Admin");
  const displayEmail = String(req.session?.user?.email || req.jwtUser?.email || "");
  return res.send(buildAuthPage("Change Password", `
    <div class="card-header">
      <h1>Change Password</h1>
      <p>Signed in as <strong style="color:#e2e8f0">${displayName}</strong>${displayEmail ? ' (' + displayEmail + ')' : ''}.</p>
    </div>
    <div id="changeAlert" class="status-msg" role="alert" aria-live="polite"></div>
    <form id="changeForm" novalidate autocomplete="off">
      <label for="currentPassword">Current Password</label>
      <div class="pw-wrap">
        <input type="password" id="currentPassword" required autocomplete="current-password"
               placeholder="Your current password"
               title="Enter the password you currently use to sign in" />
        <button type="button" class="pw-toggle" onclick="togglePw('currentPassword',this)" tabindex="-1">👁</button>
      </div>
      <label for="newPassword">New Password
        <span style="color: #94a3b8;font-size:11px;margin-left:6px;" title="Min 6 chars, 1 uppercase, 1 number, 1 dollar sign">ⓘ</span>
      </label>
      <div class="pw-wrap">
        <input type="password" id="newPassword" required autocomplete="new-password"
               placeholder="New strong password"
               title="Must be 6+ characters with at least one uppercase letter, one number and one dollar sign ($)" />
        <button type="button" class="pw-toggle" onclick="togglePw('newPassword',this)" tabindex="-1">👁</button>
      </div>
      <div id="changePasswordHint" class="pw-rules" style="margin-bottom:6px;"></div>
      <label for="confirmNewPassword">Confirm New Password</label>
      <div class="pw-wrap">
        <input type="password" id="confirmNewPassword" required autocomplete="new-password"
               placeholder="Repeat new password" />
        <button type="button" class="pw-toggle" onclick="togglePw('confirmNewPassword',this)" tabindex="-1">👁</button>
      </div>
      <div id="confirmPwHint" class="hint-text" style="margin-bottom:8px;"></div>
      <button type="submit" class="btn" id="changeBtn">Update Password</button>
    </form>
    <div class="links" style="margin-top:16px;"><a href="/">← Back to dashboard</a></div>
    <script>
      function togglePw(id, btn) {
        const inp = document.getElementById(id);
        if (inp.type === 'password') { inp.type = 'text'; btn.textContent = '🙈'; }
        else { inp.type = 'password'; btn.textContent = '👁'; }
      }
      const pwRules = { minLen: 6, upper: /[A-Z]/, num: /[0-9]/, dollar: /\\$/ };
      const newPwInput = document.getElementById('newPassword');
      const confirmPwInput = document.getElementById('confirmNewPassword');
      const hint = document.getElementById('changePasswordHint');
      const confirmHint = document.getElementById('confirmPwHint');
      const changeBtn = document.getElementById('changeBtn');
      function showAlert(msg, type) {
        const a = document.getElementById('changeAlert');
        a.textContent = msg; a.className = 'status-msg show ' + (type||'info');
      }
      const ok = (c, l) => '<div><span style="color:' + (c ? '#86efac' : '#fca5a5') + '">' + (c?'✓':'✗') + '</span> ' + l + '</div>';
      const renderHint = () => {
        const v = newPwInput.value;
        hint.innerHTML = ok(v.length>=pwRules.minLen,'6+ characters') + ok(pwRules.upper.test(v),'one uppercase letter') + ok(pwRules.num.test(v),'one number') + ok(pwRules.dollar.test(v),'one \\$ symbol');
        if (confirmPwInput.value.length) {
          const m = v === confirmPwInput.value;
          confirmHint.textContent = m ? '✓ Passwords match' : '✗ Passwords do not match';
          confirmHint.style.color = m ? '#86efac' : '#fca5a5';
        }
      };
      newPwInput.addEventListener('input', renderHint);
      confirmPwInput.addEventListener('input', () => {
        const m = newPwInput.value === confirmPwInput.value && confirmPwInput.value.length > 0;
        confirmHint.textContent = m ? '✓ Passwords match' : '✗ Passwords do not match';
        confirmHint.style.color = m ? '#86efac' : '#fca5a5';
      });
      document.getElementById('changeForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const cur = document.getElementById('currentPassword').value;
        const nw = newPwInput.value;
        const conf = confirmPwInput.value;
        if (!cur) { showAlert('Please enter your current password.', 'error'); return; }
        const pwValid = nw.length>=pwRules.minLen && pwRules.upper.test(nw) && pwRules.num.test(nw) && pwRules.dollar.test(nw);
        if (!pwValid) { showAlert('New password does not meet all the required rules. Check the checklist above.', 'error'); return; }
        if (nw !== conf) { showAlert('Passwords do not match.', 'error'); return; }
        if (cur === nw) { showAlert('New password must be different from your current password.', 'error'); return; }
        changeBtn.disabled = true; changeBtn.textContent = 'Updating…';
        try {
          const resp = await fetch('/api/auth/password/change', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ currentPassword: cur, newPassword: nw }),
          });
          const data = await resp.json();
          if (!resp.ok) throw new Error(data.error || 'Failed to change password');
          showAlert('✓ ' + (data.message || 'Password updated successfully!'), 'success');
          document.getElementById('currentPassword').value = '';
          newPwInput.value = ''; confirmPwInput.value = '';
          hint.innerHTML = ''; confirmHint.textContent = '';
        } catch (err) {
          showAlert(err.message, 'error');
        }
        changeBtn.disabled = false; changeBtn.textContent = 'Update Password';
      });
      renderHint();
    </script>
  `));
});

module.exports = router;