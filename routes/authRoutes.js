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

const buildAuthPage = (title, body) => `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title}</title>
  <style>
    body { font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; min-height: 100vh; display: grid; place-items: center; }
    .card { width: min(520px, calc(100vw - 24px)); background: #111827; border: 1px solid #334155; border-radius: 16px; padding: 24px; box-shadow: 0 12px 30px rgba(0,0,0,.35); }
    h1 { margin: 0 0 12px; font-size: 28px; }
    p, label { color: #cbd5e1; }
    input, button, textarea { width: 100%; box-sizing: border-box; padding: 12px 14px; margin: 6px 0 14px; border-radius: 10px; border: 1px solid #334155; background: #0f172a; color: #e2e8f0; }
    button { background: #2563eb; border: none; font-weight: 700; cursor: pointer; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .hint { font-size: 13px; color: #94a3b8; }
    .error { color: #fca5a5; }
    .success { color: #86efac; }
  </style>
</head>
<body>
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

  try {
    const result = await requestForgotPasswordCode(esClient, email);
    if (!result.ok) {
      return res.status(400).json({ success: false, error: result.error });
    }

    return res.json({
      success: true,
      message: "Password reset verification code generated",
      email: result.email,
      code: result.code,
      nextStep: "verify-code-and-reset-password",
    });
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

router.post("/api/auth/password/change", async (req, res) => {
  const esClient = req.app.get("esClient");
  const { email, currentPassword, newPassword } = req.body || {};

  try {
    const result = await changeAdminPassword(esClient, {
      email: sanitizeEmail(email || req.session?.user?.email),
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

router.post("/api/auth/delete/request-code", async (req, res) => {
  const esClient = req.app.get("esClient");
  const email = sanitizeEmail(req.body?.email || req.session?.user?.email);
  if (!email) {
    return res.status(400).json({ success: false, error: "Email is required" });
  }

  try {
    const result = await requestPasswordResetOrConfirmDelete(esClient, email);
    if (!result.ok) {
      return res.status(400).json({ success: false, error: result.error });
    }

    return res.json({
      success: true,
      message: "Delete confirmation code generated",
      code: result.code,
      nextStep: "confirm-delete-code",
    });
  } catch (err) {
    console.error("Delete request error:", err.message);
    return res.status(500).json({ success: false, error: "Failed to request delete code" });
  }
});

router.delete("/api/auth/delete/confirm", async (req, res) => {
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

router.get("/api/auth/admin/users", async (req, res) => {
  const esClient = req.app.get("esClient");
  try {
    const users = await listAdmins(esClient);
    return res.json({ success: true, total: users.length, users });
  } catch (err) {
    console.error("List users error:", err.message);
    return res.status(500).json({ success: false, error: "Failed to list users" });
  }
});

router.delete("/api/auth/admin/users/:userId", async (req, res) => {
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
  return res.send(buildAuthPage("Admin Login", `
    <h1>Admin Login</h1>
    <p class="hint">Use your verified admin email and password.</p>
    <form method="POST" action="/api/auth/login">
      <label>Email</label>
      <input type="email" name="email" required />
      <label>Password</label>
      <input type="password" name="password" required />
      <button type="submit">Login</button>
    </form>
    <p class="hint">Need an account? <a href="/signup" style="color:#60a5fa;">Sign up</a></p>
    <p class="hint"><a href="/forgot-password" style="color:#60a5fa;">Forgot password?</a></p>
    <p class="hint"><a href="/change-password" style="color:#60a5fa;">Change password (logged in)</a></p>
  `));
});

router.get("/signup", (req, res) => {
  return res.send(buildAuthPage("Admin Signup", `
    <h1>Admin Signup</h1>
    <p class="hint">Password must be 6+ characters and include at least one uppercase letter, one number, and one $ symbol. Account will be created directly.</p>
    <form id="signupForm" novalidate>
      <label>Name</label>
      <input type="text" id="name" name="name" required />
      <label>Email</label>
      <input type="email" id="email" name="email" autocomplete="email" required />
      <label>Password</label>
      <input type="password" id="password" name="password" required />
      <div class="hint" id="passwordHint">Enter a password that matches the rules above.</div>

      <button type="submit" id="submitBtn">Create Account</button>
      <div id="formStatus" class="hint"></div>
    </form>

    <script>
      const passwordRules = {
        minLength: 6,
        uppercase: /[A-Z]/,
        number: /[0-9]/,
        dollar: /\$/,
      };

      const signupForm = document.getElementById('signupForm');
      const passwordInput = document.getElementById('password');
      const passwordHint = document.getElementById('passwordHint');
      const submitBtn = document.getElementById('submitBtn');
      const formStatus = document.getElementById('formStatus');

      const fields = {
        name: document.getElementById('name'),
        email: document.getElementById('email'),
      };

      const updatePasswordState = () => {
        const value = passwordInput.value;
        const okLength = value.length >= passwordRules.minLength;
        const okUppercase = passwordRules.uppercase.test(value);
        const okNumber = passwordRules.number.test(value);
        const okDollar = passwordRules.dollar.test(value);
        const ok = okLength && okUppercase && okNumber && okDollar;

        passwordHint.innerHTML = [
          okLength ? '✓ 6+ characters' : '✗ 6+ characters',
          okUppercase ? '✓ one uppercase letter' : '✗ one uppercase letter',
          okNumber ? '✓ one number' : '✗ one number',
          okDollar ? '✓ one $ symbol' : '✗ one $ symbol',
        ].map((item) => '<div>' + item + '</div>').join('');
        passwordHint.style.color = ok ? '#86efac' : '#fca5a5';
        return ok;
      };

      const updateSubmitState = () => {
        updatePasswordState();
        submitBtn.disabled = false;
      }

      passwordInput.addEventListener('input', updateSubmitState);
      fields.name.addEventListener('input', updateSubmitState);
      fields.email.addEventListener('input', updateSubmitState);

      signupForm.addEventListener('submit', async (event) => {
        event.preventDefault();

        const passwordOk = updatePasswordState();
        const basicFieldsOk = fields.name.value.trim().length > 1;

        if (!passwordOk) {
          formStatus.textContent = 'Password does not meet the required rules.';
          formStatus.style.color = '#fca5a5';
          return;
        }

        if (!basicFieldsOk) {
          formStatus.textContent = 'Please fill the name field.';
          formStatus.style.color = '#fca5a5';
          return;
        }

        submitBtn.disabled = true;
        formStatus.textContent = 'Creating account...';
        formStatus.style.color = '#94a3b8';

        try {
          const response = await fetch('/api/auth/signup/request-code', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              name: fields.name.value.trim(),
              email: fields.email.value.trim(),
              password: passwordInput.value,
            }),
          });

          const data = await response.json();
          if (!response.ok) {
            throw new Error(data.error || 'Signup request failed');
          }

          formStatus.textContent = 'Account created successfully. Redirecting...';
          formStatus.style.color = '#86efac';
          window.setTimeout(() => {
            window.location.href = '/dashboard';
          }, 600);
        } catch (error) {
          formStatus.textContent = error.message;
          formStatus.style.color = '#fca5a5';
          submitBtn.disabled = false;
        }
      });

      updateSubmitState();
    </script>
  `));
});

router.get("/forgot-password", (req, res) => {
  return res.send(buildAuthPage("Forgot Password", `
    <h1>Forgot Password</h1>
    <p class="hint">Generate a verification code, then reset your password.</p>

    <form id="forgotForm" novalidate>
      <label>Email</label>
      <input type="email" id="forgotEmail" required />
      <button type="submit" id="forgotBtn">Send Verification Code</button>
      <div id="forgotStatus" class="hint"></div>
    </form>

    <div id="resetPanel" style="display:none; margin-top: 18px; padding-top: 12px; border-top: 1px solid #334155;">
      <label>Email</label>
      <input type="email" id="resetEmail" required />
      <label>Verification Code</label>
      <input type="text" id="resetCode" required />
      <label>New Password</label>
      <input type="password" id="resetNewPassword" required />
      <div class="hint" id="resetPasswordHint">Password must be 6+ characters with uppercase, number, and $ symbol.</div>
      <button type="button" id="resetBtn">Verify Code & Reset Password</button>
      <div id="resetStatus" class="hint"></div>
    </div>

    <p class="hint"><a href="/login" style="color:#60a5fa;">Back to login</a></p>

    <script>
      const passwordRules = {
        minLength: 6,
        uppercase: /[A-Z]/,
        number: /[0-9]/,
        dollar: /\$/,
      };

      const forgotForm = document.getElementById('forgotForm');
      const forgotEmail = document.getElementById('forgotEmail');
      const forgotBtn = document.getElementById('forgotBtn');
      const forgotStatus = document.getElementById('forgotStatus');
      const resetPanel = document.getElementById('resetPanel');
      const resetEmail = document.getElementById('resetEmail');
      const resetCode = document.getElementById('resetCode');
      const resetNewPassword = document.getElementById('resetNewPassword');
      const resetPasswordHint = document.getElementById('resetPasswordHint');
      const resetBtn = document.getElementById('resetBtn');
      const resetStatus = document.getElementById('resetStatus');

      const updateResetPasswordHint = () => {
        const value = resetNewPassword.value;
        const okLength = value.length >= passwordRules.minLength;
        const okUppercase = passwordRules.uppercase.test(value);
        const okNumber = passwordRules.number.test(value);
        const okDollar = passwordRules.dollar.test(value);
        const ok = okLength && okUppercase && okNumber && okDollar;

        resetPasswordHint.innerHTML = [
          okLength ? '✓ 6+ characters' : '✗ 6+ characters',
          okUppercase ? '✓ one uppercase letter' : '✗ one uppercase letter',
          okNumber ? '✓ one number' : '✗ one number',
          okDollar ? '✓ one $ symbol' : '✗ one $ symbol',
        ].map((item) => '<div>' + item + '</div>').join('');
        resetPasswordHint.style.color = ok ? '#86efac' : '#fca5a5';
        return ok;
      };

      forgotForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        forgotBtn.disabled = true;
        forgotStatus.textContent = 'Sending code...';
        forgotStatus.style.color = '#94a3b8';

        try {
          const response = await fetch('/api/auth/password/forgot/request-code', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: forgotEmail.value.trim() }),
          });

          const data = await response.json();
          if (!response.ok) {
            throw new Error(data.error || 'Failed to send verification code');
          }

          forgotStatus.textContent = (data.message || 'Verification code generated') + '. Code: ' + data.code;
          forgotStatus.style.color = '#86efac';
          resetEmail.value = forgotEmail.value.trim();
          resetCode.value = String(data.code || '');
          resetPanel.style.display = 'block';
          resetCode.focus();
        } catch (error) {
          forgotStatus.textContent = error.message;
          forgotStatus.style.color = '#fca5a5';
          forgotBtn.disabled = false;
        }
      });

      resetNewPassword.addEventListener('input', updateResetPasswordHint);

      resetBtn.addEventListener('click', async () => {
        const passwordOk = updateResetPasswordHint();
        if (!passwordOk) {
          resetStatus.textContent = 'New password does not meet required rules.';
          resetStatus.style.color = '#fca5a5';
          return;
        }

        resetBtn.disabled = true;
        resetStatus.textContent = 'Verifying code and resetting password...';
        resetStatus.style.color = '#94a3b8';

        try {
          const response = await fetch('/api/auth/password/forgot/verify-code', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              email: resetEmail.value.trim(),
              code: resetCode.value.trim(),
              newPassword: resetNewPassword.value,
            }),
          });

          const data = await response.json();
          if (!response.ok) {
            throw new Error(data.error || 'Failed to reset password');
          }

          resetStatus.textContent = data.message || 'Password reset successful. Redirecting to login...';
          resetStatus.style.color = '#86efac';
          window.setTimeout(() => {
            window.location.href = '/login';
          }, 1200);
        } catch (error) {
          resetStatus.textContent = error.message;
          resetStatus.style.color = '#fca5a5';
          resetBtn.disabled = false;
        }
      });

      updateResetPasswordHint();
    </script>
  `));
});

router.get("/change-password", (req, res) => {
  return res.send(buildAuthPage("Change Password", `
    <h1>Change Password</h1>
    <p class="hint">You must be logged in to change password.</p>

    <form id="changeForm" novalidate>
      <label>Current Password</label>
      <input type="password" id="currentPassword" required />
      <label>New Password</label>
      <input type="password" id="newPassword" required />
      <div class="hint" id="changePasswordHint">Password must be 6+ characters with uppercase, number, and $ symbol.</div>
      <button type="submit" id="changeBtn">Change Password</button>
      <div id="changeStatus" class="hint"></div>
    </form>

    <p class="hint"><a href="/dashboard" style="color:#60a5fa;">Back to dashboard</a></p>

    <script>
      const passwordRules = {
        minLength: 6,
        uppercase: /[A-Z]/,
        number: /[0-9]/,
        dollar: /\$/,
      };

      const changeForm = document.getElementById('changeForm');
      const currentPasswordInput = document.getElementById('currentPassword');
      const newPasswordInput = document.getElementById('newPassword');
      const changePasswordHint = document.getElementById('changePasswordHint');
      const changeBtn = document.getElementById('changeBtn');
      const changeStatus = document.getElementById('changeStatus');

      const updateNewPasswordHint = () => {
        const value = newPasswordInput.value;
        const okLength = value.length >= passwordRules.minLength;
        const okUppercase = passwordRules.uppercase.test(value);
        const okNumber = passwordRules.number.test(value);
        const okDollar = passwordRules.dollar.test(value);
        const ok = okLength && okUppercase && okNumber && okDollar;

        changePasswordHint.innerHTML = [
          okLength ? '✓ 6+ characters' : '✗ 6+ characters',
          okUppercase ? '✓ one uppercase letter' : '✗ one uppercase letter',
          okNumber ? '✓ one number' : '✗ one number',
          okDollar ? '✓ one $ symbol' : '✗ one $ symbol',
        ].map((item) => '<div>' + item + '</div>').join('');
        changePasswordHint.style.color = ok ? '#86efac' : '#fca5a5';
        return ok;
      };

      newPasswordInput.addEventListener('input', updateNewPasswordHint);

      changeForm.addEventListener('submit', async (event) => {
        event.preventDefault();

        const passwordOk = updateNewPasswordHint();
        if (!passwordOk) {
          changeStatus.textContent = 'New password does not meet required rules.';
          changeStatus.style.color = '#fca5a5';
          return;
        }

        changeBtn.disabled = true;
        changeStatus.textContent = 'Changing password...';
        changeStatus.style.color = '#94a3b8';

        try {
          const response = await fetch('/api/auth/password/change', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              currentPassword: currentPasswordInput.value,
              newPassword: newPasswordInput.value,
            }),
          });

          const data = await response.json();
          if (!response.ok) {
            throw new Error(data.error || 'Failed to change password');
          }

          changeStatus.textContent = data.message || 'Password changed successfully.';
          changeStatus.style.color = '#86efac';
          currentPasswordInput.value = '';
          newPasswordInput.value = '';
          updateNewPasswordHint();
          changeBtn.disabled = false;
        } catch (error) {
          changeStatus.textContent = error.message;
          changeStatus.style.color = '#fca5a5';
          changeBtn.disabled = false;
        }
      });

      updateNewPasswordHint();
    </script>
  `));
});

module.exports = router;