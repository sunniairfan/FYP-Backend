const bcrypt = require("bcrypt");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const ADMIN_USERS_INDEX = "admin_users";
const ADMIN_PENDING_INDEX = "admin_pending_signups";
const ADMIN_CHALLENGES_INDEX = "admin_signup_challenges";
const ADMIN_AUDIT_INDEX = "admin_audit_log";

const PASSWORD_POLICY = {
  minLength: 6,
  maxLength: 128,
};

const sanitizeEmail = (email) => String(email || "").trim().toLowerCase();
const sanitizeName = (name) => String(name || "").trim().replace(/\s+/g, " ").toLowerCase();

const isValidEmail = (email) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sanitizeEmail(email));

const isStrongPassword = (password) => {
  if (typeof password !== "string") return false;
  if (password.length < PASSWORD_POLICY.minLength || password.length > PASSWORD_POLICY.maxLength) {
    return false;
  }
  if (/\s/.test(password)) return false;
  return /[A-Z]/.test(password)
    && /[0-9]/.test(password)
    && /\$/.test(password);
};

const passwordPolicyMessage = () =>
  `Password must be ${PASSWORD_POLICY.minLength}+ characters and include at least one uppercase letter, one number, and one $ symbol.`;

const hashValue = (value) =>
  crypto.createHash("sha256").update(String(value)).digest("hex");

const generateNumericCode = (length = 6) => {
  const min = 10 ** (length - 1);
  const max = 10 ** length;
  return String(crypto.randomInt(min, max));
};

const generateChallenge = () => {
  const targetIndex = crypto.randomInt(0, 9);
  return {
    question: "Move your cursor to the highlighted square and click it.",
    answer: String(targetIndex),
    targetIndex,
    gridSize: 9,
  };
};

const getUserId = (email) => `admin_${hashValue(email)}`;

const getNowIso = () => new Date().toISOString();

const getExpiryIso = (minutes) => new Date(Date.now() + minutes * 60 * 1000).toISOString();

const ensureAdminAuthIndices = async (esClient) => {
  if (!esClient) return;

  const createIfMissing = async (index, mappings) => {
    const existsResp = await esClient.indices.exists({ index });
    const exists = existsResp.body === true || existsResp === true;
    if (!exists) {
      await esClient.indices.create({ index, mappings: { properties: mappings } });
    }
  };

  await createIfMissing(ADMIN_USERS_INDEX, {
    email: { type: "keyword" },
    emailNormalized: { type: "keyword" },
    name: { type: "text" },
    nameNormalized: { type: "keyword" },
    passwordHash: { type: "keyword", index: false },
    role: { type: "keyword" },
    status: { type: "keyword" },
    isVerified: { type: "boolean" },
    createdAt: { type: "date" },
    updatedAt: { type: "date" },
    verifiedAt: { type: "date" },
    lastLoginAt: { type: "date" },
    lastLoginIp: { type: "keyword" },
    failedLoginAttempts: { type: "integer" },
    lockUntil: { type: "date" },
    deletedAt: { type: "date" },
  });

  await createIfMissing(ADMIN_PENDING_INDEX, {
    email: { type: "keyword" },
    emailNormalized: { type: "keyword" },
    name: { type: "text" },
    nameNormalized: { type: "keyword" },
    passwordHash: { type: "keyword", index: false },
    codeHash: { type: "keyword", index: false },
    challengeId: { type: "keyword" },
    challengeAnswerHash: { type: "keyword", index: false },
    challengeQuestion: { type: "text" },
    challengeExpiresAt: { type: "date" },
    codeExpiresAt: { type: "date" },
    createdAt: { type: "date" },
    updatedAt: { type: "date" },
    attempts: { type: "integer" },
    verifiedAt: { type: "date" },
  });

  await createIfMissing(ADMIN_CHALLENGES_INDEX, {
    challengeId: { type: "keyword" },
    question: { type: "text" },
    answerHash: { type: "keyword", index: false },
    createdAt: { type: "date" },
    expiresAt: { type: "date" },
    usedAt: { type: "date" },
  });

  await createIfMissing(ADMIN_AUDIT_INDEX, {
    action: { type: "keyword" },
    actorId: { type: "keyword" },
    actorEmail: { type: "keyword" },
    targetId: { type: "keyword" },
    targetEmail: { type: "keyword" },
    details: { type: "object" },
    createdAt: { type: "date" },
  });
};

const createAuditEntry = async (esClient, entry) => {
  if (!esClient) return;
  await esClient.index({
    index: ADMIN_AUDIT_INDEX,
    document: {
      ...entry,
      createdAt: getNowIso(),
    },
  });
};

const getAdminByEmail = async (esClient, email) => {
  const normalizedEmail = sanitizeEmail(email);
  if (!esClient || !normalizedEmail) return null;

  try {
    const response = await esClient.search({
      index: ADMIN_USERS_INDEX,
      size: 1,
      query: {
        bool: {
          filter: [
            { term: { emailNormalized: normalizedEmail } },
          ],
        },
      },
    });
    return response.hits?.hits?.[0] || null;
  } catch (err) {
    if (err?.meta?.statusCode === 404) return null;
    throw err;
  }
};

const getAdminById = async (esClient, userId) => {
  if (!esClient || !userId) return null;
  try {
    const response = await esClient.get({ index: ADMIN_USERS_INDEX, id: userId });
    return response?._source ? { _id: response._id, _source: response._source } : null;
  } catch (err) {
    if (err?.meta?.statusCode === 404) return null;
    throw err;
  }
};

const listAdmins = async (esClient, { limit = 100 } = {}) => {
  const response = await esClient.search({
    index: ADMIN_USERS_INDEX,
    size: Math.min(limit, 200),
    sort: [{ createdAt: { order: "desc" } }],
    query: {
      bool: {
        must_not: [
          { term: { status: "deleted" } },
        ],
      },
    },
  });

  return (response.hits?.hits || []).map((hit) => ({ id: hit._id, ...hit._source }));
};

const getSignupChallenge = async (esClient) => {
  const challenge = generateChallenge();
  const challengeId = crypto.randomUUID();
  const answerHash = hashValue(`${challengeId}:${challenge.answer}`);
  const now = getNowIso();
  const expiresAt = getExpiryIso(15);

  await esClient.index({
    index: ADMIN_CHALLENGES_INDEX,
    id: challengeId,
    document: {
      challengeId,
      question: challenge.question,
      answerHash,
      createdAt: now,
      expiresAt,
    },
  });

  return { challengeId, question: challenge.question, expiresAt };
};

const verifyChallenge = async (esClient, challengeId, answer) => {
  if (!esClient || !challengeId) {
    return { ok: false, error: "Challenge is required" };
  }

  const challenge = await esClient.get({ index: ADMIN_CHALLENGES_INDEX, id: challengeId }).catch((err) => {
    if (err?.meta?.statusCode === 404) return null;
    throw err;
  });

  if (!challenge?._source) {
    return { ok: false, error: "Challenge not found" };
  }

  const source = challenge._source;
  if (new Date(source.expiresAt).getTime() < Date.now()) {
    return { ok: false, error: "Challenge expired" };
  }

  const providedHash = hashValue(`${challengeId}:${String(answer).trim()}`);
  const stored = Buffer.from(source.answerHash, "hex");
  const provided = Buffer.from(providedHash, "hex");

  if (stored.length !== provided.length || !crypto.timingSafeEqual(stored, provided)) {
    return { ok: false, error: "Invalid human verification answer" };
  }

  await esClient.update({
    index: ADMIN_CHALLENGES_INDEX,
    id: challengeId,
    body: { doc: { usedAt: getNowIso() } },
  });

  return { ok: true };
};

const queuePendingSignup = async (esClient, payload) => {
  const { name, email, password } = payload;
  const normalizedEmail = sanitizeEmail(email);
  const normalizedName = sanitizeName(name);

  if (!isValidEmail(normalizedEmail)) {
    return { ok: false, error: "not valid email" };
  }
  if (!name || String(name).trim().length < 2) {
    return { ok: false, error: "Name is required" };
  }
  if (!isStrongPassword(password)) {
    return { ok: false, error: passwordPolicyMessage() };
  }

  const existingUser = await getAdminByEmail(esClient, normalizedEmail);
  if (existingUser) {
    return { ok: false, error: "An account with this email already exists" };
  }

  const existingUserByName = await getAdminByName(esClient, normalizedName);
  if (existingUserByName) {
    return { ok: false, error: "An account with this name already exists" };
  }

  const pendingByEmail = await getPendingByEmail(esClient, normalizedEmail);
  if (pendingByEmail) {
    return { ok: false, error: "A signup request for this email already exists. Please verify your code." };
  }

  const pendingByName = await getPendingByName(esClient, normalizedName);
  if (pendingByName) {
    return { ok: false, error: "A signup request for this name already exists. Please verify your code." };
  }

  const pendingId = getUserId(normalizedEmail);
  const code = generateNumericCode(6);
  const codeHash = hashValue(code);
  const passwordHash = await bcrypt.hash(password, 12);
  const now = getNowIso();
  const expiresAt = getExpiryIso(15);

  await esClient.index({
    index: ADMIN_PENDING_INDEX,
    id: pendingId,
    document: {
      email: normalizedEmail,
      emailNormalized: normalizedEmail,
      name: String(name).trim(),
      nameNormalized: normalizedName,
      passwordHash,
      codeHash,
      codeExpiresAt: expiresAt,
      createdAt: now,
      updatedAt: now,
      attempts: 0,
    },
  });

  return {
    ok: true,
    pendingId,
    code,
    expiresAt,
    email: normalizedEmail,
    name: String(name).trim(),
  };
};

const verifyPendingSignup = async (esClient, { email, code }) => {
  const normalizedEmail = sanitizeEmail(email);
  const pendingId = getUserId(normalizedEmail);
  const pending = await esClient.get({ index: ADMIN_PENDING_INDEX, id: pendingId }).catch((err) => {
    if (err?.meta?.statusCode === 404) return null;
    throw err;
  });

  if (!pending?._source) {
    return { ok: false, error: "No pending signup found for this email" };
  }

  const source = pending._source;
  if (new Date(source.codeExpiresAt).getTime() < Date.now()) {
    return { ok: false, error: "Verification code expired. Please request a new one." };
  }

  const providedHash = hashValue(String(code).trim());
  const stored = Buffer.from(source.codeHash, "hex");
  const provided = Buffer.from(providedHash, "hex");

  if (stored.length !== provided.length || !crypto.timingSafeEqual(stored, provided)) {
    await esClient.update({
      index: ADMIN_PENDING_INDEX,
      id: pendingId,
      body: { doc: { attempts: (source.attempts || 0) + 1, updatedAt: getNowIso() } },
    });
    return { ok: false, error: "Invalid verification code" };
  }

  const userId = getUserId(normalizedEmail);
  const existingUserByName = await getAdminByName(esClient, source.name);
  if (existingUserByName && existingUserByName._id !== userId) {
    return { ok: false, error: "An account with this name already exists" };
  }

  const now = getNowIso();
  await esClient.index({
    index: ADMIN_USERS_INDEX,
    id: userId,
    document: {
      email: source.email,
      emailNormalized: source.emailNormalized,
      name: source.name,
      nameNormalized: source.nameNormalized || sanitizeName(source.name),
      passwordHash: source.passwordHash,
      role: "admin",
      status: "active",
      isVerified: true,
      createdAt: now,
      updatedAt: now,
      verifiedAt: now,
      failedLoginAttempts: 0,
    },
  });

  await esClient.delete({ index: ADMIN_PENDING_INDEX, id: pendingId }).catch(() => {});
  await createAuditEntry(esClient, {
    action: "signup_verified",
    targetId: userId,
    targetEmail: source.email,
    details: { role: "admin" },
  });

  return { ok: true, userId, email: source.email, name: source.name };
};

const loginAdmin = async (esClient, { email, password, ipAddress }) => {
  const normalizedEmail = sanitizeEmail(email);
  const user = await getAdminByEmail(esClient, normalizedEmail);

  if (!user?._source || user._source.status === "deleted") {
    return { ok: false, error: "Invalid email or password" };
  }

  const source = user._source;
  if (!source.isVerified) {
    return { ok: false, error: "Account is not verified yet" };
  }

  if (source.lockUntil && new Date(source.lockUntil).getTime() > Date.now()) {
    return { ok: false, error: "Account temporarily locked. Try again later." };
  }

  const passwordMatches = await bcrypt.compare(String(password || ""), source.passwordHash);
  if (!passwordMatches) {
    const failedLoginAttempts = (source.failedLoginAttempts || 0) + 1;
    const updateDoc = { failedLoginAttempts, updatedAt: getNowIso() };
    if (failedLoginAttempts >= 5) {
      updateDoc.lockUntil = getExpiryIso(15);
    }

    await esClient.update({
      index: ADMIN_USERS_INDEX,
      id: user._id,
      body: { doc: updateDoc },
    });

    return { ok: false, error: "Invalid email or password" };
  }

  const now = getNowIso();
  await esClient.update({
    index: ADMIN_USERS_INDEX,
    id: user._id,
    body: {
      doc: {
        failedLoginAttempts: 0,
        lockUntil: null,
        lastLoginAt: now,
        lastLoginIp: ipAddress || null,
        updatedAt: now,
      },
    },
  });

  await createAuditEntry(esClient, {
    action: "login_success",
    actorId: user._id,
    actorEmail: source.email,
    details: { ipAddress: ipAddress || null },
  });

  return {
    ok: true,
    user: {
      id: user._id,
      email: source.email,
      name: source.name,
      role: source.role || "admin",
    },
  };
};

const softDeleteAdminAccount = async (esClient, userId, actor = {}) => {
  const user = await getAdminById(esClient, userId);
  if (!user?._source) {
    return { ok: false, error: "Account not found" };
  }

  const now = getNowIso();
  await esClient.update({
    index: ADMIN_USERS_INDEX,
    id: userId,
    body: {
      doc: {
        status: "deleted",
        isVerified: false,
        deletedAt: now,
        updatedAt: now,
      },
    },
  });

  await esClient.delete({ index: ADMIN_PENDING_INDEX, id: userId }).catch(() => {});
  await createAuditEntry(esClient, {
    action: "account_deleted",
    actorId: actor.actorId || null,
    actorEmail: actor.actorEmail || null,
    targetId: userId,
    targetEmail: user._source.email,
    details: { selfDelete: Boolean(actor.selfDelete) },
  });

  return { ok: true };
};

const requestPasswordResetOrConfirmDelete = async (esClient, email) => {
  const normalizedEmail = sanitizeEmail(email);
  const user = await getAdminByEmail(esClient, normalizedEmail);
  if (!user?._source || user._source.status === "deleted") {
    return { ok: false, error: "Account not found" };
  }

  const code = generateNumericCode(6);
  const codeHash = hashValue(code);
  const now = getNowIso();
  await esClient.index({
    index: ADMIN_PENDING_INDEX,
    id: `${user._id}_delete`,
    document: {
      email: normalizedEmail,
      emailNormalized: normalizedEmail,
      name: user._source.name,
      nameNormalized: user._source.nameNormalized || sanitizeName(user._source.name),
      passwordHash: user._source.passwordHash,
      codeHash,
      challengeId: null,
      challengeQuestion: null,
      challengeExpiresAt: getExpiryIso(10),
      codeExpiresAt: getExpiryIso(10),
      createdAt: now,
      updatedAt: now,
      attempts: 0,
      purpose: "delete_account",
    },
  });

  return { ok: true, code, email: normalizedEmail };
};

const verifyDeleteCode = async (esClient, { email, code }) => {
  const normalizedEmail = sanitizeEmail(email);
  const user = await getAdminByEmail(esClient, normalizedEmail);
  if (!user?._source) {
    return { ok: false, error: "Account not found" };
  }

  const pendingId = `${user._id}_delete`;
  const pending = await esClient.get({ index: ADMIN_PENDING_INDEX, id: pendingId }).catch((err) => {
    if (err?.meta?.statusCode === 404) return null;
    throw err;
  });

  if (!pending?._source) {
    return { ok: false, error: "Delete verification not found" };
  }

  if (new Date(pending._source.codeExpiresAt).getTime() < Date.now()) {
    return { ok: false, error: "Delete verification expired" };
  }

  const providedHash = hashValue(String(code).trim());
  const stored = Buffer.from(pending._source.codeHash, "hex");
  const provided = Buffer.from(providedHash, "hex");

  if (stored.length !== provided.length || !crypto.timingSafeEqual(stored, provided)) {
    return { ok: false, error: "Invalid delete verification code" };
  }

  await softDeleteAdminAccount(esClient, user._id, {
    actorId: user._id,
    actorEmail: user._source.email,
    selfDelete: true,
  });
  await esClient.delete({ index: ADMIN_PENDING_INDEX, id: pendingId }).catch(() => {});

  return { ok: true };
};

const requestForgotPasswordCode = async (esClient, email) => {
  const normalizedEmail = sanitizeEmail(email);
  if (!isValidEmail(normalizedEmail)) {
    return { ok: false, error: "not valid email" };
  }

  const user = await getAdminByEmail(esClient, normalizedEmail);
  if (!user?._source || user._source.status === "deleted") {
    return { ok: false, error: "Account not found" };
  }

  const code = generateNumericCode(6);
  const codeHash = hashValue(code);
  const now = getNowIso();

  await esClient.index({
    index: ADMIN_PENDING_INDEX,
    id: `${user._id}_reset`,
    document: {
      email: normalizedEmail,
      emailNormalized: normalizedEmail,
      name: user._source.name,
      nameNormalized: user._source.nameNormalized || sanitizeName(user._source.name),
      passwordHash: user._source.passwordHash,
      codeHash,
      codeExpiresAt: getExpiryIso(10),
      createdAt: now,
      updatedAt: now,
      attempts: 0,
      purpose: "password_reset",
    },
  });

  return { ok: true, code, email: normalizedEmail, name: user._source.name };
};

const verifyForgotPasswordCodeAndReset = async (esClient, { email, code, newPassword }) => {
  const normalizedEmail = sanitizeEmail(email);
  if (!isStrongPassword(newPassword)) {
    return { ok: false, error: passwordPolicyMessage() };
  }

  const user = await getAdminByEmail(esClient, normalizedEmail);
  if (!user?._source || user._source.status === "deleted") {
    return { ok: false, error: "Account not found" };
  }

  const pendingId = `${user._id}_reset`;
  const pending = await esClient.get({ index: ADMIN_PENDING_INDEX, id: pendingId }).catch((err) => {
    if (err?.meta?.statusCode === 404) return null;
    throw err;
  });

  if (!pending?._source || pending._source.purpose !== "password_reset") {
    return { ok: false, error: "Password reset request not found" };
  }

  const source = pending._source;
  if (new Date(source.codeExpiresAt).getTime() < Date.now()) {
    return { ok: false, error: "Password reset code expired" };
  }

  const providedHash = hashValue(String(code).trim());
  const stored = Buffer.from(source.codeHash, "hex");
  const provided = Buffer.from(providedHash, "hex");

  if (stored.length !== provided.length || !crypto.timingSafeEqual(stored, provided)) {
    await esClient.update({
      index: ADMIN_PENDING_INDEX,
      id: pendingId,
      body: { doc: { attempts: (source.attempts || 0) + 1, updatedAt: getNowIso() } },
    });
    return { ok: false, error: "Invalid verification code" };
  }

  const passwordHash = await bcrypt.hash(String(newPassword), 12);
  await esClient.update({
    index: ADMIN_USERS_INDEX,
    id: user._id,
    body: {
      doc: {
        passwordHash,
        failedLoginAttempts: 0,
        lockUntil: null,
        updatedAt: getNowIso(),
      },
    },
  });

  await esClient.delete({ index: ADMIN_PENDING_INDEX, id: pendingId }).catch(() => {});
  await createAuditEntry(esClient, {
    action: "password_reset_success",
    actorId: user._id,
    actorEmail: user._source.email,
    targetId: user._id,
    targetEmail: user._source.email,
    details: { method: "email_code" },
  });

  return { ok: true };
};

const changeAdminPassword = async (esClient, { email, currentPassword, newPassword }) => {
  const normalizedEmail = sanitizeEmail(email);
  const user = await getAdminByEmail(esClient, normalizedEmail);
  if (!user?._source || user._source.status === "deleted") {
    return { ok: false, error: "Account not found" };
  }

  if (!isStrongPassword(newPassword)) {
    return { ok: false, error: passwordPolicyMessage() };
  }

  const currentMatches = await bcrypt.compare(String(currentPassword || ""), user._source.passwordHash);
  if (!currentMatches) {
    return { ok: false, error: "Current password is incorrect" };
  }

  const sameAsCurrent = await bcrypt.compare(String(newPassword || ""), user._source.passwordHash);
  if (sameAsCurrent) {
    return { ok: false, error: "New password must be different from current password" };
  }

  const passwordHash = await bcrypt.hash(String(newPassword), 12);
  await esClient.update({
    index: ADMIN_USERS_INDEX,
    id: user._id,
    body: {
      doc: {
        passwordHash,
        failedLoginAttempts: 0,
        lockUntil: null,
        updatedAt: getNowIso(),
      },
    },
  });

  await createAuditEntry(esClient, {
    action: "password_change_success",
    actorId: user._id,
    actorEmail: user._source.email,
    targetId: user._id,
    targetEmail: user._source.email,
    details: { method: "current_password" },
  });

  return { ok: true };
};

const getEmailTransport = () => {
  const service = String(process.env.SMTP_SERVICE || "").trim();
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if ((!service && !host) || !user || !pass) {
    return null;
  }

  if (service) {
    return nodemailer.createTransport({
      service,
      auth: { user, pass },
    });
  }

  return nodemailer.createTransport({
    host,
    port,
    secure: String(process.env.SMTP_SECURE || "false") === "true",
    auth: { user, pass },
  });
};

const sendVerificationCodeEmail = async ({ to, name, code, purpose = "signup" }) => {
  const transport = getEmailTransport();
  const from = process.env.SMTP_FROM || process.env.SMTP_USER;

  const subject = purpose === "delete_account"
    ? "Confirm your admin account deletion"
    : purpose === "password_reset"
      ? "Your password reset verification code"
    : "Your admin signup verification code";

  const text = purpose === "delete_account"
    ? `Hello ${name || "Admin"},\n\nUse this code to confirm deletion of your account: ${code}\n\nThis code expires soon.`
    : purpose === "password_reset"
      ? `Hello ${name || "Admin"},\n\nUse this code to reset your password: ${code}\n\nThis code expires soon.`
    : `Hello ${name || "Admin"},\n\nYour verification code is: ${code}\n\nThis code expires soon.`;

  if (!transport || !from) {
    if (String(process.env.ALLOW_EMAIL_CONSOLE_FALLBACK || "false") === "true") {
      console.log(`📧 Email fallback active. To: ${to}, Purpose: ${purpose}, Code: ${code}`);
      return { ok: true, fallback: true };
    }
    throw new Error("Email transport is not configured. Set SMTP_USER, SMTP_PASS, SMTP_FROM, and either SMTP_SERVICE (e.g. gmail) or SMTP_HOST/SMTP_PORT.");
  }

  await transport.sendMail({
    from,
    to,
    subject,
    text,
  });

  return { ok: true, fallback: false };
};

const getAdminByName = async (esClient, name) => {
  const normalizedName = sanitizeName(name);
  if (!esClient || !normalizedName) return null;

  try {
    const response = await esClient.search({
      index: ADMIN_USERS_INDEX,
      size: 1,
      query: {
        bool: {
          should: [
            { term: { nameNormalized: normalizedName } },
            { term: { "nameNormalized.keyword": normalizedName } },
          ],
          minimum_should_match: 1,
        },
      },
    });
    return response.hits?.hits?.[0] || null;
  } catch (err) {
    if (err?.meta?.statusCode === 404) return null;
    throw err;
  }
};

const getPendingByEmail = async (esClient, email) => {
  const normalizedEmail = sanitizeEmail(email);
  if (!esClient || !normalizedEmail) return null;

  try {
    const response = await esClient.search({
      index: ADMIN_PENDING_INDEX,
      size: 1,
      query: {
        bool: {
          filter: [
            { term: { emailNormalized: normalizedEmail } },
          ],
        },
      },
    });
    return response.hits?.hits?.[0] || null;
  } catch (err) {
    if (err?.meta?.statusCode === 404) return null;
    throw err;
  }
};

const getPendingByName = async (esClient, name) => {
  const normalizedName = sanitizeName(name);
  if (!esClient || !normalizedName) return null;

  try {
    const response = await esClient.search({
      index: ADMIN_PENDING_INDEX,
      size: 1,
      query: {
        bool: {
          should: [
            { term: { nameNormalized: normalizedName } },
            { term: { "nameNormalized.keyword": normalizedName } },
          ],
          minimum_should_match: 1,
        },
      },
    });
    return response.hits?.hits?.[0] || null;
  } catch (err) {
    if (err?.meta?.statusCode === 404) return null;
    throw err;
  }
};

module.exports = {
  ADMIN_USERS_INDEX,
  ADMIN_PENDING_INDEX,
  ADMIN_CHALLENGES_INDEX,
  ADMIN_AUDIT_INDEX,
  ensureAdminAuthIndices,
  getSignupChallenge,
  queuePendingSignup,
  verifyPendingSignup,
  loginAdmin,
  getAdminByEmail,
  getAdminById,
  listAdmins,
  sendVerificationCodeEmail,
  requestPasswordResetOrConfirmDelete,
  verifyDeleteCode,
  requestForgotPasswordCode,
  verifyForgotPasswordCodeAndReset,
  changeAdminPassword,
  softDeleteAdminAccount,
  createAuditEntry,
  isValidEmail,
  isStrongPassword,
  passwordPolicyMessage,
  sanitizeEmail,
  sanitizeName,
};