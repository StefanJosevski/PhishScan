import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import { authenticator } from "otplib";
import db, { type Scan, type User } from "./db";

const app = express();
app.use(cors());
app.use(express.json({ limit: "3mb" })); // raised limit so a base64 avatar upload fits

type NewScanInput = {
  filename: string;
  risk_tier: string;
  indicators?: string[];
  reported?: boolean;
};

function isValidNewScan(body: any): body is NewScanInput {
  if (!body || typeof body !== "object") return false;
  if (typeof body.filename !== "string" || body.filename.trim() === "") return false;
  if (typeof body.risk_tier !== "string" || body.risk_tier.trim() === "") return false;
  if (body.indicators !== undefined && !Array.isArray(body.indicators)) return false;
  return true;
}

// Get all past scans, most recent first
app.get("/api/scans", async (req, res) => {
  try {
    await db.read();
    const scans = [...db.data.scans].sort(
      (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    );
    res.json(scans);
  } catch (err) {
    console.error("GET /api/scans failed:", err);
    res.status(500).json({ error: "Failed to read scan history." });
  }
});

// Save a new scan result
app.post("/api/scans", async (req, res) => {
  if (!isValidNewScan(req.body)) {
    return res.status(400).json({
      error: "Invalid scan payload. 'filename' and 'risk_tier' are required strings, 'indicators' must be an array if provided.",
    });
  }

  const { filename, risk_tier, indicators, reported } = req.body as NewScanInput;

  try {
    await db.read();
    const newScan: Scan = {
      id: db.data.nextId,
      filename,
      risk_tier,
      indicators: indicators ?? [],
      reported: !!reported,
      created_at: new Date().toISOString(),
    };
    db.data.scans.push(newScan);
    db.data.nextId += 1;
    await db.write();

    res.status(201).json({ id: newScan.id });
  } catch (err) {
    console.error("POST /api/scans failed:", err);
    res.status(500).json({ error: "Failed to save scan." });
  }
});

// Mark a scan as reported to IT Security
app.patch("/api/scans/:id/report", async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Invalid scan id." });
  }

  try {
    await db.read();
    const scan = db.data.scans.find((s) => s.id === id);

    if (!scan) {
      return res.status(404).json({ error: `Scan ${id} not found.` });
    }

    scan.reported = true;
    await db.write();

    res.json({ success: true, id: scan.id });
  } catch (err) {
    console.error("PATCH /api/scans/:id/report failed:", err);
    res.status(500).json({ error: "Failed to update scan." });
  }
});

// Helper: strip the password hash and TOTP secret before sending a user to the client
function toPublicUser(u: User) {
  const { passwordHash, totpSecret, ...publicUser } = u;
  return publicUser;
}

function isValidRegisterInput(body: any) {
  return (
    body &&
    typeof body === "object" &&
    typeof body.name === "string" && body.name.trim() !== "" &&
    typeof body.email === "string" && body.email.trim() !== "" &&
    typeof body.password === "string" && body.password.length >= 6
  );
}

// Create a new account
app.post("/api/register", async (req, res) => {
  if (!isValidRegisterInput(req.body)) {
    return res.status(400).json({
      error: "'name' and 'email' are required, and 'password' must be at least 6 characters.",
    });
  }

  const { name, email, password, role } = req.body as { name: string; email: string; password: string; role?: string };
  const normalizedEmail = email.trim().toLowerCase();

  try {
    await db.read();

    const existing = db.data.users.find((u) => u.email === normalizedEmail);
    if (existing) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser: User = {
      id: db.data.nextUserId,
      name: name.trim(),
      email: normalizedEmail,
      passwordHash,
      role: role?.trim() || "IT Security Analyst",
      avatar: null,
      totpSecret: null,
      totpEnabled: false,
      created_at: new Date().toISOString(),
    };
    db.data.users.push(newUser);
    db.data.nextUserId += 1;
    await db.write();

    res.status(201).json({ user: toPublicUser(newUser) });
  } catch (err) {
    console.error("POST /api/register failed:", err);
    res.status(500).json({ error: "Failed to create account." });
  }
});

// Log in with email + password
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body ?? {};

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "Email and password are required." });
  }

  try {
    await db.read();
    const user = db.data.users.find((u) => u.email === email.trim().toLowerCase());

    if (!user) {
      return res.status(401).json({ error: "No account found with that email." });
    }

    const passwordMatches = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatches) {
      return res.status(401).json({ error: "Incorrect password." });
    }

    if (user.totpEnabled) {
      return res.json({ mfaRequired: true, userId: user.id });
    }

    res.json({ user: toPublicUser(user) });
  } catch (err) {
    console.error("POST /api/login failed:", err);
    res.status(500).json({ error: "Failed to log in." });
  }
});

// Complete login after a correct TOTP code
app.post("/api/verify-login", async (req, res) => {
  const { userId, code } = req.body ?? {};
  const id = Number(userId);

  if (!Number.isInteger(id) || id <= 0 || typeof code !== "string") {
    return res.status(400).json({ error: "A valid userId and code are required." });
  }

  try {
    await db.read();
    const user = db.data.users.find((u) => u.id === id);

    if (!user || !user.totpEnabled || !user.totpSecret) {
      return res.status(400).json({ error: "Two-factor authentication is not enabled for this account." });
    }

    const isValid = authenticator.check(code, user.totpSecret);
    if (!isValid) {
      return res.status(401).json({ error: "Incorrect or expired code. Try the current code from your authenticator app." });
    }

    res.json({ user: toPublicUser(user) });
  } catch (err) {
    console.error("POST /api/verify-login failed:", err);
    res.status(500).json({ error: "Failed to verify code." });
  }
});

// Start 2FA setup: generate a secret and an otpauth:// URL for the QR code
app.post("/api/users/:id/2fa/setup", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Invalid user id." });
  }

  try {
    await db.read();
    const user = db.data.users.find((u) => u.id === id);
    if (!user) {
      return res.status(404).json({ error: `User ${id} not found.` });
    }

    // Generate a fresh secret every time setup is (re)started. It only
    // becomes active once verify-setup confirms the user actually scanned it.
    const secret = authenticator.generateSecret();
    user.totpSecret = secret;
    user.totpEnabled = false;
    await db.write();

    const otpauthUrl = authenticator.keyuri(user.email, "PhishScan", secret);
    res.json({ secret, otpauthUrl });
  } catch (err) {
    console.error("POST /api/users/:id/2fa/setup failed:", err);
    res.status(500).json({ error: "Failed to start 2FA setup." });
  }
});

// Confirm setup: verify the first code from the authenticator app, then enable 2FA
app.post("/api/users/:id/2fa/verify-setup", async (req, res) => {
  const id = Number(req.params.id);
  const { code } = req.body ?? {};

  if (!Number.isInteger(id) || id <= 0 || typeof code !== "string") {
    return res.status(400).json({ error: "A valid code is required." });
  }

  try {
    await db.read();
    const user = db.data.users.find((u) => u.id === id);
    if (!user || !user.totpSecret) {
      return res.status(400).json({ error: "Start 2FA setup first." });
    }

    const isValid = authenticator.check(code, user.totpSecret);
    if (!isValid) {
      return res.status(401).json({ error: "Incorrect code. Double check the current code in your authenticator app." });
    }

    user.totpEnabled = true;
    await db.write();

    res.json({ user: toPublicUser(user) });
  } catch (err) {
    console.error("POST /api/users/:id/2fa/verify-setup failed:", err);
    res.status(500).json({ error: "Failed to confirm 2FA setup." });
  }
});

// Turn 2FA off
app.post("/api/users/:id/2fa/disable", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Invalid user id." });
  }

  try {
    await db.read();
    const user = db.data.users.find((u) => u.id === id);
    if (!user) {
      return res.status(404).json({ error: `User ${id} not found.` });
    }

    user.totpSecret = null;
    user.totpEnabled = false;
    await db.write();

    res.json({ user: toPublicUser(user) });
  } catch (err) {
    console.error("POST /api/users/:id/2fa/disable failed:", err);
    res.status(500).json({ error: "Failed to disable 2FA." });
  }
});

// Update profile (name, role, avatar)
app.patch("/api/users/:id", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: "Invalid user id." });
  }

  const { name, role, avatar } = req.body ?? {};

  try {
    await db.read();
    const user = db.data.users.find((u) => u.id === id);

    if (!user) {
      return res.status(404).json({ error: `User ${id} not found.` });
    }

    if (typeof name === "string" && name.trim() !== "") user.name = name.trim();
    if (typeof role === "string" && role.trim() !== "") user.role = role.trim();
    if (typeof avatar === "string" || avatar === null) user.avatar = avatar;

    await db.write();
    res.json({ user: toPublicUser(user) });
  } catch (err) {
    console.error("PATCH /api/users/:id failed:", err);
    res.status(500).json({ error: "Failed to update profile." });
  }
});

const PORT = 3001;
app.listen(PORT, () => console.log(`PhishScan API running on http://localhost:${PORT}`));
