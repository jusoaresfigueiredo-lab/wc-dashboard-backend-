/**
 * World Collective — Weekly Dashboard Backend
 * Node.js + Express
 *
 * Handles:
 *  - Google OAuth per team member (Gmail + Calendar)
 *  - monday.com OAuth per team member
 *  - Token storage (encrypted in .tokens.json)
 *  - Anthropic API calls with MCP connectors server-side
 *  - CORS so the frontend can call this from any domain
 */

import express       from "express";
import session       from "express-session";
import cors          from "cors";
import fs            from "fs";
import path          from "path";
import crypto        from "crypto";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// ─── Config (set these in Railway/Render environment variables) ───────────────
const {
  PORT              = 3001,
  SESSION_SECRET    = "change-this-secret",          // set in env vars
  ANTHROPIC_API_KEY,                                  // required
  GOOGLE_CLIENT_ID,                                   // required
  GOOGLE_CLIENT_SECRET,                               // required
  MONDAY_CLIENT_ID,                                   // required
  MONDAY_CLIENT_SECRET,                               // required
  FRONTEND_URL      = "http://localhost:5173",        // your deployed frontend URL
  BACKEND_URL       = `http://localhost:${PORT}`,     // this server's URL
  ENCRYPT_KEY = "change-this-32-char-key!!!!!", // must be 32 chars
} = process.env;

const GOOGLE_REDIRECT = `${BACKEND_URL}/auth/google/callback`;
const MONDAY_REDIRECT = `${BACKEND_URL}/auth/monday/callback`;

const GOOGLE_SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/calendar.readonly",
  "openid", "email", "profile",
].join(" ");

// ─── Token storage (encrypted flat file — swap for DB in production) ──────────
const TOKENS_FILE = path.join(__dirname, ".tokens.json");

function loadTokens() {
  if (!fs.existsSync(TOKENS_FILE)) return {};
  try {
    const raw = fs.readFileSync(TOKENS_FILE, "utf8");
    return JSON.parse(raw);
  } catch { return {}; }
}

function saveTokens(tokens) {
  fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2));
}

function encrypt(text) {
  const iv  = crypto.randomBytes(16);
  const key = crypto.scryptSync(ENCRYPT_KEY, "salt", 32);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  return iv.toString("hex") + ":" + cipher.update(text, "utf8", "hex") + cipher.final("hex");
}

function decrypt(text) {
  const [ivHex, encrypted] = text.split(":");
  const key = crypto.scryptSync(ENCRYPT_KEY, "salt", 32);
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, Buffer.from(ivHex, "hex"));
  return decipher.update(encrypted, "hex", "utf8") + decipher.final("utf8");
}

function storeToken(userId, service, tokenData) {
  const tokens = loadTokens();
  if (!tokens[userId]) tokens[userId] = {};
  tokens[userId][service] = encrypt(JSON.stringify(tokenData));
  saveTokens(tokens);
}

function getToken(userId, service) {
  const tokens = loadTokens();
  const enc = tokens?.[userId]?.[service];
  if (!enc) return null;
  try { return JSON.parse(decrypt(enc)); } catch { return null; }
}

function getAllConnectedUsers() {
  const tokens = loadTokens();
  return Object.entries(tokens).map(([userId, services]) => ({
    userId,
    hasGoogle:  !!services.google,
    hasMonday:  !!services.monday,
  }));
}

// ─── Google token refresh ─────────────────────────────────────────────────────
async function refreshGoogleToken(userId, tokenData) {
  if (Date.now() < tokenData.expiry_date - 60000) return tokenData; // still valid
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id:     GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      refresh_token: tokenData.refresh_token,
      grant_type:    "refresh_token",
    }),
  });
  const data = await res.json();
  const refreshed = {
    ...tokenData,
    access_token: data.access_token,
    expiry_date:  Date.now() + data.expires_in * 1000,
  };
  storeToken(userId, "google", refreshed);
  return refreshed;
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === "production", maxAge: 7 * 24 * 60 * 60 * 1000 },
}));

// ─── Google OAuth ─────────────────────────────────────────────────────────────
app.get("/auth/google", (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ error: "userId required" });
req.session.pendingUserId = userId;
req.session.save();
const params = new URLSearchParams({

  const params = new URLSearchParams({
    client_id:     GOOGLE_CLIENT_ID,
    redirect_uri:  GOOGLE_REDIRECT,
    response_type: "code",
    scope:         GOOGLE_SCOPES,
    access_type:   "offline",
    prompt:        "consent",
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get("/auth/google/callback", async (req, res) => {
  const { code } = req.query;
  const userId   = req.session.pendingUserId;
  if (!code || !userId) return res.redirect(`${FRONTEND_URL}/connect?error=missing_params`);

  try {
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT, grant_type: "authorization_code",
      }),
    });
    const tokenData = await tokenRes.json();
    storeToken(userId, "google", {
      access_token:  tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      expiry_date:   Date.now() + tokenData.expires_in * 1000,
    });
    res.redirect(`${FRONTEND_URL}/connect?success=google&user=${userId}`);
  } catch (err) {
    res.redirect(`${FRONTEND_URL}/connect?error=google_failed`);
  }
});

// ─── monday.com OAuth ─────────────────────────────────────────────────────────
app.get("/auth/monday", (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ error: "userId required" });
 req.session.pendingUserId = userId;
 req.session.save();
 res.redirect(`https://auth.monday.com/oauth2/authorize?${params}`);

  const params = new URLSearchParams({
    client_id:    MONDAY_CLIENT_ID,
    redirect_uri: MONDAY_REDIRECT,
  });
  res.redirect(`https://auth.monday.com/oauth2/authorize?${params}`);
});

app.get("/auth/monday/callback", async (req, res) => {
  const { code } = req.query;
  const userId   = req.session.pendingUserId;
  if (!code || !userId) return res.redirect(`${FRONTEND_URL}/connect?error=missing_params`);

  try {
    const tokenRes = await fetch("https://auth.monday.com/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code, client_id: MONDAY_CLIENT_ID, client_secret: MONDAY_CLIENT_SECRET,
        redirect_uri: MONDAY_REDIRECT,
      }),
    });
    const tokenData = await tokenRes.json();
    storeToken(userId, "monday", { access_token: tokenData.access_token });
    res.redirect(`${FRONTEND_URL}/connect?success=monday&user=${userId}`);
  } catch {
    res.redirect(`${FRONTEND_URL}/connect?error=monday_failed`);
  }
});

// ─── Connection status ────────────────────────────────────────────────────────
app.get("/status", (req, res) => {
  const users = getAllConnectedUsers();
  res.json({ users, week: "April 30 – May 6, 2025" });
});

app.get("/status/:userId", (req, res) => {
  const { userId } = req.params;
  res.json({
    userId,
    hasGoogle: !!getToken(userId, "google"),
    hasMonday: !!getToken(userId, "monday"),
  });
});

// ─── Core: call Anthropic with MCP tokens ────────────────────────────────────
async function callAnthropicWithMCP(prompt, mcpServers) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key":    ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
      "anthropic-beta": "mcp-client-2025-04-04",
    },
    body: JSON.stringify({
      model:      "claude-sonnet-4-20250514",
      max_tokens: 1500,
      system:     "You are a team activity analyst for World Collective. Respond ONLY with valid raw JSON — no markdown, no backticks, no preamble.",
      messages:   [{ role: "user", content: prompt }],
      mcp_servers: mcpServers,
    }),
  });
  const data = await res.json();
  const raw = (data.content || []).filter(b => b.type === "text").map(b => b.text).join("\n");
  return JSON.parse(raw.replace(/```json|```/g, "").trim());
}

// ─── Build MCP server list from stored tokens ─────────────────────────────────
function buildMCPServers(googleToken, mondayToken) {
  const servers = [];
  if (googleToken) {
    servers.push({
      type: "url", name: "gmail-mcp",
      url:  "https://gmailmcp.googleapis.com/mcp/v1",
      authorization_token: googleToken.access_token,
    });
    servers.push({
      type: "url", name: "google-calendar-mcp",
      url:  "https://calendarmcp.googleapis.com/mcp/v1",
      authorization_token: googleToken.access_token,
    });
    servers.push({
      type: "url", name: "google-drive-mcp",
      url:  "https://drivemcp.googleapis.com/mcp/v1",
      authorization_token: googleToken.access_token,
    });
  }
  if (mondayToken) {
    servers.push({
      type: "url", name: "monday-mcp",
      url:  "https://mcp.monday.com/mcp",
      authorization_token: mondayToken.access_token,
    });
  }
  return servers;
}

const WEEK = "April 30 – May 6, 2025";
const TEAM_NAMES = "Julia F, Julia V, Julie, Ana, Jeanine, Sumit, Gül, Barbara";

// ─── Dashboard data endpoints ─────────────────────────────────────────────────

// Personal: logged-in user's Gmail + Calendar
app.get("/data/my-week/:userId", async (req, res) => {
  const { userId } = req.params;
  let googleToken = getToken(userId, "google");
  if (!googleToken) return res.status(401).json({ error: "Google not connected for this user" });

  try {
    googleToken = await refreshGoogleToken(userId, googleToken);
    const mcpServers = buildMCPServers(googleToken, null);
    const data = await callAnthropicWithMCP(`You are reviewing THIS week's activity (${WEEK}) for this specific user at World Collective.
Search Gmail for emails sent AND received between April 30 and May 6 2025.
Search Google Calendar for meetings between April 30 and May 6 2025.
Respond with ONLY raw JSON:
{"emailsSent":<int>,"emailsReceived":<int>,"meetingsCount":<int>,"topThreads":[{"subject":"subject","counterpart":"who","status":"ongoing|waiting|resolved"}],"meetings":[{"title":"title","day":"Mon|Tue|Wed|Thu|Fri","attendees":"list"}],"highlight":"1 sentence biggest thing this week"}
topThreads max 4, meetings max 5.`, mcpServers);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Shared: team projects from monday.com (uses first connected monday user)
app.get("/data/team-projects", async (req, res) => {
  const allUsers = getAllConnectedUsers();
  const mondayUser = allUsers.find(u => u.hasMonday);
  if (!mondayUser) return res.status(401).json({ error: "No monday.com account connected yet" });

  const mondayToken = getToken(mondayUser.userId, "monday");
  try {
    const mcpServers = buildMCPServers(null, mondayToken);
    const data = await callAnthropicWithMCP(`You are reviewing World Collective's team project activity for ${WEEK}.
Team: ${TEAM_NAMES}.
Search monday.com for ALL boards updated between April 30 and May 6 2025.
Respond with ONLY raw JSON:
{"summary":"2-sentence overview","projects":[{"name":"board name","status":"On Track|At Risk|Blocked|Done","owner":"team member","updatedBy":"who updated","update":"1-sentence progress"}]}
Max 8 projects.`, mcpServers);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Shared: team files from Drive (uses first connected google user)
app.get("/data/team-files", async (req, res) => {
  const allUsers = getAllConnectedUsers();
  const googleUser = allUsers.find(u => u.hasGoogle);
  if (!googleUser) return res.status(401).json({ error: "No Google account connected yet" });

  let googleToken = getToken(googleUser.userId, "google");
  try {
    googleToken = await refreshGoogleToken(googleUser.userId, googleToken);
    const mcpServers = buildMCPServers(googleToken, null);
    const data = await callAnthropicWithMCP(`You are reviewing World Collective's shared Google Drive activity for ${WEEK}.
Team: ${TEAM_NAMES}.
Search shared Drive folders for files created or modified between April 30 and May 6 2025.
Respond with ONLY raw JSON:
{"summary":"1-sentence overview","files":[{"name":"file name","type":"Doc|Sheet|Slide|PDF|Other","day":"Mon|Tue|Wed|Thu|Fri","editedBy":"team member","topic":"6-word description"}]}
Max 8 files, newest first.`, mcpServers);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Shared: full AI summary across all sources
app.get("/data/ai-summary", async (req, res) => {
  const allUsers = getAllConnectedUsers();
  const googleUser = allUsers.find(u => u.hasGoogle);
  const mondayUser = allUsers.find(u => u.hasMonday);
  if (!googleUser && !mondayUser) return res.status(401).json({ error: "No accounts connected yet" });

  let googleToken = googleUser ? getToken(googleUser.userId, "google") : null;
  const mondayToken = mondayUser ? getToken(mondayUser.userId, "monday") : null;

  try {
    if (googleToken) googleToken = await refreshGoogleToken(googleUser.userId, googleToken);
    const mcpServers = buildMCPServers(googleToken, mondayToken);
    const data = await callAnthropicWithMCP(`You are World Collective's weekly debrief AI for the week of ${WEEK}.
Team: ${TEAM_NAMES}.
Pull from Gmail, Google Calendar, monday.com, and Google Drive to build a full picture of the week.
Respond with ONLY raw JSON:
{"headline":"6-8 word headline","overview":"3-4 sentence narrative of the week","wins":["win 1","win 2","win 3"],"watchItems":["watch 1","watch 2"],"nextWeek":"1-2 sentences on focus for week of May 7"}
Be specific — name real projects, suppliers, clients.`, mcpServers);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`✓ WC Dashboard backend running on port ${PORT}`));
