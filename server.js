import express  from "express";
import session  from "express-session";
import cors     from "cors";
import fs       from "fs";
import path     from "path";
import crypto   from "crypto";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

const {
  PORT           = 3001,
  SESSION_SECRET = "change-this-secret",
  ANTHROPIC_API_KEY,
  ANTHROPIC_ORG_ID,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  MONDAY_API_KEY,
  FRONTEND_URL   = "http://localhost:5173",
  BACKEND_URL    = `http://localhost:${PORT}`,
  ENCRYPT_KEY    = "change-this-32-char-key!!!!!!!!",
} = process.env;

const GOOGLE_REDIRECT = `${BACKEND_URL}/auth/google/callback`;
const GOOGLE_SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/calendar.readonly",
  "https://www.googleapis.com/auth/drive.readonly",
  "openid", "email", "profile",
].join(" ");

const WEEK = "April 30 - May 6, 2025";
const WEEK_START = "2025-04-30";
const WEEK_END = "2025-05-07";
const TEAM_NAMES = "Julia F, Julia V, Julie, Ana, Jeanine, Sumit, Gul, Barbara";

// ─── Token storage ─────────────────────────────────────────────────────────────
const TOKENS_FILE = path.join(__dirname, ".tokens.json");

function loadTokens() {
  if (!fs.existsSync(TOKENS_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(TOKENS_FILE, "utf8")); } catch { return {}; }
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

function storeToken(userId, tokenData) {
  const tokens = loadTokens();
  tokens[userId] = encrypt(JSON.stringify(tokenData));
  saveTokens(tokens);
}

function getToken(userId) {
  const tokens = loadTokens();
  const enc = tokens?.[userId];
  if (!enc) return null;
  try { return JSON.parse(decrypt(enc)); } catch { return null; }
}

function getAllConnectedUsers() {
  return Object.keys(loadTokens());
}

async function refreshGoogleToken(userId, tokenData) {
  if (Date.now() < tokenData.expiry_date - 60000) return tokenData;
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET,
      refresh_token: tokenData.refresh_token, grant_type: "refresh_token",
    }),
  });
  const data = await res.json();
  const refreshed = { ...tokenData, access_token: data.access_token, expiry_date: Date.now() + data.expires_in * 1000 };
  storeToken(userId, refreshed);
  return refreshed;
}

// ─── Google API helpers ────────────────────────────────────────────────────────
async function getGmailActivity(accessToken) {
  try {
    const afterDate = Math.floor(new Date(WEEK_START).getTime() / 1000);
    const beforeDate = Math.floor(new Date(WEEK_END).getTime() / 1000);

    const [sentRes, inboxRes] = await Promise.all([
      fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages?q=in:sent after:${afterDate} before:${beforeDate}&maxResults=20`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      }),
      fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages?q=in:inbox after:${afterDate} before:${beforeDate}&maxResults=20`, {
        headers: { Authorization: `Bearer ${accessToken}` }
      })
    ]);

    const [sentData, inboxData] = await Promise.all([sentRes.json(), inboxRes.json()]);
    const sentCount = sentData.resultSizeEstimate || 0;
    const inboxCount = inboxData.resultSizeEstimate || 0;

    // Get details of top 5 inbox messages
    const topMessages = [];
    if (inboxData.messages && inboxData.messages.length > 0) {
      const msgDetails = await Promise.all(
        inboxData.messages.slice(0, 5).map(m =>
          fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${m.id}?format=metadata&metadataHeaders=Subject&metadataHeaders=From`, {
            headers: { Authorization: `Bearer ${accessToken}` }
          }).then(r => r.json())
        )
      );
      for (const msg of msgDetails) {
        const headers = msg.payload?.headers || [];
        const subject = headers.find(h => h.name === "Subject")?.value || "(no subject)";
        const from = headers.find(h => h.name === "From")?.value || "unknown";
        topMessages.push({ subject, from });
      }
    }

    return { sentCount, inboxCount, topMessages };
  } catch (err) {
    console.log("Gmail error:", err.message);
    return { sentCount: 0, inboxCount: 0, topMessages: [] };
  }
}

async function getCalendarActivity(accessToken) {
  try {
    const res = await fetch(
      `https://www.googleapis.com/calendar/v3/calendars/primary/events?timeMin=${WEEK_START}T00:00:00Z&timeMax=${WEEK_END}T00:00:00Z&singleEvents=true&orderBy=startTime&maxResults=20`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    const data = await res.json();
    const events = (data.items || []).map(e => ({
      title: e.summary || "(no title)",
      start: e.start?.dateTime || e.start?.date || "",
      attendees: (e.attendees || []).map(a => a.email).join(", ") || "Just me",
    }));
    return events;
  } catch (err) {
    console.log("Calendar error:", err.message);
    return [];
  }
}

async function getDriveActivity(accessToken) {
  try {
    const res = await fetch(
      `https://www.googleapis.com/drive/v3/files?q=modifiedTime>'${WEEK_START}T00:00:00Z' and modifiedTime<'${WEEK_END}T00:00:00Z'&fields=files(name,mimeType,modifiedTime,lastModifyingUser)&orderBy=modifiedTime desc&pageSize=20`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );
    const data = await res.json();
    return (data.files || []).map(f => ({
      name: f.name,
      type: f.mimeType,
      modified: f.modifiedTime,
      editedBy: f.lastModifyingUser?.displayName || "unknown",
    }));
  } catch (err) {
    console.log("Drive error:", err.message);
    return [];
  }
}

async function getMondayActivity() {
  if (!MONDAY_API_KEY) return [];
  try {
    const res = await fetch("https://api.monday.com/v2", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: MONDAY_API_KEY },
      body: JSON.stringify({
        query: `{ boards(limit: 10) { name items_page(limit: 20) { items { name state updated_at column_values { text } } } } }`
      })
    });
    const data = await res.json();
    return data?.data?.boards || [];
  } catch (err) {
    console.log("Monday error:", err.message);
    return [];
  }
}

// ─── Claude (no MCP) ───────────────────────────────────────────────────────────
async function callClaude(prompt) {
  const headers = {
    "Content-Type": "application/json",
    "x-api-key": ANTHROPIC_API_KEY,
    "anthropic-version": "2023-06-01",
  };
  if (ANTHROPIC_ORG_ID) headers["anthropic-organization-id"] = ANTHROPIC_ORG_ID;

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers,
    body: JSON.stringify({
      model: "claude-opus-4-7",
      max_tokens: 2000,
      system: "You are a team activity analyst. Respond with ONLY a raw JSON object. No text before or after. No markdown. No backticks. Start with { and end with }.",
      messages: [{ role: "user", content: prompt }],
    }),
  });

  const data = await res.json();
  console.log("Claude STATUS:", res.status);
  if (data.error) console.log("Claude ERROR:", JSON.stringify(data.error));

  const raw = (data.content || []).filter(b => b.type === "text").map(b => b.text).join("\n");
  const cleaned = raw.replace(/```json|```/g, "").trim();
  if (!cleaned) throw new Error("Empty response from Claude");
  return JSON.parse(cleaned);
}

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET, resave: true, saveUninitialized: true,
  cookie: { secure: true, sameSite: "none", maxAge: 7 * 24 * 60 * 60 * 1000 },
}));

// ─── Google OAuth ──────────────────────────────────────────────────────────────
app.get("/auth/google", (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ error: "userId required" });
  req.session.pendingUserId = userId;
  req.session.save(() => {
    const params = new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID, redirect_uri: GOOGLE_REDIRECT,
      response_type: "code", scope: GOOGLE_SCOPES,
      access_type: "offline", prompt: "consent", state: userId,
    });
    res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
  });
});

app.get("/auth/google/callback", async (req, res) => {
  const { code, state } = req.query;
  const userId = state || req.session.pendingUserId;
  if (!code || !userId) return res.redirect(`${FRONTEND_URL}?error=missing_params`);
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
    storeToken(userId, {
      access_token: tokenData.access_token, refresh_token: tokenData.refresh_token,
      expiry_date: Date.now() + tokenData.expires_in * 1000,
    });
    res.redirect(`${FRONTEND_URL}?success=google&user=${userId}`);
  } catch (err) {
    res.redirect(`${FRONTEND_URL}?error=google_failed`);
  }
});

// ─── Status ────────────────────────────────────────────────────────────────────
app.get("/status", (req, res) => {
  res.json({ users: getAllConnectedUsers(), week: WEEK });
});

app.get("/status/:userId", (req, res) => {
  const { userId } = req.params;
  res.json({ userId, hasGoogle: !!getToken(userId), hasMonday: !!MONDAY_API_KEY });
});

// ─── Data endpoints ────────────────────────────────────────────────────────────
app.get("/data/my-week/:userId", async (req, res) => {
  const { userId } = req.params;
  let token = getToken(userId);
  if (!token) return res.status(401).json({ error: "Google not connected for this user" });
  try {
    token = await refreshGoogleToken(userId, token);
    const [gmail, calendar] = await Promise.all([
      getGmailActivity(token.access_token),
      getCalendarActivity(token.access_token),
    ]);

    const data = await callClaude(`Analyse this Google Workspace activity for the week of ${WEEK} for a World Collective team member.

GMAIL: ${gmail.sentCount} emails sent, ${gmail.inboxCount} received.
Top messages: ${JSON.stringify(gmail.topMessages)}

CALENDAR EVENTS: ${JSON.stringify(calendar)}

Return this exact JSON:
{"emailsSent":${gmail.sentCount},"emailsReceived":${gmail.inboxCount},"meetingsCount":${calendar.length},"topThreads":[{"subject":"subject","counterpart":"sender name","status":"ongoing"}],"meetings":[{"title":"event title","day":"Mon","attendees":"attendee list"}],"highlight":"1 sentence about the most important work this week"}

Use the actual data above. topThreads max 4, meetings max 5.`);
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/data/team-projects", async (req, res) => {
  if (!MONDAY_API_KEY) return res.status(401).json({ error: "monday.com not configured" });
  try {
    const boards = await getMondayActivity();
    const data = await callClaude(`Analyse this monday.com activity for World Collective team (${TEAM_NAMES}) for the week of ${WEEK}.

BOARDS DATA: ${JSON.stringify(boards).slice(0, 3000)}

Return this exact JSON:
{"summary":"2 sentence overview of team project health","projects":[{"name":"board or project name","status":"On Track","owner":"team member","updatedBy":"who updated","update":"1 sentence progress note"}]}

Max 8 projects.`);
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/data/team-files", async (req, res) => {
  const users = getAllConnectedUsers();
  if (!users.length) return res.status(401).json({ error: "No Google account connected yet" });
  try {
    let token = getToken(users[0]);
    token = await refreshGoogleToken(users[0], token);
    const files = await getDriveActivity(token.access_token);

    const data = await callClaude(`Analyse this Google Drive activity for World Collective team for the week of ${WEEK}.

FILES MODIFIED: ${JSON.stringify(files)}

Return this exact JSON:
{"summary":"1 sentence overview of file activity","files":[{"name":"file name","type":"Doc","day":"Mon","editedBy":"person","topic":"6 word description"}]}

Max 8 files.`);
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/data/ai-summary", async (req, res) => {
  const users = getAllConnectedUsers();
  if (!users.length) return res.status(401).json({ error: "No accounts connected yet" });
  try {
    let token = getToken(users[0]);
    token = await refreshGoogleToken(users[0], token);

    const [gmail, calendar, drive, monday] = await Promise.all([
      getGmailActivity(token.access_token),
      getCalendarActivity(token.access_token),
      getDriveActivity(token.access_token),
      getMondayActivity(),
    ]);

    const data = await callClaude(`You are World Collective weekly debrief AI for ${WEEK}.
Team: ${TEAM_NAMES}.

GMAIL: ${gmail.sentCount} sent, ${gmail.inboxCount} received. Top: ${JSON.stringify(gmail.topMessages)}
CALENDAR: ${JSON.stringify(calendar.slice(0, 10))}
DRIVE FILES: ${JSON.stringify(drive.slice(0, 10))}
MONDAY BOARDS: ${JSON.stringify(monday).slice(0, 2000)}

Return this exact JSON:
{"headline":"6-8 word headline capturing the week","overview":"3-4 sentence narrative of the week","wins":["specific win 1","specific win 2","specific win 3"],"watchItems":["thing to watch 1","thing to watch 2"],"nextWeek":"1-2 sentences on focus for week of May 7"}`);
    res.json(data);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.listen(PORT, () => console.log(`WC Dashboard backend running on port ${PORT}`));
