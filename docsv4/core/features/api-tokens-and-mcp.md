# AI Assistant Integration (MCP)

Vista exposes a read-only **MCP (Model Context Protocol) server** so your AI
assistant — Claude.ai, ChatGPT, Gemini, or any MCP-capable agent — can query
your cryptographic inventory, compliance posture and CBOM artifacts directly.
You bring your own AI; Vista only answers the questions your assistant asks,
scoped to your tenant and role, read-only.

## What your assistant can do

Once connected, your assistant has 14 tools including:

- **Inventory** — search assets, certificates (by expiry, issuer, key
  algorithm), crypto configurations, and the platform's authoritative algorithm
  assessments.
- **Risk & PQC** — your risk summary and post-quantum readiness breakdown.
- **Compliance** — frameworks and scores, per-framework evaluation, and
  drill-down into a failing control's findings.
- **CBOM** — list scopes and artifacts, and diff two snapshots ("did our
  crypto posture regress since last quarter?").

Everything is read-only. The assistant cannot change anything in your tenant
through this connection.

## Connect a GUI assistant (Claude.ai, ChatGPT, Gemini)

No token copy-paste required. The AI client handles authentication via OAuth —
it opens the Vista login page, you sign in, and then approve read-only access.

**Step 1 — Copy your MCP URL**

Go to **Settings → API Tokens**. The **Connect an AI assistant** card at the
bottom shows your MCP URL. Click **Copy URL**.

The URL is always: `https://<your-vista-host>/api/v1/mcp-service/mcp`

**Step 2 — Add an MCP connector in your AI client**

Paste the URL into your AI client's connector or tool settings. The exact
location varies by client:

| Client | Where to paste |
|--------|----------------|
| Claude.ai | Settings → Integrations → Add MCP server |
| ChatGPT | Settings → Connected apps → Add custom connector |
| Gemini | Settings → Extensions → Add MCP |

**Step 3 — Approve access**

Your AI client opens the Vista login page automatically. Sign in with your
Vista credentials. Vista shows a consent screen listing the read-only scopes
it will grant — click **Authorize**.

The client receives a scoped access token. It is stored in the client, not
shown to you; you can revoke it at any time from **Settings → API Tokens**.

**Step 4 — Ask questions**

Good starting points:

- "Give me a risk summary of my crypto inventory."
- "Which certificates expire in the next 30 days, and which assets do they live on?"
- "What's blocking my PCI-DSS score? Show me the worst control's findings."
- "Compare my two most recent CBOM artifacts and tell me what regressed."
- "How post-quantum ready are we? What should we migrate first?"

## Connect Claude Code (CLI)

Claude Code can use the same OAuth flow automatically when you run
`claude mcp add`. It opens a browser for authorization and stores the token in
your local Claude config — no manual token copy required:

```bash
claude mcp add --transport http vistaplatform \
  https://<your-vista-host>/api/v1/mcp-service/mcp
```

If you prefer to use a Personal Access Token directly (useful for scripts or
environments without a browser):

```bash
claude mcp add --transport http vistaplatform \
  https://<your-vista-host>/api/v1/mcp-service/mcp \
  --header "Authorization: Bearer <your-pat>"
```

See **Personal Access Tokens** below for how to mint one.

## Personal Access Tokens (advanced)

For scripted access or clients that don't support OAuth, you can create a
**Personal Access Token (PAT)** and pass it directly as an `Authorization:
Bearer` header.

Go to **Settings → API Tokens → New token**:

1. Name it for where it will live (e.g. "CI pipeline").
2. Pick permissions — the default set (`assets.read`, `compliance.read`,
   `reports.read`) covers all 14 MCP tools.
3. Pick an expiry (default 90 days, max 1 year).
4. **Copy the token immediately.** It is shown exactly once. Treat it like a
   password and store it in a secret manager.

Tokens are listed with their prefix, last-used time, and status. Revoke one at
any time from the same page. After revocation, in-flight sessions may keep
working for up to 15 minutes (the lifetime of the short-lived internal
credential), then fail.

## Security model

- Connections are scoped to **your tenant and your role** — no other tenant's
  data is visible, and you cannot access data your own role can't.
- Only **read-only permissions** are granted; the permission model cannot
  express a write.
- Tokens and OAuth credentials are never stored by VistaSecurity in plaintext
  (only hashed). They are never forwarded to data services.
- 25 active tokens per user; OAuth-granted tokens count against this limit.
- Revocation is immediate at the credential store (≤15 min for cached
  sessions).
