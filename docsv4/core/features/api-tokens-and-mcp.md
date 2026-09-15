# AI Assistant Integration (MCP)

Vista exposes a read-only **MCP (Model Context Protocol) server** so your AI
assistant — Claude.ai, ChatGPT, Gemini, or any MCP-capable agent — can query
your cryptographic inventory, compliance posture and CBOM artifacts directly.
You bring your own AI; Vista only answers the questions your assistant asks,
scoped to your tenant and role, read-only.

## What your assistant can do

Once connected, your assistant has 18 tools:

- **Inventory** — search your assets with the [query language](./query.md),
  count them by any facet, read one asset in full (its class, identifiers,
  endpoints, attributes and risk), read its change history, and browse the
  asset class tree.
- **Crypto** — certificates (by expiry, issuer, key algorithm), crypto
  configurations, and the platform's authoritative algorithm assessments.
- **Risk & PQC** — your risk summary and post-quantum readiness breakdown.
- **Compliance** — frameworks and scores, per-framework evaluation, and
  drill-down into a failing control's findings.
- **CBOM** — list scopes and artifacts, and diff two snapshots ("did our
  crypto posture regress since last quarter?").

Everything is read-only. The assistant cannot change anything in your tenant
through this connection.

### Your assistant speaks the same query language you do

The asset tools take a `query` — the same one line of text the Inventory filter
rail writes and a saved view stores. Ask in English; the assistant writes the
query. For example:

| You ask | Your assistant sends |
|---|---|
| "production servers nobody owns" | `environment:production class:hardware.computer.server not exists(owner_email)` |
| "what has a certificate expiring this month?" | `cert:(not_after < now+30d)` |
| "high-risk things we've seen this week" | `risk >= high and last_seen > now-7d` |
| "deprecated crypto outside dev" | `crypto:(algorithm.deprecated:true) and environment in (production, staging)` |
| "hardware nobody has scored yet" | `risk:not_assessed and class:hardware` |
| "what's waiting for approval?" | `status:pending_approval` |

Two things follow from this, and both are deliberate.

**The assistant can show you the query it ran.** Every asset answer comes back
with the query attached — and it is the query the platform *actually ran*, not
the one the assistant composed. Those differ: the platform adds your default
scope (approved inventory only). Ask "what query did you run?" and you can paste
the answer straight into the Inventory search box to see the same rows yourself.

**A query it gets wrong is refused, not guessed at.** The assistant gets back
the exact problem, where in the query it is, and usually the fix — so it corrects
itself and retries rather than quietly answering a different question.

By default the assistant sees your **approved inventory** — the same set the
Inventory page shows. Ask about something outside it and it can look: "what's
waiting for approval?" works, because naming `status` in the query sets the
default aside. The query it shows you tells you which set it read.

### What a zero means

Where an answer includes a risk score, the platform distinguishes **"we looked,
and it's clean"** from **"nobody has looked"** — a score of 0 with an empty
`risk_assessed_by` is *not assessed*. The tools carry that distinction through,
and the tool descriptions tell the assistant never to report the second as "no
risk". If an answer sounds too clean, ask what has not been assessed.

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

- "Give me a risk summary of my inventory."
- "How many assets do I have, broken down by class and environment?"
- "Which production servers have no owner? Show me the query you ran."
- "Which certificates expire in the next 30 days, and which assets do they live on?"
- "What's blocking my PCI-DSS score? Show me the worst control's findings."
- "Compare my two most recent CBOM artifacts and tell me what regressed."
- "How post-quantum ready are we? What should we migrate first?"
- "When did this asset last change, and what changed?"

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
   `reports.read`) covers all 18 MCP tools.
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
