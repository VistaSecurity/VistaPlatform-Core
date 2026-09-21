# AI Assistant Integration (MCP)

Vista exposes a read-only **MCP (Model Context Protocol) server** so your AI
assistant — Claude.ai, ChatGPT, Claude Code, or any MCP-capable agent — can query
your cryptographic inventory, compliance posture and CBOM artifacts directly.
You bring your own AI; Vista only answers the questions your assistant asks,
scoped to your tenant and role, read-only.

## What your assistant can do

Once connected, your assistant has 23 tools:

- **Inventory** — search your assets with the [query language](./query.md),
  find them by free text when you don't know a field to filter on, count them
  by any facet, read one asset in full (its class, identifiers, endpoints,
  attributes and risk), read its change history, list the software installed on
  it, and browse the asset class tree.
- **Relationships** — the typed relationships on one asset (what it runs on,
  hosts, depends on, connects to), the graph around it out to three hops, and
  its blast radius: what else is affected if it changes. See
  [Relationships](./relationships.md).
- **Crypto** — certificates (by expiry, issuer, key algorithm), crypto
  configurations, and the platform's authoritative algorithm assessments.
- **Risk & PQC** — your risk summary and post-quantum readiness breakdown.
- **Compliance** — frameworks and scores, per-framework evaluation, and
  drill-down into a failing control's findings.
- **CBOM** — list your scopes and artifacts, and read one artifact's metadata:
  the scope it was generated from, its content hash, component count, and how
  fresh your inventory was when it was taken.

Two of the 23 reach capabilities that are not part of Vista Platform Core —
asking about your inventory in plain words, and comparing two CBOM artifacts.
Both are offered to your assistant on every install, and on Core they answer
*"not included in your subscription"* rather than failing obscurely.


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

## Connecting from outside your network

Vista Platform runs in **your** cluster, on whatever address you gave it — very
often a private one, with a certificate from your own internal CA. Your MCP URL
inherits that. So before you paste it anywhere, answer one question:

**Which machine opens the connection to your MCP URL?**

| Your assistant | What dials your MCP URL | Reaches a private address? |
|---|---|---|
| Claude Code (CLI) | Your own machine | **Yes** |
| A desktop assistant running an MCP bridge locally | Your own machine | **Yes** |
| Claude.ai | Anthropic's servers | **No** |
| ChatGPT | OpenAI's servers | **No** |

If the program dialling your MCP URL sits on your network, a private address is
fine and none of the rest of this section applies. If it is a hosted service, it
is dialling from the internet, and **all three** of the following have to be
true. Most people expect only the first.

**1. A public address.** A hostname that resolves on the public internet and
reaches your cluster ingress.

**2. A publicly-trusted certificate.** A certificate from your internal CA will
be rejected. There is no way to tell a vendor's servers to trust your private
CA — you cannot install a root on machines you do not run. This is the one that
catches people out: internal TLS that works perfectly in your own browser, on
machines where you *have* installed that root, is not enough here.

**3. A matching OAuth issuer.** Sign-in is discovered, not guessed. The client
reads `https://<your-vista-host>/.well-known/oauth-authorization-server` and is
handed the addresses of the authorize and token endpoints; the token step is
then a back-channel call the client's own servers make. If those addresses
still name your internal hostname, the client is handed an address it cannot
resolve, and the connection fails *after* you have already signed in — which
reads like a bug rather than a configuration gap. Check what is advertised
today:

```bash
curl -s https://<your-vista-host>/.well-known/oauth-authorization-server
```

The chart derives those addresses from your `tls.dnsName`. If the public address
differs, set `appConfig.oauthCallbackBaseURL` (the `OAUTH_CALLBACK_BASE_URL`
environment variable) to the public one. When it is unset, the platform falls
back to the first configured CORS origin — which is your tenant app host, not
necessarily the address the assistant used.

### A tunnel is the easier route

For a hosted assistant, an outbound tunnel — Cloudflare Tunnel, Tailscale Funnel
and similar — satisfies all three at once: it gives you a public hostname with a
publicly-trusted certificate, and you point `appConfig.oauthCallbackBaseURL` at
that same hostname. Your cluster only ever makes outbound connections, so no
inbound port is opened in your firewall.

Publishing your ingress directly works too, but it is a security decision rather
than a networking one: the same hostname publishes your sign-in endpoints and
your web UI to anyone who finds it. Make that choice deliberately.

What you expose either way is a **read-only** surface, scoped to one tenant and
one role — it cannot change anything in your platform. That lowers the stakes;
it does not remove them.

Taken together with the sign-in limitation below, the shortest working path for
most people today is **Claude Code, on a machine inside your network, with a
Personal Access Token**: no public address, no certificate change, no tunnel.

## Connect a GUI assistant (Claude.ai, ChatGPT)

> **Known limitation — the automatic sign-in flow does not work yet.**
> Hosted AI clients register themselves with an OAuth server on the fly, using
> [dynamic client registration](https://www.rfc-editor.org/rfc/rfc7591) (RFC
> 7591). Vista's authorization server does not implement it yet, so a client
> that requires it stops before the login page appears. Verified against Claude
> Code, which reports *"Incompatible auth server: does not support dynamic
> client registration."* Claude.ai and ChatGPT register the same way.
>
> Until that lands, connect with a **Personal Access Token** instead — see
> [Personal Access Tokens](#personal-access-tokens-advanced) below. The steps in
> this section describe the intended flow and are kept for reference.

The AI client handles authentication via OAuth — it opens the Vista login page,
you sign in, and then approve read-only access.

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

**Gemini is not connectable today.** Vista Platform authorizes each AI client
against an allow-list of that client's exact sign-in callback address, so a
client whose address we cannot verify has nothing to match and every attempt is
rejected. Google has not published the consumer Gemini app's address, and
guessing at one would be a hole rather than a feature. Gemini CLI signs in
through a loopback address on your own machine, which is a pattern Vista
Platform already accepts, and is expected to work once it is registered as a
client in its own right. If you want a command-line assistant in the meantime,
use [Claude Code](#connect-claude-code-cli).

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
- "How post-quantum ready are we? What should we migrate first?"
- "When did this asset last change, and what changed?"
- "What runs on this server, and what breaks if I take it down?"


## Connect Claude Code (CLI)

Use a **Personal Access Token**. The bare `claude mcp add` form below is the
intended flow, but it does not work today — Claude Code requires dynamic client
registration, which Vista's authorization server does not yet implement, and the
connection fails before a browser opens:

```bash
# Does NOT work yet — see the note above.
claude mcp add --transport http vistaplatform \
  https://<your-vista-host>/api/v1/mcp-service/mcp
```

This form works, and is also what you want for scripts and for environments
without a browser:

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
   `reports.read`) covers all 23 MCP tools.
3. Pick an expiry (default 90 days, max 1 year).
4. **Copy the token immediately.** It is shown exactly once. Treat it like a
   password and store it in a secret manager.

Tokens are listed with their prefix, last-used time, and status. Revoke one at
any time from the same page. After revocation, in-flight sessions may keep
working for up to 15 minutes (the lifetime of the short-lived internal
credential), then fail.

## A 1.0.0 change if you parse tool output

Finding-shaped answers changed shape in 1.0.0, along with the rest of the
platform's finding API: a finding now names its **subject** rather than an
asset (`subject_id` / `subject_type`, not `asset_id` / `asset_type` —
`subject_type` is `asset` or `certificate`), and **severity is one lowercase
ladder** — `info` / `low` / `medium` / `high` / `critical` — rather than the
old `Low` / `Med` / `High` / `Critical`. If your assistant or a script stores
or re-parses raw tool output rather than just reading it back to you in
English, update for the new field names and values.

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
