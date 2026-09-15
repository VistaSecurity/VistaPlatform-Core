# AI assistant

**Settings → AI assistant** (Tenant Administrator).

Vista Platform is **AI-native and never AI-dependent**. Every place a model could
help has a rule-based behaviour behind it that runs whether or not anyone has
configured a model — so a deployment with no AI at all is fully functional, not
degraded and not half-built. This page is where you see which of those places
have a model available here, what happens in each when one is not, and where you
turn the whole thing off for your organization.

The page exists in every edition. It is not an upsell screen: the two switches
on it are yours in Core as much as in Enterprise, and the capabilities table is
an honest inventory of what this particular deployment does today.

## How to get there

Click your profile chip (top right) → **Organization Settings** → **Integrations
→ AI assistant**.

You need the **settings.update** permission, which the Tenant Administrator role
has. Other roles will see an access notice rather than the page.

## What the page shows

### This deployment

| Row | What it means |
|---|---|
| **Model provider** | Whether whoever runs this deployment has connected a model endpoint, and which kind. |
| **Model** | The model id this deployment asks for, when one is pinned. |
| **Capabilities on** | How many of the capabilities below can answer here right now. |

The model provider is **not** configured from this page and cannot be. It is set
by the operator who runs the platform, in the deployment's environment, alongside
the database and the certificates — see
[Connecting a model provider](../operate/configuration/ai-provider.md). That is
deliberate: it involves a credential and an endpoint, both of which belong with
the rest of the infrastructure rather than in a tenant's settings screen.

Two things you will **never** see here, by design: the endpoint address and
anything resembling an API key. The platform's configuration object has no field
that can hold a credential at all — it holds the *name* of the environment
variable the operator put one in — so there is nothing for this page to leak.

### Capabilities

One row per AI capability, and four columns:

- **Capability** — what it is.
- **Where** — where in the product you meet it.
- **Without AI** — what answers when no model does. This column is the point of
  the page. Every row has an entry; none of them is "nothing".
- **Status** — one of four:

| Status | Means | Who fixes it |
|---|---|---|
| **On** | Something can answer through this capability here. | — |
| **Enterprise** | This build has no model client in it at all. | A change of edition. |
| **No provider** | The build has it; nobody has connected a model endpoint. | Whoever runs the deployment. |
| **Not yet built** | Nothing implements this capability yet, in any edition. | Us. |

"Enterprise" and "No provider" are shown separately on purpose. One of them is a
purchase and the other is ten minutes of an administrator's time, and a single
grey dash for both would send you to the wrong person.

### Your organization's controls

Two switches, both yours, both applying to every capability above.

#### Use the AI assistant

The kill switch. Turn it **off** and no generative capability runs for your
organization — no prompt is sent anywhere on your behalf, by any part of the
platform, even where this deployment has a model provider connected and working.

Nothing breaks. Every capability falls back to exactly the behaviour in the
"Without AI" column: the CBOM comparison still writes its summary, the inventory
still classifies assets, and the end-of-life catalogue is still consulted. You
lose the model's contribution and nothing else.

It is enforced twice — once where each capability is invoked, and again at the
boundary every outbound model call passes through — so a capability added in a
future release inherits the switch rather than having to remember it.

#### Record the questions we send

**Off by default.** Every AI call is written to your audit trail either way,
with the capability, the model, who asked, how many tokens it used, and a
*fingerprint* of what was sent. What the fingerprint does not include is the
text: a person's question, or a document they pasted.

Turn this **on** and that text is stored in the audit trail alongside the
fingerprint. Turn it off and it is not. That is the whole difference.

Whichever way it is set, secrets are removed from a prompt before anything is
sent to a model, and the audit trail records the scrubbed version rather than
the original — so switching this on does not put credentials into your logs.

#### What an asset row carries when it is sent

When you ask a question about your inventory, the rows that answer it travel to
the model. They are **projected**, not sent whole: the model sees class,
hostname, display name, primary address, environment, business unit, support
group, site/region/zone, ownership, status, risk and dates.

It does **not** see the owner's email address, free-text descriptions, tags,
attributes, or the metadata collectors write. Owner addresses are personal data
about a named individual and are removed before the rows leave, so a question
like *"which production servers have no owner?"* is still answered — that part
runs in the database and the rows are the answer — while the addresses
themselves are never sent to a model provider.

Reasons to turn it on: you want to review exactly what was asked, or you are
troubleshooting an answer that looked wrong. Reasons to leave it off: the text
people type is the most sensitive thing in this whole path, and an audit trail
with a different retention policy from the data it quotes is a second copy of
that data.

#### Drafting on custom policies

A third row appears when authoring on custom policies is switched off across the
platform. It is **not** your setting and there is no toggle on it — it is a
temporary, platform-wide pause, and the row states the reason and what is
unaffected. The same notice appears on **Settings → Custom Policies**, which is
where the capability itself lives.

## Saving

Change either switch and **Save changes** becomes available. Saving writes to
your organization's settings and is recorded in your audit trail against your
user, like every other settings change.

If your platform administrator also has a copy of these settings open, the last
save wins. Reload the page to see the current values.


## Related

- [Audit Logging](../guides/audit-logging.md) — where the record of every AI call lands
- [Roles & Permissions](./roles-and-permissions.md) — who can open this page
- [Editions](../editions.md) — which capabilities belong to which edition
- [Connecting a model provider](../operate/configuration/ai-provider.md) — the operator side of the "Model provider" row above
