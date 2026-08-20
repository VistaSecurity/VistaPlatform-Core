# Legal documents for operators

Vista Platform is self-hosted. That single fact decides who is responsible for
what, and it is the thing most legal templates get wrong when they are written
for SaaS and then handed to a self-hosted product.

**You run the deployment. You are the service provider to your users, and — in
data-protection terms — you are the controller of the data in it.** We are the
software author. We do not host your deployment, cannot see your inventory, and
receive nothing from it. There is no phone-home, no telemetry, and no licence
check that reaches us.

That means the documents your users agree to are **yours**, not ours, and
nothing here is a substitute for your own counsel reviewing them.

## What ships, and where it lives

| Document | Where it lives | Who agrees to it | How |
|---|---|---|---|
| **Terms of Service** | Seeded into the platform database; edit at **Settings → Legal** | Your users | Click-through at sign-up, re-prompted when you publish a new version |
| **Privacy Policy** | Same | Your users | Same |
| **Data Processing Agreement** | [`data-processing-agreement.md`](./data-processing-agreement.md) | You and your customer | Signed offline, not click-through |
| **Software licence (FSL-1.1-ALv2)** | `LICENSE.md` at the repository root | You and the software author | Accepted by using the software |

The first two are **templates carrying `[BRACKETED]` placeholders**. They are
deliberately not finished documents: a Terms of Service naming the wrong entity,
or a Privacy Policy promising a retention period you do not honour, is worse
than none, because it is an enforceable promise you did not mean to make.

> ⚠️ **Replace every bracketed value before you let anyone accept them.**
> An agreement naming a party that does not exist is unlikely to be
> enforceable, which is the opposite of what click-through acceptance is for.

**The platform helps, but it cannot decide for you.** Settings → Legal warns
when the published version still contains placeholders, and publishing a
document that still has them requires an explicit confirmation naming what was
found. The confirmation exists because a bracketed capitalised phrase is
occasionally legitimate — but it is a deliberate act, not a default.

## How acceptance is recorded

Every acceptance writes an append-only row capturing the user, the document
**version**, the SHA-256 hash of the exact text accepted, the time, and the
server-observed IP address and user-agent.

The hash is the part that matters. It lets you prove *which words* a user
agreed to, rather than which document title — the usual failure mode when a
click-through agreement is disputed years later and the text has since changed.

Publishing a new version through **Settings → Legal** does not rewrite history:
the previous version and its acceptances stay in place, and existing users are
asked to accept the new one on their next visit.

## When you need a Data Processing Agreement

You need one when you process personal data **on behalf of someone else** and
they ask for it — which under the GDPR (Art. 28) and the UK GDPR they are
obliged to do.

In practice:

| Situation | DPA needed? |
|---|---|
| You run Vista Platform for your own organization, on your own infrastructure | **No.** You are the controller of your own data; there is no processor to contract with. |
| You run it for a client, a subsidiary you do not control, or as part of a managed service | **Yes** — you are their processor, and they need this from you. |
| You use a cloud provider, a managed database, or a hosting partner underneath | **Yes**, between you and them — and they appear in your sub-processor list. |
| You want a DPA from the software author | **No, and there is nobody to sign it.** We process nothing. Software supply is not processing. |

That last row surprises people, so it is worth stating plainly: a company that
sells you software you run yourself is not your processor. There is no data
flow to contract about.

## Answering a data subject request

Your Privacy Policy promises data subject rights — access, correction, erasure,
portability. The platform can now serve the two that need tooling.

**Access and portability.** Settings → Members → the export button on a member's
row produces a JSON file containing their profile, which versions of your legal
documents they accepted, their invitation, their API token *names*, and their
activity from the last 12 months. It never contains passwords or token values,
and it states inside the file what it leaves out. Users can serve themselves
from **My Profile → Your data**, which needs no special permission — the most
common version of this request is a person's own.

**Erasure.** Settings → Members → the erase action anonymizes the person in
place rather than deleting them: their profile becomes an anonymous placeholder,
their API tokens and invitation are deleted, and their name is removed from the
activity trail. It runs in one transaction that re-reads its own work and rolls
back rather than report an erasure that did not happen.

### What erasure keeps, and why

Erasure is not absolute, and a policy that pretends otherwise creates its own
exposure. Three categories survive, deliberately:

| Kept | Why |
|---|---|
| **Legal acceptance records** — version, content hash, time, address | This is your evidence that they agreed to your terms. Deleting it on request destroys your proof of the agreement at the request of the one person who might later dispute it. Retained for the establishment and defence of legal claims. |
| **Activity trail entries**, with the identity removed | The events stay so the record remains complete and countable. A log that can be selectively rewritten on request proves nothing — including that nobody else rewrote it. |
| **Tickets and comments they authored**, shown as an anonymous author | Those records carry only a user id, so anonymizing the profile anonymizes them automatically. The text is an operational record about your estate. |

### What erasure does not reach

State these to a data subject rather than let them assume otherwise:

- **Backups.** Data ages out on your own backup retention schedule.
- **Value snapshots in older activity entries.** An entry recording a profile
  change may still contain a previous email address inside its payload.
- **Personal data inside discovery data** — an address in a certificate subject,
  a name in an SSH key comment. It describes your estate, and removing it would
  corrupt the inventory. That is a controller-side decision, not something the
  platform should silently rewrite.

**Retention periods are still yours to enforce.** The template states them; the
platform does not expire data on its own.

## See also

- [Data Processing Agreement template](./data-processing-agreement.md)
- [Production checklist](../deployment/production-checklist.md) — the operational
  half of going live
- [Security architecture](../security/architecture.md) — the substantiation
  behind the technical measures listed in the DPA's Annex II
