# Inviting Members

Vista uses **one invitation flow for every sign-in method**. You invite a person
by email and choose their role; *they* choose how to sign in when they accept —
a password, **Google**, or **Microsoft** — based on what your organization has
enabled. You don't pre-decide their method, and you never have to send anyone a
long sign-in URL.

## Invite someone

1. Go to **Settings → People & Access → Members**.
2. Click **Invite member**.
3. Enter their **email address** and pick a **role** (you can change it later).
4. Click **Send invitation**.

They receive an email with an **Accept invitation** link. The dialog also shows a
copyable **invite link** — handy if your email relay is still being set up or the
message is slow to arrive. Anyone with that link can accept *as the invited email
address*, so treat it like a password.

## What the invitee sees

Opening the accept link shows a page that confirms the email they're joining as,
then offers the methods your organization allows:

- **Continue with Google** / **Continue with Microsoft** — appears for each SSO
  provider you've configured under **Security & SSO**. They authenticate with
  that provider and land in the app; their account is created and linked
  automatically with the role you chose.
- **Set a password** — appears unless your organization is **SSO-only**. They
  choose a password and are signed in immediately.

Either way the result is the same account, with the role from the invitation.
Members can add another sign-in method later from their profile.

## Manage pending invitations

Under **Members**, a **Pending invitations** list shows everyone invited but not
yet joined. For each you can:

- **Resend** — issues a fresh link and emails it again (the old link stops working).
- **Revoke** — cancels the invitation; the link stops working.

Invitations expire after **7 days**; resend to extend.

## How this relates to SSO settings

- The methods on the accept page come straight from **Settings → People & Access →
  Security & SSO** (your configured Google / Microsoft providers) and your
  **authentication policy**. Configure SSO there first if you want invitees to
  join with Google or Microsoft. See the Security & SSO guide.
- **Allowed email domains** on a provider still apply: an invitee can only complete
  SSO if the identity provider returns an address in an allowed domain.
- You do **not** need to create an account before someone signs in with SSO —
  inviting them (or, where enabled, their first SSO sign-in) creates it. Creating
  a separate password account for someone who will use SSO is unnecessary and is
  not how onboarding is meant to work.

## Notes

- Inviting an email that already belongs to a member is rejected — they already
  have access.
- The invited role is applied on accept. Adjust it anytime from the member row
  (**Change role**).
