# Roles and Permissions

Every member of your organization holds a **role**, and the role decides what
they can see and do. Vista ships with a set of **built-in roles** that cover the
common shapes, and lets you define **custom roles** of your own when your team
doesn't fit them.

Find it at **Settings → People & Access → Roles & Permissions** (open the profile
chip in the top-right → **Organization Settings**).

You need the **Manage users** permission to open this page. It is the same
permission that governs every action on it, so if you can see the page you can
use it.

## What the list shows

Each role is a card with:

- its **name**, and whether it is **Built-in** or **Custom**
- its **description**
- how many **permissions** it grants and how many **members** hold it

Click any card — or **View / Edit permissions** — to open the permission drawer.

## The permission drawer

The drawer lists the **whole permission catalogue**, grouped by what each
permission applies to (assets, billing, users, and so on). A ticked box means
this role grants that permission.

For a custom role, tick and untick freely and click **Save permissions**. Saving
**replaces** the role's permission set with exactly what is ticked, and takes
effect the next time an affected member makes a request.

### Why some boxes are locked

Two different things can lock a checkbox, and the drawer tells you which:

**The role is built-in.** The whole matrix is read-only. This isn't a
restriction we added for its own sake: Vista re-applies the canonical permission
set for every built-in role each time the platform is upgraded. If we accepted an
edit here, it would be quietly undone at the next upgrade and you'd have no way
to know. Rather than lie about it, the drawer says so — and if you need a
variation on a built-in role, **create a custom role** instead.

**You don't hold that permission yourself.** You can't grant a permission you
don't have. Otherwise anyone who can manage users could mint a role carrying
anything and assign it to themselves, which would make "manage users" a way to
become an administrator of everything. Two states follow from this:

- **Ticked and locked** — the role already grants it. It stays granted; you just
  can't be the one to change it.
- **Unticked and greyed out** — you can't add it.

If you need one of those permissions on a role, ask someone who holds it to make
the change.

## Create a role

1. Click **New role**.
2. Enter a **display name** — this is what everyone sees. A lowercase **key** is
   derived from it and shown below; the key is fixed once the role exists.
3. Optionally add a **description**.
4. Click **Create role**.

The new role starts with no permissions. Open it and tick what it should grant.

Custom roles are yours: platform upgrades never rewrite them.

## Delete a role

Click the **✕** on a custom role. Built-in roles have no delete control —
they can't be removed.

If nobody holds the role, it is deleted immediately.

If members still hold it, Vista **refuses** rather than quietly moving people to
some other role behind your back. The dialog tells you how many members hold it
and asks which role they should move to. Pick one and click **Reassign and
delete** — members who already hold your chosen role simply lose the deleted one.

One case has no retry from this dialog: if the role is referenced by your **SSO
group mappings** or is your SSO **default role**, deleting it would silently stop
provisioning federated users. Update **Settings → People & Access → Security &
SSO** first, then come back and delete it.

## Assigning roles to people

Roles are assigned per member under **Settings → People & Access → Members** —
use the **Change role** control on a member's row, or pick a role when you
[invite someone](member-invitations.md).
