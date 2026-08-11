# Getting Started checklist

When you first sign in, the platform shows a short **Getting Started** checklist
that walks you through the few steps that make discovery and compliance useful.
Until you finish (or hide) it, you'll see a gentle reminder each time you log in.

## Where to find it

- A **login reminder** appears once per session with a link to the checklist.
- It's always available from the **profile menu** (bottom-left) → **Getting Started**.

The checklist disappears on its own once all steps are complete.

## The steps

1. **Add network segments** — define the networks you want discovery to scope to.
   (*Settings → Network Segments*)
2. **Add locations** — organize assets by site or cloud region.
   (*Settings → Locations*)
3. **Add an agent** — register a sensor or discovery agent to start finding assets.
   (*Discovery → Sensors & Agents*)

Each step has a **Set up** button that takes you straight to the right page. When
you've done a step, use **Mark as done** to tick it off.

You'll only see the steps you have permission to perform — if your role can't, for
example, register a sensor, that step shows "Ask an admin" instead.

> **Already have an inventory?** You don't have to add everything by hand. You can
> **import a spreadsheet** (CSV/XLSX) to bulk-create network segments or assets
> (*Settings → Network Segments → Import*, or *Discovery → Import from spreadsheet*), or
> **pull servers from a connected CMDB** if you use ServiceNow, Device42, SolarWinds, or
> Oomnitza. See [Spreadsheet Import](./spreadsheet-import.md) and
> [CMDB Integrations](./cmdb-integrations.md).

## Turning it off

- **Just for you:** click **Dismiss setup guide** at the bottom of the checklist.
  The reminders stop for your account (across all your devices). You can still
  reopen the page from the profile menu any time.
- **For your whole organization:** a **Tenant Admin** can clear **"Show onboarding
  to my team"** on the checklist to hide it for everyone in the organization.
