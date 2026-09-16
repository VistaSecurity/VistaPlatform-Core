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
   (*Settings → Infrastructure → Network Segments*)
2. **Add locations** — organize assets by site or cloud region.
   (*Settings → Infrastructure → Locations*)
3. **Add an agent** — register a sensor or discovery agent to start finding assets.
   (*Discovery → Sensors & Agents*)

Each step has a **Set up** button that takes you straight to the right page, and a
**Mark as done** button to tick it off once you've finished.

A progress bar at the top counts completed steps, and a confirmation replaces it
once every step is done.

### What each step needs permission-wise

You only get the buttons for steps you can actually perform. A step your role
can't do shows **"Ask an admin"** instead of **Set up**.

| Step | Permission it needs |
|---|---|
| Add network segments | **View tenant settings** — the segment page is reachable with settings read access; *creating* a segment additionally needs settings update. |
| Add locations | **View tenant settings** — same as above. |
| Add an agent | **Create sensors** — the same permission as the **Register sensor or agent** button the step links to. |

> **Already have an inventory?** You don't have to add everything by hand. You can
> **import a spreadsheet** (CSV/XLSX) to bulk-create network segments (*Settings →
> Infrastructure → Network Segments → Import*) or assets (*Discovery → Command
> Center → Import from spreadsheet*, or the **Import** control on Inventory), or
> **pull servers from a connected CMDB** if you use ServiceNow, Device42,
> SolarWinds, or Oomnitza. See [Spreadsheet Import](./spreadsheet-import.md) and
> [CMDB Integrations](./cmdb-integrations.md).

## Turning it off

- **Just for you:** click **Dismiss setup guide** at the bottom of the checklist.
  The reminders stop for your account (across all your devices). You can still
  reopen the page from the profile menu any time.
- **For your whole organization:** anyone with the **Update tenant settings**
  permission — a Tenant Administrator, by default — can clear **"Show onboarding
  to my team"** at the bottom of the checklist to hide it for everyone. The
  checkbox is only shown to members who hold that permission.
