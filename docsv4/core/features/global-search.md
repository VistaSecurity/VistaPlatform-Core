# Global search (⌘K)

A quick-find palette lets you jump to anything in the platform without clicking
through the navigation.

## Opening it

- Press **⌘K** (Mac) or **Ctrl+K** (Windows/Linux) from any page, or
- click the **Search…** button in the top bar.

## What you can find

Start typing (two characters or more) and results appear, grouped by type:

- **Infrastructure Assets** — by hostname or IP
- **Certificates** — by common name or subject
- **Asset Classes** — by class name or path ("switch", "hardware.computer").
  Opening one takes you to every asset in that class *and everything under it*
- **Relationships** — what the best-matching asset is attached to, read from its
  own side ("web01 runs on esxi-03"). This is the quickest route to "the switch
  is being replaced on Friday — what is behind it?"
- **Devices** — by hostname or IP
- **Sensors** — by name or IP
- **Quick navigation** — type a page name (e.g. "posture", "CBOM", "sensors")
  to jump straight there

With the box empty, the palette shows the full quick-navigation list so you can
hop to any section.

## Getting around

- **↑ / ↓** move the highlight
- **Enter** opens the highlighted result
- **Esc** (or click outside) closes the palette

Selecting an **asset** opens its own page. Selecting a **certificate** takes you
to the Certificates lens with the search already filled in — certificates have no
page of their own. A **class** or a **relationship** opens Inventory filtered to
what you picked; a device or sensor opens its list under **Discovery**.

> Global search only ever shows you data you already have access to — it searches
> the same inventory your role can see.

