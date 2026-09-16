# Query

Anywhere the platform asks "which things?", the answer is a **query** — one line
of text like `class:server and environment:production`.

The same line works everywhere: the Inventory search box, a saved view, a scope
on a CBOM, an auto-approval rule, and the `query` argument an AI agent sends
through MCP. There is one language, so what you learn in one place transfers to
all of them.

You never have to type one. The filter rail writes the query for you and shows
you what it wrote — which is how most people learn it.

## The shape of it

```
field:value
```

Terms sit next to each other to mean "and":

```
class:server environment:production
```

…which the platform will rewrite as `class:server and environment:production`,
because that is the same thing said plainly.

## The handful you will actually use

| Want | Write |
|---|---|
| Match a value | `environment:production` |
| Match any of several | `environment in (production, staging)` |
| Exclude | `not environment:development` |
| Compare a number | `risk_score >= 70` |
| Compare a date | `last_seen < now-30d` |
| A whole branch of the class tree | `class:hardware` — matches servers, switches, everything under Hardware |
| One exact class | `class=server` |
| Starts with | `hostname:web-*` |
| Something the thing has | `endpoint:(port:443)` · `cert:(not_after < now+30d)` |
| Who proposed it | `proposed_by:matcher` — the machine proposer behind a suggestion |
| Just search | `payroll` — looks at names, hostnames, identifiers and tags |

Group with parentheses when you need to: `(a or b) and c`.

## Worked examples

```
environment:production class:hardware.computer.server not exists(owner_email)
```
Production servers nobody owns.

```
cert:(not_after < now+30d)
```
Anything with a certificate expiring in the next month.

```
last_seen < now-30d and status:monitoring
```
Approved, in inventory, and not seen for a month.

```
risk:not_assessed and class:hardware
```
Hardware nobody has scored yet. Note this is **not** the same as
`risk:informational`, which means "we looked, and it scored zero". The platform
keeps those apart on purpose — see below.

```
endpoint:(port in (23, 161, 512, 513))
```
Plaintext management protocols exposed.

```
proposed_by:matcher
```
Everything one particular machine proposer argued for — here, the identity
matcher, which is to say the open merge proposals. `proposed_by:` asks "which
machine decided this?", where `source:` asks "what *kind* of thing decided it".
Use `source:inferred` for everything a model proposed; use `proposed_by:` when
you want one proposer's work, and a curated rule's id works there too.

## Three things worth knowing

**"Not assessed" is not "fine."** A predicate about something nobody measured
matches neither the predicate nor its opposite. `risk_score >= 70` and
`not risk_score >= 70` together do **not** cover your whole inventory — what is
left over is exactly the things nobody has looked at. That residue is the point;
it is what tells you where your coverage gaps are.

**`:` is forgiving, `=` is exact.** `hostname:web` finds anything containing
"web", case-insensitively. `hostname="Web01"` matches that name and nothing
else, capital W included.

**Dates read forwards.** `last_seen < now-14d` is "not seen for two weeks";
`last_seen > now-14d` is "seen in the last two weeks". There is no shorthand for
either, because a shorthand would read both ways.

**`crypto:(…)` and `cert:(…)` include crypto that is not on a network port.**
Not every piece of cryptography an asset uses sits behind a socket — an
encrypted cloud volume, a database at rest, a signing configuration. Those
belong to the asset without belonging to any one of its endpoints, and asking an
asset about its crypto or its certificates returns them alongside the rest.
Asking an **endpoint** about its crypto (`endpoint:(…)` with `crypto:(…)` inside
it) is the narrower question and returns only what was measured on that port.

## Where queries are used

| Surface | What the query does |
|---|---|
| **Inventory** | Filters the list. The rail writes it; you can edit it directly. |
| **Saved views** | A named query. Keep it to yourself or share it with your team. |
| **Scopes** | The boundary a CBOM attests to (Settings → Scopes). |
| **Auto-approval rules** | Which discoveries get approved without a human. |
| **MCP / AI agents** | The `query` argument, and the query an agent shows you alongside its answer. |

## When it does not understand you

You get the exact spot and, usually, the fix:

```
environment:production and hostnaem:web-1
                           ^^^^^^^^
no field "hostnaem" on assets. did you mean "hostname"?
```

A query that does not make sense is refused, not guessed at. That matters most
for scopes and approval rules: a rule with a typo used to be a rule that
silently did **less** than you wrote.

## Related

- [Inventory and lenses](./inventory-and-lenses.md)
- [Scopes](./scopes.md)
- [Asset approval](./asset-approval.md)
- [API tokens and MCP](./api-tokens-and-mcp.md)
