# Contributing

Thanks for considering it. A few things about this project that will save you
time before you start.

## How this repository works

VistaPlatform is **open core**. This repository holds the Core edition, which
is the whole product for a single organization. Enterprise and MSP features
live in a separate private repository and are not published here.

Development happens in an internal working tree and is exported to this
repository. Practically, that means:

- **Commit history here is squashed at export time.** This repository is not a
  continuous mirror of internal history, so don't be surprised when the log
  looks compressed.
- **Some directories will look conspicuously absent** (`services/*/ee/`). That
  is the edition boundary, and it is deliberate.

## We are not taking code contributions yet

**Please don't open a pull request right now — it will be closed unread, and
that is a waste of your time rather than a judgement on your patch.**

The reason is boring and temporary. The project is presently authored by one
person, and copyright sits with that person because no company holds it yet.
While that is true, accepting outside code makes the eventual tidy-up (moving
copyright into a proper entity) require tracking down every contributor. It is
far easier to sort the entity out first and open the doors after.

That will change. When it does, this file will say so.

**What is genuinely useful in the meantime:**

- **Bug reports.** Especially anything about discovery accuracy, a crypto
  assessment you think is wrong, or a deployment that will not come up.
- **Telling us the docs are wrong.** Being new to a codebase is a perishable
  advantage — the things that confuse you now are the things worth fixing.
- **Security findings**, privately: see [SECURITY.md](SECURITY.md).

Everything below describes how the code is expected to work, and stands whether
or not you are sending patches — it is worth reading if you are building from
source or running it yourself.

## How changes are expected to be shaped

These are the rules we hold ourselves to, and the ones outside patches will be
held to when the doors open.

**A feature is not done until a user can reach it.** An endpoint with no UI is
a gap, not a feature. If a change adds a capability, it needs its consumer
alongside it. This codebase has a history of half-built features and the rule
exists to stop that recurring.

## Ground rules that will fail CI if you miss them

- **Go 1.26 only.** Not 1.27+. `go.mod`, `go.work`, and Dockerfiles all pin it.
  The `Makefile` pins `GOTOOLCHAIN` to the **exact** version `go.work` declares,
  so `make` targets are already correct. Running `go` directly outside `make`,
  pin it yourself: `GOTOOLCHAIN=go1.26.6 go work sync` (match `go.work`). Not
  `GOTOOLCHAIN=local`, which cannot fetch the pinned patch release, and never
  `auto`, which will silently download 1.27+.
- **`standards/service-registry.yaml` is the source of truth** for services,
  ports, and routes. `docker-compose.yml` and the Traefik configs are generated
  from it — run `make generate` rather than hand-editing them.
- **The schema has no migration runner.** Changes append to
  `scripts/database/schema.sql` and every statement must be safely
  re-appliable, because the chart re-runs the whole file on each upgrade.
  Test yours by applying it **twice** against a real PostgreSQL.
- **OpenAPI specs in `api/openapi/` are authored; the TypeScript client is
  generated.** Change the spec, run `cd api && npm run generate`, and commit
  the result — `make api-contract` fails on drift.

## Running the checks

```bash
make test-unit          # Go tests
make lint               # golangci-lint + eslint
make standards-check    # regenerate from the registry, then verify nothing drifted
make api-contract       # spec ↔ client ↔ handler conformance
```

`make standards-check` is the one that surprises people. It regenerates
everything derived from `standards/service-registry.yaml` and then fails if the
result differs from what is committed, so a hand-edit to a generated file shows
up as a failure rather than as working code.

Some targets you may see referenced elsewhere (`make audit`, the edition-boundary
and export gates, the git hooks) run against the internal working tree and its
tooling, which is not part of this repository — so they are not present here.
`make help` lists what this tree actually has.

## Style

Match the surrounding code. Beyond that, the one thing we care about more than
most projects: **comments should explain why, not what.** A comment that
restates the code is noise; a comment explaining why a gate fails closed here
and fails open three files away is worth more than the code it sits above.

## Security

Do not report vulnerabilities through issues or pull requests. See
[SECURITY.md](SECURITY.md).

## Licensing

The project is licensed under [LICENSE.md](LICENSE.md) (FSL-1.1-ALv2). Each
release additionally becomes Apache-2.0 two years after it ships.

When code contributions do open, there will be **no CLA and no copyright
assignment** to sign. That falls out of the licence choice: FSL is not copyleft,
so an accepted contribution does not constrain how the rest of the project is
licensed, and there is nothing to make you sign. A copyleft core would have
required the opposite.
