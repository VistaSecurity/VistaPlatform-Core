# Real captured device output corpus

Fixtures under this directory are **real command or API output captured from
actual network devices** (via a third-party project redistributing them under
a compatible open-source licence — see each vendor directory's
`PROVENANCE.md`), sanitised for public redistribution. They exist to test the
collectors in `shared/deviceinterrogation/` against what devices actually
print, rather than against text shaped by hand to make a parser succeed.

This directory is separate from the older `shared/deviceinterrogation/testdata/`
(one level up), which holds earlier hand-written fixtures. Those are not
being replaced — see each PROVENANCE.md for which vendors still only have
hand-written coverage and why.

## Layout

```
testdata/real/<vendor>/<os-or-platform>/<command-or-endpoint>[__<n>].<ext>
```

- `<vendor>` — currently only `cisco`. Reserved for `paloalto`, `fortinet`,
  `f5`, etc. if a compatible real source is found for them in the future (see
  the "Vendors not represented here" section of `cisco/PROVENANCE.md`).
- `<os-or-platform>` — the platform name as the source project names it, which
  also matches the directory names ntc-templates itself uses: `cisco_ios`,
  `cisco_nxos`, `cisco_xr`, `cisco_asa`. Kept 1:1 with the source project's own
  taxonomy rather than invented ourselves, so `PROVENANCE.md`'s per-file source
  paths line up directly with the on-disk layout here.
- `<command-or-endpoint>` — the CLI command with spaces replaced by
  underscores (`show_ip_arp`), or for a JSON/XML API, the REST path or op
  command name. Matches the `command` field carried in the Go test table
  (`real_corpus_test.go`) so a fixture's filename and its test row always name
  the same thing.
- `__<n>` — only when more than one real capture of the *same* command exists
  for the same platform and would otherwise collide (e.g. a plain and an
  IOS-XE-banner `show_version`, which instead get distinct names
  `show_version.txt` / `show_version_iosxe.txt` — the suffix form is used when
  the distinguishing detail isn't worth a whole different name).
- `<ext>` — `.txt` for CLI output, `.json` for REST JSON, `.xml` for XML API
  responses.

## What "real" means here, precisely

Every file's exact source (repository, commit, original path, licence) is
recorded in that vendor directory's `PROVENANCE.md`. A file is sanitised
(addresses rewritten to documentation ranges, serials and any credential-shaped
text redacted — see `cisco/PROVENANCE.md` for the exact method) but otherwise
unedited: line order, wording, whitespace and command quirks are preserved
exactly as the device printed them, because those are exactly the things a
parser written against imagined output gets wrong.

## Consuming this corpus

`shared/deviceinterrogation/real_corpus_test.go` (`TestRealCorpus`) is the
single test that walks every file here through the parser function that is
supposed to handle it, via an explicit file → parser table (never inferred
from the filename). `TestRealCorpus_NoOrphanFixtures` fails if a file exists
here with no table row, or a table row names a file that doesn't exist — the
corpus and the test are kept from silently drifting apart in either direction.

Every row that runs a parser asserts the CORRECT result on the real output —
the exact peer, key size, row count, port or name the device printed. The
corpus first landed (#2019) with the parser defects it surfaced pinned as
`knownGap` rows asserting the then-current, wrong behaviour; W3.2 of #2014
fixed the Cisco parsers and turned each of those rows into a hard assertion.
`knownGap` is now allowed only on a row with no parser (a command no
collector reads yet), and `TestRealCorpus_EveryParsedRowAssertsCorrectBehaviour`
keeps it that way. A new fixture that exposes a parser defect gets its fix in
the same change, or a failing row — not a row that documents the defect.
