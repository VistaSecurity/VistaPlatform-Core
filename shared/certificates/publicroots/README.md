# publicroots — the embedded public root store

`cacert.pem` is Mozilla's root store as extracted by curl
(<https://curl.se/docs/caextract.html>). It is compiled into every binary that
imports this package (`//go:embed`), so the platform decides whether a chain is
**public** the same way for every tenant and every agent, independent of the
operating-system store of whichever pod or host looked (feature #2397, owner
decision D3).

The certificate data is published by Mozilla under the
[Mozilla Public License 2.0](https://www.mozilla.org/MPL/2.0/). Keep the file's
header comment intact: `Version()` reads the snapshot date from its
`Certificate data from Mozilla as of: …` line.

## Refreshing the bundle (once per release)

```bash
curl -fsSL -o shared/certificates/publicroots/cacert.pem https://curl.se/ca/cacert.pem
sha256sum shared/certificates/publicroots/cacert.pem   # compare with https://curl.se/ca/cacert.pem.sha256
head -5 shared/certificates/publicroots/cacert.pem     # note the "as of" date
(cd shared && go test ./certificates/publicroots/)
```

Commit the new file on its own (`chore(publicroots): refresh Mozilla root bundle
to <date>`). The version the UI shows (Settings → Certificates → Trusted CAs,
`GET /trust-anchors/public-roots`) changes with it.

`*.pem` is gitignored repo-wide; `.gitignore` carries an explicit exception for
this one file.
