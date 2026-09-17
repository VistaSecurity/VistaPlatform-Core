# Immutable pre-ADR-0016 compliance upgrade fixtures

These are byte-for-byte snapshots from commit
`32f4a259fa85897c2a64ab8d4c9f162857cfbbdf`, immediately before the rating migration.
They are compressed only to keep the test corpus small. They are not a synthetic
reversal of the current schema and must not be regenerated from current files.
Public Core exports rewrite history, so tests read these files without Git.

| Fixture | Original path | SHA-256 of decompressed bytes |
|---|---|---|
| `schema.sql.gz` | `scripts/database/schema.sql` | `8896bf72a09c932708a363614db199f171b2323327323c8bfab053e9090899c9` |
| `seed.sql.gz` | `scripts/database/seed.sql` | `ff6b93fc765c6288eebaa4475e6f2c4c23fe120be6a8b4d641ea364664c06f76` |

To verify the source in a private checkout with that historical object:

```sh
git show 32f4a259fa85897c2a64ab8d4c9f162857cfbbdf:scripts/database/schema.sql | sha256sum
git show 32f4a259fa85897c2a64ab8d4c9f162857cfbbdf:scripts/database/seed.sql | sha256sum
gzip -dc schema.sql.gz | sha256sum
gzip -dc seed.sql.gz | sha256sum
```

Snapshots were created with Python `gzip.compress(source_bytes, mtime=0)`.
`TestComplianceSeverityPriorFixtureIntegrity` pins the decompressed hashes without
requiring a database or Git; the populated upgrade test replays these same bytes.
Keep regulated seed snapshots exclusively under `services/compliance-engine/ee/`,
which the public exporter removes in its entirety.
