# Release status

Machine-readable verification results for each release, written only by
the `Release Status` workflow (`.github/workflows/release-status.yml` on
the default branch). Schema and check catalogue:
`scripts/release-status-feed.mjs`.

- `latest.json` — the latest stable release
- `releases/<tag>.json` — every verified release

A result describes a verification run against that exact release. It is
not a statement about service uptime or about any particular deployment.
