# DemoCorp seed data

A realistic demonstration dataset for a self-hosted Vista Platform. It creates a
fictional mid-size enterprise — **DemoCorp** — with two data centres, a corporate
network, a post-quantum pilot and an OT plant floor, and loads it through the
normal discovery-ingest path so every downstream feature (cataloguing, risk
scoring, compliance evaluation, CBOM) behaves exactly as it does with real data.

> **Local evaluation only.** This creates users with a **known, published
> password** (below) and deliberately unhealthy cryptography. Never load it into
> an internet-reachable deployment, and never load it into a tenant you also use
> for real inventory.

## What it creates

Counts below are what the dataset actually produces, measured by
`TestIntegration_DemoCorpSeed_ShowcasesEveryFeature`. They are approximate only
in that regenerating shifts certificate dates.

| | |
|---|---|
| Tenant | DemoCorp, `pro` subscription tier |
| Users | 6 — one per default tenant role |
| Devices | 14 load balancers, firewalls, hypervisors, routers |
| Network segments | 8 (2 data centres × environments, corporate, PQC pilot, OT) |
| Infrastructure assets | ~132 |
| Crypto configurations | ~132 |
| Certificates | ~100 leaf + 1 issuing CA |
| Cryptographic keys | ~78 (deduplicated by SPKI fingerprint) |
| Algorithm links | ~650 |

## What it is built to show

Each of these is asserted by the coverage test, so the dataset cannot quietly
stop demonstrating a feature as the product changes.

- **Risk distribution across every band** — roughly 24 Critical, 2 High, 31
  Medium, 75 Low. The Criticals are genuine: SSLv3, TLS 1.0/1.1, and plaintext
  OT protocols. A demo where everything is red teaches nothing.
- **The Keys lens, including deployment counts** — a wildcard key is deployed
  across the production fleet, so one key row shows as used by **~23 assets**.
  This is why the generator issues real certificates: SPKI-fingerprint
  deduplication is only observable when certificates genuinely share a key.
- **Certificate lifecycle** — ~5 already expired, ~6 expiring inside 60 days,
  one self-signed, one CA, plus SHA-1-signed legacy certificates.
- **Post-quantum readiness with all four categories populated** — a PQC pilot
  segment using ML-KEM-768, X25519MLKEM768 and HQC-128 gives ~10 PQC-ready
  configurations against ~111 needing migration, ~4 quantum-safe symmetric and
  ~7 unclassified. Readiness lands near 11%, which is a migration story rather
  than a 0% or 100% flatline.
- **OT / ICS discovery** — 14 configurations across Modbus, DNP3 (plaintext and
  SAv5), OPC-UA, S7, EtherNet/IP and BACnet.
- **Non-TLS cryptography** — SSH, IPSec, SMB and Kerberos.
- **Stale asset lifecycle** — the lab and development segments are backdated so
  the daily job ages them into warning and archived states.
- **Compliance frameworks** — the free Core frameworks evaluate this inventory
  automatically; no extra step.

## Quick start

Requires the platform running locally (`docker compose up -d`) with the
`crypto-postgres` container up and the API gateway on `:8080`.

```bash
cd democorp-seed && ./manage-democorp.sh
```

The interactive menu loads the tenant and data, erases the data but keeps the
tenant, or removes the tenant entirely. To run it non-interactively:

```bash
cd democorp-seed && ./load-democorp.sh
```

**Users** — all six share the password `Password123!`:
`admin@democorp.com` is the tenant admin; the rest cover the remaining default
roles. Override the DB container or gateway with `DB_CONTAINER`, `DB_USER`,
`DB_NAME` and `API_GATEWAY` environment variables.

## Regenerating the findings

The findings under `data/findings/` are generated, and committed so that loading
needs no Go toolchain. Regenerate them to refresh certificate validity windows —
"expires in three weeks" decays into "expired" over time:

```bash
cd democorp-seed/generator && go run . -out ../data/findings
```

Two things the generator guarantees, both of which matter:

1. **Real X.509 certificates.** Expiry, chains, self-signing and SPKI
   fingerprints are properties of the encoded certificate. Hand-written JSON
   cannot demonstrate key reuse across hosts and renewals.
2. **Only real catalogue codes.** The ingest path resolves algorithm strings
   against the `algorithms` table, so an invented cipher name would create a new
   row and pollute the catalogue the whole product treats as authoritative.
   Every algorithm string in the generator is taken from
   `scripts/database/seed.sql`.

## Erasing

```bash
./erase-democorp.sh          # remove the tenant and everything in it
./erase-democorp.sh --data   # keep the tenant, drop its inventory
```

Both are scoped to the DemoCorp tenant and leave the rest of the database — the
platform's own seed data included — untouched.
