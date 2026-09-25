# Vendor pipeline chain (W0.2)

What an interrogation of each supported vendor actually produces at every hop
of the real pipeline, from the device's own output to the tenant's inventory.
It is the acceptance harness for the discovery-beyond-the-lab programme
(`docsv4/internal/developer/standards/features/discovery-beyond-the-lab.md`,
slice W0.2): every later fix slice turns one of its known gaps into a hard
assertion.

## The chain

```
fake appliance ──hop 1──▶ sensor_discoveries ──hop 2──▶ import request ──hop 3──▶ inventory
(device/)                 hop1_handoff.golden.json      hop2_handoff.golden.json  hop3_inventory.golden.json
```

Go `internal` packages cannot be imported across service modules, so no single
test can run all three services. Each hop is a DB-integration test in its own
module that runs that hop's REAL code, and hands its output to the next hop as a
committed golden:

| Hop | Test | Real code it runs | Reads | Writes |
|---|---|---|---|---|
| 1 | `services/device-interrogation-service/internal/services/vendor_pipeline_hop1_integration_test.go` | `CreateDevice`, the platform worker's `executeDeviceInterrogation` (collector through the Registry, `materializeInterrogatedAsset` → `writeSensorDiscovery`, `persistObservations` through the identity engine), then `UpdateJobStatus` + `ProcessJobResults` | `scenario.json`, `device/` | `hop1_handoff.golden.json`, `hop1_observations.golden.json` |
| 2 | `services/discovery-processor-service/internal/processor/vendor_pipeline_hop2_integration_test.go` | `ProcessBatch` over the hop-1 rows in a real `sensor_discoveries` table: the converter, auto-approval, and the real `InventoryClient` | `hop1_handoff.golden.json` | `hop2_handoff.golden.json` |
| 3 | `services/inventory-service/internal/services/vendor_pipeline_hop3_integration_test.go` | the import handler's decode (`ClusterSensorFinding.ToIngestFinding`), `NewAssetService(...).IngestFindingsReport` (detector wired, seeded catalogue), `ApproveAssets`, then `GetCryptoImplementations` and the PQC classifier | `hop2_handoff.golden.json` | `hop3_inventory.golden.json` |

Each hop also asserts a table of **claims** (`*_claims_integration_test.go`
beside it) — see "Known gaps" below.

What each golden holds:

- **`hop1_handoff.golden.json`** — the `sensor_discoveries` rows the in-cluster
  interrogation wrote, the network segments it learned, and every asset the
  tenant had afterwards (the device and the peers its observations created)
  with their identifiers. Hop 2 inserts the rows; hop 3 recreates the segments
  and assets, because in production they are rows of the same tables inventory
  ingests into.
- **`hop1_observations.golden.json`** — not a handoff: the facts, edges, assets,
  retained identity observations (with admission reasons) and the job's
  collection warnings, once with identity admission off and once enforced
  (`identity_admission=enforce` plus a `max_assets` allowance, the #1975 setup).
- **`hop2_handoff.golden.json`** — every import request and external-connection
  upsert `ProcessBatch` posted, decoded from the wire bytes; the fate of every
  hop-1 row (forwarded, approval status, processed or left for the poller); and
  `ProcessBatch`'s error. Hop 3 replays the import requests.
- **`hop3_inventory.golden.json`** — the inventory a tenant would see: assets
  (labelled with their hop-1 identity, or `new[...]` when the ingest minted
  one), crypto configurations with port, version, cipher, key exchange, risk
  score, band and factors, catalogue links by role, per-configuration PQC
  category, certificates, and the tenant's PQC counts.

## Running and regenerating

The hops are DB-integration tests: they skip unless `TEST_DATABASE_URL` is set.
`make test-integration-db` runs all three against an ephemeral Postgres.

When a hop's behaviour changes on purpose, regenerate **in chain order** and
review each diff:

```bash
export TEST_DATABASE_URL=...   # or run inside make test-integration-db's database
(cd services/device-interrogation-service && go test ./internal/services/ -run TestIntegration_VendorPipeline_Hop1 -update-golden)
(cd services/discovery-processor-service  && go test ./internal/processor/ -run TestIntegration_VendorPipeline_Hop2 -update-golden)
(cd services/inventory-service            && go test ./internal/services/ -run TestIntegration_VendorPipeline_Hop3 -update-golden)
```

**Drift check.** Hop 2's and hop 3's goldens record the SHA-256 of the golden
they were generated from (`input_sha256`). Regenerating hop N without
regenerating hop N+1 fails hop N+1 with a `drift:` message, and fails
`TestChain_EveryHopReadsTheGoldenBeforeIt` in `shared/deviceinterrogation/pipelinetest`,
which needs no database and runs in every plain `go test ./...`.

**Leak check.** The fixtures plant `MUST-NOT-BE-COLLECTED` wherever a vendor
returns material we must never store (PSKs, private keys, admin passwords, the
operator's email). No golden may contain it (`TestChain_NoGoldenCarriesPlantedSecrets`,
and hop 1 checks each golden as it writes it).

## Known gaps

Every claim's `Want` is the **correct** behaviour the spec calls for. Where
today's code is still wrong, the claim carries `KnownGap: "<finding> / <slice>"`
and a `Current` value, and asserts the current behaviour exactly
(`pipelinetest.Expectation`). It therefore fails in two ways, both on purpose:

- the behaviour changes without reaching the correct answer (a regression, or
  partial progress — update `Current`);
- the fix lands and the answer is now correct: delete `KnownGap` and `Current`,
  and the claim becomes a hard assertion. The fix slice's PR does this.

A gap whose `Want` equals its `Current` is rejected outright: it could never
report its own fix.

## Fixtures

`scenario.json` names the device type, the device record's hostname, the
transport, the tenant's registered network segments, and the documentation
address (`management_ip`/`management_port`) at which the downstream hops see
the appliance. `device/` holds the fake appliance's answers:

| Vendor | Transport | Source |
|---|---|---|
| unifi (baseline) | REST (`routes.json`; TLS pinned, see "Determinism") | Hand-written, from `collector_edges_integration_test.go` and `unifi_vpn_test.go` |
| cisco | SSH (`commands.json`, fixed host key, `SSH-1.99-Cisco-1.25` banner) | Mostly **real** (`../real/cisco/cisco_ios`, ntc-templates, Apache-2.0); `show crypto map`, `show crypto isakmp sa` and `show crypto ikev2 sa` are hand-written (`*.handwritten.txt`) |
| fortinet | REST | Hand-written, from `fortinet_ops_test.go`; SSL-VPN fields in FortiOS 7.x's hyphenated form |
| paloalto | REST (XML API; `POST type=keygen`) | Hand-written: `../paloalto_*.xml` and `paloalto_test.go` shapes |
| f5 | REST | Hand-written, from `f5_ops_test.go` / `f5_test.go`; one profile uses an OpenSSL cipher string and `options`; server-ssl is refused with a 403 |
| snmp | SNMP v2c over UDP (`mib.json`) | Hand-written: `snmp_ops_test.go`'s MIB, served by an `encoding/asn1` agent |

`_shared/leaf.pem` and `_shared/ca.pem` are a test certificate chain generated
for these fixtures (RSA 2048, `CN=www.example.com`, valid 2026-2046, no private
key committed). A route body may embed one with `{{PEM_JSON:_shared/leaf.pem}}`.

Every address is from RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`) and every name is under `example.test`, `example.com` or
`example.net`.

## Determinism: the fake appliances' TLS

The UniFi collector probes the controller's management plane with the real TLS
prober. Its row records the negotiated version, suite and group, the accepted
versions, the classical and hybrid support flags, and the certificate. All of
these would otherwise be Go defaults, so the REST fakes pin them
(`pipelinetest.ApplianceTLSConfig`):

- exactly TLS 1.2 and 1.3;
- exactly `X25519MLKEM768` and `X25519`, hybrid preferred;
- an Ed25519 self-signed certificate derived from a fixed seed, so its
  fingerprint never changes, where httptest's is the standard library's
  internal test certificate.

The probe's support handshakes share a 10-second budget. On loopback they take
milliseconds, and `TestFixtures_UniFiManagementProbeIsDeterministic` repeats
the probe 20 times without a database.

The client side is the product's prober, so a test cannot pin it. Two
environment inputs can change what it negotiates: `GODEBUG=tlsmlkem=0`, and a
CPU without AES-GCM acceleration (Go then prefers ChaCha20-Poly1305).
`pipelinetest.RequireDeterministicTLS` runs before hop 1 and fails with that
reason, rather than letting it show up as a golden diff.

The goldens run only nightly and in `make test-integration-db`, not in the PR
gate. So a change that alters what a hop writes must regenerate the chain in
the same PR. This includes a change merged into main while this harness's
own PR was open.

## What is real and what stands in

- **Real:** every collector, the Registry and its sanitiser, both sinks of the
  in-cluster path, the identity engine, the job's processing block,
  `ProcessBatch` and the converter, the `InventoryClient` wire format, the
  import handler's decode, `IngestFindingsReport` with the weak-crypto detector
  and the seeded catalogue, `ApproveAssets`, `GetCryptoImplementations`, the
  PQC classifier, Postgres.
- **The appliance's address.** The fakes listen on loopback (opened for one
  test through `devicetest.AllowListener`; SSH and SNMP dial it directly).
  Hop 1 records the loopback address and port as `{{APPLIANCE_IP}}` /
  `{{APPLIANCE_PORT}}`; hops 2 and 3 put the scenario's `management_ip` /
  `management_port` back, and hop 3 scopes the device's address to the segment
  that contains it, as `CreateDevice` would have.
- **Network classification at hop 2** is inventory-service's decision, so hop 2
  answers `classify-asset` from the scenario's and hop 1's segments the way
  `NetworkSegmentService.ClassifyAsset` does. Hop 3 runs the real classifier on
  every finding and fails if it disagrees with what hop 2 was told.
- **Reverse DNS at hop 2** answers nothing: the rows carry documentation
  addresses, and what public DNS says about them is not a property of the
  pipeline.
- **Inventory's per-finding outcomes at hop 2**: the stand-in answers with a
  count only, so hop 2's row statuses are what the auto-approval rules set.
  Hop 3 is where the real outcomes are recorded (`ingest_outcomes`).
- **Approval at hop 3**: every pending asset is approved, as a tenant does in
  Discovery → Approvals, because that is what materializes deferred crypto.

## Adding a vendor

Add `<vendor>/scenario.json` and `<vendor>/device/`, add the vendor to
`pipelinetest.Vendors`, generate the chain in order with `-update-golden`, and
add a case to each hop's claims table. A vendor with no claims fails its hop.
