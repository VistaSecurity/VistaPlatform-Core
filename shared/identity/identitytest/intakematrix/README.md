# The identity intake matrix

A characterization test: every intake path that turns device evidence into
identity is given the **same** evidence, and the test pins what each path does
with it **today**. It is not a statement that today is right. It exists so a PR
that changes one path's rules (scope, dynamic flag, admission, endpoint writes)
moves exactly the rows it means to, and nothing else.

| Service | Test | Paths |
|---|---|---|
| inventory-service | `services/inventory-service/internal/services/identity_intake_matrix_integration_test.go` | `TestIntegration_IdentityIntakeMatrix_InventoryService`, plus `…_HeadlineRows` |
| device-interrogation-service | `services/device-interrogation-service/internal/services/identity_intake_matrix_integration_test.go` | `TestIntegration_IdentityIntakeMatrix_DeviceInterrogationService` |

Both are DB-integration tests (`shared/testdb`): they skip without
`TEST_DATABASE_URL` and run nightly and under `make test-integration-db`.

## The scenario

`Setup` (this package) builds one tenant in `enforce` admission with a gateway
that owns its addresses in three places:

| Place (`Place`) | Address | Identifier the gateway holds |
|---|---|---|
| `dyn_segment` | `10.20.1.1` in `10.20.1.0/24`, flagged dynamic by a **measurement** | `ip_address@dyn`, measured |
| `static_segment` | `10.20.2.1` in `10.20.2.0/24`, never flagged | `ip_address@static`, declared |
| `no_segment` | `10.20.9.2`, in no segment | `ip_address@tenant`, measured |

plus the gateway's MAC and SSH host key. Each row sends the address (on ports
443/8443/9443 where the path carries ports) in one of four shapes — `ip`,
`ip+mac`, `ip+ssh`, `ip+mac+ssh` — and only the shapes the path's input can
actually carry. Every row gets a fresh tenant.

## Reading a row

A row's key is `path/place/shape`; its value is `Effect.String()`:

```
outcome=supporting*3
obs=[3x{src=measured/sensor/passive scope=tenant dyn=- ip=[tenant] kinds=- adm=[direct]
        reasons=[network_scope_unresolved] state=linked asset=fixture}]
ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0
```

| Field | Meaning |
|---|---|
| `outcome` | The path's own answer: engine outcomes folded (`supporting*3`), or what an engine-less path reports (`ok`, `refused_conflict:<kind>`, `error:…`, `nothing_to_decide`). |
| `obs` | One entry per engine receipt the path stored — the observation **exactly as its adapter built it**. Identical ones fold into `Nx{…}`. `obs=-` means the path never reached the engine. |
| `src` | `source kind / producer / mode`. |
| `scope`, `dyn`, `ip` | The observation's network scope, the scopes it marked dynamic, and the scope each `ip_address` carried — symbolised `dyn` / `static` / `tenant` (`other` = a scope the fixture did not create). |
| `kinds` | Device-binding identifiers carried (`mac`, `ssh`). |
| `adm` | Admission flags: `direct`, `auth`, `relayed`, `op_confirmed`. |
| `reasons` | The admission decision's reasons (`identity_observations.admission_reasons`). |
| `state`, `asset` | Where the observation row ended: state, and whether it is linked to the gateway (`fixture`), another asset, or none. |
| `ids` | Identifier rows added to the gateway. |
| `resourced` | Gateway identifier rows whose `source_kind` the path changed (e.g. `ip@dyn:measured>declared`). |
| `ports` | `asset_endpoints` rows added to the gateway. |
| `new_assets`, `other_ids`, `other_ports`, `proposals` | Assets created; rows written to assets other than the gateway; merge proposals opened. |

## Changing a row

1. Change the rule.
2. Run the test. Each row that moved fails on its own, named
   `…/<path>/<place>/<shape>`, printing `got` and `want`.
3. Check that **only** the rows your change is about moved. A row you did not
   expect to move is the point of this test — find out why before you touch it.
4. Copy the `got` line over the `want` line. Rows carry a comment naming the
   identity-intake issue item (1–10) or owner decision they demonstrate; update
   or remove that comment when the row stops demonstrating it.

A new path or shape fails with `no expectation for this row` and prints the
line to paste; an expectation whose row no longer exists fails too.

## Proof the harness can fail

Both halves were mutation-tested by changing one adapter's dynamic flag and
predicting the red rows before running:

- inventory-service: forcing `discoveryObservation`'s dynamic flag to false
  turned exactly `ingest_scan/dyn_segment/*` (four rows), the
  `confirm_after_scan` / `link_after_scan` `dyn_segment/ip` rows that consume
  that scan, and the headline dynamic-segment subtest red — nothing else.
- device-interrogation-service: removing the peer path's `net.vlans` DHCP
  overlay turned exactly the two `peer_controller_run_reports_dhcp_operator_static`
  rows red. The non-operator variant stays green because the same run stores a
  measured posture on the segment before the peer is resolved.
