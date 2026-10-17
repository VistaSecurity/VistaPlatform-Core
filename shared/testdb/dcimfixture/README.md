# dcimfixture — the DCIM scale tenant

Deterministic generator for DATA_MODEL §12's tenant (500 sites, 5,000 racks,
50,000 assets, 500,000 interfaces, 200,000 IPs in 20,000 prefixes, 100,000
cables) plus the budget helper every performance-budgeted DCIM test uses.

```go
db := testdb.Connect(t)
tenant := testdb.NewTenant(t, db)
sum := dcimfixture.Populate(ctx, t, db, tenant, dcimfixture.Scale1()) // or Small()
```

`Scale1()` is §12; `Small()` is 400 assets for unit-ish runs. Names are stable
(`site-0042`, `rack-0042-07`, `sw-0042-07-01`, `Gi1/0/24`); ids come from a PRNG
seeded by `Scale.Seed`, so two runs with the same seed produce the same
`Summary.Digest`. Never seed from the clock.

## Phase awareness

`Populate` runs each populator only if every table in its `Requires` exists
(`to_regclass('public.<t>')`) and lists the rest in `Summary.Skipped`. Today it
writes `regions`, `site_groups`, `sites` (§12's 500 at Scale1, `site-0042`) and two
`locations` per site (`hall-0042-1`, row 2.1; every asset is placed in its site and
a hall of it), `assets`, `tags`, `object_tags`, `object_changes`, `journal_entries`,
`unresolved_terminations`, `interfaces` + `mac_addresses` (row 1.2; canonical
names `GigabitEthernet1/0/N`, read back into `Env.Interfaces`), the IPAM tables
(`ipam.go`, row 1.3: VRFs, route targets, aggregates, VLAN groups and VLANs,
prefixes, IP ranges, IP addresses, the utilisation cache, FHRP groups, ASNs — at
Scale1 20,000 prefixes and 200,000 addresses over 50 VRFs) and the tenant's
device catalogue (`catalogue.go`, row 2.2: 5 manufacturers × 4 device types, each
with InterfacesPerAsset interface templates, a device role per class, and every
asset given a type and a role), contacts (`contacts.go`, row 2.8: a contact per site, a tenant
role, and every asset assigned its site's contact as primary), wireless (`wireless.go`, row 4.4: a LAN
group per site holding a WPA2/AES, a WPA/TKIP and an open SSID, each pointing at its algorithms-catalogue
row), circuits (`circuits.go`, row 4.1: 5 providers with a provider network each, 2 circuits per site,
each with an A and a Z termination), tunnels (`vpn.go`, row 4.3: a modern and a legacy IKE proposal, an
IPsec proposal, and one IPsec tunnel per 50 assets with its own IKE / IPsec policy and profile and a
termination on the asset's last interface; algorithm ids resolved from the catalogue when seeded),
virtualisation (`virtualization.go`, row 4.2: one cluster per site; the servers of each site's first rack its
hosts, those of its second rack its VMs with vCPUs, memory, disk and one virtual disk) and the
asset components (`components.go`, row 3.1: per asset one `con 0` console port, one `Rear1`
rear port with `FrontPortsPerRear` positions and a front port per position, read back into
`Env.ConsolePorts`/`RearPorts`/`FrontPorts`), the racks (`racks.go`, row 2.3: RacksPerSite 42U
racks per site in their assets' hall — 5,000 at Scale1 — every asset racked bottom-up on
the front face by its device type's `u_height`, and `rack_utilization` filled) and cables (`cables.go`,
row 3.2: `CablesPerRack` per rack — 100,000 at Scale1 — the first three of each rack a patch from an
interface through two panels' front, rear and two-position trunk to another interface, the rest interface
to interface; terminations with their asset's site/location/rack, the components' `cable_id`, and every
cabled interface's `cable_paths` row computed by `shared/dcim/cablepath` over an in-memory graph;
`Summary.PatchedInterfaces` are the patched origins). `Small()` has 4 cables per rack, enough for one
patch and one direct cable. Row 2.4's hardware (`hardware.go`, counted as `inventory_items`): a "Network Module" bay holding a module of a fixture module type and two power-supply inventory items per asset, and a two-member virtual chassis per rack.

## Adding a populator (the hook for rows 1.x–3.x)

1. Write `func populateX(ctx, tx *sql.Tx, e *Env) (int, error)` in this package.
   Read `e.Assets` (and whatever an earlier populator appended to `Env`), draw
   randomness only from `e.Rng`, bulk-load with `copyRows` (lib/pq `CopyIn`),
   and call `e.Witness(name)` for every name or id you generate so the
   determinism digest covers it. Return the row count, or `-1` when there is
   nothing to attach to.
2. Append `{Name, Requires: []string{"x", ...}, Run: populateX}` to `Populators()`,
   after the populators it depends on.
3. Do not give tables with a global primary key (anything keyed on `id` alone)
   a PRNG id: two tenants would collide. Let the database default it.
4. Add the count assertion to `TestIntegration_DCIMFixture_PopulatesAtScale1` and
   a budget with `AssertUnder` for the §12 query your table owns.

## Budgets

```go
dcimfixture.AssertUnder(t, "cable trace", took, 100*time.Millisecond)
```

Always logs and records. Fails only when `DCIM_BUDGETS=enforce` (the nightly
`test-backend` job); on PRs a breach is informative so a loaded runner cannot
flake the gate. With `TEST_ARTIFACTS_DIR` set, each call appends
`{name, duration_ms, budget_ms, over}` to `$TEST_ARTIFACTS_DIR/dcim-budgets.json`;
nightly uploads it as the `dcim-budgets` artifact.

## Running

- `go test ./testdb/dcimfixture/` (in `shared/`): unit tests; the integration
  tests skip without `TEST_DATABASE_URL`.
- `make test-dcim-scale`: ephemeral Postgres, `DCIM_SCALE=1` (Scale1), report in
  `build/dcim-scale/dcim-budgets.json`. `DCIM_BUDGETS=enforce make test-dcim-scale`
  to fail on a breach.
- `DCIM_SCALE` unset (the general `make test-integration-db` sweep) uses `Small()`.

Config contexts (`config_contexts.go`, row 5.3): a base context that applies to every asset, a heavier
override, and an inactive one the renderer must skip.
