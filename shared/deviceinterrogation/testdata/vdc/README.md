# Virtual device context fixtures (DCIM gap 1, part 2)

SYNTHESISED in the response shapes each collector's parser is written against,
for the projection tests in `vdc_projection_test.go`. No capture from a real
device is in this directory: names, MACs and addresses are invented (RFC 5737 /
RFC 1918 ranges, `00:00:5e:00:53:xx` documentation MACs), and every JSON and XML
file plants the value `PlantedVdcSecret-4410` in a field the typed projection has
no field for, which the tests assert never reaches the observation (the CLI
output has no such field).

| File | Collector | Shape |
|---|---|---|
| `fortinet_cmdb_system_interface.json` | Fortinet | `GET /api/v2/cmdb/system/interface` with `vdom` on each item, two VDOMs |
| `paloalto_show_interface_all.xml` | Palo Alto | `<show><interface>all</interface></show>`, interfaces in vsys1 and vsys2, one in no vsys |
| `paloalto_config_vsys.xml` | Palo Alto | `type=config&action=get&xpath=/config/devices/entry/vsys`: the operator's `display-name` per vsys, beside settings that are never read |
| `f5_net_route_domain.json` | F5 | `GET /mgmt/tm/net/route-domain` with each route domain's `vlans` |
| `cisco_nxos_show_vdc_membership.txt` | Cisco NX-OS | `show vdc membership` from the default VDC: two VDCs, the unallocated pool, a breakout port |
