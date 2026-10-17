# Provenance of these fixtures

Copied unmodified from the NetBox community device-type library,
https://github.com/netbox-community/devicetype-library, at commit
`37f5f02c27eedf60767594174598daec5b9e2bee` (2026-10-15). The library is
dedicated to the public domain under **CC0 1.0 Universal** (its `LICENSE.txt`);
attribution is given anyway (see `public/NOTICE`, THIRD-PARTY DATA).

| Fixture | Library path | Why it is here |
|---|---|---|
| `cisco-c9300-48p.yaml` | `device-types/Cisco/C9300-48P.yaml` | 51 interfaces (48 PoE copper, stack ports, management), console ports, module bays |
| `apc-ap7900b.yaml` | `device-types/APC/AP7900B.yaml` | power port and eight power outlets referencing it (feed leg), a console port |
| `panduit-cpa24bly.yaml` | `device-types/Panduit/CPA24BLY.yaml` | 24 front and 24 rear ports joined by the 4.4+ `port-mappings` list |
