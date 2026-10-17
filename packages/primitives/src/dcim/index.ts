// DCIM vocabulary primitives (asset-inventory ADR-0010 D2).
//
// The object-kind registry is generated from standards/vocabulary.yaml — edit
// the YAML and run `make generate`, never object-kinds.gen.ts. The Go mirror is
// shared/dcim; `make audit` fails if either drifts.
//
// The interface, port and cable type registries (types.gen.ts) are generated from
// standards/interface-types.yaml and standards/cable-types.yaml by
// scripts/generate-dcim-types.mjs; shared/dcim/types_gen.go is the Go mirror.
//
// Import as `@vistasecurity/primitives/dcim`.
export { OBJECT_KINDS, OBJECT_KIND_LABELS, type ObjectKind } from './object-kinds.gen';
export * from './types.gen';
