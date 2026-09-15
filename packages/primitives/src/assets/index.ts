// Asset primitives — the generated class taxonomy (ADR-0002 D2).
//
// Generated from standards/asset-classes.yaml by
// scripts/generate-asset-classes.mjs; `make audit` fails on drift. Import as
// `@vistasecurity/primitives/assets`.
export { ASSET_CLASSES, ASSET_CLASS_KEYS, CLASS_TREE } from './classes.gen';
export type {
  AssetClass,
  AssetClassCycloneDXType,
  AssetClassKey,
  AssetClassNode,
} from './classes.gen';

// The effective per-class attribute schemas — the same content as the Go
// mirror shared/assetclass/attribute_schemas_gen.json. This is what gives the
// query language's `attr.<name>` namespace a vocabulary on the TypeScript side
// (QUERY_LANGUAGE §4.2); before it existed the production catalogue shipped
// with an empty one and every `attr.<name>` reported unknown_field.
export { ATTRIBUTE_SCHEMAS, attributeSchema } from './attribute-schemas.gen';
export type {
  AssetAttributeProperty,
  AssetAttributeSchema,
  AssetAttributeType,
} from './attribute-schemas.gen';
