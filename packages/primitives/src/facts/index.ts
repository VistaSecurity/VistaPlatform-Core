// Fact-key registry primitives.
//
// The registry itself is generated from standards/fact-keys.yaml — edit the
// YAML and run `make generate`, never keys.gen.ts.
export {
  FACT_KEYS,
  FACT_KEY_DEFS,
  FACT_KEY_ORDER,
  isFactKey,
} from './keys.gen';
export type { FactKey, FactKeyDef, FactProducer, FactValueType } from './keys.gen';
