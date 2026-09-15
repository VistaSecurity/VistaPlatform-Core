// Finding-registry primitives (asset-inventory ADR-0005 D3).
//
// The registry itself is generated from standards/findings-registry.yaml —
// edit the YAML and run `make generate`, never registry.gen.ts. The Go mirror
// is shared/findings; `make audit` fails if either drifts.
//
// Import as `@vistasecurity/primitives/findings`.
export {
  FINDING_KIND,
  FINDING_KIND_KEYS,
  FINDING_KINDS,
  FINDING_PRODUCER,
  FINDING_PRODUCER_KEYS,
  FINDING_PRODUCERS,
  FINDING_SUBJECT,
  FINDING_SUBJECT_TYPES,
  findingKind,
  findingProducer,
  OPEN_FINDINGS_QUERY,
} from './registry.gen';
export type {
  FindingKind,
  FindingKindKey,
  FindingProducer,
  FindingProducerKey,
  FindingRung,
  FindingScoreSource,
  FindingSeverity,
  FindingSeverityModel,
  FindingSubjectType,
} from './registry.gen';
