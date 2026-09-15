#!/usr/bin/env node
// Generates the findings registry from standards/findings-registry.yaml
// (asset-inventory ADR-0005 D3). Outputs:
//   shared/findings/registry_gen.go
//   packages/primitives/src/findings/registry.gen.ts
// Run via `make generate`; `make audit` fails on drift (--check mode).
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';
import { goConst, goConstBlock, goStr, tsStr, fail as sharedFail } from './lib/registry-codegen.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const VALID = {
  severity_model: ['fixed', 'ladder'],
  severity: ['critical', 'high', 'medium', 'low', 'info', 'from-control', 'from-catalogue'],
  score_source: ['fixed', 'catalogue', 'cvss_x10', 'ladder'],
};

const fail = (msg) => sharedFail('findings-registry', msg);

function checkScore(label, score) {
  if (typeof score !== 'number' || !Number.isInteger(score)) fail(`${label}: score must be an integer`);
  if (score < 0 || score > 100) fail(`${label}: score ${score} out of bounds (0-100)`);
}

function validate(registry) {
  // `open_query` is the ONE definition of "an open finding", in the query
  // language, shared by the Go readers, the TypeScript facet rail and the
  // inventory facet's compiled count. It is generated rather than written twice
  // because the two halves disagreeing is exactly what got the has_findings
  // facet withdrawn in Gate 1.
  if (typeof registry.open_query !== 'string' || !registry.open_query.trim()) {
    fail('no open_query defined');
  }
  if (!registry.open_query.startsWith('finding:(')) {
    fail('open_query must be a finding:(…) sub-predicate — it is spliced into asset queries');
  }

  const subjectTypes = registry.subject_types || [];
  if (!subjectTypes.length) fail('no subject_types defined');
  const subjectSet = new Set(subjectTypes);
  if (subjectSet.size !== subjectTypes.length) fail('duplicate entry in subject_types');
  for (const s of subjectTypes) {
    if (!/^[a-z0-9_]+$/.test(s)) fail(`bad subject_type: ${s}`);
  }

  const producers = registry.producers || [];
  if (!producers.length) fail('no producers defined');

  const seenProducers = new Set();
  const seenKinds = new Set();

  for (const p of producers) {
    if (!p.key || !/^[a-z0-9_]+$/.test(p.key)) fail(`bad producer key: ${p.key}`);
    if (seenProducers.has(p.key)) fail(`duplicate producer: ${p.key}`);
    seenProducers.add(p.key);
    if (!p.label) fail(`${p.key}: label required`);
    if (!p.description) fail(`${p.key}: description required`);
    if (!p.catalogue) fail(`${p.key}: catalogue required (use 'none' where there is no catalogue)`);
    if (!Array.isArray(p.kinds) || !p.kinds.length) fail(`${p.key}: at least one kind required`);

    for (const k of p.kinds) {
      const label = `${p.key}/${k.key}`;
      if (!k.key || !/^[a-z0-9_]+$/.test(k.key)) fail(`bad kind key: ${label}`);
      // Kind keys are unique across the whole registry, not just within a
      // producer, so the generated constants can be flat and a finding row is
      // readable from its kind alone.
      if (seenKinds.has(k.key)) fail(`duplicate kind key across producers: ${k.key}`);
      seenKinds.add(k.key);

      if (!VALID.severity_model.includes(k.severity_model)) {
        fail(`${label}: invalid severity_model: ${k.severity_model}`);
      }
      if (!VALID.score_source.includes(k.score_source)) {
        fail(`${label}: invalid score_source: ${k.score_source}`);
      }
      if (typeof k.feeds_risk !== 'boolean') fail(`${label}: feeds_risk must be an explicit bool`);
      if (!k.title_template || !k.title_template.includes('{subject}')) {
        fail(`${label}: title_template must mention {subject}`);
      }
      if (!k.description) fail(`${label}: description required`);
      // Guidance is the REMEDIATOR seam's null default (ADR-0008 D1) and the
      // text the Findings inspector shows, so a kind without it leaves a
      // deployment with no model answering "what do I do about this?" with
      // nothing. Required for that reason, and separately from `description`,
      // which is written for us and carries table names and workstream
      // numbers that must not reach a tenant or a prompt.
      if (!k.guidance) fail(`${label}: guidance required — it is what answers a finding of this kind when no model is configured`);
      if (k.guidance.trim() === k.description.trim()) {
        fail(`${label}: guidance must not be a copy of description — one is customer-facing, the other is ours`);
      }

      if (!Array.isArray(k.subject_types) || !k.subject_types.length) {
        fail(`${label}: at least one subject_type required`);
      }
      const seenSubjects = new Set();
      for (const s of k.subject_types) {
        if (!subjectSet.has(s)) fail(`${label}: subject_type '${s}' is not in the registry subject_types list`);
        if (seenSubjects.has(s)) fail(`${label}: duplicate subject_type '${s}'`);
        seenSubjects.add(s);
      }

      if (k.severity_model === 'ladder') {
        if (k.score_source !== 'ladder') fail(`${label}: ladder kinds need score_source: ladder`);
        if (k.default_severity) fail(`${label}: ladder kinds carry severity per rung, not default_severity`);
        if (k.score) fail(`${label}: ladder kinds carry score per rung, not a kind-level score`);
        if (!Array.isArray(k.rungs) || k.rungs.length < 2) fail(`${label}: ladder kinds need at least two rungs`);
        for (const r of k.rungs) {
          if (!r.threshold) fail(`${label}: every rung needs a threshold`);
          if (!VALID.severity.includes(r.severity)) fail(`${label}: invalid rung severity: ${r.severity}`);
          checkScore(`${label} rung '${r.threshold}'`, r.score);
          if (!k.feeds_risk && r.score !== 0) {
            fail(`${label}: feeds_risk is false so every rung score must be 0 (got ${r.score})`);
          }
        }
      } else {
        if (k.score_source === 'ladder') fail(`${label}: score_source 'ladder' needs severity_model 'ladder'`);
        if (k.rungs) fail(`${label}: rungs are only valid on ladder kinds`);
        if (!k.default_severity || !VALID.severity.includes(k.default_severity)) {
          fail(`${label}: fixed kinds need a valid default_severity`);
        }
        checkScore(label, k.score ?? 0);
        if (!k.feeds_risk && (k.score ?? 0) !== 0) {
          fail(`${label}: feeds_risk is false so score must be 0 (got ${k.score})`);
        }
        // A kind that feeds risk with a literal score of zero would silently
        // contribute nothing. Catalogue- and CVSS-sourced scores are resolved
        // at evaluation time, so only the literal source is checked here.
        if (k.feeds_risk && k.score_source === 'fixed' && (k.score ?? 0) === 0) {
          fail(`${label}: feeds_risk with score_source 'fixed' needs a score above 0`);
        }
      }
    }
  }
}

function render(registry) {
  const subjectTypes = registry.subject_types;
  const producers = registry.producers;
  const kinds = producers.flatMap((p) => p.kinds.map((k) => ({ ...k, producer: p.key })));

  const producerConsts = goConstBlock(
    producers.map((p) => ({ name: `Producer${goConst(p.key)}`, value: goStr(p.key) })));

  const kindConsts = goConstBlock(
    kinds.map((k) => ({ name: `Kind${goConst(k.key)}`, value: goStr(k.key) })));

  const subjectConsts = goConstBlock(
    subjectTypes.map((s) => ({ name: `Subject${goConst(s)}`, value: goStr(s) })));

  const producerEntries = producers
    .map(
      (p) => `	{
		Key:         ${goStr(p.key)},
		Label:       ${goStr(p.label)},
		Catalogue:   ${goStr(p.catalogue)},
		Description: ${goStr(p.description.trim())},
	},`,
    )
    .join('\n');

  const kindEntries = kinds
    .map((k) => {
      const rungs = (k.rungs || [])
        .map((r) => `{Threshold: ${goStr(r.threshold)}, Severity: ${goStr(r.severity)}, Score: ${r.score}}`)
        .join(', ');
      const rungLiteral = rungs ? `[]Rung{${rungs}}` : 'nil';
      const subjects = k.subject_types.map((s) => goStr(s)).join(', ');
      // Field names are padded to the longest key (DefaultSeverity) so the
      // emitted literal is gofmt-clean; every value stays on one line so that
      // gofmt's alignment block is never broken by a nested literal.
      return `	{
		Producer:        ${goStr(k.producer)},
		Key:             ${goStr(k.key)},
		SeverityModel:   ${goStr(k.severity_model)},
		DefaultSeverity: ${goStr(k.default_severity ?? '')},
		Score:           ${k.score ?? 0},
		ScoreSource:     ${goStr(k.score_source)},
		Rungs:           ${rungLiteral},
		SubjectTypes:    []string{${subjects}},
		FeedsRisk:       ${k.feeds_risk},
		TitleTemplate:   ${goStr(k.title_template)},
		Guidance:        ${goStr(k.guidance.trim())},
		Description:     ${goStr(k.description.trim())},
	},`;
    })
    .join('\n');

  return `// Code generated by scripts/generate-findings-registry.mjs from
// standards/findings-registry.yaml. DO NOT EDIT — edit the YAML and run
// \`make generate\`.

// Package findings is the generated registry of finding producers and kinds
// (asset-inventory ADR-0005 D3). Every row in the findings table carries a
// producer and a kind from this registry; there is no CHECK constraint, so
// Validate is the enforcement point.
package findings

import "fmt"

// Producer keys.
const (
${producerConsts}
)

// Kind keys. Unique across the whole registry, not just within a producer.
const (
${kindConsts}
)

// Subject types. The shared vocabulary for what a finding (or a ticket, or an
// alert) is about.
const (
${subjectConsts}
)

// Rung is one step of a ladder severity model. Rungs are ordered worst-last.
type Rung struct {
	Threshold string \`json:"threshold"\`
	Severity  string \`json:"severity"\`
	Score     int    \`json:"score"\`
}

// Producer is one finding producer: a subsystem that judges facts against a
// catalogue or a rule set.
type Producer struct {
	Key         string \`json:"key"\`
	Label       string \`json:"label"\`
	Catalogue   string \`json:"catalogue"\`
	Description string \`json:"description"\`
}

// Kind is one finding kind a producer may emit.
type Kind struct {
	Producer        string   \`json:"producer"\`
	Key             string   \`json:"key"\`
	SeverityModel   string   \`json:"severity_model"\`
	DefaultSeverity string   \`json:"default_severity,omitempty"\`
	Score           int      \`json:"score"\`
	ScoreSource     string   \`json:"score_source"\`
	Rungs           []Rung   \`json:"rungs,omitempty"\`
	SubjectTypes    []string \`json:"subject_types"\`
	FeedsRisk       bool     \`json:"feeds_risk"\`
	TitleTemplate   string   \`json:"title_template"\`

	// Guidance is the customer-facing remediation text for this kind: what a
	// person does about a finding of this kind, generic to the kind and never
	// to one instance.
	//
	// It is the REMEDIATOR seam's null default (ADR-0008 D1). A deployment
	// with no model configured answers "draft me a remediation plan" with
	// exactly this string, so it has to stand on its own — it is not a
	// placeholder for something an AI would say better, it is the answer.
	//
	// Deliberately NOT [Kind.Description], which is written for us and carries
	// internal history, table names and workstream numbers. None of that
	// belongs in front of a tenant, and none of it belongs in a prompt.
	Guidance string \`json:"guidance"\`

	Description string \`json:"description"\`
}

// Producers is the generated producer list, in YAML order.
var Producers = []Producer{
${producerEntries}
}

// All is the generated finding-kind list, in YAML order.
var All = []Kind{
${kindEntries}
}

// SubjectTypes is the shared finding-subject vocabulary, in YAML order.
var SubjectTypes = []string{${subjectTypes.map((s) => goStr(s)).join(', ')}}

// OpenQuery is what "open" means, in the query language, in ONE place.
//
// Both halves are load-bearing. \`detection_state\` is the finding's own
// lifecycle — is the condition still detected? INACTIVE means it went away —
// and \`workflow_status\` is the human one: has anybody dealt with it? Counting
// only the first includes findings someone already signed off; counting only the
// second includes findings that have since been fixed.
//
// The inventory \`has_findings\` facet COMPILES this text to produce its count,
// and the facet rail WRITES it when its checkbox is ticked, so the number and
// the list it leads to are one predicate rather than two spellings of an
// intention. The TypeScript half is OPEN_FINDINGS_QUERY, generated from the same
// line of YAML.
const OpenQuery = ${goStr(registry.open_query)}

// Get returns the registry entry for a producer and kind. The second result is
// false when the pair is not registered.
func Get(producer, kind string) (Kind, bool) {
	for _, k := range All {
		if k.Producer == producer && k.Key == kind {
			return k, true
		}
	}
	return Kind{}, false
}

// GetProducer returns the registry entry for a producer key.
func GetProducer(producer string) (Producer, bool) {
	for _, p := range Producers {
		if p.Key == producer {
			return p, true
		}
	}
	return Producer{}, false
}

// Validate reports whether a finding may be written: the producer and kind
// must be registered together, and the subject type must be one the kind
// allows. This is the enforcement point — the findings table has no CHECK.
func Validate(producer, kind, subjectType string) error {
	k, ok := Get(producer, kind)
	if !ok {
		if _, producerKnown := GetProducer(producer); !producerKnown {
			return fmt.Errorf("findings: unknown producer %q", producer)
		}
		return fmt.Errorf("findings: producer %q does not emit kind %q", producer, kind)
	}
	for _, s := range k.SubjectTypes {
		if s == subjectType {
			return nil
		}
	}
	return fmt.Errorf(
		"findings: kind %q/%q cannot be about subject type %q (allowed: %v)",
		producer, kind, subjectType, k.SubjectTypes)
}

// GuidanceFor returns the customer-facing remediation guidance for a producer
// and kind, and false when the pair is not registered.
//
// The false is not decoration. It is what stops an unregistered kind being
// answered with an empty string that reads, in a UI or in a plan draft, like
// "there is nothing to do about this" — which is the not-assessed-rendered-as-
// assessed shape ADR-0008 D4.3 is written against.
func GuidanceFor(producer, kind string) (string, bool) {
	k, ok := Get(producer, kind)
	if !ok {
		return "", false
	}
	return k.Guidance, true
}

// FeedsRisk reports whether a producer and kind contribute to the asset risk
// rollup. An unregistered pair feeds nothing — callers that care about the
// difference between "does not feed risk" and "not registered" use Validate.
func FeedsRisk(producer, kind string) bool {
	k, ok := Get(producer, kind)
	return ok && k.FeedsRisk
}
`;
}

// ---------------------------------------------------------------------------
// TypeScript mirror
// ---------------------------------------------------------------------------
//
// The same registry for the TypeScript side. It exists because the vocabulary
// crossed the language boundary by hand before it did: the query language's
// `finding` target publishes `producer`, `kind` and `subject_type` as closed
// value sets, and until this file existed the TypeScript catalogue carried a
// typed-out copy of all three with nothing checking it against the YAML.
//
// Shapes mirror the Go structs with the field names in TypeScript house style
// (severityModel, not SeverityModel), so the two read as one registry.

function renderTs(registry) {
  const subjectTypes = registry.subject_types;
  const producers = registry.producers;
  const kinds = producers.flatMap((p) => p.kinds.map((k) => ({ ...k, producer: p.key })));

  const union = (values) => values.map((v) => `  | ${tsStr(v)}`).join('\n');
  const inline = (values) => values.map((v) => tsStr(v)).join(', ');
  const constMembers = (entries) => entries.map((e) => `  ${e.name}: ${tsStr(e.value)},`).join('\n');

  const producerEntries = producers
    .map((p) => [
      '  {',
      `    key: ${tsStr(p.key)},`,
      `    label: ${tsStr(p.label)},`,
      `    catalogue: ${tsStr(p.catalogue)},`,
      `    description: ${tsStr(p.description.trim())},`,
      '  },',
    ].join('\n'))
    .join('\n');

  const kindEntries = kinds
    .map((k) => {
      const lines = [
        '  {',
        `    producer: ${tsStr(k.producer)},`,
        `    key: ${tsStr(k.key)},`,
        `    severityModel: ${tsStr(k.severity_model)},`,
      ];
      // A ladder kind carries a severity per rung. The Go struct spells that
      // absence as the zero value and hides it with `omitempty`; here the field
      // is simply not emitted, because `defaultSeverity: ''` would read as a
      // severity rather than as the absence of one.
      if (k.default_severity) lines.push(`    defaultSeverity: ${tsStr(k.default_severity)},`);
      lines.push(`    score: ${k.score ?? 0},`);
      lines.push(`    scoreSource: ${tsStr(k.score_source)},`);
      if (k.rungs) {
        lines.push('    rungs: [');
        for (const r of k.rungs) {
          lines.push(
            `      { threshold: ${tsStr(r.threshold)}, severity: ${tsStr(r.severity)}, ` +
            `score: ${r.score} },`);
        }
        lines.push('    ],');
      }
      lines.push(`    subjectTypes: [${inline(k.subject_types)}],`);
      lines.push(`    feedsRisk: ${k.feeds_risk},`);
      lines.push(`    titleTemplate: ${tsStr(k.title_template)},`);
      lines.push(`    guidance: ${tsStr(k.guidance.trim())},`);
      lines.push(`    description: ${tsStr(k.description.trim())},`);
      lines.push('  },');
      return lines.join('\n');
    })
    .join('\n');

  return `// Code generated by scripts/generate-findings-registry.mjs from
// standards/findings-registry.yaml. DO NOT EDIT — edit the YAML and run
// \`make generate\`.
//
// The finding registry for the TypeScript side — producers, the kinds each one
// emits, and the shared subject vocabulary. The Go mirror is
// shared/findings/registry_gen.go; both come from the same YAML, and
// \`make audit\` fails if either drifts.
//
// The query language's \`finding\` target publishes producer, kind and
// subject_type as closed value sets (QUERY_LANGUAGE §4.3), and
// \`query/registry-fields.gen.ts\` reads all three from here rather than
// repeating them.
//
// There is no \`validate()\` here, unlike the Go mirror. Go's is the enforcement
// point for WRITES — the findings table carries no CHECK constraint — and
// nothing in a browser writes a finding. A TypeScript copy of that rule would
// be a second opinion about something the server owns.

/** How a kind's severity is decided. */
export type FindingSeverityModel =
${union(VALID.severity_model)};

/** Where a kind's score comes from. \`catalogue\` and \`cvss_x10\` are resolved at
 *  evaluation time, not from this registry. */
export type FindingScoreSource =
${union(VALID.score_source)};

/** A severity a kind may declare. \`from-control\` and \`from-catalogue\` defer to
 *  the control or the algorithm catalogue the finding came from. */
export type FindingSeverity =
${union(VALID.severity)};

/** Every registered producer key. */
export type FindingProducerKey =
${union(producers.map((p) => p.key))};

/** Every registered kind key. Kind keys are unique across the whole registry,
 *  not just within a producer, so a finding row is readable from its kind
 *  alone. */
export type FindingKindKey =
${union(kinds.map((k) => k.key))};

/** What a finding (or a ticket, or an alert) can be about. */
export type FindingSubjectType =
${union(subjectTypes)};

/** One step of a ladder severity model. Rungs are ordered worst-last. */
export interface FindingRung {
  threshold: string;
  severity: FindingSeverity;
  score: number;
}

/** One finding producer: a subsystem that judges facts against a catalogue or
 *  a rule set. */
export interface FindingProducer {
  key: FindingProducerKey;
  label: string;
  /** The catalogue it judges against, or 'none' where there is not one. */
  catalogue: string;
  description: string;
}

/** One finding kind a producer may emit. */
export interface FindingKind {
  producer: FindingProducerKey;
  key: FindingKindKey;
  severityModel: FindingSeverityModel;
  /** Absent on a ladder kind, which carries a severity per rung. */
  defaultSeverity?: FindingSeverity;
  score: number;
  scoreSource: FindingScoreSource;
  /** Only a ladder kind has rungs. */
  rungs?: readonly FindingRung[];
  subjectTypes: readonly FindingSubjectType[];
  /** Whether the finding contributes to the asset risk rollup. */
  feedsRisk: boolean;
  titleTemplate: string;
  /**
   * Customer-facing remediation guidance: what a person does about a finding
   * of this kind. Generic to the kind, never to one instance.
   *
   * It is also the remediator seam's null default (ADR-0008 D1) — a deployment
   * with no model configured answers "draft me a plan" with exactly this — so
   * it has to stand on its own. Not the description field, which is ours.
   */
  guidance: string;
  description: string;
}

/** The producer list, in registry order. */
export const FINDING_PRODUCERS: readonly FindingProducer[] = [
${producerEntries}
];

/** The finding-kind list, in registry order. */
export const FINDING_KINDS: readonly FindingKind[] = [
${kindEntries}
];

/** The shared finding-subject vocabulary, in registry order. */
export const FINDING_SUBJECT_TYPES: readonly FindingSubjectType[] = [${inline(subjectTypes)}];

/**
 * What "open" means, in the query language, in ONE place.
 *
 * Both halves are load-bearing. \`detection_state\` is the finding's own
 * lifecycle (still detected? INACTIVE means it went away) and
 * \`workflow_status\` is the human one (has anybody dealt with it?). Counting
 * only the first includes findings someone already signed off; counting only
 * the second includes findings that have since been fixed.
 *
 * The facet rail writes this text when its "has open findings" checkbox is
 * ticked, and the server's \`has_findings\` facet COMPILES the same text to
 * produce the number beside it. The Go half is findings.OpenQuery, generated
 * from the same line of YAML.
 */
export const OPEN_FINDINGS_QUERY = ${tsStr(registry.open_query)};

/** Producer keys alone, in registry order. */
export const FINDING_PRODUCER_KEYS: readonly FindingProducerKey[] = [
${producers.map((p) => `  ${tsStr(p.key)},`).join('\n')}
];

/** Kind keys alone, in registry order. */
export const FINDING_KIND_KEYS: readonly FindingKindKey[] = [
${kinds.map((k) => `  ${tsStr(k.key)},`).join('\n')}
];

/** Producers by symbol, for call sites that prefer a name to a literal. */
export const FINDING_PRODUCER = {
${constMembers(producers.map((p) => ({ name: goConst(p.key), value: p.key })))}
} as const satisfies Record<string, FindingProducerKey>;

/** Kinds by symbol. */
export const FINDING_KIND = {
${constMembers(kinds.map((k) => ({ name: goConst(k.key), value: k.key })))}
} as const satisfies Record<string, FindingKindKey>;

/** Subject types by symbol. */
export const FINDING_SUBJECT = {
${constMembers(subjectTypes.map((s) => ({ name: goConst(s), value: s })))}
} as const satisfies Record<string, FindingSubjectType>;

/** The registry entry for a producer key, or undefined when it is not
 *  registered. Mirrors Go's \`findings.GetProducer\`. */
export function findingProducer(key: string): FindingProducer | undefined {
  return FINDING_PRODUCERS.find((p) => p.key === key);
}

/** The registry entry for a kind key, or undefined when it is not registered.
 *  Mirrors Go's \`findings.Get\`, which takes the producer as well because it
 *  also checks the pairing; kind keys are unique, so a read needs only the
 *  kind. */
export function findingKind(key: string): FindingKind | undefined {
  return FINDING_KINDS.find((k) => k.key === key);
}
`;
}

async function main() {
  const checkOnly = process.argv.includes('--check');
  const registryPath = path.resolve(root, 'standards', 'findings-registry.yaml');

  const registry = yaml.parse(await fs.readFile(registryPath, 'utf8'));
  validate(registry);
  const kindCount = registry.producers.reduce((n, p) => n + p.kinds.length, 0);

  const outputs = [
    [path.resolve(root, 'shared', 'findings', 'registry_gen.go'), render(registry)],
    [
      path.resolve(root, 'packages', 'primitives', 'src', 'findings', 'registry.gen.ts'),
      renderTs(registry),
    ],
  ];

  if (checkOnly) {
    for (const [outPath, want] of outputs) {
      const current = (await fs.pathExists(outPath)) ? await fs.readFile(outPath, 'utf8') : '';
      if (current !== want) {
        fail(`${path.relative(root, outPath)} is out of date — run \`make generate\``);
      }
    }
    console.log(
      `findings-registry check OK (${registry.producers.length} producers, ${kindCount} kinds)`);
    return;
  }

  for (const [outPath, content] of outputs) {
    await fs.ensureDir(path.dirname(outPath));
    await fs.writeFile(outPath, content);
    console.log(
      `Generated: ${path.relative(root, outPath)} ` +
      `(${registry.producers.length} producers, ${kindCount} kinds)`);
  }
}

main().catch((e) => fail(e.message));
