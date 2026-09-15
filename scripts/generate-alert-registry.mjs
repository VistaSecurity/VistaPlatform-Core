#!/usr/bin/env node
// Generates the Go alert catalog from standards/alert-registry.yaml
// (NOTIFICATION_ALERTING_ARCHITECTURE.md §8.2). Output:
//   services/compliance-engine/internal/alertcatalog/registry_gen.go
// Run via `make generate`; `make audit` fails on drift (--check mode).
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const VALID = {
  track: ['tenant', 'platform'],
  kind: ['policy', 'operational'],
  status: ['live', 'planned'],
  severity_model: ['ladder', 'fixed'],
  severity: ['critical', 'high', 'medium', 'low', 'info', 'from-control', 'from-threshold'],
};

function fail(msg) {
  console.error(`alert-registry: ${msg}`);
  process.exit(1);
}

function goStr(s) {
  return JSON.stringify(String(s ?? ''));
}

async function main() {
  const checkOnly = process.argv.includes('--check');
  const registryPath = path.resolve(root, 'standards', 'alert-registry.yaml');
  const outPath = path.resolve(
    root, 'services', 'compliance-engine', 'internal', 'alertcatalog', 'registry_gen.go');

  const registry = yaml.parse(await fs.readFile(registryPath, 'utf8'));
  const types = registry.alert_types || [];
  if (!types.length) fail('no alert_types defined');

  const seen = new Set();
  for (const t of types) {
    if (!t.id || !/^[a-z0-9_]+$/.test(t.id)) fail(`bad id: ${t.id}`);
    if (seen.has(t.id)) fail(`duplicate id: ${t.id}`);
    seen.add(t.id);
    for (const f of ['track', 'kind', 'status', 'severity_model']) {
      if (!VALID[f].includes(t[f])) fail(`${t.id}: invalid ${f}: ${t[f]}`);
    }
    if (!t.source) fail(`${t.id}: source required`);
    if (t.severity_model === 'ladder') {
      // Two ladder shapes, mutually exclusive.
      //
      //   baseline_rung  a TUNABLE ladder. The rung is a product default the
      //                  tenant may replace and an activated framework may add
      //                  to, so the registry declares one rung and the effective
      //                  ladder is assembled per tenant (alertcatalog.BuildLadder).
      //   rungs          a FIXED ladder. The boundaries come from a published
      //                  standard or from the finding ladder the alert is driven
      //                  by, so there is nothing for a tenant to tune and the
      //                  registry declares the whole thing.
      //
      // Both, or neither, would leave "what is this type's ladder?" with two
      // answers or none — so exactly one is required.
      const r = t.baseline_rung;
      const rungs = t.rungs;
      if (r && rungs) fail(`${t.id}: baseline_rung and rungs are mutually exclusive`);
      if (r) {
        if (!r.severity) fail(`${t.id}: ladder types need baseline_rung with severity`);
        if (r.days === undefined && r.percent === undefined) fail(`${t.id}: baseline_rung needs days or percent`);
      } else if (Array.isArray(rungs) && rungs.length) {
        for (const rung of rungs) {
          if (!rung || typeof rung.threshold !== 'string' || !rung.threshold.trim()) {
            fail(`${t.id}: every rung needs a threshold label`);
          }
          if (!VALID.severity.includes(rung.severity)) {
            fail(`${t.id}: rung ${rung.threshold}: invalid severity: ${rung.severity}`);
          }
        }
      } else {
        fail(`${t.id}: ladder types need either a baseline_rung or a rungs list`);
      }
    } else {
      if (!t.default_severity || !VALID.severity.includes(t.default_severity)) {
        fail(`${t.id}: fixed types need a valid default_severity`);
      }
      // A fixed-severity type has ONE severity, so a rungs list on it has no
      // meaning — and the emitter below is unconditional, so an unvalidated
      // `rungs:` here reached the generated Go verbatim: an empty threshold and
      // a severity outside the vocabulary both passed, and alertcatalog.FixedRung
      // reads Rungs without consulting SeverityModel, so a detector could open an
      // alert at a severity the alerts table's CHECK constraint rejects. Refused
      // rather than ignored: silently dropping it would leave the YAML claiming
      // a ladder the product does not have.
      if (t.rungs !== undefined) {
        fail(`${t.id}: rungs is only meaningful for severity_model: ladder (this is ${t.severity_model})`);
      }
    }
  }

  const entries = types.map((t) => {
    const rungDays = t.baseline_rung?.days ?? 0;
    const rungPercent = t.baseline_rung?.percent ?? 0;
    const rungSeverity = t.baseline_rung?.severity ?? '';
    // Field names are padded to the longest key (BaselineSeverity /
    // EnabledByDefault) so the emitted literal is gofmt-clean — gofmt aligns
    // composite-literal values, and CI's format check runs on this file.
    //
    // Rungs is emitted LAST and only when present: a multi-line value ends
    // gofmt's alignment run, so anything after it would be padded to a
    // different width and the generated file would not be gofmt-clean.
    const rungs = Array.isArray(t.rungs) && t.rungs.length
      ? `\n		Rungs: []LadderRung{\n${t.rungs
          .map((r) => `			{Threshold: ${goStr(r.threshold)}, Severity: ${goStr(r.severity)}},`)
          .join('\n')}\n		},`
      : '';
    return `	{
		ID:               ${goStr(t.id)},
		Track:            ${goStr(t.track)},
		Kind:             ${goStr(t.kind)},
		Status:           ${goStr(t.status)},
		Source:           ${goStr(t.source)},
		SubjectType:      ${goStr(t.subject_type)},
		SeverityModel:    ${goStr(t.severity_model)},
		DefaultSeverity:  ${goStr(t.default_severity ?? '')},
		BaselineDays:     ${rungDays},
		BaselinePercent:  ${rungPercent},
		BaselineSeverity: ${goStr(rungSeverity)},
		AutoResolve:      ${goStr(t.auto_resolve ?? '')},
		EnabledByDefault: ${t.enabled_by_default !== false},
		Description:      ${goStr((t.description ?? '').trim())},${rungs}
	},`;
  });

  const out = `// Code generated by scripts/generate-alert-registry.mjs from
// standards/alert-registry.yaml. DO NOT EDIT — edit the YAML and run
// \`make generate\`.
package alertcatalog

// LadderRung is one step of a FIXED ladder — a ladder whose boundaries come
// from a published standard (the CVSS qualitative bands) or from the finding
// ladder the alert is driven by, rather than from a tenant preference.
//
// Threshold is the boundary in the detector's own units, as a label a person
// reads ("CVSS 7.0 or higher"). It is deliberately free text and deliberately
// NOT parsed: the producer owns the numbers, the registry owns what a rung
// MEANS, and parsing an integer back out of an English sentence would make a
// typo in the YAML a silent change of behaviour. (Same split, and the same
// reasoning, as the findings registry's rungs.)
//
// Distinct from [Rung], which is a rung of a TUNABLE day ladder assembled per
// tenant by BuildLadder and carries a Source saying where it came from. A
// fixed rung has no source to report: it is the product's, always.
type LadderRung struct {
	Threshold string \`json:"threshold"\`
	Severity  string \`json:"severity"\`
}

// Entry is one registry alert type (the catalog row).
type Entry struct {
	ID               string \`json:"id"\`
	Track            string \`json:"track"\`
	Kind             string \`json:"kind"\`
	Status           string \`json:"status"\`
	Source           string \`json:"source"\`
	SubjectType      string \`json:"subject_type"\`
	SeverityModel    string \`json:"severity_model"\`
	DefaultSeverity  string \`json:"default_severity,omitempty"\`
	BaselineDays     int    \`json:"baseline_days,omitempty"\`
	BaselinePercent  int    \`json:"baseline_percent,omitempty"\`
	BaselineSeverity string \`json:"baseline_severity,omitempty"\`
	AutoResolve      string \`json:"auto_resolve,omitempty"\`
	EnabledByDefault bool   \`json:"enabled_by_default"\`
	Description      string \`json:"description"\`

	// Rungs is the fixed ladder, worst-last. Empty for a fixed-severity type
	// and for a ladder type that declares a tunable baseline_rung instead.
	Rungs []LadderRung \`json:"rungs,omitempty"\`
}

// Registry is the generated alert-type catalog, in YAML order.
var Registry = []Entry{
${entries.join('\n')}
}
`;

  if (checkOnly) {
    const current = (await fs.pathExists(outPath)) ? await fs.readFile(outPath, 'utf8') : '';
    if (current !== out) {
      fail('registry_gen.go is out of date — run `make generate`');
    }
    console.log(`alert-registry check OK (${types.length} types)`);
    return;
  }

  await fs.ensureDir(path.dirname(outPath));
  await fs.writeFile(outPath, out);
  console.log(`Generated: ${path.relative(root, outPath)} (${types.length} alert types)`);
}

main().catch((e) => fail(e.message));
