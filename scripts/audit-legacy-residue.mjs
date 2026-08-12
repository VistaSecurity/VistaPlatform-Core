#!/usr/bin/env node
/**
 * Legacy-table residue audit.
 *
 * The partition conversion (network_assets, crypto_implementations,
 * sensor_discoveries → *_partitioned behind live-name views) left the drained
 * originals behind as *_legacy, and the stale objects pinned to them caused
 * four separate incidents before the residue was finally retired:
 *
 *   - junction FKs targeting the empty crypto_implementations_legacy broke
 * populated schema re-applies and silently blocked every
 *     key↔implementation link;
 *   - v_ci_inventory read the empty tables, so Enterprise CMDB sync exported
 *     nothing;
 *   - mv_remediation_queue / mv_location_finding_summary read them, so the
 *     remediation queue and location summaries were permanently empty;
 *   - FKs to network_assets_legacy meant external_connections.source_asset_id
 *     could never be persisted.
 *
 * The rule this enforces, in both directions:
 *
 *   1. No statement in schema.sql may REFERENCE a *_legacy relation — no
 *      view reading one, no FK targeting one, no index/policy/trigger on one.
 *      The ONLY permitted statements naming a legacy relation are the
 *      POST-MIGRATIONS `DROP TABLE IF EXISTS public.<x>_legacy CASCADE;`
 *      retirement drops (comments are always fine).
 *   2. Those retirement drops must remain present for all three tables —
 *      deleting them would resurrect the residue on upgraded clusters.
 *
 * Static by design (parses the schema source, needs no database) so it runs
 * everywhere `make audit` does. The DB-backed complement — pg_depend/
 * pg_constraint checks against a live schema, plus behavior proofs — lives in
 * services/inventory-service/internal/services/legacy_residue_integration_test.go.
 *
 *   node scripts/audit-legacy-residue.mjs [--strict]
 *
 * Mutation-test BOTH polarities: add `CREATE VIEW x AS SELECT * FROM
 * network_assets_legacy;` and check it fails; delete one of the DROP TABLE
 * lines and check it fails; restore and check it passes.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const STRICT = process.argv.includes('--strict');

const SOURCE = path.join(ROOT, 'scripts/database/schema.sql');
const LEGACY_TABLES = [
  'network_assets_legacy',
  'crypto_implementations_legacy',
  'sensor_discoveries_legacy',
];

const problems = [];

if (!fs.existsSync(SOURCE)) {
  problems.push(`schema source missing: ${path.relative(ROOT, SOURCE)}`);
} else {
  const lines = fs.readFileSync(SOURCE, 'utf8').split('\n');
  const isRetirementDrop = (stmt) =>
    /^DROP TABLE IF EXISTS public\.\w+_legacy CASCADE;$/.test(stmt.trim());
  const seenDrops = new Set();

  lines.forEach((raw, i) => {
    // Strip line comments; `--` never appears inside a string literal in this
    // file's legacy-touching statements.
    const code = raw.split('--')[0];
    if (!/\w+_legacy\b/.test(code)) return;
    if (isRetirementDrop(code)) {
      for (const t of LEGACY_TABLES) if (code.includes(t)) seenDrops.add(t);
      return;
    }
    problems.push(
      `schema.sql:${i + 1} references a *_legacy relation outside the ` +
        `retirement drops: ${code.trim().slice(0, 120)}`
    );
  });

  for (const t of LEGACY_TABLES) {
    if (!seenDrops.has(t)) {
      problems.push(
        `retirement drop for ${t} is missing — without ` +
          `\`DROP TABLE IF EXISTS public.${t} CASCADE;\` in POST-MIGRATIONS, ` +
          `clusters installed before the retirement keep the residual table ` +
          `and everything stale that pins it.`
      );
    }
  }
}

if (problems.length === 0) {
  console.log(
    '✅ legacy residue: no statement references a *_legacy relation; all retirement drops present'
  );
  process.exit(0);
}

for (const p of problems) {
  console.error(`${STRICT ? '❌' : '⚠️'} legacy residue: ${p}`);
}
console.error(
  '\nThe *_legacy tables are drained, empty residue of the partition ' +
    'conversion. Anything that reads them reads nothing; any FK targeting ' +
    'them rejects every live id. Point new objects at the *_partitioned ' +
    'tables (or the live-name views) instead.'
);
process.exit(STRICT ? 1 : 0);
