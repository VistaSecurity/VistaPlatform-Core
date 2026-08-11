#!/usr/bin/env node
// Audit that no Go service writes a credential-shaped column straight to the
// database without going through shared/security/credentials.
//
// WHY THIS EXISTS
//
// found integration credentials stored plaintext in six live
// database stores. Every one had the same cause, and it was not carelessness:
// there was no shared helper, so `json.Marshal(config)` was the path of least
// resistance for anyone adding a connector. Fixing the six stores without
// fixing that resets the clock — the seventh connector lands plaintext for
// exactly the same reason.
//
// So this check enforces the *procedure*, not the six instances: a Go file
// that writes a column named like a credential must import the credentials
// package. It cannot verify the import is actually applied to that column
// (that is what the DB-integration tests do, asserting on raw column bytes),
// but it does make "I didn't know there was a helper" impossible.
//
// HOW IT DECIDES
//
//   1. Parse every non-test .go file under services/ for SQL writes:
//      INSERT INTO <table> (col, col, ...)  and  UPDATE ... SET col = ...
//   2. Flag any written column whose name matches CREDENTIAL_COLUMN.
//   3. Pass if the file imports shared/security/credentials.
//   4. Otherwise fail — unless the (file, column) pair is in EXEMPT, which
//      requires a written reason.
//
// Wired into `make audit`. Run directly for the same output.
//
// MUTATION TEST (do this if you change the matcher): delete the credentials
// import from services/cluster-sensor-service/internal/services/alert_service.go
// and re-run — it must fail on slack_webhook_url. A guard that cannot fail is
// worse than no guard.

import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const HELPER_IMPORT = 'shared/security/credentials';

// Column names that mean "this holds, or can hold, a secret". Deliberately
// shaped on the *name*, because a name is what a new connector's author picks
// and it is the only signal available without executing the code.
const CREDENTIAL_COLUMN =
  /(^|_)(config|credentials?|secret|secrets|password|passwd|api_key|apikey|token|webhook_url|private_key|client_secret|auth_config)($|_)/i;

// Name shapes that carry no secret whatever the table. These are suffixes and
// prefixes rather than whole names, because they generalise: any future
// *_hash column is a hash, not the thing hashed.
const NON_CREDENTIAL_SHAPE = [
  [/_hash$/, 'a one-way hash of a secret is not the secret'],
  [/_encrypted$/, 'the column name is the contract: it already holds ciphertext'],
  [/_at$/, 'timestamp'],
  [/_id$/, 'foreign key'],
  [/_count$/, 'counter'],
  [/_version$/, 'version number'],
  [/_expires$/, 'expiry timestamp'],
  [/^force_/, 'boolean flag'],
];

// Whole column names that trip the matcher but provably hold no secret. Each
// needs a reason; "it's fine" is not one.
const NON_CREDENTIAL_COLUMNS = new Map([
  ['mapping_config', 'field-name mapping between our schema and a remote CMDB — no auth material'],
  ['field_mapping_config', 'field-name mapping — no auth material'],
  ['sync_config', 'CMDB sync schedule/direction knobs; the credentials live in connection_config'],
  ['token_url', "an IdP's OAuth token ENDPOINT, a public URL, not a token"],
  ['token_prefix', 'the non-secret display prefix of an API token; the token itself is hashed'],
  ['password_encryption_method', 'names the algorithm a remote database uses — a discovery finding, not a credential'],
  ['ui_config', 'tenant white-label branding (colours, logo URL) — no auth material'],
  ['raw_config', 'the raw device configuration text a discovery scrapes; a finding, not our credential'],
  ['configuration_drift', 'boolean drift flag'],
]);

// Whole `table.column` stores whose name trips the matcher but which hold no
// secret. Table-scoped so that a genuinely credential-bearing `config` column
// elsewhere still trips.
const NON_CREDENTIAL_STORES = new Map([
  [
    'tenant_admin_settings.config',
    'tenant admin PREFERENCES — discovery defaults, network spaces, auto-approval rules. No auth material; written by four services for exactly that reason.',
  ],
  [
    'user_workflow_progress.config',
    'onboarding wizard step state',
  ],
]);

// (file, table.column) pairs that write a credential-shaped column but do not
// use the helper. Each needs a reason. Prefer fixing the code — this list is a
// migration backlog, not a permanent home.
const EXEMPT = [
  // ---- Pre-existing hand-rolled encryptors ( step 3).
  // These DO encrypt; they just predate the shared helper and each carries its
  // own drifting denylist and no enc:v1: tag. Migrating them needs the
  // legacy-unprefixed read path and per-store integration tests, which is a
  // second PR's worth of work.
  {
    file: 'services/admin-service/internal/integrations/service.go',
    store: 'platform_integrations.config',
    reason: 'hand-rolled encryptConfig with its own denylist — migrate to credentials.Cipher',
  },
  {
    file: 'services/device-interrogation-service/internal/handlers/integrations_repository.go',
    store: 'platform_integrations.config',
    reason: 'config is encrypted by the handler layer (handlers/integrations.go encryptConfig) before it reaches this repository',
  },
  {
    file: 'services/device-interrogation-service/internal/handlers/experimental_actions.go',
    store: 'platform_integrations.config',
    reason: 'same hand-rolled encryptConfig as integrations.go — migrate together',
  },
  {
    file: 'services/device-interrogation-service/internal/services/device_service.go',
    store: 'devices.password',
    reason: 'encrypted with encryption.Service directly (no enc:v1: tag) — migrate to credentials.Cipher',
  },
  {
    file: 'services/device-interrogation-service/internal/services/job_queue_service.go',
    store: 'device_jobs.credentials',
    reason: 'credentials arrive already encrypted from device_service and are decrypted agent-side; this layer only relays ciphertext',
  },
  {
    file: 'services/inventory-service/ee/cmdbsync/service.go',
    store: 'cmdb_sync_profiles.connection_config',
    reason: 'encrypted by cmdbCredentialCipher (#959) — the prototype for the shared helper; fold it in',
  },

  // ---- Constant seed data, no credential can reach the column.
  {
    file: 'services/auth-service/internal/auth/service.go',
    store: 'tenant_notification_channels.config',
    reason:
      'seedDefaultNotificationPack inserts two SQL literals — {} for the in-app channel and {"recipients":[],"recipient_role":"tenant_admin"} for email. No caller input, no credential field. notification-service (the owning writer) encrypts everything else that reaches this column.',
  },

  // ---- Single-use reset/verification nonces.
  // These are recoverable secrets in a plaintext column, but the right fix is
  // to STORE A HASH (they are only ever compared, never replayed by us), which
  // is a different change from encryption-at-rest and out of's scope.
  {
    file: 'services/admin-service/internal/handlers/auth.go',
    store: 'platform_users.password_reset_token',
    reason: 'single-use reset nonce; correct fix is hashing, not encryption — tracked separately',
  },
  {
    file: 'services/admin-service/internal/handlers/platform_user_repository.go',
    store: 'platform_users.password_reset_token',
    reason: 'single-use reset nonce; correct fix is hashing, not encryption — tracked separately',
  },
  {
    file: 'services/auth-service/internal/api/users.go',
    store: 'users.email_verification_token',
    reason: 'single-use verification nonce; correct fix is hashing, not encryption — tracked separately',
  },
];

function isExempt(file, store) {
  return EXEMPT.some((e) => e.file === file && e.store === store);
}

function isCredentialColumn(col) {
  if (!CREDENTIAL_COLUMN.test(col)) return false;
  if (NON_CREDENTIAL_COLUMNS.has(col)) return false;
  return !NON_CREDENTIAL_SHAPE.some(([re]) => re.test(col));
}

async function goFiles(dir) {
  const out = [];
  async function walk(d) {
    let entries;
    try {
      entries = await fs.readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) {
        if (e.name === 'vendor' || e.name === 'node_modules') continue;
        await walk(p);
      } else if (e.name.endsWith('.go') && !e.name.endsWith('_test.go')) {
        out.push(p);
      }
    }
  }
  await walk(dir);
  return out;
}

// Normalises a table reference to bare lowercase name, dropping any schema
// qualifier and quotes ("audit"."siem_integrations" -> siem_integrations).
function normalizeTable(raw) {
  return raw.replace(/"/g, '').split('.').pop().toLowerCase();
}

// (table, column) pairs written by INSERT INTO <table> ( ... ). Only the
// parenthesised column list is parsed; the VALUES clause is ignored.
function insertWrites(src) {
  const found = [];
  const re = /INSERT\s+INTO\s+([\w."]+)\s*\(([^)]*)\)/gis;
  let m;
  while ((m = re.exec(src)) !== null) {
    const table = normalizeTable(m[1]);
    for (const raw of m[2].split(',')) {
      const col = raw.trim().replace(/^"|"$/g, '');
      if (/^[a-z_][a-z0-9_]*$/i.test(col)) found.push([table, col.toLowerCase()]);
    }
  }
  return found;
}

// (table, column) pairs assigned by UPDATE ... SET col = ..., col = ...
// (stops at WHERE / RETURNING / end of statement).
function updateWrites(src) {
  const found = [];
  const re = /UPDATE\s+([\w."]+)\s+SET\s+([\s\S]*?)(?:\bWHERE\b|\bRETURNING\b|`)/gi;
  let m;
  while ((m = re.exec(src)) !== null) {
    const table = normalizeTable(m[1]);
    const assignRe = /([a-z_][a-z0-9_]*)\s*=/gi;
    let a;
    while ((a = assignRe.exec(m[2])) !== null) found.push([table, a[1].toLowerCase()]);
  }
  return found;
}

async function main() {
  const files = await goFiles(path.join(root, 'services'));
  const violations = [];
  let scanned = 0;
  let writersFound = 0;

  for (const abs of files) {
    const rel = path.relative(root, abs);
    const src = await fs.readFile(abs, 'utf8');
    scanned++;
    if (!/INSERT\s+INTO|UPDATE\s+[\w."]+\s+SET/i.test(src)) continue;

    const writes = [...insertWrites(src), ...updateWrites(src)];
    const credentialWrites = [];
    const seen = new Set();
    for (const [table, col] of writes) {
      const key = `${table}.${col}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (!isCredentialColumn(col)) continue;
      if (NON_CREDENTIAL_STORES.has(key)) continue;
      credentialWrites.push(key);
    }
    if (credentialWrites.length === 0) continue;
    writersFound++;

    if (src.includes(HELPER_IMPORT)) continue;

    const unexcused = credentialWrites.filter((k) => !isExempt(rel, k));
    if (unexcused.length > 0) {
      violations.push({ file: rel, columns: unexcused });
    }
  }

  if (violations.length > 0) {
    console.error('');
    console.error('credential-encryption audit FAILED');
    console.error('');
    console.error('These files write a credential-shaped column but do not import');
    console.error(`  github.com/vistasecurity/vistaplatform/${HELPER_IMPORT}`);
    console.error('');
    for (const v of violations) {
      console.error(`  ${v.file}`);
      console.error(`      columns: ${v.columns.join(', ')}`);
    }
    console.error('');
    console.error('Fix by routing the write through credentials.Cipher (EncryptMap for a');
    console.error('JSONB config blob, EncryptValue for a scalar column) and decrypting on');
    console.error('read — see shared/security/credentials/credentials.go, and');
    console.error('services/cluster-sensor-service/internal/services/alert_service.go for a');
    console.error('scalar example.');
    console.error('');
    console.error('If the column genuinely holds no secret, add it to');
    console.error('NON_CREDENTIAL_COLUMNS (or the file to EXEMPT) in this script WITH A');
    console.error('REASON. Silencing it without one is how #961 happened.');
    console.error('');
    process.exit(1);
  }

  console.log(
    `credential-encryption audit OK: ${scanned} Go files scanned, ${writersFound} credential-column writers, all on the shared helper`,
  );
}

main().catch((err) => {
  console.error('audit-credential-encryption crashed:', err);
  process.exit(1);
});
