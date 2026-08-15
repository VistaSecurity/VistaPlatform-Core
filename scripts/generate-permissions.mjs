#!/usr/bin/env node
// Generates every tenant-RBAC permission artefact from standards/permissions.yaml.
//
// Before this existed, the permission catalogue and the per-role grant filters
// were hand-maintained in five places in three languages (SQL, Go, TypeScript,
// JavaScript). They drifted — commit 8ada815f lost the `alerts` resource from
// the Go mirror of security_admin, and the JS mirror in audit-permissions.mjs
// under-reported security_admin for the whole of.
//
// Outputs:
//   scripts/database/seed.sql                              (2 generated regions)
//   services/auth-service/internal/auth/role_grants_gen.go (whole file)
//   shared/rbac/permissions.go                             (1 generated region)
//   packages/primitives/src/rbac/constants.ts              (whole file)
//   scripts/lib/role-grants.gen.mjs                        (whole file)
//
// Run via `make generate`; `make audit` runs `--check` and fails on drift.
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const root = path.resolve(__dirname, '..');

const IDENT = /^[a-z][a-z0-9_]*$/;

function fail(msg) {
  console.error(`permissions: ${msg}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Load + validate
// ---------------------------------------------------------------------------

function load() {
  const registryPath = path.join(root, 'standards', 'permissions.yaml');
  const reg = yaml.parse(fs.readFileSync(registryPath, 'utf8'));

  const permissions = [];
  const byName = new Map();
  for (const res of reg.resources || []) {
    if (!IDENT.test(res.name || '')) fail(`bad resource name: ${res.name}`);
    if (!res.permissions?.length) fail(`resource ${res.name}: no permissions`);
    for (const p of res.permissions) {
      if (!IDENT.test(p.action || '')) fail(`${res.name}: bad action: ${p.action}`);
      if (!p.description) fail(`${res.name}.${p.action}: description required`);
      const name = `${res.name}.${p.action}`;
      if (byName.has(name)) fail(`duplicate permission: ${name}`);
      const row = {
        name,
        resource: res.name,
        action: p.action,
        scope: p.scope || 'tenant',
        description: p.description,
      };
      byName.set(name, row);
      permissions.push(row);
    }
  }
  if (!permissions.length) fail('no permissions defined');

  const retired = reg.retired || [];
  for (const group of retired) {
    if (!group.names?.length) fail('retired group with no names');
    for (const n of group.names) {
      if (byName.has(n)) fail(`${n} is both live and retired`);
    }
  }

  const roles = reg.roles || [];
  if (!roles.length) fail('no roles defined');
  const CLAUSE_FIELDS = [
    'resources', 'actions', 'names',
    'except_resources', 'except_actions', 'except_names',
  ];
  for (const r of roles) {
    if (!IDENT.test(r.name || '')) fail(`bad role name: ${r.name}`);
    if (!r.display_name || !r.summary) fail(`role ${r.name}: display_name and summary required`);
    const g = r.grant;
    if (!g) fail(`role ${r.name}: grant required`);
    if (!g.all && !g.any_of?.length) fail(`role ${r.name}: grant needs any_of or all: true`);
    if (g.all && g.any_of) fail(`role ${r.name}: grant cannot be both all and any_of`);
    for (const clause of g.any_of || []) {
      const keys = Object.keys(clause);
      if (!keys.length) fail(`role ${r.name}: empty grant clause`);
      for (const k of keys) {
        if (!CLAUSE_FIELDS.includes(k)) fail(`role ${r.name}: unknown clause field: ${k}`);
        if (!Array.isArray(clause[k]) || !clause[k].length) {
          fail(`role ${r.name}: clause field ${k} must be a non-empty list`);
        }
      }
      // Every referenced permission name must exist, or the filter is dead.
      for (const n of [...(clause.names || []), ...(clause.except_names || [])]) {
        if (!byName.has(n)) fail(`role ${r.name}: unknown permission name in grant: ${n}`);
      }
      for (const rn of [...(clause.resources || []), ...(clause.except_resources || [])]) {
        if (!permissions.some((p) => p.resource === rn)) {
          fail(`role ${r.name}: unknown resource in grant: ${rn}`);
        }
      }
    }
    for (const n of g.except_names || []) {
      if (!byName.has(n)) fail(`role ${r.name}: unknown permission name in except_names: ${n}`);
    }
  }
  return { permissions, resources: reg.resources, retired, roles };
}

// ---------------------------------------------------------------------------
// Grant evaluation — the ONE semantic definition. SQL/Go/JS emitters below all
// derive from the same clause shape, and `evaluate` is what the self-check uses
// to prove the emitted SQL and the emitted JS agree.
// ---------------------------------------------------------------------------

function clauseMatches(clause, p) {
  if (clause.resources && !clause.resources.includes(p.resource)) return false;
  if (clause.actions && !clause.actions.includes(p.action)) return false;
  if (clause.names && !clause.names.includes(p.name)) return false;
  if (clause.except_resources?.includes(p.resource)) return false;
  if (clause.except_actions?.includes(p.action)) return false;
  if (clause.except_names?.includes(p.name)) return false;
  return true;
}

function grants(role, p) {
  const g = role.grant;
  if (g.except_names?.includes(p.name)) return false;
  if (g.all) return true;
  return (g.any_of || []).some((c) => clauseMatches(c, p));
}

// ---------------------------------------------------------------------------
// SQL emitters
// ---------------------------------------------------------------------------

const sqlLit = (s) => `'${String(s).replace(/'/g, "''")}'`;

// `col IN ('a','b')` collapsed to `col = 'a'` for a single value — that is the
// shape the hand-written SQL used, and keeping it makes the first generated
// output diff-clean against what shipped.
function sqlIn(col, values, negate = false) {
  if (values.length === 1) return `${col} ${negate ? '<>' : '='} ${sqlLit(values[0])}`;
  return `${col} ${negate ? 'NOT IN' : 'IN'} (${values.map(sqlLit).join(', ')})`;
}

function sqlClause(clause) {
  const parts = [];
  if (clause.actions) parts.push(sqlIn('tp.action', clause.actions));
  if (clause.resources) parts.push(sqlIn('tp.resource', clause.resources));
  if (clause.names) parts.push(sqlIn('tp.name', clause.names));
  if (clause.except_actions) parts.push(sqlIn('tp.action', clause.except_actions, true));
  if (clause.except_resources) parts.push(sqlIn('tp.resource', clause.except_resources, true));
  if (clause.except_names) parts.push(sqlIn('tp.name', clause.except_names, true));
  return parts.join(' AND ');
}

// Positive filter: the WHERE predicate that selects the permissions the role
// should hold (used by the INSERT).
//
// A disjunction is ALWAYS bracketed. It is spliced in after an `AND`, and an
// unbracketed `A OR B` there binds as `(... AND A) OR B` — which drops the
// tenant and role scoping off the second clause entirely. sqlSelfCheck below
// evaluates the emitted SQL to make sure this cannot regress.
function sqlGrantExpr(role) {
  const g = role.grant;
  const clauses = g.all ? [] : (g.any_of || []).map(sqlClause);
  const except = g.except_names ? sqlIn('tp.name', g.except_names, true) : null;

  if (g.all) return except || 'TRUE';
  const body = clauses.length === 1 ? clauses[0] : `(${clauses.join(' OR ')})`;
  if (!except) return body;
  return `${clauses.length === 1 ? `(${body})` : body} AND ${except}`;
}

// Negative filter: the WHERE predicate that selects grants the role should NOT
// hold (used by the reconciliation DELETE). `all + except_names` is emitted as
// the direct positive test rather than NOT(<>), matching the shipped SQL.
function sqlRevokeExpr(role) {
  const g = role.grant;
  if (g.all && g.except_names) return sqlIn('tp.name', g.except_names);
  const grant = sqlGrantExpr(role);
  return isBracketed(grant) ? `NOT ${grant}` : `NOT (${grant})`;
}

// True iff the expression is a single bracketed group — `(a OR b)` is, but
// `(a OR b) AND c` is not, so `NOT` still needs its own brackets there.
function isBracketed(expr) {
  if (!expr.startsWith('(')) return false;
  let depth = 0;
  for (let i = 0; i < expr.length; i += 1) {
    if (expr[i] === '(') depth += 1;
    else if (expr[i] === ')') {
      depth -= 1;
      if (depth === 0) return i === expr.length - 1;
    }
  }
  return false;
}

// Render `<indent>AND <expr><suffix>`, wrapping a long disjunction at its OR
// boundaries with the continuation aligned just inside the opening bracket.
function renderAnd(indent, expr, suffix) {
  const prefix = `${indent}AND `;
  if ((prefix + expr).length <= 102 || !expr.includes(' OR ')) return prefix + expr + suffix;
  const cont = ' '.repeat(prefix.length + expr.indexOf('(') + 1);
  return prefix + expr.split(' OR ').join(`\n${cont}OR `) + suffix;
}

function emitSeedCatalogue(reg) {
  const out = [];
  out.push('INSERT INTO tenant_permissions (name, resource, action, scope, description) VALUES');
  const rows = [];
  // +4 = two quotes, the trailing comma, and one separating space.
  const width = (f) => Math.max(...reg.permissions.map((p) => p[f].length)) + 4;
  const nameW = width('name');
  const resW = width('resource');
  const actW = width('action');
  for (const res of reg.resources) {
    if (res.note) {
      for (const line of res.note.trimEnd().split('\n')) {
        rows.push({ comment: `-- ${line}`.trimEnd() });
      }
    }
    for (const p of res.permissions) {
      const row = reg.permissions.find((x) => x.name === `${res.name}.${p.action}`);
      rows.push({
        sql: `(${(sqlLit(row.name) + ',').padEnd(nameW)}${(sqlLit(row.resource) + ',').padEnd(resW)}${(sqlLit(row.action) + ',').padEnd(actW)}${sqlLit(row.scope)}, ${sqlLit(row.description)})`,
      });
    }
  }
  const sqlRows = rows.filter((r) => r.sql);
  let seen = 0;
  for (const r of rows) {
    if (r.comment) {
      out.push(r.comment);
    } else {
      seen += 1;
      out.push(r.sql + (seen === sqlRows.length ? '' : ','));
    }
  }
  out.push('ON CONFLICT (name) DO NOTHING;');

  for (const group of reg.retired) {
    out.push('');
    if (group.note) {
      for (const line of group.note.trimEnd().split('\n')) out.push(`-- ${line}`.trimEnd());
    }
    out.push(`-- CASCADE on tenant_role_permissions removes the matching grants automatically.`);
    out.push(`DELETE FROM tenant_permissions WHERE name IN (${group.names.map(sqlLit).join(', ')});`);
  }
  return out.join('\n');
}

function emitSeedGrants(reg) {
  const out = [];
  out.push('-- ----------------------------------------------------------------');
  out.push('-- Reconcile permission grants on SYSTEM roles to match the');
  out.push('-- canonical filters below. The DELETE removes grants that no');
  out.push('-- longer satisfy the current filter; the INSERT adds any new');
  out.push('-- ones. Both are no-ops once the role is in the desired state.');
  out.push('-- Only touches is_system_role=true; custom user-created roles');
  out.push('-- are never modified here.');
  out.push('-- ----------------------------------------------------------------');
  for (const role of reg.roles) {
    out.push('');
    out.push(`-- ${role.display_name} (internal: ${role.name})`);
    if (role.note) {
      for (const line of role.note.trimEnd().split('\n')) out.push(`-- ${line}`.trimEnd());
    }
    out.push('DELETE FROM tenant_role_permissions trp');
    out.push('USING tenant_roles tr, tenant_permissions tp');
    out.push('WHERE trp.role_id = tr.id AND trp.permission_id = tp.id');
    out.push(`  AND tr.tenant_id = tenant_record.id AND tr.name = ${sqlLit(role.name)} AND tr.is_system_role = true`);
    out.push(renderAnd('  ', sqlRevokeExpr(role), ';'));
    out.push('INSERT INTO tenant_role_permissions (role_id, permission_id)');
    out.push('SELECT tr.id, tp.id FROM tenant_roles tr CROSS JOIN tenant_permissions tp');
    out.push(`WHERE tr.tenant_id = tenant_record.id AND tr.name = ${sqlLit(role.name)} AND tr.is_system_role = true`);
    out.push(renderAnd('  ', sqlGrantExpr(role), ''));
    out.push('ON CONFLICT (role_id, permission_id) DO NOTHING;');
  }
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// SQL evaluator — a recursive-descent reader for the restricted predicate
// grammar the emitters above produce (AND / OR / NOT / IN / = / <> / TRUE over
// tp.<col>). It exists so the self-check can evaluate the SQL WE EMIT rather
// than trusting it.
//
// This is not decoration. The first version of sqlGrantExpr emitted a
// disjunction unbracketed — `AND tp.resource = 'billing' OR tp.name IN (...)`
// — which Postgres reads as `(everything AND resource='billing') OR name
// IN (...)`, detaching the tenant and role scoping from the second half. The
// JS-only self-check was green through it. This evaluator fails on it.
// ---------------------------------------------------------------------------

function sqlTokens(expr) {
  const re = /\s*(\(|\)|,|<>|=|NOT IN|NOT|AND|OR|IN|TRUE|tp\.[a-z_]+|'(?:[^']|'')*')/gy;
  const toks = [];
  let i = 0;
  while (i < expr.length) {
    re.lastIndex = i;
    const m = re.exec(expr);
    if (!m) fail(`sql evaluator: cannot tokenize at ${JSON.stringify(expr.slice(i, i + 30))}`);
    toks.push(m[1]);
    i = re.lastIndex;
  }
  return toks;
}

function sqlEval(expr, row) {
  const toks = sqlTokens(expr.replace(/\s+/g, ' '));
  let pos = 0;
  const peek = () => toks[pos];
  const take = (t) => {
    if (toks[pos] !== t) fail(`sql evaluator: expected ${t}, got ${toks[pos]} in ${expr}`);
    pos += 1;
  };
  const unquote = (s) => s.slice(1, -1).replace(/''/g, "'");

  function parseOr() {
    let v = parseAnd();
    while (peek() === 'OR') { pos += 1; v = parseAnd() || v; }
    return v;
  }
  function parseAnd() {
    let v = parseUnary();
    while (peek() === 'AND') { pos += 1; v = parseUnary() && v; }
    return v;
  }
  function parseUnary() {
    if (peek() === 'NOT') { pos += 1; return !parseUnary(); }
    if (peek() === '(') { pos += 1; const v = parseOr(); take(')'); return v; }
    if (peek() === 'TRUE') { pos += 1; return true; }
    const col = peek();
    if (!col?.startsWith('tp.')) fail(`sql evaluator: expected a column, got ${col} in ${expr}`);
    pos += 1;
    const field = col.slice(3);
    if (!(field in row)) fail(`sql evaluator: unknown column ${col}`);
    const op = peek();
    pos += 1;
    if (op === '=' || op === '<>') {
      const lit = unquote(peek());
      pos += 1;
      return op === '=' ? row[field] === lit : row[field] !== lit;
    }
    if (op === 'IN' || op === 'NOT IN') {
      take('(');
      const vals = [];
      for (;;) {
        vals.push(unquote(peek()));
        pos += 1;
        if (peek() === ',') { pos += 1; continue; }
        break;
      }
      take(')');
      const hit = vals.includes(row[field]);
      return op === 'IN' ? hit : !hit;
    }
    return fail(`sql evaluator: unknown operator ${op} in ${expr}`);
  }

  const result = parseOr();
  if (pos !== toks.length) fail(`sql evaluator: trailing tokens in ${expr}`);
  return result;
}

// The emitted predicate is spliced in after the tenant and role scoping:
//
//	WHERE tr.tenant_id = ... AND tr.name = ... AND <expr>
//
// so an unbracketed top-level OR detaches that scoping from everything past the
// OR. Model it with a guard conjunct that is FALSE for every row: whatever
// <expr> says, `false AND <expr>` must be false. It is only NOT false when the
// OR has escaped the guard — which is exactly the bug.
//
// Note that a `TRUE AND <expr>` context does NOT detect this (an escaped OR
// still evaluates to the right answer there). The guard has to be false.
function sqlEvalBindsUnderGuard(expr, row) {
  return sqlEval(`tp.scope = '__no_such_scope__' AND ${expr}`, row) === false;
}

// ---------------------------------------------------------------------------
// Go emitters
// ---------------------------------------------------------------------------

const goConstName = (p) =>
  'Permission' +
  [p.resource, p.action]
    .map((s) => s.split('_').map((w) => w[0].toUpperCase() + w.slice(1)).join(''))
    .join('');

function goComment(text, indent = '\t') {
  return text.trimEnd().split('\n').map((l) => `${indent}// ${l}`.trimEnd()).join('\n');
}

function emitGoConsts(reg) {
  const out = [];
  out.push('const (');
  let first = true;
  for (const res of reg.resources) {
    if (!first) out.push('');
    first = false;
    if (res.note) out.push(goComment(res.note));
    const names = res.permissions.map((p) => goConstName({ resource: res.name, action: p.action }));
    const w = Math.max(...names.map((n) => n.length));
    for (const [i, p] of res.permissions.entries()) {
      out.push(`\t${names[i].padEnd(w)} = "${res.name}.${p.action}"`);
    }
  }
  out.push(')');
  // Trailing blank line so the END marker is not glued to the closing paren —
  // gofmt requires a blank line between a declaration and a following comment.
  out.push('');
  return out.join('\n');
}

function emitGoGrants(reg) {
  const entries = reg.roles.map((role) => {
    const note = role.note ? goComment(role.note, '\t') + '\n' : '';
    return `${note}\t{
\t\tRole:   ${JSON.stringify(role.name)},
\t\tRevoke: ${JSON.stringify(sqlRevokeExpr(role))},
\t\tGrant:  ${JSON.stringify(sqlGrantExpr(role))},
\t},`;
  });
  return `// Code generated by scripts/generate-permissions.mjs from
// standards/permissions.yaml. DO NOT EDIT — edit the YAML and run
// \`make generate\`.
package auth

// roleGrantFilter is one system role's permission reconciliation filter. The
// two expressions are SQL predicates over the aliases tr (tenant_roles) and tp
// (tenant_permissions):
//
//	Revoke — selects grants the role must NOT hold (the reconciliation DELETE)
//	Grant  — selects the permissions the role must hold (the INSERT)
//
// They are the same expressions emitted into the seed.sql DO block, from the
// same YAML, so the path a new tenant takes (assignRolePermissions) and the
// path an existing tenant takes on helm upgrade (seed.sql) cannot diverge.
type roleGrantFilter struct {
	Role   string
	Revoke string
	Grant  string
}

// roleGrantFilters is the generated grant matrix, in registry order.
var roleGrantFilters = []roleGrantFilter{
${entries.join('\n')}
}
`;
}

// ---------------------------------------------------------------------------
// TypeScript emitter
// ---------------------------------------------------------------------------

function emitTs(reg) {
  const out = [];
  out.push('// Code generated by scripts/generate-permissions.mjs from');
  out.push('// standards/permissions.yaml. DO NOT EDIT — edit the YAML and run');
  out.push('// `make generate`.');
  out.push('//');
  out.push('// Tenant permission registry for the TypeScript side — both frontend-v2 and');
  out.push('// admin-ui-v2 import it as `@vistasecurity/primitives/rbac`, and every gate');
  out.push('// checks against it. The Go mirror is shared/rbac/permissions.go; the DB');
  out.push('// mirror is the tenant_permissions table seeded by scripts/database/seed.sql.');
  out.push('// All three come from the same YAML.');
  out.push('');
  out.push('export const TENANT_PERMISSIONS = {');
  for (const res of reg.resources) {
    if (res.note) {
      for (const line of res.note.trimEnd().split('\n')) out.push(`  // ${line}`.trimEnd());
    }
    out.push(`  ${res.name}: {`);
    for (const p of res.permissions) {
      out.push(`    ${p.action}: '${res.name}.${p.action}',`);
    }
    out.push('  },');
  }
  out.push('} as const;');
  out.push('');
  out.push('type ValueOf<T> = T[keyof T];');
  out.push('type DeepValueOf<T> = T extends object ? DeepValueOf<ValueOf<T>> : T;');
  out.push('');
  out.push('export type TenantPermissionKey = DeepValueOf<typeof TENANT_PERMISSIONS>;');
  out.push('');
  return out.join('\n');
}

// ---------------------------------------------------------------------------
// JS emitter (scripts/audit-permissions.mjs ROLE_GRANTS)
// ---------------------------------------------------------------------------

function jsList(values) {
  return `[${values.map((v) => `'${v}'`).join(', ')}]`;
}

function jsClause(clause) {
  const parts = [];
  const one = (field, values, col, negate) => {
    if (values.length === 1) return `p.${col} ${negate ? '!==' : '==='} '${values[0]}'`;
    return `${negate ? '!' : ''}${jsList(values)}.includes(p.${col})`;
  };
  if (clause.resources) parts.push(one('resources', clause.resources, 'resource', false));
  if (clause.actions) parts.push(one('actions', clause.actions, 'action', false));
  if (clause.names) parts.push(one('names', clause.names, 'name', false));
  if (clause.except_resources) parts.push(one('x', clause.except_resources, 'resource', true));
  if (clause.except_actions) parts.push(one('x', clause.except_actions, 'action', true));
  if (clause.except_names) parts.push(one('x', clause.except_names, 'name', true));
  return parts.length > 1 ? parts.join(' && ') : parts[0];
}

function jsGrantExpr(role) {
  const g = role.grant;
  const except = g.except_names
    ? (g.except_names.length === 1
      ? `p.name !== '${g.except_names[0]}'`
      : `!${jsList(g.except_names)}.includes(p.name)`)
    : null;
  if (g.all) return except || 'true';
  const clauses = (g.any_of || []).map(jsClause);
  const body = clauses.length === 1 ? clauses[0] : clauses.map((c) => `(${c})`).join(' || ');
  return except ? `(${body}) && ${except}` : body;
}

function emitJs(reg) {
  const entries = reg.roles.map((role) => {
    const note = role.note
      ? role.note.trimEnd().split('\n').map((l) => `  // ${l}`.trimEnd()).join('\n') + '\n'
      : '';
    const expr = jsGrantExpr(role);
    const grants = expr.length > 70
      ? `(p) =>\n      ${expr.replace(/ \|\| /g, ' ||\n      ')}`
      : `(p) => ${expr}`;
    return `${note}  {
    role: '${role.name}',
    displayName: ${JSON.stringify(role.display_name)},
    description: ${JSON.stringify(role.summary)},
    grants: ${grants},
  },`;
  });
  return `// Code generated by scripts/generate-permissions.mjs from
// standards/permissions.yaml. DO NOT EDIT — edit the YAML and run
// \`make generate\`.
//
// Role grant predicates, consumed by scripts/audit-permissions.mjs to compute
// the permission x role matrix. These are the same filters emitted into
// scripts/database/seed.sql and services/auth-service/internal/auth/
// role_grants_gen.go, from the same YAML, so the matrix cannot drift from what
// the database actually grants.
//
// Each predicate takes a parsed { name, resource, action } row and returns true
// iff that role gets the permission.
export const ROLE_GRANTS = [
${entries.join('\n')}
];
`;
}

// ---------------------------------------------------------------------------
// Region splicing
// ---------------------------------------------------------------------------

function spliceRegion(src, marker, body, commentPrefix) {
  const begin = `${commentPrefix} BEGIN GENERATED: ${marker} — from standards/permissions.yaml (make generate)`;
  const end = `${commentPrefix} END GENERATED: ${marker}`;
  const bi = src.indexOf(begin);
  const ei = src.indexOf(end);
  if (bi === -1 || ei === -1 || ei < bi) {
    fail(`region markers for "${marker}" not found (or out of order) — expected:\n  ${begin}\n  ${end}`);
  }
  const head = src.slice(0, bi + begin.length);
  const tail = src.slice(ei);
  return `${head}\n${body}\n${tail}`;
}

// A generated SQL region living inside the DO block is indented; re-indent the
// emitted body to the marker's own indentation.
function indentBody(body, indent) {
  return body
    .split('\n')
    .map((l) => (l.length ? indent + l : l))
    .join('\n');
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

async function main() {
  const checkOnly = process.argv.includes('--check');
  const reg = load();

  // Self-check: prove the SQL and JS emitters agree with the reference
  // evaluator on every (role, permission) pair. A generator that emits two
  // filters with different meanings is exactly the bug this replaces.
  selfCheck(reg);

  const seedPath = path.join(root, 'scripts', 'database', 'seed.sql');
  let seed = fs.readFileSync(seedPath, 'utf8');
  seed = spliceRegion(seed, 'tenant permission catalogue', emitSeedCatalogue(reg), '--');
  seed = spliceRegion(seed, 'system role grant filters', indentBody(emitSeedGrants(reg), '        '), '        --');

  const outputs = [
    [seedPath, seed],
    [path.join(root, 'services', 'auth-service', 'internal', 'auth', 'role_grants_gen.go'), emitGoGrants(reg)],
    [path.join(root, 'shared', 'rbac', 'permissions.go'), spliceRegion(
      fs.readFileSync(path.join(root, 'shared', 'rbac', 'permissions.go'), 'utf8'),
      'tenant permission constants', emitGoConsts(reg), '//')],
    [path.join(root, 'packages', 'primitives', 'src', 'rbac', 'constants.ts'), emitTs(reg)],
    [path.join(root, 'scripts', 'lib', 'role-grants.gen.mjs'), emitJs(reg)],
  ];

  if (checkOnly) {
    const stale = [];
    for (const [p, content] of outputs) {
      const current = fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '';
      if (current !== content) stale.push(path.relative(root, p));
    }
    if (stale.length) {
      fail(`out of date — run \`make generate\`:\n  ${stale.join('\n  ')}`);
    }
    console.log(`permissions check OK (${reg.permissions.length} permissions, ${reg.roles.length} roles, 5 artefacts)`);
    return;
  }

  for (const [p, content] of outputs) {
    await fs.ensureDir(path.dirname(p));
    await fs.writeFile(p, content);
    console.log(`Generated: ${path.relative(root, p)}`);
  }
  console.log(`  ${reg.permissions.length} permissions, ${reg.roles.length} roles`);
}

// Evaluate the emitted JS predicate source and the reference evaluator against
// every permission, for every role, and require agreement. Also asserts the
// SQL grant/revoke predicates partition the catalogue (revoke = NOT grant).
function selfCheck(reg) {
  for (const role of reg.roles) {
    // eslint-disable-next-line no-new-func
    const jsFn = new Function('p', `return (${jsGrantExpr(role)});`);
    for (const p of reg.permissions) {
      const want = grants(role, p);
      const got = jsFn(p);
      if (want !== got) {
        fail(`self-check: JS predicate for role ${role.name} disagrees on ${p.name} (yaml=${want}, js=${got})`);
      }
    }
    const revoke = sqlRevokeExpr(role);
    const grant = sqlGrantExpr(role);
    if (!revoke || !grant) fail(`self-check: empty SQL filter for role ${role.name}`);
    for (const p of reg.permissions) {
      const want = grants(role, p);
      const row = { name: p.name, resource: p.resource, action: p.action, scope: p.scope };
      if (sqlEval(grant, row) !== want) {
        fail(`self-check: SQL grant filter for role ${role.name} disagrees on ${p.name} (yaml=${want})\n  ${grant}`);
      }
      // The reconciliation DELETE must be the exact complement of the INSERT,
      // or a run either strips a granted permission or leaves a stale grant.
      if (sqlEval(revoke, row) !== !want) {
        fail(`self-check: SQL revoke filter for role ${role.name} is not the complement of its grant filter at ${p.name}\n  ${revoke}`);
      }
      // Both are spliced in after the tenant/role scoping and must bind under it.
      for (const [kind, expr] of [['grant', grant], ['revoke', revoke]]) {
        if (!sqlEvalBindsUnderGuard(expr, row)) {
          fail(`self-check: SQL ${kind} filter for role ${role.name} escapes the tenant/role scoping at ${p.name} — an unbracketed top-level OR\n  ${expr}`);
        }
      }
    }
  }
}

main().catch((e) => fail(e.stack || e.message));
