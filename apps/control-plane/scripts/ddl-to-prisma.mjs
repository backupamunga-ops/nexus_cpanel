#!/usr/bin/env node
/**
 * ddl-to-prisma — deterministic generator for apps/control-plane/prisma/schema.prisma
 * from the canonical DDL (specs/nexuspanel-schema-v2.0.sql).
 *
 * Governance (ADR-0004): the DDL is the single source of truth. This generator is
 * the ONLY writer of schema.prisma. The CI drift job regenerates and fails on any
 * diff (npm run prisma:check). Never hand-edit schema.prisma; change the DDL (with
 * an ADR) and regenerate.
 *
 * Deterministic: the output is a pure function of the DDL text. Constructs Prisma
 * cannot express (partial UNIQUE constraints/indexes, GIN operator-class indexes,
 * CHECK constraints) are enforced by the DDL itself and listed in the file header.
 *
 * usage: ddl-to-prisma.mjs <ddl.sql> <schema.prisma>
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const [, , ddlPath, outPath] = process.argv;
if (!ddlPath || !outPath) {
  console.error('usage: ddl-to-prisma.mjs <ddl.sql> <schema.prisma>');
  process.exit(2);
}
const ddl = readFileSync(ddlPath, 'utf8');

// ---------------------------------------------------------------------------
// Lexing: split SQL into statements, honoring line comments, strings, $$ bodies
// ---------------------------------------------------------------------------

function splitStatements(sql) {
  const stmts = [];
  let cur = '';
  let i = 0;
  let inString = false;
  let dollarTag = null;
  while (i < sql.length) {
    const ch = sql[i];
    if (dollarTag) {
      if (sql.startsWith(dollarTag, i)) {
        cur += dollarTag;
        i += dollarTag.length;
        dollarTag = null;
        continue;
      }
      cur += ch;
      i += 1;
      continue;
    }
    if (!inString && sql.startsWith('--', i)) {
      while (i < sql.length && sql[i] !== '\n') i += 1;
      continue;
    }
    if (!inString && ch === "'") {
      inString = true;
      cur += ch;
      i += 1;
      continue;
    }
    if (inString) {
      if (ch === "'") {
        if (sql[i + 1] === "'") { cur += "''"; i += 2; continue; }
        inString = false;
      }
      cur += ch;
      i += 1;
      continue;
    }
    if (ch === '$') {
      const m = /^\$[a-zA-Z_]*\$/.exec(sql.slice(i));
      if (m) {
        dollarTag = m[0];
        cur += m[0];
        i += m[0].length;
        continue;
      }
    }
    if (ch === ';') {
      stmts.push(cur.trim());
      cur = '';
      i += 1;
      continue;
    }
    cur += ch;
    i += 1;
  }
  if (cur.trim()) stmts.push(cur.trim());
  return stmts.filter((s) => s.length > 0);
}

/** Split on top-level commas (paren depth 0, outside strings). */
function splitTopLevel(text, sep = ',') {
  const parts = [];
  let depth = 0;
  let cur = '';
  let inString = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inString) {
      cur += ch;
      if (ch === "'") inString = false;
      continue;
    }
    if (ch === "'") { inString = true; cur += ch; continue; }
    if (ch === '(') depth += 1;
    if (ch === ')') depth -= 1;
    if (ch === sep && depth === 0) { parts.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

/** Index of the next top-level keyword match, or -1. */
function findKeyword(text, keywords) {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inString) { if (ch === "'") inString = false; continue; }
    if (ch === "'") { inString = true; continue; }
    if (ch === '(') depth += 1;
    if (ch === ')') { depth -= 1; continue; }
    if (depth === 0) {
      for (const kw of keywords) {
        const re = new RegExp(`^${kw}\\b`, 'i');
        if (re.test(text.slice(i))) return i;
      }
    }
  }
  return -1;
}

function stripParens(text) {
  const inner = text.trim().replace(/^\(/, '').replace(/\)$/, '').trim();
  return inner;
}

// ---------------------------------------------------------------------------
// Parsing: tables, columns, constraints, indexes
// ---------------------------------------------------------------------------

const tables = new Map(); // name -> { name, columns: [], tableUniques: [], indexes: [], fks: [] }
const deferredFks = [];

function ensureTable(name) {
  if (!tables.has(name)) tables.set(name, { name, columns: [], tableUniques: [], indexes: [], fks: [] });
  return tables.get(name);
}

function parseType(raw) {
  let t = raw.trim().toLowerCase();
  let isArray = false;
  if (t.endsWith('[]')) { isArray = true; t = t.slice(0, -2).trim(); }
  let mods = null;
  const pm = /^([a-z ]+?)\s*\(\s*(\d+)\s*(?:,\s*(\d+))?\s*\)$/.exec(t);
  if (pm) { t = pm[1].trim(); mods = [Number(pm[2]), pm[3] ? Number(pm[3]) : null]; }
  t = t.replace(/\s+/g, ' ');
  if (t === 'int') t = 'integer';
  if (t === 'bool') t = 'boolean';
  if (t === 'character varying') t = 'varchar';
  if (t === 'timestamp with time zone' || t === 'timestamp') t = 'timestamptz';
  return { base: t, mods, isArray };
}

const NATIVE = {
  uuid: (m) => ['String', '@db.Uuid'],
  citext: () => ['String', '@db.Citext'],
  text: () => ['String', null],
  varchar: (m) => ['String', m ? `@db.VarChar(${m[0]})` : null],
  char: (m) => ['String', m ? `@db.Char(${m[0]})` : null],
  boolean: () => ['Boolean', null],
  smallint: () => ['Int', '@db.SmallInt'],
  integer: () => ['Int', null],
  bigint: () => ['BigInt', '@db.BigInt'],
  real: () => ['Float', '@db.Real'],
  'double precision': () => ['Float', '@db.DoublePrecision'],
  numeric: (m) => ['Decimal', m ? `@db.Decimal(${m[0]}, ${m[1] ?? 0})` : null],
  jsonb: () => ['Json', null],
  json: () => ['Json', null],
  bytea: () => ['Bytes', null],
  inet: () => ['String', '@db.Inet'],
  timestamptz: () => ['DateTime', '@db.Timestamptz(6)'],
  date: () => ['DateTime', '@db.Date'],
};

function mapDefault(expr, prismaType) {
  let e = expr.trim();
  // strip trailing casts like '::jsonb', '::text'
  e = e.replace(/::[a-zA-Z_]+(\[\])?(\s|$).*$/, '$1').trim();
  if (/^uuid_generate_v7\s*\(\s*\)$/i.test(e)) return '@default(dbgenerated("uuid_generate_v7()"))';
  if (/^gen_random_uuid\s*\(\s*\)$/i.test(e)) return '@default(dbgenerated("gen_random_uuid()"))';
  if (/^now\s*\(\s*\)$/i.test(e) || /^current_timestamp$/i.test(e)) return '@default(now())';
  if (/^true$/i.test(e)) return '@default(true)';
  if (/^false$/i.test(e)) return '@default(false)';
  if (/^-?\d+(\.\d+)?$/.test(e)) return `@default(${e})`;
  const sm = /^'((?:[^']|'')*)'$/.exec(e);
  if (sm) {
    const val = sm[1].replace(/''/g, "'");
    if (prismaType === 'Json') return `@default("${val.replace(/"/g, '\\"')}")`;
    return `@default("${val.replace(/"/g, '\\"')}")`;
  }
  return `@default(dbgenerated("${e.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"))`;
}

function parseColumn(def) {
  const typeRe = /^(\w+)\s+((?:double\s+precision)|(?:character\s+varying)|[a-z_]+)\s*(\(\s*\d+\s*(?:,\s*\d+)?\s*\))?\s*(\[\])?\s*/i;
  const m = typeRe.exec(def);
  if (!m) throw new Error(`cannot parse column: ${def}`);
  const name = m[1];
  let typeText = m[2];
  if (m[3]) typeText += m[3].replace(/\s+/g, '');
  if (m[4]) typeText += '[]';
  const parsed = parseType(typeText);
  const rest = def.slice(m[0].length).trim();

  const col = {
    name, parsed, notNull: false, unique: false, pk: false,
    defaultExpr: null, fk: null, raw: def,
  };

  let cursor = rest;
  for (;;) {
    cursor = cursor.replace(/^\s+/, '');
    if (cursor.length === 0) break;
    let km;
    if ((km = /^NOT NULL\b/i.exec(cursor))) { col.notNull = true; cursor = cursor.slice(km[0].length); continue; }
    if ((km = /^NULL\b/i.exec(cursor))) { col.notNull = false; cursor = cursor.slice(km[0].length); continue; }
    if ((km = /^UNIQUE\b/i.exec(cursor))) { col.unique = true; cursor = cursor.slice(km[0].length); continue; }
    if ((km = /^PRIMARY KEY\b/i.exec(cursor))) { col.pk = true; cursor = cursor.slice(km[0].length); continue; }
    if ((km = /^DEFAULT\b/i.exec(cursor))) {
      const restText = cursor.slice(km[0].length).replace(/^\s+/, '');
      const stop = findKeyword(restText, ['NOT\\s+NULL', 'NULL', 'UNIQUE', 'PRIMARY\\s+KEY', 'REFERENCES', 'CHECK']);
      const expr = stop === -1 ? restText : restText.slice(0, stop);
      col.defaultExpr = expr.trim();
      cursor = stop === -1 ? '' : restText.slice(stop);
      continue;
    }
    if ((km = /^REFERENCES\s+(\w+)\s*\(\s*(\w+)\s*\)/i.exec(cursor))) {
      col.fk = { refTable: km[1], refCol: km[2], onDelete: null };
      cursor = cursor.slice(km[0].length);
      const od = /^\s*ON DELETE\s+(CASCADE|SET NULL|RESTRICT|NO ACTION)/i.exec(cursor);
      if (od) { col.fk.onDelete = od[1].toUpperCase(); cursor = cursor.slice(od[0].length); }
      continue;
    }
    if ((km = /^CHECK\b/i.exec(cursor))) {
      // skip balanced parens
      let depth = 0; let i = 0;
      for (; i < cursor.length; i += 1) {
        if (cursor[i] === '(') depth += 1;
        if (cursor[i] === ')') { depth -= 1; if (depth === 0) break; }
      }
      cursor = cursor.slice(i + 1);
      continue;
    }
    throw new Error(`cannot parse column modifier at: ${cursor} (column: ${def})`);
  }
  return col;
}

function addFk(tableName, fk) {
  ensureTable(tableName).fks.push(fk);
}

for (const stmt of splitStatements(ddl)) {
  let m;

  if ((m = /^CREATE TABLE\s+(?:IF NOT EXISTS\s+)?([\w.]+)\s*\(([\s\S]*)\)\s*$/.exec(stmt))) {
    const t = ensureTable(m[1]);
    for (const item of splitTopLevel(m[2])) {
      if (/^(UNIQUE|PRIMARY KEY|FOREIGN KEY|CHECK|CONSTRAINT)\b/i.test(item)) {
        const uq = /^UNIQUE\s*\(([\s\S]*?)\)\s*(WHERE[\s\S]*)?$/i.exec(item);
        if (uq) {
          t.tableUniques.push({ cols: uq[1].split(',').map((c) => c.trim()), partial: Boolean(uq[2]) });
          continue;
        }
        const fk = /^FOREIGN KEY\s*\(\s*(\w+)\s*\)\s*REFERENCES\s+(\w+)\s*\(\s*(\w+)\s*\)\s*(?:ON DELETE\s+(CASCADE|SET NULL|RESTRICT|NO ACTION))?/i.exec(item);
        if (fk) { addFk(t.name, { col: fk[1], refTable: fk[2], refCol: fk[3], onDelete: fk[4] ? fk[4].toUpperCase() : null }); continue; }
        // PRIMARY KEY (a, b) / CHECK / CONSTRAINT name ... — tracked minimally
        const tpk = /^PRIMARY KEY\s*\(([\s\S]*?)\)$/i.exec(item);
        if (tpk) { t.compositePk = tpk[1].split(',').map((c) => c.trim()); continue; }
        continue;
      }
      const col = parseColumn(item);
      t.columns.push(col);
      if (col.fk) t.fks.push({ col: col.name, ...col.fk });
    }
    continue;
  }

  if ((m = /^ALTER TABLE\s+([\w.]+)\s+ADD CONSTRAINT\s+\w+\s+FOREIGN KEY\s*\(\s*(\w+)\s*\)\s*REFERENCES\s+([\w.]+)\s*\(\s*(\w+)\s*\)\s*(?:ON DELETE\s+(CASCADE|SET NULL|RESTRICT|NO ACTION))?/is.exec(stmt))) {
    deferredFks.push({ table: m[1], fk: { col: m[2], refTable: m[3], refCol: m[4], onDelete: m[5] ? m[5].toUpperCase() : null } });
    continue;
  }

  if ((m = /^CREATE\s+(UNIQUE\s+)?INDEX\s+(?:IF NOT EXISTS\s+)?(?:\w+\s+)?ON\s+([\w.]+)\s+([\s\S]*)$/is.exec(stmt))) {
    const t = ensureTable(m[2]);
    let rest = m[3].trim();
    let method = 'btree';
    const um = /^USING\s+(\w+)\s*/i.exec(rest);
    if (um) { method = um[1].toLowerCase(); rest = rest.slice(um[0].length); }
    const cm = /^\(([\s\S]*?)\)\s*(WHERE[\s\S]*)?$/i.exec(rest);
    if (!cm) continue;
    const cols = cm[1].split(',').map((c) => c.trim());
    const partial = Boolean(cm[2]);
    t.indexes.push({ cols, method, partial });
    continue;
  }
  // CREATE EXTENSION / FUNCTION / TRIGGER / VIEW / POLICY / etc. — ignored
}
for (const d of deferredFks) addFk(d.table, d.fk);

// ---------------------------------------------------------------------------
// Emitting
// ---------------------------------------------------------------------------

const modelName = (table) =>
  table.split('_').map((w) => {
    if (/ies$/.test(w)) return w.slice(0, -3) + 'y';
    if (/sses$/.test(w)) return w.slice(0, -2);
    if (/s$/.test(w) && !/ss$/.test(w)) return w.slice(0, -1);
    return w;
  }).map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join('');

/** Fixed-width cell that always keeps at least two trailing spaces. */
const cell = (s, n) => s + ' '.repeat(Math.max(2, n - s.length));

// Group FKs: target model gets relation field; source gets back-relation list.
const backRefs = new Map(); // refTable -> [{ fromTable, relName }]
function relationName(fromTable, col) {
  return `${fromTable}.${col}`;
}
for (const t of tables.values()) {
  for (const fk of t.fks) {
    if (!backRefs.has(fk.refTable)) backRefs.set(fk.refTable, []);
    backRefs.get(fk.refTable).push({ fromTable: t.name, col: fk.col, relName: relationName(t.name, fk.col) });
  }
}

const onDeleteMap = (d) =>
  ({ CASCADE: 'Cascade', 'SET NULL': 'SetNull', RESTRICT: 'Restrict', 'NO ACTION': 'NoAction' }[d ?? 'NO ACTION']);

const skipped = { partialUnique: 0, partialIndex: 0, ginIndex: 0, check: 0 };

function columnLines(t) {
  const lines = [];
  for (const c of t.columns) {
    const { base, mods, isArray } = c.parsed;
    const mapper = NATIVE[base];
    if (!mapper) throw new Error(`unmapped type ${base} (column ${t.name}.${c.name})`);
    let [ptype, native] = mapper(mods);
    if (isArray) {
      if (!['String', 'Int', 'BigInt'].includes(ptype)) throw new Error(`unsupported array type ${base} (${t.name}.${c.name})`);
      ptype += '[]';
      native = null; // scalar lists: driver-default mapping
    }
    const attrs = [];
    if (c.pk) attrs.push('@id');
    if (isArray && c.defaultExpr) {
      const stripped = c.defaultExpr.replace(/::[a-zA-Z_]+(\[\])?/g, '').trim();
      attrs.push(stripped === "'{}'" ? '@default([])' : `@default(dbgenerated("${c.defaultExpr.replace(/"/g, '\\"')}"))`);
    } else if (c.defaultExpr) {
      attrs.push(mapDefault(c.defaultExpr, ptype));
    }
    if (c.unique) attrs.push('@unique');
    if (native) attrs.push(native);
    if (!c.notNull && !c.pk && !isArray) ptype += '?';
    lines.push(`  ${cell(c.name, 18)}${cell(ptype, 14)}${attrs.join(' ')}`.trimEnd());
  }
  return lines;
}

function relationLines(t) {
  const lines = [];
  for (const fk of t.fks) {
    const col = t.columns.find((c) => c.name === fk.col);
    if (!col) throw new Error(`FK references unknown column ${t.name}.${fk.col}`);
    const target = modelName(fk.refTable);
    const optional = !col.notNull;
    const relField = fk.col.endsWith('_id') ? fk.col.slice(0, -3) : `${fk.col}_${fk.refTable}`;
    lines.push(`  ${cell(relField, 18)}${cell(optional ? `${target}?` : target, 14)}@relation("${relationName(t.name, fk.col)}", fields: [${fk.col}], references: [id], onDelete: ${onDeleteMap(fk.onDelete)})`);
  }
  return lines;
}

function backRelationLines(t) {
  const refs = backRefs.get(t.name) ?? [];
  return refs.map((r) => `  ${cell(`${r.fromTable}__${r.col}`, 18)}${cell(`${modelName(r.fromTable)}[]`, 14)}@relation("${r.relName}")`);
}

function attrLines(t) {
  const lines = [];
  // Map the Prisma model back to its real (snake_case) table name — without
  // this, the generated client queries e.g. "User" instead of "users".
  lines.push(`  @@map("${t.name}")`);
  if (t.compositePk) lines.push(`  @@id([${t.compositePk.join(', ')}])`);
  for (const u of t.tableUniques) {
    if (u.partial) { skipped.partialUnique += 1; continue; }
    lines.push(`  @@unique([${u.cols.join(', ')}])`);
  }
  for (const ix of t.indexes) {
    if (ix.partial) { skipped.partialIndex += 1; continue; }
    if (ix.method !== 'btree') { skipped.ginIndex += 1; continue; }
    const cols = ix.cols.map((c) => {
      const dm = /^(\w+)\s+DESC$/i.exec(c);
      if (dm) return `${dm[1]}(sort: Desc)`;
      return c;
    });
    lines.push(`  @@index([${cols.join(', ')}])`);
  }
  return lines;
}

const header = `// ============================================================================
// GENERATED FILE — DO NOT EDIT (ADR-0004: the DDL is the single source of truth)
//
//   generator: apps/control-plane/scripts/ddl-to-prisma.mjs
//   source:    specs/nexuspanel-schema-v2.0.sql
//   regenerate: \`npm run prisma:gen\`   ·   drift gate: \`npm run prisma:check\`
//
// Enforced by the DDL itself (not expressible in Prisma, verified in CI):
//   - partial UNIQUE constraints / partial indexes (WHERE ...)
//   - GIN indexes with operator classes (trigram search)
//   - CHECK constraints (incl. the audit_chain_heads singleton guard)
// ============================================================================

generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}
`;

const out = [header];
for (const t of tables.values()) {
  out.push(`model ${modelName(t.name)} {`);
  const body = [...columnLines(t), ...relationLines(t), ...backRelationLines(t), ...attrLines(t)];
  out.push(body.join('\n'));
  out.push('}');
  out.push('');
}
writeFileSync(outPath, out.join('\n'), 'utf8');
process.stdout.write(`ddl-to-prisma: wrote ${outPath} — ${tables.size} models (skipped: ${skipped.partialUnique} partial uniques, ${skipped.partialIndex} partial indexes, ${skipped.ginIndex} gin indexes)\n`);
