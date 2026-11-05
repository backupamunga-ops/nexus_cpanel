#!/usr/bin/env node
/**
 * C6 permission-coverage check (master spec §11.3, security control C6):
 * "CI check that every controller method has a permission decorator."
 *
 * Scans every *.controller.ts (excluding *.spec.ts) under the given root and
 * asserts that each HTTP-route method declares @RequirePermission(...) or
 * @Public(). A route without either fails the build — fail-closed by
 * construction, mirroring the runtime PermissionsGuard.
 *
 * Usage:
 *   node scripts/check-permissions.mjs <src-root>
 *   node scripts/check-permissions.mjs --self-test     (embedded fixtures)
 *
 * Round-1 scope: single-file regex/line analysis of decorator blocks;
 * decorator arguments containing parentheses inside strings are not
 * expected in this codebase and would need a real AST (P3, if controllers
 * grow complex decorator payloads).
 *
 * Vocabulary check (C4/C6): every @RequirePermission literal found in a
 * controller must appear in KNOWN_PERMISSIONS (common/permissions.ts) —
 * API-token scopes are validated against that same set at creation time, so
 * an unlisted permission would be unscopeable and unreachable. The reverse
 * direction (vocabulary entry with no route) is allowed: entries may
 * legitimately precede their endpoints.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const HTTP_DECORATOR = /^@\b(Get|Post|Patch|Put|Delete|Head|Options|All)\b/;
const METHOD_LINE = /^\s*(?:private\s+|protected\s+|public\s+)?(?:async\s+)?[A-Za-z_$][\w$]*\s*\(/;
const PERMISSION_LITERAL = /@RequirePermission\(\s*'([^']+)'\s*\)/g;

/** Strips block and line comments (string-literal-unaware, fine for TS controllers here). */
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
}

/** Returns violation strings for one controller file's source. */
/** Detects class-level @Public/@RequirePermission (applies to every route). */
function classCoverage(lines, classLineIdx) {
  const block = [];
  let j = classLineIdx - 1;
  let blanks = 0;
  while (j >= 0) {
    const t = lines[j].trim();
    if (t === '') {
      blanks += 1;
      if (blanks > 2) break;
      j -= 1;
      continue;
    }
    if (t.startsWith('@')) {
      block.push(t);
      blanks = 0;
      j -= 1;
      continue;
    }
    break;
  }
  const text = block.join('\n');
  if (/@Public\b/.test(text)) return 'public';
  if (/@RequirePermission\b/.test(text)) return 'permission';
  return null;
}

export function checkSource(src, label) {
  const violations = [];
  const lines = stripComments(src).split('\n');
  const classLineIdx = lines.findIndex((l) => /^\s*export\s+(?:abstract\s+)?class\b/.test(l));
  const coveredByClass = classLineIdx >= 0 ? classCoverage(lines, classLineIdx) : null;
  let i = 0;
  while (i < lines.length) {
    if (!HTTP_DECORATOR.test(lines[i].trim())) {
      i += 1;
      continue;
    }
    // Decorator block = decorators ABOVE the HTTP decorator (e.g. @Public,
    // @UseGuards — stopped by the previous method's signature/body) plus the
    // HTTP decorator plus decorators BELOW it, up to the method signature.
    const block = [lines[i]];
    const collect = (from, step) => {
      let j = from;
      let blanks = 0;
      while (j >= 0 && j < lines.length) {
        const t = lines[j].trim();
        if (t === '') {
          blanks += 1;
          if (blanks > 2) break;
          j += step;
          continue;
        }
        if (t.startsWith('@')) {
          block.push(lines[j]);
          blanks = 0;
          j += step;
          continue;
        }
        break;
      }
      return j;
    };
    collect(i - 1, -1);
    const j = collect(i + 1, +1);
    const blockText = block.join('\n');
    const hasOwn = /@RequirePermission\b/.test(blockText) || /@Public\b/.test(blockText);
    if (!hasOwn && coveredByClass === null) {
      const name = (lines[j] ?? '').trim().slice(0, 60) || '<eof>';
      violations.push(`${label}: route ${block[0].trim()} on "${name}" lacks @RequirePermission/@Public`);
    }
    i = j;
  }
  return violations;
}

/** Extracts the string literals of the KNOWN_PERMISSIONS array (or null). */
export function extractVocabulary(permissionsTs) {
  const m = permissionsTs.match(/KNOWN_PERMISSIONS[^=]*=\s*\[([^\]]*)\]/s);
  if (!m) return null;
  const out = [];
  for (const lit of m[1].matchAll(/'([^']+)'/g)) out.push(lit[1]);
  return out.length > 0 ? out : null;
}

/** All @RequirePermission literals appearing in a source file. */
export function extractRequiredPermissions(src) {
  return [...stripComments(src).matchAll(PERMISSION_LITERAL)].map((m) => m[1]);
}

function listControllerFiles(root) {
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir)) {
      const p = join(dir, entry);
      const s = statSync(p);
      if (s.isDirectory()) walk(p);
      else if (entry.endsWith('.controller.ts') && !entry.endsWith('.spec.ts')) out.push(p);
    }
  };
  walk(root);
  return out;
}

function run(root) {
  const files = listControllerFiles(root);
  if (files.length === 0) {
    console.error(`permissions:check: no *.controller.ts found under ${root} — refusing to pass vacuously`);
    process.exit(1);
  }
  const violations = [];
  const vocabulary = extractVocabulary(
    readFileSync(join(root, 'common', 'permissions.ts'), 'utf8'),
  );
  if (!vocabulary) {
    console.error('permissions:check: KNOWN_PERMISSIONS not found in common/permissions.ts');
    process.exit(1);
  }
  const known = new Set(vocabulary);
  for (const file of files) {
    const src = readFileSync(file, 'utf8');
    violations.push(...checkSource(src, file.replace(`${root}/`, '')));
    for (const p of extractRequiredPermissions(src)) {
      if (!known.has(p)) {
        violations.push(
          `${file.replace(`${root}/`, '')}: permission '${p}' is not in KNOWN_PERMISSIONS (common/permissions.ts) — API tokens cannot be scoped to it`,
        );
      }
    }
  }

  // Web vocabulary drift guard: the tokens screen renders scope checkboxes
  // from apps/web/lib/permissions.ts; a stale mirror would offer scopes the
  // server rejects (or hide scopes it accepts). Same-name array works because
  // WEB_KNOWN_PERMISSIONS contains KNOWN_PERMISSIONS as a substring.
  const webVocabPath = join(process.cwd(), '..', 'web', 'lib', 'permissions.ts');
  let webVocabulary = null;
  try {
    webVocabulary = extractVocabulary(readFileSync(webVocabPath, 'utf8'));
  } catch {
    violations.push(`web vocabulary file not found at ${webVocabPath} — refusing to pass vacuously`);
  }
  if (webVocabulary) {
    const drift = diffVocabularies(vocabulary, webVocabulary);
    for (const d of drift) {
      violations.push(`web/lib/permissions.ts: ${d}`);
    }
  }

  if (violations.length > 0) {
    console.error(`permissions:check: ${violations.length} violation(s):`);
    for (const v of violations) console.error('  ✗ ' + v);
    process.exit(1);
  }
  console.log(
    `permissions:check: ${files.length} controller(s), every route decorated, all permissions in vocabulary, web mirror in sync ✓`,
  );
}

/**
 * Set difference between server and web vocabularies, as human-readable
 * drift lines (empty = in lockstep).
 */
export function diffVocabularies(server, web) {
  const out = [];
  for (const p of server) {
    if (!web.includes(p)) out.push(`'${p}' is in KNOWN_PERMISSIONS but missing from the web mirror`);
  }
  for (const p of web) {
    if (!server.includes(p)) out.push(`'${p}' exists only in the web mirror — not a real permission`);
  }
  return out;
}

function selfTest() {
  const good = `
@Controller('demo')
export class DemoController {
  @Get()
  @RequirePermission('demo:list')
  async list() {}

  @Public()
  @Get('open')
  async open() {}

  @Post()
  @HttpCode(204)
  @RequirePermission('demo:create')
  async create() {}
}`;
  const bad = `
@Controller('demo')
export class BadController {
  @Get()
  async undecorated() {}
}`;
  const partial = `
@Controller('demo')
export class PartialController {
  @Get()
  @RequirePermission('demo:list')
  async list() {}

  @Delete(':id')
  async delete(@Param('id') id: string) {}
}`;
  if (checkSource(good, 'good').length !== 0) {
    console.error('self-test FAILED: good fixture flagged');
    process.exit(1);
  }
  if (checkSource(bad, 'bad').length !== 1 || checkSource(partial, 'partial').length !== 1) {
    console.error('self-test FAILED: violating fixtures not caught');
    process.exit(1);
  }
  const vocab = `export const KNOWN_PERMISSIONS: readonly string[] = [
  'demo:list',
  'demo:create',
];`;
  if (JSON.stringify(extractVocabulary(vocab)) !== JSON.stringify(['demo:list', 'demo:create'])) {
    console.error('self-test FAILED: vocabulary extraction broken');
    process.exit(1);
  }
  if (extractRequiredPermissions(good).join(',') !== 'demo:list,demo:create') {
    console.error('self-test FAILED: permission literal extraction broken');
    process.exit(1);
  }
  const unknownPerm = good.replace("'demo:list'", "'demo:typo'");
  const unknown = extractRequiredPermissions(unknownPerm).filter(
    (p) => !['demo:list', 'demo:create'].includes(p),
  );
  if (unknown.length !== 1 || unknown[0] !== 'demo:typo') {
    console.error('self-test FAILED: unknown-permission detection broken');
    process.exit(1);
  }
  const drift1 = diffVocabularies(['a:b', 'c:d'], ['a:b', 'c:d']);
  const drift2 = diffVocabularies(['a:b', 'c:d'], ['a:b']);
  const drift3 = diffVocabularies(['a:b'], ['a:b', 'x:y']);
  if (
    drift1.length !== 0 ||
    drift2.length !== 1 || !drift2[0].includes("'c:d'") ||
    drift3.length !== 1 || !drift3[0].includes("'x:y'")
  ) {
    console.error('self-test FAILED: web vocabulary drift detection broken');
    process.exit(1);
  }
  console.log('permissions:check self-test ✓');
}

const arg = process.argv[2];
if (arg === '--self-test') {
  selfTest();
} else if (arg) {
  run(arg);
} else {
  console.error('usage: check-permissions.mjs <src-root> | --self-test');
  process.exit(2);
}
