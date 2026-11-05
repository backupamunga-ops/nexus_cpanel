/**
 * cPanel zone-file parser (B15, migration spec §3 "dnszone file → dns zone
 * + records").
 *
 * A cPanel `dnszones/<domain>.db` member is a BIND zone file. We parse the
 * record lines the panel can actually represent (A, AAAA, CNAME, MX, TXT,
 * SRV, CAA, NS — ADR-0012's allowlist) and skip what the nameserver owns
 * (SOA) or what cannot round-trip ($TTL/$ORIGIN directives, RFC 3597
 * unknown-type lines) — every skip is visible in the mapping notes, never
 * silent.
 *
 * The parser is intentionally line-oriented and dependency-free: it joins
 * parenthesized continuations (SOA/TXT/SPF records wrap), strips comments,
 * and defaults TTLs from $TTL.
 */

export interface ParsedZoneRecord {
  name: string;
  type: string;
  /** Content as written (TXT keeps its quotes; MX/SRV carry their numbers). */
  content: string;
  ttl: number | null;
  priority: number | null;
  weight: number | null;
  port: number | null;
}

export interface ParsedZoneFile {
  defaultTtl: number | null;
  records: ParsedZoneRecord[];
  /** Directive/skip notes for the mapping ledger — never silently dropped. */
  skipped: string[];
}

/** Types the panel allowlist supports (shapeRecord re-validates each). */
const SUPPORTED = new Set(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'CAA', 'NS']);

function stripComment(line: string): string {
  // A ';' outside quotes starts a comment.
  let out = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"' && line[i - 1] !== '\\') inQuotes = !inQuotes;
    if (c === ';' && !inQuotes) break;
    out += c;
  }
  return out.trim();
}

/** Joins parenthesized continuation lines: `(...)` spans become one line. */
function logicalLines(text: string): string[] {
  const lines = text.split(/\r?\n/);
  const out: string[] = [];
  let buf = '';
  let depth = 0;
  for (const raw of lines) {
    const line = stripComment(raw);
    if (!line && depth === 0) continue;
    // Count parens outside quotes (zone files never nest inside quotes).
    const opens = (line.match(/\(/g) ?? []).length;
    const closes = (line.match(/\)/g) ?? []).length;
    if (depth === 0) {
      buf = line;
    } else {
      buf += ' ' + line;
    }
    depth += opens - closes;
    if (depth <= 0) {
      depth = 0;
      if (buf.trim()) out.push(buf.trim().replace(/\s*\(\s*/g, ' ( ').replace(/\s*\)\s*/g, ' ) '));
      buf = '';
    }
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}

function tokenToInt(t: string | undefined): number | null {
  if (t === undefined) return null;
  const n = Number(t);
  return Number.isInteger(n) && n >= 0 && n <= 65535 ? n : null;
}

/** TTLs are not priorities: RFC 2181 allows up to 2^31-1. */
function tokenToTtl(t: string | undefined): number | null {
  if (t === undefined) return null;
  const n = Number(t);
  return Number.isInteger(n) && n >= 0 && n <= 2147483647 ? n : null;
}

export function parseZoneFile(text: string): ParsedZoneFile {
  const records: ParsedZoneRecord[] = [];
  const skipped: string[] = [];
  let defaultTtl: number | null = null;
  let lastOwner: string | null = null;

  for (const line of logicalLines(text)) {
    if (/^\$TTL\b/i.test(line)) {
      const v = tokenToTtl(line.split(/\s+/)[1]);
      if (v === null) skipped.push(`unparseable $TTL: ${line.slice(0, 80)}`);
      else defaultTtl = v;
      continue;
    }
    if (/^\$(ORIGIN|INCLUDE|GENERATE)\b/i.test(line)) {
      skipped.push(`directive not imported: ${line.slice(0, 80)}`);
      continue;
    }

    let tokens = line.split(/\s+/);
    // Owner inheritance: a line starting with whitespace repeats the last owner.
    const inherited = /^\s/.test(line);
    if (inherited && lastOwner) tokens = [lastOwner, ...tokens];
    const owner = tokens[0].replace(/^"|"$/g, '');
    if (!owner) continue;
    lastOwner = owner;

    // Scan for TYPE: `owner ttl class type ...` or `owner class type ...`.
    let i = 1;
    let ttl: number | null = null;
    let type: string | null = null;
    while (i < tokens.length) {
      const t = tokens[i].toUpperCase();
      if (t === 'IN' || t === 'CH' || t === 'HS') {
        i++;
        continue;
      }
      if (type === null && SUPPORTED.has(t)) {
        type = t;
        i++;
        break;
      }
      if (ttl === null && /^\d+$/.test(tokens[i])) {
        ttl = Number(tokens[i]);
        i++;
        continue;
      }
      if (type === null && t === 'SOA') {
        skipped.push(`SOA for ${owner} is managed by the nameserver — not imported`);
        type = 'SOA';
        break;
      }
      skipped.push(`unsupported record type "${tokens[i]}" for ${owner} — not imported`);
      type = 'UNSUPPORTED';
      break;
    }
    if (type === null || type === 'SOA' || type === 'UNSUPPORTED') continue;

    const rdata = tokens.slice(i).join(' ').trim();
    if (!rdata) {
      skipped.push(`empty rdata for ${owner} ${type} — not imported`);
      continue;
    }

    if (type === 'MX') {
      // `MX 10 mail.host.` — the priority token moves into `priority`.
      const p = tokenToInt(rdata.split(/\s+/)[0]);
      records.push({
        name: owner,
        type,
        content: rdata.split(/\s+/).slice(1).join(' ') || '.',
        ttl: ttl ?? defaultTtl,
        priority: p,
        weight: null,
        port: null,
      });
      continue;
    }
    if (type === 'SRV') {
      const [p, w, port, ...target] = rdata.split(/\s+/);
      records.push({
        name: owner,
        type,
        content: target.join(' ') || '.',
        ttl: ttl ?? defaultTtl,
        priority: tokenToInt(p),
        weight: tokenToInt(w),
        port: tokenToInt(port),
      });
      continue;
    }
    records.push({ name: owner, type, content: rdata, ttl: ttl ?? defaultTtl, priority: null, weight: null, port: null });
  }
  return { defaultTtl, records, skipped };
}
