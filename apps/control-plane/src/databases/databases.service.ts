import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { createHmac, randomBytes, scryptSync } from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAppender, InjectAudit } from '../audit/audit.service';
import { AgentClientService } from '../agent/agent-client.service';
import { getSecretBox } from '../common/secretbox';
import { Actor } from '../sites/sites.service';

/**
 * Databases (API spec §4.10) — MariaDB 11 only, ADR-0001/0015.
 *
 *   - the agent is the only writer of node state (unix-socket admin via the
 *     DatabaseEngineAdapter seam); the panel owns the registry
 *     (`databases`, DDL-first);
 *   - provisioning is agent-first: a failed agent call leaves NO row;
 *   - the credential is stored as a SecretBox envelope (ADR-0009/0015) in
 *     `db_password_hash` — decrypt only at point of use (connection-string
 *     generator + reveal), never in audit payloads, never sent back to the
 *     agent (MariaDB keeps its own hash after CREATE USER);
 *   - least privilege by default: one database, one user, ALL on db.*,
 *     localhost unless an explicit host is given;
 *   - engine lock: 'mariadb' only — mysql/postgres are rejected honestly
 *     (planned, not silent aliases);
 *   - phpMyAdmin/Adminer SSO issues an HMAC-signed 60s token (session-only);
 *     the consumer plugin ships with the app installer (B14) — stated
 *     honestly, no dead links.
 *
 * Ownership boundary (C7): every route resolves the owning account and
 * 404s for invisible resources (§3.2 anti-enumeration).
 */

const DB_NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;
const DB_USER_RE = /^[a-z][a-z0-9_]{0,31}$/;
const DB_HOST_RE = /^[a-zA-Z0-9._-]{1,253}$/;
const SSO_TTL_MS = 60_000;

export interface DatabaseDto {
  id: string;
  hosting_account_id: string;
  account_username: string;
  engine: string;
  name: string;
  db_user: string;
  size_mb: number;
  created_at: string;
}

export interface DatabaseUserDto {
  user: string;
  host: string;
  /** v1.0 provisions exactly one grant per database (ADR-0015). */
  privileges: string;
}

export interface SsoTokenDto {
  url: string;
  token: string;
  expires_at: string;
  /** Honest consumer note — the Adminer/phpMyAdmin plugin ships with B14. */
  consumer: string;
}

interface AccountRow {
  id: string;
  username: string;
  homedir: string;
  package_id: string | null;
}

@Injectable()
export class DatabasesService {
  private readonly logger = new Logger(DatabasesService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly agent: AgentClientService,
    @InjectAudit() private readonly audit: AuditAppender,
  ) {}

  // ---- ownership (C7) ---------------------------------------------------------

  private async requireAccount(actor: Actor | undefined, accountId: unknown): Promise<AccountRow> {
    if (typeof accountId !== 'string' || !/^[0-9a-f-]{36}$/i.test(accountId)) {
      throw new BadRequestException('account_id is required');
    }
    const account = await this.prisma.hostingAccount.findFirst({
      where: { id: accountId, deleted_at: null },
      select: { id: true, username: true, homedir: true, package_id: true },
    });
    if (!account) throw new NotFoundException('hosting account not found');
    if (!actor?.isSuperAdmin) {
      if (!actor?.userId) throw new NotFoundException('hosting account not found');
      const access = await this.prisma.userHostingAccountAccess.findFirst({
        where: { user_id: actor.userId, hosting_account_id: account.id, revoked_at: null },
        select: { id: true },
      });
      if (!access) throw new NotFoundException('hosting account not found');
    }
    return account;
  }

  private async requireVisibleDatabase(id: string, actor?: Actor) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      throw new NotFoundException('database not found');
    }
    const row = await this.prisma.database.findFirst({
      where: { id, deleted_at: null },
      include: { hosting_account: { select: { id: true, username: true, homedir: true, package_id: true } } },
    });
    if (!row) throw new NotFoundException('database not found');
    if (!actor?.isSuperAdmin) {
      if (!actor?.userId) throw new NotFoundException('database not found');
      const access = await this.prisma.userHostingAccountAccess.findFirst({
        where: { user_id: actor.userId, hosting_account_id: row.hosting_account_id, revoked_at: null },
        select: { id: true },
      });
      if (!access) throw new NotFoundException('database not found');
    }
    return row;
  }

  // ---- package limits -----------------------------------------------------------

  private async dbPolicyOf(account: AccountRow): Promise<{ maxDbs: number | null; maxSizeMb: number | null }> {
    if (!account.package_id) return { maxDbs: null, maxSizeMb: null };
    const pkg = await this.prisma.package.findFirst({
      where: { id: account.package_id, deleted_at: null },
      select: { quotas: true },
    });
    const quotas = (pkg?.quotas ?? {}) as Record<string, unknown>;
    return {
      maxDbs: typeof quotas['db_count'] === 'number' ? quotas['db_count'] : null,
      maxSizeMb: typeof quotas['db_size_mb'] === 'number' ? quotas['db_size_mb'] : null,
    };
  }

  // ---- CRUD -----------------------------------------------------------------------

  async list(actor: Actor | undefined, accountId: unknown): Promise<{ data: DatabaseDto[] }> {
    const account = await this.requireAccount(actor, accountId);
    const rows = await this.prisma.database.findMany({
      where: { hosting_account_id: account.id, deleted_at: null },
      orderBy: { created_at: 'asc' },
      include: { hosting_account: { select: { username: true } } },
    });
    return { data: rows.map(toDto) };
  }

  async create(
    actor: Actor | undefined,
    input: {
      account_id?: unknown;
      engine?: unknown;
      name?: unknown;
      db_user?: unknown;
      password?: unknown;
      host?: unknown;
    },
  ): Promise<DatabaseDto> {
    const account = await this.requireAccount(actor, input.account_id);

    const engine =
      input.engine === undefined || input.engine === null
        ? 'mariadb' // default when omitted (UI sends mariadb explicitly too)
        : String(input.engine).trim().toLowerCase();
    if (engine !== 'mariadb') {
      // Honest engine lock (ADR-0001): no silent aliasing to MariaDB.
      throw new BadRequestException(
        `engine must be 'mariadb' — v1.0 is MariaDB-only (ADR-0001); '${engine || 'empty'}' is planned for v1.2, not silently aliased`,
      );
    }
    const name = typeof input.name === 'string' ? input.name.trim().toLowerCase() : '';
    if (!DB_NAME_RE.test(name)) {
      throw new BadRequestException('database name must start with a letter: lowercase letters, digits, underscore (max 64)');
    }
    const defaultUser = `${account.username.slice(0, 16)}_${name.slice(0, 15)}`.replace(/[^a-z0-9_]/g, '_').slice(0, 32);
    const dbUser = typeof input.db_user === 'string' && input.db_user.trim() !== '' ? input.db_user.trim().toLowerCase() : defaultUser;
    if (!DB_USER_RE.test(dbUser)) {
      throw new BadRequestException('db_user must start with a letter: lowercase letters, digits, underscore (max 32)');
    }
    const host = typeof input.host === 'string' && input.host.trim() !== '' ? input.host.trim() : 'localhost';
    if (!DB_HOST_RE.test(host)) {
      throw new BadRequestException('host must be a hostname, IP or localhost');
    }
    const password = typeof input.password === 'string' && input.password !== '' ? input.password : generatePassword();
    if (password.length < 8 || password.length > 1024 || password.includes('\0')) {
      throw new BadRequestException('password must be 8-1024 bytes without NUL');
    }

    const dup = await this.prisma.database.findFirst({
      where: { engine, name, deleted_at: null },
      select: { id: true },
    });
    if (dup) throw new ConflictException('this database name already exists on the engine');

    const policy = await this.dbPolicyOf(account);
    if (policy.maxDbs !== null) {
      const count = await this.prisma.database.count({ where: { hosting_account_id: account.id, deleted_at: null } });
      if (count >= policy.maxDbs) {
        throw new ConflictException(`this package caps the account at ${policy.maxDbs} databases`);
      }
    }

    let agentResult: Awaited<ReturnType<AgentClientService['databaseCreate']>>;
    try {
      agentResult = await this.agent.databaseCreate({
        engine,
        name,
        user: dbUser,
        password,
        host,
        owner_username: account.username,
      });
    } catch (e) {
      await this.audit.append({
        operation: 'database.create',
        parameters: { account_id: account.id, engine, name, user: dbUser, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      throw e;
    }

    const credentialsEnc = Buffer.from(getSecretBox().encrypt(password), 'utf8');
    const row = await this.prisma.$transaction(async (tx) => {
      const created = await tx.database.create({
        data: {
          hosting_account_id: account.id,
          engine,
          name,
          db_user: dbUser,
          db_password_hash: credentialsEnc,
          size_mb: 0,
        },
        include: { hosting_account: { select: { username: true } } },
      });
      await this.audit.appendWithClient(tx, {
        operation: 'database.create',
        parameters: {
          database_id: created.id,
          engine,
          name,
          user: dbUser,
          host,
          // ADR-0015: a credential fingerprint, never the material itself.
          credential_fingerprint: fingerprintOf(password),
        },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: account.id,
      });
      return created;
    });
    return toDto(row);
  }

  async remove(actor: Actor | undefined, id: string, input: { drop_user?: unknown }): Promise<void> {
    const row = await this.requireVisibleDatabase(id, actor);
    const dropUser = input.drop_user !== false; // default: tear the user down too
    try {
      await this.agent.databaseDelete(
        row.engine,
        row.name,
        dropUser ? row.db_user : undefined,
        'localhost',
      );
    } catch (e) {
      await this.audit.append({
        operation: 'database.delete',
        parameters: { database_id: row.id, name: row.name, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
      throw e;
    }
    await this.prisma.$transaction(async (tx) => {
      await tx.database.update({ where: { id: row.id }, data: { deleted_at: new Date() } });
      await this.audit.appendWithClient(tx, {
        operation: 'database.delete',
        parameters: { database_id: row.id, name: row.name, user: dropUser ? row.db_user : null },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
    });
    this.logger.log(`database ${row.name} of ${row.hosting_account.username} removed`);
  }

  // ---- users / grants ----------------------------------------------------------------

  async listUsers(actor: Actor | undefined, id: string): Promise<{ data: DatabaseUserDto[] }> {
    const row = await this.requireVisibleDatabase(id, actor);
    return {
      data: [{ user: row.db_user, host: 'localhost', privileges: 'ALL PRIVILEGES' }],
    };
  }

  async createUser(
    actor: Actor | undefined,
    id: string,
    input: { user?: unknown; password?: unknown; host?: unknown },
  ): Promise<DatabaseUserDto> {
    const row = await this.requireVisibleDatabase(id, actor);
    const user = typeof input.user === 'string' ? input.user.trim().toLowerCase() : '';
    if (!DB_USER_RE.test(user)) {
      throw new BadRequestException('user must start with a letter: lowercase letters, digits, underscore (max 32)');
    }
    const host = typeof input.host === 'string' && input.host.trim() !== '' ? input.host.trim() : 'localhost';
    if (!DB_HOST_RE.test(host)) {
      throw new BadRequestException('host must be a hostname, IP or localhost');
    }
    const password = typeof input.password === 'string' && input.password !== '' ? input.password : generatePassword();
    if (password.length < 8 || password.length > 1024 || password.includes('\0')) {
      throw new BadRequestException('password must be 8-1024 bytes without NUL');
    }
    try {
      await this.agent.databaseCreate({
        engine: row.engine,
        // create with an existing database name is idempotent on the DB;
        // the agent creates the user + grant without dropping anything.
        name: row.name,
        user,
        password,
        host,
        owner_username: row.hosting_account.username,
      });
    } catch (e) {
      await this.audit.append({
        operation: 'database.user.create',
        parameters: { database_id: row.id, user, host, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
      throw e;
    }
    await this.audit.append({
      operation: 'database.user.create',
      parameters: { database_id: row.id, user, host, credential_fingerprint: fingerprintOf(password) },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: row.hosting_account_id,
    });
    return { user, host, privileges: 'ALL PRIVILEGES' };
  }

  async deleteUser(actor: Actor | undefined, id: string, user: string, host = 'localhost'): Promise<void> {
    const row = await this.requireVisibleDatabase(id, actor);
    if (!DB_USER_RE.test(user)) {
      throw new NotFoundException('database user not found');
    }
    if (user === row.db_user && host === 'localhost') {
      throw new ConflictException('this is the database primary user — delete the database instead');
    }
    try {
      await this.agent.databaseDelete(row.engine, row.name, user, host);
    } catch (e) {
      await this.audit.append({
        operation: 'database.user.delete',
        parameters: { database_id: row.id, user, host, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
      throw e;
    }
    await this.audit.append({
      operation: 'database.user.delete',
      parameters: { database_id: row.id, user, host },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: row.hosting_account_id,
    });
  }

  // ---- size / dump / restore ------------------------------------------------------------

  /** Live size from information_schema; caches the last reading on the row. */
  async refreshSize(actor: Actor | undefined, id: string): Promise<DatabaseDto> {
    const row = await this.requireVisibleDatabase(id, actor);
    let sizeMb = 0;
    try {
      const res = await this.agent.databaseSize(row.engine, row.name);
      sizeMb = res.size_mb;
    } catch (e) {
      await this.audit.append({
        operation: 'database.size',
        parameters: { database_id: row.id, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
      throw e;
    }
    const policy = await this.dbPolicyOf(row.hosting_account as AccountRow);
    if (policy.maxSizeMb !== null && sizeMb > policy.maxSizeMb) {
      this.logger.warn(
        `database ${row.name} of ${row.hosting_account.username} is ${sizeMb} MB — package cap is ${policy.maxSizeMb} MB (over_quota_policy governs the response, B13 alerting pending)`,
      );
    }
    const updated = await this.prisma.$transaction(async (tx) => {
      const u = await tx.database.update({ where: { id: row.id }, data: { size_mb: sizeMb } });
      await this.audit.appendWithClient(tx, {
        operation: 'database.size',
        parameters: { database_id: row.id, size_mb: sizeMb },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
      return u;
    });
    return toDto(updated);
  }

  /** Operator tool: dump confined under the account's own home (C13). */
  async dump(actor: Actor | undefined, id: string, input: { output_path?: unknown }) {
    const row = await this.requireVisibleDatabase(id, actor);
    const rawPath = typeof input.output_path === 'string' && input.output_path.trim() !== '' ? input.output_path.trim() : `backups/${row.name}-${Date.now()}.sql`;
    if (rawPath.includes('..') || rawPath.includes('\0')) {
      throw new BadRequestException('output_path must stay inside the account home');
    }
    try {
      const res = await this.agent.databaseDump(row.engine, row.name, rawPath, row.hosting_account.username);
      await this.audit.append({
        operation: 'database.dump',
        parameters: { database_id: row.id, output: res.output },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
      return { status: res.status, output_path: res.output };
    } catch (e) {
      await this.audit.append({
        operation: 'database.dump',
        parameters: { database_id: row.id, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
      throw e;
    }
  }

  /** Operator tool: restore from a dump inside the account's own home. */
  async restore(actor: Actor | undefined, id: string, input: { input_path?: unknown }) {
    const row = await this.requireVisibleDatabase(id, actor);
    const rawPath = typeof input.input_path === 'string' ? input.input_path.trim() : '';
    if (!rawPath || rawPath.includes('..') || rawPath.includes('\0')) {
      throw new BadRequestException('input_path must name a dump inside the account home');
    }
    try {
      const res = await this.agent.databaseRestore(row.engine, row.name, rawPath, row.hosting_account.username);
      await this.audit.append({
        operation: 'database.restore',
        parameters: { database_id: row.id, input: rawPath },
        outcome: 'success',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
      return { status: res.status };
    } catch (e) {
      await this.audit.append({
        operation: 'database.restore',
        parameters: { database_id: row.id, error: (e as Error).message },
        outcome: 'failure',
        actorUserId: actor?.userId ?? null,
        hostingAccountId: row.hosting_account_id,
      });
      throw e;
    }
  }

  // ---- connection string + reveal + SSO -------------------------------------------------

  /** Connection string generator: decrypts at point of use, audit carries a fingerprint only. */
  async connectionString(actor: Actor | undefined, id: string): Promise<{ connection_string: string; note: string }> {
    const row = await this.requireVisibleDatabase(id, actor);
    const password = this.decryptCredential(row.db_password_hash);
    await this.auditFingerprinted('database.connection_string', row, actor);
    return {
      connection_string: `mysql://${row.db_user}:${encodeURIComponent(password)}@localhost:3306/${row.name}`,
      note: 'The credential was decrypted at point of use only; the audit trail carries a fingerprint, not the secret.',
    };
  }

  /** Session-only reveal (C6 SessionOnly at the controller). */
  async revealPassword(actor: Actor | undefined, id: string): Promise<{ password: string }> {
    const row = await this.requireVisibleDatabase(id, actor);
    const password = this.decryptCredential(row.db_password_hash);
    await this.auditFingerprinted('database.reveal', row, actor);
    return { password };
  }

  private decryptCredential(envelope: Uint8Array | Buffer | null): string {
    if (!envelope) throw new NotFoundException('database credential not found');
    const enc = Buffer.from(envelope).toString('utf8');
    try {
      return getSecretBox().decrypt(enc);
    } catch (e) {
      throw new Error(`credential decryption failed (wrong PANEL_SECRET_KEY?): ${(e as Error).message}`);
    }
  }

  private async auditFingerprinted(operation: string, row: { id: string; name: string; db_user: string; hosting_account_id: string }, actor?: Actor) {
    await this.audit.append({
      operation,
      parameters: { database_id: row.id, name: row.name, user: row.db_user, material: 'fingerprint-only (ADR-0015)' },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: row.hosting_account_id,
    });
  }

  /** Signed short-TTL SSO token (ADR-0015). Consumer ships with B14. */
  async phpmyadminSso(actor: Actor | undefined, id: string): Promise<SsoTokenDto> {
    const row = await this.requireVisibleDatabase(id, actor);
    const expires = new Date(Date.now() + SSO_TTL_MS);
    const nonce = randomBytes(8).toString('hex');
    const payload = `db=${row.id};user=${row.db_user};exp=${expires.getTime()};n=${nonce}`;
    const token = `${Buffer.from(payload).toString('base64url')}.${createHmac('sha256', ssoHmacKey()).update(payload).digest('base64url')}`;
    await this.audit.append({
      operation: 'database.sso.issue',
      parameters: { database_id: row.id, expires_at: expires.toISOString() },
      outcome: 'success',
      actorUserId: actor?.userId ?? null,
      hostingAccountId: row.hosting_account_id,
    });
    return {
      url: `/phpmyadmin/sso?token=${token}`,
      token,
      expires_at: expires.toISOString(),
      consumer: 'token issued — the Adminer/phpMyAdmin SSO plugin ships with the app installer (B14); until then this URL has no consumer, stated honestly',
    };
  }
}

function toDto(row: {
  id: string;
  hosting_account_id: string;
  engine: string;
  name: string;
  db_user: string;
  size_mb: number;
  created_at: Date;
  hosting_account?: { username: string } | null;
}): DatabaseDto {
  return {
    id: row.id,
    hosting_account_id: row.hosting_account_id,
    account_username: row.hosting_account?.username ?? '',
    engine: row.engine,
    name: row.name,
    db_user: row.db_user,
    size_mb: row.size_mb,
    created_at: row.created_at.toISOString(),
  };
}

function fingerprintOf(secret: string): string {
  return createHmac('sha256', 'nexuspanel-cred-fingerprint').update(secret).digest('hex').slice(0, 16);
}

/** HMAC key for SSO tokens — derived from PANEL_SECRET_KEY with a distinct
 *  app salt (fail-closed like SecretBox: no key, no tokens). */
function ssoHmacKey(): Buffer {
  const key = process.env.PANEL_SECRET_KEY;
  if (!key) {
    throw new Error('PANEL_SECRET_KEY is not set — refusing to issue SSO tokens');
  }
  return scryptSync(key, 'nexuspanel:sso-hmac:v1', 32);
}

function generatePassword(): string {
  // 24 chars from an unambiguous alphabet; generated server-side when the
  // caller omits a password (the UI shows it once on the receipt).
  const alphabet = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const bytes = randomBytes(24);
  let out = '';
  for (const b of bytes) out += alphabet[b % alphabet.length];
  return out;
}
