import { Injectable, Logger } from '@nestjs/common';
import { BadRequestException } from '@nestjs/common';
import { AgentClientService } from '../agent/agent-client.service';
import { AuditService } from '../audit/audit.service';

/**
 * Hosting account lifecycle — M0 slice of API spec §4.4.
 * Privileged actions flow: validate → agent command → audit append.
 * Persistence to `hosting_accounts` (schema v2.0) lands with Prisma in P1;
 * the M0 store is process-memory, seeded by the agent's own account.list.
 */
export interface ManagedAccount {
  username: string;
  package_id: string;
  status: 'active' | 'suspended';
  uid?: number;
  gid?: number;
  homedir?: string;
}

const USERNAME_RE = /^[a-z][a-z0-9-]{0,31}$/;
const RESERVED = new Set([
  'root', 'daemon', 'bin', 'sys', 'adm', 'nobody', 'sshd', 'www-data',
  'postgres', 'nexusagent', 'nexuspanel', 'ubuntu', 'debian',
]);

@Injectable()
export class AccountsService {
  private readonly logger = new Logger(AccountsService.name);
  private readonly accounts = new Map<string, ManagedAccount>();

  constructor(
    private readonly agent: AgentClientService,
    private readonly audit: AuditService,
  ) {}

  list(): { data: ManagedAccount[] } {
    return { data: [...this.accounts.values()] };
  }

  async create(username: string, packageId: string, actorUserId?: string): Promise<ManagedAccount> {
    if (!USERNAME_RE.test(username) || RESERVED.has(username)) {
      throw new BadRequestException('username violates policy');
    }
    if (this.accounts.has(username)) {
      throw new BadRequestException('account exists');
    }
    const result = await this.agent.accountCreate(username, packageId);
    const account: ManagedAccount = {
      username,
      package_id: packageId,
      status: 'active',
      uid: result.uid,
      gid: result.gid,
      homedir: result.homedir,
    };
    this.accounts.set(username, account);
    this.audit.append('account.create', { username, package_id: packageId }, 'success', actorUserId ?? null);
    this.logger.log(`created hosting account ${username} (uid ${result.uid})`);
    return account;
  }

  async suspend(username: string, actorUserId?: string): Promise<ManagedAccount> {
    const account = this.requireAccount(username);
    await this.agent.accountSuspend(username);
    account.status = 'suspended';
    this.audit.append('account.suspend', { username }, 'success', actorUserId ?? null);
    return account;
  }

  /** Soft-removes the account from the panel and deletes the OS user via the agent. */
  async remove(username: string, actorUserId?: string): Promise<void> {
    this.requireAccount(username);
    await this.agent.accountDelete(username);
    this.accounts.delete(username);
    this.audit.append('account.delete', { username }, 'success', actorUserId ?? null);
    this.logger.log(`deleted hosting account ${username}`);
  }

  async usage(username: string): Promise<Record<string, number | string>> {
    this.requireAccount(username);
    return this.agent.accountUsage(username);
  }

  private requireAccount(username: string): ManagedAccount {
    const account = this.accounts.get(username);
    if (!account) {
      throw new BadRequestException('account not found');
    }
    return account;
  }
}
