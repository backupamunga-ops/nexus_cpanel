import { BadRequestException } from '@nestjs/common';

/**
 * The nginx vhost renderer — the single source of the panel's per-site
 * server blocks. Deterministic and panel-owned: the same domain state always
 * renders the same bytes, which is what makes config_versions history and
 * drift detection meaningful. Per-domain access/error logs are emitted into
 * the account's logs/ directory so the viewer can read them through the
 * confined filesystem.read path.
 *
 * PHP sites: when a phpVersion is passed the block gains `index.php` in the
 * index list plus a fastcgi location pointed at the site's own FPM pool
 * socket (/run/php/php<version>-fpm-<fqdn>.sock — the agent's php.create_pool
 * renderPool owns that name). Callers MUST only pass a version that has a
 * live pool (sites + php flows enforce this); a socket without a pool would
 * 502, and this renderer deliberately does not hide that.
 */

export interface VhostRedirect {
  source_path: string;
  destination_url: string;
  status_code: number;
  is_wildcard: boolean;
}

/** <homedir>/logs — nginx writes the site's logs inside the account home. */
export function logsDirForDocroot(docroot: string): string {
  const m = /^\/home\/([a-z0-9][a-z0-9_-]{0,31})\//.exec(docroot);
  if (!m) {
    throw new BadRequestException('document_root must live under /home/<username>/');
  }
  return `/home/${m[1]}/logs`;
}

export function renderVhost(
  serverName: string,
  docroot: string,
  aliases: string[],
  redirects: VhostRedirect[],
  phpVersion?: string | null,
): string {
  const names = [serverName, `www.${serverName}`, ...aliases].join(' ');
  const logsDir = logsDirForDocroot(docroot);
  const php = typeof phpVersion === 'string' && phpVersion !== '' ? phpVersion : null;
  const lines: string[] = [
    '# managed by nexuspanel — do not edit (drift is reported, not merged)',
    'server {',
    '\tlisten 80;',
    `\tserver_name ${names};`,
    `\troot ${docroot};`,
    php ? '\tindex index.php index.html index.htm;' : '\tindex index.html index.htm;',
    `\taccess_log ${logsDir}/${serverName}.access.log;`,
    `\terror_log ${logsDir}/${serverName}.error.log;`,
    '',
    '\tlocation / {',
    '\t\ttry_files $uri $uri/ =404;',
    '\t}',
  ];
  if (php) {
    lines.push(
      '',
      `\t# php ${php} via the site's own fpm pool (php.create_pool)`,
      '\tlocation ~ \\.php$ {',
      '\t\ttry_files $uri =404;',
      `\t\tfastcgi_pass unix:/run/php/php${php}-fpm-${serverName}.sock;`,
      '\t\tfastcgi_index index.php;',
      '\t\tinclude fastcgi_params;',
      '\t\tfastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;',
      '\t}',
    );
  }
  for (const r of redirects) {
    const match = r.is_wildcard ? `^~ ${r.source_path}` : `= ${r.source_path}`;
    lines.push('', `\t# redirect ${r.source_path} to ${r.destination_url}`);
    lines.push(`\tlocation ${match} {`);
    lines.push(`\t\treturn ${r.status_code} ${r.destination_url};`);
    lines.push('\t}');
  }
  lines.push('}', '');
  return lines.join('\n');
}
