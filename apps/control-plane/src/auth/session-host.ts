import { UnauthorizedException } from '@nestjs/common';

/**
 * C14 — Session isolation across reseller domains (security model §C14,
 * ADR-0003). When a reseller serves the panel from `panel.resellerbrand.com`,
 * a session minted there must not be usable from any other host — least of
 * all another reseller's branded domain.
 *
 * Two layers cooperate:
 *
 *   1. Cookie layer (refresh-cookie.ts): the refresh cookie is HOST-ONLY —
 *      no `Domain` attribute — which is exactly "cookie Domain attribute set
 *      to the request's Host". The browser itself never ships reseller A's
 *      cookie to reseller B's origin.
 *   2. Server layer (this module): host-only cookies do not stop a copied
 *      token, so the session row records the Host it was created on
 *      (`user_sessions.bound_host`) and every refresh re-classifies the
 *      request Host against the LIVE set of active reseller custom domains:
 *
 *        - neither host is a custom domain  → allowed (canonical panel hosts,
 *          localhost variants, LAN names — one panel, many names/ports)
 *        - exactly one side is a custom domain → REJECTED (no floating
 *          between the branded origin and the canonical panel)
 *        - both sides custom → allowed only when they are the SAME domain
 *
 *      A session minted on reseller A's domain therefore fails on reseller
 *      B's domain with the refresh path's uniform 401 — no oracle about why.
 *
 * Domain status semantics: only `custom_domain_status = 'active'` domains
 * participate in enforcement. `pending`/`error` domains are not yet served,
 * so binding against them would lock users out of sessions for an outage of
 * the brand's DNS; once a domain activates, sessions minted BEFORE
 * activation remain panel-kind (they stay canonical-only) until the user
 * signs in again on the branded host.
 */

export interface HostClassification {
  kind: 'custom' | 'panel';
  /** The matching custom domain (normalized), when kind = 'custom'. */
  domain?: string;
}

/**
 * Normalizes a Host header value: lowercase, port stripped (IPv4/IPv6 with
 * brackets), trailing dot removed. Returns null for absent/empty values.
 */
export function normalizeHost(raw: string | null | undefined): string | null {
  if (typeof raw !== 'string') return null;
  let host = raw.trim().toLowerCase();
  if (host.length === 0) return null;
  // [::1]:8080 → [::1]; example.com:8443 → example.com
  if (host.startsWith('[')) {
    const end = host.indexOf(']');
    if (end !== -1) host = host.slice(0, end + 1);
  } else {
    const first = host.indexOf(':');
    const last = host.lastIndexOf(':');
    // Exactly one colon separates the port (IPv4/name); more means a bare
    // IPv6 literal, which carries no port.
    if (first !== -1 && first === last) host = host.slice(0, first);
  }
  if (host.endsWith('.')) host = host.slice(0, -1);
  return host.length > 0 ? host : null;
}

/**
 * Classifies a request host against the set of ACTIVE reseller custom
 * domains (already normalized by the caller).
 */
export function classifyHost(
  host: string | null | undefined,
  activeCustomDomains: readonly string[],
): HostClassification {
  const normalized = normalizeHost(host);
  if (!normalized) return { kind: 'panel' };
  if (activeCustomDomains.includes(normalized)) {
    return { kind: 'custom', domain: normalized };
  }
  return { kind: 'panel' };
}

/**
 * The C14 refresh gate. Throws the refresh path's uniform 401 when the
 * session's bound host and the presenting request's host cross a reseller
 * domain boundary (see module doc for the exact rule).
 */
export function assertSessionHostAllowed(
  boundHost: string | null | undefined,
  requestHost: string | null | undefined,
  activeCustomDomains: readonly string[],
): void {
  const bound = classifyHost(boundHost, activeCustomDomains);
  const request = classifyHost(requestHost, activeCustomDomains);
  if (bound.kind === 'panel' && request.kind === 'panel') {
    return; // canonical panel hosts interoperate freely
  }
  if (
    bound.kind === 'custom' &&
    request.kind === 'custom' &&
    bound.domain === request.domain
  ) {
    return; // same branded origin
  }
  throw new UnauthorizedException('invalid refresh token');
}
