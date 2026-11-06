import {
  EXTENSION_SCOPES,
  EXTENSION_TYPES,
  SEMVER_RE,
  isCompatible,
  PANEL_CONTRACT_VERSION,
} from './extension-scopes';

/**
 * Extension manifest validation (SDK spec §4) — fail-closed.
 *
 * The manifest is the extension's whole identity: what it is, which types it
 * claims, which scopes it requests and which endpoints the panel may call.
 * Every rule here is normative; the panel refuses to even REGISTER an
 * extension that fails any of them, so a malformed manifest can never sit
 * half-trusted in the database waiting for someone to enable it.
 */

export interface ExtensionManifest {
  name: string;
  slug: string;
  version: string;
  author?: string;
  description?: string;
  license?: string;
  homepage?: string;
  nexuspanel_compat: { min: string; max: string };
  types: string[];
  permissions: string[];
  endpoints: {
    register?: string;
    heartbeat?: string;
    widgets?: Record<string, { slot: string; entry: string }>;
    hooks?: Record<string, string>;
  };
  ui?: { settings_url?: string };
  storage?: { type: string; name: string };
}

export interface ValidatedManifest {
  manifest: ExtensionManifest;
  /** Human-readable problems; empty means valid. */
  problems: string[];
}

const SLUG_RE = /^[a-z0-9][a-z0-9-]{2,63}$/;
const PATH_RE = /^\/[A-Za-z0-9._~\-/]*$/;
const SLOT_RE = /^[a-z0-9]+(\.[a-z0-9_-]+)+$/; // e.g. dashboard.main
const HOOK_RE = /^[a-z0-9_]+(\.[a-z0-9_]+)+$/; // e.g. backup.completed

/** Pull `url` apart; return its origin (`https://host[:port]`) or null. */
export function originOf(url: string): string | null {
  try {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u.origin;
  } catch {
    return null;
  }
}

/**
 * Validate an unknown JSON blob as an extension manifest. Returns ALL
 * problems (not just the first) so a developer sees the full list at once.
 */
export function validateManifest(raw: unknown): ValidatedManifest {
  const problems: string[] = [];
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return { manifest: null as unknown as ExtensionManifest, problems: ['manifest must be a JSON object'] };
  }
  const m = raw as Record<string, unknown>;

  const name = typeof m.name === 'string' ? m.name.trim() : '';
  if (!name || name.length > 120) problems.push('name is required (1-120 chars)');

  const slug = typeof m.slug === 'string' ? m.slug : '';
  if (!SLUG_RE.test(slug)) {
    problems.push(`slug "${slug}" must match ${SLUG_RE.source} (3-64 chars, lowercase, digits, hyphens)`);
  }

  const version = typeof m.version === 'string' ? m.version : '';
  if (!SEMVER_RE.test(version)) problems.push(`version "${version}" must be semver (MAJOR.MINOR.PATCH)`);

  const compat = m.nexuspanel_compat;
  if (typeof compat !== 'object' || compat === null) {
    problems.push('nexuspanel_compat {min,max} is required');
  } else if (!isCompatible(PANEL_CONTRACT_VERSION, compat as { min?: unknown; max?: unknown })) {
    problems.push(
      `nexuspanel_compat window does not include this panel's contract version ${PANEL_CONTRACT_VERSION}`,
    );
  }

  const types = Array.isArray(m.types) ? m.types.map(String) : [];
  if (types.length === 0) problems.push('declare at least one type');
  for (const t of types) {
    if (!EXTENSION_TYPES.includes(t)) problems.push(`unknown type "${t}" (allowed: ${EXTENSION_TYPES.join(', ')})`);
  }

  const permissions = Array.isArray(m.permissions) ? m.permissions.map(String) : [];
  for (const p of permissions) {
    if (!EXTENSION_SCOPES[p]) problems.push(`unknown permission scope "${p}" — extensions may only request from the closed list (SDK spec §6)`);
  }
  if (new Set(permissions).size !== permissions.length) {
    problems.push('duplicate permission scopes in manifest');
  }

  // ---- endpoints -----------------------------------------------------------
  const ep = (typeof m.endpoints === 'object' && m.endpoints !== null ? m.endpoints : {}) as Record<string, unknown>;
  const endpoints: ExtensionManifest['endpoints'] = {};
  for (const key of ['register', 'heartbeat'] as const) {
    const v = ep[key];
    if (v !== undefined) {
      if (typeof v !== 'string' || !PATH_RE.test(v)) {
        problems.push(`endpoints.${key} must be a path starting with "/"`);
      } else {
        endpoints[key] = v;
      }
    }
  }
  const widgetsRaw = ep.widgets;
  const widgets: Record<string, { slot: string; entry: string }> = {};
  if (widgetsRaw !== undefined) {
    if (typeof widgetsRaw !== 'object' || widgetsRaw === null) {
      problems.push('endpoints.widgets must be an object of {id: {slot, entry}}');
    } else {
      for (const [id, w] of Object.entries(widgetsRaw as Record<string, unknown>)) {
        if (typeof w !== 'object' || w === null) {
          problems.push(`endpoints.widgets.${id} must be {slot, entry}`);
          continue;
        }
        const slot = (w as Record<string, unknown>).slot;
        const entry = (w as Record<string, unknown>).entry;
        if (typeof slot !== 'string' || !SLOT_RE.test(slot)) {
          problems.push(`endpoints.widgets.${id}.slot "${slot}" must look like "dashboard.main"`);
        }
        if (typeof entry !== 'string' || !PATH_RE.test(entry)) {
          problems.push(`endpoints.widgets.${id}.entry must be a path starting with "/"`);
        }
        if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(id)) problems.push(`widget id "${id}" must be kebab-case`);
        if (typeof slot === 'string' && typeof entry === 'string') widgets[id] = { slot, entry };
      }
    }
  }
  endpoints.widgets = widgets;

  const hooksRaw = ep.hooks;
  const hooks: Record<string, string> = {};
  if (hooksRaw !== undefined) {
    if (typeof hooksRaw !== 'object' || hooksRaw === null) {
      problems.push('endpoints.hooks must be an object of {event: path}');
    } else {
      for (const [event, path] of Object.entries(hooksRaw as Record<string, unknown>)) {
        if (!HOOK_RE.test(event)) problems.push(`hook event "${event}" must look like "backup.completed"`);
        if (typeof path !== 'string' || !PATH_RE.test(path)) {
          problems.push(`endpoints.hooks.${event} must be a path starting with "/"`);
        } else {
          hooks[event] = path;
        }
      }
    }
  }
  endpoints.hooks = hooks;

  const uiRaw = m.ui;
  if (uiRaw !== undefined) {
    if (typeof uiRaw !== 'object' || uiRaw === null) {
      problems.push('ui must be an object');
    } else {
      const settings = (uiRaw as Record<string, unknown>).settings_url;
      if (settings !== undefined && (typeof settings !== 'string' || !PATH_RE.test(settings))) {
        problems.push('ui.settings_url must be a path starting with "/"');
      }
    }
  }

  const storageRaw = m.storage;
  if (storageRaw !== undefined) {
    if (typeof storageRaw !== 'object' || storageRaw === null) {
      problems.push('storage must be {type, name}');
    } else {
      const s = storageRaw as Record<string, unknown>;
      if (s.type !== 'postgres_namespace') problems.push('storage.type must be "postgres_namespace"');
      if (typeof s.name !== 'string' || !SLUG_RE.test(s.name)) {
        problems.push('storage.name must match the slug rules (3-64 chars, lowercase)');
      }
    }
  }

  if (problems.length > 0) {
    return { manifest: null as unknown as ExtensionManifest, problems };
  }

  const manifest: ExtensionManifest = {
    name,
    slug,
    version,
    ...(typeof m.author === 'string' ? { author: m.author } : {}),
    ...(typeof m.description === 'string' ? { description: m.description } : {}),
    ...(typeof m.license === 'string' ? { license: m.license } : {}),
    ...(typeof m.homepage === 'string' ? { homepage: m.homepage } : {}),
    nexuspanel_compat: compat as { min: string; max: string },
    types,
    permissions: [...new Set(permissions)],
    endpoints,
    ...(uiRaw !== undefined ? { ui: uiRaw as ExtensionManifest['ui'] } : {}),
    ...(storageRaw !== undefined ? { storage: storageRaw as ExtensionManifest['storage'] } : {}),
  };
  return { manifest, problems: [] };
}
