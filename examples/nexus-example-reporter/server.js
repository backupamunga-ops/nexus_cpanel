/**
 * nexus-example-reporter — the NexusPanel SDK reference extension
 * (extension SDK spec §11) and the platform's own acceptance test.
 *
 * What it does (exactly the §11 contract, nothing more):
 *   - type `integration`: subscribes to `backup.completed` / `backup.failed`
 *     hooks and posts a plain-text summary to WEBHOOK_URL;
 *   - type `widget`: renders a "Last backup" card on the dashboard.main
 *     slot, themed from the panel's postMessage context;
 *   - verifies EVERY panel call's §5.1 signature and 60 s timestamp window
 *     before acting on it (a receiver that does not verify is the #1 way
 *     extension deployments get abused — the reference implementation does
 *     not ship that hole).
 *
 * Zero dependencies (node stdlib only) — `node server.js` is the whole
 * install. Configuration is environment-only:
 *
 *   PORT=8800                          listen port
 *   SHARED_SECRET=...                  from the panel's one-time approval
 *   EXTENSION_ID=...                   uuid from the panel's approval
 *   PANEL_BASE_URL=http://panel:3000   control-plane origin (not used to
 *                                      authenticate — the derived token
 *                                      lives with the operator)
 *   WEBHOOK_URL=https://hooks.example/backup   summary sink
 *
 * The manifest served at /nexuspanel-manifest.json is what the admin
 * installs: POST /api/v1/extensions {"manifest_url": "http://this-host:8800/"}.
 */

'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 8800);
const SHARED_SECRET = process.env.SHARED_SECRET || '';
const EXTENSION_ID = process.env.EXTENSION_ID || '';
const WEBHOOK_URL = process.env.WEBHOOK_URL || '';
const TIMESTAMP_TOLERANCE_SEC = 60;

const MANIFEST = {
  name: 'Example Backup Reporter',
  slug: 'nexus-example-reporter',
  version: '1.0.0',
  author: 'NexusPanel <examples@nexuspanel.dev>',
  description:
    'Posts a backup summary to a webhook and shows a "Last backup" widget on the dashboard. Ships with the SDK as the acceptance test.',
  license: 'MIT',
  homepage: 'https://github.com/backupamunga-ops/nexus_cpanel/tree/main/examples/nexus-example-reporter',
  nexuspanel_compat: { min: '1.0.0', max: '1.99.99' },
  types: ['integration', 'widget'],
  permissions: ['backup:read'],
  endpoints: {
    register: '/register',
    heartbeat: '/health',
    widgets: {
      'last-backup': { slot: 'dashboard.main', entry: '/widgets/last-backup' },
    },
    hooks: {
      'backup.completed': '/hooks/backup-completed',
      'backup.failed': '/hooks/backup-failed',
    },
  },
  ui: {
    settings_url: '/ui/settings',
  },
};

// ---- state (in-memory; the spec lets a storageless extension own its state) --
const lastEvent = { type: null, occurred_at: null, job: null, status: null, size_bytes: null };

// ---- §5.1 signature verification -------------------------------------------

function verifyPanelSignature(req, rawBody) {
  if (!SHARED_SECRET) return { ok: false, reason: 'SHARED_SECRET not configured' };
  const id = req.headers['x-nexuspanel-extension-id'];
  const ts = req.headers['x-nexuspanel-timestamp'];
  const sig = req.headers['x-nexuspanel-signature'];
  if (!id || !ts || !sig) return { ok: false, reason: 'missing signature headers' };
  if (EXTENSION_ID && String(id) !== EXTENSION_ID) {
    return { ok: false, reason: 'unknown extension id' };
  }
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(ts)) > TIMESTAMP_TOLERANCE_SEC) {
    return { ok: false, reason: 'timestamp outside the 60s replay window' };
  }
  const expected = crypto
    .createHmac('sha256', SHARED_SECRET)
    .update(`${req.method}${req.url}${rawBody}${String(ts)}`)
    .digest('base64');
  const a = Buffer.from(expected);
  const b = Buffer.from(String(sig));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: 'signature mismatch' };
  }
  return { ok: true };
}

// ---- outbound summary (type integration) ------------------------------------

function postSummary(event) {
  if (!WEBHOOK_URL) return Promise.resolve();
  const text =
    event.event_type === 'backup.failed'
      ? `✗ Backup FAILED on ${event.payload?.hosting_account_id ?? 'panel'} at ${event.occurred_at}` +
        (event.payload?.error ? ` — ${JSON.stringify(event.payload.error).slice(0, 200)}` : '')
      : `✓ Backup completed at ${event.occurred_at}` +
        (event.payload?.parameters?.size_bytes ? ` (${event.payload.parameters.size_bytes} bytes)` : '');
  const body = JSON.stringify({ text, source: 'nexus-example-reporter', event_id: event.event_id });
  return fetch(WEBHOOK_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  }).catch((e) => console.error(`[reporter] webhook post failed: ${e.message}`));
}

// ---- widget HTML (type widget, SDK spec §7) ----------------------------------

function widgetHtml() {
  const rows = [
    ['Status', lastEvent.status ?? '—'],
    ['Finished', lastEvent.occurred_at ?? 'never'],
    ['Job', lastEvent.job ?? '—'],
    ['Size', lastEvent.size_bytes != null ? `${lastEvent.size_bytes} bytes` : '—'],
  ];
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  body { font: 13px/1.6 Inter, system-ui, sans-serif; margin: 0; padding: 12px 14px;
         background: var(--w-bg, transparent); color: var(--w-fg, inherit); }
  .row { display: flex; justify-content: space-between; gap: 12px; padding: 4px 0; }
  .k { opacity: 0.62; font-size: 11.5px; }
  .v { font-weight: 600; font-size: 12.5px; text-align: right; overflow-wrap: anywhere; }
  .ok { color: #22c55e; } .bad { color: #ef4444; }
</style></head>
<body>
  <div class="row"><span class="k">Status</span><span class="v ${lastEvent.status === 'failed' ? 'bad' : lastEvent.status ? 'ok' : ''}">${esc(lastEvent.status ?? 'waiting for the first backup')}</span></div>
  ${rows.slice(1).map(([k, v]) => `<div class="row"><span class="k">${k}</span><span class="v">${esc(String(v))}</span></div>`).join('')}
<script>
  window.addEventListener('message', (m) => {
    if (!m.data || m.data.type !== 'nexuspanel:context') return;
    const t = m.data.theme || {};
    const s = document.documentElement.style;
    s.setProperty('--w-bg', t.background || 'transparent');
    s.setProperty('--w-fg', t.foreground || 'inherit');
  });
  // §7: the widget asks, the panel answers — kept for forward compatibility
  window.parent.postMessage({ type: 'nexuspanel:widget-ready', widget: 'last-backup' }, '*');
</script>
</body></html>`;
}

function esc(s) {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function settingsHtml() {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>
  body { font: 13px/1.6 Inter, system-ui, sans-serif; margin: 0; padding: 14px; }
  code { background: rgba(127,127,127,.15); padding: 1px 5px; border-radius: 4px; }
</style></head><body>
<h3 style="margin:0 0 6px">Example Backup Reporter</h3>
<p>Configuration is environment-only by design (a reference extension must
not need a settings database): set <code>WEBHOOK_URL</code> to the sink that
receives the backup summaries. Everything else — scopes, hooks, widget —
was declared in the manifest and approved by the panel admin.</p>
</body></html>`;
}

// ---- server -------------------------------------------------------------------

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

const server = http.createServer(async (req, res) => {
  const raw = await readBody(req);
  const path = req.url.split('?')[0];

  // Public (unsigned) surfaces: the manifest itself and the widget iframe —
  // the iframe is browser-facing; the panel signs only server→server calls.
  if (req.method === 'GET' && path === '/nexuspanel-manifest.json') {
    return json(res, 200, MANIFEST);
  }
  if (req.method === 'GET' && path === '/widgets/last-backup') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(widgetHtml());
  }
  if (req.method === 'GET' && path === '/ui/settings') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(settingsHtml());
  }

  // Everything below is a panel → extension call: VERIFY FIRST (§5.1).
  const v = verifyPanelSignature(req, raw);
  if (!v.ok) return json(res, 401, { error: 'unauthorized', reason: v.reason });

  if (req.method === 'GET' && path === '/register') {
    // §5.2 registration confirmation: identify ourselves to the panel
    return json(res, 200, {
      extension_id: EXTENSION_ID || 'pending',
      manifest_version: MANIFEST.version,
      ready: true,
    });
  }
  if (req.method === 'GET' && path === '/health') {
    return json(res, 200, { status: 'ok' });
  }
  if (req.method === 'POST' && (path === '/hooks/backup-completed' || path === '/hooks/backup-failed')) {
    try {
      const event = JSON.parse(raw || '{}');
      lastEvent.type = event.event_type ?? path;
      lastEvent.occurred_at = event.occurred_at ?? null;
      lastEvent.status = event.event_type === 'backup.failed' ? 'failed' : 'success';
      lastEvent.job = event.payload?.parameters?.job_name ?? event.payload?.job_id ?? null;
      lastEvent.size_bytes = event.payload?.parameters?.size_bytes ?? null;
      console.log(`[reporter] ${event.event_type} @ ${event.occurred_at}`);
      await postSummary(event);
    } catch (e) {
      return json(res, 400, { error: `bad hook payload: ${e.message}` });
    }
    return json(res, 200, { received: true });
  }
  return json(res, 404, { error: 'not found' });
});

server.listen(PORT, () => {
  console.log(`nexus-example-reporter listening on :${PORT}`);
  if (!SHARED_SECRET) {
    console.warn('[reporter] SHARED_SECRET is not set — panel calls will be rejected until you configure the credentials shown at approval time.');
  }
});
