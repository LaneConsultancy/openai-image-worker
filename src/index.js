/*
 * openai-image-mcp — remote MCP server on Cloudflare Workers (with OAuth)
 *
 * MCP tool `generate_image` (OpenAI gpt-image-2) over Streamable-HTTP, connectable
 * to claude.ai as a custom Connector. claude.ai requires OAuth for custom connectors,
 * so this implements a minimal OAuth 2.1 Authorization Server (Dynamic Client
 * Registration + Authorization Code + PKCE), gated by a single shared password
 * (AUTH_PASSWORD secret) — suitable for a personal connector.
 *
 * Secrets (Worker): OPENAI_API_KEY, AUTH_PASSWORD, MCP_TOKEN (path-token for curl tests).
 * KV binding: IMAGES (also reused for oauth client/code/token records).
 *
 * Auth routes:
 *   GET  /.well-known/oauth-protected-resource[/mcp]
 *   GET  /.well-known/oauth-authorization-server[/mcp]
 *   POST /register            (Dynamic Client Registration)
 *   GET  /authorize           (password form)
 *   POST /authorize           (verify password -> issue code)
 *   POST /token               (code/refresh -> access token)
 * MCP routes:
 *   POST /mcp                 (requires Bearer access token)
 *   POST /mcp/<MCP_TOKEN>     (path-token bypass, for curl testing)
 * Images:
 *   GET  /i/<id>.png
 */

const PROTOCOL_VERSION = '2024-11-05';

const TOOLS = [{
  name: 'generate_image',
  description: 'Start generating an image with OpenAI gpt-image-2. Returns a job_id IMMEDIATELY without waiting for the render (this avoids the connector\'s 60s tool-call timeout, so HIGH and MEDIUM quality and large/landscape sizes all work). After calling this, call get_generated_image with the returned job_id, polling every ~15-20s until it returns the image (high quality can take 30-120s). Use high/medium quality freely.',
  inputSchema: {
    type: 'object',
    properties: {
      prompt: { type: 'string', description: 'Detailed description of the image to generate.' },
      size: { type: 'string', enum: ['1024x1024', '1536x1024', '1024x1536', 'auto'], description: '1536x1024=landscape, 1024x1536=portrait. Default 1024x1024.' },
      quality: { type: 'string', enum: ['low', 'medium', 'high', 'auto'], description: 'Render quality. Default high. high/medium are fully supported (polling handles the longer render time).' },
      n: { type: 'integer', minimum: 1, maximum: 4, description: 'Number of images (default 1).' }
    },
    required: ['prompt']
  }
}, {
  name: 'get_generated_image',
  description: 'Retrieve the result of a generate_image job. Returns the image inline + a 24h download URL when ready; or {status: processing} (call again in ~15-20s); or an error. Poll this until the image is returned.',
  inputSchema: {
    type: 'object',
    properties: { job_id: { type: 'string', description: 'The job_id returned by generate_image.' } },
    required: ['job_id']
  }
}];

// ---------- helpers ----------
const CORS = { 'Access-Control-Allow-Origin': '*' };
const j = (obj, status = 200, extra = {}) => new Response(JSON.stringify(obj), {
  status, headers: { 'Content-Type': 'application/json', ...CORS, ...extra }
});
const rpc = (id, result) => ({ jsonrpc: '2.0', id, result });
const rpcErr = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });
const toolText = (text, isError) => ({ content: [{ type: 'text', text }], ...(isError ? { isError: true } : {}) });

function b64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function randToken(n = 32) { const a = new Uint8Array(n); crypto.getRandomValues(a); return b64url(a); }
async function sha256b64url(str) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return b64url(new Uint8Array(d));
}
function formToObj(text) {
  const o = {};
  for (const [k, v] of new URLSearchParams(text)) o[k] = v;
  return o;
}
async function readParams(req) {
  const ct = req.headers.get('content-type') || '';
  if (ct.includes('application/json')) { try { return await req.json(); } catch { return {}; } }
  return formToObj(await req.text());
}

// ---------- OpenAI image generation ----------
async function generateImage(args, env, origin) {
  const key = env.OPENAI_API_KEY;
  if (!key) throw new Error('OPENAI_API_KEY secret is not set on the Worker.');
  const prompt = (args.prompt || '').trim();
  if (!prompt) throw new Error('prompt is required.');
  const model = env.OPENAI_IMAGE_MODEL || 'gpt-image-2';
  const reqBody = {
    model, prompt,
    n: Math.min(Math.max(parseInt(args.n, 10) || 1, 1), 4),
    size: args.size || '1024x1024',
    quality: args.quality || 'high'
  };
  const r = await fetch('https://api.openai.com/v1/images/generations', {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(reqBody)
  });
  if (!r.ok) { const t = await r.text().catch(() => ''); throw new Error(`OpenAI API ${r.status}: ${t.slice(0, 600)}`); }
  const data = await r.json();
  const items = Array.isArray(data.data) ? data.data : [];
  if (!items.length) throw new Error('OpenAI returned no image data.');
  const content = [], urls = [];
  for (const it of items) {
    const b64 = it.b64_json; if (!b64) continue;
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const id = crypto.randomUUID();
    await env.IMAGES.put(`img/${id}.png`, bytes, { expirationTtl: 86400 });
    urls.push(`${origin}/i/${id}.png`);
    content.push({ type: 'image', data: b64, mimeType: 'image/png' });
  }
  content.unshift({
    type: 'text',
    text: `Generated ${urls.length} image(s) with ${model} (${reqBody.size}, quality=${reqBody.quality}).\n` +
          `Download URL(s), valid 24h:\n${urls.join('\n')}\n\nTo save into the repo: curl -sL "${urls[0]}" -o ./public/image.png`
  });
  return { content };
}

// Durable Object that runs the slow render in an independent, durable context via an alarm,
// so it survives well past the connector's 60s tool-call timeout.
export class RenderJob {
  constructor(state, env) { this.state = state; this.env = env; }
  async fetch(request) {
    const payload = await request.json();
    await this.state.storage.put('payload', payload);
    await this.state.storage.setAlarm(Date.now() + 100);
    return new Response('queued');
  }
  async alarm() {
    const p = await this.state.storage.get('payload');
    if (!p) return;
    await this.state.storage.delete('payload');
    try {
      const result = await generateImage(p.args, this.env, p.origin);
      await this.env.IMAGES.put(`job:${p.jobId}`, JSON.stringify({ status: 'done', result }), { expirationTtl: 86400 });
    } catch (e) {
      await this.env.IMAGES.put(`job:${p.jobId}`, JSON.stringify({ status: 'error', error: e.message }), { expirationTtl: 3600 });
    }
  }
}

// ---------- MCP JSON-RPC ----------
async function handleRpc(m, env, origin, ctx) {
  const { id, method, params } = m || {};
  switch (method) {
    case 'initialize':
      return rpc(id, { protocolVersion: (params && params.protocolVersion) || PROTOCOL_VERSION, capabilities: { tools: {} }, serverInfo: { name: 'openai-image', version: '3.0.0' } });
    case 'notifications/initialized': case 'initialized': return null;
    case 'ping': return rpc(id, {});
    case 'tools/list': return rpc(id, { tools: TOOLS });
    case 'tools/call': {
      const name = params && params.name, args = (params && params.arguments) || {};
      if (name === 'generate_image') {
        if (!(args.prompt || '').trim()) return rpc(id, toolText('prompt is required.', true));
        const jobId = crypto.randomUUID();
        await env.IMAGES.put(`job:${jobId}`, JSON.stringify({ status: 'processing' }), { expirationTtl: 3600 });
        // Hand the slow render to a Durable Object alarm (a durable, independent execution
        // context) so it completes regardless of the connector's 60s tool-call timeout.
        const stub = env.RENDER_JOB.get(env.RENDER_JOB.idFromName(jobId));
        await stub.fetch('https://do/start', { method: 'POST', body: JSON.stringify({ jobId, args, origin }) });
        return rpc(id, toolText(`Image generation started. job_id=${jobId}\nCall get_generated_image with this job_id, polling every ~15-20s until it returns the image (high quality can take 30-120s).`));
      }
      if (name === 'get_generated_image') {
        const jid = (args.job_id || '').trim();
        if (!jid) return rpc(id, toolText('job_id is required.', true));
        const rec = await env.IMAGES.get(`job:${jid}`);
        if (!rec) return rpc(id, toolText(`No job "${jid}" found (it may have expired). Start a new generate_image.`, true));
        const job = JSON.parse(rec);
        if (job.status === 'processing') return rpc(id, toolText('status: processing — not ready yet. Call get_generated_image again in ~15-20s.'));
        if (job.status === 'error') return rpc(id, toolText(`Error: ${job.error}`, true));
        return rpc(id, job.result);
      }
      return rpc(id, toolText(`Unknown tool: ${name}`, true));
    }
    default: return id != null ? rpcErr(id, -32601, `Method not found: ${method}`) : null;
  }
}
async function serveMcp(req, env, origin, ctx) {
  if (req.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
  let body; try { body = await req.json(); } catch { return j(rpcErr(null, -32700, 'Parse error'), 400); }
  if (Array.isArray(body)) {
    const out = []; for (const m of body) { const r = await handleRpc(m, env, origin, ctx); if (r) out.push(r); }
    return out.length ? j(out) : new Response(null, { status: 202, headers: CORS });
  }
  const r = await handleRpc(body, env, origin, ctx);
  return r ? j(r) : new Response(null, { status: 202, headers: CORS });
}

// ---------- OAuth ----------
function authServerMeta(origin) {
  return {
    issuer: origin,
    authorization_endpoint: `${origin}/authorize`,
    token_endpoint: `${origin}/token`,
    registration_endpoint: `${origin}/register`,
    scopes_supported: ['mcp'],
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    code_challenge_methods_supported: ['S256']
  };
}
function protectedResourceMeta(origin) {
  return { resource: `${origin}/mcp`, authorization_servers: [origin], scopes_supported: ['mcp'], bearer_methods_supported: ['header'] };
}
function authorizeForm(origin, qs, error) {
  const hidden = ['client_id', 'redirect_uri', 'code_challenge', 'code_challenge_method', 'state', 'scope', 'response_type', 'resource']
    .map((k) => `<input type="hidden" name="${k}" value="${(qs.get(k) || '').replace(/"/g, '&quot;')}">`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize OpenAI Image Gen</title><style>
body{font-family:-apple-system,system-ui,sans-serif;background:#faf9f7;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
.card{background:#fff;border:1px solid #e6e3dd;border-radius:14px;padding:28px;max-width:360px;width:90%;box-shadow:0 8px 30px rgba(0,0,0,.06)}
h1{font-size:18px;margin:0 0 4px}p{color:#6b6760;font-size:14px;margin:0 0 18px}
input[type=password]{width:100%;box-sizing:border-box;padding:11px 12px;border:1px solid #d9d5cd;border-radius:9px;font-size:15px}
button{width:100%;margin-top:14px;padding:11px;background:#1a1a1a;color:#fff;border:0;border-radius:9px;font-size:15px;cursor:pointer}
.err{color:#b42318;font-size:13px;margin-top:10px}</style></head>
<body><form class="card" method="post" action="/authorize"><h1>Authorize OpenAI Image Gen</h1>
<p>Enter the connector password to allow Claude to use this image-generation tool.</p>
<input type="password" name="password" placeholder="Connector password" autofocus required>
${error ? `<div class="err">${error}</div>` : ''}${hidden}<button type="submit">Authorize</button></form></body></html>`;
}

async function handleOAuth(path, req, env, origin, url) {
  // discovery
  if (req.method === 'GET' && path.startsWith('/.well-known/oauth-protected-resource')) return j(protectedResourceMeta(origin));
  if (req.method === 'GET' && (path.startsWith('/.well-known/oauth-authorization-server') || path === '/.well-known/openid-configuration')) return j(authServerMeta(origin));

  // dynamic client registration
  if (req.method === 'POST' && path === '/register') {
    const meta = await readParams(req);
    const id = 'client_' + randToken(16);
    const redirect_uris = Array.isArray(meta.redirect_uris) ? meta.redirect_uris : [];
    const record = { redirect_uris, client_name: meta.client_name || 'mcp-client' };
    await env.IMAGES.put(`oauth:client:${id}`, JSON.stringify(record), { expirationTtl: 60 * 60 * 24 * 90 });
    return j({
      client_id: id, client_id_issued_at: Math.floor(Date.now() / 1000),
      redirect_uris, token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'],
      client_name: record.client_name
    }, 201);
  }

  // authorization endpoint
  if (path === '/authorize') {
    if (req.method === 'GET') {
      const qs = url.searchParams;
      const clientId = qs.get('client_id');
      const rec = clientId ? await env.IMAGES.get(`oauth:client:${clientId}`) : null;
      if (!rec) return new Response('Unknown client_id', { status: 400 });
      return new Response(authorizeForm(origin, qs, ''), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
    if (req.method === 'POST') {
      const p = await readParams(req);
      const qs = new URLSearchParams(p);
      const rec = p.client_id ? await env.IMAGES.get(`oauth:client:${p.client_id}`) : null;
      if (!rec) return new Response('Unknown client_id', { status: 400 });
      const client = JSON.parse(rec);
      if (!client.redirect_uris.includes(p.redirect_uri)) return new Response('Invalid redirect_uri', { status: 400 });
      if (!env.AUTH_PASSWORD || p.password !== env.AUTH_PASSWORD) {
        return new Response(authorizeForm(origin, qs, 'Incorrect password.'), { status: 401, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }
      const code = randToken(24);
      await env.IMAGES.put(`oauth:code:${code}`, JSON.stringify({
        client_id: p.client_id, redirect_uri: p.redirect_uri,
        code_challenge: p.code_challenge || '', scope: p.scope || 'mcp'
      }), { expirationTtl: 300 });
      const back = new URL(p.redirect_uri);
      back.searchParams.set('code', code);
      if (p.state) back.searchParams.set('state', p.state);
      return Response.redirect(back.toString(), 302);
    }
  }

  // token endpoint
  if (req.method === 'POST' && path === '/token') {
    const p = await readParams(req);
    if (p.grant_type === 'authorization_code') {
      const rec = p.code ? await env.IMAGES.get(`oauth:code:${p.code}`) : null;
      if (!rec) return j({ error: 'invalid_grant' }, 400);
      const c = JSON.parse(rec);
      await env.IMAGES.delete(`oauth:code:${p.code}`);
      if (c.redirect_uri !== p.redirect_uri) return j({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' }, 400);
      if (c.code_challenge) {
        if (!p.code_verifier || (await sha256b64url(p.code_verifier)) !== c.code_challenge) return j({ error: 'invalid_grant', error_description: 'PKCE failed' }, 400);
      }
      const access = randToken(32), refresh = randToken(32);
      await env.IMAGES.put(`oauth:token:${access}`, JSON.stringify({ client_id: c.client_id, scope: c.scope }), { expirationTtl: 3600 });
      await env.IMAGES.put(`oauth:refresh:${refresh}`, JSON.stringify({ client_id: c.client_id, scope: c.scope }), { expirationTtl: 60 * 60 * 24 * 90 });
      return j({ access_token: access, token_type: 'Bearer', expires_in: 3600, refresh_token: refresh, scope: c.scope });
    }
    if (p.grant_type === 'refresh_token') {
      const rec = p.refresh_token ? await env.IMAGES.get(`oauth:refresh:${p.refresh_token}`) : null;
      if (!rec) return j({ error: 'invalid_grant' }, 400);
      const c = JSON.parse(rec);
      const access = randToken(32);
      await env.IMAGES.put(`oauth:token:${access}`, JSON.stringify({ client_id: c.client_id, scope: c.scope }), { expirationTtl: 3600 });
      return j({ access_token: access, token_type: 'Bearer', expires_in: 3600, refresh_token: p.refresh_token, scope: c.scope });
    }
    return j({ error: 'unsupported_grant_type' }, 400);
  }
  return null;
}

// ---------- router ----------
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const origin = url.origin;
    const path = url.pathname;
    const parts = path.split('/').filter(Boolean);

    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...CORS, 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization, Mcp-Session-Id' } });
    }

    // images
    if (req.method === 'GET' && parts[0] === 'i' && parts[1]) {
      const val = await env.IMAGES.get(`img/${parts[1]}`, { type: 'arrayBuffer' });
      if (!val) return new Response('Not found', { status: 404 });
      return new Response(val, { headers: { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=86400' } });
    }
    if (path === '/health') return new Response('ok');

    // oauth
    if (path.startsWith('/.well-known/') || path === '/register' || path === '/authorize' || path === '/token') {
      const r = await handleOAuth(path, req, env, origin, url);
      if (r) return r;
    }

    // MCP via path-token (testing/power use)
    if (parts[0] === 'mcp' && parts[1] && env.MCP_TOKEN && parts[1] === env.MCP_TOKEN) {
      return serveMcp(req, env, origin, ctx);
    }

    // MCP via OAuth bearer (claude.ai)
    if (path === '/mcp') {
      const auth = req.headers.get('authorization') || '';
      const m = auth.match(/^Bearer\s+(.+)$/i);
      const tok = m && (await env.IMAGES.get(`oauth:token:${m[1]}`));
      if (!tok) {
        return new Response(JSON.stringify({ error: 'invalid_token' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', ...CORS, 'WWW-Authenticate': `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource"` }
        });
      }
      return serveMcp(req, env, origin, ctx);
    }

    return new Response('Not found', { status: 404 });
  }
};
