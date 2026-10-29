import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

/**
 * SIMULATED Veyns, for development only.
 *
 * Speaks the same API shapes Veyns does (JWKS, veyns.js sign-in, /v1/approvals) and
 * signs real ES256 tokens, so the node code under test is the code that talks to the
 * real service. There is no biometric here: "scanning" is a button. Nodes trust this
 * issuer only when it is configured as their issuer, and every page says SIMULATED.
 */

const SECRET = 'sim-backend-secret';

export function startSimIssuer({ port = 7190, dataDir = 'data/sim-issuer', clientId = 'vc_sim_veynscall' } = {}) {
  fs.mkdirSync(dataDir, { recursive: true });
  const issuer = `http://localhost:${port}`;
  const keyFile = path.join(dataDir, 'key.json');
  const accountsFile = path.join(dataDir, 'palms.json');

  let jwk;
  if (fs.existsSync(keyFile)) jwk = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
  else {
    const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    jwk = { ...privateKey.export({ format: 'jwk' }), kid: crypto.randomBytes(6).toString('hex') };
    fs.writeFileSync(keyFile, JSON.stringify(jwk));
  }
  const privateKey = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  const publicJwk = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, kid: jwk.kid, alg: 'ES256', use: 'sig' };

  const palms = fs.existsSync(accountsFile) ? JSON.parse(fs.readFileSync(accountsFile, 'utf8')) : [];
  const savePalms = () => fs.writeFileSync(accountsFile, JSON.stringify(palms, null, 2));
  const requests = new Map();

  const now = () => Math.floor(Date.now() / 1000);
  const b64 = v => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
  function token(claims) {
    const head = b64({ alg: 'ES256', typ: 'JWT', kid: jwk.kid });
    const body = b64({ iss: issuer, aud: clientId, iat: now(), exp: now() + 300, veyns_presence: true, jti: crypto.randomUUID(), ...claims });
    const sig = crypto.sign('sha256', Buffer.from(`${head}.${body}`), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    return `${head}.${body}.${sig}`;
  }

  const canonical = v => (Array.isArray(v) ? `[${v.map(canonical).join(',')}]`
    : v && typeof v === 'object' ? `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`
    : JSON.stringify(v));
  const digest = (statement, details) => crypto.createHash('sha256').update(canonical({ statement, details: details ?? null })).digest('base64url');
  const bare = sub => sub.replace(/^pairwise:[^:]+:/, '');
  const esc = s => String(s).replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);

  const page = (title, body) => `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>
:root{color-scheme:dark;--bg:#07090f;--card:#10141f;--line:#232a3b;--ink:#eef2ff;--mute:#8a93ab;--accent:#5b8cff;--ok:#3ddc97;--bad:#ff6b6b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 Inter,system-ui,sans-serif;padding:20px}
.sim{background:#3b2a00;color:#ffd166;border:1px solid #6b4e00;border-radius:10px;padding:8px 12px;font-size:12px;letter-spacing:.04em;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;margin-bottom:12px}
h1{font-size:18px;margin:0 0 6px}p{color:var(--mute);margin:0 0 12px}pre{white-space:pre-wrap;word-break:break-all;color:var(--mute);font-size:12px}
button,a.btn{display:inline-block;font:inherit;border:0;border-radius:12px;padding:12px 16px;background:var(--accent);color:#fff;cursor:pointer;text-decoration:none;margin:4px 6px 0 0}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--ink)}input{font:inherit;padding:11px;border-radius:10px;border:1px solid var(--line);background:#0b0e16;color:var(--ink);width:100%;margin-bottom:8px}
.palm{width:84px;height:84px;border-radius:50%;border:2px solid var(--accent);display:grid;place-items:center;margin:8px 0 12px;font-size:40px}
.scanning .palm{animation:p 1s infinite}@keyframes p{50%{box-shadow:0 0 0 12px #5b8cff33}}
</style></head><body><div class="sim">SIMULATED VEYNS · development only · no biometric is read</div>${body}</body></html>`;

  const send = (res, status, body, type = 'application/json') => {
    res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store', 'access-control-allow-origin': '*' });
    res.end(type === 'application/json' ? JSON.stringify(body) : body);
  };
  const readBody = req => new Promise(resolve => {
    let s = '';
    req.on('data', c => (s += c));
    req.on('end', () => { try { resolve(JSON.parse(s || '{}')); } catch { resolve({}); } });
  });
  const authorized = req => {
    const [, cred] = (req.headers.authorization || '').split(' ');
    return Buffer.from(cred || '', 'base64').toString() === `${clientId}:${SECRET}`;
  };

  const sdk = `(() => {
  const ISSUER = ${JSON.stringify(issuer)};
  function signin({ clientId, nonce }) {
    return new Promise((resolve, reject) => {
      const shade = document.createElement('div');
      shade.style.cssText = 'position:fixed;inset:0;background:#000a;display:grid;place-items:center;z-index:99999';
      const frame = document.createElement('iframe');
      frame.src = ISSUER + '/signin?client_id=' + encodeURIComponent(clientId) + '&nonce=' + encodeURIComponent(nonce) + '&origin=' + encodeURIComponent(location.origin);
      frame.style.cssText = 'width:min(420px,94vw);height:min(620px,90vh);border:0;border-radius:18px;background:#07090f';
      shade.appendChild(frame); document.body.appendChild(shade);
      function done(e) {
        if (e.origin !== ISSUER) return;
        window.removeEventListener('message', done); shade.remove();
        if (e.data && e.data.token) resolve({ token: e.data.token });
        else { const err = new Error('cancelled'); err.code = 'cancelled'; reject(err); }
      }
      window.addEventListener('message', done);
    });
  }
  window.veyns = { signin };
})();`;

  function decide(r, approve) {
    if (r.status !== 'pending') return;
    if (!approve) { r.status = 'denied'; return; }
    r.status = 'approved';
    r.decision_id = crypto.randomUUID();
    r.decision = token({
      sub: r.subject.startsWith('pairwise:') ? r.subject : `pairwise:${clientId}:${r.subject}`,
      auth_time: now(),
      amr: ['veyns:palm'],
      veyns_intent: 'action',
      veyns_action: { digest: digest(r.action.statement, r.action.details) },
      request_id: r.request_id,
      request_nonce: r.challenge,
    });
  }

  const requestCard = r => `<div class="card" id="r-${esc(r.request_id)}"><h1>${esc(r.action.statement)}</h1>
<pre>${esc(JSON.stringify(r.action.details, null, 2))}</pre>
<form method="post" action="/approve/${esc(r.request_id)}" style="display:inline"><input type="hidden" name="d" value="yes"><button>✋ Scan palm</button></form>
<form method="post" action="/approve/${esc(r.request_id)}?deny=1" style="display:inline"><button class="ghost">Deny</button></form></div>`;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, issuer);
    const p = url.pathname;
    for (const r of requests.values()) if (r.status === 'pending' && r.expires_at < now()) r.status = 'expired';

    if (p === '/jwks.json') return send(res, 200, { keys: [publicJwk] });
    if (p === '/veyns.js') return send(res, 200, sdk, 'text/javascript');

    if (p === '/signin' && req.method === 'GET') {
      const q = url.searchParams;
      const list = palms.map(a => `<button class="ghost" data-sub="${esc(a.sub)}" style="width:100%;text-align:left">✋ ${esc(a.label)}</button>`).join('');
      return send(res, 200, page('Veyns sign-in', `<div class="card"><h1>Sign in with your palm</h1>
<p>Pick the palm that is "on the scanner", or enroll a new simulated palm.</p>${list || '<p>No simulated palms yet.</p>'}
<form id="new"><input name="label" placeholder="New palm owner, e.g. Alice" required maxlength="30"><button>Enroll palm and sign in</button></form>
<button class="ghost" id="cancel">Cancel</button></div>
<script>
const q=${JSON.stringify({ client: q.get('client_id'), nonce: q.get('nonce'), origin: q.get('origin') })};
async function go(body){const r=await fetch('/signin',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...body,client:q.client,nonce:q.nonce})});const o=await r.json();parent.postMessage({token:o.token},q.origin);}
document.querySelectorAll('[data-sub]').forEach(b=>b.onclick=()=>go({sub:b.dataset.sub}));
document.getElementById('new').onsubmit=e=>{e.preventDefault();go({label:new FormData(e.target).get('label')});};
document.getElementById('cancel').onclick=()=>parent.postMessage({cancelled:true},q.origin);
</script>`), 'text/html');
    }
    if (p === '/signin' && req.method === 'POST') {
      const body = await readBody(req);
      if (body.client !== clientId) return send(res, 400, { error: 'unknown client' });
      let account = palms.find(a => a.sub === body.sub);
      if (!account && body.label) {
        account = { sub: crypto.randomBytes(12).toString('base64url'), label: String(body.label).slice(0, 30) };
        palms.push(account);
        savePalms();
      }
      if (!account) return send(res, 400, { error: 'no such palm' });
      return send(res, 200, { token: token({ sub: account.sub, nonce: body.nonce, auth_time: now(), amr: ['veyns:palm'], veyns_intent: 'login' }) });
    }

    if (p === '/v1/approvals' && req.method === 'POST') {
      if (!authorized(req)) return send(res, 401, { error: 'invalid_client' });
      const body = await readBody(req);
      if (!body.subject || !body.idempotency_key || !body.action?.statement) return send(res, 400, { error: 'Provide the application subject and an idempotency key' });
      const sub = bare(body.subject);
      if (!palms.some(a => a.sub === sub)) return send(res, 400, { error: 'That account has no palm scanner connected' });
      const existing = [...requests.values()].find(r => r.key === body.idempotency_key);
      if (existing) return send(res, 200, existing);
      const r = {
        request_id: crypto.randomUUID(), key: body.idempotency_key, subject: body.subject, action: body.action,
        challenge: crypto.randomBytes(16).toString('base64url'), status: 'pending',
        expires_at: now() + Math.min(Number(body.expires_in) || 120, 600),
      };
      r.approval_url = `${issuer}/approve/${r.request_id}`;
      requests.set(r.request_id, r);
      return send(res, 200, r);
    }
    let m;
    if ((m = p.match(/^\/v1\/approvals\/([\w-]+)(\/cancel)?$/))) {
      if (!authorized(req)) return send(res, 401, { error: 'invalid_client' });
      const r = requests.get(m[1]);
      if (!r) return send(res, 404, { error: 'not_found' });
      if (m[2]) { if (r.status === 'pending') r.status = 'cancelled'; }
      return send(res, 200, { request_id: r.request_id, status: r.status, decision: r.decision, decision_id: r.decision_id });
    }

    // The "phone": every pending palm request for one person.
    if ((m = p.match(/^\/device\/([\w-]+)$/))) {
      const account = palms.find(a => a.sub === m[1]);
      if (!account) return send(res, 404, page('Unknown palm', '<div class="card"><h1>Unknown palm</h1></div>'), 'text/html');
      const pending = [...requests.values()].filter(r => r.status === 'pending' && bare(r.subject) === account.sub);
      return send(res, 200, page(`${account.label}'s Veyns`, `<div class="card"><div class="palm">✋</div><h1>${esc(account.label)}'s palm scanner</h1>
<p>Requests waiting for this palm appear here.</p></div>${pending.map(requestCard).join('') || '<div class="card"><p>Nothing waiting.</p></div>'}
<script>setTimeout(()=>location.reload(),2500)</script>`), 'text/html');
    }
    if ((m = p.match(/^\/approve\/([\w-]+)$/))) {
      const r = requests.get(m[1]);
      if (!r) return send(res, 404, page('Not found', '<div class="card"><h1>Request not found</h1></div>'), 'text/html');
      if (req.method === 'POST') {
        decide(r, !url.searchParams.has('deny'));
        res.writeHead(303, { location: req.headers.referer || `/approve/${r.request_id}` });
        return res.end();
      }
      return send(res, 200, page('Palm request', r.status === 'pending' ? requestCard(r)
        : `<div class="card"><h1>${esc(r.status)}</h1><p>${esc(r.action.statement)}</p></div>`), 'text/html');
    }
    send(res, 404, { error: 'not_found' });
  });

  return new Promise(resolve => server.listen(port, '127.0.0.1', () => resolve({ server, issuer, clientId, secret: SECRET, close: () => server.close() })));
}
