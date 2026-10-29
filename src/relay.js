import { createPalmRequester, HttpError } from './palm.js';

/**
 * The palm relay: the only part of Veyns Call that runs on a server (Vercel).
 *
 * Creating a Veyns palm request needs the app's backend secret, which must not sit on
 * every person's machine. The relay holds it and does exactly three things: create a
 * request, report its status, cancel it. It never sees keys, calls or media, and it
 * cannot forge a scan: every node verifies Veyns' ES256 signature on the decision.
 *
 * It only forwards Veyns Call's own actions, so it cannot be used to put arbitrary
 * text in front of someone's palm.
 */

const ALLOWED = [
  /^Bind my palm to Veyns Call identity [2-9A-Z]{4}(-[2-9A-Z]{4}){3}$/,
  /^Invite a new person to Veyns Call$/,
  /^Start a call on Veyns Call$/,
  /^Answer a call on Veyns Call$/,
  /^Confirm I am still the person on this Veyns Call$/,
];
const KINDS = new Set(['enroll', 'invite', 'call', 'answer', 'presence']);

function checkAction(statement, details) {
  if (typeof statement !== 'string' || !ALLOWED.some(re => re.test(statement))) throw new HttpError(400, 'Not a Veyns Call action.');
  if (!details || details.app !== 'veyns-call' || !KINDS.has(details.kind)) throw new HttpError(400, 'Not a Veyns Call action.');
  if (JSON.stringify(details).length > 1024) throw new HttpError(400, 'Details too large.');
}

export function createRelay({ issuer, clientId, backendSecret, fetchImpl = fetch }) {
  const veyns = createPalmRequester({ issuer, clientId, backendSecret, fetchImpl });
  const id = v => (typeof v === 'string' && /^[\w-]{6,80}$/.test(v) ? v : null);

  const routes = {
    'GET /api/config': () => ({ issuer, clientId, palm: veyns.enabled }),

    'POST /api/palm/request': async ({ body }) => {
      const human = typeof body.human === 'string' && body.human.length <= 200 ? body.human : null;
      const key = id(body.key);
      if (!human || !key) throw new HttpError(400, 'Missing person or idempotency key.');
      checkAction(body.statement, body.details);
      return veyns.request({ human, statement: body.statement, details: body.details, key, expiresIn: Math.min(Number(body.expiresIn) || 300, 600) });
    },

    'POST /api/palm/status': async ({ body }) => {
      const requestId = id(body.requestId);
      if (!requestId) throw new HttpError(400, 'Missing request.');
      return veyns.poll(requestId);
    },

    'POST /api/palm/cancel': async ({ body }) => {
      const requestId = id(body.requestId);
      if (requestId) await veyns.cancel(requestId);
      return { ok: true };
    },
  };

  /** Plain Node (req, res) handler, used by Vercel and by the tests. */
  return async function handle(req, res) {
    const url = new URL(req.url, 'http://relay');
    const route = routes[`${req.method} ${url.pathname}`];
    // Nodes call this from their own process, not from a page: no cookies, no CORS needed.
    res.setHeader('cache-control', 'no-store');
    res.setHeader('content-type', 'application/json');
    if (!route) { res.statusCode = 404; return res.end(JSON.stringify({ error: 'not found' })); }
    let body = {};
    if (req.method === 'POST') {
      if (req.body && typeof req.body === 'object') body = req.body;
      else {
        let raw = '';
        for await (const chunk of req) { raw += chunk; if (raw.length > 16 * 1024) break; }
        try { body = JSON.parse(raw || '{}'); } catch { body = {}; }
      }
    }
    try {
      res.statusCode = 200;
      res.end(JSON.stringify(await route({ body })));
    } catch (error) {
      res.statusCode = error.status || 500;
      res.end(JSON.stringify({ error: error.status ? error.message : 'Relay error.' }));
    }
  };
}

/** What a node uses instead of talking to Veyns directly: same interface as createPalmRequester. */
export function createRelayRequester({ relay, fetchImpl = fetch }) {
  async function call(pathname, body) {
    let response;
    try {
      response = await fetchImpl(relay + pathname, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(15_000),
      });
    } catch {
      throw new HttpError(502, 'The palm relay is not reachable.');
    }
    const out = await response.json().catch(() => ({}));
    if (!response.ok) throw new HttpError(response.status === 400 ? 400 : 502, out.error || `Relay returned ${response.status}.`);
    return out;
  }
  return {
    enabled: true,
    request: ({ human, statement, details, key, expiresIn }) => call('/api/palm/request', { human, statement, details, key, expiresIn }),
    poll: requestId => call('/api/palm/status', { requestId }),
    cancel: requestId => call('/api/palm/cancel', { requestId }).catch(() => {}),
  };
}
