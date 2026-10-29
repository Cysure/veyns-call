import crypto from 'node:crypto';
import { canonicalJson } from './pq.js';

/**
 * Veyns palm approvals, and verification of palm proofs made by anyone.
 *
 * A palm proof is the decision token Veyns signs (ES256, published JWKS) when a person
 * approves an exact action with a palm scan. Any peer can check it without trusting
 * the node that produced it: the signature, the issuer and app, that it was a palm
 * scan, that it approves *this* action (digest), whose palm (subject), and when.
 *
 * Asking Veyns for a scan needs the app's backend credential; checking one does not.
 */

const LEEWAY = 30;

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/** base64url SHA-256 over the canonical {statement, details}; absent details become null. */
export const actionDigest = (statement, details) =>
  crypto.createHash('sha256').update(canonicalJson({ statement, details: details ?? null }), 'utf8').digest('base64url');

/** The approvals API may name people `pairwise:<client>:<sub>`; the stable human ID is the bare subject. */
export const humanOf = (sub, clientId) => (sub?.startsWith(`pairwise:${clientId}:`) ? sub.slice(`pairwise:${clientId}:`.length) : sub);

function decodeJwt(token) {
  const parts = typeof token === 'string' ? token.split('.') : [];
  if (parts.length !== 3) throw new HttpError(400, 'malformed token');
  try {
    return {
      parts,
      header: JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')),
      claims: JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')),
    };
  } catch {
    throw new HttpError(400, 'malformed token');
  }
}

/**
 * @param trusted  Map of issuer URL -> the Veyns client ID tokens must be issued for.
 *                 A proof from any other issuer is refused, so nobody can stand up
 *                 their own "Veyns" and mint palm scans.
 */
export function createPalmVerifier({ trusted, now = () => Math.floor(Date.now() / 1000), fetchImpl = fetch }) {
  const jwks = new Map(); // issuer -> { keys, loadedAt }

  async function key(issuer, kid) {
    let entry = jwks.get(issuer);
    if (!entry || (!entry.keys.has(kid) && now() - entry.loadedAt > 60)) {
      let body;
      try {
        const response = await fetchImpl(`${issuer}/jwks.json`, { signal: AbortSignal.timeout(10_000) });
        if (!response.ok) throw new Error(String(response.status));
        body = await response.json();
      } catch {
        throw new HttpError(502, `could not load signing keys from ${issuer}`);
      }
      const keys = new Map();
      for (const k of body.keys || []) {
        if (k.kty !== 'EC' || k.crv !== 'P-256' || !k.kid) continue;
        keys.set(k.kid, crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: k.x, y: k.y }, format: 'jwk' }));
      }
      entry = { keys, loadedAt: now() };
      jwks.set(issuer, entry);
    }
    const found = entry.keys.get(kid);
    if (!found) throw new HttpError(401, 'signed with an unknown key');
    return found;
  }

  /** Checks the token's signature and origin only. Returns its claims. */
  async function verifyToken(token, { allowExpired = false } = {}) {
    const { parts, header, claims } = decodeJwt(token);
    if (header.alg !== 'ES256') throw new HttpError(401, 'not ES256');
    if (!trusted.has(claims.iss)) throw new HttpError(401, `untrusted issuer ${claims.iss}`);
    const k = await key(claims.iss, header.kid);
    const ok = crypto.verify('sha256', Buffer.from(`${parts[0]}.${parts[1]}`),
      { key: k, dsaEncoding: 'ieee-p1363' }, Buffer.from(parts[2], 'base64url'));
    if (!ok) throw new HttpError(401, 'signature did not verify');
    const problem =
      claims.aud !== trusted.get(claims.iss) ? 'issued for a different app'
      : !allowExpired && (typeof claims.exp !== 'number' || claims.exp + LEEWAY <= now()) ? 'expired'
      : typeof claims.sub !== 'string' || !claims.sub ? 'missing subject'
      : null;
    if (problem) throw new HttpError(401, problem);
    return claims;
  }

  /**
   * Verifies a palm proof for an exact action.
   * @param proof     { decision } as returned by Veyns.
   * @param statement the exact words the person approved.
   * @param details   the exact details object.
   * @param human     the bare Veyns subject the proof must belong to (omit to learn it).
   * @param maxAge    seconds since the scan; omit for enrollment proofs checked later.
   */
  async function verifyPalm(proof, { statement, details, human, maxAge, notBefore }) {
    const claims = await verifyToken(proof?.decision, { allowExpired: maxAge === undefined });
    const subject = humanOf(claims.sub, claims.aud);
    const t = now();
    const problem =
      claims.veyns_intent !== 'action' ? 'not an approval'
      : !(claims.amr || []).includes('veyns:palm') ? 'not a palm scan'
      : claims.veyns_action?.digest !== actionDigest(statement, details) ? 'approves a different action'
      : human !== undefined && subject !== human ? 'a different person\'s palm'
      : typeof claims.auth_time !== 'number' || claims.auth_time > t + LEEWAY ? 'scan time is in the future'
      : maxAge !== undefined && claims.auth_time < t - maxAge ? 'scan is too old'
      : notBefore !== undefined && claims.auth_time < notBefore - LEEWAY ? 'scan predates the request'
      : null;
    if (problem) throw new HttpError(401, `Palm proof rejected: ${problem}.`);
    return { human: subject, issuer: claims.iss, authTime: claims.auth_time, jti: claims.jti ?? null, claims };
  }

  return { verifyToken, verifyPalm };
}

/**
 * Asks Veyns to put an action in front of a person's palm scanner.
 * Ported from Handover: the subject is tried in the documented pairwise form, then bare.
 */
export function createPalmRequester({ issuer, clientId, backendSecret, fetchImpl = fetch }) {
  async function backend(pathname, body, extraHeaders = {}) {
    if (!backendSecret) throw new HttpError(400, 'Palm scans need VEYNS_BACKEND_SECRET.');
    const authorization = 'Basic ' + Buffer.from(`${clientId}:${backendSecret}`).toString('base64');
    let response;
    try {
      response = await fetchImpl(issuer + pathname, {
        method: body === undefined ? 'GET' : 'POST',
        headers: { ...extraHeaders, authorization, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      throw new HttpError(502, 'Veyns is not reachable right now.');
    }
    const out = await response.json().catch(() => ({}));
    if (response.status === 401) throw new HttpError(502, 'Veyns rejected the backend credential.');
    if (!response.ok) throw new HttpError(response.status >= 500 ? 502 : 400, out.error_description || out.error || `Veyns returned ${response.status}.`);
    return out;
  }

  let subjectForm = null;

  /** Returns { requestId, approvalUrl }. */
  async function request({ human, statement, details, key, expiresIn = 120 }) {
    const forms = [
      { name: 'pairwise', subject: `pairwise:${clientId}:${human}`, key },
      { name: 'plain', subject: human, key: `${key}-plain` },
    ].filter(f => (subjectForm ? f.name === subjectForm : true));
    const refusals = [];
    for (const form of forms) {
      try {
        const remote = await backend('/v1/approvals', {
          subject: form.subject,
          idempotency_key: form.key,
          expires_in: expiresIn,
          action: { statement, details },
        }, { 'idempotency-key': form.key });
        subjectForm = form.name;
        return { requestId: remote.request_id, approvalUrl: remote.approval_url ?? null };
      } catch (error) {
        if (error.status !== 400) throw error;
        refusals.push(`${form.name}: ${error.message}`);
      }
    }
    subjectForm = null;
    throw new HttpError(400, `Veyns refused the palm request. ${refusals.join(' — ')}`);
  }

  /** Returns { status, decision? }; status is pending | verifying | approved | denied | expired | cancelled. */
  async function poll(requestId) {
    const remote = await backend(`/v1/approvals/${encodeURIComponent(requestId)}`);
    return { status: remote.status, decision: remote.decision ?? null };
  }

  const cancel = requestId => backend(`/v1/approvals/${encodeURIComponent(requestId)}/cancel`, {}).catch(() => {});

  return { request, poll, cancel, enabled: Boolean(backendSecret && clientId) };
}
