import crypto from 'node:crypto';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';

/**
 * Post-quantum primitives for Veyns Call.
 *
 * Identity: ML-DSA-65 (FIPS 204). Every message that matters is signed with it.
 * Sessions: hybrid ML-KEM-768 (FIPS 203) + X25519, mixed with the Hyperswarm Noise
 * handshake hash. An attacker has to break ML-KEM *and* X25519 to read a call.
 * Frames: AES-256-GCM with a per-direction counter nonce.
 */

export const b64 = bytes => Buffer.from(bytes).toString('base64url');
export const unb64 = text => new Uint8Array(Buffer.from(String(text), 'base64url'));
export const sha256 = data => crypto.createHash('sha256').update(data).digest();
export const randomId = (bytes = 16) => crypto.randomBytes(bytes).toString('base64url');

/** Canonical JSON: keys sorted recursively, arrays in order, no whitespace. Same rule as Veyns. */
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort()
      .map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

const DOMAIN = 'VEYNS-CALL-V1';
const signable = (context, payload) => Buffer.from(`${DOMAIN}/${context}\n${canonicalJson(payload)}`, 'utf8');

export function newIdentityKeys() {
  const sig = ml_dsa65.keygen(crypto.randomBytes(32));
  return { sigPub: b64(sig.publicKey), sigSec: b64(sig.secretKey) };
}

/** Short, human-checkable fingerprint of an ML-DSA public key, e.g. "7KQ2-M9XA-…". */
export function fingerprint(sigPub) {
  const alphabet = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  const hash = sha256(unb64(sigPub));
  let out = '';
  for (let i = 0; i < 16; i++) out += alphabet[hash[i] % 32] + (i % 4 === 3 && i < 15 ? '-' : '');
  return out;
}

/** The stable ID of a person on the network: SHA-256 of their ML-DSA public key. */
export const identityId = sigPub => sha256(unb64(sigPub)).toString('hex');

export const sign = (sigSec, context, payload) => b64(ml_dsa65.sign(signable(context, payload), unb64(sigSec)));

export function verify(sigPub, context, payload, signature) {
  try {
    return ml_dsa65.verify(unb64(signature), signable(context, payload), unb64(sigPub));
  } catch {
    return false;
  }
}

/* ------------------------------------------------------- hybrid session */

/** Fresh per-connection key material: nothing here outlives the connection. */
export function ephemeral() {
  const kem = ml_kem768.keygen(crypto.randomBytes(64));
  const dhSec = x25519.utils.randomSecretKey();
  return { kemPub: kem.publicKey, kemSec: kem.secretKey, dhSec, dhPub: x25519.getPublicKey(dhSec) };
}

export const encapsulate = kemPub => ml_kem768.encapsulate(kemPub);
export const decapsulate = (ct, kemSec) => ml_kem768.decapsulate(ct, kemSec);
export const dh = (dhSec, peerDhPub) => x25519.getSharedSecret(dhSec, peerDhPub);

/**
 * Both sides encapsulate to the other, so each contributes a KEM secret. The two
 * KEM secrets, the X25519 secret and the transcript (which includes the Noise
 * handshake hash) go through HKDF-SHA-256. Keys are split by role so the two
 * directions never share a key.
 */
export function deriveSessionKeys({ mineKem, theirsKem, dhShared, transcript, iAmLow }) {
  const [low, high] = iAmLow ? [mineKem, theirsKem] : [theirsKem, mineKem];
  const ikm = Buffer.concat([Buffer.from(low), Buffer.from(high), Buffer.from(dhShared)]);
  const okm = Buffer.from(crypto.hkdfSync('sha256', ikm, sha256(transcript), Buffer.from(`${DOMAIN}/session`), 64));
  const lowToHigh = okm.subarray(0, 32);
  const highToLow = okm.subarray(32, 64);
  return { send: iAmLow ? lowToHigh : highToLow, recv: iAmLow ? highToLow : lowToHigh };
}

/** AES-256-GCM, 96-bit nonce = 32 zero bits + 64-bit counter. Counters never repeat within a key. */
export function frameCipher(key) {
  let counter = 0n;
  const nonce = n => {
    const iv = Buffer.alloc(12);
    iv.writeBigUInt64BE(n, 4);
    return iv;
  };
  return {
    seal(plain) {
      const c = crypto.createCipheriv('aes-256-gcm', key, nonce(counter++));
      const body = Buffer.concat([c.update(plain), c.final()]);
      return Buffer.concat([body, c.getAuthTag()]);
    },
    open(sealed) {
      if (sealed.length < 16) throw new Error('short frame');
      const d = crypto.createDecipheriv('aes-256-gcm', key, nonce(counter++));
      d.setAuthTag(sealed.subarray(sealed.length - 16));
      return Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]);
    },
  };
}
