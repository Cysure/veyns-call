import { sha256, canonicalJson } from './pq.js';

/**
 * The exact actions people approve with their palm.
 *
 * Privacy rule: the palm service sees every statement and details object, so neither
 * may name who is calling whom. Each action carries only a digest of the real
 * content; the peers recompute that digest from the call they actually hold.
 */

const digest = (kind, content) => sha256(Buffer.from(canonicalJson({ kind, ...content }), 'utf8')).toString('hex');

/** Max age of a palm scan that starts, answers or re-confirms a call. */
export const CALL_SCAN_SECONDS = 180;
/** How long the other side has to answer a presence check before the call ends. */
export const PRESENCE_SECONDS = 120;

export const inviteAction = ({ inviteId, inviter, expiresAt }) => ({
  statement: 'Invite a new person to Veyns Call',
  details: { app: 'veyns-call', kind: 'invite', ref: digest('invite', { inviteId, inviter, expiresAt }) },
});

export const callAction = offer => ({
  statement: 'Start a call on Veyns Call',
  details: { app: 'veyns-call', kind: 'call', ref: digest('call', offer) },
});

export const answerAction = offer => ({
  statement: 'Answer a call on Veyns Call',
  details: { app: 'veyns-call', kind: 'answer', ref: digest('answer', offer) },
});

export const presenceAction = ({ callId, nonce, from, to }) => ({
  statement: 'Confirm I am still the person on this Veyns Call',
  details: { app: 'veyns-call', kind: 'presence', ref: digest('presence', { callId, nonce, from, to }) },
});
