import { sign, verify, identityId, fingerprint, sha256 } from './pq.js';

/**
 * A card is a person's public identity on the network: a name, an avatar, an ML-DSA-65
 * key, and the palm proof that binds that key to one Veyns human. Nobody gets a card
 * without scanning a palm, and the card is useless without the matching secret key.
 */

const MAX_AVATAR = 96 * 1024;

export const avatarHash = avatar => sha256(Buffer.from(avatar, 'utf8')).toString('hex');

/**
 * What the person approves with their palm when they create their identity.
 * Everything sent to Veyns is opaque: the palm service learns that someone bound a
 * key, never their name or picture (those are hashed into `profile`).
 */
export function enrollAction({ name, sigPub, avatar, createdAt }) {
  return {
    statement: `Bind my palm to Veyns Call identity ${fingerprint(sigPub)}`,
    details: { app: 'veyns-call', kind: 'enroll', identity: identityId(sigPub), profile: profileHash({ name, avatar }), createdAt },
  };
}

export const profileHash = ({ name, avatar }) => sha256(Buffer.from(`${name}\n${avatarHash(avatar)}`, 'utf8')).toString('hex');

export function checkProfile({ name, avatar }) {
  if (typeof name !== 'string' || !name.trim() || name.trim().length > 40) return 'Name must be 1 to 40 characters.';
  if (typeof avatar !== 'string' || !/^data:image\/(png|jpeg|webp|svg\+xml);base64,/.test(avatar)) return 'Avatar must be an image.';
  if (avatar.length > MAX_AVATAR) return 'Avatar is too large.';
  return null;
}

const body = card => ({ v: card.v, name: card.name, avatar: card.avatar, sigPub: card.sigPub, human: card.human, issuer: card.issuer, createdAt: card.createdAt, palm: card.palm });

export function makeCard({ keys, name, avatar, human, issuer, createdAt, palm }) {
  const card = { v: 1, name, avatar, sigPub: keys.sigPub, human, issuer, createdAt, palm };
  return { ...card, sig: sign(keys.sigSec, 'card', body(card)) };
}

/**
 * Full check of someone else's card: self-signature, and a palm proof from a trusted
 * issuer, by the human the card names, approving exactly this key, name and avatar.
 */
export async function verifyCard(card, verifier) {
  if (!card || card.v !== 1 || typeof card.sigPub !== 'string') throw new Error('Not a Veyns Call card.');
  const problem = checkProfile(card);
  if (problem) throw new Error(problem);
  if (!verify(card.sigPub, 'card', body(card), card.sig)) throw new Error('The card signature does not verify.');
  const action = enrollAction(card);
  const palm = await verifier.verifyPalm(card.palm, { ...action, human: card.human });
  if (palm.issuer !== card.issuer) throw new Error('The card names a different palm issuer.');
  return { id: identityId(card.sigPub), fingerprint: fingerprint(card.sigPub), palm };
}

/** The part of a card that is safe and useful to show in the UI. */
export const cardView = card => card && ({
  id: identityId(card.sigPub),
  name: card.name,
  avatar: card.avatar,
  fingerprint: fingerprint(card.sigPub),
  human: card.human,
  createdAt: card.createdAt,
});
