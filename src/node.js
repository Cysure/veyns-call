import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Hyperswarm from 'hyperswarm';
import { WebSocketServer } from 'ws';
import { Channel } from './channel.js';
import { newIdentityKeys, identityId, fingerprint, sign, verify, sha256, randomId, b64, unb64 } from './pq.js';
import { createPalmVerifier, createPalmRequester, humanOf, HttpError } from './palm.js';
import { enrollAction, makeCard, verifyCard, cardView, checkProfile } from './identity.js';
import { inviteAction, callAction, answerAction, presenceAction, CALL_SCAN_SECONDS, PRESENCE_SECONDS } from './actions.js';

/**
 * One person's Veyns Call node. It holds their keys, talks to peers over Hyperswarm
 * through post-quantum channels, and serves their UI on localhost.
 *
 * The node — not the UI — enforces every gate: no card without a palm, no contact
 * without a verified card, no call without the caller's fresh palm proof, no media
 * until both palms have been verified, and no media after a failed presence check.
 */

const PUBLIC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');
const INVITE_SECONDS = 24 * 3600;
const RING_SECONDS = 75;
const now = () => Math.floor(Date.now() / 1000);
const topic = (kind, value) => sha256(Buffer.from(`veyns-call/v1/${kind}/${value}`));
const inviteCode = secret => `vc1.${b64(secret)}`;
const parseInvite = code => {
  const m = /^vc1\.([\w-]{43})$/.exec(String(code || '').trim());
  if (!m) throw new HttpError(400, 'That is not a Veyns Call invite code.');
  return Buffer.from(unb64(m[1]));
};
const inviteIdOf = secret => sha256(Buffer.concat([Buffer.from('invite-id/'), secret])).toString('hex');
const inviteMac = (secret, transcriptHash) => crypto.createHmac('sha256', secret).update(transcriptHash).digest();

export async function startNode(options) {
  const {
    name = 'node', port = 7101, dataDir = `data/${name}`,
    issuer, clientId, backendSecret, simulated = false, bootstrap, fetchImpl = fetch, log = () => {},
  } = options;

  fs.mkdirSync(dataDir, { recursive: true });
  const file = path.join(dataDir, 'node.json');
  const store = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8'))
    : { human: null, keys: null, card: null, contacts: {}, invites: {}, redeeming: null, events: [], history: [] };
  const save = () => {
    fs.writeFileSync(`${file}.tmp`, JSON.stringify(store, null, 1));
    fs.renameSync(`${file}.tmp`, file);
  };

  const verifier = createPalmVerifier({ trusted: new Map([[issuer, clientId]]), fetchImpl });
  const requester = createPalmRequester({ issuer, clientId, backendSecret, fetchImpl });
  const myId = () => store.keys && identityId(store.keys.sigPub);

  /* ------------------------------------------------------------ events */

  const sockets = new Set();
  let pushTimer = null;
  function push() {
    clearTimeout(pushTimer);
    pushTimer = setTimeout(() => {
      const text = JSON.stringify({ type: 'state', state: view() });
      for (const ws of sockets) if (ws.readyState === 1) ws.send(text);
    }, 20);
  }
  function event(kind, text) {
    store.events.unshift({ at: now(), kind, text });
    store.events.length = Math.min(store.events.length, 100);
    save();
    push();
    log(`[${name}] ${kind}: ${text}`);
  }
  const contactName = id => store.contacts[id]?.card.name || `${id.slice(0, 8)}…`;

  /* ------------------------------------------------------------- palm */

  const scans = new Map();

  /**
   * Puts an action in front of this person's palm and resolves with the verified proof.
   * The node checks its own proof exactly as a peer will, so a bad one never leaves.
   */
  function scan(purpose, action, { onApproved, onFailed = () => {}, maxAge = CALL_SCAN_SECONDS, human = store.human } = {}) {
    const id = randomId(9);
    const s = { id, purpose, statement: action.statement, status: 'requesting', createdAt: now(), approvalUrl: null, requestId: null, error: null };
    scans.set(id, s);
    push();
    const fail = message => {
      if (s.status === 'cancelled') return;
      s.status = 'failed';
      s.error = message;
      push();
      onFailed(message);
    };
    (async () => {
      const notBefore = now();
      try {
        const r = await requester.request({ human, statement: action.statement, details: action.details, key: id, expiresIn: 300 });
        Object.assign(s, { requestId: r.requestId, approvalUrl: r.approvalUrl, status: 'pending' });
        push();
      } catch (error) {
        return fail(error.message);
      }
      const deadline = Date.now() + 320_000;
      while (Date.now() < deadline && s.status === 'pending') {
        await new Promise(r => setTimeout(r, 1200));
        if (s.status !== 'pending') return;
        let remote;
        try {
          remote = await requester.poll(s.requestId);
        } catch {
          continue;
        }
        if (['pending', 'verifying'].includes(remote.status)) continue;
        if (remote.status !== 'approved') return fail(`The palm scan was ${remote.status}.`);
        const proof = { decision: remote.decision };
        try {
          await verifier.verifyPalm(proof, { ...action, human, maxAge, notBefore });
        } catch (error) {
          return fail(error.message);
        }
        s.status = 'approved';
        push();
        setTimeout(() => scans.delete(id), 10_000);
        return onApproved(proof);
      }
      if (s.status === 'pending') fail('The palm scan timed out.');
    })().catch(error => fail(error.message));
    return s;
  }

  function cancelScan(id) {
    const s = scans.get(id);
    if (!s || !['pending', 'requesting'].includes(s.status)) return;
    s.status = 'cancelled';
    if (s.requestId) requester.cancel(s.requestId);
    push();
  }

  /* ------------------------------------------------------------ swarm */

  const swarm = new Hyperswarm(bootstrap ? { bootstrap } : {});
  const channels = new Map(); // peer identity id -> Channel
  const joined = new Map();   // topic hex -> discovery
  const join = (t, opts) => {
    const hex = t.toString('hex');
    if (!joined.has(hex)) joined.set(hex, swarm.join(t, opts));
  };
  const leave = t => {
    const hex = t.toString('hex');
    if (joined.delete(hex)) swarm.leave(t).catch(() => {});
  };

  function goOnline() {
    if (!store.card) return;
    join(topic('inbox', myId()), { server: true, client: false });
    for (const id of Object.keys(store.contacts)) join(topic('inbox', id), { server: false, client: true });
    for (const inv of Object.values(store.invites)) {
      if (!inv.usedBy && inv.expiresAt > now() && inv.secret) join(topic('invite', inv.id), { server: true, client: false });
    }
    if (store.redeeming) join(topic('invite', store.redeeming.inviteId), { server: false, client: true });
  }

  swarm.on('connection', (socket, info) => {
    if (!store.card) return socket.destroy();
    const ch = new Channel(socket, { keys: store.keys, card: store.card });
    const topics = (info.topics || []).map(t => Buffer.from(t).toString('hex'));
    ch.on('ready', () => onReady(ch, topics).catch(error => ch.close(error.message)));
    ch.on('message', msg => onMessage(ch, msg).catch(error => log(`[${name}] message error: ${error.message}`)));
    ch.on('media', chunk => onMedia(ch, chunk));
    ch.on('close', reason => onClosed(ch, reason));
  });

  async function onReady(ch, topics) {
    const r = store.redeeming;
    if (r && topics.includes(topic('invite', r.inviteId).toString('hex'))) {
      ch.role = 'redeemer';
      ch.send({ t: 'redeem', mac: b64(inviteMac(Buffer.from(unb64(r.secret)), ch.transcriptHash)) });
      return;
    }
    if (store.contacts[ch.peerId]) return attach(ch);
    // A stranger may only be someone redeeming one of my invites, and gets 10 s to prove it.
    ch.role = 'stranger';
    ch.strangerTimer = setTimeout(() => ch.close('stranger without an invite'), 10_000);
  }

  function attach(ch) {
    ch.role = 'contact';
    const old = channels.get(ch.peerId);
    if (old && old !== ch) old.close('replaced');
    channels.set(ch.peerId, ch);
    push();
  }

  function onClosed(ch, reason) {
    clearTimeout(ch.strangerTimer);
    if (channels.get(ch.peerId) !== ch) return;
    channels.delete(ch.peerId);
    if (call && call.peerId === ch.peerId && call.state !== 'ended') endCall('the connection dropped');
    push();
  }

  /* ---------------------------------------------------------- invites */

  async function onMessage(ch, msg) {
    if (ch.role === 'stranger') return msg.t === 'redeem' ? acceptRedeem(ch, msg) : ch.close('not a contact');
    if (ch.role === 'redeemer') return msg.t === 'welcome' ? acceptWelcome(ch, msg) : ch.close('expected welcome');
    if (ch.role !== 'contact') return;
    const handler = callHandlers[msg.t];
    if (handler) await handler(ch, msg);
  }

  async function acceptRedeem(ch, msg) {
    clearTimeout(ch.strangerTimer);
    const mac = Buffer.from(unb64(msg.mac || ''));
    const inv = Object.values(store.invites).find(i => {
      if (!i.secret || i.usedBy || i.expiresAt <= now()) return false;
      const want = inviteMac(Buffer.from(unb64(i.secret)), ch.transcriptHash);
      return want.length === mac.length && crypto.timingSafeEqual(want, mac);
    });
    if (!inv) {
      event('blocked', 'Refused a connection that did not hold a valid invite.');
      return ch.close('bad invite');
    }
    try {
      await verifyCard(ch.peerCard, verifier);
    } catch (error) {
      event('blocked', `Refused an invite redemption: ${error.message}`);
      return ch.close('bad card');
    }
    inv.usedBy = ch.peerId;
    inv.usedAt = now();
    delete inv.secret; // single use: the secret is gone once someone has used it
    store.contacts[ch.peerId] = { card: ch.peerCard, addedAt: now(), via: 'my invite' };
    save();
    leave(topic('invite', inv.id));
    ch.send({ t: 'welcome', invite: { inviteId: inv.id, inviter: myId(), expiresAt: inv.expiresAt, palm: inv.palm } });
    attach(ch);
    join(topic('inbox', ch.peerId), { server: false, client: true });
    event('ok', `${ch.peerCard.name} joined with your invite. Their palm-bound identity verified.`);
  }

  async function acceptWelcome(ch, msg) {
    const r = store.redeeming;
    try {
      const card = await verifyCard(ch.peerCard, verifier);
      const inv = msg.invite || {};
      if (inv.inviteId !== r.inviteId || inv.inviter !== ch.peerId) throw new Error('the invite does not match');
      // The inviter's own palm proof: a human, the one on this card, issued this invite.
      await verifier.verifyPalm(inv.palm, { ...inviteAction(inv), human: ch.peerCard.human });
      store.contacts[ch.peerId] = { card: ch.peerCard, addedAt: now(), via: 'their invite' };
      store.redeeming = null;
      save();
      leave(topic('invite', inv.inviteId));
      attach(ch);
      join(topic('inbox', ch.peerId), { server: false, client: true });
      event('ok', `You joined ${ch.peerCard.name} (${card.fingerprint}). Their palm-signed invite verified.`);
    } catch (error) {
      event('blocked', `Refused the inviter: ${error.message}`);
      ch.close('bad welcome');
    }
  }

  /* ------------------------------------------------------------ calls */

  let call = null;
  const seenCalls = new Set();
  const liveCall = () => (call && call.state === 'live' ? call : null);

  function endCall(reason, { notify = false } = {}) {
    if (!call || call.state === 'ended') return;
    const c = call;
    if (notify) channels.get(c.peerId)?.send({ t: 'hangup', callId: c.id, reason });
    if (c.scanId) cancelScan(c.scanId);
    clearTimeout(c.ringTimer);
    clearTimeout(c.presence?.timer);
    c.state = 'ended';
    c.endedAt = now();
    c.endReason = reason;
    store.history.unshift({
      id: c.id, peerId: c.peerId, direction: c.direction, startedAt: c.createdAt, liveAt: c.liveAt ?? null,
      endedAt: c.endedAt, reason, proofs: c.proofs,
    });
    store.history.length = Math.min(store.history.length, 50);
    save();
    for (const ws of sockets) if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'media-reset' }));
    setTimeout(() => { if (call === c) { call = null; push(); } }, 4000);
    push();
  }

  function goLive() {
    call.state = 'live';
    call.liveAt = now();
    for (const ws of sockets) if (ws.readyState === 1) ws.send(JSON.stringify({ type: 'media-reset' }));
    event('ok', `Call with ${contactName(call.peerId)} is live. Both palms verified; media is ML-KEM-768 + X25519 encrypted.`);
  }

  function startCall(peerId, video) {
    if (!store.card) throw new HttpError(400, 'Create your identity first.');
    if (!store.contacts[peerId]) throw new HttpError(404, 'Not one of your contacts.');
    if (!channels.has(peerId)) throw new HttpError(409, `${contactName(peerId)} is offline.`);
    if (call && call.state !== 'ended') throw new HttpError(409, 'You are already in a call.');
    const offer = { callId: randomId(12), from: myId(), to: peerId, video: Boolean(video), nonce: randomId(12), createdAt: now() };
    const c = call = { id: offer.callId, peerId, direction: 'out', state: 'scanning', offer, createdAt: now(), proofs: {} };
    const s = scan('call', callAction(offer), {
      onApproved: proof => {
        if (call !== c || c.state !== 'scanning') return;
        const ch = channels.get(peerId);
        if (!ch) return endCall(`${contactName(peerId)} went offline`);
        c.proofs.caller = true;
        ch.send({ t: 'call', offer, palm: proof, sig: sign(store.keys.sigSec, 'call', { offer, decision: proof.decision }) });
        c.state = 'ringing';
        c.ringTimer = setTimeout(() => endCall('no answer', { notify: true }), RING_SECONDS * 1000);
        push();
      },
      onFailed: reason => { if (call === c) endCall(`your palm scan did not complete (${reason})`); },
    });
    c.scanId = s.id;
    push();
    return c;
  }

  async function verifyPeerProof(ch, kind, action, proof) {
    try {
      const out = await verifier.verifyPalm(proof, { ...action, human: store.contacts[ch.peerId].card.human, maxAge: CALL_SCAN_SECONDS });
      if (seenCalls.has(`${kind}:${out.jti}`)) throw new Error('This palm proof was already used.');
      if (out.jti) seenCalls.add(`${kind}:${out.jti}`);
      return out;
    } catch (error) {
      return { error: error.message };
    }
  }

  const callHandlers = {
    async call(ch, { offer, palm, sig }) {
      const who = contactName(ch.peerId);
      const refuse = reason => {
        event('blocked', `Blocked a call from ${who}: ${reason}`);
        ch.send({ t: 'refused', callId: offer?.callId, reason });
      };
      if (!offer || offer.from !== ch.peerId || offer.to !== myId()) return refuse('the call is not addressed between you two');
      if (!verify(ch.peerCard.sigPub, 'call', { offer, decision: palm?.decision }, sig)) return refuse('the call is not signed by their key');
      if (typeof offer.createdAt !== 'number' || Math.abs(now() - offer.createdAt) > CALL_SCAN_SECONDS) return refuse('the call is stale');
      if (seenCalls.has(`call:${offer.callId}`)) return refuse('the call was replayed');
      const proof = await verifyPeerProof(ch, 'call', callAction(offer), palm);
      if (proof.error) return refuse(`no valid palm proof (${proof.error})`);
      seenCalls.add(`call:${offer.callId}`);
      if (call && call.state !== 'ended') return ch.send({ t: 'busy', callId: offer.callId });
      call = { id: offer.callId, peerId: ch.peerId, direction: 'in', state: 'incoming', offer, createdAt: now(), proofs: { caller: proof.authTime } };
      call.ringTimer = setTimeout(() => endCall('missed', { notify: true }), RING_SECONDS * 1000);
      event('ok', `${who} is calling. Their palm scan verified (${new Date(proof.authTime * 1000).toLocaleTimeString()}).`);
    },

    async answer(ch, { callId, palm }) {
      if (!call || call.id !== callId || call.peerId !== ch.peerId || call.state !== 'ringing') return;
      const proof = await verifyPeerProof(ch, 'answer', answerAction(call.offer), palm);
      if (proof.error) {
        event('blocked', `${contactName(ch.peerId)} answered without a valid palm proof: ${proof.error}`);
        return endCall('the answer had no valid palm proof', { notify: true });
      }
      clearTimeout(call.ringTimer);
      call.proofs.callee = proof.authTime;
      goLive();
    },

    async refused(ch, { callId, reason }) {
      if (call?.id === callId) endCall(`refused: ${reason}`);
    },
    async busy(ch, { callId }) {
      if (call?.id === callId) endCall(`${contactName(ch.peerId)} is busy`);
    },
    async decline(ch, { callId }) {
      if (call?.id === callId) endCall(`${contactName(ch.peerId)} declined`);
    },
    async hangup(ch, { callId, reason }) {
      if (call?.id === callId && call.peerId === ch.peerId) endCall(reason ? `they ended it: ${reason}` : 'they hung up');
    },

    /** The other person asks me to prove, again, that my palm is behind this call. */
    async 'presence?'(ch, { callId, nonce }) {
      const c = liveCall();
      if (!c || c.id !== callId || c.peerId !== ch.peerId || typeof nonce !== 'string') return;
      event('info', `${contactName(ch.peerId)} asked you to confirm with your palm that it is still you.`);
      const s = scan('presence', presenceAction({ callId, nonce, from: ch.peerId, to: myId() }), {
        onApproved: proof => {
          if (call === c && c.state === 'live') channels.get(c.peerId)?.send({ t: 'presence', callId, nonce, palm: proof });
        },
      });
      c.presenceScan = s.id;
      push();
    },

    async presence(ch, { callId, nonce, palm }) {
      const c = liveCall();
      if (!c || c.id !== callId || !c.presence || c.presence.nonce !== nonce) return;
      const proof = await verifyPeerProof(ch, 'presence', presenceAction({ callId, nonce, from: myId(), to: ch.peerId }), palm);
      if (proof.error) {
        event('blocked', `Presence check failed: ${proof.error}`);
        return endCall('presence check failed', { notify: true });
      }
      clearTimeout(c.presence.timer);
      c.presence = null;
      event('ok', `${contactName(ch.peerId)} re-confirmed with their palm.`);
    },
  };

  function answerCall(id) {
    if (!call || call.id !== id || call.direction !== 'in' || call.state !== 'incoming') throw new HttpError(409, 'No call to answer.');
    const c = call;
    c.state = 'scanning';
    const s = scan('answer', answerAction(c.offer), {
      onApproved: proof => {
        if (call !== c || c.state !== 'scanning') return;
        clearTimeout(c.ringTimer);
        channels.get(c.peerId)?.send({ t: 'answer', callId: c.id, palm: proof });
        c.proofs.callee = true;
        goLive();
      },
      onFailed: reason => { if (call === c && c.state === 'scanning') { c.state = 'incoming'; push(); event('info', `Answer scan did not complete: ${reason}`); } },
    });
    c.scanId = s.id;
    push();
  }

  function checkPresence(id) {
    const c = liveCall();
    if (!c || c.id !== id) throw new HttpError(409, 'No live call.');
    if (c.presence) throw new HttpError(409, 'A presence check is already running.');
    const nonce = randomId(12);
    c.presence = { nonce, deadline: now() + PRESENCE_SECONDS };
    c.presence.timer = setTimeout(() => {
      event('blocked', `${contactName(c.peerId)} did not confirm with their palm in time. Call ended.`);
      endCall('presence check timed out', { notify: true });
    }, PRESENCE_SECONDS * 1000);
    channels.get(c.peerId)?.send({ t: 'presence?', callId: id, nonce });
    event('info', `Asked ${contactName(c.peerId)} to re-confirm with their palm.`);
  }

  function onMedia(ch, chunk) {
    const c = liveCall();
    // Media from anyone but the verified peer of a live call is dropped on the floor.
    if (!c || ch.peerId !== c.peerId) return;
    for (const ws of sockets) if (ws.readyState === 1) ws.send(chunk);
  }

  /* --------------------------------------------------------- HTTP API */

  let loginNonce = null;

  function view() {
    const me = store.card ? cardView(store.card) : null;
    return {
      name,
      config: { issuer, clientId, simulated, palmReady: requester.enabled },
      stage: !store.human ? 'signin' : !store.card ? 'create' : 'ready',
      human: store.human,
      device: simulated && store.human ? `${issuer}/device/${store.human}` : null,
      me,
      contacts: Object.entries(store.contacts).map(([id, c]) => ({ ...cardView(c.card), via: c.via, addedAt: c.addedAt, online: channels.has(id) })),
      invites: Object.values(store.invites).map(i => ({
        id: i.id, createdAt: i.createdAt, expiresAt: i.expiresAt, status: i.usedBy ? 'used' : i.expiresAt <= now() ? 'expired' : i.palm ? 'open' : 'scanning',
        code: !i.usedBy && i.palm && i.secret ? inviteCode(Buffer.from(unb64(i.secret))) : null,
        usedBy: i.usedBy ? contactName(i.usedBy) : null,
      })),
      redeeming: store.redeeming ? { since: store.redeeming.since } : null,
      scans: [...scans.values()].map(s => ({ id: s.id, purpose: s.purpose, statement: s.statement, status: s.status, approvalUrl: s.approvalUrl, requestId: s.requestId, error: s.error })),
      call: call && {
        id: call.id, peer: cardView(store.contacts[call.peerId]?.card), direction: call.direction, state: call.state,
        video: call.offer.video, createdAt: call.createdAt, liveAt: call.liveAt ?? null, endReason: call.endReason ?? null,
        presence: call.presence ? { deadline: call.presence.deadline } : null, proofs: call.proofs,
      },
      history: store.history.slice(0, 20).map(h => ({ ...h, peer: contactName(h.peerId) })),
      events: store.events.slice(0, 40),
    };
  }

  const routes = {
    'GET /api/state': () => view(),

    'POST /api/onboard/start': () => {
      loginNonce = { value: randomId(18), expires: now() + 300 };
      return { nonce: loginNonce.value };
    },
    'POST /api/onboard/signin': async ({ body }) => {
      const pending = loginNonce;
      loginNonce = null;
      if (!pending || pending.expires < now()) throw new HttpError(401, 'Sign-in expired. Try again.');
      const claims = await verifier.verifyToken(body.token);
      if (claims.nonce !== pending.value) throw new HttpError(401, 'That sign-in did not start here.');
      if (claims.veyns_intent !== 'login') throw new HttpError(401, 'That token is not a sign-in.');
      if (!(claims.amr || []).includes('veyns:palm')) throw new HttpError(401, 'Veyns Call needs palm sign-in.');
      if (typeof claims.auth_time !== 'number' || claims.auth_time < now() - 300) throw new HttpError(401, 'That sign-in is too old.');
      if (store.card && humanOf(claims.sub, clientId) !== store.human) throw new HttpError(409, 'This node already belongs to a different palm.');
      store.human = humanOf(claims.sub, clientId);
      save();
      push();
      return view();
    },
    'POST /api/onboard/create': ({ body }) => {
      if (!store.human) throw new HttpError(400, 'Sign in with your palm first.');
      if (store.card) throw new HttpError(409, 'Your identity already exists.');
      const profile = { name: String(body.name || '').trim(), avatar: body.avatar };
      const problem = checkProfile(profile);
      if (problem) throw new HttpError(400, problem);
      const keys = newIdentityKeys();
      const createdAt = now();
      const action = enrollAction({ ...profile, sigPub: keys.sigPub, createdAt });
      const s = scan('enroll', action, {
        maxAge: 600,
        onApproved: async palm => {
          if (store.card) return;
          const card = makeCard({ keys, ...profile, human: store.human, issuer, createdAt, palm });
          try {
            await verifyCard(card, verifier);
          } catch (error) {
            return event('blocked', `Could not create your identity: ${error.message}`);
          }
          store.keys = keys;
          store.card = card;
          save();
          goOnline();
          event('ok', `Identity ${fingerprint(keys.sigPub)} created and bound to your palm.`);
        },
      });
      return { scan: s.id };
    },

    'POST /api/invites': () => {
      if (!store.card) throw new HttpError(400, 'Create your identity first.');
      const secret = crypto.randomBytes(32);
      const inv = { id: inviteIdOf(secret), secret: b64(secret), createdAt: now(), expiresAt: now() + INVITE_SECONDS, palm: null };
      store.invites[inv.id] = inv;
      save();
      const s = scan('invite', inviteAction({ inviteId: inv.id, inviter: myId(), expiresAt: inv.expiresAt }), {
        maxAge: 600,
        onApproved: palm => {
          inv.palm = palm;
          save();
          join(topic('invite', inv.id), { server: true, client: false });
          event('ok', 'Invite created and signed by your palm. Share the code; it works once, for 24 hours, while you are online.');
        },
        onFailed: () => { delete store.invites[inv.id]; save(); push(); },
      });
      return { scan: s.id };
    },
    'POST /api/invites/revoke': ({ body }) => {
      const inv = store.invites[body.id];
      if (inv) { leave(topic('invite', inv.id)); delete store.invites[inv.id]; save(); push(); }
      return view();
    },
    'POST /api/invites/redeem': ({ body }) => {
      if (!store.card) throw new HttpError(400, 'Create your identity first.');
      const secret = parseInvite(body.code);
      if (store.redeeming) leave(topic('invite', store.redeeming.inviteId));
      store.redeeming = { inviteId: inviteIdOf(secret), secret: b64(secret), since: now() };
      save();
      join(topic('invite', store.redeeming.inviteId), { server: false, client: true });
      event('info', 'Looking for the person who invited you. They need to be online.');
      return view();
    },
    'POST /api/invites/cancel-redeem': () => {
      if (store.redeeming) leave(topic('invite', store.redeeming.inviteId));
      store.redeeming = null;
      save();
      push();
      return view();
    },

    'POST /api/calls': ({ body }) => { startCall(body.to, body.video); return view(); },
    'POST /api/calls/answer': ({ body }) => { answerCall(body.id); return view(); },
    'POST /api/calls/decline': ({ body }) => {
      if (call?.id === body.id && call.state !== 'ended') {
        channels.get(call.peerId)?.send({ t: 'decline', callId: call.id });
        endCall('you declined');
      }
      return view();
    },
    'POST /api/calls/hangup': ({ body }) => { if (call?.id === body.id) endCall('you hung up', { notify: true }); return view(); },
    'POST /api/calls/presence': ({ body }) => { checkPresence(body.id); return view(); },
    'POST /api/scans/cancel': ({ body }) => { cancelScan(body.id); return view(); },
  };

  const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png' };
  const csp = [
    "default-src 'self'", `script-src 'self' ${issuer}`, `connect-src 'self' ws://localhost:${port} ws://127.0.0.1:${port}`,
    "img-src 'self' data: blob:", "media-src 'self' blob:", `frame-src ${issuer}`, "style-src 'self' 'unsafe-inline'", "object-src 'none'", "base-uri 'none'",
  ].join('; ');
  const localOrigin = origin => !origin || origin === `http://localhost:${port}` || origin === `http://127.0.0.1:${port}`;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${port}`);
    const route = routes[`${req.method} ${url.pathname}`];
    if (route) {
      // Only this node's own page may drive it.
      if (!localOrigin(req.headers.origin)) { res.writeHead(403); return res.end(); }
      let body = {};
      if (req.method === 'POST') {
        let raw = '';
        for await (const chunk of req) { raw += chunk; if (raw.length > 512 * 1024) break; }
        try { body = JSON.parse(raw || '{}'); } catch { body = {}; }
      }
      try {
        const out = await route({ body });
        res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        return res.end(JSON.stringify(out));
      } catch (error) {
        res.writeHead(error.status || 500, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ error: error.status ? error.message : 'Something went wrong.' }));
      }
    }
    const rel = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    const filePath = path.join(PUBLIC, path.normalize(rel));
    if (!filePath.startsWith(PUBLIC) || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'content-type': types[path.extname(filePath)] || 'application/octet-stream', 'content-security-policy': csp, 'cache-control': 'no-store' });
    fs.createReadStream(filePath).pipe(res);
  });

  const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 2 * 1024 * 1024, verifyClient: ({ origin }) => localOrigin(origin) });
  wss.on('connection', ws => {
    sockets.add(ws);
    ws.send(JSON.stringify({ type: 'state', state: view() }));
    ws.on('message', (data, isBinary) => {
      // Outgoing media leaves only while a call is live, and only to the verified peer.
      const c = liveCall();
      if (isBinary && c) channels.get(c.peerId)?.sendMedia(Buffer.from(data));
    });
    ws.on('close', () => sockets.delete(ws));
  });

  await new Promise(resolve => server.listen(port, '127.0.0.1', resolve));
  goOnline();
  log(`[${name}] http://localhost:${port}`);

  return {
    url: `http://localhost:${port}`,
    view,
    store,
    /** Test hook: send a raw message to a contact, bypassing the node's own gates. */
    sendRaw: (peerId, msg) => channels.get(peerId)?.send(msg),
    async close() {
      for (const ws of sockets) ws.terminate();
      wss.close();
      server.close();
      await swarm.destroy();
    },
  };
}
