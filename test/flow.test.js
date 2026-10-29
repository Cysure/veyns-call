import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import createTestnet from 'hyperdht/testnet.js';
import WebSocket from 'ws';
import { startSimIssuer } from '../src/sim-issuer.js';
import { startNode } from '../src/node.js';

/**
 * End to end on the real stack: a local DHT, real Hyperswarm connections, the PQ
 * channel, and real ES256 palm tokens from the simulated issuer. Only the palm
 * "scan" is a button press.
 */

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'veyns-call-'));
let testnet, sim, alice, bob, mallory;
const ports = { sim: 17190, alice: 17101, bob: 17102, mallory: 17103 };

const until = async (fn, what, ms = 20_000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error(`timed out waiting for ${what}`);
};

async function api(node, route, body) {
  const res = await fetch(node.url + route, body === undefined ? {} : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const out = await res.json();
  if (!res.ok) throw Object.assign(new Error(out.error), { status: res.status });
  return out;
}

/** Presses "Scan palm" on the simulated scanner for this node's waiting request. */
async function palm(node, purpose, { deny = false } = {}) {
  const s = await until(() => node.view().scans.find(x => x.purpose === purpose && x.status === 'pending'), `${purpose} scan`);
  await fetch(`${sim.issuer}/approve/${s.requestId}${deny ? '?deny=1' : ''}`, { method: 'POST', redirect: 'manual' });
  return s;
}

async function onboard(node, label) {
  const { nonce } = await api(node, '/api/onboard/start', {});
  const { token } = await (await fetch(`${sim.issuer}/signin`, { method: 'POST', body: JSON.stringify({ client: sim.clientId, nonce, label }) })).json();
  await api(node, '/api/onboard/signin', { token });
  const avatar = 'data:image/svg+xml;base64,' + Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg"><text>${label}</text></svg>`).toString('base64');
  await api(node, '/api/onboard/create', { name: label, avatar });
  await palm(node, 'enroll');
  await until(() => node.view().stage === 'ready', `${label} identity`);
}

async function befriend(a, b) {
  await api(a, '/api/invites', {});
  await palm(a, 'invite');
  const code = await until(() => a.view().invites.find(i => i.status === 'open')?.code, 'invite code');
  await api(b, '/api/invites/redeem', { code });
  const bId = b.view().me.id;
  const aId = a.view().me.id;
  await until(() => a.view().contacts.find(c => c.id === bId && c.online), 'a sees b');
  await until(() => b.view().contacts.find(c => c.id === aId && c.online), 'b sees a');
  return { aId, bId };
}

function wsOf(node) {
  const ws = new WebSocket(node.url.replace('http', 'ws') + '/ws', { origin: node.url });
  ws.media = [];
  ws.on('message', (data, binary) => { if (binary) ws.media.push(Buffer.from(data)); });
  return new Promise(resolve => ws.on('open', () => resolve(ws)));
}

before(async () => {
  testnet = await createTestnet(3);
  sim = await startSimIssuer({ port: ports.sim, dataDir: path.join(tmp, 'sim') });
  const common = { issuer: sim.issuer, clientId: sim.clientId, backendSecret: sim.secret, simulated: true, bootstrap: testnet.bootstrap };
  alice = await startNode({ ...common, name: 'alice', port: ports.alice, dataDir: path.join(tmp, 'alice') });
  bob = await startNode({ ...common, name: 'bob', port: ports.bob, dataDir: path.join(tmp, 'bob') });
  mallory = await startNode({ ...common, name: 'mallory', port: ports.mallory, dataDir: path.join(tmp, 'mallory') });
  await onboard(alice, 'Alice');
  await onboard(bob, 'Bob');
  await onboard(mallory, 'Mallory');
});

after(async () => {
  await Promise.all([alice, bob, mallory].map(n => n?.close()));
  sim?.close();
  await testnet?.destroy();
});

test('identity cards are palm-bound', () => {
  const me = alice.view().me;
  assert.match(me.fingerprint, /^[2-9A-Z]{4}(-[2-9A-Z]{4}){3}$/);
  assert.equal(alice.store.card.human, alice.view().human);
  assert.ok(alice.store.card.palm.decision, 'the enrollment palm proof is inside the card');
});

test('a palm-signed invite connects two people, and works once', async () => {
  await befriend(alice, bob);
  const used = alice.view().invites.find(i => i.status === 'used');
  assert.equal(used.usedBy, 'Bob');
  assert.equal(used.code, null, 'a used invite no longer shows its code');
});

test('a guessed invite code connects nobody', async () => {
  await api(mallory, '/api/invites/redeem', { code: 'vc1.' + Buffer.alloc(32, 7).toString('base64url') });
  await new Promise(r => setTimeout(r, 1500));
  assert.equal(mallory.view().contacts.length, 0);
  await api(mallory, '/api/invites/cancel-redeem', {});
});

test('a call goes live only after both palms, and media flows', async () => {
  const bobId = bob.view().me.id;
  const [aWs, bWs] = await Promise.all([wsOf(alice), wsOf(bob)]);
  await api(alice, '/api/calls', { to: bobId, video: true });
  assert.equal(alice.view().call.state, 'scanning');

  // Before the palm scan, Bob has heard nothing.
  await new Promise(r => setTimeout(r, 500));
  assert.equal(bob.view().call, null);

  await palm(alice, 'call');
  const incoming = await until(() => bob.view().call?.state === 'incoming' && bob.view().call, 'ringing');
  assert.equal(incoming.peer.name, 'Alice');

  // Media sent while ringing is not forwarded.
  aWs.send(Buffer.from('too-early'));
  await new Promise(r => setTimeout(r, 300));
  assert.equal(bWs.media.length, 0);

  await api(bob, '/api/calls/answer', { id: incoming.id });
  await palm(bob, 'answer');
  await until(() => alice.view().call?.state === 'live' && bob.view().call?.state === 'live', 'live');

  aWs.send(Buffer.from('hello-bob'));
  bWs.send(Buffer.from('hello-alice'));
  await until(() => bWs.media.some(m => m.toString() === 'hello-bob'), 'media to bob');
  await until(() => aWs.media.some(m => m.toString() === 'hello-alice'), 'media to alice');

  // Presence check: Bob must scan again or the call ends.
  await api(alice, '/api/calls/presence', { id: incoming.id });
  await palm(bob, 'presence');
  await until(() => alice.view().events.some(e => e.text.includes('re-confirmed')), 'presence confirmed');
  assert.equal(alice.view().call.state, 'live');

  await api(alice, '/api/calls/hangup', { id: incoming.id });
  await until(() => bob.view().call?.state !== 'live', 'hangup reaches bob');
  aWs.close();
  bWs.close();
});

test('a denied palm scan never rings the other side', async () => {
  await until(() => !alice.view().call && !bob.view().call, 'idle');
  await api(alice, '/api/calls', { to: bob.view().me.id, video: false });
  await palm(alice, 'call', { deny: true });
  await until(() => alice.view().call?.state === 'ended', 'call ended');
  assert.match(alice.view().call.endReason, /denied/);
  await new Promise(r => setTimeout(r, 500));
  assert.equal(bob.view().call, null);
});

test('calls without a valid palm proof are blocked by the receiver', async () => {
  await until(() => !alice.view().call && !bob.view().call, 'idle');
  const aliceId = alice.view().me.id;
  const bobId = bob.view().me.id;
  const offer = { callId: 'forged-call-0001', from: aliceId, to: bobId, video: true, nonce: 'n1', createdAt: Math.floor(Date.now() / 1000) };

  // The attacker holds Alice's real ML-DSA key (a stolen device, an AI agent on it) but not her palm.
  const { sign } = await import('../src/pq.js');
  const signed = (o, p) => ({ t: 'call', offer: o, palm: p, sig: sign(alice.store.keys.sigSec, 'call', { offer: o, decision: p?.decision }) });
  const before = bob.view().events.filter(e => e.kind === 'blocked').length;

  // 1. No palm proof at all.
  alice.sendRaw(bobId, signed(offer, null));
  // 2. Alice's real enrollment palm proof replayed as a call proof.
  alice.sendRaw(bobId, signed({ ...offer, callId: 'forged-call-0002' }, alice.store.card.palm));
  // 3. Signed with the wrong key.
  alice.sendRaw(bobId, { ...signed({ ...offer, callId: 'forged-call-0003' }, null), sig: sign(mallory.store.keys.sigSec, 'call', { offer, decision: undefined }) });

  const blocked = await until(() => {
    const list = bob.view().events.filter(e => e.kind === 'blocked');
    return list.length >= before + 3 && list.slice(0, 3).map(e => e.text);
  }, 'three blocked calls');
  assert.ok(blocked.some(t => /no valid palm proof \(malformed token\)/.test(t)), blocked.join('\n'));
  assert.ok(blocked.some(t => /no valid palm proof \(Palm proof rejected: (not an approval|approves a different action)/.test(t)), blocked.join('\n'));
  assert.ok(blocked.some(t => /not signed by their key/.test(t)), blocked.join('\n'));
  assert.equal(bob.view().call, null, 'nothing rang');
});

test('the channel is quantum-safe and bound to the Noise session', async () => {
  const { Channel } = await import('../src/channel.js');
  const { newIdentityKeys } = await import('../src/pq.js');
  // Two in-memory sockets wired back to back, sharing a Noise handshake hash.
  const { EventEmitter } = await import('node:events');
  const hh = Buffer.alloc(32, 9);
  const sock = () => Object.assign(new EventEmitter(), { handshakeHash: hh, destroyed: false, destroy() { this.destroyed = true; this.emit('close'); } });
  const s1 = sock(), s2 = sock();
  const tapped = [];
  s1.write = d => { tapped.push(d); setImmediate(() => s2.emit('data', d)); };
  s2.write = d => setImmediate(() => s1.emit('data', d));
  const k1 = newIdentityKeys(), k2 = newIdentityKeys();
  const c1 = new Channel(s1, { keys: k1, card: { sigPub: k1.sigPub } });
  const c2 = new Channel(s2, { keys: k2, card: { sigPub: k2.sigPub } });
  await Promise.all([new Promise(r => c1.on('ready', r)), new Promise(r => c2.on('ready', r))]);
  assert.deepEqual(c1.transcriptHash, c2.transcriptHash);
  const got = new Promise(r => c2.on('message', r));
  c1.send({ secret: 'meet at noon' });
  assert.deepEqual(await got, { secret: 'meet at noon' });
  assert.ok(!Buffer.concat(tapped).includes('meet at noon'), 'plaintext never on the wire');
});
