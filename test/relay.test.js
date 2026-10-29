import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startSimIssuer } from '../src/sim-issuer.js';
import { createRelay, createRelayRequester } from '../src/relay.js';
import { callAction } from '../src/actions.js';

let sim, server, relayUrl;

before(async () => {
  sim = await startSimIssuer({ port: 17290, dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'relay-')) });
  server = http.createServer(createRelay({ issuer: sim.issuer, clientId: sim.clientId, backendSecret: sim.secret }));
  await new Promise(r => server.listen(17291, '127.0.0.1', r));
  relayUrl = 'http://127.0.0.1:17291';
});
after(() => { server?.close(); sim?.close(); });

const post = (p, body) => fetch(relayUrl + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

test('the relay reports its configuration but never the secret', async () => {
  const c = await (await fetch(`${relayUrl}/api/config`)).json();
  assert.deepEqual(Object.keys(c).sort(), ['clientId', 'issuer', 'palm']);
  assert.equal(c.palm, true);
});

test('the relay forwards only Veyns Call actions', async () => {
  const r = await post('/api/palm/request', { human: 'someone', key: 'abcdefgh', statement: 'Send 10 BTC to Mallory', details: { app: 'veyns-call', kind: 'call' } });
  assert.equal(r.status, 400);
  const r2 = await post('/api/palm/request', { human: 'someone', key: 'abcdefgh', statement: 'Start a call on Veyns Call', details: { app: 'other', kind: 'call' } });
  assert.equal(r2.status, 400);
});

test('a node can request and poll a palm scan through the relay', async () => {
  // Enroll a simulated palm so Veyns has a scanner for this person.
  const { token } = await (await fetch(`${sim.issuer}/signin`, { method: 'POST', body: JSON.stringify({ client: sim.clientId, nonce: 'n', label: 'Relay' }) })).json();
  const human = JSON.parse(Buffer.from(token.split('.')[1], 'base64url')).sub;
  const requester = createRelayRequester({ relay: relayUrl });
  const action = callAction({ callId: 'c1', from: 'a', to: 'b', video: false, nonce: 'n', createdAt: 1 });
  const { requestId } = await requester.request({ human, ...action, key: 'relay-test-1' });
  assert.equal((await requester.poll(requestId)).status, 'pending');
  await fetch(`${sim.issuer}/approve/${requestId}`, { method: 'POST', redirect: 'manual' });
  const done = await requester.poll(requestId);
  assert.equal(done.status, 'approved');
  assert.match(done.decision, /^[\w-]+\.[\w-]+\.[\w-]+$/);
});
