// One real Veyns Call node on the public Hyperswarm DHT, palm scans from real Veyns via the relay.
import fs from 'node:fs';
import { startNode } from './src/node.js';

// Read only our own .env; never a machine-wide variable.
const env = {};
if (fs.existsSync('.env')) {
  for (const line of fs.readFileSync('.env', 'utf8').split(/\r?\n/)) {
    const m = /^\s*([A-Z_]+)\s*=\s*(.*)\s*$/.exec(line);
    if (m) env[m[1]] = m[2].replace(/^"(.*)"$/, '$1');
  }
}
const issuer = (env.VEYNS_ISSUER || 'https://sandbox.id.veyns.io').replace(/\/$/, '');
// The client ID is the node's trust anchor: palm proofs must be issued for exactly this app.
// It is pinned here, never fetched from the relay, so a hostile relay cannot change whom we trust.
const clientId = env.VEYNS_CLIENT_ID;
const relay = env.VEYNS_CALL_RELAY;
if (!clientId || (!relay && !env.VEYNS_BACKEND_SECRET)) {
  console.error('Set VEYNS_CLIENT_ID and VEYNS_CALL_RELAY in .env (see .env.example). For a local demo run `npm run dev`.');
  process.exit(1);
}
await startNode({
  name: env.VEYNS_CALL_NAME || 'me',
  port: Number(env.VEYNS_CALL_PORT || 7100),
  dataDir: env.VEYNS_CALL_DATA || 'data/me',
  issuer,
  clientId,
  relay,
  backendSecret: relay ? undefined : env.VEYNS_BACKEND_SECRET,
  log: console.log,
});
