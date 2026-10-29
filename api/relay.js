import { createRelay } from '../src/relay.js';

// Vercel sends every /api/* request here (see vercel.json).
const env = process.env;
const relay = createRelay({
  issuer: (env.VEYNS_ISSUER || 'https://sandbox.id.veyns.io').replace(/\/$/, ''),
  clientId: env.VEYNS_CLIENT_ID || '',
  backendSecret: env.VEYNS_BACKEND_SECRET || '',
});

export default function handler(req, res) {
  const url = new URL(req.url, 'http://internal');
  const original = url.searchParams.get('__path');
  if (original !== null) {
    url.searchParams.delete('__path');
    req.url = `/api/${original}${url.search}`;
  }
  return relay(req, res);
}
