// Development network on one machine: a private DHT, the SIMULATED Veyns issuer,
// and three people's nodes. Each node is a separate swarm peer with its own keys.
import createTestnet from 'hyperdht/testnet.js';
import { startSimIssuer } from '../src/sim-issuer.js';
import { startNode } from '../src/node.js';

const testnet = await createTestnet(3);
const sim = await startSimIssuer({ port: 7190, dataDir: 'data/dev/sim-issuer' });
const people = [['alice', 7101], ['bob', 7102], ['carol', 7103]];
const nodes = [];
for (const [name, port] of people) {
  nodes.push(await startNode({
    name, port, dataDir: `data/dev/${name}`,
    issuer: sim.issuer, clientId: sim.clientId, backendSecret: sim.secret, simulated: true,
    bootstrap: testnet.bootstrap, log: console.log,
  }));
}
console.log(`\nSimulated Veyns: ${sim.issuer}`);
for (const n of nodes) console.log(`  ${n.url}`);

const stop = async () => {
  await Promise.all(nodes.map(n => n.close()));
  sim.close();
  await testnet.destroy();
  process.exit(0);
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
