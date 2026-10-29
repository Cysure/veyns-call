import { EventEmitter } from 'node:events';
import {
  b64, unb64, sha256, sign, verify, identityId, canonicalJson,
  ephemeral, encapsulate, decapsulate, dh, deriveSessionKeys, frameCipher,
} from './pq.js';

/**
 * A post-quantum channel over one Hyperswarm connection.
 *
 * Hyperswarm already wraps the socket in Noise (X25519 / ChaCha20). That is not
 * quantum safe, so this layer runs its own hybrid handshake inside it and encrypts
 * every frame again with keys from ML-KEM-768 + X25519, bound to the Noise handshake
 * hash so the two layers cannot be split apart and relayed.
 *
 *   1. both sides send HELLO: card + ephemeral ML-KEM and X25519 keys, ML-DSA signed
 *   2. both sides send KEM:   a ciphertext encapsulated to the other's ML-KEM key, signed
 *   3. both derive keys; every later frame is AES-256-GCM sealed
 *
 * Frames on the wire: 4-byte big-endian length, then the body.
 * Sealed bodies: 1 type byte (0 = JSON, 1 = media), then the payload.
 */

const MAX_FRAME = 4 * 1024 * 1024;
const HANDSHAKE_MS = 15_000;

export class Channel extends EventEmitter {
  constructor(socket, { keys, card }) {
    super();
    this.socket = socket;
    this.keys = keys;
    this.card = card;
    this.myId = identityId(keys.sigPub);
    this.eph = ephemeral();
    this.state = 'hello';
    this.peerCard = null;
    this.peerId = null;
    this.buffer = Buffer.alloc(0);
    this.noise = Buffer.from(socket.handshakeHash || Buffer.alloc(32));

    this.timer = setTimeout(() => this.close('handshake timed out'), HANDSHAKE_MS);
    socket.on('data', data => this.onData(data));
    socket.on('error', () => {});
    socket.on('close', () => this.onClose());

    this.myHello = {
      t: 'hello',
      card,
      kemPub: b64(this.eph.kemPub),
      dhPub: b64(this.eph.dhPub),
    };
    this.myHello.sig = sign(keys.sigSec, 'hello', this.helloSigned(this.myHello));
    this.writeRaw(Buffer.from(JSON.stringify(this.myHello)));
  }

  helloSigned(h) {
    return { kemPub: h.kemPub, dhPub: h.dhPub, noise: b64(this.noise), card: identityId(h.card.sigPub) };
  }

  writeRaw(body) {
    if (this.socket.destroyed) return;
    const head = Buffer.alloc(4);
    head.writeUInt32BE(body.length);
    this.socket.write(Buffer.concat([head, body]));
  }

  onData(data) {
    this.buffer = Buffer.concat([this.buffer, data]);
    while (this.buffer.length >= 4) {
      const length = this.buffer.readUInt32BE(0);
      if (length > MAX_FRAME) return this.close('frame too large');
      if (this.buffer.length < 4 + length) return;
      const frame = this.buffer.subarray(4, 4 + length);
      this.buffer = this.buffer.subarray(4 + length);
      try {
        this.onFrame(frame);
      } catch (error) {
        return this.close(`protocol error: ${error.message}`);
      }
    }
  }

  onFrame(frame) {
    if (this.state === 'ready') {
      const plain = this.rx.open(frame);
      if (plain[0] === 0) this.emit('message', JSON.parse(plain.subarray(1).toString('utf8')));
      else if (plain[0] === 1) this.emit('media', plain.subarray(1));
      return;
    }
    const msg = JSON.parse(frame.toString('utf8'));
    if (this.state === 'hello') {
      if (msg.t !== 'hello' || !msg.card?.sigPub) throw new Error('expected hello');
      if (!verify(msg.card.sigPub, 'hello', this.helloSigned(msg), msg.sig)) throw new Error('hello signature');
      this.peerHello = msg;
      this.peerCard = msg.card;
      this.peerId = identityId(msg.card.sigPub);
      if (this.peerId === this.myId) throw new Error('connected to myself');
      const { cipherText, sharedSecret } = encapsulate(unb64(msg.kemPub));
      this.myKemSecret = sharedSecret;
      this.myKem = { t: 'kem', ct: b64(cipherText) };
      this.myKem.sig = sign(this.keys.sigSec, 'kem', { ct: this.myKem.ct, to: msg.kemPub, noise: b64(this.noise) });
      this.writeRaw(Buffer.from(JSON.stringify(this.myKem)));
      this.state = 'kem';
      return;
    }
    if (this.state === 'kem') {
      if (msg.t !== 'kem') throw new Error('expected kem');
      if (!verify(this.peerCard.sigPub, 'kem', { ct: msg.ct, to: this.myHello.kemPub, noise: b64(this.noise) }, msg.sig)) throw new Error('kem signature');
      const theirs = decapsulate(unb64(msg.ct), this.eph.kemSec);
      const iAmLow = this.myId < this.peerId;
      const [lowHello, highHello, lowKem, highKem] = iAmLow
        ? [this.myHello, this.peerHello, this.myKem, msg]
        : [this.peerHello, this.myHello, msg, this.myKem];
      const transcript = Buffer.from(canonicalJson({
        noise: b64(this.noise),
        low: { hello: this.helloSigned(lowHello), ct: lowKem.ct },
        high: { hello: this.helloSigned(highHello), ct: highKem.ct },
      }));
      this.transcriptHash = sha256(transcript);
      const keys = deriveSessionKeys({
        mineKem: this.myKemSecret,
        theirsKem: theirs,
        dhShared: dh(this.eph.dhSec, unb64(this.peerHello.dhPub)),
        transcript,
        iAmLow,
      });
      this.tx = frameCipher(keys.send);
      this.rx = frameCipher(keys.recv);
      // Ephemeral secrets are no longer needed: drop them so a later memory read gets nothing.
      this.eph.kemSec.fill(0);
      this.eph.dhSec.fill(0);
      this.myKemSecret.fill(0);
      this.state = 'ready';
      clearTimeout(this.timer);
      this.emit('ready');
    }
  }

  send(message) {
    if (this.state !== 'ready') throw new Error('channel not ready');
    this.writeRaw(this.tx.seal(Buffer.concat([Buffer.from([0]), Buffer.from(JSON.stringify(message))])));
  }

  sendMedia(chunk) {
    if (this.state !== 'ready') return;
    this.writeRaw(this.tx.seal(Buffer.concat([Buffer.from([1]), chunk])));
  }

  close(reason = 'closed') {
    this.closeReason ??= reason;
    clearTimeout(this.timer);
    this.socket.destroy();
  }

  onClose() {
    clearTimeout(this.timer);
    if (this.state === 'closed') return;
    this.state = 'closed';
    this.emit('close', this.closeReason || 'disconnected');
  }
}
