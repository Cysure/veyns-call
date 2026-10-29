# Veyns Call

Peer-to-peer, post-quantum voice and video calls that only palm-verified humans can place or answer.

- **Human-gated identity.** You join only through an invite from someone already on the network, and that invite is signed by their palm. You then pick a name and avatar, your device generates an ML-DSA-65 key, and your palm binds that key to you.
- **Palm to call, palm to answer.** The caller's palm scan is checked by the person being called, and the answer scan is checked by the caller. A device or AI agent that holds your key but not your palm cannot ring anyone.
- **"Verify it's them".** Mid-call, either side can ask the other to scan again. With no valid scan within 2 minutes, the call ends.
- **Quantum-safe and private.** Media goes directly between the two devices. Each connection runs a hybrid ML-KEM-768 + X25519 handshake inside Hyperswarm's Noise, and every frame is encrypted with AES-256-GCM. Veyns only ever sees generic wording plus a hash, so it never learns who calls whom.

## Run it

```bash
npm install
npm run dev     # private DHT + SIMULATED Veyns + alice :7101, bob :7102, carol :7103
npm test        # end to end on real Hyperswarm, real PQ channel, real ES256 palm tokens
```

In dev mode, "scanning a palm" means pressing a button on the simulated Veyns: <http://localhost:7190/approve/…>, or each person's scanner page at `/device/<id>`. Every page says **SIMULATED**.

For a real node: copy `.env.example` to `.env`, fill in a Veyns client ID and backend secret, then run `npm start`. It uses the public Hyperswarm DHT.

## Stack

| Layer | What |
|---|---|
| Network | `hyperswarm` / `hyperdht` (Holepunch, the stack under Keet): discovery, NAT hole-punching, Noise |
| PQ layer | `@noble/post-quantum`: ML-DSA-65 identities, ML-KEM-768 + X25519 (`@noble/curves`) per connection; Node HKDF-SHA-256 and AES-256-GCM |
| Palm | Veyns approvals API. A proof is the ES256 decision token, which any peer verifies against Veyns' JWKS |
| Media | Browser `MediaRecorder` (WebM VP8/Opus) → local node → PQ channel → peer → `MediaSource`. WebRTC is not used because DTLS-SRTP is not quantum-safe |
| UI | Plain HTML/CSS/JS served by each person's own node on localhost |

## How a call is gated

```
caller node                                          callee node
  offer = {callId, from, to, nonce, createdAt}
  palm scan: "Start a call on Veyns Call" + H(offer)
  ── call{offer, palmProof, ML-DSA sig} ──────────►  verify: sig, Veyns signature + issuer + app,
                                                      palm amr, digest == H(offer), subject == caller's
                                                      enrolled palm, scan < 180 s old, not replayed
                                                      ── otherwise: blocked, logged, nothing rings
                                                     palm scan: "Answer a call on Veyns Call" + H(offer)
  verify the same way ◄──────── answer{palmProof} ──
  live                                                live
```

Media is forwarded only while the node's call is `live`. Media that arrives while a call is still ringing, or from anyone other than the verified peer, is dropped by the node, not by the UI.

## What this does not do yet (honest limits)

1. **The palm gate does not yet prove a live, physical palm.** In the Veyns sandbox, decisions come back with no scanner attestation and no presentation-attack-detection (PAD) result (`sensorEvidence: none`). A proof shows that the Veyns account holder approved through the palm flow. It does not show that an attested sensor read a real hand. Don't claim deepfake-proof until Veyns ships attested scanners.
2. **A palm gates the start of a call and the presence checks, not every frame.** Once a call is live, a verified human could still play synthetic audio or video. "Verify it's them" narrows that window but does not close it.
3. **Palm proofs are signed with ES256, which is classical.** Confidentiality is post-quantum. The palm proof's own signature is only as quantum-safe as Veyns' signing key. Every proof is also wrapped in the sender's ML-DSA-65 signature.
4. **Every node holds the Veyns backend secret.** Production needs a small palm relay that holds the secret and only creates and polls requests. The relay could refuse service, but it cannot forge a scan, because peers verify Veyns' signature themselves.
5. **Keys are stored unencrypted** in `data/<name>/node.json`. They still need to be sealed with a device key (OS keystore, Secure Enclave or StrongBox).
6. **Peers see each other's IP addresses**, as in any direct P2P call. Hiding them would mean relaying calls.
7. **Invites need the inviter online** when the invitee redeems.
8. **There is no forward-secret rekeying per call.** Each connection has fresh ephemeral keys, but a long-lived connection reuses its keys across calls.
9. **Not packaged yet.** Next step is the Pear runtime on desktop and Bare / `bare-kit` on iOS and Android.
