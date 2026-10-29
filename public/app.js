// Veyns Call UI. It only shows state and carries media; the local node enforces every gate.

const $ = id => document.getElementById(id);
let state = null;
let ws = null;
let avatar = null;

async function api(path, body) {
  const res = await fetch(path, body === undefined ? {} : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const out = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(out.error || `Request failed (${res.status})`);
  return out;
}

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const time = t => new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

/* ------------------------------------------------------------ socket */

function connect() {
  ws = new WebSocket(`ws://${location.host}/ws`);
  ws.binaryType = 'arraybuffer';
  ws.onmessage = e => {
    if (typeof e.data !== 'string') return media.receive(e.data);
    const msg = JSON.parse(e.data);
    if (msg.type === 'state') render(msg.state);
    if (msg.type === 'media-reset') media.resetRemote();
  };
  ws.onclose = () => setTimeout(connect, 1000);
}

/* ------------------------------------------------------------ render */

function render(next) {
  const prevCall = state?.call;
  state = next;
  document.title = state.me ? `Veyns Call · ${state.me.name}` : 'Veyns Call';
  $('sim-banner').hidden = !state.config.simulated;
  if (state.device) $('device-link').href = state.device;
  $('view-signin').hidden = state.stage !== 'signin';
  $('view-create').hidden = state.stage !== 'create';
  $('view-home').hidden = state.stage !== 'ready';
  if (state.stage === 'create' && !avatar) shuffleAvatar();
  if (state.stage === 'ready') renderHome();
  renderScan();
  renderCall(prevCall);
}

function renderHome() {
  const { me, contacts, invites, events, redeeming } = state;
  $('me-avatar').src = me.avatar;
  $('me-name').textContent = me.name;
  $('me-fp').textContent = me.fingerprint;

  $('contacts-count').textContent = contacts.length ? `${contacts.filter(c => c.online).length} online` : '';
  $('contacts-empty').hidden = contacts.length > 0;
  $('contacts').innerHTML = contacts.map(c => `
    <li class="contact ${c.online ? 'online' : ''}">
      <img class="avatar sm" src="${esc(c.avatar)}" alt="">
      <div class="who"><b>${esc(c.name)}</b><span class="mono"><span class="dot"></span>${c.online ? 'online' : 'offline'} · ${esc(c.fingerprint.slice(0, 9))}</span></div>
      <button class="btn ghost icon" data-call="${esc(c.id)}" data-video="0" ${c.online ? '' : 'disabled'} title="Voice call" aria-label="Voice call ${esc(c.name)}">📞</button>
      <button class="btn primary icon" data-call="${esc(c.id)}" data-video="1" ${c.online ? '' : 'disabled'} title="Video call" aria-label="Video call ${esc(c.name)}">🎥</button>
    </li>`).join('');

  $('invites').innerHTML = invites.filter(i => i.status !== 'expired').map(i => `
    <li class="invite-item">
      ${i.status === 'open' ? `<code>${esc(i.code)}</code><div class="row"><button class="btn small primary" data-copy="${esc(i.code)}">Copy code</button><button class="btn small ghost" data-revoke="${esc(i.id)}">Revoke</button><span class="mute small">expires ${time(i.expiresAt)}</span></div>`
      : i.status === 'used' ? `<span class="small">✓ Used by <b>${esc(i.usedBy)}</b></span>`
      : '<span class="mute small">Waiting for your palm…</span>'}
    </li>`).join('');
  $('redeeming').hidden = !redeeming;

  $('events').innerHTML = events.map(e => `<li class="${e.kind === 'blocked' ? 'blocked' : ''}"><time>${time(e.at)}</time><span class="k-${e.kind}"></span><span>${esc(e.text)}</span></li>`).join('');
}

const PURPOSE = { enroll: 'Bind your palm', invite: 'Sign the invite', call: 'Place the call', answer: 'Answer the call', presence: 'Prove it is still you' };

function renderScan() {
  const s = state.scans.find(x => ['requesting', 'pending'].includes(x.status));
  const failed = !s && state.scans.find(x => x.status === 'failed' && x.purpose === 'enroll');
  $('scan-sheet').hidden = !s;
  if (failed) $('create-error').textContent = failed.error;
  if (!s) return;
  $('scan-purpose').textContent = PURPOSE[s.purpose] || 'Palm scan';
  $('scan-statement').textContent = s.statement;
  $('scan-status').textContent = s.status === 'requesting' ? 'Sending the request to your scanner…' : 'Put your palm on your Veyns scanner.';
  $('scan-open').hidden = !s.approvalUrl;
  if (s.approvalUrl) $('scan-open').href = s.approvalUrl;
  $('scan-cancel').dataset.id = s.id;
}

const CALL_TEXT = {
  out: { scanning: 'Scan your palm to place the call', ringing: 'Ringing… they must scan their palm to answer', live: '', ended: 'Call ended' },
  in: { incoming: 'is calling you · their palm verified', scanning: 'Scan your palm to answer', live: '', ended: 'Call ended' },
};

function renderCall(prev) {
  const c = state.call;
  $('call').hidden = !c;
  if (!c) { media.stop(); return; }
  $('call-avatar').src = c.peer?.avatar || '';
  $('call-name').textContent = c.peer?.name || 'Unknown';
  $('call-fp').textContent = c.peer?.fingerprint || '';
  const live = c.state === 'live';
  $('call').className = `call ${live ? 'live' : ''} ${live && c.video ? 'has-video' : ''}`;
  $('local').hidden = !(live && c.video);
  $('call-state').textContent = live ? `Live · ${c.video ? 'video' : 'voice'}` : c.state === 'ended' ? `Call ended · ${c.endReason}` : CALL_TEXT[c.direction][c.state];
  $('call-answer').hidden = !(c.direction === 'in' && c.state === 'incoming');
  $('call-presence').hidden = !live;
  $('call-presence').disabled = Boolean(c.presence);
  $('call-presence').textContent = c.presence ? 'Waiting for their palm…' : "Verify it's them";
  $('call-end').textContent = c.direction === 'in' && c.state === 'incoming' ? 'Decline' : c.state === 'ended' ? 'Close' : 'End';
  const callerOk = c.proofs?.caller, calleeOk = c.proofs?.callee;
  $('call-proofs').innerHTML = [
    `<span class="proof ${callerOk ? 'ok' : ''}">${callerOk ? '✓' : '…'} Caller palm</span>`,
    `<span class="proof ${calleeOk ? 'ok' : ''}">${calleeOk ? '✓' : '…'} Answer palm</span>`,
    live ? '<span class="proof ok">🔒 ML-KEM-768 + X25519</span>' : '',
  ].join('');
  $('call-note').textContent = live ? 'Media goes peer to peer. No server can see or record this call.' : '';

  if (live && !(prev && prev.id === c.id && prev.state === 'live')) media.start(c);
  if (!live) media.stop();
}

/* ------------------------------------------------------------- media */

const media = (() => {
  let stream = null, recorder = null, ms = null, sb = null, queue = [], current = null, synthetic = null;

  const mimeFor = video => {
    const options = video ? ['video/webm;codecs=vp8,opus', 'video/webm'] : ['audio/webm;codecs=opus', 'audio/webm'];
    return options.find(m => window.MediaRecorder?.isTypeSupported(m) && window.MediaSource?.isTypeSupported(m)) || options[0];
  };

  /** No camera or microphone (or the browser refused): send a labelled test pattern so the call still proves the path. */
  function testPattern(video, label) {
    const canvas = Object.assign(document.createElement('canvas'), { width: 480, height: 360 });
    const g = canvas.getContext('2d');
    const ac = new AudioContext();
    const osc = ac.createOscillator();
    const gain = ac.createGain();
    gain.gain.value = 0.02;
    osc.frequency.value = 440;
    const dest = ac.createMediaStreamDestination();
    osc.connect(gain).connect(dest);
    osc.start();
    let t = 0;
    const timer = setInterval(() => {
      t++;
      const grad = g.createLinearGradient(0, 0, 480, 360);
      grad.addColorStop(0, '#2a1d7a'); grad.addColorStop(1, '#0a5a7a');
      g.fillStyle = grad; g.fillRect(0, 0, 480, 360);
      g.strokeStyle = '#ffffff55'; g.lineWidth = 3;
      for (let i = 0; i < 5; i++) { g.beginPath(); g.arc(240, 380, 60 + i * 40 + (t % 40), Math.PI * 1.1, Math.PI * 1.9); g.stroke(); }
      g.fillStyle = '#fff'; g.font = '600 24px system-ui'; g.textAlign = 'center';
      g.fillText(`${label} · test pattern`, 240, 170);
      g.font = '14px system-ui'; g.fillText(new Date().toLocaleTimeString(), 240, 200);
    }, 66);
    const s = video ? canvas.captureStream(15) : new MediaStream();
    for (const track of dest.stream.getAudioTracks()) s.addTrack(track);
    synthetic = () => { clearInterval(timer); osc.stop(); ac.close(); };
    return s;
  }

  async function start(c) {
    stop();
    current = c;
    resetRemote();
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: c.video });
    } catch {
      stream = testPattern(c.video, state.me.name);
    }
    if (current !== c) return stop();
    $('local').srcObject = stream;
    recorder = new MediaRecorder(stream, { mimeType: mimeFor(c.video), videoBitsPerSecond: 900_000, audioBitsPerSecond: 48_000 });
    recorder.ondataavailable = async e => {
      if (e.data.size && ws?.readyState === 1) ws.send(await e.data.arrayBuffer());
    };
    recorder.start(120);
  }

  function stop() {
    current = null;
    try { recorder?.stop(); } catch {}
    recorder = null;
    stream?.getTracks().forEach(t => t.stop());
    stream = null;
    synthetic?.();
    synthetic = null;
    $('local').srcObject = null;
    $('remote').removeAttribute('src');
    $('remote').load();
    ms = sb = null;
    queue = [];
  }

  function resetRemote() {
    queue = [];
    sb = null;
    const c = state?.call;
    if (!c || c.state !== 'live') return;
    ms = new MediaSource();
    const video = $('remote');
    video.src = URL.createObjectURL(ms);
    ms.addEventListener('sourceopen', () => {
      sb = ms.addSourceBuffer(mimeFor(c.video));
      sb.mode = 'sequence';
      sb.addEventListener('updateend', pump);
      pump();
    }, { once: true });
    video.play().catch(() => { video.muted = true; video.play().catch(() => {}); });
  }

  function pump() {
    if (!sb || sb.updating || !queue.length) return;
    try {
      sb.appendBuffer(queue.shift());
    } catch {
      queue = [];
    }
    // Stay close to real time: if the buffer runs ahead, skip forward.
    const v = $('remote');
    if (sb.buffered.length) {
      const end = sb.buffered.end(sb.buffered.length - 1);
      if (end - v.currentTime > 1.2) v.currentTime = end - 0.25;
    }
  }

  function receive(buf) {
    if (!state?.call || state.call.state !== 'live') return;
    queue.push(buf);
    if (queue.length > 200) queue.splice(0, queue.length - 200);
    pump();
  }

  return { start, stop, receive, resetRemote };
})();

/* ------------------------------------------------------------ avatar */

/** A generated avatar: a gradient with vein-like curves, unique per shuffle. */
function shuffleAvatar() {
  const r = () => Math.random();
  const h1 = Math.floor(r() * 360), h2 = (h1 + 60 + Math.floor(r() * 120)) % 360;
  const veins = Array.from({ length: 5 }, (_, i) => {
    const x = 30 + i * 17 + r() * 10, c1 = 40 + r() * 60, c2 = 100 + r() * 60;
    return `<path d="M${x} 170 C ${x + (r() - .5) * 60} ${c2}, ${x + (r() - .5) * 60} ${c1}, ${x + (r() - .5) * 40} ${10 + r() * 30}" />`;
  }).join('');
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 160 160"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="hsl(${h1} 85% 58%)"/><stop offset="1" stop-color="hsl(${h2} 85% 45%)"/></linearGradient></defs><rect width="160" height="160" fill="url(#g)"/><g fill="none" stroke="#fff" stroke-opacity=".55" stroke-width="3" stroke-linecap="round">${veins}</g></svg>`;
  avatar = `data:image/svg+xml;base64,${btoa(svg)}`;
  $('avatar-preview').src = avatar;
}

$('avatar-shuffle').addEventListener('click', shuffleAvatar);
$('avatar-file').addEventListener('change', async e => {
  const file = e.target.files[0];
  if (!file) return;
  const img = await createImageBitmap(file);
  const size = 192, canvas = Object.assign(document.createElement('canvas'), { width: size, height: size });
  const s = Math.min(img.width, img.height);
  canvas.getContext('2d').drawImage(img, (img.width - s) / 2, (img.height - s) / 2, s, s, 0, 0, size, size);
  avatar = canvas.toDataURL('image/jpeg', 0.82);
  $('avatar-preview').src = avatar;
});

/* ----------------------------------------------------------- actions */

function loadSdk() {
  if (window.veyns) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const s = Object.assign(document.createElement('script'), { src: `${state.config.issuer}/veyns.js` });
    s.onload = resolve;
    s.onerror = () => reject(new Error('Could not reach Veyns.'));
    document.head.appendChild(s);
  });
}

$('signin').addEventListener('click', async () => {
  $('signin-error').textContent = '';
  try {
    const [{ nonce }] = await Promise.all([api('/api/onboard/start', {}), loadSdk()]);
    const { token } = await window.veyns.signin({ clientId: state.config.clientId, nonce, method: 'palm' });
    render(await api('/api/onboard/signin', { token }));
  } catch (error) {
    if (error.code !== 'cancelled') $('signin-error').textContent = error.message;
  }
});

$('create-form').addEventListener('submit', async e => {
  e.preventDefault();
  $('create-error').textContent = '';
  try {
    await api('/api/onboard/create', { name: new FormData(e.target).get('name'), avatar });
  } catch (error) {
    $('create-error').textContent = error.message;
  }
});

const guard = (el, fn) => async (...args) => {
  $(el).textContent = '';
  try { await fn(...args); } catch (error) { $(el).textContent = error.message; }
};

$('invite-new').addEventListener('click', guard('invite-error', () => api('/api/invites', {})));
$('redeem-form').addEventListener('submit', guard('invite-error', async e => {
  e.preventDefault();
  await api('/api/invites/redeem', { code: new FormData(e.target).get('code') });
  e.target.reset();
}));
$('redeem-cancel').addEventListener('click', () => api('/api/invites/cancel-redeem', {}));

document.addEventListener('click', guard('invite-error', async e => {
  const t = e.target.closest('[data-call],[data-copy],[data-revoke]');
  if (!t) return;
  if (t.dataset.call) await api('/api/calls', { to: t.dataset.call, video: t.dataset.video === '1' });
  if (t.dataset.copy) { await navigator.clipboard.writeText(t.dataset.copy).catch(() => {}); t.textContent = 'Copied'; }
  if (t.dataset.revoke) await api('/api/invites/revoke', { id: t.dataset.revoke });
}));

$('scan-cancel').addEventListener('click', e => api('/api/scans/cancel', { id: e.target.dataset.id }));
$('call-answer').addEventListener('click', () => api('/api/calls/answer', { id: state.call.id }).catch(alert));
$('call-presence').addEventListener('click', () => api('/api/calls/presence', { id: state.call.id }).catch(alert));
$('call-end').addEventListener('click', () => {
  const c = state.call;
  if (!c) return;
  if (c.state === 'ended') return render({ ...state, call: null });
  api(c.direction === 'in' && c.state === 'incoming' ? '/api/calls/decline' : '/api/calls/hangup', { id: c.id });
});

api('/api/state').then(render);
connect();
