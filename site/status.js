fetch('/api/config').then(r => r.json()).then(c => {
  document.getElementById('status').textContent = c.palm
    ? `Relay ready · Veyns client ${c.clientId}`
    : 'Relay is up, but the Veyns client ID or backend secret is not set yet.';
}).catch(() => { document.getElementById('status').textContent = 'Relay unreachable.'; });
