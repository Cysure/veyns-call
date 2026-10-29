// Veyns sign-in for a local Veyns Call node. Veyns only accepts registered origins, so the
// ceremony runs here and the token goes back to the node in the URL fragment (never sent
// to any server). The node checks the signature, its own nonce and the palm claim.
(async () => {
  const $ = id => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  const nonce = params.get('nonce');
  const back = params.get('return');
  // Only ever hand a token back to a node on this same machine.
  if (!nonce || !/^[\w-]{16,64}$/.test(nonce) || !/^http:\/\/(localhost|127\.0\.0\.1):\d{2,5}\/$/.test(back || '')) {
    $('error').textContent = 'Open this page from Veyns Call on your device.';
    return;
  }
  let config;
  try {
    config = await (await fetch('/api/config')).json();
    await new Promise((resolve, reject) => {
      const s = Object.assign(document.createElement('script'), { src: `${config.issuer}/veyns.js` });
      s.onload = () => (window.veyns ? resolve() : reject(new Error('Veyns did not load.')));
      s.onerror = () => reject(new Error('Could not reach Veyns.'));
      document.head.appendChild(s);
    });
  } catch (error) {
    $('error').textContent = error.message;
    return;
  }
  $('go').disabled = false;
  $('go').addEventListener('click', async () => {
    $('error').textContent = '';
    try {
      const { token } = await window.veyns.signin({ clientId: config.clientId, nonce, method: 'palm' });
      location.replace(`${back}#veyns_token=${encodeURIComponent(token)}`);
    } catch (error) {
      if (error.code === 'popup_blocked') $('error').textContent = 'Your browser blocked the Veyns window. Allow pop-ups for this site and try again.';
      else if (error.code !== 'cancelled') $('error').textContent = error.message || 'Veyns could not sign you in.';
    }
  });
})();
