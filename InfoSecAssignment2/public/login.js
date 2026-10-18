const { startAuthentication } = SimpleWebAuthnBrowser;
const msg = document.getElementById('msg');
const post = (url, body) => fetch(url, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body || {}),
});

document.getElementById('go').addEventListener('click', async () => {
  const userId = document.getElementById('userId').value.trim();
  try {
    const optRes = await post('/api/login/options', { userId });
    if (!optRes.ok) throw new Error((await optRes.json()).error);
    const optionsJSON = await optRes.json();
    const assertion = await startAuthentication({ optionsJSON });
    const verRes = await post('/api/login/verify', assertion);
    if (!verRes.ok) throw new Error((await verRes.json()).error);
    const me = await (await fetch('/api/me')).json();
    msg.textContent = `Signed in as ${me.name} (${me.role})`;
  } catch (e) {
    msg.textContent = e.message;
  }
});

document.getElementById('logout').addEventListener('click', async () => {
  await post('/api/logout');
  msg.textContent = 'Logged out';
});
