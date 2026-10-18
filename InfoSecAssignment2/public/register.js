const { startRegistration } = SimpleWebAuthnBrowser;
const msg = document.getElementById('msg');
const post = (url, body) => fetch(url, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

document.getElementById('go').addEventListener('click', async () => {
  const userId = document.getElementById('userId').value.trim();
  const code = document.getElementById('code').value.trim();
  try {
    const optRes = await post('/api/register/options', { userId, code });
    if (!optRes.ok) throw new Error((await optRes.json()).error);
    const optionsJSON = await optRes.json();
    const attestation = await startRegistration({ optionsJSON });
    const verRes = await post('/api/register/verify', attestation);
    const out = await verRes.json();
    msg.textContent = verRes.ok ? 'Passkey registered.' : out.error;
  } catch (e) {
    msg.textContent = e.message;
  }
});
