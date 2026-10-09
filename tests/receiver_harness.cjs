// Run the actual receiver script with Node Web Crypto and a minimal DOM adapter.
// This verifies browser-code behavior, not certificate installation or mobile UI.
const fs = require('node:fs');
const { webcrypto } = require('node:crypto');
const { performance } = require('node:perf_hooks');
const nativeFetch = global.fetch;
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const nodes = Object.fromEntries(['token','password','signing_fingerprint','encrypted_preview','decrypted_preview','signature_preview','receive','download','status'].map(id => [id, {value:'',hidden:true,textContent:''}]));
nodes.token.value = input.token;
nodes.password.value = input.password;
nodes.signing_fingerprint.value = input.fingerprint;
global.document = {getElementById: id => nodes[id]};
global.window = {isSecureContext:true};
Object.defineProperty(global, 'crypto', {value:webcrypto, configurable:true});
global.performance = performance;
global.fetch = async (url, options) => {
  const response = await nativeFetch(url.startsWith('/') ? input.base+url : url, options);
  if (url === '/proof' && input.mode === 'bad_signature') {
    const proof = await response.json();
    const changed = Buffer.from(proof.signature,'base64'); changed[0] ^= 1;
    proof.signature = changed.toString('base64');
    return new Response(JSON.stringify(proof),{status:200});
  }
  return response;
};
require('../receiver/receiver.js');
(async () => {
  await nodes.receive.onclick();
  let recovered = null;
  if (!nodes.download.hidden) recovered = Buffer.from(await (await nativeFetch(nodes.download.href)).arrayBuffer()).toString('base64');
  process.stdout.write(JSON.stringify({status:nodes.status.textContent, hidden:nodes.download.hidden, recovered, passwordCleared:nodes.password.value==='', decryptedPreview:nodes.decrypted_preview.textContent, encryptedPreview:nodes.encrypted_preview.textContent, signaturePreview:nodes.signature_preview.textContent}));
  if (nodes.download.href) URL.revokeObjectURL(nodes.download.href);
})().catch(err => { console.error(err); process.exitCode=1; });
