'use strict';
const el = id => document.getElementById(id);
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const hex = b => Array.from(new Uint8Array(b), n => n.toString(16).padStart(2,'0')).join('');
let blobUrl;
el('receive').onclick = async () => {
  const begin = performance.now(); let claimed = false;
  el('receive').disabled = true; el('download').hidden = true;
  for (const id of ['encrypted_preview','decrypted_preview','signature_preview']) el(id).textContent = '';
  if (blobUrl) { URL.revokeObjectURL(blobUrl); blobUrl = undefined; }
  try {
    if (!window.isSecureContext || !crypto.subtle) throw Error('Trust the HTTPS certificate to enable browser cryptography. See README.');
    const token = el('token').value.trim(), password = el('password').value;
    const trustedFingerprint = el('signing_fingerprint').value.trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(trustedFingerprint)) throw Error('Enter the trusted signing-key fingerprint shown on the sender.');
    if (!/^[A-Za-z0-9_-]{43}$/.test(token) || [...password].length < 12) throw Error('Enter a valid token and password of at least 12 characters.');
    el('status').textContent = 'Receiving encrypted package…';
    const networkStart = performance.now();
    const response = await fetch('/claim', {method:'POST', headers:{Authorization:'Bearer '+token}, body:'', signal:AbortSignal.timeout(60000)});
    if (!response.ok) throw Error('Transfer rejected: unauthorized, expired, or already used token.');
    claimed = true;
    const receipt = response.headers.get('X-Receipt-Token');
    const length = Number(response.headers.get('Content-Length'));
    if (!Number.isInteger(length) || length < 25 || length > 20*1024*1024+4096) throw Error('Invalid transfer size.');
    const buffer = await response.arrayBuffer();
    const packageNetworkSeconds = (performance.now()-networkStart)/1000;
    if (buffer.byteLength !== length) throw Error('Incomplete transfer.');
    const data = new Uint8Array(buffer), view = new DataView(buffer);
    const decoder = new TextDecoder('utf-8', {fatal:true});
    if (decoder.decode(data.slice(0,5)) !== 'CVLT1') throw Error('Invalid package.');
    const hlen = view.getUint32(5);
    if (hlen < 1 || hlen > 2048 || data.length < 9+hlen+16) throw Error('Invalid header.');
    const meta = JSON.parse(decoder.decode(data.slice(9,9+hlen)));
    const fields = ['version','algorithm','kdf','iterations','salt','nonce','filename','size','sha256'];
    if (Object.keys(meta).length !== fields.length || fields.some(k=>!(k in meta)) || meta.version !== 1 || meta.algorithm !== 'AES-256-GCM' || meta.kdf !== 'PBKDF2-SHA256' || meta.iterations !== 600000) throw Error('Unsupported package.');
    if (!Number.isInteger(meta.size) || meta.size < 0 || meta.size > 20*1024*1024 || data.length !== 9+hlen+meta.size+16 || typeof meta.filename !== 'string' || !/^[A-Za-z0-9._ -]{1,120}$/.test(meta.filename) || typeof meta.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(meta.sha256)) throw Error('Invalid metadata.');
    const salt = b64(meta.salt), nonce = b64(meta.nonce);
    if (salt.length !== 16 || nonce.length !== 12) throw Error('Invalid KDF salt or nonce.');
    el('encrypted_preview').textContent = hex(data.slice(9+hlen,9+hlen+Math.min(meta.size,256))) || '(empty plaintext; package still contains an authentication tag)';
    const proofNetworkStart = performance.now();
    const proofResponse = await fetch('/proof',{method:'POST',headers:{Authorization:'Bearer '+receipt},body:'',signal:AbortSignal.timeout(15000)});
    if (!proofResponse.ok || Number(proofResponse.headers.get('Content-Length'))>8192) throw Error('Signature proof unavailable.');
    const proof = await proofResponse.json();
    const networkSeconds = packageNetworkSeconds+(performance.now()-proofNetworkStart)/1000;
    if (typeof proof.message !== 'string' || proof.message.length>2048 || typeof proof.signature !== 'string' || proof.signature.length>1024 || typeof proof.public_key !== 'string' || proof.public_key.length>2048 || proof.salt_length !== 350) throw Error('Invalid signature proof.');
    const publicBytes = b64(proof.public_key), signedMessage = b64(proof.message);
    const proofHashStart = performance.now();
    const fingerprint = hex(await crypto.subtle.digest('SHA-256',publicBytes));
    const packageDigest = hex(await crypto.subtle.digest('SHA-256',data));
    const proofHashSeconds = (performance.now()-proofHashStart)/1000;
    if (fingerprint !== trustedFingerprint) throw Error('Signing public key does not match the trusted fingerprint.');
    const verifyStart = performance.now();
    const publicKey = await crypto.subtle.importKey('spki',publicBytes,{name:'RSA-PSS',hash:'SHA-256'},false,['verify']);
    const signatureValid = await crypto.subtle.verify({name:'RSA-PSS',saltLength:350},publicKey,b64(proof.signature),signedMessage);
    const signatureSeconds = (performance.now()-verifyStart)/1000;
    const manifest = JSON.parse(decoder.decode(signedMessage));
    if (!signatureValid || manifest.package_sha256 !== packageDigest || manifest.original_sha256 !== meta.sha256 || manifest.filename !== meta.filename || typeof manifest.published_at !== 'string' || !Number.isFinite(Date.parse(manifest.published_at))) throw Error('Digital signature verification failed or signed package was modified.');
    el('signature_preview').textContent = proof.signature;
    const decryptStart = performance.now();
    const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations:600000, hash:'SHA-256'}, material, {name:'AES-GCM',length:256}, false, ['decrypt']);
    const aesStart = performance.now();
    const plain = await crypto.subtle.decrypt({name:'AES-GCM', iv:nonce, additionalData:data.slice(0,9+hlen), tagLength:128}, key, data.slice(9+hlen));
    const aesSeconds = (performance.now()-aesStart)/1000;
    const decryptSeconds = (performance.now()-decryptStart)/1000;
    el('password').value = '';
    const hashStart = performance.now();
    const digest = hex(await crypto.subtle.digest('SHA-256', plain));
    const hashSeconds = (performance.now()-hashStart)/1000;
    if (digest !== meta.sha256) throw Error('Recovered hash mismatch.');
    const receivedAt = new Date().toISOString();
    const preview = new Uint8Array(plain).slice(0,512);
    let recoveredPreview;
    try { recoveredPreview = decoder.decode(preview); if (/[\x00-\x08\x0e-\x1f]/.test(recoveredPreview)) throw Error('binary'); }
    catch (_) { recoveredPreview = 'Binary bytes (hex): '+hex(preview); }
    el('decrypted_preview').textContent = recoveredPreview || '(empty file)';
    const receiveSeconds = (performance.now()-begin)/1000;
    blobUrl = URL.createObjectURL(new Blob([plain], {type:'application/octet-stream'}));
    el('download').href = blobUrl; el('download').download = meta.filename; el('download').hidden = false;
    el('status').textContent = `Authenticated recovery succeeded · ${meta.size} bytes\nSHA-256: ${digest}\nSender hash matches: YES\nNetwork request + complete body: ${(networkSeconds*1000).toFixed(3)} ms\nAES decryption: ${(aesSeconds*1000).toFixed(3)} ms\nDecryption workflow (includes KDF): ${(decryptSeconds*1000).toFixed(3)} ms\nSHA-256: ${(hashSeconds*1000).toFixed(3)} ms\nReceive + recovery: ${(receiveSeconds*1000).toFixed(3)} ms\nNetwork throughput: ${(data.length/1e6/networkSeconds).toFixed(3)} MB/s (package bytes / 1,000,000 / seconds)`;
    el('status').textContent += `\nFile successfully transferred and recovered\nOriginal SHA-256: ${meta.sha256}\nDigital signature: VERIFIED (trusted RSA-PSS key)\nSigning-key fingerprint: ${fingerprint}\nPublished at (sender UTC): ${manifest.published_at}\nRecovered at (receiver UTC): ${receivedAt}\nProof fingerprint + package hashing: ${(proofHashSeconds*1000).toFixed(3)} ms\nRSA-PSS verification (includes import and SHA-256): ${(signatureSeconds*1000).toFixed(3)} ms\nNetwork timing includes package and signature-proof requests.`;
    try {
      const ack = await fetch('/receipt', {method:'POST',headers:{Authorization:'Bearer '+receipt,'Content-Type':'application/json'},body:JSON.stringify({sha256:digest,network_seconds:networkSeconds,decrypt_seconds:decryptSeconds,hash_seconds:hashSeconds,receive_seconds:receiveSeconds,signature_valid:true,signature_seconds:signatureSeconds,received_at:receivedAt}),signal:AbortSignal.timeout(15000)});
      if (!ack.ok) el('status').textContent += '\nSender receipt rejected; recovery remains successful.';
    } catch (_) { el('status').textContent += '\nCould not deliver sender receipt; recovery remains successful.'; }
  } catch (error) {
    el('password').value = '';
    el('status').textContent = `FAILED: ${error.name === 'OperationError' ? 'Authentication failed: incorrect password or tampered ciphertext.' : error.message}\nElapsed until failure: ${(performance.now()-begin).toFixed(3)} ms${claimed ? '\nToken consumed. Ask sender to publish a new transfer.' : ''}`;
  } finally { el('receive').disabled = false; }
};
