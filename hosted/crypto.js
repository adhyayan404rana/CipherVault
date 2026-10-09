'use strict';
// Shared browser cryptography. Never uploads plaintext, passwords or unwrapped keys.
(() => {
  const MAX = 20*1024*1024, encoder = new TextEncoder();
  const seconds = start => (performance.now()-start)/1000;
  const random = n => crypto.getRandomValues(new Uint8Array(n));
  const hex = value => Array.from(new Uint8Array(value),x=>x.toString(16).padStart(2,'0')).join('');
  const b64 = value => { let text=''; for(const byte of new Uint8Array(value)) text+=String.fromCharCode(byte); return btoa(text); };
  const un64 = text => Uint8Array.from(atob(text),c=>c.charCodeAt(0));
  const concat = (...arrays) => { const out=new Uint8Array(arrays.reduce((n,a)=>n+a.length,0)); let at=0; for(const a of arrays){out.set(a,at);at+=a.length;} return out; };
  const safeName = name => {
    let value=String(name).replaceAll('\\','/').split('/').pop().replace(/[^A-Za-z0-9._ -]/g,'_').replace(/^[ .]+|[ .]+$/g,'').slice(0,120);
    return !value || /^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])$/i.test(value.split('.')[0]) ? 'file.bin' : value;
  };
  function check(data){if(!(data instanceof Uint8Array)||data.length>MAX)throw Error('File limit: 20 MiB.');}
  async function hash(data){const start=performance.now();return {value:hex(await crypto.subtle.digest('SHA-256',data)),seconds:seconds(start)};}
  async function derive(password,salt){
    if(typeof password!=='string'||[...password].length<12||[...password].length>1024)throw Error('Use a password of 12–1024 characters.');
    const material=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveKey']);
    return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:600000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  }
  async function rawKey(bytes){if(!(bytes instanceof Uint8Array)||bytes.length!==32)throw Error('AES-256 key file must contain exactly 32 raw bytes.');return crypto.subtle.importKey('raw',bytes,'AES-GCM',false,['encrypt','decrypt']);}
  async function encrypt(data,password,filename,keyBytes=null){
    check(data); const start=performance.now(),salt=keyBytes?new Uint8Array():random(16),nonce=random(12);
    const setupStart=performance.now(),key=keyBytes?await rawKey(keyBytes):await derive(password,salt),keySetup=seconds(setupStart);
    const digest=await hash(data),meta={version:1,algorithm:'AES-256-GCM',kdf:keyBytes?'RAW-KEY':'PBKDF2-SHA256',iterations:keyBytes?0:600000,salt:b64(salt),nonce:b64(nonce),filename:safeName(filename),size:data.length,sha256:digest.value};
    const header=encoder.encode(JSON.stringify(meta)),prefix=new Uint8Array(9);prefix.set(encoder.encode('CVLT1'));new DataView(prefix.buffer).setUint32(5,header.length);
    const aad=concat(prefix,header),aesStart=performance.now(),cipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:aad,tagLength:128},key,data));
    return {package:concat(aad,cipher),metadata:meta,aes_seconds:seconds(aesStart),hash_seconds:digest.seconds,key_setup_seconds:keySetup,seconds:seconds(start)};
  }
  function parse(input){
    const data=input instanceof Uint8Array?input:new Uint8Array(input),decode=new TextDecoder('utf-8',{fatal:true});
    if(data.length<25||data.length>MAX+4096||decode.decode(data.slice(0,5))!=='CVLT1')throw Error('Invalid CipherVault package.');
    const length=new DataView(data.buffer,data.byteOffset,data.byteLength).getUint32(5);
    if(length<1||length>2048||data.length<9+length+16)throw Error('Invalid package header.');
    const meta=JSON.parse(decode.decode(data.slice(9,9+length))),fields=['version','algorithm','kdf','iterations','salt','nonce','filename','size','sha256'];
    if(!meta||Object.keys(meta).length!==fields.length||fields.some(k=>!(k in meta))||meta.version!==1||meta.algorithm!=='AES-256-GCM'||!['RAW-KEY','PBKDF2-SHA256'].includes(meta.kdf))throw Error('Unsupported package.');
    if(!Number.isInteger(meta.size)||meta.size<0||meta.size>MAX||data.length!==9+length+meta.size+16||typeof meta.filename!=='string'||safeName(meta.filename)!==meta.filename||typeof meta.sha256!=='string'||!/^[0-9a-f]{64}$/.test(meta.sha256))throw Error('Invalid metadata.');
    const salt=un64(meta.salt),nonce=un64(meta.nonce);
    if(nonce.length!==12||(meta.kdf==='RAW-KEY'?(salt.length!==0||meta.iterations!==0):(salt.length!==16||meta.iterations!==600000)))throw Error('Invalid key parameters.');
    return {meta,salt,nonce,aad:data.slice(0,9+length),cipher:data.slice(9+length)};
  }
  async function decrypt(packageBytes,password,keyBytes=null){
    const start=performance.now(),{meta,salt,nonce,aad,cipher}=parse(packageBytes),setupStart=performance.now();
    const key=meta.kdf==='RAW-KEY'?await rawKey(keyBytes):await derive(password,salt),keySetup=seconds(setupStart),aesStart=performance.now();
    let data;
    try{data=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:nonce,additionalData:aad,tagLength:128},key,cipher));}
    catch(_){throw Error('Authentication failed: wrong password/key file or modified package.');}
    const aesSeconds=seconds(aesStart),digest=await hash(data);
    if(digest.value!==meta.sha256)throw Error('Recovered SHA-256 mismatch.');
    return {data,metadata:meta,sha256:digest.value,aes_seconds:aesSeconds,hash_seconds:digest.seconds,key_setup_seconds:keySetup,seconds:seconds(start)};
  }
  const rsaOptions={name:'RSA-PSS',modulusLength:3072,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'};
  async function generateIdentity(password,userId){
    const start=performance.now(),keyStart=performance.now(),pair=await crypto.subtle.generateKey(rsaOptions,true,['sign','verify']),keySeconds=seconds(keyStart);
    const publicBytes=new Uint8Array(await crypto.subtle.exportKey('spki',pair.publicKey)),privateBytes=new Uint8Array(await crypto.subtle.exportKey('pkcs8',pair.privateKey)),fingerprint=await hash(publicBytes);
    const salt=random(16),nonce=random(12),wrapStart=performance.now(),wrappingKey=await derive(password,salt),aad=encoder.encode('CipherVault signing identity:'+userId);
    const wrapped=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:aad},wrappingKey,privateBytes));privateBytes.fill(0);
    return {public_key:b64(publicBytes),fingerprint:fingerprint.value,wrapped_key:{salt:b64(salt),nonce:b64(nonce),ciphertext:b64(wrapped),iterations:600000},key_seconds:keySeconds,wrap_seconds:seconds(wrapStart),fingerprint_seconds:fingerprint.seconds,seconds:seconds(start)};
  }
  async function unlockIdentity(profile,password,userId){
    const start=performance.now(),wrap=profile.wrapped_key;
    if(!wrap||wrap.iterations!==600000||un64(wrap.salt).length!==16||un64(wrap.nonce).length!==12)throw Error('Invalid signing-key envelope.');
    const wrappingKey=await derive(password,un64(wrap.salt));let plain;
    try{plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:un64(wrap.nonce),additionalData:encoder.encode('CipherVault signing identity:'+userId)},wrappingKey,un64(wrap.ciphertext)));}
    catch(_){throw Error('Signing-key passphrase is incorrect or the encrypted identity was modified.');}
    try{return {key:await crypto.subtle.importKey('pkcs8',plain,{name:'RSA-PSS',hash:'SHA-256'},false,['sign']),seconds:seconds(start)};}
    finally{plain.fill(0);}
  }
  async function sign(data,key){const start=performance.now();return {signature:new Uint8Array(await crypto.subtle.sign({name:'RSA-PSS',saltLength:350},key,data)),seconds:seconds(start)};}
  async function verify(data,signature,publicBytes){
    const start=performance.now(),key=await crypto.subtle.importKey('spki',publicBytes,{name:'RSA-PSS',hash:'SHA-256'},false,['verify']);
    const bits=key.algorithm.modulusLength;
    if(bits<2048||bits>4096)throw Error('Expected a 2048–4096-bit RSA public key.');
    return {valid:await crypto.subtle.verify({name:'RSA-PSS',saltLength:Math.ceil((bits-1)/8)-32-2},key,signature,data),seconds:seconds(start)};
  }
  function pem(publicBytes){const text=b64(publicBytes);return '-----BEGIN PUBLIC KEY-----\n'+text.match(/.{1,64}/g).join('\n')+'\n-----END PUBLIC KEY-----\n';}
  function readPem(text){if(text.length>8192||!text.includes('-----BEGIN PUBLIC KEY-----'))throw Error('Choose an RSA public PEM key.');return un64(text.replace(/-----[A-Z ]+-----/g,'').replace(/\s/g,''));}
  function preview(data,limit=512){const bytes=new Uint8Array(data).slice(0,limit);try{const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);if(/[\x00-\x08\x0e-\x1f]/.test(text))throw Error('binary');return text||'(empty file)';}catch(_){return 'Binary bytes (hex): '+hex(bytes);}}
  const api={MAX,seconds,random,hex,b64,un64,concat,safeName,hash,derive,encrypt,decrypt,parse,generateIdentity,unlockIdentity,sign,verify,pem,readPem,preview};
  globalThis.CVcrypto=api;
  if(typeof module!=='undefined')module.exports=api;
})();
