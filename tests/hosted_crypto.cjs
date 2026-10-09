const {webcrypto}=require('node:crypto');
Object.defineProperty(global,'crypto',{value:webcrypto});
const fs=require('node:fs'),C=require('../hosted/crypto.js');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
(async()=>{
  const key=input.key?C.un64(input.key):null,data=C.un64(input.data),packageBytes=C.un64(input.package);
  const recovered=await C.decrypt(packageBytes,input.password,key);
  const encrypted=await C.encrypt(data,input.password,'interop.bin',key);
  const hash=await C.hash(data);
  const verified=await C.verify(data,C.un64(input.signature),C.un64(input.public_key));
  const privateKey=await crypto.subtle.importKey('pkcs8',C.un64(input.private_key),{name:'RSA-PSS',hash:'SHA-256'},false,['sign']);
  const signed=await C.sign(data,privateKey);
  let wrongRejected=false;
  try{await C.decrypt(packageBytes,'an incorrect password',key?new Uint8Array(32):null);}catch(_){wrongRejected=true;}
  process.stdout.write(JSON.stringify({recovered:C.b64(recovered.data),package:C.b64(encrypted.package),digest:hash.value,
    signature:C.b64(signed.signature),valid:verified.valid,wrongRejected,encrypt_seconds:encrypted.seconds,decrypt_seconds:recovered.seconds,
    hash_seconds:hash.seconds,sign_seconds:signed.seconds,verify_seconds:verified.seconds}));
})().catch(error=>{console.error(error.message);process.exitCode=1;});
