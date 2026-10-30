'use strict';
// Portable transfer evidence. No plaintext, passwords, or private keys enter this file.
const CVevidence=(()=>{
  const C=globalThis.CVcrypto,encoder=new TextEncoder(),decoder=new TextDecoder('utf-8',{fatal:true});
  async function digest(bytes){return (await C.hash(bytes)).value;}
  async function senderEventHash(message,signature){return digest(C.concat(C.un64(message),C.un64(signature)));}
  async function receiptPayload(row,recoveredSha,stamp){
    return {version:1,transfer_id:row.id,recipient_id:row.recipient_id,
      manifest_sha256:await digest(C.un64(row.message)),sender_event_sha256:await senderEventHash(row.message,row.signature),
      package_sha256:row.manifest.package_sha256,recovered_sha256:recoveredSha,recovered_at:stamp};
  }
  function bundle(row){
    return {format:'CipherVault chain of custody',version:1,transfer_id:row.id,
      sender:{message:row.message,signature:row.signature,public_key:row.public_key,fingerprint:row.fingerprint},
      receiver:row.receipt?.attestation_message?{
        message:row.receipt.attestation_message,signature:row.receipt.attestation_signature,
        public_key:row.receipt.recipient_public_key,fingerprint:row.receipt.recipient_fingerprint,
        recorded_at:row.receipt.recorded_at}:null,verifiers:[]};
  }
  async function eventHash(event){return digest(C.concat(C.un64(event.message),C.un64(event.signature)));}
  async function verify(bundle){
    if(!bundle||bundle.format!=='CipherVault chain of custody'||bundle.version!==1||!bundle.sender)throw Error('Unsupported evidence bundle.');
    const sender=bundle.sender,publicBytes=C.un64(sender.public_key),message=C.un64(sender.message),signature=C.un64(sender.signature);
    if(await digest(publicBytes)!==sender.fingerprint)throw Error('Sender public-key fingerprint mismatch.');
    if(!(await C.verify(message,signature,publicBytes)).valid)throw Error('Sender signature is invalid.');
    const manifest=JSON.parse(decoder.decode(message));
    if(manifest.id!==bundle.transfer_id||!manifest.sender_id||!manifest.recipient_id||!manifest.package_sha256||!manifest.original_sha256)throw Error('Signed manifest does not match this transfer.');
    let previousHash=await eventHash(sender),receipt=null;
    if(bundle.receiver){
    const receiver=bundle.receiver,recipientBytes=C.un64(receiver.public_key),receiptBytes=C.un64(receiver.message);
    if(await digest(recipientBytes)!==receiver.fingerprint)throw Error('Receiver public-key fingerprint mismatch.');
    if(!(await C.verify(receiptBytes,C.un64(receiver.signature),recipientBytes)).valid)throw Error('Receiver signature is invalid.');
    receipt=JSON.parse(decoder.decode(receiptBytes));
    if(receipt.version!==1||receipt.transfer_id!==manifest.id||receipt.recipient_id!==manifest.recipient_id||
      receipt.manifest_sha256!==await digest(message)||receipt.sender_event_sha256!==await senderEventHash(sender.message,sender.signature)||
      receipt.package_sha256!==manifest.package_sha256||receipt.recovered_sha256!==manifest.original_sha256)
      throw Error('Receiver evidence does not match the signed sender event.');
    previousHash=await eventHash(receiver);
    }
    for(const verifier of bundle.verifiers||[]){
      const publicBytes=C.un64(verifier.public_key),message=C.un64(verifier.message);
      if(await digest(publicBytes)!==verifier.fingerprint||!(await C.verify(message,C.un64(verifier.signature),publicBytes)).valid)
        throw Error('Verifier signature or fingerprint is invalid.');
      const claim=JSON.parse(decoder.decode(message));
      if(claim.version!==1||claim.transfer_id!==manifest.id||claim.previous_event_sha256!==previousHash||
        claim.action!=='verified evidence bundle'||!claim.verifier_id)throw Error('Verifier event breaks the chain.');
      previousHash=await eventHash(verifier);
    }
    return {status:receipt?'verified-chain':'sender-only',manifest,receipt,verifiers:(bundle.verifiers||[]).length};
  }
  async function appendVerifier(bundle,identity,key){
    const checked=await verify(bundle),events=bundle.verifiers||[],previous=events.at(-1)||bundle.receiver||bundle.sender;
    const claim={version:1,transfer_id:checked.manifest.id,previous_event_sha256:await eventHash(previous),action:'verified evidence bundle',verifier_id:identity.user_id,verified_at:new Date().toISOString()};
    const bytes=encoder.encode(JSON.stringify(claim)),signed=await C.sign(bytes,key);
    return {...bundle,verifiers:[...events,{message:C.b64(bytes),signature:C.b64(signed.signature),public_key:identity.public_key,fingerprint:identity.fingerprint}]};
  }
  return {receiptPayload,bundle,verify,appendVerifier};
})();
if(typeof module!=='undefined')module.exports=CVevidence;
