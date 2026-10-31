'use strict';
window.CVLab = (() => {
  const el = (tag, cls, text) => { const n=document.createElement(tag);n.className=cls||'';if(text!==undefined)n.textContent=text;return n; };
  const run=document.getElementById('challenge-run');
  run.addEventListener('click',async()=>{
    const status=document.getElementById('challenge-status'),result=document.getElementById('challenge-results');run.disabled=true;result.replaceChildren();status.textContent='Generating a fresh key and testing the original message…';
    try{
      const text=document.getElementById('challenge-text').value;if(!text.length)throw Error('Enter a message first.');
      const bytes=new TextEncoder().encode(text),key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),iv=crypto.getRandomValues(new Uint8Array(12)),params={name:'AES-GCM',iv};
      const start=performance.now(),cipher=new Uint8Array(await crypto.subtle.encrypt(params,key,bytes)),enc=performance.now()-start;
      const decStart=performance.now(),recovered=await crypto.subtle.decrypt(params,key,cipher),dec=performance.now()-decStart;
      const recoveredText=new TextDecoder().decode(recovered);if(recoveredText!==text)throw Error('Original recovery did not match.');
      const modified=cipher.slice();modified[0]^=1;let rejected=false;
      try{await crypto.subtle.decrypt(params,key,modified);}catch(error){if(error.name!=='OperationError')throw error;rejected=true;}
      for(const [name,value] of [['Original plaintext',text],['Ciphertext + authentication tag (hex)',Array.from(cipher,b=>b.toString(16).padStart(2,'0')).join('')],['Recovered plaintext',recoveredText]]){result.append(el('h3','',name),el('pre','',value));}
      const verdict=el('div',rejected?'challenge-verdict':'error',rejected?'✓ Original recovered. Tampered ciphertext rejected. No altered plaintext released.':'Unexpected result: modified ciphertext was accepted.');result.prepend(verdict);
      status.textContent=`${bytes.length} UTF-8 bytes · AES encryption ${enc.toFixed(3)} ms · decryption ${dec.toFixed(3)} ms\nChanged exactly one bit in ciphertext byte 0. Timings exclude key generation.`;
    }catch(error){status.textContent=error.message;}finally{run.disabled=false;}
  });
  return {};
})();
