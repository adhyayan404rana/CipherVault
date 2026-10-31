'use strict';
window.CVLab = (() => {
  const el = (tag, cls, text) => { const n=document.createElement(tag);n.className=cls||'';if(text!==undefined)n.textContent=text;return n; };
  function render(parent, data) {
    if(!data.trials?.length)return; // Older saved experiments remain readable.
    const panel=el('section','avalanche-panel'),controls=el('div','lab-controls');
    const label=el('label','','Experiment'),mode=el('select');
    for(const name of ['Plaintext bit flip','Key bit flip']) {const option=el('option','',name);mode.append(option);}
    label.append(mode);
    const sliderLabel=el('label','','Trial'),slider=el('input');slider.type='range';slider.min=0;slider.value=0;slider.step=1;sliderLabel.append(slider);
    const play=el('button','secondary','Play trials');play.type='button';controls.append(label,sliderLabel,play);
    const stats=el('div','lab-stats'),caption=el('p','muted'),map=el('div','bit-map');map.setAttribute('role','img');
    const legend=el('p','bit-legend','● Highlighted = changed bit · 0/1 = resulting bit · byte order, least-significant bit first');
    const bytes=el('div','byte-comparison'),baseline=el('pre'),output=el('pre');
    bytes.append(el('div','','Baseline ciphertext'),baseline,el('div','','Changed ciphertext'),output);
    const meter=el('div','avalanche-meter'),fill=el('span'),target=el('i');meter.append(fill,target);meter.setAttribute('aria-hidden','true');
    panel.append(controls,stats,meter,caption,map,legend,bytes,el('p','muted','Bit target: 50% on average. Character target: 100% maximum of 32 displayed hex digits; independent outputs average 93.75%. Actual trials vary.'));
    parent.append(panel);
    let timer=null;
    function stop(){clearInterval(timer);timer=null;play.textContent='Play trials';}
    function draw(){
      const trials=data.trials.filter(t=>t.experiment===mode.value);slider.max=trials.length-1;
      const trial=trials[Number(slider.value)],base=data.baseline_hex.match(/../g).map(x=>parseInt(x,16)),out=trial.output_hex.match(/../g).map(x=>parseInt(x,16));
      const mask=base.flatMap((b,i)=>Array.from({length:8},(_,k)=>((b^out[i])>>k)&1));
      const count=mask.reduce((a,b)=>a+b,0),mean=data.rows.filter(t=>t.experiment===mode.value).reduce((a,b)=>a+b.changed_percent,0)/trials.length;
      const changedCharacters=[...data.baseline_hex].filter((character,i)=>character!==trial.output_hex[i]).length;
      stats.replaceChildren();
      for(const [value,name] of [[`${count} / 128`,'Output bits changed'],[`${(count/128*100).toFixed(1)}%`,'Bit avalanche · target 50%'],[`${(changedCharacters/32*100).toFixed(1)}%`,'Hex characters changed · max 100%'],[`${trial.changed_bytes} / 16`,'Output bytes changed'],[`${mean.toFixed(1)}%`,'Mean across this mode']]) {const card=el('div');card.append(el('strong','',value),el('span','',name));stats.append(card);}
      fill.style.width=(count/128*100)+'%';
      caption.textContent=`Trial ${Number(slider.value)+1} of ${trials.length} · ${mode.value} at position ${trial.flipped_bit} · marker = 50% reference`;
      map.setAttribute('aria-label',`${count} of 128 output bits changed after flipping ${mode.value.toLowerCase()} position ${trial.flipped_bit}`);
      map.replaceChildren(...mask.map((changed,i)=>{const cell=el('span',changed?'bit changed':'bit',String((out[Math.floor(i/8)]>>(i%8))&1));cell.style.setProperty('--delay',`${Math.floor(i/8)*18}ms`);cell.title=`Output bit ${i}: ${(base[Math.floor(i/8)]>>(i%8))&1} → ${(out[Math.floor(i/8)]>>(i%8))&1}${changed?' (changed)':' (unchanged)'}`;cell.setAttribute('aria-hidden','true');return cell;}));
      baseline.textContent=base.map(b=>b.toString(16).padStart(2,'0')).join(' ');output.replaceChildren(...out.map((b,i)=>el('span',b!==base[i]?'byte-changed':'',b.toString(16).padStart(2,'0')+' ')));
    }
    mode.onchange=()=>{stop();slider.value=0;draw();};slider.oninput=()=>{stop();draw();};
    play.onclick=()=>{if(timer){stop();return;}play.textContent='Pause trials';timer=setInterval(()=>{if(!panel.isConnected||panel.closest('.page')?.hidden||document.hidden){stop();return;}slider.value=(Number(slider.value)+1)%(Number(slider.max)+1);draw();},900);};draw();
  }
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
  return {render};
})();
