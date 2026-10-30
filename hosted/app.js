'use strict';
const C=CVcrypto,$=id=>document.getElementById(id);
let account=null,profile=null,csrf='',mode='',results={},transfers=[],users=[],artifacts=null;
const blobUrls=new Set(),te=new TextEncoder();
const timing=(label,value)=>`${label}: ${(value*1000).toFixed(3)} ms`;
function notice(text,error=false){const target=$('auth').hidden?$('notice'):$('auth-status');target.textContent=text;target.className=error?'error':'success';}
async function api(path,data,method){
  const options={method:method||(data===undefined?'GET':'POST'),credentials:'same-origin',headers:{}};
  if(options.method!=='GET')options.headers['X-CSRF-Token']=csrf;
  if(data!==undefined){options.headers['Content-Type']='application/json';options.body=JSON.stringify(data);}
  options.signal=AbortSignal.timeout(90000);
  let response;
  try{response=await fetch('/api/'+path,options);}catch(error){throw Error(error.name==='TimeoutError'?'The backend did not respond within 90 seconds. Wait a minute, refresh this page and try again.':'Could not reach the backend. Check your connection, wait a minute and refresh this page.');}
  if(!response.headers.get('Content-Type')?.includes('application/json'))throw Error(`The backend is temporarily unavailable (HTTP ${response.status}). It may be waking up or a proxy request failed. Wait a minute, refresh this page and try again. This response does not indicate an incorrect password.`);
  let value;
  try{value=await response.json();}catch(error){throw Error('The backend returned an invalid API response. Refresh this page and try again.');}
  if(!response.ok)throw Error(value.error+(value.elapsed_until_failure_seconds!==undefined?'\n'+timing('Elapsed until failure (server)',value.elapsed_until_failure_seconds):''));
  if(value.csrf)csrf=value.csrf;
  return value;
}
function bind(id,action){$(id).addEventListener('click',async()=>{const start=performance.now();$(id).disabled=true;try{await action();}catch(error){notice(error.message+'\n'+timing('Elapsed until failure',C.seconds(start)),true);}finally{$(id).disabled=false;}});}
function download(container,bytes,name,label='Download file'){
  const node=$(container);node.replaceChildren();const link=document.createElement('a'),url=URL.createObjectURL(new Blob([bytes],{type:'application/octet-stream'}));blobUrls.add(url);link.href=url;link.download=C.safeName(name);link.textContent=label;node.append(link);
}
function appendDownload(container,bytes,name,label){const link=document.createElement('a'),url=URL.createObjectURL(new Blob([bytes]));blobUrls.add(url);link.href=url;link.download=C.safeName(name);link.textContent=label;$(container).append(link);}
async function read(id,max=C.MAX){const file=$(id).files[0];if(!file)throw Error('Choose a file first.');if(file.size>max)throw Error(`File exceeds ${max} byte limit.`);return new Uint8Array(await file.arrayBuffer());}
async function keyFile(id){const bytes=await read(id,32);if(bytes.length!==32)throw Error('AES-256 key file requires exactly 32 raw bytes.');return bytes;}
function metricResult(r,operation){return [timing(operation+' workflow',r.seconds),timing('Raw AES '+operation.toLowerCase(),r.aes_seconds),timing(r.metadata.kdf==='RAW-KEY'?'Key-file import':'Password derivation',r.key_setup_seconds),timing('SHA-256',r.hash_seconds),`Original size: ${r.metadata.size} bytes`,`SHA-256: ${r.metadata.sha256}`,`AES throughput: ${r.aes_seconds>0?(r.metadata.size/1e6/r.aes_seconds).toFixed(3):'0'} MB/s (original bytes / 1,000,000 / AES seconds)`].join('\n');}
async function openArtifacts(){
  return new Promise((resolve,reject)=>{const request=indexedDB.open('CipherVault:'+account.id,1);request.onupgradeneeded=()=>request.result.createObjectStore('artifacts');request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(Error('Browser storage unavailable; downloads remain usable in this session.'));});
}
async function artifact(key,value){if(!artifacts)return null;return new Promise((resolve,reject)=>{const tx=artifacts.transaction('artifacts',value===undefined?'readonly':'readwrite'),store=tx.objectStore('artifacts'),request=value===undefined?store.get(key):store.put(value,key);request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(Error('Could not save encrypted output in browser storage.'));});}
async function save(kind,value){await api('results/'+kind,value);results[kind]=value;}
function page(name){document.querySelectorAll('.page').forEach(node=>node.hidden=node.id!=='page-'+name);document.querySelectorAll('nav button').forEach(node=>(node.classList.toggle('active',node.dataset.page===name),node.setAttribute('aria-current',node.dataset.page===name?'page':'false')));window.scrollTo(0,0);}
document.querySelectorAll('[data-page]').forEach(node=>node.addEventListener('click',()=>page(node.dataset.page)));
function table(parent,rows){if(!rows.length)return;const wrap=document.createElement('div');wrap.className='table-wrap';const t=document.createElement('table'),head=document.createElement('tr'),keys=Object.keys(rows[0]).filter(k=>typeof rows[0][k]!=='object');for(const k of keys){const th=document.createElement('th');th.textContent=k;head.append(th);}t.append(head);for(const row of rows){const tr=document.createElement('tr');for(const k of keys){const td=document.createElement('td');td.textContent=typeof row[k]==='number'?Number(row[k].toFixed(6)):String(row[k]??'');tr.append(td);}t.append(tr);}wrap.append(t);parent.append(wrap);}
function csv(parent,rows,name){if(!rows.length)return;const keys=Object.keys(rows[0]).filter(k=>typeof rows[0][k]!=='object'),quote=x=>'"'+String(x??'').replaceAll('"','""')+'"',text=[keys.map(quote).join(','),...rows.map(r=>keys.map(k=>quote(r[k])).join(','))].join('\n');const a=document.createElement('a'),url=URL.createObjectURL(new Blob([text],{type:'text/csv'}));blobUrls.add(url);a.href=url;a.download=name+'.csv';a.textContent='Download measurements CSV';parent.append(a);}
function paragraph(parent,text){const p=document.createElement('p');p.textContent=text;parent.append(p);}
function getThemeColors(){
  const mode=document.documentElement.getAttribute('data-theme')||'system';
  const isLight=mode==='light'||(mode==='system'&&window.matchMedia&&!window.matchMedia('(prefers-color-scheme: dark)').matches);
  return isLight?['#0284c7','#059669','#7c3aed','#d97706']:['#58c4f6','#69dfba','#bba5fa','#f5c875'];
}
function plot(parent,title,series,xlabel,ylabel){
  const clean=series.map(s=>({...s,points:s.points.filter(p=>p.every(Number.isFinite)).sort((a,b)=>a[0]-b[0])}));
  const all=clean.flatMap(s=>s.points),card=document.createElement('figure');card.className='chart-card';
  const heading=document.createElement('figcaption');heading.textContent=title;card.append(heading);parent.append(card);
  if(!all.length){paragraph(card,'No measurements available yet.');return;}
  const legend=document.createElement('div');legend.className='chart-legend';card.append(legend);
  const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg');
  svg.classList.add('measurement-chart');svg.setAttribute('role','img');svg.setAttribute('aria-label',title+'. '+xlabel+'; '+ylabel);card.append(svg);
  const tip=document.createElement('output');tip.className='chart-tooltip';tip.hidden=true;card.append(tip);
  const format=v=>v===0?'0':Math.abs(v)<.01?v.toExponential(1):Number(v.toPrecision(4)).toLocaleString('en-US');
  const values=[...new Set(all.map(p=>p[0]))].sort((a,b)=>a-b),minX=values[0],maxX=values.at(-1);
  // Wide file-size ranges need logarithmic spacing so the small files remain readable.
  const logX=minX>0&&maxX/minX>=100,tx=v=>logX?Math.log10(v):v;
  const low=Math.min(0,...all.map(p=>p[1])),high=Math.max(...all.map(p=>p[1]),.000001);
  // Open nearly face-on, matching the analysis chart's readable front view.
  const startAzimuth=0,startElevation=.12;
  let azimuth=startAzimuth,elevation=startElevation,autoRotate=!window.matchMedia('(prefers-reduced-motion: reduce)').matches,drag=null;
  const controls=document.createElement('div');controls.className='chart-controls';card.insertBefore(controls,svg);
  const hint=document.createElement('span');hint.textContent='3D | Drag to rotate | Depth = series';controls.append(hint);
  function control(label,action){const button=document.createElement('button');button.type='button';button.className='secondary';button.textContent=label;button.addEventListener('click',action);controls.append(button);}
  function pauseRotation(){autoRotate=false;rotationButton.textContent='Play rotation';rotationButton.setAttribute('aria-pressed','false');}
  const rotationButton=document.createElement('button');rotationButton.type='button';rotationButton.className='secondary';rotationButton.textContent=autoRotate?'Pause rotation':'Play rotation';rotationButton.setAttribute('aria-pressed',String(autoRotate));rotationButton.addEventListener('click',()=>{autoRotate=!autoRotate;rotationButton.textContent=autoRotate?'Pause rotation':'Play rotation';rotationButton.setAttribute('aria-pressed',String(autoRotate));});controls.append(rotationButton);
  control('Rotate left',()=>{pauseRotation();azimuth-=.15;draw();});
  control('Rotate right',()=>{pauseRotation();azimuth+=.15;draw();});
  control('Reset view',()=>{pauseRotation();azimuth=startAzimuth;elevation=startElevation;draw();});
  svg.setAttribute('tabindex','0');svg.setAttribute('role','group');
  svg.setAttribute('aria-label',title+'. 3D graph. '+xlabel+'; '+ylabel+'. Depth represents series. Use arrow keys to rotate.');
  const clamp=v=>Math.max(.08,Math.min(1.15,v));
  svg.addEventListener('pointerdown',event=>{if(event.button!==0)return;pauseRotation();drag={x:event.clientX,y:event.clientY,a:azimuth,e:elevation};svg.setPointerCapture(event.pointerId);});
  svg.addEventListener('pointermove',event=>{if(!drag)return;azimuth=drag.a+(event.clientX-drag.x)*.006;elevation=clamp(drag.e+(event.clientY-drag.y)*.005);draw();});
  const stopDrag=()=>{drag=null;};
  svg.addEventListener('pointerup',stopDrag);svg.addEventListener('pointercancel',stopDrag);svg.addEventListener('lostpointercapture',stopDrag);
  svg.addEventListener('keydown',event=>{if(event.target!==svg)return;if(!['ArrowLeft','ArrowRight','ArrowUp','ArrowDown','Home'].includes(event.key))return;event.preventDefault();pauseRotation();if(event.key==='Home'){azimuth=startAzimuth;elevation=startElevation;}else if(event.key==='ArrowLeft')azimuth-=.1;else if(event.key==='ArrowRight')azimuth+=.1;else elevation=clamp(elevation+(event.key==='ArrowUp'?.1:-.1));draw();});
  function draw(){
    tip.hidden=true;
    const colors=getThemeColors();
    legend.replaceChildren();
    clean.forEach((s,i)=>{const item=document.createElement('span'),dot=document.createElement('i');dot.style.background=colors[i%colors.length];item.append(dot,document.createTextNode(s.name));legend.append(item);});
    const width=Math.max(280,card.clientWidth-40),height=width<500?390:Math.min(820,Math.max(540,width*.64));
    svg.setAttribute('viewBox',`0 0 ${width} ${height}`);svg.replaceChildren();
    // Orthographic projection of real 3D coordinates: X = input, Y = series, Z = measurement.
    const ca=Math.cos(azimuth),sa=Math.sin(azimuth),ce=Math.cos(elevation),se=Math.sin(elevation);
    function rotate(x,y,z){const horizontal=x*ca-y*sa,depth=x*sa+y*ca;return [horizontal,depth*se-z*ce,depth*ce+z*se];}
    const corners=[];for(const x of [-1,1])for(const y of [-.55,.55])for(const z of [0,1.2])corners.push(rotate(x,y,z));
    const xs=corners.map(p=>p[0]),ys=corners.map(p=>p[1]);
    const xmin=Math.min(...xs),xmax=Math.max(...xs),ymin=Math.min(...ys),ymax=Math.max(...ys);
    const scale=Math.min((width-105)/(xmax-xmin),(height-105)/(ymax-ymin));
    function project(x,y,z){const p=rotate(x,y,z);return [width/2+(p[0]-(xmin+xmax)/2)*scale,38+(height-105)/2+(p[1]-(ymin+ymax)/2)*scale,p[2]];}
    const px=v=>minX===maxX?0:-1+2*(tx(v)-tx(minX))/(tx(maxX)-tx(minX));
    const pz=v=>(v-low)/(high*1.12-low)*1.2;
    const lane=i=>clean.length===1?0:-.55+1.1*i/(clean.length-1);
    function el(tag,attrs,text){const node=document.createElementNS(ns,tag);for(const [key,value]of Object.entries(attrs))node.setAttribute(key,value);if(text!==undefined)node.textContent=text;svg.append(node);return node;}
    function line(a,b,attrs={}){const p=project(...a),q=project(...b);return el('line',{x1:p[0],y1:p[1],x2:q[0],y2:q[1],class:'chart-gridline',...attrs});}
    function label(position,text,attrs={}){const p=project(...position);el('text',{x:p[0],y:p[1],'text-anchor':'middle',...attrs},text);}
    el('title',{},title);el('desc',{},'3D measured values with separate series lanes. Drag or use arrow keys to rotate. Focus or hover over a point to inspect it.');
    const floor=[[-1,-.55,0],[1,-.55,0],[1,.55,0],[-1,.55,0]].map(p=>project(...p));
    el('polygon',{points:floor.map(p=>p.slice(0,2).join(',')).join(' '),fill:'var(--chart-grid)','fill-opacity':'.22'});
    for(let i=0;i<=4;i++){
      const z=1.2*i/4,v=low+(high*1.12-low)*i/4;
      line([-1,-.55,z],[1,-.55,z]);line([-1,-.55,z],[-1,.55,z]);
      label([-1,.55,z],format(v),{dx:-9,dy:4,'text-anchor':'end'});
    }
    line([-1,.55,0],[-1,.55,1.2],{'stroke-dasharray':'none'});
    const stride=Math.max(1,Math.ceil((values.length-1)/(width<500?3:7)));
    values.filter((v,i)=>i%stride===0||i===values.length-1).forEach(v=>{line([px(v),-.55,0],[px(v),.55,0]);label([px(v),.55,0],format(v),{dy:22});});
    el('text',{x:12,y:20,class:'chart-unit'},ylabel);
    el('text',{x:width/2,y:height-12,'text-anchor':'middle'},xlabel+(logX?' (log scale)':''));
    const ordered=clean.map((s,index)=>({s,index,depth:rotate(0,lane(index),0)[2]})).sort((a,b)=>a.depth-b.depth);
    for(const {s,index}of ordered){
      const color=colors[index%colors.length],y=lane(index);
      line([-1,y,0],[1,y,0],{stroke:color,'stroke-opacity':'.4'});
      label([1,y,0],String(index+1),{dx:12,dy:4});
      const points=s.points.map(p=>project(px(p[0]),y,pz(p[1])));
      if(points.length>1){
        const baseStart=project(px(s.points[0][0]),y,0),baseEnd=project(px(s.points.at(-1)[0]),y,0);
        el('polygon',{points:[baseStart,...points,baseEnd].map(p=>p.slice(0,2).join(',')).join(' '),fill:color,'fill-opacity':'.09'});
        el('path',{d:points.map((p,i)=>`${i?'L':'M'}${p[0]},${p[1]}`).join(' '),fill:'none',stroke:color,'stroke-width':2.5,'stroke-linejoin':'round','stroke-linecap':'round'});
      }
      s.points.forEach((p,i)=>{
        const label=`${s.name} | ${xlabel}: ${format(p[0])} | ${ylabel}: ${format(p[1])}`;
        const point=el('circle',{cx:points[i][0],cy:points[i][1],r:4.5,fill:color,stroke:'var(--chart-point-stroke)','stroke-width':1.5,tabindex:0,'aria-label':label,class:'chart-point'});
        const show=()=>{if(drag)return;tip.textContent=label;tip.hidden=false;};const hide=()=>{tip.hidden=true;};
        point.addEventListener('pointerenter',show);point.addEventListener('pointerleave',hide);point.addEventListener('focus',show);point.addEventListener('blur',hide);
        point.addEventListener('keydown',e=>{if(e.key==='Escape')hide();});
      });
    }
    [...legend.children].forEach((item,i)=>item.append(document.createTextNode(` (lane ${i+1})`)));
  }
  draw();
  chartAnimators.set(card,elapsed=>{if(!autoRotate||drag||document.hidden||svg.matches(':hover')||svg.contains(document.activeElement)||window.matchMedia('(prefers-reduced-motion: reduce)').matches)return;azimuth+=elapsed*.000052;draw();});
  chartResizeObserver.observe(card);chartDrawers.set(card,draw);
}
const chartDrawers=new WeakMap();
const chartAnimators=new Map();
let lastChartFrame=performance.now();
setInterval(()=>{const now=performance.now(),elapsed=Math.min(now-lastChartFrame,250);lastChartFrame=now;for(const [card,advance] of chartAnimators){if(!card.isConnected){chartAnimators.delete(card);continue;}const bounds=card.getBoundingClientRect();if(bounds.width&&bounds.bottom>0&&bounds.top<innerHeight)advance(elapsed);}},100);
const chartResizeObserver=new ResizeObserver(entries=>{for(const {target}of entries){if(target.isConnected)chartDrawers.get(target)?.();else chartResizeObserver.unobserve(target);}});
// Stop observing charts removed when a new experiment replaces its results.
new MutationObserver(records=>{for(const record of records)for(const node of record.removedNodes)if(node.nodeType===1){if(node.matches('.chart-card'))chartResizeObserver.unobserve(node);node.querySelectorAll('.chart-card').forEach(card=>chartResizeObserver.unobserve(card));}}).observe(document.body,{childList:true,subtree:true});

function renderMeasurements(kind,value,target=null){
  if(kind==='hash_resistance'&&!target&&$('integrity-resistance-results'))renderMeasurements(kind,value,$('integrity-resistance-results'));
  const parent=target||$(kind+'-results');if(!parent)return;parent.replaceChildren();paragraph(parent,timing('Total measured analysis (Python server)',value.total_seconds));
  const rows=value.rows||[];
  if(kind==='benchmarks'){
    const configurations=[['AES encryption vs plaintext size','aes_encrypt_ms','Encryption','Duration (ms)'],['AES decryption vs plaintext size','aes_decrypt_ms','Decryption','Duration (ms)'],['SHA-256 vs plaintext size','sha256_ms','SHA-256','Duration (ms)'],['AES throughput vs plaintext size','aes_encrypt_MB_s','Encryption','Throughput (MB/s)']];
    for(const [title,field,label,unit]of configurations)plot(parent,title,[{name:label,points:rows.map(r=>[r.size_KiB,r[field]])}],'Plaintext size (KiB)',unit);
    plot(parent,'RSA-PSS signing / verification',[{name:'Signing',points:rows.map(r=>[r.size_KiB,r.rsa_sign_ms])},{name:'Verification',points:rows.map(r=>[r.size_KiB,r.rsa_verify_ms])}],'Plaintext size (KiB)','Duration (ms)');
    paragraph(parent,timing('RSA key generation, separate setup',value.key_generation_seconds)+'\nRSA curves exclude separately recorded file hashing. MB/s = bytes / 1,000,000 / seconds.');
    const vault=$('vault-graphs');vault.replaceChildren();plot(vault,'Encryption / decryption vs plaintext size',[{name:'Encryption',points:rows.map(r=>[r.size_KiB,r.aes_encrypt_ms])},{name:'Decryption',points:rows.map(r=>[r.size_KiB,r.aes_decrypt_ms])}],'Plaintext size (KiB)','Median AES duration (ms)');paragraph(vault,'Generated test plaintexts, medians of three trials. Larger inputs usually take more processing time; fluctuations can reflect timing noise.');
  }else if(kind==='password_lengths'){
    plot(parent,'Password characters vs encryption / decryption',[{name:'Encryption',points:rows.map(r=>[r.password_characters,r.encrypt_ms])},{name:'Decryption',points:rows.map(r=>[r.password_characters,r.decrypt_ms])}],'Password length (characters)','Median workflow duration (ms)');paragraph(parent,'Identical 1 MiB plaintext, three trials per password length. PBKDF2 uses 600,000 iterations and always derives a 256-bit AES key. Longer passwords do not add AES rounds; timings can remain similar. Character count alone does not establish password strength.');
  }else if(kind==='lengths'){
    for(const [field,label]of [['encrypt_ms','Encryption'],['decrypt_ms','Decryption']])plot(parent,label+' vs plaintext size',[128,192,256].map(bits=>({name:'AES-'+bits,points:rows.filter(r=>r.key_bits===bits).map(r=>[r.size_KiB,r[field]])})),'Plaintext size (KiB)','Median AES duration (ms)');
    const fixed=rows.filter(r=>r.size_bytes===1024*1024);plot(parent,'AES key length at fixed 1 MiB plaintext',[{name:'Encryption',points:fixed.map(r=>[r.key_bits,r.encrypt_ms])},{name:'Decryption',points:fixed.map(r=>[r.key_bits,r.decrypt_ms])}],'Key length (bits)','Median AES duration (ms)');paragraph(parent,'Analysis-only AES-128/192/256 comparison. File vault and transfer always use AES-256. Larger keys use more rounds, while hardware acceleration and measurement noise affect runtime.');
  }else if(kind==='avalanche'){
    plot(parent,'Single-bit changes vs ciphertext changes',['Plaintext bit flip','Key bit flip'].map(experiment=>({name:experiment,points:rows.filter(r=>r.experiment===experiment).map(r=>[r.flipped_bit,r.changed_percent])})),'Flipped bit position','Changed output bits (%)');
    paragraph(parent,timing('Random key setup',value.key_setup_seconds)+'\n'+timing('Baseline block encryption',value.baseline_encryption_seconds)+'\nPlaintext bit flips illustrate diffusion; key bit flips illustrate key sensitivity. This isolated single-block experiment never reuses GCM nonces. A small experiment does not prove security or guarantee 50% changes.');
  }else if(kind==='hash_resistance'){
    for(const field of ['median_attempts_used','median_search_ms']){plot(parent,field==='median_search_ms'?'Truncated SHA-256 search time':'Truncated SHA-256 attempts',['Preimage','Second preimage','Collision'].map(property=>({name:property,points:value.toy.filter(r=>r.property===property).map(r=>[r.retained_bits,r[field]])})),'Retained digest bits',field==='median_search_ms'?'Duration (ms)':'Attempts used');paragraph(parent,field==='median_search_ms'?'Actual median search times for deliberately shortened 8-, 12- and 16-bit digest prefixes. Timing varies with hardware and which candidates are found.':'Attempts used, capped by the search budget. Collision searches can match any two distinct candidates; preimage searches must match a fixed target. Capped searches may finish without finding a match.');}
    plot(parent,'Full SHA-256 · bounded search attempts',value.full.map((r,index)=>({name:r.property,points:[[index+1,r.attempts]]})),'Experiment index','Attempts used');
    paragraph(parent,'Full 256-bit SHA-256 uses the same bounded search budget. A failed search means no match was found among those candidates; it does not prove resistance. See the results table for success or failure.');
    plot(parent,'Theoretical generic SHA-256 work (not measured)',[{name:'log2 generic work',points:value.theory.map((r,index)=>[index+1,r.log2_generic_work])}],'1: preimage · 2: second preimage · 3: collision','log2 expected work');
    paragraph(parent,'Ideal-hash generic work estimates: about 2^256 attempts for preimages and ordinary second-preimage searches, versus 2^128 for collisions. These estimates are not measured by this experiment.');
    paragraph(parent,'Preimage: search for input matching a target digest. Second preimage: search for another input matching an existing file digest. Collision: search for any two distinct inputs sharing a digest. Truncated prefixes are deliberately weaker; failed budget-limited searches do not prove SHA-256 resistance. The theoretical graph shows generic work estimates, not experimental results.');
    table(parent,value.full.map(r=>({property:r.property,attempts:r.attempts,found:r.found,elapsed_ms:r.seconds*1000,hash_ms:r.hash_seconds*1000})));table(parent,value.toy);csv(parent,value.toy,kind);return;
  }
  table(parent,rows);csv(parent,rows,kind);
}
function renderVaultHistory(){const parent=$('vault-history');parent.replaceChildren();const rows=results.vault_metrics?.rows||[];if(!rows.length)return;plot(parent,'Your measured AES file operations',['Encryption','Decryption'].map(operation=>({name:operation,points:rows.filter(r=>r.operation===operation).map(r=>[r.size_bytes/1024,r.aes_ms]).sort((a,b)=>a[0]-b[0])})),'Original size (KiB)','AES duration (ms)');table(parent,rows);csv(parent,rows,'vault-operations');}
async function vaultMetric(result,operation){const rows=[...(results.vault_metrics?.rows||[]),{operation,size_bytes:result.metadata.size,key_method:result.metadata.kdf==='RAW-KEY'?'Key file':'Password',aes_ms:result.aes_seconds*1000,hash_ms:result.hash_seconds*1000,workflow_ms:result.seconds*1000}].slice(-100);await save('vault_metrics',{rows});renderVaultHistory();}
function formatStamp(value){const date=new Date(value);return value&&Number.isFinite(date.getTime())?new Intl.DateTimeFormat('en-GB',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit',fractionalSecondDigits:3,timeZoneName:'short'}).format(date):'Not recorded';}
function receiptFields(parent,title,entries){
  const section=document.createElement('section'),heading=document.createElement('h3'),list=document.createElement('dl');heading.textContent=title;list.className='receipt-fields';section.append(heading,list);
  for(const [label,value]of entries){const term=document.createElement('dt'),description=document.createElement('dd');term.textContent=label;description.textContent=value;list.append(term,description);}parent.append(section);
}
function downloadEvidence(value){const blob=new Blob([JSON.stringify(value,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),link=document.createElement('a');blobUrls.add(url);link.href=url;link.download='ciphervault-evidence-'+value.transfer_id+'.json';link.click();setTimeout(()=>{URL.revokeObjectURL(url);blobUrls.delete(url);},60000);}
function signatureDetails(parent,signature,verified){const details=document.createElement('details'),summary=document.createElement('summary'),value=document.createElement('pre');summary.textContent='Digital signature · RSA-PSS / SHA-256 · Base64';value.textContent=signature;details.append(summary);paragraph(details,verified?'Receiver reports signature verified against the trusted signing fingerprint.':'Sender signature; awaiting recipient verification.');paragraph(details,'Signs the transfer manifest, which binds the encrypted package hash, original file hash, sender and recipient.');details.append(value);parent.append(details);}
function receiptTimings(parent,title,values,labels){const entries=Object.entries(values||{}).filter(([key,value])=>key.endsWith('_seconds')&&Number.isFinite(value)).map(([key,value])=>[labels[key]||key.replaceAll('_',' '),(value*1000).toFixed(3)+' ms']);receiptFields(parent,title,entries);}
async function refreshTransfers(){
  users=(await api('directory')).users;transfers=(await api('transfers')).transfers;
  await Promise.all(transfers.filter(row=>row.receipt).map(async row=>{try{row.evidence_valid=(await CVevidence.verify(CVevidence.bundle(row))).status==='verified-chain';}catch(error){row.evidence_valid=false;row.evidence_error=error.message;}}));
  $('recipient').replaceChildren();for(const user of users.filter(u=>u.user_id!==account.id)){const option=document.createElement('option');option.value=user.user_id;option.textContent=user.username;$('recipient').append(option);}
  $('inbox').replaceChildren();for(const row of transfers.filter(t=>t.recipient_id===account.id&&['sent','verified'].includes(t.status)&&Date.parse(t.expires_at)>Date.now())){const option=document.createElement('option');option.value=row.id;option.textContent=row.manifest.filename+' · from '+(users.find(u=>u.user_id===row.sender_id)?.username||row.sender_id);$('inbox').append(option);}
  const parent=$('transfer-list');parent.replaceChildren();
  for(const row of transfers){const item=document.createElement('article');item.className='transfer-item';const heading=document.createElement('h3');heading.textContent=row.manifest.filename;item.append(heading);const status=document.createElement('span');status.className='badge';status.textContent=Date.parse(row.expires_at)<=Date.now()?'Expired':row.evidence_valid?'Verified recovery':row.receipt?'Unverified receipt':row.status==='sent'?'Awaiting recovery':row.status;item.append(status);paragraph(item,`${row.sender_id===account.id?'Sent':'Inbox'} · ${row.manifest.size_bytes} bytes · ${users.find(u=>u.user_id===row.sender_id)?.username||'Sender'} → ${users.find(u=>u.user_id===row.recipient_id)?.username||'Recipient'}`);
    if(row.evidence_valid)paragraph(item,'File successfully transferred and recovered (signed recipient claim).');else if(row.receipt)paragraph(item,'Receipt cannot be cryptographically verified: '+(row.evidence_error||'recipient signature missing'));
    const grid=document.createElement('div');grid.className='receipt-grid';item.append(grid);
    receiptFields(grid,'Integrity & authenticity',[
      ['Original SHA-256',row.manifest.original_sha256],
      ['Recovered SHA-256',row.receipt?.sha256||'Awaiting recovery'],
      ['Hash comparison',row.receipt?(row.receipt.sha256===row.manifest.original_sha256?'MATCH':'MISMATCH'):'Pending'],
      ['RSA-PSS signature',row.evidence_valid?'VERIFIED (sender and recipient)':'Signed; recipient evidence pending or invalid'],
      ['Sender signing fingerprint',row.fingerprint],
    ]);
    receiptFields(grid,'Transfer timeline',[
      ['Published · sender clock',formatStamp(row.manifest.published_at)],
      ['Stored · server clock',formatStamp(row.created_at)],
      ['Recovered · receiver clock',formatStamp(row.receipt?.recovered_at)],
      ['Receipt recorded · server clock',formatStamp(row.receipt?.recorded_at)],
      ['Expires',formatStamp(row.expires_at)],
    ]);
    receiptTimings(grid,'Sender timings',{...row.timings,...(row.upload_seconds!=null?{upload_seconds:row.upload_seconds}:{})},{aes_seconds:'AES encryption',encryption_seconds:'Encryption workflow',hash_seconds:'SHA-256 (file + package)',key_setup_seconds:'Password derivation',sign_seconds:'RSA-PSS signing',upload_seconds:'Upload + complete response'});
    if(row.receipt){receiptTimings(grid,'Receiver timings',row.receipt,{aes_seconds:'AES decryption',decrypt_seconds:'Decryption workflow',hash_seconds:'Recovered file SHA-256',network_seconds:'Download + complete response',receive_seconds:'Total receive & recovery',signature_seconds:'RSA-PSS verification'});paragraph(item,timing('Combined measured processing time',row.timings.encryption_seconds+row.timings.sign_seconds+(row.upload_seconds||0)+row.receipt.receive_seconds));paragraph(item,'Sum of encryption workflow, signing, upload and receive/recovery. Excludes signing-key unlock, metadata requests and time waiting for the receiver.');}
    signatureDetails(item,row.signature,!!row.receipt?.signature_valid);
    const evidenceButton=document.createElement('button');evidenceButton.type='button';evidenceButton.className='secondary';evidenceButton.textContent='Download evidence bundle';evidenceButton.onclick=()=>{downloadEvidence(CVevidence.bundle(row));};item.append(evidenceButton);
    if(row.evidence_valid)paragraph(item,'Receiver signed the recovered hash and chained it to the sender manifest.');
    const zone=document.createElement('p');zone.className='muted';zone.textContent='Dates shown in '+Intl.DateTimeFormat().resolvedOptions().timeZone+'. Device clocks are not trusted timestamp-authority evidence.';item.append(zone);
    if(row.sender_id===account.id){const del=document.createElement('button');del.className='secondary';del.textContent='Delete transfer';del.onclick=async()=>{try{await api('transfers/'+row.id,undefined,'DELETE');await refreshTransfers();notice('Transfer deleted.');}catch(error){notice(error.message,true);}};item.append(del);}parent.append(item);
  }
  renderSummary();
}
function renderSummary(){const summary=$('summary');summary.replaceChildren();for(const [name,value]of [['Your transfers',transfers.length],['Verified receipts',transfers.filter(t=>t.evidence_valid).length],['Benchmark sizes',results.benchmarks?.rows?.length||0]]){const card=document.createElement('article');card.className='card';const h=document.createElement('h2');h.textContent=String(value);card.append(h);paragraph(card,name);summary.append(card);}}
async function initialise(){
  const value=await api('session');csrf=value.csrf;account=value.user;profile=value.profile;mode=value.mode;
  $('auth').hidden=!!account;$('workspace').hidden=!account;if(!account)return;page('dashboard');
  $('mode').textContent=mode==='local'?'Local account demo':'Hosted account workspace';$('account-label').textContent=profile?.username||account.email;$('identity-setup').hidden=!!profile;$('my-fingerprint').textContent=profile?.fingerprint||'Create your signing identity first.';
  results=(await api('results')).results;for(const [kind,value]of Object.entries(results))renderMeasurements(kind,value);renderVaultHistory();
  if(results.hash_metrics)$('hash-status').textContent='Saved hashing measurements:\n'+JSON.stringify(results.hash_metrics,null,2);
  if(results.signature_metrics)$('verify-status').textContent='Saved signature measurements:\n'+JSON.stringify(results.signature_metrics,null,2);
  try{artifacts?.close();artifacts=await openArtifacts();const saved=await artifact('encrypted');if(saved){download('encrypted-download',saved.package,saved.filename+'.cvault','Download previous encrypted package');$('encrypt-status').textContent='Restored encrypted output. Passwords and plaintext are not saved.';}}catch(error){notice(error.message,true);}
  await refreshTransfers();
}
const authHint=document.createElement('p');authHint.className='muted';authHint.textContent='Use 12–128 password characters. First time here? Create an account, then sign in.';$('account-password').after(authHint);
bind('register',async()=>{notice('Creating your account…');const result=await api('register',{email:$('email').value.trim(),password:$('account-password').value});$('account-password').value='';notice(result.message+'\n'+timing('Registration',result.operation_seconds));});
bind('login',async()=>{notice('Signing in…');const result=await api('login',{email:$('email').value.trim(),password:$('account-password').value});$('account-password').value='';await initialise();notice(timing('Sign-in',result.operation_seconds));});
bind('logout',async()=>{try{await api('logout',{});}finally{for(const url of blobUrls)URL.revokeObjectURL(url);blobUrls.clear();artifacts?.close();account=null;profile=null;results={};transfers=[];location.reload();}});
bind('enroll',async()=>{const start=performance.now(),identity=await C.generateIdentity($('new-signing-password').value,account.id);$('new-signing-password').value='';await api('identity',{username:$('username').value.trim(),public_key:identity.public_key,fingerprint:identity.fingerprint,wrapped_key:identity.wrapped_key});await initialise();notice([timing('RSA-3072 key generation',identity.key_seconds),timing('Private-key password derivation + encryption',identity.wrap_seconds),timing('Public-key SHA-256',identity.fingerprint_seconds),timing('Complete identity setup',C.seconds(start))].join('\n'));});
$('vault-method').onchange=()=>{$('vault-key-label').hidden=$('vault-method').value!=='Key file';$('vault-password-label').hidden=$('vault-method').value==='Key file';};
bind('encrypt',async()=>{ $('encrypted-download').replaceChildren();$('encrypt-status').textContent='';const file=$('vault-file').files[0],data=await read('vault-file'),key=$('vault-method').value==='Key file'?await keyFile('vault-key'):null,result=await C.encrypt(data,$('vault-password').value,file.name,key);$('vault-password').value='';if(key)key.fill(0);download('encrypted-download',result.package,result.metadata.filename+'.cvault','Download encrypted package');$('encrypt-status').textContent=metricResult(result,'Encryption');await artifact('encrypted',{package:result.package,filename:result.metadata.filename});await vaultMetric(result,'Encryption');notice('Encryption complete.');});
bind('decrypt',async()=>{ $('decrypted-download').replaceChildren();$('decrypt-status').textContent='';const packageBytes=await read('decrypt-file',C.MAX+4096),meta=C.parse(packageBytes).meta,key=meta.kdf==='RAW-KEY'?await keyFile('decrypt-key'):null;try{const result=await C.decrypt(packageBytes,$('decrypt-password').value,key);download('decrypted-download',result.data,result.metadata.filename,'Download recovered file');$('decrypt-status').textContent='Authentication succeeded · recovered hash matches\n'+metricResult(result,'Decryption');await vaultMetric(result,'Decryption');notice('Decryption complete.');}finally{$('decrypt-password').value='';if(key)key.fill(0);}});
bind('hash',async()=>{const data=await read('hash-file'),result=await C.hash(data);$('hash-status').textContent='SHA-256: '+result.value+'\n'+timing('Hash computation',result.seconds);await save('hash_metrics',{digest:result.value,hash_seconds:result.seconds,size_bytes:data.length});});
bind('compare',async()=>{const first=await read('hash-file'),second=await read('compare-file'),start=performance.now(),a=await C.hash(first),b=await C.hash(second),same=first.length===second.length&&first.every((v,i)=>v===second[i]),elapsed=C.seconds(start);$('hash-status').textContent=`Original SHA-256: ${a.value}\nComparison SHA-256: ${b.value}\nHashes match: ${a.value===b.value}\nBytes equal: ${same}\n${timing('Original hashing',a.seconds)}\n${timing('Comparison hashing',b.seconds)}\n${timing('Complete hash / byte comparison',elapsed)}`;await save('hash_metrics',{original_digest:a.value,comparison_digest:b.value,bytes_equal:same,comparison_seconds:elapsed,original_hash_seconds:a.seconds,comparison_hash_seconds:b.seconds});});
bind('hash-change',async()=>{const original=await read('hash-file');if(!original.length)throw Error('Select a nonempty file for the one-byte change demonstration.');const start=performance.now(),changed=original.slice();changed[0]^=1;const a=await C.hash(original),b=await C.hash(changed);$('hash-status').textContent=`Flipped one bit in the first byte.\nOriginal: ${a.value}\nModified: ${b.value}\n${timing('Original SHA-256',a.seconds)}\n${timing('Modified SHA-256',b.seconds)}\n${timing('Complete demonstration',C.seconds(start))}\nThis demonstrates sensitivity to changes, not a proof of collision resistance.`;});
async function unlocked(password){const identity=(await api('identity')).profile;if(!identity)throw Error('Create your signing identity first.');return C.unlockIdentity(identity,password,account.id);}
bind('export-public',async()=>{if(!profile)throw Error('Create your signing identity first.');appendDownload('my-fingerprint',te.encode(C.pem(C.un64(profile.public_key))),'public.pem','Download public key');});
bind('sign',async()=>{const data=await read('sign-file'),unlock=await unlocked($('sign-password').value);$('sign-password').value='';const hash=await C.hash(data),signed=await C.sign(data,unlock.key);download('signature-download',signed.signature,'file.sig','Download RSA-PSS signature');appendDownload('signature-download',te.encode(C.pem(C.un64(profile.public_key))),'public.pem','Download public key');$('sign-status').textContent=[timing('Private-key unlock',unlock.seconds),timing('Standalone SHA-256',hash.seconds),timing('RSA-PSS signing (browser API includes internal SHA-256)',signed.seconds),'SHA-256: '+hash.value].join('\n');await save('signature_metrics',{digest:hash.value,hash_seconds:hash.seconds,sign_seconds:signed.seconds,unlock_seconds:unlock.seconds});});
bind('verify',async()=>{const data=await read('verify-file'),signature=await read('verify-signature',512),publicBytes=C.readPem(new TextDecoder().decode(await read('verify-public',8192))),hash=await C.hash(data),verified=await C.verify(data,signature,publicBytes);$('verify-status').textContent=(verified.valid?'Signature VERIFIED':'Signature verification FAILED')+'\n'+timing('Standalone SHA-256',hash.seconds)+'\n'+timing('RSA-PSS verification (includes public-key import and internal hashing)',verified.seconds);await save('signature_metrics',{valid:verified.valid,hash_seconds:hash.seconds,verify_seconds:verified.seconds});});
bind('send',async()=>{
  const start=performance.now();for(const id of ['send-status','send-plaintext','send-ciphertext','send-signature'])$(id).textContent='';
  const recipient=$('recipient').value;if(!recipient)throw Error('The recipient must register and create a signing identity first.');
  const data=await read('send-file'),file=$('send-file').files[0],encrypted=await C.encrypt(data,$('send-password').value,file.name);$('send-password').value='';
  const unlock=await unlocked($('send-signing-password').value);$('send-signing-password').value='';const packageHash=await C.hash(encrypted.package),id=crypto.randomUUID(),manifest={id,sender_id:account.id,recipient_id:recipient,filename:encrypted.metadata.filename,size_bytes:data.length,package_bytes:encrypted.package.length,original_sha256:encrypted.metadata.sha256,package_sha256:packageHash.value,published_at:new Date().toISOString()},message=te.encode(JSON.stringify(manifest)),signed=await C.sign(message,unlock.key);
  const timings={encryption_seconds:encrypted.seconds,aes_seconds:encrypted.aes_seconds,hash_seconds:encrypted.hash_seconds+packageHash.seconds,sign_seconds:signed.seconds,key_setup_seconds:encrypted.key_setup_seconds};
  const draft=await api('transfers',{message:C.b64(message),signature:C.b64(signed.signature),timings}),uploadStart=performance.now();
  const response=await fetch(draft.upload_url,{method:draft.upload_method,headers:{'Content-Type':'application/octet-stream',...(draft.upload_url.startsWith('/')?{'X-CSRF-Token':csrf}:{'x-upsert':'false'})},body:encrypted.package});await response.arrayBuffer();if(!response.ok)throw Error('Encrypted upload failed. Delete the unfinished draft and retry.');
  const uploadSeconds=C.seconds(uploadStart);await api('transfers/'+id+'/publish',{upload_seconds:uploadSeconds});
  $('send-plaintext').textContent=C.preview(data);$('send-ciphertext').textContent=C.hex(C.parse(encrypted.package).cipher.slice(0,Math.min(data.length,256)))||'(empty plaintext)';$('send-signature').textContent=C.b64(signed.signature);
  $('send-status').textContent='File sent · awaiting recipient verification\nPublished (sender clock): '+formatStamp(manifest.published_at)+'\n'+metricResult(encrypted,'Encryption')+'\n'+timing('Package SHA-256',packageHash.seconds)+'\n'+timing('Signing-key unlock',unlock.seconds)+'\n'+timing('RSA-PSS signing (includes internal hashing)',signed.seconds)+'\n'+timing('Upload request + complete response',uploadSeconds)+'\n'+timing('Server signature verification',draft.server_signature_seconds)+'\n'+timing('Server signature prehash',draft.server_hash_seconds)+'\n'+timing('Complete preparation + upload + publish',C.seconds(start));await refreshTransfers();notice('Ciphertext sent. Share the password separately.');
});

bind('sign-evidence',async()=>{$('evidence-status').textContent='';try{const file=$('evidence-file').files[0];if(!file)throw Error('Choose an evidence bundle first.');if(file.size>50000)throw Error('Evidence bundle is too large.');const value=JSON.parse(await file.text());await CVevidence.verify(value);const unlock=await unlocked($('evidence-signing-password').value);const next=await CVevidence.appendVerifier(value,profile,unlock.key);await CVevidence.verify(next);downloadEvidence(next);$('evidence-status').textContent='Verification signed and chained. Download the updated bundle.';}finally{$('evidence-signing-password').value='';}});
bind('verify-evidence',async()=>{$('evidence-status').textContent='';const file=$('evidence-file').files[0];if(!file)throw Error('Choose an evidence bundle JSON file.');if(file.size>50000)throw Error('Evidence bundle is too large.');const value=JSON.parse(await file.text()),result=await CVevidence.verify(value);$('evidence-status').textContent=(result.status==='verified-chain'?'Both transfer signatures and their chain verify. The signed receiver recovered-hash claim matches the manifest.':'Sender signature verifies; no signed receiver receipt is present.')+'\nVerifier signatures: '+result.verifiers+'\nSender fingerprint: '+value.sender.fingerprint+(value.receiver?'\nReceiver fingerprint: '+value.receiver.fingerprint:'')+'\nCompare fingerprints through a trusted channel; timestamps are device claims.';});
bind('refresh-transfers',async()=>{await refreshTransfers();notice('Inbox and receipts refreshed.');});
bind('receive',async()=>{
  for(const id of ['receive-status','receive-ciphertext','receive-plaintext','receive-signature'])$(id).textContent='';$('receive-download').replaceChildren();
  const row=transfers.find(t=>t.id===$('inbox').value);if(!row)throw Error('Refresh your inbox and choose a transfer.');
  const expected=$('receive-fingerprint').value.trim().toLowerCase();if(!/^[a-f0-9]{64}$/.test(expected))throw Error('Enter the sender signing fingerprint verified through a trusted separate channel.');
  const start=performance.now(),networkStart=performance.now();let response=await fetch('/api/transfers/'+row.id+'/download');if(!response.ok)throw Error('Download denied or transfer expired.');
  if(response.headers.get('Content-Type').includes('application/json')){const info=await response.json();response=await fetch(info.download_url);if(!response.ok)throw Error('Private encrypted download failed.');}
  const packageBytes=new Uint8Array(await response.arrayBuffer()),networkSeconds=C.seconds(networkStart);
  if(packageBytes.length!==row.manifest.package_bytes||packageBytes.length>C.MAX+4096)throw Error('Received package size mismatch.');
  const publicHash=await C.hash(C.un64(row.public_key));if(publicHash.value!==expected||row.fingerprint!==expected)throw Error('Untrusted sender signing key.');
  const message=C.un64(row.message),manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(message)),packageHash=await C.hash(packageBytes),verified=await C.verify(message,C.un64(row.signature),C.un64(row.public_key));
  if(!verified.valid||manifest.id!==row.id||manifest.sender_id!==row.sender_id||manifest.recipient_id!==account.id||manifest.package_sha256!==packageHash.value)throw Error('Digital signature or package hash verification failed.');
  const meta=C.parse(packageBytes).meta;if(meta.sha256!==manifest.original_sha256||meta.filename!==manifest.filename||meta.size!==manifest.size_bytes)throw Error('Signed manifest does not match package metadata.');
  $('receive-ciphertext').textContent=C.hex(C.parse(packageBytes).cipher.slice(0,Math.min(meta.size,256)))||'(empty plaintext)';
  let recovered;try{recovered=await C.decrypt(packageBytes,$('receive-password').value);}finally{$('receive-password').value='';}
  const receiveSeconds=C.seconds(start),stamp=new Date().toISOString();download('receive-download',recovered.data,recovered.metadata.filename,'Download recovered file');$('receive-plaintext').textContent=C.preview(recovered.data);$('receive-signature').textContent=row.signature;
  $('receive-status').textContent='File successfully transferred and recovered\nRSA-PSS: VERIFIED against trusted signing fingerprint\nOriginal SHA-256: '+manifest.original_sha256+'\nRecovered SHA-256: '+recovered.sha256+'\nPublished (sender clock): '+formatStamp(manifest.published_at)+'\nRecovered (receiver clock): '+formatStamp(stamp)+'\n'+metricResult(recovered,'Decryption')+'\n'+timing('Signing public-key fingerprint SHA-256',publicHash.seconds)+'\n'+timing('Encrypted package SHA-256',packageHash.seconds)+'\n'+timing('RSA-PSS verification (includes import and hashing)',verified.seconds)+'\n'+timing('Download through complete response body',networkSeconds)+'\n'+timing('Total receive and recovery',receiveSeconds)+`\nNetwork throughput: ${(packageBytes.length/1e6/networkSeconds).toFixed(3)} MB/s (package bytes / 1,000,000 / network seconds)`;
  if(row.status!=='verified')try{const unlock=await unlocked($('receive-signing-password').value);const attestation=await CVevidence.receiptPayload(row,recovered.sha256,stamp),attestationMessage=te.encode(JSON.stringify(attestation)),receiptSignature=await C.sign(attestationMessage,unlock.key);await api('transfers/'+row.id+'/receipt',{sha256:recovered.sha256,signature_valid:true,network_seconds:networkSeconds,decrypt_seconds:recovered.seconds,aes_seconds:recovered.aes_seconds,hash_seconds:recovered.hash_seconds,signature_seconds:verified.seconds,receive_seconds:receiveSeconds,recovered_at:stamp,attestation_message:C.b64(attestationMessage),attestation_signature:C.b64(receiptSignature.signature)});$('receive-status').textContent+='\nReceiver chain-of-custody signature: recorded';}catch(error){$('receive-status').textContent+='\nRecovery succeeded; signed receipt could not be recorded: '+error.message;}finally{$('receive-signing-password').value='';}
  await refreshTransfers();notice('Recovery succeeded. Download the recovered file.');
});
document.querySelectorAll('[data-analysis]').forEach(button=>button.onclick=async()=>{const start=performance.now();button.disabled=true;try{notice('Running measured '+button.dataset.analysis+' experiment…');const data=button.dataset.analysis==='avalanche'?{block:$('analysis-block').value.trim()}:{},value=await api('analysis/'+button.dataset.analysis,data);results[button.dataset.analysis]=value.result;renderMeasurements(button.dataset.analysis,value.result);renderSummary();notice(timing('Analysis request + response',C.seconds(start)));}catch(error){notice(error.message+'\n'+timing('Elapsed until failure',C.seconds(start)),true);}finally{button.disabled=false;}});
initialise().catch(error=>{$('auth-status').textContent=error.message;notice(error.message,true);});

let trafficCapture=null;
function clearTraffic(){trafficCapture=null;$('traffic-results').hidden=true;$('traffic-file').value='';$('traffic-status').textContent='';$('traffic-search').value='';$('traffic-protocol').replaceChildren(new Option('All protocols',''));for(const id of ['traffic-summary','traffic-charts','traffic-radar','traffic-protocols','traffic-endpoints','traffic-packets'])$(id).replaceChildren();}
function renderTrafficRadar(capture){
  const parent=$('traffic-radar'),radar=CVtraffic.radar(capture);parent.replaceChildren();
  const signals=document.createElement('div');signals.className='radar-grid';parent.append(signals);
  for(const signal of radar.signals){const card=document.createElement('section');card.className='radar-signal';const heading=document.createElement('h3');heading.textContent=signal.name;const strong=document.createElement('strong');strong.textContent=signal.value;card.append(heading,strong);paragraph(card,signal.detail);signals.append(card);}
  const heading=document.createElement('h3');heading.textContent='Observed activity bursts';parent.append(heading);
  table(parent,radar.bursts.slice(0,20).map((burst,index)=>({burst:index+1,from_seconds:Number(burst.start.toFixed(3)),to_seconds:Number(burst.end.toFixed(3)),packets:burst.packets,frame_bytes:burst.frame_bytes,visible_peers:burst.peers.join(' ↔ ')})));
  if(radar.bursts.length>20)paragraph(parent,`Showing the first 20 of ${radar.bursts.length} bursts.`);
  if(radar.visibleRequests.length){const details=document.createElement('details'),summary=document.createElement('summary');summary.textContent='HTTP request text visible in the packet summary';details.append(summary);for(const request of radar.visibleRequests)paragraph(details,request);parent.append(details);}
}
function renderTrafficPackets(){
  if(!trafficCapture)return;
  const protocol=$('traffic-protocol').value,query=$('traffic-search').value.toLowerCase();
  const rows=trafficCapture.packets.filter(p=>(!protocol||p.protocol===protocol)&&(!query||[p.source,p.destination,p.info].some(v=>v.toLowerCase().includes(query))));
  $('traffic-count').textContent=`${rows.length.toLocaleString()} matching packets | showing first ${Math.min(rows.length,200)}. Charts summarise the complete imported CSV.`;
  $('traffic-packets').replaceChildren();table($('traffic-packets'),rows.slice(0,200));
}
bind('traffic-analyse',async()=>{
  const file=$('traffic-file').files[0];clearTraffic();
  try{
    if(!file)throw Error('Choose a Wireshark CSV first.');
    if(file.size>10*1024*1024)throw Error('Choose a CSV smaller than 10 MiB.');
    if(!file.name.toLowerCase().endsWith('.csv'))throw Error('Export your capture as CSV in Wireshark first.');
    const capture=CVtraffic.analyse(await file.text());trafficCapture=capture;$('traffic-results').hidden=false;
    for(const [label,value]of [['Packets',capture.packets.length.toLocaleString()],['Frame bytes',capture.bytes.toLocaleString()],['Capture span',capture.duration.toFixed(3)+' s']]){
      const card=document.createElement('article');card.className='card';const heading=document.createElement('h2');heading.textContent=label;card.append(heading);paragraph(card,value);$('traffic-summary').append(card);
    }
    renderTrafficRadar(capture);
    plot($('traffic-charts'),'Packet rate',[{name:'Packets / second',points:capture.timeline.map(b=>[b.seconds,b.packets/capture.binWidth])}],'Seconds from first imported packet','Packets / s');
    plot($('traffic-charts'),'Traffic volume',[{name:'Frame bytes / second',points:capture.timeline.map(b=>[b.seconds,b.bytes/capture.binWidth])}],'Seconds from first imported packet','Bytes / s');
    paragraph($('traffic-charts'),`Averages over fixed ${capture.binWidth}-second bins, including empty intervals. The last bin may be partial. Capture span is the time between the first and last imported packets.`);
    table($('traffic-protocols'),capture.protocols);table($('traffic-endpoints'),capture.endpoints.slice(0,20));
    for(const row of capture.protocols)$('traffic-protocol').append(new Option(row.protocol,row.protocol));renderTrafficPackets();
    $('traffic-status').textContent=`${file.name} | ${capture.packets.length.toLocaleString()} packets analysed in this browser.`;
  }catch(error){clearTraffic();$('traffic-status').textContent=error.message;}
});
bind('traffic-clear',async()=>clearTraffic());
$('logout').addEventListener('click',clearTraffic);
$('traffic-protocol').addEventListener('change',renderTrafficPackets);
$('traffic-search').addEventListener('input',renderTrafficPackets);

function getSavedTheme(){try{return localStorage.getItem('ciphervault_theme')||'system';}catch(e){return 'system';}}
function applyTheme(choice){
  try{localStorage.setItem('ciphervault_theme',choice);}catch(e){}
  document.documentElement.setAttribute('data-theme',choice);
  document.querySelectorAll('[data-theme-btn]').forEach(btn=>{
    const active=btn.dataset.themeBtn===choice;
    btn.classList.toggle('active',active);
    btn.setAttribute('aria-checked',active?'true':'false');
  });
  const chip=$('theme-current-chip');
  if(chip)chip.textContent=choice==='light'?'Light':choice==='dark'?'Dark':'Auto';
  document.querySelectorAll('.chart-card').forEach(card=>{
    chartDrawers.get(card)?.();
  });
}
document.addEventListener('click',e=>{
  const btn=e.target.closest('[data-theme-btn]');
  if(btn)applyTheme(btn.dataset.themeBtn);
});
if(window.matchMedia){
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change',()=>{
    if(getSavedTheme()==='system'){
      document.querySelectorAll('.chart-card').forEach(card=>chartDrawers.get(card)?.());
    }
  });
}
const themeCollapsible=$('theme-collapsible');
if(themeCollapsible){
  try{
    if(localStorage.getItem('ciphervault_theme_collapsed')==='true'){
      themeCollapsible.removeAttribute('open');
    }
  }catch(e){}
  themeCollapsible.addEventListener('toggle',()=>{
    try{localStorage.setItem('ciphervault_theme_collapsed',!themeCollapsible.open);}catch(e){}
  });
}
applyTheme(getSavedTheme());
