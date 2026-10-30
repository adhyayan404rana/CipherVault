'use strict';
// Wireshark packet-summary exports only; raw capture contents never leave the browser.
const CVtraffic=(()=>{
  function parseCSV(text){
    if(text.length>10*1024*1024)throw Error('Choose a CSV smaller than 10 MiB.');
    const rows=[];let row=[],field='',quoted=false,closed=false;
    const finish=()=>{row.push(field);field='';closed=false;};
    for(let i=0;i<text.length;i++){
      const c=text[i];
      if(quoted){if(c==='"'){if(text[i+1]==='"'){field+='"';i++;}else{quoted=false;closed=true;}}else field+=c;}
      else if(c==='"'){if(field||closed)throw Error('Invalid CSV quoting.');quoted=true;}
      else if(c===',')finish();
      else if(c==='\n'||c==='\r'){if(c==='\r'&&text[i+1]==='\n')i++;finish();if(row.some(v=>v.trim()))rows.push(row);row=[];}
      else{if(closed)throw Error('Invalid text after a quoted CSV field.');field+=c;}
      if(rows.length>100001)throw Error('Import at most 100,000 packets. Export a smaller displayed range in Wireshark.');
    }
    if(quoted)throw Error('CSV contains an unfinished quoted field.');
    finish();if(row.some(v=>v.trim()))rows.push(row);
    if(rows.length<2)throw Error('The CSV contains no packets.');
    return rows;
  }
  function analyse(text){
    const rows=parseCSV(text.replace(/^\uFEFF/,'')),header=rows.shift().map(v=>v.trim().toLowerCase());
    const names=['no.','time','source','destination','protocol','length','info'];
    const indices=names.map(n=>header.indexOf(n));
    if(indices.some(i=>i<0))throw Error('Export the default Wireshark columns: No., Time, Source, Destination, Protocol, Length, Info. Set Time Display Format to Seconds Since Beginning of Capture.');
    const packets=rows.map((r,i)=>{
      if(r.length!==header.length)throw Error(`CSV row ${i+2} has the wrong number of columns.`);
      const [number,time,source,destination,protocol,length,info]=indices.map(j=>r[j].trim());
      if(!number||!time||!length||!Number.isInteger(Number(number))||Number(number)<1||!Number.isFinite(Number(time))||Number(time)<0||!Number.isSafeInteger(Number(length))||Number(length)<0||Number(length)>4294967295||!source||!destination||!protocol)throw Error(`Invalid packet at row ${i+2}. Use numeric seconds since beginning of capture and numeric packet lengths.`);
      return {number:Number(number),time:Number(time),source,destination,protocol,length:Number(length),info};
    });
    if(packets.length>100000)throw Error('Import at most 100,000 packets.');
    packets.sort((a,b)=>a.time-b.time);
    const start=packets[0].time,end=packets.at(-1).time,duration=end-start,protocols=new Map(),endpoints=new Map();let bytes=0;
    const binWidth=Math.max(1,Math.ceil(duration/120)),bins=new Map();
    for(const p of packets){
      bytes+=p.length;
      const proto=protocols.get(p.protocol)||{protocol:p.protocol,packets:0,bytes:0};proto.packets++;proto.bytes+=p.length;protocols.set(p.protocol,proto);
      for(const [address,direction]of [[p.source,'sent'],[p.destination,'received']]){const endpoint=endpoints.get(address)||{address,sent_packets:0,received_packets:0,sent_bytes:0,received_bytes:0};endpoint[direction+'_packets']++;endpoint[direction+'_bytes']+=p.length;endpoints.set(address,endpoint);}
      const index=Math.floor((p.time-start)/binWidth),bin=bins.get(index)||{packets:0,bytes:0};bin.packets++;bin.bytes+=p.length;bins.set(index,bin);
    }
    const timeline=Array.from({length:Math.floor(duration/binWidth)+1},(_,i)=>({seconds:i*binWidth,packets:bins.get(i)?.packets||0,bytes:bins.get(i)?.bytes||0}));
    return {packets,bytes,duration,binWidth,timeline,protocols:[...protocols.values()].sort((a,b)=>b.bytes-a.bytes),endpoints:[...endpoints.values()].sort((a,b)=>(b.sent_bytes+b.received_bytes)-(a.sent_bytes+a.received_bytes))};
  }
  function radar(capture){
    const packets=capture.packets,span=capture.duration,gap=Math.max(.5,Math.min(3,span*.05));
    const bursts=[];let current=null;
    for(const packet of packets){
      if(!current||packet.time-current.end>gap){current={start:packet.time,end:packet.time,packets:0,frame_bytes:0,peers:new Set()};bursts.push(current);}
      current.end=packet.time;current.packets++;current.frame_bytes+=packet.length;
      current.peers.add(packet.source);current.peers.add(packet.destination);
    }
    const similar=bursts.filter((burst,i)=>burst.frame_bytes>=1000&&bursts.some((other,j)=>j<i&&other.frame_bytes>=1000&&Math.abs(other.frame_bytes-burst.frame_bytes)/Math.max(other.frame_bytes,burst.frame_bytes)<=.15)).length;
    const http=packets.filter(p=>/^HTTP/i.test(p.protocol));
    const visibleRequests=http.filter(p=>/\b(GET|POST|PUT|DELETE|PATCH|HEAD)\s+\S+/.test(p.info)).slice(0,5).map(p=>p.info.slice(0,160));
    return {gap,bursts:bursts.map(b=>({...b,peers:[...b.peers]})),similar,
      signals:[
        {name:'Endpoints and direction',value:`${capture.endpoints.length} visible addresses`,detail:'Source and destination addresses are in the packet summary. A proxy or NAT can hide the actual user.'},
        {name:'Activity timing',value:`${bursts.length} activity bursts over ${span.toFixed(2)} s`,detail:'Burst boundaries are estimates based on gaps between packet timestamps.'},
        {name:'Traffic volume',value:`${capture.bytes.toLocaleString()} frame bytes`,detail:'Frame lengths include overhead and retransmissions; they do not reveal the exact file size.'},
        {name:'Similar traffic',value:`${similar} bursts with similar volume`,detail:'Similarity is a volume clue, not proof that the same file was sent.'},
        {name:'Visible HTTP requests',value:http.length?`${http.length} HTTP-labelled packets`:'None labelled HTTP',detail:http.length?'An HTTP-labelled summary may reveal request method or path; the CSV does not prove what payload was exposed.':'TLS labels alone do not prove every packet or payload was encrypted.'}
      ],visibleRequests};
  }
  return {analyse,radar};
})();
if(typeof module!=='undefined')module.exports=CVtraffic;
