// Copy only public dashboard assets; never bundle Python, .env, keys or local data.
const fs=require('node:fs');
const path=require('node:path');
const output=path.join(__dirname,'frontend_dist');
fs.mkdirSync(path.join(output,'assets'),{recursive:true});
fs.copyFileSync(path.join(__dirname,'hosted/index.html'),path.join(output,'index.html'));
for(const file of ['app.js','crypto.js','style.css']){
  fs.copyFileSync(path.join(__dirname,'hosted',file),path.join(output,'assets',file));
}
console.log('Built public CipherVault dashboard (four static files).');
