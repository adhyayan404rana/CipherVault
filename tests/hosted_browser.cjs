// Actual Chrome UI test: separate normal/incognito-equivalent browser contexts.
const {chromium}=require('../.test-tools/node_modules/playwright');
const fs=require('node:fs');
const assert=require('node:assert/strict');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const errors=[];
async function auth(page,email,username){
  await page.goto(input.base);
  await page.locator('#email').fill(email);
  await page.locator('#account-password').fill('shortpass');
  await page.locator('#register').click();
  await page.waitForFunction(()=>document.getElementById('auth-status').textContent.includes('12–128 characters'));
  assert(await page.locator('#auth-status').isVisible());
  assert.equal(await page.locator('#workspace').isVisible(),false);
  await page.locator('#account-password').fill('an unregistered long password');
  await page.locator('#login').click();
  await page.waitForFunction(()=>document.getElementById('auth-status').textContent.includes('Invalid email or password'));
  assert(await page.locator('#auth-status').isVisible());
  await page.locator('#account-password').fill('browser account password 2026!');
  await page.locator('#register').click();
  await page.waitForFunction(()=>document.getElementById('auth-status').textContent.includes('created'));
  await page.locator('#account-password').fill('browser account password 2026!');
  await page.locator('#login').click();
  await page.locator('#identity-setup').waitFor({state:'visible'});
  await page.locator('#username').fill(username);
  await page.locator('#new-signing-password').fill('separate browser signing password!');
  await page.locator('#enroll').click();
  await page.waitForFunction(()=>document.getElementById('notice').textContent.includes('Complete identity setup'));
}
async function navigate(page,name){await page.locator('nav [data-page="'+name+'"]').click();}
async function saveDownload(page,selector,path){const promise=page.waitForEvent('download');await page.locator(selector).click();const download=await promise;await download.saveAs(path);return fs.readFileSync(path);}
(async()=>{
  const browser=await chromium.launch({executablePath:input.chrome,headless:true});
  try{
    const contextA=await browser.newContext(),contextB=await browser.newContext();
    const alice=await contextA.newPage(),bob=await contextB.newPage();
    for(const page of [alice,bob])page.on('pageerror',error=>errors.push(error.message));
    await auth(alice,'alice@example.test','alice');await auth(bob,'bob@example.test','bob');
    await navigate(alice,'transfer');await alice.locator('#refresh-transfers').click();
    await alice.waitForFunction(()=>document.querySelectorAll('#recipient option').length===1);
    const fingerprint=(await alice.locator('#my-fingerprint').textContent()).trim();
    await alice.locator('#send-file').setInputFiles(input.demo);
    await alice.locator('#send-password').fill('separate browser file password!');
    await alice.locator('#send-signing-password').fill('separate browser signing password!');
    await alice.locator('#send').click();
    await alice.waitForFunction(()=>document.getElementById('send-status').textContent.includes('File sent'));
    assert((await alice.locator('#send-plaintext').textContent()).includes('Hosted CipherVault demo'));
    await navigate(bob,'transfer');await bob.locator('#refresh-transfers').click();
    await bob.waitForFunction(()=>document.querySelectorAll('#inbox option').length===1);
    await bob.locator('#receive-fingerprint').fill('0'.repeat(64));
    await bob.locator('#receive-password').fill('separate browser file password!');
    await bob.locator('#receive').click();
    await bob.waitForFunction(()=>document.getElementById('notice').textContent.includes('Untrusted sender'));
    assert.equal(await bob.locator('#receive-download a').count(),0);
    await bob.locator('#receive-fingerprint').fill(fingerprint);
    await bob.locator('#receive-password').fill('incorrect browser file password');
    await bob.locator('#receive').click();
    await bob.waitForFunction(()=>document.getElementById('notice').textContent.includes('Authentication failed'));
    assert.equal(await bob.locator('#receive-download a').count(),0);
    await bob.locator('#receive-password').fill('separate browser file password!');
    await bob.locator('#receive').click();
    await bob.waitForFunction(()=>document.getElementById('receive-status').textContent.includes('File successfully transferred'));
    const recovered=await saveDownload(bob,'#receive-download a',input.recovered);
    assert.deepEqual(recovered,fs.readFileSync(input.demo));
    assert((await bob.locator('#receive-status').textContent()).includes('RSA-PSS: VERIFIED'));
    const senderSignature=(await alice.locator('#send-signature').textContent()).trim();
    assert.equal(senderSignature.length,512);
    assert.equal((await bob.locator('#receive-signature').textContent()).trim(),senderSignature);
    await bob.locator('#refresh-transfers').click();
    await bob.waitForFunction(()=>document.querySelector('#transfer-list .receipt-grid')?.textContent.includes('VERIFIED'));
    assert.equal((await bob.locator('#transfer-list details pre').first().textContent()).trim(),senderSignature);
    assert((await bob.locator('#transfer-list').textContent()).includes('Transfer timeline'));
    assert((await bob.locator('#transfer-list').textContent()).includes('Receiver timings'));
    assert(!((await bob.locator('#receive-status').textContent()).includes('UTC (sender clock):')));
    await alice.locator('#refresh-transfers').click();
    await alice.waitForFunction(()=>document.getElementById('transfer-list').textContent.includes('successfully transferred'));
    assert.equal((await alice.locator('#transfer-list details pre').first().textContent()).trim(),senderSignature);
    await bob.locator('#transfer-list').screenshot({path:input.screenshot.replace('hosted-dashboard','transfer-receipt')});
    await bob.reload();await bob.locator('#workspace').waitFor({state:'visible'});await navigate(bob,'transfer');
    await bob.waitForFunction(()=>document.getElementById('transfer-list').textContent.includes('successfully transferred'));
    assert.equal(await bob.locator('#receive-download a').count(),0);
    // File vault raw-key encryption and authenticated recovery.
    await navigate(alice,'vault');await alice.locator('#vault-file').setInputFiles(input.demo);
    await alice.locator('#vault-method').selectOption('Key file');await alice.locator('#vault-key').setInputFiles(input.key);
    await alice.locator('#encrypt').click();await alice.waitForFunction(()=>document.getElementById('encrypt-status').textContent.includes('Encryption workflow'));
    const encrypted=await saveDownload(alice,'#encrypted-download a',input.encrypted);
    await alice.locator('#decrypt-file').setInputFiles(input.encrypted);await alice.locator('#decrypt-key').setInputFiles(input.key);
    await alice.locator('#decrypt').click();await alice.waitForFunction(()=>document.getElementById('decrypt-status').textContent.includes('Authentication succeeded'));
    assert.deepEqual(await saveDownload(alice,'#decrypted-download a',input.vaultRecovered),fs.readFileSync(input.demo));
    await alice.reload();await alice.locator('#workspace').waitFor({state:'visible'});await navigate(alice,'vault');
    await alice.locator('#encrypted-download a').waitFor();assert.equal(await alice.locator('#decrypted-download a').count(),0);
    // Hashing, signing, verification and a changed-file rejection.
    await navigate(alice,'integrity');await alice.locator('#hash-file').setInputFiles(input.demo);
    await alice.locator('#hash').click();await alice.waitForFunction(()=>document.getElementById('hash-status').textContent.includes('SHA-256:'));
    await alice.locator('#sign-file').setInputFiles(input.demo);await alice.locator('#sign-password').fill('separate browser signing password!');
    await alice.locator('#sign').click();await alice.locator('#signature-download a').first().waitFor();
    await saveDownload(alice,'#signature-download a:first-child',input.signature);
    await saveDownload(alice,'#signature-download a:last-child',input.publicKey);
    await alice.locator('#verify-file').setInputFiles(input.demo);await alice.locator('#verify-signature').setInputFiles(input.signature);await alice.locator('#verify-public').setInputFiles(input.publicKey);
    await alice.locator('#verify').click();await alice.waitForFunction(()=>document.getElementById('verify-status').textContent.includes('Signature VERIFIED'));
    await alice.locator('#verify-file').setInputFiles(input.changed);await alice.locator('#verify').click();await alice.waitForFunction(()=>document.getElementById('verify-status').textContent.includes('FAILED'));
    await alice.locator('#page-integrity [data-analysis="hash_resistance"]').click();
    await alice.locator('#integrity-resistance-results canvas').first().waitFor({timeout:45000});
    assert.equal(await alice.locator('#integrity-resistance-results canvas').count(),4);
    assert((await alice.locator('#integrity-resistance-results').textContent()).includes('does not prove resistance'));
    assert.equal(await alice.locator('#hash_resistance-results canvas').count(),4);
    await navigate(alice,'analysis');await alice.locator('[data-analysis="avalanche"]').click();
    await alice.locator('#avalanche-results canvas').first().waitFor();
    await navigate(alice,'benchmark');await alice.locator('#page-benchmark [data-analysis="benchmarks"]').click();
    await alice.locator('#benchmarks-results canvas').first().waitFor({timeout:45000});
    await navigate(alice,'vault');await alice.locator('[data-analysis="password_lengths"]').click();
    await alice.locator('#password_lengths-results canvas').waitFor({timeout:45000});
    assert.equal(errors.length,0,errors.join('\n'));
    await navigate(alice,'dashboard');await alice.screenshot({path:input.screenshot,fullPage:true});
    process.stdout.write(JSON.stringify({success:true,browserErrors:errors,bytes:recovered.length,encrypted:CIPHER_MAGIC(encrypted),checks:['two isolated accounts','untrusted key rejection','wrong password rejection','signature verified','SHA-256 match','byte-exact recovery','persistent receipt','AES key-file roundtrip','encrypted output restored','hashing','RSA sign/verify','modified-file rejection','avalanche graph','six-size benchmark graphs','password character graph']}));
  }finally{await browser.close();}
})().catch(error=>{console.error(error.stack);process.exitCode=1;});
function CIPHER_MAGIC(bytes){return bytes.subarray(0,5).toString()==='CVLT1';}
