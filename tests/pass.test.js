import test from 'node:test';import assert from 'node:assert/strict';
import forge from 'node-forge';import {unzipSync,strFromU8} from 'fflate';import {createPass,passData,validate} from '../src/pass.js';import worker from '../worker/index.js';
const d={name:'Max Mustermann',memberNumber:'RG-2026-00000G',validUntil:'2027-10-12'};
test('input rejects invalid dates and control characters',()=>{assert.deepEqual(validate(d),d);for(const validUntil of ['2027-02-30','2027-13-01','2027-00-00','bad'])assert.throws(()=>validate({...d,validUntil}));assert.throws(()=>validate({...d,memberNumber:'../escape'}));assert.throws(()=>validate({...d,name:'Jan\nHeader'}));});
test('expiry honors Berlin summer and winter time',()=>{assert.equal(passData({...d,validUntil:'2027-07-01'},{}).expirationDate,'2027-07-01T21:59:59.000Z');assert.equal(passData({...d,validUntil:'2027-12-01'},{}).expirationDate,'2027-12-01T22:59:59.000Z');});
test('unconfigured generator returns honest status and refuses downloads',async()=>{const status=await worker.fetch(new Request('http://localhost/api/status'),{});assert.equal((await status.json()).ready,false);const response=await worker.fetch(new Request('http://localhost/api/pass',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(d)}),{});assert.equal(response.status,503);const qr=await worker.fetch(new Request('http://localhost/api/qr?number='+d.memberNumber),{});assert.equal(qr.status,200);assert.match(await qr.text(),/<svg/);});
test('signed archive has correct fields, hashes and detached CMS signature',async()=>{
 const key=forge.pki.rsa.generateKeyPair(2048);
 function makeCert(subject,issuer,publicKey,signingKey,serial){const cert=forge.pki.createCertificate();cert.publicKey=publicKey;cert.serialNumber=serial;cert.validity.notBefore=new Date(Date.now()-10000);cert.validity.notAfter=new Date(Date.now()+86400000);cert.setSubject(subject);cert.setIssuer(issuer);cert.sign(signingKey,forge.md.sha256.create());return cert;}
 const rootAttrs=[{name:'commonName',value:'Test WWDR'}];const root=makeCert(rootAttrs,rootAttrs,key.publicKey,key.privateKey,'01');const signer=forge.pki.rsa.generateKeyPair(2048);const attrs=[{type:'0.9.2342.19200300.100.1.1',value:'pass.test.rawgravel'},{name:'organizationalUnitName',value:'TESTTEAM01'}];const cert=makeCert(attrs,rootAttrs,signer.publicKey,key.privateKey,'02');
 const env={PASS_CERTIFICATE_PEM:forge.pki.certificateToPem(cert),PASS_PRIVATE_KEY_PEM:forge.pki.privateKeyToPem(signer.privateKey),APPLE_WWDR_CERTIFICATE_PEM:forge.pki.certificateToPem(root),PASS_TYPE_IDENTIFIER:'pass.test.rawgravel',APPLE_TEAM_IDENTIFIER:'TESTTEAM01'};
 const hosted=await worker.fetch(new Request('http://localhost/api/pass',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(d)}),env);assert.equal(hosted.status,200,await hosted.clone().text());
 const files=unzipSync(await createPass(d,env));const pass=JSON.parse(strFromU8(files['pass.json']));assert.equal(pass.generic.primaryFields[0].value,d.name);assert.equal(pass.serialNumber,d.memberNumber);assert.equal(pass.barcodes[0].message,d.memberNumber);const manifest=JSON.parse(strFromU8(files['manifest.json']));for(const [name,hash]of Object.entries(manifest))assert.equal(forge.md.sha1.create().update(String.fromCharCode(...files[name])).digest().toHex(),hash);
 // Verify independently with native OpenSSL in the next integration check.
 const cms=forge.pkcs7.messageFromAsn1(forge.asn1.fromDer(String.fromCharCode(...files.signature)));assert.equal(cms.certificates.length,2);assert.ok(files['icon@3x.png']);
 const {mkdtemp,writeFile,rm}=await import('node:fs/promises');const {tmpdir}=await import('node:os');const {join}=await import('node:path');const {execFileSync}=await import('node:child_process');const dir=await mkdtemp(join(tmpdir(),'rawgravel-test-'));try{await writeFile(join(dir,'signature'),files.signature);await writeFile(join(dir,'manifest'),files['manifest.json']);execFileSync('openssl',['cms','-verify','-binary','-inform','DER','-in',join(dir,'signature'),'-content',join(dir,'manifest'),'-noverify','-out',join(dir,'verified')],{stdio:'pipe'});}finally{await rm(dir,{recursive:true});}
 await assert.rejects(()=>createPass(d,{...env,PASS_TYPE_IDENTIFIER:'pass.wrong'}));
});

test('browser form origins work through hosting proxy and reject foreign origins',async()=>{
 const publicOrigin='https://wallet.example.com';
 const submit=(origin,fetchSite)=>worker.fetch(new Request('https://internal-worker.example/api/pass',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Origin:origin,...(fetchSite?{'Sec-Fetch-Site':fetchSite}:{})},body:new URLSearchParams(d)}),{PUBLIC_ORIGIN:publicOrigin});
 assert.equal((await submit(publicOrigin,'same-origin')).status,503);
 assert.equal((await submit('https://internal-worker.example','same-origin')).status,503);
 assert.equal((await submit('https://untrusted.example','cross-site')).status,403);
 assert.equal((await submit('null')).status,403);
 const page=await worker.fetch(new Request(publicOrigin),{});assert.equal(page.headers.get('Referrer-Policy'),'same-origin');
});
