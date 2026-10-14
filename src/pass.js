import forge from 'node-forge';
import {zipSync,strToU8} from 'fflate';
import {assets} from './assets.js';
// Workers expose Web Crypto rather than Node's crypto.randomBytes.
forge.random.getBytesSync = count => {
 const bytes = new Uint8Array(count);
 for(let offset=0;offset<count;offset+=65536)crypto.getRandomValues(bytes.subarray(offset,Math.min(count,offset+65536)));
 let binary='';for(const byte of bytes)binary+=String.fromCharCode(byte);return binary;
};
forge.random.getBytes = (count,callback) => {try{const bytes=forge.random.getBytesSync(count);if(callback){callback(null,bytes);return;}return bytes;}catch(error){if(callback){callback(error);return;}throw error;}};
export const keys=['PASS_CERTIFICATE_PEM','PASS_PRIVATE_KEY_PEM','APPLE_WWDR_CERTIFICATE_PEM','PASS_TYPE_IDENTIFIER','APPLE_TEAM_IDENTIFIER'];
const pem=x=>x.replace(/\\n/g,'\n');
export function configuration(env){return keys.every(k=>typeof env[k]==='string'&&env[k].trim());}
export function validate(data){
 if(!data||typeof data!=='object')throw Error('Bitte die Mitgliedsdaten eingeben.');
 const {name,memberNumber,validUntil}=data;
 if(typeof name!=='string'||!name.trim()||name.trim().length>70||/[\x00-\x1f]/.test(name))throw Error('Bitte einen Namen mit höchstens 70 Zeichen eingeben.');
 if(typeof memberNumber!=='string'||!/^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/.test(memberNumber))throw Error('Mitgliedsnummer: 1–40 Zeichen, Buchstaben, Zahlen, Punkt, Bindestrich oder Unterstrich.');
 if(typeof validUntil!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(validUntil)||Number(validUntil.slice(0,4))<2000||Number(validUntil.slice(0,4))>2100||new Date(validUntil+'T12:00:00Z').toISOString().slice(0,10)!==validUntil)throw Error('Bitte ein gültiges Datum zwischen 2000 und 2100 eingeben.');
 return {name:name.trim(),memberNumber,validUntil};
}
export function passData(d,env){
 const noon=new Date(d.validUntil+'T12:00:00Z');
 const berlinHour=Number(new Intl.DateTimeFormat('en-GB',{timeZone:'Europe/Berlin',hour:'2-digit',hourCycle:'h23'}).format(noon));
 const expiration=new Date(Date.parse(d.validUntil+'T23:59:59Z')-(berlinHour-12)*3600000).toISOString();
 return {formatVersion:1,passTypeIdentifier:env.PASS_TYPE_IDENTIFIER,teamIdentifier:env.APPLE_TEAM_IDENTIFIER,serialNumber:d.memberNumber,organizationName:'RAWGRAVEL',description:'RAWGRAVEL Mitgliedskarte',logoText:'RAWGRAVEL',backgroundColor:'rgb(28, 41, 52)',foregroundColor:'rgb(255, 255, 255)',labelColor:'rgb(193, 239, 37)',expirationDate:expiration,barcodes:[{format:'PKBarcodeFormatQR',message:d.memberNumber,messageEncoding:'iso-8859-1',altText:d.memberNumber}],generic:{headerFields:[{key:'type',label:'',value:'MEMBER'}],primaryFields:[{key:'name',label:'NAME',value:d.name}],secondaryFields:[{key:'member',label:'MITGLIEDSNUMMER',value:d.memberNumber}],auxiliaryFields:[{key:'expiry',label:'GÜLTIG BIS',value:d.validUntil.split('-').reverse().join('.')},{key:'status',label:'STATUS BEI AUSSTELLUNG',value:new Date(expiration)>new Date()?'Aktiv':'Abgelaufen'}],backFields:[{key:'brand',label:'RAWGRAVEL Member',value:'GRAVEL · ROAD · ADVENTURE'},{key:'note',label:'Gültigkeit',value:'Gültig bis einschließlich '+d.validUntil.split('-').reverse().join('.')+'. Der Status bei Ausstellung wird nicht automatisch aktualisiert.'}]}};
}
export async function createPass(d,env){
 let stage="CERTIFICATE_PARSE";try{
 const cert=forge.pki.certificateFromPem(pem(env.PASS_CERTIFICATE_PEM));
 const wwdr=forge.pki.certificateFromPem(pem(env.APPLE_WWDR_CERTIFICATE_PEM));
 stage="PRIVATE_KEY_PARSE";
 const key=forge.pki.privateKeyFromPem(pem(env.PASS_PRIVATE_KEY_PEM));
 if(new Date()<cert.validity.notBefore||new Date()>cert.validity.notAfter)throw Error('Zertifikat ist nicht gültig.');
 const uid=cert.subject.getField({type:'0.9.2342.19200300.100.1.1'});
 const team=cert.subject.getField('OU');
 if(!uid||uid.value!==env.PASS_TYPE_IDENTIFIER||!team||team.value!==env.APPLE_TEAM_IDENTIFIER)throw Error('Zertifikat und Pass-Kennung stimmen nicht überein.');
 if(!cert.publicKey.n.equals(key.n)||!cert.publicKey.e.equals(key.e))throw Error('Schlüssel und Zertifikat stimmen nicht überein.');
 stage="CERTIFICATE_CHAIN";
 const hashes={'1.2.840.113549.1.1.11':'SHA-256','1.2.840.113549.1.1.12':'SHA-384','1.2.840.113549.1.1.13':'SHA-512'};
 const hash=hashes[cert.signatureOid];if(!hash)throw Error('Nicht unterstützte Zertifikatsignatur.');
 const der=forge.asn1.toDer(cert.tbsCertificate).getBytes();
 const spki=forge.asn1.toDer(forge.pki.publicKeyToAsn1(wwdr.publicKey)).getBytes();
 const toBytes=x=>Uint8Array.from(x,c=>c.charCodeAt(0));
 const verificationKey=await crypto.subtle.importKey('spki',toBytes(spki),{name:'RSASSA-PKCS1-v1_5',hash},false,['verify']);
 if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',verificationKey,toBytes(cert.signature),toBytes(der)))throw Error('WWDR-Zertifikat passt nicht zum Signierzertifikat.');
 stage="MANIFEST";
 const files={'pass.json':strToU8(JSON.stringify(passData(d,env)))};
 for(const [name,b64]of Object.entries(assets))files[name]=Uint8Array.from(atob(b64),c=>c.charCodeAt(0));
 const manifest={};for(const [name,bytes]of Object.entries(files)){const md=forge.md.sha1.create();md.update(String.fromCharCode(...bytes));manifest[name]=md.digest().toHex();}
 files['manifest.json']=strToU8(JSON.stringify(manifest));
 stage="CMS_SIGNATURE";
 const signed=forge.pkcs7.createSignedData();signed.content=forge.util.createBuffer(String.fromCharCode(...files['manifest.json']));signed.addCertificate(cert);signed.addCertificate(wwdr);signed.addSigner({key,certificate:cert,digestAlgorithm:forge.pki.oids.sha256,authenticatedAttributes:[{type:forge.pki.oids.contentType,value:forge.pki.oids.data},{type:forge.pki.oids.messageDigest},{type:forge.pki.oids.signingTime,value:new Date()}]});signed.sign({detached:true});
 files.signature=Uint8Array.from(forge.asn1.toDer(signed.toAsn1()).getBytes(),c=>c.charCodeAt(0));
 stage="ZIP";
 return zipSync(files,{level:6});
 }catch(error){error.signingStage=stage;throw error;}
}
