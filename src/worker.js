import {html} from './page.js';
import {configuration,validate,createPass} from './pass.js';
import QRCode from 'qrcode';
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin'};
function json(data,status=200){return Response.json(data,{status,headers});}
export default {async fetch(request,env){
 const url=new URL(request.url);
 if(request.method==='GET'&&url.pathname==='/')return new Response(html,{headers:{...headers,'Content-Type':'text/html; charset=utf-8','Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'"}});
 if(request.method==='GET'&&url.pathname==='/api/status')return json({ready:configuration(env)});
 if(request.method==='GET'&&url.pathname==='/api/qr'){const number=url.searchParams.get('number')||'';if(!/^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/.test(number))return json({error:'Ungültige Mitgliedsnummer.'},400);return new Response(await QRCode.toString(number,{type:'svg',margin:4,errorCorrectionLevel:'M'}),{headers:{...headers,'Content-Type':'image/svg+xml'}});}
 if(request.method==='POST'&&url.pathname==='/api/pass'){
 // Accept the configured external origin when running behind a proxy.
 const trustedOrigins=new Set([url.origin,...(env.PUBLIC_ORIGIN?[new URL(env.PUBLIC_ORIGIN).origin]:[])]);
 const origin=request.headers.get('Origin');
 if((origin&&!trustedOrigins.has(origin))||request.headers.get('Sec-Fetch-Site')==='cross-site')return json({error:'Anfrage nicht erlaubt.'},403);
 if(!request.headers.get('Content-Type')?.includes('application/x-www-form-urlencoded'))return json({error:'Ungültiges Formular.'},415);
 const body=await request.text();if(body.length>2048)return json({error:'Anfrage zu groß.'},413);
 let d;try{d=validate(Object.fromEntries(new URLSearchParams(body)));}catch(e){return json({error:e.message},400);}
 if(!configuration(env))return json({error:'Apple-Wallet-Signierung ist noch nicht eingerichtet. Das Pass-Type-ID-Zertifikat fehlt.'},503);
 try{const bytes=await createPass(d,env);return new Response(bytes,{headers:{...headers,'Content-Type':'application/vnd.apple.pkpass','Content-Disposition':'attachment; filename="RAWGRAVEL-'+d.memberNumber+'.pkpass"'}});}catch(error){return json({error:'Der Pass konnte nicht signiert werden. Bitte die Zertifikatskonfiguration prüfen.',code:error.signingStage||'SIGNING'},500);}
 }
 return json({error:'Nicht gefunden.'},404);
}};
