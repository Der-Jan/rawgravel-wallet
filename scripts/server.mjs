import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {timingSafeEqual} from 'node:crypto';
import worker from '../worker/index.js';
const config=JSON.parse(await readFile('/run/secrets/wallet.json','utf8'));
const origin=process.env.PUBLIC_ORIGIN||'https://wallet.example.com';
config.PUBLIC_ORIGIN=origin;
const credentials=config.ADMIN_BASIC_AUTH;
function authorized(req){if(!credentials)return false;const expected=Buffer.from('Basic '+Buffer.from(credentials).toString('base64'));const actual=Buffer.from(req.headers.authorization||'');return actual.length===expected.length&&timingSafeEqual(actual,expected);}
const server=http.createServer(async(req,res)=>{
 if(req.url==='/healthz'){res.writeHead(200,{'Content-Type':'text/plain'});res.end('ok');return;}
 if(process.env.PUBLIC_ACCESS!=='true'&&!authorized(req)){res.writeHead(401,{'WWW-Authenticate':'Basic realm="RAWGRAVEL", charset="UTF-8"','Cache-Control':'no-store'});res.end('Anmeldung erforderlich.');return;}
 try{let size=0;const parts=[];for await(const part of req){size+=part.length;if(size>4096){res.writeHead(413);res.end('Anfrage zu groß.');return;}parts.push(part);}
 const url=new URL(req.url,origin);const r=await worker.fetch(new Request(url,{method:req.method,headers:req.headers,...(parts.length?{body:Buffer.concat(parts)}:{})}),config);res.writeHead(r.status,Object.fromEntries(r.headers));res.end(Buffer.from(await r.arrayBuffer()));
 }catch{res.writeHead(500,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify({error:'Die Anfrage konnte nicht verarbeitet werden.'}));}
});server.requestTimeout=15000;server.headersTimeout=10000;server.listen(3000,'0.0.0.0',()=>console.log('RAWGRAVEL server ready on port 3000'));
