import {build} from 'esbuild';
await build({entryPoints:['src/worker.js'],outfile:'worker/index.js',bundle:true,format:'esm',platform:'browser',target:'es2022',minify:true,define:{'global':'globalThis'}});
