import fs from 'node:fs';
const read=p=>fs.readFileSync(new URL(p,import.meta.url),'utf8');
let script=[read('engine.js'),read('content.js'),read('ui.js')].map(s=>s.replace(/^import .*;\s*$/gm,'').replace(/^export /gm,'')).join('\n');
if(script.includes('</script'))throw new Error('Unexpected script closing sequence.');
const page=read('shell.html').replace('/* INLINE_STYLE */',read('styles.css')).replace('/* INLINE_SCRIPT */',script);
fs.mkdirSync(new URL('dist/',import.meta.url),{recursive:true});fs.writeFileSync(new URL('dist/index.html',import.meta.url),page);
console.log('Built self-contained dist/index.html; no runtime dependencies.');
