// Serves /<repo>/app/* by decrypting ciphertext with the keys of the projects unlocked in this browser.
// A path no unlocked project owns sends the visitor back to the password box.
const SCOPE = new URL(self.registration.scope).pathname.replace(/\/$/, '');   // /repo/app
const BASE = SCOPE.replace(/\/app$/, '');                                       // /repo
let KEYS = null, TABLES = null, KEY_CHECKED = 0;

function idb(){return new Promise((ok,no)=>{const r=indexedDB.open('ps-vault-v2',1);r.onupgradeneeded=()=>r.result.createObjectStore('k');r.onsuccess=()=>ok(r.result);r.onerror=()=>no(r.error)})}
async function loadKeys(){
  const db = await idb();
  KEYS = await new Promise((ok,no)=>{const out=[];const t=db.transaction('k');const c=t.objectStore('k').openCursor();
    c.onsuccess=()=>{const cur=c.result;if(cur){out.push({id:cur.key,val:cur.value});cur.continue()}else ok(out)};c.onerror=()=>no(c.error)});
  // keep only unexpired unlocks ({key, exp}); anything older than 3 days (or from the earlier format) is dropped
  const now = Date.now(), live = [], dead = [];
  for (const r of KEYS) {
    if (r.val && r.val.raw && r.val.exp > now) {
      try { live.push({id:r.id, key: await crypto.subtle.importKey('raw', r.val.raw, {name:'AES-CBC'}, false, ['decrypt'])}); continue; } catch (_) {}
    }
    dead.push(r.id);
  }
  if (dead.length) await new Promise(ok=>{const t=db.transaction('k','readwrite');for(const id of dead)t.objectStore('k').delete(id);t.oncomplete=ok});
  KEYS = live; KEY_CHECKED = now;
  TABLES = null;
}
async function clearKeys(){const db=await idb();await new Promise(ok=>{const t=db.transaction('k','readwrite');t.objectStore('k').clear();t.oncomplete=ok});KEYS=[];TABLES=[]}
async function dec(key, buf){ return crypto.subtle.decrypt({name:'AES-CBC', iv:buf.slice(0,16)}, key, buf.slice(16)); }
async function fetchBin(url){ const r = await fetch(url, {cache:'no-cache'}); if (!r.ok) throw new Error(r.status); return r.arrayBuffer(); }
async function tables(){
  if (!KEYS || Date.now() - KEY_CHECKED > 60000) { await loadKeys(); TABLES = null; }   // re-check expiry every minute
  if (!TABLES) {
    TABLES = [];
    for (const k of KEYS) {
      try { TABLES.push({key:k.key, map:JSON.parse(new TextDecoder().decode(await dec(k.key, await fetchBin(BASE + '/m/' + k.id + '.bin'))))}); }
      catch (_) { /* entry re-published with a new key or removed: ignore */ }
    }
    // Every project unlocked in this browser -> assemble the global key (XOR of the per-project shares)
    // and open the station-wide pages (home, GPU queue, project status, figure review).
    try {
      const cfg = await (await fetch(BASE + '/config.json', {cache:'no-cache'})).json();
      const have = Object.fromEntries(KEYS.map(k => [k.id, k.key]));
      if (cfg.g && cfg.entries.length && cfg.entries.every(e => have[e.id] && e.share)) {
        let G = new Uint8Array(32);
        for (const e of cfg.entries) {
          const s = new Uint8Array(await dec(have[e.id], b64(e.share).buffer));
          G = G.map((x, i) => x ^ s[i]);
        }
        const gk = await crypto.subtle.importKey('raw', G, {name:'AES-CBC'}, false, ['decrypt']);
        TABLES.push({key:gk, map:JSON.parse(new TextDecoder().decode(await dec(gk, await fetchBin(BASE + '/m/' + cfg.g + '.bin'))))});
      }
    } catch (_) { /* global pages stay closed */ }
  }
  return TABLES;
}
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
// Media players (Safari in particular) ask for byte ranges and need a 206 answer to play video/audio.
function respond(req, body, type){
  const total = body.byteLength, range = req.headers.get('range');
  if (!/charset/i.test(type) && /^(text\/|application\/(json|x-ndjson|javascript)|image\/svg)/i.test(type)) type += '; charset=utf-8';
  const base = {'Content-Type': type, 'Cache-Control': 'no-store', 'Accept-Ranges': 'bytes'};
  const m = range && /^bytes=(\d*)-(\d*)$/.exec(range.trim());
  if (m && (m[1] !== '' || m[2] !== '')) {
    let start = m[1] === '' ? Math.max(0, total - Number(m[2])) : Number(m[1]);
    let end = m[1] !== '' && m[2] !== '' ? Math.min(Number(m[2]), total - 1) : total - 1;
    if (start >= total || start > end) return new Response(null, {status: 416, headers: {'Content-Range': 'bytes */' + total}});
    return new Response(body.slice(start, end + 1), {status: 206, headers: {...base, 'Content-Range': `bytes ${start}-${end}/${total}`, 'Content-Length': String(end - start + 1)}});
  }
  return new Response(body, {headers: {...base, 'Content-Length': String(total)}});
}
function notOnline(path){
  const html = '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>&#8203;</title>'
    + '<body style="font-family:-apple-system,system-ui,sans-serif;background:#f0f4f5;color:#152934;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">'
    + '<div style="text-align:center;max-width:32rem;padding:1rem"><p>这个页面属于一个还没解锁的项目，或者只在本机研究站、没有放到网上。<br>'
    + 'This page belongs to a project not yet unlocked here, or exists only on the local research station.</p>'
    + '<p><a href="' + BASE + '/?next=' + encodeURIComponent(path) + '" style="color:#fff;background:#14635f;padding:.45rem .9rem;border-radius:.5rem;text-decoration:none">输入密码 Enter password</a></p>'
    + '<p><a href="javascript:history.back()" style="color:#14635f">返回 Back</a> · <a href="' + BASE + '/" style="color:#14635f">首页 Home</a></p></div></body>';
  return new Response(html, {status: 404, headers: {'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store'}});
}
function toLock(path){ return Response.redirect(BASE + '/?next=' + encodeURIComponent(path), 302); }

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', ev => ev.waitUntil(self.clients.claim()));
self.addEventListener('message', ev => { if (ev.data === 'reload-keys') { KEYS = null; TABLES = null; } });
self.addEventListener('fetch', ev => {
  const url = new URL(ev.request.url);
  if (url.origin !== location.origin || !url.pathname.startsWith(SCOPE + '/')) return;
  ev.respondWith((async () => {
    const path = url.pathname.slice(SCOPE.length) + url.search;
    if (url.pathname.slice(SCOPE.length) === '/logout') { await clearKeys(); return Response.redirect(BASE + '/?logout=1', 302); }
    for (const t of await tables()) {
      const hit = t.map[path] || t.map[url.pathname.slice(SCOPE.length)];
      if (hit && typeof hit !== 'string') {
        const body = await dec(t.key, await fetchBin(BASE + '/e/' + hit[0] + '.bin'));
        return respond(ev.request, body, hit[1]);
      }
    }
    // Unlocked but this page was never put online (station home, cross-project pages, files > 95 MB):
    // say so instead of asking for a password again. Nothing unlocked: back to the password box.
    if ((await tables()).length) return notOnline(path);
    return toLock(path);
  })());
});
