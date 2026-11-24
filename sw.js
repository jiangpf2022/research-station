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
  for (const r of KEYS) (r.val && r.val.key && r.val.exp > now ? live.push({id:r.id, key:r.val.key}) : dead.push(r.id));
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
  }
  return TABLES;
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
        return new Response(body, {headers: {'Content-Type': hit[1], 'Cache-Control': 'no-store'}});
      }
    }
    return toLock(path);
  })());
});
