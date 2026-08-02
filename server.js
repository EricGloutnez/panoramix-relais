// KÜTO — serveur de la plateforme de feuilles de caisse
// PIN (4 chiffres) pour l'iPad du comptoir ; mot de passe fort (haché scrypt) pour l'admin.
// N'utilise que les modules intégrés de Node (http, crypto, fs) ; Postgres seulement en production.
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const url = require('url');

const store = process.env.DATABASE_URL ? require('./store-pg') : require('./store-json');
const PUBLIC = path.join(__dirname, 'public');
const SECRET = process.env.SESSION_SECRET || 'kuto-secret-change-me';
const SYNC_KEY = process.env.SYNC_KEY || 'kuto-sync';

// --- Intégration Presto (app Supabase) — clé publique, adresse et restaurant Dix30 ---
const PRESTO = {
  url: process.env.PRESTO_URL || 'https://pzezuaqltyfyowlwlgue.supabase.co',
  anon: process.env.PRESTO_ANON || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB6ZXp1YXFsdHlmeW93bHdsZ3VlIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjkzNTQ2MTUsImV4cCI6MjA4NDkzMDYxNX0.HsDdgoT80H2RGSiC3GdiSj6WPe0qaMCr9MsaZyGcdqs',
  restaurant: process.env.PRESTO_RESTAURANT || 'e5d2fbcc-6e96-4202-8ae5-9c5ef2aa691a'
};
function prestoTime(hms){ if (!hms) return ''; const p = String(hms).split(':'); return p[0] + 'h' + (p[1] || '00'); }
function prestoIso(d){ return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2,'0') + '-' + String(d.getDate()).padStart(2,'0'); }

// Se connecte à Presto ; retourne { days: horaire Service par date, pool: toutes les personnes Service + managers }
async function prestoSync(email, password){
  const authRes = await fetch(PRESTO.url + '/auth/v1/token?grant_type=password', {
    method: 'POST',
    headers: { 'apikey': PRESTO.anon, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email, password: password })
  });
  if (!authRes.ok){ const e = new Error('auth'); e.code = 401; throw e; }
  const token = (await authRes.json()).access_token;
  if (!token){ const e = new Error('auth'); e.code = 401; throw e; }
  const H = { apikey: PRESTO.anon, Authorization: 'Bearer ' + token };

  const today = new Date();
  const mk = o => { const d = new Date(today); d.setDate(today.getDate() + o); return prestoIso(d); };
  const isService = p => /service/i.test(p || '');

  // Horaire (fenêtre proche) — quarts Service
  const schedUrl = PRESTO.url + '/rest/v1/shifts?select=employee_id,date,start_time,end_time,position'
    + '&restaurant_id=eq.' + PRESTO.restaurant + '&date=gte.' + mk(-7) + '&date=lte.' + mk(30);
  const schedRaw = await (await fetch(schedUrl, { headers: H })).json();
  const sched = (Array.isArray(schedRaw) ? schedRaw : []).filter(s => isService(s.position));

  // Bassin (fenêtre large) — toutes les personnes qui ont des quarts Service
  const poolUrl = PRESTO.url + '/rest/v1/shifts?select=employee_id,position'
    + '&restaurant_id=eq.' + PRESTO.restaurant + '&date=gte.' + mk(-120) + '&date=lte.' + mk(30);
  const poolRaw = await (await fetch(poolUrl, { headers: H })).json();
  const poolIds = new Set((Array.isArray(poolRaw) ? poolRaw : []).filter(s => isService(s.position)).map(s => s.employee_id).filter(Boolean));

  // + les managers (rôle)
  try {
    const rolesUrl = PRESTO.url + '/rest/v1/user_roles?select=user_id&restaurant_id=eq.' + PRESTO.restaurant + '&role=eq.manager';
    const roles = await (await fetch(rolesUrl, { headers: H })).json();
    (Array.isArray(roles) ? roles : []).forEach(r => { if (r.user_id) poolIds.add(r.user_id); });
  } catch(e){}

  // Noms (union horaire + bassin)
  const allIds = new Set([...poolIds]);
  sched.forEach(s => { if (s.employee_id) allIds.add(s.employee_id); });
  const names = {};
  const idArr = [...allIds];
  if (idArr.length){
    const pUrl = PRESTO.url + '/rest/v1/profiles?select=user_id,full_name&user_id=in.(' + idArr.join(',') + ')';
    const profs = await (await fetch(pUrl, { headers: H })).json();
    (Array.isArray(profs) ? profs : []).forEach(p => { names[p.user_id] = p.full_name; });
  }

  const days = {};
  sched.forEach(s => {
    const nm = names[s.employee_id] || 'Employé';
    (days[s.date] = days[s.date] || []).push({ name: nm, time: prestoTime(s.start_time) + '–' + prestoTime(s.end_time) });
  });
  const pool = [...poolIds].map(id => names[id]).filter(Boolean).sort((a, b) => a.localeCompare(b));
  return { days: days, pool: pool };
}

// ---------- Utilitaires ----------
function adminToken(){ return crypto.createHmac('sha256', SECRET).update('admin-v1').digest('hex'); }

function hashPw(pw){
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPw(pw, stored){
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(pw, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex'), b = Buffer.from(test, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function send(res, code, obj){
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}
function readBody(req){
  return new Promise(resolve => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 4e6) req.destroy(); });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch(e){ resolve({}); } });
  });
}

// Sert l'application (index.html), qu'il soit dans public/ ou à la racine du dépôt.
function serveStatic(req, res){
  const candidates = [
    path.join(PUBLIC, 'index.html'),
    path.join(__dirname, 'index.html')
  ];
  for (const f of candidates){
    try {
      const buf = fs.readFileSync(f);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(buf);
    } catch(e){ /* essaie le prochain */ }
  }
  res.writeHead(404);
  res.end('index.html introuvable');
}

// ---------- Valeurs initiales ----------
async function ensureDefaults(){
  const cfg = await store.getConfig();
  const patch = {};
  if (!cfg.pin) patch.pin = process.env.INITIAL_PIN || '1234';
  if (!cfg.admin_hash) patch.admin_hash = hashPw(process.env.INITIAL_ADMIN_PASSWORD || 'kuto-admin');
  if (Object.keys(patch).length) await store.setConfig(patch);
}

// ---------- Routeur ----------
async function handleApi(req, res, pathname, query){
  const cfg = await store.getConfig();
  const pinOk = (req.headers['x-pin'] || '') === cfg.pin;
  const adminOk = (req.headers['x-admin-token'] || '') === adminToken();

  // Auth
  if (req.method === 'POST' && pathname === '/api/login'){
    const b = await readBody(req);
    return (b.pin || '') === cfg.pin ? send(res, 200, { ok: true }) : send(res, 401, { ok: false });
  }
  if (req.method === 'POST' && pathname === '/api/admin/login'){
    const b = await readBody(req);
    return verifyPw(b.password || '', cfg.admin_hash)
      ? send(res, 200, { ok: true, token: adminToken() })
      : send(res, 401, { ok: false });
  }
  if (req.method === 'POST' && pathname === '/api/admin/settings'){
    if (!adminOk) return send(res, 401, { error: 'Accès admin requis' });
    const b = await readBody(req);
    const patch = {};
    if (b.pin && /^\d{4}$/.test(b.pin)) patch.pin = b.pin;
    if (b.adminPassword && b.adminPassword.length >= 6) patch.admin_hash = hashPw(b.adminPassword);
    if (!Object.keys(patch).length) return send(res, 400, { error: 'PIN 4 chiffres, mot de passe ≥ 6 caractères' });
    await store.setConfig(patch);
    return send(res, 200, { ok: true });
  }

  // Roster
  if (pathname === '/api/roster'){
    if (req.method === 'GET'){ if (!pinOk) return send(res, 401, { error: 'PIN' }); return send(res, 200, await store.getServers()); }
    if (req.method === 'POST'){
      if (!adminOk) return send(res, 401, { error: 'Admin' });
      const b = await readBody(req); const name = (b.name || '').trim();
      if (!name) return send(res, 400, { error: 'Nom requis' });
      return send(res, 200, await store.addServer(name));
    }
  }
  if (pathname.startsWith('/api/roster/') && req.method === 'DELETE'){
    if (!adminOk) return send(res, 401, { error: 'Admin' });
    await store.deleteServer(parseInt(pathname.split('/').pop(), 10));
    return send(res, 200, { ok: true });
  }

  // Feuilles
  if (pathname === '/api/sheets/find' && req.method === 'GET'){
    if (!pinOk) return send(res, 401, { error: 'PIN' });
    return send(res, 200, await store.findSheet(query.date, query.service));
  }
  if (pathname === '/api/sheets'){
    if (req.method === 'GET'){ if (!pinOk) return send(res, 401, { error: 'PIN' }); return send(res, 200, await store.getSheets({ start: query.start, end: query.end })); }
    if (req.method === 'POST'){
      if (!pinOk) return send(res, 401, { error: 'PIN' });
      const b = await readBody(req);
      if (!b || !b.id) return send(res, 400, { error: 'Feuille invalide' });
      return send(res, 200, await store.upsertSheet(b));
    }
  }
  if (pathname.startsWith('/api/sheets/') && req.method === 'DELETE'){
    if (!adminOk) return send(res, 401, { error: 'Admin' });
    await store.deleteSheet(decodeURIComponent(pathname.split('/').pop()));
    return send(res, 200, { ok: true });
  }

  // Horaire (import Presto)
  if (pathname === '/api/schedule'){
    if (req.method === 'GET'){
      if (!pinOk) return send(res, 401, { error: 'PIN' });
      return send(res, 200, await store.getScheduleForDate(query.date));
    }
    if (req.method === 'POST'){
      if ((req.headers['x-sync-key'] || '') !== SYNC_KEY) return send(res, 401, { error: 'Clé de synchro invalide' });
      const b = await readBody(req);
      if (!b || !b.days || typeof b.days !== 'object') return send(res, 400, { error: 'Format invalide (attendu { days: {date: [...] } })' });
      await store.setSchedule(b.days);
      return send(res, 200, { ok: true, dates: Object.keys(b.days).length });
    }
  }

  // Synchronisation Presto (le mot de passe n'est jamais conservé ; l'identifiant, oui)
  if (pathname === '/api/presto/email' && req.method === 'GET'){
    if (!pinOk) return send(res, 401, { error: 'PIN' });
    return send(res, 200, { email: cfg.presto_email || '' });
  }
  if (pathname === '/api/presto/pool' && req.method === 'GET'){
    if (!pinOk) return send(res, 401, { error: 'PIN' });
    let p = []; try { p = JSON.parse(cfg.presto_pool || '[]'); } catch(e){}
    return send(res, 200, p);
  }
  if (pathname === '/api/presto/sync' && req.method === 'POST'){
    if (!pinOk) return send(res, 401, { error: 'PIN' });
    const b = await readBody(req);
    const email = (b.email || '').trim(), password = b.password || '';
    if (!email || !password) return send(res, 400, { error: 'Courriel et mot de passe requis' });
    try {
      const result = await prestoSync(email, password);
      await store.setSchedule(result.days);
      await store.setConfig({ presto_email: email, presto_pool: JSON.stringify(result.pool || []) });
      const names = [...new Set(Object.values(result.days).flat().map(x => x.name))];
      return send(res, 200, { ok: true, dates: Object.keys(result.days).length, servers: names, pool: (result.pool || []).length });
    } catch(e){
      if (e && e.code === 401) return send(res, 401, { error: 'Identifiants Presto invalides' });
      console.error('Presto sync:', e && e.message);
      return send(res, 500, { error: 'Échec de la synchronisation Presto' });
    }
  }

  if (pathname === '/api/health') return send(res, 200, { ok: true });
  return send(res, 404, { error: 'Route inconnue' });
}

const server = http.createServer(async (req, res) => {
  // CORS : permet au bookmarklet (sur le site de Presto) d'envoyer l'horaire
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-pin, x-admin-token, x-sync-key');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  if (req.method === 'OPTIONS'){ res.writeHead(204); return res.end(); }

  const parsed = url.parse(req.url, true);
  if (parsed.pathname.startsWith('/api/')){
    try { await handleApi(req, res, parsed.pathname, parsed.query); }
    catch(e){ console.error(e); send(res, 500, { error: 'Erreur serveur' }); }
  } else {
    serveStatic(req, res);
  }
});

const PORT = process.env.PORT || 3000;
store.init()
  .then(ensureDefaults)
  .then(() => server.listen(PORT, () => console.log('KÜTO en écoute sur le port ' + PORT)))
  .catch(err => { console.error('Erreur de démarrage:', err); process.exit(1); });
