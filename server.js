// PanoramixRemote relay server (zero dependencies).
// Pairs a Windows "agent" (the PC being controlled) with a "viewer" (a browser)
// over WebSocket, so both sides only need an OUTBOUND connection — no port forwarding,
// no fixed IP, no VPN. The relay never inspects the binary screen/input frames; it only
// checks a shared secret and forwards bytes between the paired peers. It also serves the
// browser control page at "/".
//
// Env vars:
//   PORT          - provided by the host (Render/Koyeb/etc). Defaults to 8080 locally.
//   RELAY_SECRET  - shared secret. Every agent and viewer must present it. REQUIRED.

'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const ws = require('./wslite');

const PORT = parseInt(process.env.PORT || '8080', 10);
const SECRET = process.env.RELAY_SECRET || '';
if (!SECRET) { console.error('FATAL: RELAY_SECRET environment variable is not set.'); process.exit(1); }

const VIEWER_HTML = fs.readFileSync(path.join(__dirname, 'viewer.html'));

// name -> agent conn
const agents = new Map();

const server = http.createServer((req, res) => {
  if (req.url === '/health') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('OK'); return; }
  if (req.url === '/favicon.ico') { res.writeHead(204); res.end(); return; }
  if (req.url === '/' || req.url.startsWith('/?')) {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(VIEWER_HTML);
    return;
  }
  res.writeHead(404); res.end();
});

function send(conn, obj) { try { conn.send(JSON.stringify(obj), false); } catch (_) {} }

ws.attach(server, (conn) => {
  conn._role = null; conn._name = null; conn._peer = null;

  conn.on('message', (data, isBinary) => {
    if (conn._peer) { // paired: forward binary verbatim
      if (conn._peer.readyState === conn._peer.OPEN) conn._peer.send(data, true);
      return;
    }
    if (isBinary) return;
    let msg; try { msg = JSON.parse(data.toString()); } catch (_) { return; }
    if (msg.secret !== SECRET) { send(conn, { type: 'error', reason: 'bad-secret' }); conn.close(); return; }

    if (msg.role === 'agent') {
      const name = String(msg.machine || '').trim();
      if (!name) { send(conn, { type: 'error', reason: 'no-name' }); conn.close(); return; }
      const prev = agents.get(name);
      if (prev && prev !== conn) { send(prev, { type: 'replaced' }); try { prev.close(); } catch (_) {} }
      conn._role = 'agent'; conn._name = name; agents.set(name, conn);
      send(conn, { type: 'registered', machine: name });
      console.log(`[agent] "${name}" online (${agents.size} total)`);
      return;
    }
    if (msg.role === 'viewer') {
      if (msg.list) { send(conn, { type: 'machines', machines: [...agents.keys()] }); return; }
      const name = String(msg.machine || '').trim();
      const agent = agents.get(name);
      if (!agent) { send(conn, { type: 'error', reason: 'offline', machine: name }); return; }
      if (agent._peer) { send(conn, { type: 'error', reason: 'busy', machine: name }); return; }
      conn._role = 'viewer'; conn._name = name; conn._peer = agent; agent._peer = conn;
      send(agent, { type: 'viewer-connected' });
      send(conn, { type: 'connected', machine: name });
      console.log(`[pair] viewer <-> "${name}"`);
      return;
    }
    send(conn, { type: 'error', reason: 'bad-role' }); conn.close();
  });

  conn.on('close', () => {
    if (conn._role === 'agent' && conn._name && agents.get(conn._name) === conn) {
      agents.delete(conn._name);
      console.log(`[agent] "${conn._name}" gone (${agents.size} total)`);
    }
    if (conn._peer) {
      const peer = conn._peer; conn._peer = null;
      if (peer._peer === conn) peer._peer = null;
      send(peer, { type: 'peer-gone' });
    }
  });
});

server.listen(PORT, () => console.log(`PanoramixRemote relay listening on port ${PORT}`));
