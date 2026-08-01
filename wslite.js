// Minimal, dependency-free RFC6455 WebSocket implementation (server + a small client for tests).
// Enough for our needs: text + binary messages, ping/pong, close, fragmentation reassembly.
'use strict';
const crypto = require('crypto');
const http = require('http');
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function acceptKey(key) {
  return crypto.createHash('sha1').update(key + GUID).digest('base64');
}

// Encode a single frame. mask=true only for the client side.
function encodeFrame(opcode, payload, mask) {
  payload = payload || Buffer.alloc(0);
  const len = payload.length;
  let header;
  let offset;
  if (len < 126) { header = Buffer.alloc(2); header[1] = len; offset = 2; }
  else if (len < 65536) { header = Buffer.alloc(4); header[1] = 126; header.writeUInt16BE(len, 2); offset = 4; }
  else { header = Buffer.alloc(10); header[1] = 127; header.writeUInt32BE(0, 2); header.writeUInt32BE(len, 6); offset = 10; }
  header[0] = 0x80 | (opcode & 0x0f); // FIN + opcode
  if (mask) {
    header[1] |= 0x80;
    const mkey = crypto.randomBytes(4);
    const masked = Buffer.allocUnsafe(len);
    for (let i = 0; i < len; i++) masked[i] = payload[i] ^ mkey[i & 3];
    return Buffer.concat([header, mkey, masked]);
  }
  return Buffer.concat([header, payload]);
}

// A parser that consumes bytes and emits complete messages.
class Parser {
  constructor(onMessage, onControl) {
    this.buf = Buffer.alloc(0);
    this.onMessage = onMessage;   // (buffer, isBinary)
    this.onControl = onControl;   // (opcode, buffer)
    this.fragments = [];
    this.fragOpcode = null;
  }
  push(chunk) {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    // Parse as many frames as available.
    for (;;) {
      if (this.buf.length < 2) return;
      const b0 = this.buf[0], b1 = this.buf[1];
      const fin = (b0 & 0x80) !== 0;
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let off = 2;
      if (len === 126) { if (this.buf.length < off + 2) return; len = this.buf.readUInt16BE(off); off += 2; }
      else if (len === 127) { if (this.buf.length < off + 8) return; const hi = this.buf.readUInt32BE(off); const lo = this.buf.readUInt32BE(off + 4); len = hi * 4294967296 + lo; off += 8; }
      let mkey = null;
      if (masked) { if (this.buf.length < off + 4) return; mkey = this.buf.slice(off, off + 4); off += 4; }
      if (this.buf.length < off + len) return; // wait for full payload
      let payload = this.buf.slice(off, off + len);
      if (masked) { const out = Buffer.allocUnsafe(len); for (let i = 0; i < len; i++) out[i] = payload[i] ^ mkey[i & 3]; payload = out; }
      this.buf = this.buf.slice(off + len);

      if (opcode === 0x8 || opcode === 0x9 || opcode === 0xA) { this.onControl(opcode, payload); continue; }
      // data frame (0x1 text, 0x2 binary, 0x0 continuation)
      if (opcode === 0x0) {
        this.fragments.push(payload);
      } else {
        this.fragOpcode = opcode;
        this.fragments = [payload];
      }
      if (fin) {
        const full = this.fragments.length === 1 ? this.fragments[0] : Buffer.concat(this.fragments);
        const isBinary = this.fragOpcode === 0x2;
        this.fragments = []; this.fragOpcode = null;
        this.onMessage(full, isBinary);
      }
    }
  }
}

// Wraps a raw socket into a connection with send/on APIs.
class Conn {
  constructor(socket, isServer) {
    this.socket = socket;
    this.isServer = isServer;
    this._handlers = { message: [], close: [], error: [] };
    this.readyState = 1; // OPEN
    this.OPEN = 1;
    this._closed = false;
    const parser = new Parser(
      (buf, bin) => this._emit('message', buf, bin),
      (opcode, buf) => {
        if (opcode === 0x9) { this._raw(encodeFrame(0xA, buf, !isServer)); } // ping -> pong
        else if (opcode === 0x8) { this.close(); } // close
        // pong (0xA) ignored
      }
    );
    socket.on('data', (d) => { try { parser.push(d); } catch (e) { this._emit('error', e); this.close(); } });
    socket.on('close', () => { this.readyState = 3; this._emit('close'); });
    socket.on('error', (e) => { this._emit('error', e); });
  }
  on(ev, fn) { if (this._handlers[ev]) this._handlers[ev].push(fn); return this; }
  _emit(ev, ...args) { (this._handlers[ev] || []).forEach((f) => { try { f(...args); } catch (_) {} }); }
  _raw(buf) { try { if (this.readyState === 1) this.socket.write(buf); } catch (_) {} }
  send(payload, binary) {
    if (typeof payload === 'string') payload = Buffer.from(payload);
    this._raw(encodeFrame(binary ? 0x2 : 0x1, payload, !this.isServer));
  }
  ping() { this._raw(encodeFrame(0x9, Buffer.alloc(0), !this.isServer)); }
  close() { if (this._closed) return; this._closed = true; try { this._raw(encodeFrame(0x8, Buffer.alloc(0), !this.isServer)); } catch (_) {} try { this.socket.end(); } catch (_) {} this.readyState = 3; }
}

// Attach a WS handler to an http.Server. onConnection(conn, req).
function attach(server, onConnection) {
  server.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'];
    if (!key) { socket.destroy(); return; }
    const headers = [
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      'Sec-WebSocket-Accept: ' + acceptKey(key),
      '\r\n',
    ].join('\r\n');
    socket.write(headers);
    socket.setNoDelay(true);
    const conn = new Conn(socket, true);
    onConnection(conn, req);
  });
}

// Minimal client for tests: connect(url) -> Promise<Conn>
function connect(url) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const key = crypto.randomBytes(16).toString('base64');
    const req = http.request({
      host: u.hostname, port: u.port || 80, path: u.pathname || '/', method: 'GET',
      headers: { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Key': key, 'Sec-WebSocket-Version': '13' },
    });
    req.on('upgrade', (res, socket) => { socket.setNoDelay(true); resolve(new Conn(socket, false)); });
    req.on('error', reject);
    req.end();
  });
}

module.exports = { attach, connect, encodeFrame, acceptKey };
