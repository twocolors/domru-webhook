'use strict';

const dgram = require('dgram');
const crypto = require('crypto');
const os = require('os');
const { request } = require('undici');
const pkg = require('./package.json');

const DOMRU_URL = process.env.DOMRU_URL;
const WEBHOOK_URL = process.env.WEBHOOK_URL;
const DEBUG = process.env.DEBUG && process.env.DEBUG == 'true' ? true : false;
const PORT = process.env.PORT || 5060;

if (!DOMRU_URL) {
  console.error('ENV DOMRU_URL is not set');
  process.exit(1);
}

if (!WEBHOOK_URL) {
  console.error('ENV WEBHOOK_URL is not set');
  process.exit(1);
}

const USER_AGENT = `${pkg.name}/${pkg.version}`;
const ISSUES = pkg.bugs.url;

let REALM = '';
let USER = '';
let PASS = '';

let IP = process.env.IP || null;
let UUID = null;

let callId = null;
let cseq = null;
let expires = null;
let registerTimer = null;

const socket = dgram.createSocket('udp4');

const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const tag = () => crypto.randomBytes(4).toString('hex');
const header = (m, l, s) =>
  m.match(new RegExp(`^(${l}|${s}):.*$`, 'mi'))?.[0] || null;
const headers = (m) => {
  const via = header(m, 'Via', 'v');
  const from = header(m, 'From', 'f');
  const to = header(m, 'To', 't');
  const callId = header(m, 'Call-ID', 'i');
  const cseq = header(m, 'CSeq');

  return { via, from, to, callId, cseq };
};
const unRegister = () => {
  callId = crypto.randomUUID();
  cseq = 1;
  expires = 120;

  clearTimeout(registerTimer);
};

function debug(m) {
  if (DEBUG) console.log(m);
}

function getIp() {
  const interfaces = os.networkInterfaces();
  for (const devName in interfaces) {
    const iface = interfaces[devName];

    for (let i = 0; i < iface.length; i++) {
      const alias = iface[i];
      if (
        alias.family === 'IPv4' &&
        alias.address !== '127.0.0.1' &&
        !alias.internal
      ) {
        return alias.address;
      }
    }
  }

  console.error(`IP error`);
  process.exit(1);
}

function getUUID(ip) {
  const h = crypto.createHash('sha256').update(ip).digest('hex');
  return [
    h.slice(0, 8),
    h.slice(8, 12),
    '4' + h.slice(13, 16),
    ((parseInt(h[16], 16) & 0x3) | 0x8).toString(16) + h.slice(17, 20),
    h.slice(20, 32),
  ].join('-');
}

async function fetchCredentials() {
  try {
    const { statusCode, body } = await request(DOMRU_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'user-agent': USER_AGENT,
      },
      body: JSON.stringify({ installationId: UUID }),
    });

    if (statusCode !== 200 && statusCode !== 201) {
      console.error(`${DOMRU_URL} error ${statusCode}`);
      process.exit(1);
    }

    const json = await body.json();
    const data = json?.data;

    if (!data || !data.login || !data.password || !data.realm) {
      console.error(`Credentials not received (${DOMRU_URL})`);
      process.exit(1);
    }

    USER = data.login;
    PASS = data.password;
    REALM = data.realm;

    console.log('Credentials:');
    console.log('  realm    =', REALM);
    console.log('  login    =', USER);
    console.log('  password =', PASS);
    console.log('\n');
  } catch (e) {
    console.log('!!! Credentials error:', e.message);
    process.exit(1);
  }
}

function sendWebhook(payload) {
  console.log(`!!! Send Webhook to ${WEBHOOK_URL}\n\n`);

  try {
    request(WEBHOOK_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'user-agent': USER_AGENT,
      },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    console.log('!!! Webhook error:', e.message);
  }
}

function buildRegister(auth) {
  let msg = `REGISTER sip:${REALM} SIP/2.0
Via: SIP/2.0/UDP ${IP}:${PORT};branch=z9hG4bK${tag()};rport
Max-Forwards: 70
From: <sip:${USER}@${REALM}>;tag=${tag()}
To: <sip:${USER}@${REALM}>
Call-ID: ${callId}
CSeq: ${cseq} REGISTER
Contact: <sip:${USER}@${IP}:${PORT};ob>;reg-id=42;expires=${cseq === 1 ? 0 : expires}
Supported: outbound
Expires: ${cseq === 1 ? 0 : expires}
X-Domru-Issues: ${ISSUES}
User-Agent: ${USER_AGENT}`;

  if (auth) msg += `\nAuthorization: ${auth}`;
  msg += `\nContent-Length: 0\n\n`;
  return msg;
}

function buildAuth(realm, nonce) {
  const ha1 = md5(`${USER}:${realm}:${PASS}`);
  const ha2 = md5(`REGISTER:sip:${REALM}`);
  const response = md5(`${ha1}:${nonce}:${ha2}`);

  return `Digest username="${USER}", realm="${realm}", nonce="${nonce}", uri="sip:${REALM}", response="${response}"`;
}

function send(msg) {
  debug('>>> SIP >>>\n' + msg);
  socket.send(msg, 5060, REALM);
}

function sendRegister(auth) {
  send(buildRegister(auth));
}

function scheduleRegister() {
  clearTimeout(registerTimer);

  registerTimer = setTimeout(
    () => {
      cseq++;
      sendRegister();
    },
    Math.max((expires - 5) * 1000, 1000)
  );
}

async function handle403() {
  console.log('!!! Forbidden -> re-fetch credentials (sleep 60 sec)\n\n');

  await sleep(60 * 1000);

  await fetchCredentials();

  unRegister();
  sendRegister();
}

async function handle401(msg) {
  const realm = msg.match(/realm="([^"]+)"/i)?.[1];
  const nonce = msg.match(/nonce="([^"]+)"/i)?.[1];
  if (!realm || !nonce) return;

  if (registerTimer) {
    await handle403(msg);
    return;
  }

  cseq++;

  sendRegister(buildAuth(realm, nonce));
}

function handleInvite(msg, rinfo) {
  const { via, from, to, callId, cseq } = headers(msg);

  sendWebhook({
    event: 'Ringing',
  });

  const trying = `SIP/2.0 100 Trying
${via}
${from}
${to}
${callId}
${cseq}
Content-Length: 0

`;

  const busy = `SIP/2.0 486 Busy Here
${via}
${from}
${to};tag=${tag()}
${callId}
${cseq}
Content-Length: 0

`;

  setTimeout(() => {
    debug('>>> SIP >>>\n' + trying);
    socket.send(trying, rinfo.port, rinfo.address);
  }, 25);

  setTimeout(() => {
    debug('>>> SIP >>>\n' + busy);
    socket.send(busy, rinfo.port, rinfo.address);
  }, 175);
}

function handleOptions(msg, rinfo) {
  const { via, from, to, callId, cseq } = headers(msg);

  if (!via || !from || !to || !callId || !cseq) {
    console.error('Malformed OPTIONS, skip');
    return;
  }

  const ok = `SIP/2.0 200 OK
${via}
${from}
${to};tag=${tag()}
${callId}
${cseq}
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE
X-Domru-Issues: ${ISSUES}
User-Agent: ${USER_AGENT}
Content-Length: 0

`;

  debug('>>> SIP >>>\n' + ok);
  socket.send(ok, rinfo.port, rinfo.address);
}

function handleNotify(msg, rinfo) {
  const { via, from, to, callId, cseq } = headers(msg);

  if (!via || !from || !to || !callId || !cseq) {
    console.error('Malformed NOTIFY, skip');
    return;
  }

  const not = `SIP/2.0 405 Method Not Allowed
${via}
${from}
${to};tag=${tag()}
${callId}
${cseq}
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE
User-Agent: ${USER_AGENT}
Content-Length: 0

`;

  debug('>>> SIP >>>\n' + not);
  socket.send(not, rinfo.port, rinfo.address);
}

socket.on('message', async (buf, rinfo) => {
  const msg = buf.toString();
  debug('<<< SIP <<<\n' + msg);

  if (msg.startsWith('SIP/2.0 401')) await handle401(msg);
  else if (msg.startsWith('SIP/2.0 403')) await handle403();
  else if (msg.startsWith('SIP/2.0 200') && msg.includes('REGISTER')) {
    const exp = msg.match(/Expires:\s*(\d+)/i);
    if (exp) expires = parseInt(exp[1], 10);
    if (cseq === 1) {
      setTimeout(() => sendRegister(), 250);
    } else {
      scheduleRegister();
    }
  } else if (msg.startsWith('INVITE')) handleInvite(msg, rinfo);
  else if (msg.startsWith('OPTIONS')) handleOptions(msg, rinfo);
  else if (msg.startsWith('NOTIFY')) handleNotify(msg, rinfo);
});

async function init() {
  if (!IP) IP = getIp();
  UUID = getUUID(IP);

  console.log('DEBUG: ', DEBUG);
  console.log('IP:    ', IP);
  console.log('PORT:  ', PORT);
  console.log('UUID:  ', UUID);

  await fetchCredentials();

  unRegister();
  sendRegister();
}

socket.bind(PORT, init);
