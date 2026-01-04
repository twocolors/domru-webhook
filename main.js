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

function info(message) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] [info] ${message}`);
}

function error(message) {
  const ts = new Date().toISOString();
  console.error(`[${ts}] [error] ${message}`);
}

function debug(message) {
  if (DEBUG) {
    const ts = new Date().toISOString();
    console.log(`${ts}\n${message}`);
  }
}

if (!DOMRU_URL) {
  error(`ENV DOMRU_URL is not set`);
  process.exit(1);
}

if (!WEBHOOK_URL) {
  error(`ENV WEBHOOK_URL is not set`);
  process.exit(1);
}

const USER_AGENT = `${pkg.name}/${pkg.version}`;
const ISSUES = pkg.bugs.url;

let REALM = '';
let USER = '';
let PASS = '';

let SIPDEVICES = null;
let IP = process.env.IP || null;
let UUID = null;

let callId = null;
let cseq = null;
let expires = null;
let registerTimer = null;
let authFailure = null;
let lastNonce = null;

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
  expires = 60;

  clearTimeout(registerTimer);

  registerTimer = null;
  authFailure = 0;
  lastNonce = null;
};

async function handleAuthFailure(reason = 'auth') {
  error(`Auth failure (${reason}) -> re-fetch credentials`);

  await sleep(30 * 1000);
  await fetchCredentials();

  unRegister();
  sendRegister();
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

  error(`IP get error`);
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

async function fetchSipdevices() {
  try {
    const isSipDevices = /\/sipdevices\/?$/.test(DOMRU_URL);
    if (isSipDevices) {
      SIPDEVICES = DOMRU_URL;
      return;
    }

    const res = await fetch(DOMRU_URL, {
      headers: {
        'user-agent': USER_AGENT,
      },
      redirect: 'follow',
    });

    if (res.status !== 200 && res.status !== 201) {
      error(`${DOMRU_URL} error ${res.status} in fetchSipdevices`);
      process.exit(1);
    }

    const text = await res.text();

    if (!text) {
      error(`Sipdevices not received (${DOMRU_URL})`);
      process.exit(1);
    }

    const videosnapshots = text.match(
      /<img[^>]+src=["']([^"']+videosnapshots)["']/i
    );

    if (!videosnapshots) {
      error(`Videosnapshots not received (${DOMRU_URL})`);
      process.exit(1);
    }

    SIPDEVICES = videosnapshots[1].replace(/\/videosnapshots$/, '/sipdevices');

    if (!SIPDEVICES) {
      error(`Sipdevices not received (${DOMRU_URL})`);
      process.exit(1);
    }
  } catch (e) {
    error(`Sipdevices error: ${e.message}`);
    process.exit(1);
  }
}

async function fetchCredentials() {
  try {
    const { statusCode, body } = await request(SIPDEVICES, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'user-agent': USER_AGENT,
      },
      body: JSON.stringify({ installationId: UUID }),
    });

    if (statusCode !== 200 && statusCode !== 201) {
      error(`${SIPDEVICES} error ${statusCode} in fetchCredentials`);
      process.exit(1);
    }

    const json = await body.json();
    const data = json?.data;

    if (!data || !data.login || !data.password || !data.realm) {
      error(`Credentials not received (${SIPDEVICES})`);
      process.exit(1);
    }

    USER = data.login;
    PASS = data.password;
    REALM = data.realm;

    console.log(`
Credentials:
REALM:\t${REALM}
USER:\t${USER}
PASS:\t${PASS}
`);
  } catch (e) {
    error(`Credentials error: ${e.message}`);
    process.exit(1);
  }
}

function sendWebhook(payload) {
  info(`Send Webhook to ${WEBHOOK_URL}`);

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
    error(`Webhook error: ${e.message}`);
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
Allow-Events: message-summary
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
  debug(`>>> SIP >>>\n${msg}`);
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
    (expires - 5) * 1000
  );
}

async function handle403() {
  await handleAuthFailure('403 forbidden');
}

async function handle401(msg) {
  const realm = msg.match(/realm="([^"]+)"/i)?.[1];
  const nonce = msg.match(/nonce="([^"]+)"/i)?.[1];
  if (!realm || !nonce) return;

  if (lastNonce === nonce) {
    authFailure++;
  } else {
    authFailure = 1;
    lastNonce = nonce;
  }

  if (authFailure >= 2) {
    await handleAuthFailure('invalid credentials');
    return;
  }

  cseq++;
  sendRegister(buildAuth(realm, nonce));
}

function handleInvite(msg, rinfo) {
  const { via, from, to, callId, cseq } = headers(msg);
  const toTag = tag();

  sendWebhook({
    event: 'Ringing',
  });

  const trying = `SIP/2.0 100 Trying
${via}
${from}
${to};tag=${toTag}
${callId}
${cseq}
Content-Length: 0

`;

  const ringing = `SIP/2.0 180 Ringing
${via}
${from}
${to};tag=${toTag}
${callId}
${cseq}
Content-Length: 0

`;

  const busy = `SIP/2.0 486 Busy Here
${via}
${from}
${to};tag=${toTag}
${callId}
${cseq}
Content-Length: 0

`;

  setTimeout(() => {
    debug(`>>> SIP >>>\n${trying}`);
    socket.send(trying, rinfo.port, rinfo.address);
  }, 25);

  setTimeout(() => {
    debug(`>>> SIP >>>\n${ringing}`);
    socket.send(ringing, rinfo.port, rinfo.address);
  }, 150);

  setTimeout(() => {
    debug(`>>> SIP >>>\n${busy}`);
    socket.send(busy, rinfo.port, rinfo.address);
  }, 25000);
}

function handleOptions(msg, rinfo) {
  const { via, from, to, callId, cseq } = headers(msg);

  if (!via || !from || !to || !callId || !cseq) {
    error(`Malformed OPTIONS, skip`);
    return;
  }

  const ok = `SIP/2.0 200 OK
${via}
${from}
${to};tag=${tag()}
${callId}
${cseq}
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, NOTIFY
X-Domru-Issues: ${ISSUES}
User-Agent: ${USER_AGENT}
Content-Length: 0

`;

  debug(`>>> SIP >>>\n${ok}`);
  socket.send(ok, rinfo.port, rinfo.address);
}

function handleNotify(msg, rinfo) {
  const { via, from, to, callId, cseq } = headers(msg);

  if (!via || !from || !to || !callId || !cseq) {
    error(`Malformed NOTIFY, skip`);
    return;
  }

  const ok = `SIP/2.0 200 OK
${via}
${from}
${to};tag=${tag()}
${callId}
${cseq}
User-Agent: ${USER_AGENT}
Content-Length: 0

`;

  debug(`>>> SIP >>>\n${ok}`);
  socket.send(ok, rinfo.port, rinfo.address);
}

socket.on('message', async (buf, rinfo) => {
  const msg = buf.toString();
  debug(`<<< SIP <<<\n${msg}`);

  if (msg.startsWith('SIP/2.0 401')) await handle401(msg);
  else if (msg.startsWith('SIP/2.0 403')) await handle403();
  else if (msg.startsWith('SIP/2.0 200') && msg.includes('REGISTER')) {
    authFailure = 0;
    lastNonce = null;

    const exp = msg.match(/Expires:\s*(\d+)/i);
    if (exp && exp[1] && exp[1] > 0) expires = parseInt(exp[1], 10);

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
  await fetchSipdevices();

  if (!IP) IP = getIp();
  UUID = getUUID(IP);

  console.log(`DOMRU:\t${SIPDEVICES}
DEBUG:\t${DEBUG}
IP:\t${IP}
PORT:\t${PORT}
UUID:\t${UUID}`);

  await fetchCredentials();

  unRegister();
  sendRegister();
}

socket.bind(PORT, init);
