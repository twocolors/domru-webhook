'use strict';

const dgram = require('dgram');
const crypto = require('crypto');
const os = require('os');
const { request } = require('undici');
const pkg = require('./package.json');

const DOMRU_URL = process.env.DOMRU_URL;
const WEBHOOK_URL = process.env.WEBHOOK_URL;
const SIP_DEBUG = process.env.SIP_DEBUG || false;

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

const SIP_PORT = 5060;
const LOCAL_PORT = process.env.LOCAL_PORT || 5060;

let SIP_SERVER = '';
let USER = '';
let PASS = '';

let PUBLIC_IP = '';
let LOCAL_IP = '';
let UUID = '';

let callId = crypto.randomUUID();
let cseq = 1;
let expires = 120;

let registerStep = 1;
let registerTimer = null;
let optionsTimer = null;

const socket = dgram.createSocket('udp4');

const md5 = (s) => crypto.createHash('md5').update(s).digest('hex');
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function getHeader(msg, longName, shortName) {
  return (
    msg.match(new RegExp(`^${longName}:.*$`, 'mi'))?.[0] ||
    (shortName ? msg.match(new RegExp(`^${shortName}:.*$`, 'mi'))?.[0] : null)
  );
}

async function getPublicIP() {
  const { statusCode, body } = await request(
    'https://api.ipify.org?format=text',
    {
      headers: { 'user-agent': USER_AGENT },
    }
  );

  if (statusCode !== 200 && statusCode !== 201) {
    console.error(`PUBLIC_IP error ${statusCode}`);
    process.exit(1);
  }

  return (await body.text()).trim();
}

function getLocalIP() {
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

  console.error(`LOCAL_IP error`);
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

async function fetchSipCredentials() {
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
    console.error(`SIP Credentials not received or incomplete from ${DOMRU_URL}`);
    process.exit(1);
  }

  USER = data.login;
  PASS = data.password;
  SIP_SERVER = data.realm;

  console.log('SIP Credentials:');
  console.log('  realm    =', SIP_SERVER);
  console.log('  login    =', USER);
  console.log('  password =', PASS);
  console.log('\n');

  return data;
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
  const branch = 'z9hG4bK' + crypto.randomBytes(6).toString('hex');
  const tag = crypto.randomBytes(4).toString('hex');

  let msg = `REGISTER sip:${SIP_SERVER} SIP/2.0
Via: SIP/2.0/UDP ${LOCAL_IP}:${LOCAL_PORT};branch=${branch}
Max-Forwards: 70
From: <sip:${USER}@${SIP_SERVER}>;tag=${tag}
To: <sip:${USER}@${SIP_SERVER}>
Call-ID: ${callId}
CSeq: ${cseq} REGISTER
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE
Contact: <sip:${USER}@${LOCAL_IP}:${LOCAL_PORT}>;expires=${cseq === 1 ? 0 : expires}
Expires: ${cseq === 1 ? 0 : expires}
X-Domru-Issues: ${ISSUES}
User-Agent: ${USER_AGENT}`;

  if (auth) msg += `\nAuthorization: ${auth}`;
  msg += `\nContent-Length: 0\n\n`;
  return msg;
}

function buildOptions() {
  const branch = 'z9hG4bK' + crypto.randomBytes(6).toString('hex');
  const tag = crypto.randomBytes(4).toString('hex');

  return `OPTIONS sip:${SIP_SERVER} SIP/2.0
Via: SIP/2.0/UDP ${LOCAL_IP}:${LOCAL_PORT};branch=${branch}
Max-Forwards: 70
From: <sip:${USER}@${SIP_SERVER}>;tag=${tag}
To: <sip:${USER}@${SIP_SERVER}>
Call-ID: ${crypto.randomUUID()}
CSeq: 1 OPTIONS
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE
Contact: <sip:${USER}@${LOCAL_IP}:${LOCAL_PORT}>
X-Domru-Issues: ${ISSUES}
User-Agent: ${USER_AGENT}
Content-Length: 0`;
}

function buildAuth(realm, nonce) {
  const ha1 = md5(`${USER}:${realm}:${PASS}`);
  const ha2 = md5(`REGISTER:sip:${SIP_SERVER}`);
  const response = md5(`${ha1}:${nonce}:${ha2}`);

  return `Digest username="${USER}", realm="${realm}", nonce="${nonce}", uri="sip:${SIP_SERVER}", response="${response}"`;
}

function send(msg) {
  if (SIP_DEBUG) console.log('>>> SIP >>>\n' + msg);
  socket.send(msg, SIP_PORT, SIP_SERVER);
}

function sendRegister(auth) {
  send(buildRegister(auth));
}

function sendOptions() {
  send(buildOptions());
}

function scheduleReRegister() {
  clearTimeout(registerTimer);
  registerTimer = setTimeout(
    () => {
      cseq++;
      sendRegister();
    },
    Math.max((expires - 5) * 1000, 1000)
  );
}

function startOptionsKeepalive() {
  clearInterval(optionsTimer);
  optionsTimer = setInterval(sendOptions, 30000);
}

async function handle403() {
  console.log(
    '!!! Forbidden -> re-fetch SIP credentials (sleep 60 sec)\n\n'
  );

  clearTimeout(registerTimer);
  clearInterval(optionsTimer);

  callId = crypto.randomUUID();
  registerStep = 1;
  cseq = 1;

  await sleep(60 * 1000);
  await fetchSipCredentials();

  sendRegister();
}

async function handle401(msg) {
  const realm = msg.match(/realm="([^"]+)"/i)?.[1];
  const nonce = msg.match(/nonce="([^"]+)"/i)?.[1];
  if (!realm || !nonce) return;

  if (registerStep === 2) {
    await handle403(msg);
    return;
  }

  registerStep = 2;
  cseq++;

  sendRegister(buildAuth(realm, nonce));
}

function handleInvite(msg, rinfo) {
  const via = getHeader(msg, 'Via', 'v');
  const from = getHeader(msg, 'From', 'f');
  const to = getHeader(msg, 'To', 't');
  const callId = getHeader(msg, 'Call-ID', 'i');
  const cseq = getHeader(msg, 'CSeq');

  sendWebhook({
    type: 'INVITE',
    from,
    to,
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
${to};tag=${crypto.randomBytes(4).toString('hex')}
${callId}
${cseq}
Content-Length: 0

`;

  if (SIP_DEBUG) console.log('>>> SIP >>>\n' + trying);
  socket.send(trying, rinfo.port, rinfo.address);

  setTimeout(() => {
    if (SIP_DEBUG) console.log('>>> SIP >>>\n' + busy);
    socket.send(busy, rinfo.port, rinfo.address);
  }, 250);
}

function handleOptions(msg, rinfo) {
  const via = getHeader(msg, 'Via', 'v');
  const from = getHeader(msg, 'From', 'f');
  const to = getHeader(msg, 'To', 't');
  const callId = getHeader(msg, 'Call-ID', 'i');
  const cseq = getHeader(msg, 'CSeq');

  if (!via || !from || !to || !callId || !cseq) {
    console.error('Malformed OPTIONS, skip');
    return;
  }

  const ok = `SIP/2.0 200 OK
${via}
${from}
${to};tag=${crypto.randomBytes(4).toString('hex')}
${callId}
${cseq}
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE
X-Domru-Issues: ${ISSUES}
User-Agent: ${USER_AGENT}
Content-Length: 0

`;

  if (SIP_DEBUG) console.log('>>> SIP >>>\n' + ok);
  socket.send(ok, rinfo.port, rinfo.address);
}

function handleNotify(msg, rinfo) {
  const via = getHeader(msg, 'Via', 'v');
  const from = getHeader(msg, 'From', 'f');
  const to = getHeader(msg, 'To', 't');
  const callId = getHeader(msg, 'Call-ID', 'i');
  const cseq = getHeader(msg, 'CSeq');

  if (!via || !from || !to || !callId || !cseq) {
    console.error('Malformed NOTIFY, skip');
    return;
  }

  const not = `SIP/2.0 405 Method Not Allowed
${via}
${from}
${to};tag=${crypto.randomBytes(4).toString('hex')}
${callId}
${cseq}
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE
User-Agent: ${USER_AGENT}
Content-Length: 0

`;

  if (SIP_DEBUG) console.log('>>> SIP >>>\n' + not);
  socket.send(not, rinfo.port, rinfo.address);
}

socket.on('message', async (buf, rinfo) => {
  const msg = buf.toString();
  if (SIP_DEBUG) console.log('<<< SIP <<<\n' + msg);

  if (msg.startsWith('SIP/2.0 401')) await handle401(msg);
  else if (msg.startsWith('SIP/2.0 403')) await handle403();
  else if (msg.startsWith('SIP/2.0 200') && msg.includes('REGISTER')) {
    const exp = msg.match(/Expires:\s*(\d+)/i);
    if (exp) expires = parseInt(exp[1], 10);
    if (cseq === 1) {
      setTimeout(() => sendRegister(), 250);
    } else {
      registerStep = 1;
      scheduleReRegister();
      // startOptionsKeepalive();
    }
  } else if (msg.startsWith('INVITE')) handleInvite(msg, rinfo);
  else if (msg.startsWith('OPTIONS')) handleOptions(msg, rinfo);
  else if (msg.startsWith('NOTIFY')) handleNotify(msg, rinfo);
});

async function init() {
  // PUBLIC_IP = await getPublicIP();
  LOCAL_IP = getLocalIP();
  UUID = getUUID(LOCAL_IP);

  // console.log('Public IP:', PUBLIC_IP);
  console.log('LOCAL IP:  ', LOCAL_IP);
  console.log('LOCAL PORT:', LOCAL_PORT);
  console.log('UUID:      ', UUID);

  await fetchSipCredentials();

  sendRegister();
}

socket.bind(LOCAL_PORT, init);
