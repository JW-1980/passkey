// End-to-end with Firebase: a real Chromium with a virtual authenticator, the Firebase JS SDK
// against the Firebase Auth emulator, the PHP auth hub (examples/firebase-hub) and the Rust desktop
// sign-in (packages/firebase).
//
//   firebase emulators:start --only auth --project demo-passkey-test
//   FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099 node --test e2e/firebase.e2e.mjs
//
// Needs: php, the example bundle (npm run build:firebase-example in packages/js), Playwright with
// Chromium, and for the desktop test the Rust example (cargo build --features desktop --example
// desktop_sign_in in packages/firebase).
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { chromium } = createRequire(import.meta.url)('playwright');
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 8766;
const ORIGIN = `http://localhost:${PORT}`;
const EMULATOR = process.env.FIREBASE_AUTH_EMULATOR_HOST ?? '';
const PROJECT = process.env.FIREBASE_PROJECT_ID ?? 'demo-passkey-test';
const skip = EMULATOR === '' && 'set FIREBASE_AUTH_EMULATOR_HOST to a running Firebase Auth emulator';

let server;
let browser;
let workDir;

before(async () => {
  if (skip) return;
  workDir = mkdtempSync(join(tmpdir(), 'firebase-e2e-'));
  server = spawn('php', ['-S', `localhost:${PORT}`, join(root, 'examples/firebase-hub/public/index.php')], {
    env: { ...process.env, HUB_ORIGIN: ORIGIN, HUB_DB: join(workDir, 'hub.sqlite'), FIREBASE_PROJECT_ID: PROJECT },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  server.stderr.on('data', (chunk) => {
    if (process.env.E2E_SERVER_LOG) process.stderr.write(chunk);
  });
  for (let attempt = 0; ; attempt++) {
    try {
      if ((await fetch(`${ORIGIN}/`)).ok) break;
    } catch {
      // not up yet
    }
    assert.ok(attempt < 50, 'the PHP example server did not start');
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  browser = await chromium.launch();
});

after(async () => {
  await browser?.close();
  server?.kill();
  if (workDir) rmSync(workDir, { recursive: true, force: true });
});

async function visitor() {
  const context = await browser.newContext();
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  await page.goto(ORIGIN);
  await page.waitForFunction(() => document.getElementById('status').textContent !== 'Loading…');
  return { context, page, cdp, authenticatorId };
}

const status = (page) => page.textContent('#status');

async function waitForStatus(page, pattern) {
  await page.waitForFunction((source) => new RegExp(source).test(document.getElementById('status').textContent), pattern.source, { timeout: 15000 });
  return status(page);
}

async function signUp(page) {
  const email = `e2e-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`;
  await page.fill('#email', email);
  await page.fill('#password', 'a long password 123');
  await page.click('#sign-up');
  const text = await waitForStatus(page, /^Signed in as /);
  return { email, uid: /^Signed in as (\S+) /.exec(text)[1], text };
}

test('a Firebase user adds a passkey and signs in with it as the same Firebase user', { skip }, async () => {
  const { context, page, cdp, authenticatorId } = await visitor();
  const { uid, text } = await signUp(page);
  assert.match(text, / with password$/, 'the property session knows the method');

  await page.click('#add-passkey');
  await page.waitForSelector('#passkeys li');
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  assert.equal(credentials.length, 1);
  assert.equal(credentials[0].isResidentCredential, true);

  await page.click('#sign-out');
  await waitForStatus(page, /^Signed out$/);

  await page.click('#passkey-sign-in');
  const after = await waitForStatus(page, /^Signed in as /);
  assert.equal(after, `Signed in as ${uid} with passkey (multi-factor)`);
  await context.close();
});

test('the hub refuses to register a passkey without a Firebase ID token, or with a forged one', { skip }, async () => {
  const { context, page } = await visitor();
  const answers = await page.evaluate(async () => {
    const none = await fetch('/passkey/register/options', { method: 'POST' });
    const header = btoa(JSON.stringify({ alg: 'none' })).replace(/=+$/, '');
    const body = btoa(JSON.stringify({ sub: 'someone', aud: 'other' })).replace(/=+$/, '');
    const forged = await fetch('/passkey/register/options', { method: 'POST', headers: { Authorization: `Bearer ${header}.${body}.` } });
    return [none.status, forged.status, (await forged.json()).error.code];
  });
  assert.deepEqual(answers, [401, 401, 'unauthenticated']);
  await context.close();
});

test('the property backend refuses an ID token of another project', { skip }, async () => {
  const response = await fetch(`http://${EMULATOR}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake-api-key`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: `other-${Date.now()}@example.com`, password: 'a long password 123', returnSecureToken: true }),
  });
  const { idToken } = await response.json();
  const [, payload] = idToken.split('.');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
  claims.aud = 'demo-someone-else';
  claims.iss = 'https://securetoken.google.com/demo-someone-else';
  const forged = `${idToken.split('.')[0]}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.`;
  const session = await fetch(`${ORIGIN}/session`, { method: 'POST', headers: { Authorization: `Bearer ${forged}` } });
  assert.equal(session.status, 401);
});

const desktopBinary = join(root, 'packages/firebase/target/debug/examples/desktop_sign_in');

test('a desktop app signs in through the browser and holds a Firebase session for the same user', { skip: skip || (!existsSync(desktopBinary) && 'build the desktop example first') }, async () => {
  const { context, page } = await visitor();
  const { uid } = await signUp(page);

  const app = spawn(desktopBinary, [`${ORIGIN}/passkey`, `${ORIGIN}/desktop`, PROJECT, EMULATOR], { stdio: ['ignore', 'pipe', 'inherit'] });
  const lines = createInterface({ input: app.stdout });
  const next = () => new Promise((resolve) => lines.once('line', resolve));
  const open = await next();
  assert.match(open, /^OPEN http:\/\/localhost:8766\/desktop\?challenge=/);

  await page.goto(open.slice(5));
  await page.waitForSelector('#desktop:not([hidden])');
  const result = next();
  await page.click('#approve');
  assert.equal(await result, `SESSION ${uid} password`);
  await context.close();
});
