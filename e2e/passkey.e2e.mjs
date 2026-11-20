// End-to-end: a real Chromium with a virtual authenticator, the browser client of packages/js, the
// PHP server of packages/php (through the plain-PHP example) and the desktop handoff of
// packages/desktop.
//
//   node --test e2e/passkey.e2e.mjs
//
// Needs: php, a built example bundle (npm run build:example in packages/js), Playwright with
// Chromium, and for the handoff test a built example binary (cargo build --example handoff).
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const { chromium } = createRequire(import.meta.url)('playwright');
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 8765;
const ORIGIN = `http://localhost:${PORT}`;

let server;
let browser;
let workDir;

before(async () => {
  workDir = mkdtempSync(join(tmpdir(), 'passkey-e2e-'));
  server = spawn('php', ['-S', `localhost:${PORT}`, join(root, 'examples/plain-php/public/index.php')], {
    env: { ...process.env, PASSKEY_EXAMPLE_ORIGIN: ORIGIN, PASSKEY_EXAMPLE_DB: join(workDir, 'example.sqlite') },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  server.stderr.on('data', (chunk) => {
    if (process.env.E2E_SERVER_LOG) process.stderr.write(chunk);
  });
  for (let attempt = 0; ; attempt++) {
    try {
      const response = await fetch(`${ORIGIN}/api/me`);
      if (response.ok) break;
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

/** A fresh browser profile with its own virtual platform authenticator. */
async function visitor({ userVerified = true } = {}) {
  const context = await browser.newContext();
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: userVerified,
      automaticPresenceSimulation: true,
    },
  });
  await page.goto(ORIGIN);
  return { context, page, cdp, authenticatorId };
}

async function createAccount(page, name) {
  await page.fill('#demo-name', name);
  await page.click('#demo button');
  await page.waitForSelector('#member:not([hidden])');
}

async function addPasskey(page) {
  await page.click('#add');
  await page.waitForFunction(() => document.getElementById('status').textContent !== '');
  return page.textContent('#status');
}

test('an account adds a passkey in the browser and signs in with it', async () => {
  const { context, page, cdp, authenticatorId } = await visitor();
  await createAccount(page, 'Ada');

  assert.equal(await addPasskey(page), 'Passkey added.');
  await page.waitForSelector('#list li');
  assert.equal(await page.locator('#list li').count(), 1);
  assert.match(await page.textContent('#list li'), /never used/);
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  assert.equal(credentials.length, 1);
  assert.equal(credentials[0].isResidentCredential, true, 'the passkey must be discoverable');
  assert.equal(credentials[0].rpId, 'localhost');

  await page.click('#sign-out');
  await page.waitForSelector('#guest:not([hidden])');

  await page.click('#sign-in');
  await page.waitForSelector('#member:not([hidden])');
  assert.equal(await page.textContent('#who'), 'Ada');
  assert.equal(await page.textContent('#status'), 'Signed in.');
  await page.waitForSelector('#list li');
  assert.match(await page.textContent('#list li'), /last used 20\d\d-/);
  await context.close();
});

test('the same authenticator cannot hold a second passkey for the account', async () => {
  const { context, page } = await visitor();
  await createAccount(page, 'Grace');
  assert.equal(await addPasskey(page), 'Passkey added.');

  assert.equal(await addPasskey(page), 'This device already has a passkey for this account.');
  const stored = await page.evaluate(() => fetch('/passkey/passkeys').then((r) => r.json()));
  assert.equal(stored.passkeys.length, 1);
  await context.close();
});

test('a sign-in without user verification is refused by the server', async () => {
  const { context, page, cdp, authenticatorId } = await visitor();
  await createAccount(page, 'Linus');
  assert.equal(await addPasskey(page), 'Passkey added.');
  await page.click('#sign-out');
  await page.waitForSelector('#guest:not([hidden])');

  await cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: false });
  await page.click('#sign-in');
  await page.waitForFunction(() => document.getElementById('status').textContent !== '');

  assert.notEqual(await page.textContent('#status'), 'Signed in.');
  assert.equal(await page.isHidden('#member'), true);
  const me = await page.evaluate(() => fetch('/api/me').then((r) => r.json()));
  assert.equal(me.account, null);
  await context.close();
});

test('a visitor without a passkey for this site is not signed in', async () => {
  const { context, page } = await visitor();
  await page.click('#sign-in');
  await page.waitForFunction(() => document.getElementById('status').textContent !== '');

  assert.equal(await page.isHidden('#member'), true);
  await context.close();
});

test('a removed passkey no longer signs in', async () => {
  const { context, page } = await visitor();
  await createAccount(page, 'Margaret');
  assert.equal(await addPasskey(page), 'Passkey added.');
  await page.waitForSelector('#list li button');
  await page.click('#list li button');
  await page.waitForFunction(() => document.querySelectorAll('#list li').length === 0);
  await page.click('#sign-out');
  await page.waitForSelector('#guest:not([hidden])');

  await page.click('#sign-in');
  await page.waitForFunction(() => document.getElementById('status').textContent !== '');
  assert.equal(await page.textContent('#status'), 'This passkey is not valid.');
  assert.equal(await page.isHidden('#member'), true);
  await context.close();
});

test('state-changing requests without the CSRF token are refused', async () => {
  const { context, page } = await visitor();
  const status = await page.evaluate(() => fetch('/passkey/login/options', { method: 'POST' }).then((r) => r.status));
  assert.equal(status, 419);
  await context.close();
});

const handoffBinary = join(root, 'packages/desktop/target/debug/examples/handoff');

/** Starts the desktop side (the Rust crate) and resolves with its lines of output. */
function desktopApp() {
  const child = spawn(handoffBinary, [`${ORIGIN}/desktop-sign-in`], { stdio: ['ignore', 'pipe', 'inherit'] });
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  const next = async () => (await lines.next()).value;
  return { child, next };
}

test('a desktop app signs in through the browser with the passkey', { skip: !existsSync(handoffBinary) && 'build the desktop example first' }, async () => {
  const { context, page } = await visitor();
  await createAccount(page, 'Katherine');
  assert.equal(await addPasskey(page), 'Passkey added.');
  await page.click('#sign-out');
  await page.waitForSelector('#guest:not([hidden])');

  const desktop = desktopApp();
  const open = await desktop.next();
  assert.match(open, /^OPEN http:\/\/localhost:8765\/desktop-sign-in\?challenge=[\w-]{43}&port=\d+&state=[\w-]{43}$/);

  // The "system browser": sign in with the passkey on the real origin, then approve.
  await page.goto(open.slice('OPEN '.length));
  await page.click('#sign-in');
  await page.waitForSelector('#handoff:not([hidden])');
  assert.equal(await page.textContent('#handoff-who'), 'Katherine');
  await page.click('#approve');
  await page.waitForURL(/^http:\/\/127\.0\.0\.1:\d+\/callback\?code=/);
  assert.match(await page.textContent('body'), /Signed in\. You can close this tab/);

  const grantLine = await desktop.next();
  assert.match(grantLine, /^GRANT /);
  const grant = JSON.parse(grantLine.slice('GRANT '.length));

  // The desktop app redeems the code with its verifier, without any cookie.
  const exchange = (body) =>
    fetch(`${ORIGIN}/passkey/handoff/exchange`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const first = await exchange(grant);
  assert.equal(first.status, 200);
  assert.equal((await first.json()).name, 'Katherine');
  assert.equal((await exchange(grant)).status, 400, 'a code redeems only once');
  await context.close();
});

test('a code intercepted from the callback is worthless without the verifier', { skip: !existsSync(handoffBinary) && 'build the desktop example first' }, async () => {
  const { context, page } = await visitor();
  await createAccount(page, 'Dorothy');

  const desktop = desktopApp();
  const open = (await desktop.next()).slice('OPEN '.length);
  await page.goto(open);
  await page.waitForSelector('#handoff:not([hidden])');
  await page.click('#approve');
  await page.waitForURL(/^http:\/\/127\.0\.0\.1:\d+\/callback\?code=/);
  const code = new URL(page.url()).searchParams.get('code');
  await desktop.next();

  const response = await fetch(`${ORIGIN}/passkey/handoff/exchange`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, code_verifier: 'A'.repeat(43) }),
  });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, 'invalid_handoff');
  await context.close();
});

test('declining in the browser tells the desktop app', { skip: !existsSync(handoffBinary) && 'build the desktop example first' }, async () => {
  const { context, page } = await visitor();
  await createAccount(page, 'Joan');

  const desktop = desktopApp();
  await page.goto((await desktop.next()).slice('OPEN '.length));
  await page.waitForSelector('#handoff:not([hidden])');
  await page.click('#deny');
  await page.waitForURL(/^http:\/\/127\.0\.0\.1:\d+\/callback\?error=denied/);

  assert.equal(await desktop.next(), 'ERROR the sign-in was declined in the browser');
  await context.close();
});
