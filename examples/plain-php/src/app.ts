import { createPasskeyClient, isPasskeyError } from '../../../packages/js/src/index.js';
import { browserAuthenticator } from '../../../packages/js/src/browser.js';
import { handoffDeniedUrl, readHandoffRequest } from '../../../packages/js/src/handoff.js';

const csrf = document.querySelector<HTMLMetaElement>('meta[name="csrf-token"]')?.content ?? '';
const headers = (): Record<string, string> => ({ 'X-CSRF-Token': csrf });
const client = createPasskeyClient({ baseUrl: '/passkey', authenticator: browserAuthenticator(), headers });

const $ = <T extends HTMLElement = HTMLElement>(id: string): T => document.getElementById(id) as T;
const status = (text: string): void => {
  $('status').textContent = text;
};

async function api(method: string, path: string, body?: unknown): Promise<{ account?: { id: string; name: string } | null }> {
  const response = await fetch(path, {
    method,
    headers: { ...headers(), 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return response.json();
}

function explain(error: unknown): string {
  if (!isPasskeyError(error)) {
    return 'Something went wrong.';
  }
  switch (error.code) {
    case 'cancelled':
      return 'The passkey prompt was closed.';
    case 'unsupported':
      return 'This browser does not support passkeys.';
    case 'already_registered':
      return 'This device already has a passkey for this account.';
    default:
      return error.message;
  }
}

async function render(): Promise<void> {
  const { account } = await api('GET', '/api/me');
  const handoff = location.pathname === '/desktop-sign-in' ? readHandoffRequest(location.href) : null;

  $('guest').hidden = account != null;
  $('member').hidden = account == null || handoff !== null;
  $('handoff').hidden = account == null || handoff === null;
  if (location.pathname === '/desktop-sign-in' && handoff === null) {
    status('This desktop sign-in link is not valid. Start again from the app.');
  }
  if (account == null) {
    return;
  }
  $('who').textContent = account.name;
  $('handoff-who').textContent = account.name;

  const list = $('list');
  list.replaceChildren();
  for (const passkey of await client.list()) {
    const item = document.createElement('li');
    item.textContent = `${passkey.name} — ${passkey.lastUsedAt === null ? 'never used' : `last used ${passkey.lastUsedAt}`} `;
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.textContent = 'Remove';
    remove.addEventListener('click', () => void client.remove(passkey.id).then(render));
    item.append(remove);
    list.append(item);
  }
}

$('demo').addEventListener('submit', (event) => {
  event.preventDefault();
  void api('POST', '/api/demo-account', { name: $<HTMLInputElement>('demo-name').value }).then(render);
});
$('sign-out').addEventListener('click', () => void api('POST', '/api/sign-out').then(render));
$('add').addEventListener('click', () => {
  status('');
  client
    .register({ name: `Passkey ${new Date().toISOString().slice(0, 10)}` })
    .then(() => status('Passkey added.'))
    .catch((error: unknown) => status(explain(error)))
    .finally(() => void render());
});
$('sign-in').addEventListener('click', () => {
  status('');
  client
    .signIn()
    .then(() => status('Signed in.'))
    .catch((error: unknown) => status(explain(error)))
    .finally(() => void render());
});
$('approve').addEventListener('click', () => {
  const request = readHandoffRequest(location.href);
  if (request !== null) {
    client
      .authorizeHandoff(request)
      .then((redirect) => location.assign(redirect))
      .catch((error: unknown) => status(explain(error)));
  }
});
$('deny').addEventListener('click', () => {
  const request = readHandoffRequest(location.href);
  if (request !== null) {
    location.assign(handoffDeniedUrl(request));
  }
});

void render();
