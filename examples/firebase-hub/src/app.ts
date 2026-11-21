// Browser side of the example: Firebase for the classic methods, the hub for passkeys, and the
// session exchange with the "property" backend.
import { initializeApp } from 'firebase/app';
import {
  connectAuthEmulator,
  createUserWithEmailAndPassword,
  getAuth,
  onAuthStateChanged,
  signInWithCustomToken,
  signInWithEmailAndPassword,
  signOut,
} from 'firebase/auth';
import { browserAuthenticator } from '../../../packages/js/src/browser.js';
import { isPasskeyError } from '../../../packages/js/src/errors.js';
import { createFirebasePasskeys, exchangeIdToken, isReauthenticationRequired } from '../../../packages/js/src/firebase.js';

const config = JSON.parse(document.body.dataset.config ?? '{}') as { projectId: string; emulator: string; hub: string };
const app = initializeApp({ apiKey: 'fake-api-key', projectId: config.projectId, authDomain: `${config.projectId}.firebaseapp.com` });
const auth = getAuth(app);
connectAuthEmulator(auth, config.emulator, { disableWarnings: true });

const passkeys = createFirebasePasskeys({ auth, signInWithCustomToken, hubUrl: config.hub, authenticator: browserAuthenticator() });
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const status = (text: string) => {
  $('status').textContent = text;
};
const params = new URLSearchParams(location.search);
const handoff = params.has('challenge') ? { challenge: params.get('challenge') ?? '', port: Number(params.get('port')), state: params.get('state') ?? '' } : null;

async function show(): Promise<void> {
  const user = auth.currentUser;
  $('signed-out').hidden = user !== null;
  $('signed-in').hidden = user === null;
  $('desktop').hidden = user === null || handoff === null;
  if (user === null) {
    status('Signed out');
    return;
  }
  const session = await exchangeIdToken<{ uid: string; method: string; mfa: boolean }>('/session', user);
  status(`Signed in as ${session.uid} with ${session.method}${session.mfa ? ' (multi-factor)' : ''}`);
  const list = await passkeys.list();
  $('passkeys').replaceChildren(...list.map((p) => Object.assign(document.createElement('li'), { textContent: p.name })));
}

function report(error: unknown): void {
  if (isPasskeyError(error) && error.code === 'cancelled') return;
  if (isReauthenticationRequired(error)) {
    status('Please sign in again first.');
    return;
  }
  status(`Error: ${error instanceof Error ? error.message : String(error)}`);
}

const email = () => $<HTMLInputElement>('email').value;
const password = () => $<HTMLInputElement>('password').value;

$('sign-up').onclick = () => createUserWithEmailAndPassword(auth, email(), password()).catch(report);
$('sign-in').onclick = () => signInWithEmailAndPassword(auth, email(), password()).catch(report);
$('passkey-sign-in').onclick = () => passkeys.signIn().catch(report);
$('add-passkey').onclick = () => passkeys.register({ name: 'This device' }).then(show).catch(report);
$('sign-out').onclick = async () => {
  await fetch('/session', { method: 'DELETE' });
  await signOut(auth);
};
$('approve').onclick = async () => {
  if (handoff === null) return;
  try {
    location.href = await passkeys.authorizeHandoff(handoff);
  } catch (error) {
    report(error);
  }
};
$('deny').onclick = () => {
  if (handoff !== null) location.href = `http://127.0.0.1:${handoff.port}/callback?error=denied&state=${handoff.state}`;
};
onAuthStateChanged(auth, () => {
  show().catch(report);
});
