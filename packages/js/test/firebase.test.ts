import { describe, expect, it } from 'vitest';
import { PasskeyError } from '../src/index.js';
import { createFirebasePasskeys, customTokenFrom, exchangeIdToken, isReauthenticationRequired } from '../src/firebase.js';
import type { Authenticator } from '../src/index.js';

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
  credentials: RequestCredentials | undefined;
}

function fakeFetch(answers: Response[]): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const fetchFn = (async (url: RequestInfo | URL, init?: RequestInit) => {
    calls.push({
      url: String(url),
      method: init?.method ?? 'GET',
      headers: init?.headers as Record<string, string>,
      body: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined,
      credentials: init?.credentials,
    });
    const answer = answers.shift();
    if (answer === undefined) throw new Error('unexpected request');
    return answer;
  }) as typeof fetch;
  return { fetch: fetchFn, calls };
}

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const TOKEN = 'eyJhbGciOiJSUzI1NiJ9.eyJ1aWQiOiJ1In0.c2ln';
const ASSERTION = { id: 'aWQ', rawId: 'aWQ', type: 'public-key' as const, response: { clientDataJSON: 'a', authenticatorData: 'b', signature: 'c' } };
const ATTESTATION = { id: 'aWQ', rawId: 'aWQ', type: 'public-key' as const, response: { clientDataJSON: 'a', attestationObject: 'b' } };
const SUMMARY = { id: 'aWQ', name: 'Laptop', createdAt: '2026-11-21T10:00:00Z', lastUsedAt: null, synced: true, transports: ['internal'] };

const authenticator: Authenticator = {
  isSupported: async () => true,
  supportsAutofill: async () => false,
  create: async () => ATTESTATION,
  get: async () => ASSERTION,
};

function auth(signedIn: boolean) {
  return {
    currentUser: signedIn ? { uid: 'uid-1', getIdToken: async () => 'id.token.value' } : null,
  };
}

describe('createFirebasePasskeys', () => {
  it('signs in with a passkey and hands the custom token to Firebase', async () => {
    const { fetch, calls } = fakeFetch([json({ ceremony: 'c1', publicKey: { challenge: 'x' } }), json({ firebase: { customToken: TOKEN, expiresIn: 300 } })]);
    const exchanged: string[] = [];
    const a = auth(false);
    const passkeys = createFirebasePasskeys({
      auth: a,
      signInWithCustomToken: async (given, token) => {
        expect(given).toBe(a);
        exchanged.push(token);
        return { user: { uid: 'uid-1' } };
      },
      hubUrl: 'https://login.example/passkey/',
      authenticator,
      fetch,
    });

    const credential = await passkeys.signIn();

    expect(credential).toEqual({ user: { uid: 'uid-1' } });
    expect(exchanged).toEqual([TOKEN]);
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      'POST https://login.example/passkey/login/options',
      'POST https://login.example/passkey/login/verify',
    ]);
    expect(calls.every((c) => c.credentials === 'omit')).toBe(true);
    expect(calls[0]?.headers.Authorization).toBeUndefined();
  });

  it('refuses an answer without a usable custom token', async () => {
    const { fetch } = fakeFetch([json({ ceremony: 'c1', publicKey: { challenge: 'x' } }), json({ ok: true })]);
    const passkeys = createFirebasePasskeys({ auth: auth(false), signInWithCustomToken: async () => ({}), hubUrl: '/p', authenticator, fetch });
    await expect(passkeys.signIn()).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('maps a Firebase refusal and a Firebase network failure', async () => {
    for (const [firebaseCode, expected] of [
      ['auth/user-disabled', 'server'],
      ['auth/network-request-failed', 'network'],
    ] as const) {
      const { fetch } = fakeFetch([json({ ceremony: 'c1', publicKey: { challenge: 'x' } }), json({ firebase: { customToken: TOKEN } })]);
      const passkeys = createFirebasePasskeys({
        auth: auth(false),
        signInWithCustomToken: async () => {
          throw Object.assign(new Error('nope'), { code: firebaseCode });
        },
        hubUrl: '/p',
        authenticator,
        fetch,
      });
      const error = await passkeys.signIn().catch((e: unknown) => e);
      expect(error).toBeInstanceOf(PasskeyError);
      expect((error as PasskeyError).code).toBe(expected);
    }
  });

  it('registers with the ID token as bearer and without cookies', async () => {
    const { fetch, calls } = fakeFetch([json({ ceremony: 'c1', publicKey: { challenge: 'x' } }), json({ passkey: SUMMARY }, 201)]);
    const passkeys = createFirebasePasskeys({ auth: auth(true), signInWithCustomToken: async () => ({}), hubUrl: '/p', authenticator, fetch });

    expect(await passkeys.register({ name: 'Laptop' })).toEqual(SUMMARY);
    expect(calls[0]?.headers.Authorization).toBe('Bearer id.token.value');
    expect(calls[1]?.headers.Authorization).toBe('Bearer id.token.value');
    expect(calls[1]?.body).toMatchObject({ ceremony: 'c1', name: 'Laptop' });
  });

  it('needs a signed-in user for managing passkeys, without asking the hub', async () => {
    const { fetch, calls } = fakeFetch([]);
    const passkeys = createFirebasePasskeys({ auth: auth(false), signInWithCustomToken: async () => ({}), hubUrl: '/p', authenticator, fetch });
    for (const action of [() => passkeys.register(), () => passkeys.list(), () => passkeys.remove('x'), () => passkeys.rename('x', 'y')]) {
      await expect(action()).rejects.toMatchObject({ code: 'server', serverCode: 'unauthenticated' });
    }
    expect(calls).toEqual([]);
  });

  it('recognises the request for a fresh sign-in', async () => {
    const { fetch } = fakeFetch([json({ error: { code: 'reauthentication_required', message: 'again' } }, 403)]);
    const passkeys = createFirebasePasskeys({ auth: auth(true), signInWithCustomToken: async () => ({}), hubUrl: '/p', authenticator, fetch });
    const error = await passkeys.register().catch((e: unknown) => e);
    expect(isReauthenticationRequired(error)).toBe(true);
    expect(isReauthenticationRequired(new PasskeyError('server', 'x', { serverCode: 'unauthenticated' }))).toBe(false);
  });

  it('authorizes a handoff only to the loopback address', async () => {
    const { fetch } = fakeFetch([json({ redirect: 'http://127.0.0.1:5000/callback?code=c&state=s' }), json({ redirect: 'https://evil.example/' })]);
    const passkeys = createFirebasePasskeys({ auth: auth(true), signInWithCustomToken: async () => ({}), hubUrl: '/p', authenticator, fetch });
    expect(await passkeys.authorizeHandoff({ challenge: 'c', port: 5000, state: 's' })).toBe('http://127.0.0.1:5000/callback?code=c&state=s');
    await expect(passkeys.authorizeHandoff({ challenge: 'c', port: 5000, state: 's' })).rejects.toMatchObject({ code: 'invalid_response' });
  });
});

describe('customTokenFrom', () => {
  it('accepts only a JWT-shaped token', () => {
    expect(customTokenFrom({ firebase: { customToken: TOKEN } })).toBe(TOKEN);
    expect(() => customTokenFrom({ firebase: { customToken: 'not a token' } })).toThrow(PasskeyError);
    expect(() => customTokenFrom(null)).toThrow(PasskeyError);
  });
});

describe('exchangeIdToken', () => {
  it('posts the ID token as bearer and returns the answer', async () => {
    const { fetch, calls } = fakeFetch([json({ ok: true })]);
    expect(await exchangeIdToken('/session', { uid: 'u', getIdToken: async () => 'tok' }, { fetch })).toEqual({ ok: true });
    expect(calls[0]).toMatchObject({ method: 'POST', url: '/session', credentials: 'same-origin' });
    expect(calls[0]?.headers.Authorization).toBe('Bearer tok');
  });

  it('turns a refusal into a PasskeyError with the server code', async () => {
    const { fetch } = fakeFetch([json({ error: { code: 'mfa_required', message: 'Use a passkey' } }, 403)]);
    await expect(exchangeIdToken('/session', { uid: 'u', getIdToken: async () => 'tok' }, { fetch })).rejects.toMatchObject({
      code: 'server',
      status: 403,
      serverCode: 'mfa_required',
    });
  });
});
