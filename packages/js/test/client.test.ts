import { describe, expect, it } from 'vitest';
import { createPasskeyClient, laravelCsrfHeaders, PasskeyError } from '../src/index.js';
import type { Authenticator, PasskeySummary } from '../src/index.js';

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
  credentials: RequestCredentials | undefined;
}

/** A fetch that answers from a queue and records what was sent. */
function fakeFetch(answers: (Response | Error)[]): { fetch: typeof fetch; calls: Call[] } {
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
    if (answer === undefined) {
      throw new Error('unexpected request');
    }
    if (answer instanceof Error) {
      throw answer;
    }
    return answer;
  }) as typeof fetch;
  return { fetch: fetchFn, calls };
}

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const SUMMARY: PasskeySummary = {
  id: 'Y3JlZC1pZA',
  name: 'Laptop',
  createdAt: '2026-11-20T10:00:00Z',
  lastUsedAt: null,
  synced: true,
  transports: ['internal'],
};

const ATTESTATION = { id: 'Y3JlZC1pZA', rawId: 'Y3JlZC1pZA', type: 'public-key' as const, response: { clientDataJSON: 'a', attestationObject: 'b' } };
const ASSERTION = { id: 'Y3JlZC1pZA', rawId: 'Y3JlZC1pZA', type: 'public-key' as const, response: { clientDataJSON: 'a', authenticatorData: 'b', signature: 'c' } };

function fakeAuthenticator(overrides: Partial<Authenticator> = {}): Authenticator & { seen: unknown[] } {
  const seen: unknown[] = [];
  return {
    seen,
    isSupported: async () => true,
    supportsAutofill: async () => false,
    create: async (options) => {
      seen.push(options);
      return ATTESTATION;
    },
    get: async (options, getOptions) => {
      seen.push([options, getOptions]);
      return ASSERTION;
    },
    ...overrides,
  };
}

const CREATION = { rp: { name: 'App' }, user: { id: 'dQ', name: 'u', displayName: 'U' }, challenge: 'Y2hhbGxlbmdl', pubKeyCredParams: [] };
const REQUEST = { challenge: 'Y2hhbGxlbmdl', rpId: 'app.example' };

describe('register', () => {
  it('hands the server options to the authenticator and posts the result with the ceremony', async () => {
    const { fetch, calls } = fakeFetch([json({ ceremony: 'cer-1', publicKey: CREATION }), json({ passkey: SUMMARY }, 201)]);
    const authenticator = fakeAuthenticator();
    const client = createPasskeyClient({ baseUrl: 'https://app.example/passkey/', authenticator, fetch });

    await expect(client.register({ name: 'Laptop' })).resolves.toEqual(SUMMARY);

    expect(authenticator.seen).toEqual([CREATION]);
    expect(calls.map((c) => [c.method, c.url])).toEqual([
      ['POST', 'https://app.example/passkey/register/options'],
      ['POST', 'https://app.example/passkey/register/verify'],
    ]);
    expect(calls[1]?.body).toEqual({ ceremony: 'cer-1', credential: ATTESTATION, name: 'Laptop' });
    expect(calls[1]?.headers['Content-Type']).toBe('application/json');
    expect(calls[0]?.credentials).toBe('same-origin');
  });

  it('leaves the name out when none is given', async () => {
    const { fetch, calls } = fakeFetch([json({ ceremony: 'cer-1', publicKey: CREATION }), json({ passkey: SUMMARY })]);
    await createPasskeyClient({ baseUrl: '/passkey', authenticator: fakeAuthenticator(), fetch }).register();
    expect(calls[1]?.body).toEqual({ ceremony: 'cer-1', credential: ATTESTATION });
  });

  it('does not call the server when the device has no passkey support', async () => {
    const { fetch, calls } = fakeFetch([]);
    const client = createPasskeyClient({ baseUrl: '/passkey', authenticator: fakeAuthenticator({ isSupported: async () => false }), fetch });
    await expect(client.register()).rejects.toMatchObject({ code: 'unsupported' });
    expect(calls).toEqual([]);
  });

  it('does not verify when the person closes the prompt', async () => {
    const { fetch, calls } = fakeFetch([json({ ceremony: 'cer-1', publicKey: CREATION })]);
    const authenticator = fakeAuthenticator({
      create: async () => {
        throw new PasskeyError('cancelled', 'closed');
      },
    });
    await expect(createPasskeyClient({ baseUrl: '/passkey', authenticator, fetch }).register()).rejects.toMatchObject({ code: 'cancelled' });
    expect(calls).toHaveLength(1);
  });

  it.each([
    [{ publicKey: CREATION }],
    [{ ceremony: '', publicKey: CREATION }],
    [{ ceremony: 'cer-1' }],
    [{ ceremony: 'cer-1', publicKey: { rp: {} } }],
    [[]],
  ])('refuses unreadable options %j without prompting', async (options) => {
    const { fetch } = fakeFetch([json(options)]);
    const authenticator = fakeAuthenticator();
    await expect(createPasskeyClient({ baseUrl: '/passkey', authenticator, fetch }).register()).rejects.toMatchObject({ code: 'invalid_response' });
    expect(authenticator.seen).toEqual([]);
  });

  it('refuses a stored passkey it cannot read', async () => {
    const { fetch } = fakeFetch([json({ ceremony: 'cer-1', publicKey: CREATION }), json({ passkey: { id: 1 } })]);
    await expect(createPasskeyClient({ baseUrl: '/passkey', authenticator: fakeAuthenticator(), fetch }).register()).rejects.toMatchObject({
      code: 'invalid_response',
    });
  });
});

describe('signIn', () => {
  it('returns the server answer of a verified sign-in untouched', async () => {
    const { fetch, calls } = fakeFetch([json({ ceremony: 'cer-2', publicKey: REQUEST }), json({ next: 'second_factor' })]);
    const authenticator = fakeAuthenticator();
    const client = createPasskeyClient({ baseUrl: '/passkey', authenticator, fetch });

    await expect(client.signIn({ autofill: true })).resolves.toEqual({ next: 'second_factor' });

    expect(authenticator.seen).toEqual([[REQUEST, { autofill: true }]]);
    expect(calls[0]?.body).toBeUndefined();
    expect(calls[1]?.body).toEqual({ ceremony: 'cer-2', credential: ASSERTION });
  });

  it('reports a server refusal with its status, code and message', async () => {
    const { fetch } = fakeFetch([
      json({ ceremony: 'cer-2', publicKey: REQUEST }),
      json({ error: { code: 'invalid_passkey', message: 'This passkey is not valid.' } }, 401),
    ]);
    const error = await createPasskeyClient({ baseUrl: '/passkey', authenticator: fakeAuthenticator(), fetch })
      .signIn()
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(PasskeyError);
    expect(error).toMatchObject({ code: 'server', status: 401, serverCode: 'invalid_passkey', message: 'This passkey is not valid.' });
  });

  it('reports a server error without a JSON body', async () => {
    const { fetch } = fakeFetch([new Response('<html>Bad gateway</html>', { status: 502 })]);
    const error = await createPasskeyClient({ baseUrl: '/passkey', authenticator: fakeAuthenticator(), fetch })
      .signIn()
      .catch((e: unknown) => e);
    expect(error).toMatchObject({ code: 'server', status: 502, serverCode: undefined });
  });

  it('reports an unreachable server as a network error and keeps the cause', async () => {
    const cause = new TypeError('fetch failed');
    const { fetch } = fakeFetch([cause]);
    const error = await createPasskeyClient({ baseUrl: '/passkey', authenticator: fakeAuthenticator(), fetch })
      .signIn()
      .catch((e: unknown) => e);
    expect(error).toMatchObject({ code: 'network', cause });
  });

  it('refuses a success answer that is not JSON', async () => {
    const { fetch } = fakeFetch([new Response('ok', { status: 200 })]);
    await expect(createPasskeyClient({ baseUrl: '/passkey', authenticator: fakeAuthenticator(), fetch }).signIn()).rejects.toMatchObject({
      code: 'invalid_response',
    });
  });
});

describe('management', () => {
  it('lists, renames and removes with encoded ids', async () => {
    const renamed = { ...SUMMARY, name: 'Work laptop' };
    const { fetch, calls } = fakeFetch([json({ passkeys: [SUMMARY] }), json({ passkey: renamed }), new Response(null, { status: 204 })]);
    const client = createPasskeyClient({ baseUrl: '/passkey', authenticator: fakeAuthenticator(), fetch });

    await expect(client.list()).resolves.toEqual([SUMMARY]);
    await expect(client.rename('a/b', 'Work laptop')).resolves.toEqual(renamed);
    await expect(client.remove('a/b')).resolves.toBeUndefined();

    expect(calls.map((c) => [c.method, c.url, c.body])).toEqual([
      ['GET', '/passkey/passkeys', undefined],
      ['PATCH', '/passkey/passkeys/a%2Fb', { name: 'Work laptop' }],
      ['DELETE', '/passkey/passkeys/a%2Fb', undefined],
    ]);
  });

  it('refuses a list with an unreadable entry', async () => {
    const { fetch } = fakeFetch([json({ passkeys: [SUMMARY, { id: 'x' }] })]);
    await expect(createPasskeyClient({ baseUrl: '/passkey', authenticator: fakeAuthenticator(), fetch }).list()).rejects.toMatchObject({
      code: 'invalid_response',
    });
  });
});

describe('headers', () => {
  it('resolves extra headers per request', async () => {
    let token = 'one';
    const { fetch, calls } = fakeFetch([json({ passkeys: [] }), json({ passkeys: [] })]);
    const client = createPasskeyClient({
      baseUrl: '/passkey',
      authenticator: fakeAuthenticator(),
      fetch,
      credentials: 'omit',
      headers: async () => ({ Authorization: `Bearer ${token}` }),
    });
    await client.list();
    token = 'two';
    await client.list();
    expect(calls.map((c) => c.headers.Authorization)).toEqual(['Bearer one', 'Bearer two']);
    expect(calls[0]?.credentials).toBe('omit');
  });

  it('echoes the decoded Laravel XSRF cookie', () => {
    expect(laravelCsrfHeaders(() => 'a=1; XSRF-TOKEN=abc%3D%3D; b=2')()).toEqual({ 'X-XSRF-TOKEN': 'abc==' });
    expect(laravelCsrfHeaders(() => 'XSRF-TOKEN=first')()).toEqual({ 'X-XSRF-TOKEN': 'first' });
    expect(laravelCsrfHeaders(() => 'NOT-XSRF-TOKEN=x')()).toEqual({});
    expect(laravelCsrfHeaders(() => '')()).toEqual({});
  });
});

describe('authorizeHandoff', () => {
  const request = { challenge: 'c'.repeat(43), port: 51234, state: 's'.repeat(43) };

  it('returns the loopback address of the desktop app', async () => {
    const redirect = `http://127.0.0.1:51234/callback?code=abc&state=${request.state}`;
    const { fetch, calls } = fakeFetch([json({ redirect })]);
    const client = createPasskeyClient({ baseUrl: '/passkey', authenticator: fakeAuthenticator(), fetch });
    await expect(client.authorizeHandoff(request)).resolves.toBe(redirect);
    expect(calls[0]?.body).toEqual(request);
  });

  it.each([
    'https://evil.example/callback?code=abc',
    'http://127.0.0.1:51235/callback?code=abc',
    'http://127.0.0.1:51234.evil.example/callback?code=abc',
    'http://127.0.0.1:51234@evil.example/callback?code=abc',
    'http://localhost:51234/callback?code=abc',
  ])('refuses to send the code to %s', async (redirect) => {
    const { fetch } = fakeFetch([json({ redirect })]);
    const client = createPasskeyClient({ baseUrl: '/passkey', authenticator: fakeAuthenticator(), fetch });
    await expect(client.authorizeHandoff(request)).rejects.toMatchObject({ code: 'invalid_response' });
  });
});
