import { PasskeyError } from './errors.js';
import type {
  AuthenticationResponseJSON,
  Authenticator,
  CreationOptionsJSON,
  GetOptions,
  PasskeySummary,
  RegistrationResponseJSON,
  RequestOptionsJSON,
} from './types.js';

export interface PasskeyClientOptions {
  /** Where the server's passkey routes live, for example `/passkey` or `https://app.example/passkey`. */
  baseUrl: string;
  authenticator: Authenticator;
  /** Defaults to the global `fetch`. */
  fetch?: typeof fetch;
  /**
   * Extra headers for every request, resolved per request: a CSRF token for cookie sessions
   * (see `laravelCsrfHeaders`), or `Authorization: Bearer …` for token sessions.
   */
  headers?: () => Record<string, string> | Promise<Record<string, string>>;
  /** Cookie policy of `fetch`. Default `same-origin`. */
  credentials?: RequestCredentials;
}

export interface HandoffRequest {
  /** PKCE S256 challenge of the desktop app. */
  challenge: string;
  /** Loopback port the desktop app listens on. */
  port: number;
  state: string;
}

export interface PasskeyClient {
  isSupported(): Promise<boolean>;
  supportsAutofill(): Promise<boolean>;
  /** Creates a passkey for the signed-in account and stores it at the server. */
  register(input?: { name?: string }): Promise<PasskeySummary>;
  /**
   * Signs in with a passkey. Resolves with the server's own answer to a successful sign-in (what
   * that holds is the app's choice: a redirect, a token, a next step such as a second factor).
   */
  signIn<T = unknown>(options?: GetOptions): Promise<T>;
  list(): Promise<PasskeySummary[]>;
  rename(id: string, name: string): Promise<PasskeySummary>;
  remove(id: string): Promise<void>;
  /**
   * Browser page of the desktop handoff: asks the server for a single-use code for the signed-in
   * account and returns the loopback URL to send the browser to.
   */
  authorizeHandoff(request: HandoffRequest): Promise<string>;
}

interface CeremonyStart<T> {
  ceremony: string;
  publicKey: T;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isSummary(value: unknown): value is PasskeySummary {
  return (
    isRecord(value) &&
    typeof value.id === 'string' &&
    typeof value.name === 'string' &&
    typeof value.createdAt === 'string' &&
    (value.lastUsedAt === null || typeof value.lastUsedAt === 'string') &&
    typeof value.synced === 'boolean' &&
    Array.isArray(value.transports)
  );
}

function ceremonyStart<T>(value: unknown): CeremonyStart<T> {
  if (
    isRecord(value) &&
    typeof value.ceremony === 'string' &&
    value.ceremony !== '' &&
    isRecord(value.publicKey) &&
    typeof value.publicKey.challenge === 'string'
  ) {
    return { ceremony: value.ceremony, publicKey: value.publicKey as T };
  }
  throw new PasskeyError('invalid_response', 'The server sent passkey options this client cannot read.');
}

function summary(value: unknown): PasskeySummary {
  const passkey = isRecord(value) ? value.passkey : undefined;
  if (isSummary(passkey)) {
    return passkey;
  }
  throw new PasskeyError('invalid_response', 'The server sent a passkey this client cannot read.');
}

export function createPasskeyClient(options: PasskeyClientOptions): PasskeyClient {
  const base = options.baseUrl.replace(/\/+$/, '');
  const { authenticator } = options;
  const credentials = options.credentials ?? 'same-origin';

  async function call(method: string, path: string, body?: unknown): Promise<unknown> {
    const doFetch = options.fetch ?? globalThis.fetch;
    const headers: Record<string, string> = { Accept: 'application/json', ...(await options.headers?.()) };
    const init: RequestInit = { method, headers, credentials, cache: 'no-store' };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }

    let response: Response;
    try {
      response = await doFetch(base + path, init);
    } catch (cause) {
      throw new PasskeyError('network', 'The server could not be reached.', { cause });
    }

    let payload: unknown = undefined;
    if (response.status !== 204) {
      try {
        payload = await response.json();
      } catch (cause) {
        if (response.ok) {
          throw new PasskeyError('invalid_response', 'The server did not answer with JSON.', { cause });
        }
      }
    }
    if (!response.ok) {
      const error = isRecord(payload) && isRecord(payload.error) ? payload.error : {};
      const details: { status: number; serverCode?: string } = { status: response.status };
      if (typeof error.code === 'string') {
        details.serverCode = error.code;
      }
      throw new PasskeyError(
        'server',
        typeof error.message === 'string' ? error.message : `The server answered with status ${response.status}.`,
        details,
      );
    }
    return payload;
  }

  async function requireSupport(): Promise<void> {
    if (!(await authenticator.isSupported())) {
      throw new PasskeyError('unsupported', 'Passkeys are not supported on this device.');
    }
  }

  return {
    isSupported: () => authenticator.isSupported(),
    supportsAutofill: () => authenticator.supportsAutofill(),

    async register(input = {}) {
      await requireSupport();
      const start = ceremonyStart<CreationOptionsJSON>(await call('POST', '/register/options'));
      const credential: RegistrationResponseJSON = await authenticator.create(start.publicKey);
      const body: Record<string, unknown> = { ceremony: start.ceremony, credential };
      if (input.name !== undefined) {
        body.name = input.name;
      }
      return summary(await call('POST', '/register/verify', body));
    },

    async signIn<T = unknown>(getOptions: GetOptions = {}) {
      await requireSupport();
      const start = ceremonyStart<RequestOptionsJSON>(await call('POST', '/login/options'));
      const credential: AuthenticationResponseJSON = await authenticator.get(start.publicKey, getOptions);
      return (await call('POST', '/login/verify', { ceremony: start.ceremony, credential })) as T;
    },

    async list() {
      const payload = await call('GET', '/passkeys');
      const passkeys = isRecord(payload) ? payload.passkeys : undefined;
      if (Array.isArray(passkeys) && passkeys.every(isSummary)) {
        return passkeys;
      }
      throw new PasskeyError('invalid_response', 'The server sent a passkey list this client cannot read.');
    },

    async rename(id, name) {
      return summary(await call('PATCH', `/passkeys/${encodeURIComponent(id)}`, { name }));
    },

    async remove(id) {
      await call('DELETE', `/passkeys/${encodeURIComponent(id)}`);
    },

    async authorizeHandoff(request) {
      const payload = await call('POST', '/handoff/authorize', request);
      const redirect = isRecord(payload) ? payload.redirect : undefined;
      // The server builds the loopback URL itself; anything else is refused here as well, so a
      // tampered answer can never send the code to another host.
      if (typeof redirect === 'string' && redirect.startsWith(`http://127.0.0.1:${request.port}/`)) {
        return redirect;
      }
      throw new PasskeyError('invalid_response', 'The server sent a handoff address this client refuses.');
    },
  };
}

/**
 * Headers for a Laravel cookie session: echoes the `XSRF-TOKEN` cookie as `X-XSRF-TOKEN`.
 * Pass it as `headers` when the passkey routes sit behind the `web` middleware group.
 */
export function laravelCsrfHeaders(cookieSource: () => string = () => document.cookie): () => Record<string, string> {
  return () => {
    const match = /(?:^|;\s*)XSRF-TOKEN=([^;]+)/.exec(cookieSource());
    return match?.[1] === undefined ? {} : { 'X-XSRF-TOKEN': decodeURIComponent(match[1]) };
  };
}
