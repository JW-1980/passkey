import { createPasskeyClient, type HandoffRequest } from './client.js';
import { PasskeyError } from './errors.js';
import type { Authenticator, GetOptions, PasskeySummary } from './types.js';

/** The part of a Firebase `User` this module uses (structural, so the SDK is not bundled here). */
export interface FirebaseUserLike {
  readonly uid: string;
  getIdToken(forceRefresh?: boolean): Promise<string>;
}

/** The part of a Firebase `Auth` this module uses. */
export interface FirebaseAuthLike {
  readonly currentUser: FirebaseUserLike | null;
}

export interface FirebasePasskeysOptions<A extends FirebaseAuthLike, C> {
  /** The Firebase `Auth` instance (`getAuth(app)`). */
  auth: A;
  /** Firebase's `signInWithCustomToken` from `firebase/auth`. */
  signInWithCustomToken: (auth: A, customToken: string) => Promise<C>;
  /** The hub's passkey routes, for example `https://login.example.nl/passkey`. */
  hubUrl: string;
  authenticator: Authenticator;
  fetch?: typeof fetch;
}

export interface FirebasePasskeys<C> {
  isSupported(): Promise<boolean>;
  supportsAutofill(): Promise<boolean>;
  /**
   * Signs in with a passkey: the hub verifies it and answers a custom token, which is exchanged at
   * Firebase. Resolves with Firebase's `UserCredential`.
   */
  signIn(options?: GetOptions): Promise<C>;
  /**
   * Adds a passkey to the signed-in Firebase user. Needs a recent sign-in; otherwise it fails with
   * a `PasskeyError` for which {@link isReauthenticationRequired} is true: re-authenticate with
   * Firebase (or sign in with a passkey) and try again.
   */
  register(input?: { name?: string }): Promise<PasskeySummary>;
  list(): Promise<PasskeySummary[]>;
  rename(id: string, name: string): Promise<PasskeySummary>;
  /** Removes a passkey. Needs a recent sign-in, like {@link register}. */
  remove(id: string): Promise<void>;
  /** Browser page of the desktop/Android handoff: returns the loopback URL to navigate to. */
  authorizeHandoff(request: HandoffRequest): Promise<string>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Reads `{ firebase: { customToken } }` from a hub answer. */
export function customTokenFrom(answer: unknown): string {
  const firebase = isRecord(answer) ? answer.firebase : undefined;
  const token = isRecord(firebase) ? firebase.customToken : undefined;
  if (typeof token === 'string' && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) {
    return token;
  }
  throw new PasskeyError('invalid_response', 'The sign-in service did not send a usable token.');
}

/** True when the hub asks for a fresh sign-in before this action. */
export function isReauthenticationRequired(error: unknown): boolean {
  return error instanceof PasskeyError && error.serverCode === 'reauthentication_required';
}

export function createFirebasePasskeys<A extends FirebaseAuthLike, C>(options: FirebasePasskeysOptions<A, C>): FirebasePasskeys<C> {
  async function bearer(): Promise<Record<string, string>> {
    const user = options.auth.currentUser;
    if (user === null) {
      return {};
    }
    return { Authorization: `Bearer ${await user.getIdToken()}` };
  }

  const clientOptions: Parameters<typeof createPasskeyClient>[0] = {
    baseUrl: options.hubUrl,
    authenticator: options.authenticator,
    headers: bearer,
    // Bearer tokens only: the hub never reads cookies, so none are sent to it.
    credentials: 'omit',
  };
  if (options.fetch !== undefined) {
    clientOptions.fetch = options.fetch;
  }
  const client = createPasskeyClient(clientOptions);

  function requireUser(): void {
    if (options.auth.currentUser === null) {
      throw new PasskeyError('server', 'Sign in first.', { status: 401, serverCode: 'unauthenticated' });
    }
  }

  return {
    isSupported: () => client.isSupported(),
    supportsAutofill: () => client.supportsAutofill(),

    async signIn(getOptions = {}) {
      const answer = await client.signIn<unknown>(getOptions);
      const token = customTokenFrom(answer);
      try {
        return await options.signInWithCustomToken(options.auth, token);
      } catch (cause) {
        const code = isRecord(cause) && typeof cause.code === 'string' ? cause.code : '';
        if (code === 'auth/network-request-failed') {
          throw new PasskeyError('network', 'Firebase could not be reached.', { cause });
        }
        throw new PasskeyError('server', 'Firebase refused the sign-in.', { cause, serverCode: code || 'firebase' });
      }
    },

    async register(input = {}) {
      requireUser();
      return client.register(input);
    },

    async list() {
      requireUser();
      return client.list();
    },

    async rename(id, name) {
      requireUser();
      return client.rename(id, name);
    },

    async remove(id) {
      requireUser();
      return client.remove(id);
    },

    async authorizeHandoff(request) {
      requireUser();
      return client.authorizeHandoff(request);
    },
  };
}

/**
 * Exchanges the signed-in user's ID token for the application's own session (step F6 of the
 * design): `POST url` with the ID token as bearer. Resolves with the server's JSON answer.
 */
export async function exchangeIdToken<T = unknown>(
  url: string,
  user: FirebaseUserLike,
  init: { fetch?: typeof fetch; headers?: Record<string, string>; credentials?: RequestCredentials } = {},
): Promise<T> {
  const doFetch = init.fetch ?? globalThis.fetch;
  let response: Response;
  try {
    response = await doFetch(url, {
      method: 'POST',
      credentials: init.credentials ?? 'same-origin',
      cache: 'no-store',
      headers: { Accept: 'application/json', ...init.headers, Authorization: `Bearer ${await user.getIdToken()}` },
    });
  } catch (cause) {
    throw new PasskeyError('network', 'The server could not be reached.', { cause });
  }
  const payload: unknown = await response.json().catch(() => undefined);
  if (!response.ok) {
    const error = isRecord(payload) && isRecord(payload.error) ? payload.error : {};
    const details: { status: number; serverCode?: string } = { status: response.status };
    if (typeof error.code === 'string') {
      details.serverCode = error.code;
    }
    throw new PasskeyError('server', typeof error.message === 'string' ? error.message : `The server answered with status ${response.status}.`, details);
  }
  return payload as T;
}
