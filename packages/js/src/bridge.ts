import { PASSKEY_ERROR_CODES, PasskeyError, type PasskeyErrorCode } from './errors.js';
import type { AuthenticationResponseJSON, Authenticator, RegistrationResponseJSON } from './types.js';

/**
 * A native passkey API reached through a bridge: React Native, or a webview that calls into
 * Kotlin or Swift. `create` and `get` receive the WebAuthn options as an object and may answer
 * with an object or with its JSON text (what Android's Credential Manager returns).
 */
export interface NativePasskeyBridge {
  isSupported(): boolean | Promise<boolean>;
  create(options: object): Promise<unknown>;
  get(options: object): Promise<unknown>;
}

function parse(value: unknown): Record<string, unknown> | null {
  let parsed = value;
  if (typeof value === 'string') {
    try {
      parsed = JSON.parse(value);
    } catch {
      return null;
    }
  }
  return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
}

function hasStrings(record: unknown, fields: string[]): boolean {
  return (
    typeof record === 'object' &&
    record !== null &&
    fields.every((field) => typeof (record as Record<string, unknown>)[field] === 'string')
  );
}

/** Error names of `react-native-passkey` (its `error` field), mapped to this library's codes. */
const REACT_NATIVE_PASSKEY_ERRORS: Record<string, PasskeyErrorCode> = {
  UserCancelled: 'cancelled',
  Interrupted: 'cancelled',
  TimedOut: 'cancelled',
  NotSupported: 'unsupported',
  NoCreateOption: 'unsupported',
  NoCredentials: 'no_credentials',
  CredentialAlreadyExists: 'already_registered',
  BadConfiguration: 'security',
  InvalidChallenge: 'invalid_response',
  InvalidUserId: 'invalid_response',
};

/**
 * Translates what a bridge threw. Understood shapes: `{ code }` holding one of this library's own
 * codes (what the Android helper of this repository reports), and `{ error }` holding an error
 * name of `react-native-passkey`.
 */
export function fromBridgeError(error: unknown): PasskeyError {
  if (error instanceof PasskeyError) {
    return error;
  }
  const record = typeof error === 'object' && error !== null ? (error as Record<string, unknown>) : {};
  const message = typeof record.message === 'string' && record.message !== '' ? record.message : 'The passkey prompt failed.';
  const details = { cause: error };
  if (typeof record.code === 'string' && (PASSKEY_ERROR_CODES as readonly string[]).includes(record.code)) {
    return new PasskeyError(record.code as PasskeyErrorCode, message, details);
  }
  if (typeof record.error === 'string') {
    const code = REACT_NATIVE_PASSKEY_ERRORS[record.error];
    if (code !== undefined) {
      return new PasskeyError(code, message, details);
    }
  }
  return new PasskeyError('unknown', message, details);
}

export function bridgeAuthenticator(bridge: NativePasskeyBridge): Authenticator {
  return {
    isSupported: async () => bridge.isSupported(),
    // Autofill (conditional mediation) is a browser feature; native apps show their own sheet.
    supportsAutofill: async () => false,
    async create(options) {
      let result: unknown;
      try {
        result = await bridge.create(options);
      } catch (error) {
        throw fromBridgeError(error);
      }
      const credential = parse(result);
      if (
        credential === null ||
        !hasStrings(credential, ['id', 'rawId']) ||
        !hasStrings(credential.response, ['clientDataJSON', 'attestationObject'])
      ) {
        throw new PasskeyError('invalid_response', 'The device returned a passkey this client cannot read.');
      }
      return { ...credential, type: 'public-key' } as RegistrationResponseJSON;
    },
    async get(options, getOptions = {}) {
      if (getOptions.autofill === true) {
        throw new PasskeyError('unsupported', 'Passkey autofill is only available in a browser.');
      }
      let result: unknown;
      try {
        result = await bridge.get(options);
      } catch (error) {
        throw fromBridgeError(error);
      }
      const credential = parse(result);
      if (
        credential === null ||
        !hasStrings(credential, ['id', 'rawId']) ||
        !hasStrings(credential.response, ['clientDataJSON', 'authenticatorData', 'signature'])
      ) {
        throw new PasskeyError('invalid_response', 'The device returned a sign-in this client cannot read.');
      }
      return { ...credential, type: 'public-key' } as AuthenticationResponseJSON;
    },
  };
}
