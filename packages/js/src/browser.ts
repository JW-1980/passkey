import {
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  startAuthentication,
  startRegistration,
  WebAuthnError,
} from '@simplewebauthn/browser';
import { PasskeyError } from './errors.js';
import type { Authenticator } from './types.js';

/** Translates what the browser (or `@simplewebauthn/browser`) threw into a `PasskeyError`. */
export function fromBrowserError(error: unknown): PasskeyError {
  if (error instanceof PasskeyError) {
    return error;
  }
  const name = error instanceof Error ? error.name : '';
  const code = error instanceof WebAuthnError ? error.code : '';
  const message = error instanceof Error ? error.message : 'The passkey prompt failed.';
  const details = { cause: error };

  if (code === 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED' || name === 'InvalidStateError') {
    return new PasskeyError('already_registered', 'This device already has a passkey for this account.', details);
  }
  if (code === 'ERROR_CEREMONY_ABORTED' || name === 'AbortError' || name === 'NotAllowedError') {
    // The browser reports a closed prompt, a timeout and a refused permission the same way, on
    // purpose (so a site cannot tell them apart).
    return new PasskeyError('cancelled', 'The passkey prompt was closed.', details);
  }
  if (code === 'ERROR_INVALID_DOMAIN' || code === 'ERROR_INVALID_RP_ID' || name === 'SecurityError') {
    return new PasskeyError('security', 'This page may not use passkeys of this site.', details);
  }
  if (name === 'NotSupportedError') {
    return new PasskeyError('unsupported', 'This device cannot create the requested passkey.', details);
  }
  return new PasskeyError('unknown', message, details);
}

/** The browser's own WebAuthn API, through `@simplewebauthn/browser`. */
export function browserAuthenticator(): Authenticator {
  return {
    isSupported: async () => browserSupportsWebAuthn(),
    supportsAutofill: () => browserSupportsWebAuthnAutofill(),
    async create(options) {
      try {
        return (await startRegistration({
          optionsJSON: options as unknown as Parameters<typeof startRegistration>[0]['optionsJSON'],
        })) as unknown as Awaited<ReturnType<Authenticator['create']>>;
      } catch (error) {
        throw fromBrowserError(error);
      }
    },
    async get(options, getOptions = {}) {
      try {
        return (await startAuthentication({
          optionsJSON: options as unknown as Parameters<typeof startAuthentication>[0]['optionsJSON'],
          useBrowserAutofill: getOptions.autofill === true,
        })) as unknown as Awaited<ReturnType<Authenticator['get']>>;
      } catch (error) {
        throw fromBrowserError(error);
      }
    },
  };
}
