/**
 * Why a passkey action failed, in terms an app can act on.
 *
 * - `cancelled`: the person closed the prompt, or it timed out. Not an error to report.
 * - `unsupported`: this device or browser has no passkey support.
 * - `already_registered`: this authenticator already holds a passkey for the account.
 * - `no_credentials`: no passkey for this site is available on the device.
 * - `security`: the page's origin does not match the relying party (configuration error).
 * - `network`: the server could not be reached.
 * - `server`: the server answered with an error; see `status` and `serverCode`.
 * - `invalid_response`: the server or the authenticator returned something unusable.
 * - `unknown`: anything else; see `cause`.
 */
export type PasskeyErrorCode =
  | 'cancelled'
  | 'unsupported'
  | 'already_registered'
  | 'no_credentials'
  | 'security'
  | 'network'
  | 'server'
  | 'invalid_response'
  | 'unknown';

export const PASSKEY_ERROR_CODES: readonly PasskeyErrorCode[] = [
  'cancelled',
  'unsupported',
  'already_registered',
  'no_credentials',
  'security',
  'network',
  'server',
  'invalid_response',
  'unknown',
];

export interface PasskeyErrorDetails {
  /** HTTP status of a `server` error. */
  status?: number;
  /** The server's own error code of a `server` error, such as `ceremony_expired`. */
  serverCode?: string;
  cause?: unknown;
}

export class PasskeyError extends Error {
  readonly code: PasskeyErrorCode;
  readonly status: number | undefined;
  readonly serverCode: string | undefined;

  constructor(code: PasskeyErrorCode, message: string, details: PasskeyErrorDetails = {}) {
    super(message, details.cause === undefined ? undefined : { cause: details.cause });
    this.name = 'PasskeyError';
    this.code = code;
    this.status = details.status;
    this.serverCode = details.serverCode;
  }
}

export function isPasskeyError(value: unknown): value is PasskeyError {
  return value instanceof PasskeyError;
}
