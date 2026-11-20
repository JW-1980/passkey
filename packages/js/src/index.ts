export { createPasskeyClient, laravelCsrfHeaders } from './client.js';
export type { HandoffRequest, PasskeyClient, PasskeyClientOptions } from './client.js';
export { isPasskeyError, PASSKEY_ERROR_CODES, PasskeyError } from './errors.js';
export type { PasskeyErrorCode, PasskeyErrorDetails } from './errors.js';
export type {
  AuthenticationResponseJSON,
  Authenticator,
  CreationOptionsJSON,
  CredentialDescriptorJSON,
  GetOptions,
  PasskeySummary,
  RegistrationResponseJSON,
  RequestOptionsJSON,
} from './types.js';
