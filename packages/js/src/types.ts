/**
 * The JSON forms of WebAuthn options and responses (W3C WebAuthn Level 3, §5.1.9–§5.1.10): binary
 * fields are base64url strings. Only the fields this library reads are spelled out; everything
 * else passes through untouched.
 */
export interface CredentialDescriptorJSON {
  type: 'public-key';
  id: string;
  transports?: string[];
}

export interface CreationOptionsJSON {
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  timeout?: number;
  excludeCredentials?: CredentialDescriptorJSON[];
  authenticatorSelection?: Record<string, unknown>;
  attestation?: string;
  extensions?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface RequestOptionsJSON {
  challenge: string;
  rpId?: string;
  timeout?: number;
  allowCredentials?: CredentialDescriptorJSON[];
  userVerification?: string;
  extensions?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface RegistrationResponseJSON {
  id: string;
  rawId: string;
  type: 'public-key';
  response: { clientDataJSON: string; attestationObject: string; transports?: string[]; [key: string]: unknown };
  [key: string]: unknown;
}

export interface AuthenticationResponseJSON {
  id: string;
  rawId: string;
  type: 'public-key';
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string | null;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface GetOptions {
  /**
   * Offer passkeys in the autofill of an input with `autocomplete="username webauthn"` instead of
   * a modal prompt (conditional mediation). Browser only.
   */
  autofill?: boolean;
}

/**
 * The part that talks to the platform's passkey API. One implementation per platform:
 * `browserAuthenticator()` for the web, `bridgeAuthenticator()` for React Native and for webviews
 * that reach a native credential API through a bridge.
 */
export interface Authenticator {
  isSupported(): Promise<boolean>;
  /** Whether `get` with `autofill: true` can work here. */
  supportsAutofill(): Promise<boolean>;
  create(options: CreationOptionsJSON): Promise<RegistrationResponseJSON>;
  get(options: RequestOptionsJSON, getOptions?: GetOptions): Promise<AuthenticationResponseJSON>;
}

/** A stored passkey as the server describes it. Never contains key material. */
export interface PasskeySummary {
  /** The credential ID (base64url). */
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
  /** Whether the passkey can be synced to other devices (backup eligible). */
  synced: boolean;
  transports: string[];
}
