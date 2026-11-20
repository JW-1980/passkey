# Security notes

What the library guarantees, what it leaves to the application, and why.

## What the library does

| Property | How |
|---|---|
| Signature, challenge, origin, relying-party hash, flags | `web-auth/webauthn-lib` runs the WebAuthn verification steps; nothing of it is reimplemented here |
| User verification required | The options ask for it and the server refuses a response without the UV flag, at registration and at sign-in |
| Phishing resistance | Only exact, listed origins are accepted. Subdomains of a listed origin are **not** accepted unless listed |
| No account enumeration at sign-in | Sign-in is discoverable-only: no username goes to the server, and every failure answers `invalid_passkey` with the same text |
| Replay | A ceremony is deleted when it is read; a response for another challenge fails verification |
| Cross-purpose and cross-account use of a ceremony | The stored state carries its purpose and, for registration, the account; a mismatch answers `ceremony_expired` |
| Cloned authenticator | When the authenticator uses a signature counter, a value that does not increase is refused. The stored counter never decreases under concurrent sign-ins |
| Opaque user handle | The authenticator stores an HMAC-derived 32-byte handle, never the account ID or e-mail address |
| Server secrets at rest | The challenge table holds only the SHA-256 of ceremony IDs and handoff codes |
| Passkey table | Public keys only. A leak of this table does not let anyone sign in |
| Desktop handoff | Code only to `127.0.0.1`, bound to the app's PKCE challenge, single-use, 60 seconds; `state` checked in constant time by the app; the app's listener ignores anything that is not the exact callback |
| Abuse | Laravel routes are rate limited per address (default 30 per minute); at most 10 passkeys per account |

## What the application must decide

- **What a passkey sign-in is worth.** With user verification a passkey is possession plus
  biometric or PIN. Whether that replaces a second factor is a product decision. The Laravel bridge
  lets the application answer a verified sign-in itself (`passkey.login`), for example with
  "continue with the second factor".
- **Who may add a passkey.** The library requires a signed-in account. Whether a session that was
  opened with a password may add a passkey (and so reach passkey-level assurance) is the
  application's rule; enforce it with middleware on `register/*`.
- **Recovery.** A person who loses every passkey needs another way in. The library has none on purpose.
- **Removing the last passkey.** Allowed by the library; block it in the application if a passkey is
  the only way in.
- **Audit log.** The Laravel bridge dispatches `PasskeyRegistered`, `PasskeyAuthenticated`,
  `PasskeyDeleted` and `PasskeyRejected` (with the underlying reason). Write them to the audit log.
- **CSRF.** The browser routes change state on a cookie session. In Laravel they sit in the `web`
  group; elsewhere the application must check its own token (the example does).
- **The relying-party ID.** It is fixed when the first passkey is created. Changing the domain
  later invalidates every passkey.

## Known limits

- **Attestation is not verified.** The library asks for `none`. A deployment that must restrict
  which authenticator models are allowed needs attestation and the FIDO Metadata Service; that is
  not built.
- **The passkey limit is not atomic.** Two registrations finishing at the same instant can exceed
  the limit by one.
- **The loopback callback is plain HTTP on 127.0.0.1**, as RFC 8252 prescribes. Another program of
  the same user can read the code from the browser's request, which is why the code is useless
  without the verifier that never leaves the app.
- **A local program can end a pending desktop handoff** by calling the callback with a wrong
  `state`. The app then has to start again; nothing leaks.
