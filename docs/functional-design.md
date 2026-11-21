# Functional design: standard sign-in with Firebase Authentication and passkeys

Status: **design, partly built** (see §18 for what exists and what was executed). Written 21 November 2026.

This document describes one sign-in component for all our web properties and apps. It replaces the
idea of a passkey-only library with a **combination**: Firebase Authentication holds the identities
and offers the classic sign-in methods; this repository adds passkeys on top and makes every
platform end with the same thing, a Firebase session for one Firebase user.

Paths are relative to the root of this repository unless they start with `boekhouderv3/`.

---

## 1. Goal, scope and non-goals

**Goal.** One account per person across our properties (boekhouderv3, Nutricompare, welzolekker and
later ones), one set of sign-in methods, and the same behaviour in:

| Client | Runtime |
|---|---|
| Browser | Any modern browser, on any of our domains |
| Desktop app | Rust with Tauri 2 (Windows first; macOS and Linux follow from the same code) |
| Android app | Rust with Tauri 2 on Android (webview plus Kotlin helper) |
| Server-rendered PHP site | PHP 8.3+, with or without Laravel 12/13 |

and with these backends and databases:

| Backend | Databases |
|---|---|
| PHP (plain or Laravel) | MySQL 8.4, MariaDB 10.6+ / 11.8, SQLite 3 |
| Rust (for example a Tauri app's own local backend, or an Axum service) | not needed for verification; the passkey store lives in the PHP hub |

**In scope.**

1. Sign-in methods of Firebase Authentication: email and password, email link, Google, Apple,
   Microsoft and other providers that Firebase supports, with Firebase's own multi-factor
   authentication where enabled.
2. **Passkeys** (WebAuthn, discoverable, user verification required) as an extra sign-in method for
   an existing Firebase user, bridged to Firebase with **custom tokens**.
3. A **central auth hub**: one small PHP service per Firebase project that verifies passkeys, keeps
   the passkey store and mints custom tokens. It is the only place that holds the Firebase service
   account key.
4. **Verification of Firebase ID tokens** in PHP and in Rust, so that every backend can trust a
   sign-in without calling Google per request.
5. **Desktop sign-in** through the system browser (RFC 8252, PKCE), for every method, ending in a
   Firebase session inside the desktop app.
6. **Android sign-in**: passkeys through Credential Manager in the app; other methods through the
   system browser handoff.
7. A Firebase **REST client in Rust** (desktop and Android have no official Firebase SDK).
8. Optional **admin operations** (look up, revoke sessions, disable, delete) through the Identity
   Toolkit API.

**Non-goals.**

- Authorization. Roles, memberships and rights stay in each product. The component answers *who*
  someone is, never *what they may do*.
- One shared session across products. Each backend exchanges a Firebase ID token for **its own
  session** (§6.6). There is no single sign-out across products beyond revoking Firebase refresh
  tokens (§6.9).
- Migrating existing users from a product's own user table. That is a product task; §15 describes
  how boekhouderv3 does it.
- A passkey-only account without any Firebase method (open question Q3).
- Replacing Firebase's own MFA. Firebase TOTP or SMS MFA keeps working for classic methods.

## 2. Terms

| Term | Meaning |
|---|---|
| **Firebase user** | A user record in one Firebase project, identified by its `uid` (1 to 128 characters). The one identity of a person across our properties |
| **ID token** | A JWT that Firebase issues after a sign-in: RS256, one hour, audience = project ID. Proves who is signed in |
| **Refresh token** | Long-lived token with which a client obtains new ID tokens. Revocable per user |
| **Custom token** | A JWT that *we* sign with the service account key. A client exchanges it at Firebase for an ID token of the named `uid` |
| **Auth hub** | The PHP service of §4 that bridges passkeys to Firebase |
| **Relying party (RP)** | WebAuthn term: the domain the passkeys belong to (`rpId`) |
| **Property** | One of our products with its own backend and its own session |
| **Product session** | The session a property's backend gives after it verified an ID token |
| **Handoff** | Desktop/Android sign-in through the system browser with a loopback redirect and PKCE |
| **Recent sign-in** | An ID token whose `auth_time` is at most N seconds old (default 600) |

## 3. Decisions this design makes

| # | Decision | Why | Rejected alternatives |
|---|---|---|---|
| D1 | **Firebase Authentication is the identity store** for all properties of one brand family, in **one** Firebase project | One account per person; Firebase gives email, password, email link, social providers, MFA, email delivery and abuse protection without us operating them | Our own OIDC provider (Laravel Passport) — far more to build and operate; Auth0/Keycloak — not asked |
| D2 | **Passkeys are bridged with custom tokens** | Firebase Authentication has no passkey sign-in. A custom token is Firebase's supported way to sign in a user that *we* authenticated | Storing passkeys in Firebase user claims (no verification there); a second identity store for passkey users (two identities per person) |
| D3 | **Only the auth hub holds the service account key** | Whoever holds it can sign in as any user. One place, outside the web root, minimal code | Every property minting tokens (key on every server) |
| D4 | **Every backend verifies the ID token locally** (Google's public keys, cached) and gives **its own session** | No call to Google per request; each product keeps its own session length, cookies and rights; matches the existing rule "each service keeps its own session" in boekhouderv3 (ACCOUNT-8) | Sending the ID token with every API call (one-hour tokens, refresh logic in every client and every backend) |
| D5 | **One relying-party ID for all passkeys**, the registrable domain of the auth hub; other domains use **Related Origin Requests** (`/.well-known/webauthn`) or the hub's sign-in page | A passkey belongs to one domain; one `rpId` means one passkey per person for all properties | One `rpId` per property (one passkey per property, and the hub must know which store to use) |
| D6 | **Registering a passkey needs a recent Firebase sign-in** | A stolen ID token or a session left open must not be able to add a permanent passkey | No recency check |
| D7 | **A passkey sign-in counts as multi-factor**: the custom token carries `login_method: "passkey"`, and verifiers expose that | A passkey with user verification proves possession plus a biometric or PIN | Asking for Firebase MFA after a passkey (double work, and custom-token sign-ins skip Firebase MFA anyway) |
| D8 | **Desktop and Android use the system browser** for every non-passkey method (and desktop also for passkeys) | Google and Apple refuse OAuth in embedded webviews; a desktop webview does not run on our domain, so passkeys do not work there | Firebase JS SDK inside the webview (popups and redirects are blocked; passkeys impossible) |
| D9 | **Rust talks to Firebase through its REST API** | There is no official Firebase SDK for Rust; the REST API is public and documented | An unofficial crate (unmaintained or incomplete) |

## 4. Components

```
                     ┌──────────────────────────────── Firebase project ───────────────────────────────┐
                     │  Firebase Authentication: users, email/password, email link, Google, Apple,      │
                     │  MFA. Issues ID tokens + refresh tokens. Accepts our custom tokens.               │
                     └──────────▲──────────────────────────▲───────────────────────────▲────────────────┘
       signInWith… (SDK/REST)   │      signInWithCustomToken │                Identity Toolkit (admin)
                                │                            │                           │
 ┌──────────────┐   passkey   ┌─┴────────────────────────────┴──┐  service account key   │
 │ Browser /    │────────────▶│ Auth hub (PHP, packages/php)    │────────────────────────┘
 │ Tauri apps   │◀────────────│  - WebAuthn (webauthn-lib)       │
 │ (Firebase    │ custom token│  - passkey store (PDO / Laravel) │   MySQL / MariaDB / SQLite
 │  SDK or REST)│             │  - custom tokens, handoff        │
 └──────┬───────┘             └──────────────────────────────────┘
        │ ID token (once)
        ▼
 ┌──────────────────────┐   verifies with Google's public keys (cached), then its own session
 │ Property backends    │   PHP: packages/php Firebase\IdTokenVerifier
 │ (PHP, Laravel, Rust) │   Rust: packages/firebase (feature "verify")
 └──────────────────────┘
```

| Component | Path | Language | Role |
|---|---|---|---|
| Passkey core (existing) | `packages/php/src` | PHP | WebAuthn ceremonies, policy, PDO stores, handoff |
| Firebase bridge | `packages/php/src/Firebase` | PHP | Service account, custom tokens, ID token verification, admin client, the hub's request handler |
| Laravel bridge | `packages/php/src/Laravel` | PHP | Routes for the hub, a `firebase` guard for APIs |
| JS client (existing) + Firebase adapter | `packages/js/src`, `packages/js/src/firebase.ts` | TypeScript | Browser passkey flows that end in `signInWithCustomToken` |
| Desktop handoff (existing) | `packages/desktop` | Rust | Loopback listener and PKCE |
| Firebase for Rust | `packages/firebase` | Rust | REST client (custom token, refresh, password, IdP, lookup, delete), session refresh, ID token verifier, desktop sign-in |
| Android helper (existing) | `packages/android` | Kotlin | Credential Manager for passkeys in a Tauri/Capacitor webview |

## 5. Sign-in methods per platform

| Method | Browser | Desktop (Tauri) | Android (Tauri) | Plain PHP site |
|---|---|---|---|---|
| Email + password | Firebase JS SDK | system browser handoff (F4); REST `signInWithPassword` allowed as fallback | Firebase REST from Rust, or handoff | Firebase JS SDK on the page, then session exchange (F6) |
| Email link | Firebase JS SDK | handoff | handoff | JS SDK |
| Google / Apple / Microsoft | JS SDK popup or redirect | handoff | handoff (Custom Tab) | JS SDK |
| Firebase MFA (TOTP/SMS) | JS SDK | handoff | handoff | JS SDK |
| **Passkey** | WebAuthn on the page → hub → custom token (F3) | handoff, passkey used in the system browser | Credential Manager via Kotlin helper → hub → custom token (F5) | same as browser |

"Handoff" always ends in the same place: the desktop or Android app receives a **custom token** for
the uid that signed in in the browser and exchanges it at Firebase over REST. The app then holds its
own Firebase refresh token.

## 6. Flows

### 6.1 F1 — Sign up and sign in with a Firebase method

1. The client uses the Firebase SDK (browser) or the handoff (apps) to sign up or sign in.
2. Firebase returns an ID token and a refresh token.
3. The client calls its property's session exchange (F6).

Account creation, email verification, password reset and provider linking are Firebase features and
are configured in the Firebase console. The component does not reimplement them.

### 6.2 F2 — Add a passkey (signed in)

1. The client takes a **fresh** ID token (`getIdToken()`); if the user signed in more than 600
   seconds ago, the client first re-authenticates with Firebase (`reauthenticateWithCredential`,
   `reauthenticateWithPopup`, or a passkey sign-in, F3).
2. `POST {hub}/passkey/register/options` with `Authorization: Bearer <ID token>`.
3. The hub verifies the ID token (§7, SR-2), checks recency (SR-6), limits the number of passkeys
   (default 10) and answers WebAuthn creation options. The WebAuthn user is the Firebase uid
   (through an opaque handle), the name the email address (or the uid if there is none).
4. The client creates the passkey (browser API, Credential Manager) and posts the response to
   `register/verify` with the same bearer.
5. The hub verifies the registration and stores the passkey with `user_id = uid`.

### 6.3 F3 — Sign in with a passkey

1. `POST {hub}/passkey/login/options` (no bearer) → options with an empty `allowCredentials`
   (discoverable credential, no username).
2. The client asks the authenticator; the person confirms with biometrics or PIN.
3. `POST {hub}/passkey/login/verify` → the hub verifies the assertion, checks the counter, and
   answers `{ "firebase": { "customToken": "…" } }`. The custom token names the stored uid, lives at
   most one hour (default 300 seconds) and carries `login_method: "passkey"`.
4. The client calls `signInWithCustomToken` (SDK) or `accounts:signInWithCustomToken` (REST).
   Firebase returns an ID token for the **same** Firebase user that signed up with F1.
5. Session exchange (F6).

A disabled or deleted Firebase user cannot get a session: Firebase refuses the custom token sign-in
(`USER_DISABLED`), and the hub deletes the passkeys of a deleted user when told so (F10).

### 6.4 F4 — Desktop sign-in through the system browser

1. The desktop app starts a loopback listener on `127.0.0.1:<random port>` and creates a PKCE
   verifier and `state` (`packages/desktop`).
2. It opens the system browser on the hub's sign-in page (or a property page that embeds the same
   client) with `?challenge=…&port=…&state=…`.
3. On that page the person signs in with **any** method (F1 or F3) and sees what they approve
   ("Sign in to <app> on this computer").
4. On approval the page calls `POST {hub}/passkey/handoff/authorize` with the Firebase ID token as
   bearer. The hub verifies it, requires a recent sign-in (FR-4), records the uid and how the
   browser signed in, and answers the
   loopback address with a single-use code (60 seconds).
5. The browser goes to the loopback address; the app checks `state`.
6. The app calls `POST {hub}/passkey/handoff/exchange` with `{ code, code_verifier }`; the hub
   checks PKCE and answers `{ "firebase": { "customToken": "…" } }` with
   `login_method: "handoff"` and `login_via` = the browser's method (for example `password`,
   `google.com`, `passkey`), and `login_mfa` true when the browser session was multi-factor.
7. The app exchanges the custom token at Firebase over REST and stores the refresh token in the
   operating system's credential store (Windows Credential Manager, Keychain, Secret Service).
8. Session exchange with the app's backends (F6), if any.

### 6.5 F5 — Android

- **Passkey:** the webview page gets options from the hub and passes them over the Tauri bridge to
  the Kotlin helper (`packages/android`), which calls Credential Manager. The origin is
  `android:apk-key-hash:<hash>`, listed at the hub; the hub serves `assetlinks.json` on the `rpId`
  domain. Then as F3 step 3–5, with the custom token exchanged through Rust REST or the JS SDK
  (`signInWithCustomToken` works in a webview because it needs no popup).
- **Other methods:** as F4, with a Custom Tab instead of the desktop browser. The loopback redirect
  works on Android; an App Link redirect is an alternative (open question Q5).

### 6.6 F6 — Session exchange at a property

1. The client posts the ID token once to its property's backend, for example `POST /session` with
   `Authorization: Bearer <ID token>` (same-origin, with CSRF protection for cookie sessions).
2. The backend verifies it locally (§7: signature against Google's keys, `iss`, `aud`, `exp`, `iat`,
   `auth_time`, `sub`), optionally checks revocation (SR-9), looks up or creates its own user row
   linked to the uid, and starts **its own** session.
3. The backend decides by itself whether the sign-in is strong enough (for example a product that
   requires multi-factor accepts `login_method = passkey`, `login_mfa = true` or
   `firebase.sign_in_second_factor`, see SR-7).

### 6.7 F7 — Step-up

A sensitive action in a property may ask for a recent sign-in: the client re-authenticates (F3 or a
Firebase method), sends the new ID token, and the backend checks `auth_time`. The component offers
`isRecent(seconds)` on the verified identity.

### 6.8 F8 — Manage passkeys

`GET passkeys`, `PATCH passkeys/{id}` (rename) and `DELETE passkeys/{id}` at the hub, each with the
ID token as bearer. Delete requires a recent sign-in (SR-6). A user sees and changes only their own
passkeys.

### 6.9 F9 — Sign out and revoke

- Sign out in one property ends that property's session and, in the client, the Firebase session
  (`signOut()` or forgetting the refresh token).
- "Sign out everywhere" revokes the user's Firebase refresh tokens (admin client, `validSince`);
  backends that check revocation (SR-9) then refuse ID tokens issued before that time. Product
  sessions that already exist end only when the product checks again or expires them; each product
  documents its own session lifetime.

### 6.10 F10 — Delete an account

The product deletes its own data under its own rules (retention duties stay with the product), then
the Firebase user is deleted (client `user.delete()` after a recent sign-in, or the admin client),
and the hub deletes all passkeys of that uid (`deleteUser`). Passkeys stored on devices remain there
but can no longer sign in: their credential is unknown to the hub.

### 6.11 F11 — Lost passkey, recovery

Passkeys are an extra method. A person who loses all passkeys signs in with a Firebase method (F1),
including password reset by email, and can then add a new passkey (F2). The hub never resets
anything itself.

## 7. Functional requirements

| ID | Requirement |
|---|---|
| FR-1 | The hub offers the HTTP contract of `docs/protocol.md`, extended in §9, under a configurable base path (default `/passkey`) |
| FR-2 | `login/verify` answers a Firebase custom token for the uid of the passkey, and nothing else about the account |
| FR-3 | Registering, listing, renaming, deleting passkeys and authorizing a handoff accept only a valid Firebase ID token of the **same project** as bearer |
| FR-4 | Registering and deleting a passkey, and authorizing a desktop/Android handoff, require a recent sign-in (default 600 s, configurable 60–3600) |
| FR-5 | The custom token lifetime is configurable (60–3600 s, default 300) and carries the claims of §9.3 |
| FR-6 | The handoff exchange answers a custom token for the uid that authorized it, with the browser's method in the claims |
| FR-7 | PHP offers `IdTokenVerifier` that returns a `FirebaseIdentity` (uid, email, email verified, name, picture, sign-in provider, auth time, issue and expiry time, login method, multi-factor flag, all claims) or throws one exception type |
| FR-8 | Rust offers the same verifier (feature `verify`) with the same rules and the same result fields |
| FR-9 | Rust offers a Firebase REST client: sign in with custom token, with email and password, with an IdP credential; refresh; look up the signed-in user; send a password-reset email; delete the signed-in user |
| FR-10 | Rust offers a session holder that refreshes the ID token before it expires (default when less than 5 minutes remain) and reports a revoked or disabled user as signed out |
| FR-11 | Rust offers `desktop::sign_in`, which runs F4 end to end and returns a Firebase session |
| FR-12 | JS offers `createFirebasePasskeys`, which runs F2, F3, F8 and the browser side of F4 with a Firebase `Auth` object, without bundling the Firebase SDK itself |
| FR-13 | The hub's store runs on MySQL 8.4, MariaDB 10.6+/11.8 and SQLite through PDO, and in Laravel through its migrations; the schema is the existing one (`user_id` holds the uid) |
| FR-14 | The hub can delete all passkeys of a uid (account deletion) |
| FR-15 | The PHP admin client can look up a user, revoke refresh tokens, disable and enable, and delete a user |
| FR-16 | Every part works against the **Firebase Auth emulator** for development and tests, switched on explicitly (§11) |
| FR-17 | The hub serves `/.well-known/webauthn` (related origins), `assetlinks.json` and `apple-app-site-association` when configured |
| FR-18 | The hub answers CORS only for listed web origins, with no cookies (bearer tokens only) |

## 8. Security requirements

| ID | Requirement |
|---|---|
| SR-1 | The service account key is read from a file outside the web root or from an environment variable; it is never logged, never returned and never sent to a client |
| SR-2 | ID token verification checks: header `alg` = `RS256` and a `kid` of Google's current keys; signature; `iss` = `https://securetoken.google.com/<project>`; `aud` = `<project>`; `exp` in the future; `iat` and `auth_time` not in the future (60 s clock skew); `sub` non-empty and at most 128 characters; `uid` = `sub` |
| SR-3 | Google's keys are fetched over HTTPS and cached for the `max-age` of the response (never longer than 24 hours); an unknown `kid` causes at most one refetch per minute |
| SR-4 | Emulator mode (unsigned tokens) is only possible through an explicit constructor **and** only for project IDs that start with `demo-`, which cannot exist as real projects; production configuration cannot enable it by accident |
| SR-5 | Custom tokens are RS256, `iss` = `sub` = the service account email, `aud` = the Identity Toolkit audience, `exp − iat` ≤ 3600, `uid` 1–128 characters, no reserved claim names |
| SR-6 | Recent-sign-in checks use `auth_time` of the verified token, not `iat` (a refreshed token keeps the old `auth_time`) |
| SR-7 | `login_method`, `login_via` and `login_mfa` are trusted only when `firebase.sign_in_provider` = `custom`: only the hub can mint custom tokens, so only it can set them |
| SR-8 | All WebAuthn policy of `docs/security.md` stays: user verification required, discoverable credentials, single-use challenges bound to their purpose, counter check, origin allow-list |
| SR-9 | Revocation: a backend that needs it calls the admin lookup (or keeps `validSince` per uid) and refuses tokens with `auth_time` before `validSince`. Optional because it costs a call to Google |
| SR-10 | The hub rate-limits `login/options`, `login/verify` and `handoff/exchange` per IP (default 30 per minute) |
| SR-11 | Error answers never say whether an account or a passkey exists (`invalid_passkey` for every sign-in failure) |
| SR-12 | The bearer token is accepted only in the `Authorization` header, never in a query string or cookie |

## 9. HTTP contract (additions to `docs/protocol.md`)

### 9.1 Authentication of the hub's signed-in routes

`Authorization: Bearer <Firebase ID token>`. Missing or invalid: `401` with
`{"error":{"code":"unauthenticated",…}}`. Not recent enough where required: `403`
`{"error":{"code":"reauthentication_required",…}}`.

### 9.2 Answers that carry a custom token

`login/verify` and `handoff/exchange` answer `200`, `Cache-Control: no-store`:

```json
{ "firebase": { "customToken": "<JWT>", "expiresIn": 300 } }
```

### 9.3 Claims in the custom token

| Claim | Values | Meaning |
|---|---|---|
| `login_method` | `passkey`, `handoff` | How the hub authenticated this sign-in |
| `login_via` | the browser's `sign_in_provider` (`password`, `google.com`, `passkey`, …) | Only for `handoff` |
| `login_mfa` | `true` / `false` | `true` for a passkey, and for a handoff whose browser session was a passkey or Firebase MFA |

### 9.4 Account deletion (server to server)

Not an HTTP route: `FirebasePasskeys::deleteUser(uid)` in PHP, called by the property that deletes
the account, or by a listener on Firebase's user deletion (Firebase Extensions / Cloud Functions are
outside this repository).

## 10. Data

The existing tables (`packages/php/src/Storage/Schema.php` and the Laravel migration) stay as they
are. `passkeys.user_id` (`VARCHAR(191)`) holds the Firebase uid (at most 128 characters). No email
address or name is stored at the hub. Properties store the uid in their own user table.

## 11. Configuration

| Setting | Where | Default |
|---|---|---|
| Firebase project ID | hub, every verifier | — (required) |
| Firebase Web API key | clients only (not a secret: it identifies the project) | — |
| Service account JSON | hub only (file path or variable) | — (required at the hub) |
| Relying-party ID, name, origins, related origins | hub | from the application URL |
| Recent sign-in window | hub | 600 s |
| Custom token lifetime | hub | 300 s |
| Max passkeys per user | hub | 10 |
| Allowed CORS origins | hub | none |
| Emulator host (`FIREBASE_AUTH_EMULATOR_HOST`) | development only | unset |

## 12. Platform and database support

| Part | Supported | Tested in this repository (§18) |
|---|---|---|
| PHP 8.3+, plain | yes | yes |
| Laravel 12, 13 | yes | yes (13) |
| MySQL 8.4 | yes | no (not available on the test machine) |
| MariaDB 10.6+, 11.8 | yes | 11.8 in the earlier passkey run |
| SQLite | yes | yes |
| Rust desktop (Windows, macOS, Linux) | yes | Linux only |
| Rust on Android (Tauri 2) | yes (pure Rust, rustls) | no: no Android toolchain on the test machine (§18) |
| Browsers | Chromium, Firefox, Safari (Related Origin Requests: Chromium 128+ and Safari 18+; others use the hub page) | Chromium |

## 13. Failure behaviour

| Situation | Behaviour |
|---|---|
| Google's key endpoint unreachable, no cached keys | Verification fails closed (`unavailable`); the client shows "try again"; no sign-in |
| Google's key endpoint unreachable, keys cached | Cached keys are used until their `max-age` runs out |
| Firebase unreachable during `signInWithCustomToken` | The client shows a network error; the custom token expires unused (no state at the hub) |
| User disabled in Firebase | Firebase refuses the custom token (`USER_DISABLED`); the client shows "account disabled" |
| User deleted in Firebase but passkeys left at the hub | Firebase would create a **new** empty user for the uid on custom token sign-in; therefore the hub checks the user exists when `checkUserExists` is on (needs the admin client) and properties call `deleteUser` on deletion (F10) |
| Custom token expired before use | Firebase refuses (`INVALID_CUSTOM_TOKEN`); the client starts again |
| Refresh token revoked | Rust session holder reports signed out; JS SDK fires `onAuthStateChanged(null)` |
| Handoff code reused, expired or wrong verifier | `400 invalid_handoff`, code spent |
| Passkey cancelled by the person | `cancelled`, not reported as an error |
| Service account key missing or invalid at the hub | The hub refuses to start (configuration error), it never answers a sign-in without a token |

## 14. Privacy

Firebase Authentication stores email addresses, names, provider identities, IP addresses of sign-in
and sign-in times at Google. Firebase Authentication offers **no data residency** choice for user
records. Each product must therefore record this processing (processor agreement with Google, the
transfer basis, a DPIA where the product requires one) before going live. The hub itself stores no
personal data other than the uid and the passkey's public key, name and timestamps.

## 15. Integration in boekhouderv3

boekhouderv3 is the first product to use the component. Its own design, in Dutch, is
`boekhouderv3/docs/FIREBASE-INLOG-FO.md`, with the operator's decision in
`boekhouderv3/docs/BESLUITEN.md`. In short:

| boekhouderv3 part | Role |
|---|---|
| `server/backend` (Laravel 13) | Auth hub (Laravel bridge), behind a feature flag that is off by default |
| `server/chat` (Hub), `server/cloud` | Relying properties: verify the ID token, give their own session |
| `apps/web` (React) | Firebase JS SDK + `createFirebasePasskeys` |
| `apps/desktop` (Tauri) | `firebase` crate, `desktop::sign_in` |
| `apps/mobiel` (Tauri Android) | Kotlin passkey helper + `firebase` crate |

## 16. Tests

| Level | What | How |
|---|---|---|
| Unit (PHP) | Custom token format and signature; verifier accepts a correct token and refuses each broken claim, wrong key, wrong `alg`, `none` outside emulator mode, emulator mode for a non-`demo-` project; key cache and refetch limit; hub routes with and without bearer, recency, CORS | PHPUnit with generated RSA keys |
| Unit (Rust) | Same verifier rules; REST client against a local fake server; session refresh timing; desktop sign-in with a fake hub | `cargo test` |
| Unit (JS) | `createFirebasePasskeys` with a fake `fetch` and a fake `signInWithCustomToken` | Vitest |
| Integration | PHP custom token → Firebase Auth **emulator** → ID token for the same uid; admin client against the emulator; Rust REST client against the emulator | PHPUnit/`cargo test`, skipped with a message when no emulator runs |
| End to end | Chromium with a virtual authenticator: sign up with email and password (emulator), add a passkey, sign out, sign in with the passkey, same uid; desktop handoff with the Rust example ends in a Firebase session for the same uid | `node --test e2e/firebase.e2e.mjs` |

What the emulator cannot show: real RS256 ID tokens from Google (the emulator signs nothing). The
RS256 path is covered by unit tests with our own keys, and must be checked once against a real
project (§18).

## 17. Open questions (with recommendation)

| # | Question | Recommendation |
|---|---|---|
| Q1 | One Firebase project for all properties, or one per property? | **One** for properties that share users (D1); a separate project only for a property that must never share accounts |
| Q2 | Identity Platform (paid tier) for TOTP MFA, blocking functions and audit logs? | Yes for products that require MFA for some users (boekhouderv3 cloud); the free tier is enough otherwise |
| Q3 | Allow sign-up with only a passkey (no email)? | No for now: recovery then needs a second method; revisit when synced passkeys are common among our users |
| Q4 | Where does the hub run, and on which domain? | On the domain whose registrable part becomes the `rpId` (for example `login.<brand>.nl`, `rpId = <brand>.nl`) |
| Q5 | Android redirect: loopback or App Link? | Loopback first (same code as desktop); App Link when the Play policy or a device blocks it |
| Q6 | Check revocation on every session exchange? | Yes at session exchange (one lookup per sign-in, not per request) for products with money or personal data |

## 18. What exists and what was executed

The authoritative status, per part and with dates, is in [`status.md`](status.md). This design is
not evidence of anything; only that file reports executions.
