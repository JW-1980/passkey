# Integration

How to add the library to an application, per part, followed by notes for the three products it
was written for.

## 1. Installing from this repository

The packages are not published to a registry.

**PHP** — add the repository to the application's `composer.json` and require the package:

```json
{
  "repositories": [
    { "type": "vcs", "url": "https://github.com/JW-1980/passkey" }
  ]
}
```

The Composer manifest sits at the root of this repository, so the `vcs` form works; for a local
checkout use `{ "type": "path", "url": "../passkey" }`. Then `composer require jw-1980/passkey:^0.1`
(the first stable tag is **`v0.1.0`** on `main`; Composer reads the tag through the `vcs` repository).
To follow unreleased work, require `dev-main` instead of a version.

**JavaScript** — `npm install ../passkey/packages/js` (run `npm run build` there first), or add it
as a workspace package.

**Rust** — `passkey-desktop = { git = "https://github.com/JW-1980/passkey" }` or a `path` dependency.

**Android** — include `packages/android` as a Gradle module (`includeBuild` or a copied module).

## 2. Server

### Laravel

1. Require the package and run `php artisan migrate` (tables `passkeys` and `passkey_challenges`).
2. Check `APP_URL`: its host becomes the relying-party ID. Set `PASSKEY_RP_ID` when the passkeys
   should belong to a parent domain (`example.com` for an app on `app.example.com`), and then list
   every origin in `PASSKEY_ORIGINS`.
3. Set `PASSKEY_USER_HANDLE_SECRET` to 32 or more random bytes. Without it the secret is derived
   from `APP_KEY`.
4. The routes appear under `/passkey` in the `web` group with the `auth` middleware where needed.
   For a token API set `passkey.routes.middleware` to `['api']`, `auth_middleware` to
   `['auth:sanctum']` and `passkey.login` to a class that issues the token.

What a verified sign-in leads to is one class:

```php
final class ContinueWithSecondFactor implements \Jw1980\Passkey\Laravel\Contracts\CompletesLogin
{
    public function complete(Request $request, AuthenticationResult $result): array
    {
        $request->session()->put('login.pending_user', $result->userId);

        return ['next' => 'second_factor'];
    }
}
```

Listen to `PasskeyRegistered`, `PasskeyAuthenticated`, `PasskeyDeleted` and `PasskeyRejected` for
the audit log.

### PHP without a framework

See [`examples/plain-php/public/index.php`](../examples/plain-php/public/index.php): the whole
server side in one file, including the CSRF check and session handling the application owns.

## 3. Browser

Build the page so that passkey support is checked before a button is shown:

```ts
if (await passkeys.isSupported()) { showPasskeyButton(); }
```

For passkeys in the username field's autofill, give the input `autocomplete="username webauthn"`
and call `passkeys.signIn({ autofill: true })` when the page loads (check `supportsAutofill()`).

## 4. Android

**Server.** Set `PASSKEY_ANDROID_PACKAGE` and `PASSKEY_ANDROID_FINGERPRINTS` (the SHA-256
fingerprints of every signing certificate, including Play App Signing's). The Laravel bridge then
serves `/.well-known/assetlinks.json` and accepts the app's `android:apk-key-hash:…` origin.
Without Laravel: `WellKnown::assetLinks()` and `WellKnown::androidOrigin()`.

**React Native.** Use `react-native-passkey` with `bridgeAuthenticator(Passkey)`; nothing from
`packages/android` is needed.

**Webview app (Tauri, Capacitor).** Expose two bridge commands that call `PasskeyBridge`:

```kotlin
private val passkeys = PasskeyBridge()

suspend fun create(requestJson: String): String = passkeys.create(activity, requestJson)
suspend fun get(requestJson: String): String = passkeys.get(activity, requestJson)
// On PasskeyBridgeException: reject with an object { code, message }.
```

```ts
const authenticator = bridgeAuthenticator({
  isSupported: () => true,                                   // the module needs Android 9+
  create: (options) => invoke('passkey_create', { requestJson: JSON.stringify(options) }),
  get: (options) => invoke('passkey_get', { requestJson: JSON.stringify(options) }),
});
```

## 5. iOS

Set `PASSKEY_APPLE_APP_IDS` (`<Team ID>.<bundle id>`), add the `webcredentials:<domain>` associated
domain to the app, and use `react-native-passkey`. iOS sends the site's `https://` origin, so the
server needs no extra origin. There is no Swift helper in this repository.

## 6. Desktop

1. Server: set `passkey.handoff.enabled` and `passkey.handoff.completer` to a class implementing
   `CompletesHandoff`. `approve()` runs when the browser asks for a code (refuse there when the
   browser session is too weak); `complete()` issues the desktop session at the exchange.
2. Web: a page (for example `/desktop-sign-in`) that requires sign-in, shows who is signing in to
   the desktop app, and calls `authorizeHandoff(readHandoffRequest(location.href))` on approval.
3. Desktop: `passkey_desktop::Handoff` as in the README; open the URL with the shell's opener and
   post the grant with the app's own HTTP client. Keep the resulting session in memory or in the
   operating system's credential store.

---

## Notes per product

These notes describe what adopting the library means in each repository as it stood on
20 November 2026. Nothing in those repositories was changed.

### boekhouderv3

- **It already has passkey code.** `server/backend` (Fortify passkeys), `server/relay`
  (`web-auth/webauthn-lib`, being phased out under RELAY-UIT-1), the Rust reference cloud API
  (`webauthn-rs`) and the web client. The open gap is passkey sign-in in the PHP cloud API
  `server/cloud` and, if wanted, in the Android companion.
- **Adopting it is an operator decision.** A new dependency in the sign-in code needs a decision in
  `docs/BESLUITEN.md` and a sceptical review (CLAUDE.md §0.7 D4 and §0.9 point 7).
- **Existing decisions the integration must implement itself**, because they are product rules:
  the second factor stays mandatory after a passkey (TOEGANG-4; use a `CompletesLogin` that
  continues with TOTP), a passkey may only be added from a passkey session or an enrolment link
  (PK-11; middleware on `register/*`), the sign-in proof of LOGIN-1 (PK-7), and the limits of PK-12
  (the library's defaults match "at most 10 passkeys"; the request limits differ).
- **Dutch interface (I10).** The library's messages are English. Show Dutch text per error `code`
  and never the server's `message`.
- **Desktop.** `apps/desktop/src-tauri/src/cloud_aanmelden.rs` already implements the same
  system-browser flow (DESKTOP-LOGIN-2) with the parameter `poort` and the path `/terug`.
  `passkey-desktop` uses `port` and a configurable callback path. Replacing tested code is not
  needed; the crate is for a new integration.
- **Mobile.** The companion app pairs with a QR code and has no account sign-in of its own.
  A passkey sign-in on the phone is not covered by MOB-1 or MOB-5 and needs a decision first.
- **Database.** Production is MariaDB 11.8; see `docs/status.md` for what was run on it.

### Nutricompare

- Laravel 12 with Inertia and Vue: the Laravel bridge and the browser client fit as they are.
  Use `laravelCsrfHeaders()`.
- Require the stable tag: `jw-1980/passkey:^0.1` (tag `v0.1.0` on `main`), with the `vcs` repository
  from §1. Do not require the old branch `dev-ccr-bec2376c-lyaxky`.
- Its standard forbids SQLite as evidence and also requires MySQL 8.4. Run the PHP suite against
  MariaDB 11.8 **and** MySQL 8.4 with the `PASSKEY_TEST_*` variables before reporting it as working
  there; `docs/status.md` says what was run (MySQL 8.4 not yet).
- Its `composer.json` requires PHP `^8.3`; the package supports PHP 8.3 and newer.

### welzolekker

- Laravel 13 with Blade: the Laravel bridge fits; load the browser client from the Vite bundle.
- Require the stable tag: `jw-1980/passkey:^0.1` (tag `v0.1.0` on `main`), with the `vcs` repository
  from §1. Do not require the old branch `dev-ccr-bec2376c-lyaxky`.
- The React Native app (Expo 58): add `react-native-passkey` (it needs a development build, not
  Expo Go) and use `bridgeAuthenticator(Passkey)`. The API routes need a token guard
  (`passkey.routes.middleware` and `passkey.login`), which the application must supply.
- Its `composer.json` requires PHP `^8.4.1`; the package supports PHP 8.3 and newer.
- Its guidelines say dependencies are not changed without approval: adding the package is the
  owner's call.
