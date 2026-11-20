# passkey

Passkey (WebAuthn) sign-in for a product with a backend, a browser app, a mobile app and a desktop
app. One server package, one client package and two small native helpers, all speaking the same
HTTP contract.

| Part | Path | For | Built on |
|---|---|---|---|
| Server | [`packages/php`](packages/php) | PHP 8.3+, with or without Laravel 12/13 | `web-auth/webauthn-lib` 5.3 |
| Client | [`packages/js`](packages/js) | Browser, React Native, bridged webviews | `@simplewebauthn/browser` 14 |
| Android helper | [`packages/android`](packages/android) | Webview apps on Android (Tauri, Capacitor) | AndroidX Credential Manager 1.6 |
| Desktop helper | [`packages/desktop`](packages/desktop) | Desktop apps (Tauri or any Rust) | std, `sha2`, `base64`, `getrandom` |

WebAuthn verification is done by maintained libraries; this repository adds the policy, the state
(challenges, stored passkeys), the HTTP contract and the glue per platform.

## How each platform signs in

- **Browser.** The page calls the browser's own passkey API on the site's origin.
- **React Native.** The app calls the platform passkey API through
  [`react-native-passkey`](https://github.com/f-23/react-native-passkey); the client wraps it.
- **Webview app on Android.** The page hands the server's options over the app's bridge to the
  Android helper, which calls Credential Manager.
- **Desktop.** A passkey belongs to a web domain, and a desktop webview does not run on that domain.
  The app opens the **system browser** on a page of the site, the person signs in there with the
  passkey, and the app receives a single-use code on a loopback address, protected with PKCE
  (RFC 8252 and RFC 7636).

Native apps must be associated with the domain; the server package builds the association files
(`/.well-known/assetlinks.json`, `/.well-known/apple-app-site-association`).

## Policy (fixed, not configurable)

- User verification is **required**: a passkey proves possession plus a biometric or PIN.
- Passkeys are **discoverable**: sign-in needs no username, and the server never says whether an
  account exists.
- No attestation is requested; ES256 and RS256 are accepted.
- Challenges are random, single-use, bound to their purpose and expire (default 5 minutes).
- A signature counter that does not increase is refused (cloned authenticator).
- Only listed origins are accepted: `https://` on the relying-party domain, `http://localhost` for
  development, and `android:apk-key-hash:…` for a listed Android app.

Details and the reasons: [`docs/security.md`](docs/security.md).

## Quick start

### Laravel

```bash
composer require jw-1980/passkey      # from this repository, see docs/integration.md
php artisan migrate
```

The service provider is discovered automatically. It registers the routes under `/passkey` (web
middleware, session guard) and uses `APP_URL` and `APP_NAME` for the relying party. Publish the
config with `php artisan vendor:publish --tag=passkey-config`.

### PHP without a framework

```php
use Jw1980\Passkey\{PasskeyServer, PasskeyUser, RelyingParty};
use Jw1980\Passkey\Storage\{PdoChallengeStore, PdoCredentialStore, Schema};

foreach (Schema::statements('mysql') as $sql) { $pdo->exec($sql); }   // once

$passkeys = new PasskeyServer(
    RelyingParty::forUrl('https://app.example', 'Example App'),
    new PdoCredentialStore($pdo),
    new PdoChallengeStore($pdo),
    $userHandleSecret,                       // 32+ random bytes, kept on the server
);

$ceremony = $passkeys->beginRegistration(new PasskeyUser($id, $email, $name));   // → JSON to the client
$passkey  = $passkeys->finishRegistration($ceremonyId, $credential, $user, 'Laptop');

$ceremony = $passkeys->beginAuthentication();
$result   = $passkeys->finishAuthentication($ceremonyId, $credential);           // $result->userId
```

A complete working application: [`examples/plain-php`](examples/plain-php).

### Browser

```ts
import { createPasskeyClient, laravelCsrfHeaders, isPasskeyError } from '@jw-1980/passkey';
import { browserAuthenticator } from '@jw-1980/passkey/browser';

const passkeys = createPasskeyClient({
  baseUrl: '/passkey',
  authenticator: browserAuthenticator(),
  headers: laravelCsrfHeaders(),
});

await passkeys.register({ name: 'Laptop' });   // signed-in account adds a passkey
await passkeys.signIn();                        // resolves with the server's answer
```

Errors are `PasskeyError`s with a `code` (`cancelled`, `unsupported`, `already_registered`,
`no_credentials`, `security`, `network`, `server`, `invalid_response`, `unknown`). Show your own
text per code; `cancelled` is not an error to report.

### React Native

```ts
import { Passkey } from 'react-native-passkey';
import { createPasskeyClient } from '@jw-1980/passkey';
import { bridgeAuthenticator } from '@jw-1980/passkey/bridge';

const passkeys = createPasskeyClient({
  baseUrl: 'https://app.example/passkey',
  authenticator: bridgeAuthenticator(Passkey),
  credentials: 'omit',
  headers: () => ({ Authorization: `Bearer ${token}` }),
});
```

### Desktop (Rust)

```rust
let handoff = passkey_desktop::Handoff::start(Default::default())?;
open_in_system_browser(&handoff.authorize_url("https://app.example/desktop-sign-in"));
let grant = handoff.wait()?;            // blocks; cancel with handoff.cancel_handle()
// POST { code, code_verifier } to https://app.example/passkey/handoff/exchange
```

Per-platform steps, including Android and the association files: [`docs/integration.md`](docs/integration.md).
The HTTP contract: [`docs/protocol.md`](docs/protocol.md).

## Verifying

```bash
tools/verify.sh
```

runs every check that the machine has the tools for and says which ones it skipped. What it runs:

| Check | Command |
|---|---|
| PHP dependencies | `composer install` at the repository root (installs into `packages/php/vendor`) |
| PHP tests | `cd packages/php && vendor/bin/phpunit` |
| PHP static analysis, level 8 | `vendor/bin/phpstan analyse` |
| PHP style | `vendor/bin/pint --test` |
| JS types and tests | `cd packages/js && npm run typecheck && npm test` |
| Rust | `cd packages/desktop && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test` |
| Android | `cd packages/android && gradle testDebugUnitTest assembleRelease` (needs an Android SDK) |
| End to end | `node --test e2e/passkey.e2e.mjs` (PHP, Chromium via Playwright, the Rust example) |

The PHP tests use in-memory SQLite by default. To run them on MySQL or MariaDB, set
`PASSKEY_TEST_DSN`, `PASSKEY_TEST_USER`, `PASSKEY_TEST_PASSWORD` (core) and `PASSKEY_TEST_DB_DRIVER`,
`PASSKEY_TEST_DB_HOST`, `PASSKEY_TEST_DB_PORT`, `PASSKEY_TEST_DB_DATABASE`, `PASSKEY_TEST_DB_USER`,
`PASSKEY_TEST_DB_PASSWORD` (Laravel) to a **throwaway** database: its tables are dropped.

## What is and is not verified

See [`docs/status.md`](docs/status.md): it lists, per part, what was executed and what has never
run on a real device.
