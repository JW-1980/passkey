# Status

What was executed, where, and what has never run. A result here describes the commit and the
machine it ran on; run `tools/verify.sh` for a current one.

## Executed on 20 November 2026

Machine: Linux x86-64 (cloud container), PHP 8.3.6, Node 22.23, Rust 1.97, JDK 21, headless Chromium.

| Part | What ran | Result |
|---|---|---|
| `packages/php` core | PHPUnit, 104 tests, on in-memory SQLite | passed |
| `packages/php` Laravel bridge | PHPUnit with Testbench 11 on **Laravel 13.43**, 18 tests, SQLite | passed |
| `packages/php` on Laravel 12 | The same 122 tests with **Laravel 12.73** and Testbench 10.12, SQLite | passed |
| `packages/php` on MariaDB | The same 122 tests on **MariaDB 11.8.9** (official binary, local server), core through PDO and Laravel 13 through the `mariadb` driver | passed |
| `packages/php` | PHPStan level 8 (2.1.x) over `src`, `config`, `routes`, `database`; Pint | no errors |
| `packages/php` | Nine deliberate defects (PKCE check removed, origin list widened, single-use removed, owner checks removed, …) | eight made tests fail; the ninth (auth middleware removed from the routes) is caught by a second check in the controller, so behaviour did not change |
| `packages/js` | TypeScript 5.9 strict, Vitest, 64 tests | passed |
| `packages/desktop` | `cargo test` (13 tests), clippy with `-D warnings`, rustfmt | passed, on Linux |
| `packages/android` | `gradle testDebugUnitTest assembleRelease` with AGP 8.13.2, Kotlin 2.4.21, compile SDK 36: 3 unit tests, release AAR built | passed |
| End to end | `e2e/passkey.e2e.mjs`: headless Chromium with a CDP virtual authenticator against the plain-PHP example, plus the Rust handoff example as the desktop app; 9 tests, run three times | passed |
| Installing | `composer install` of `jw-1980/passkey` into an empty project through a `path` repository | passed |

## Never executed

| What | Why it matters | To do |
|---|---|---|
| **A real authenticator** (Touch ID, Windows Hello, Android, a security key, a password manager) | Every passkey in the tests is software: a CDP virtual authenticator or the test's own ES256 key. RS256 (Windows Hello with a TPM) was never exercised | Register and sign in by hand on each target platform |
| **Android on a device or emulator** | `PasskeyBridge.create` and `get` compile, and the error mapping is unit-tested, but Credential Manager was never called. The association file and the `android:apk-key-hash` origin were only tested with a software authenticator | Run in an app signed with the listed certificate |
| **React Native / iOS** | `bridgeAuthenticator` is tested against the documented result and error shapes of `react-native-passkey` 3.6.2, not against the module on a device. There is no iOS code in this repository | Run in a development build on both platforms |
| **Windows and macOS desktop** | The Rust crate ran on Linux only. It uses the standard library's sockets, so it should behave the same, but that is not evidence | `cargo test` on Windows; one handoff by hand with the real browser |
| **Browsers other than Chromium** | Firefox and Safari were not run | Manual check, or Playwright with their engines (they have no virtual authenticator over CDP) |
| **MySQL 8.4** | Only MariaDB 11.8.9 and SQLite ran. The MySQL table definition avoids `CREATE INDEX IF NOT EXISTS`, which MySQL lacks, but was not executed there | Run the suite with the `PASSKEY_TEST_*` variables |
| **MariaDB 10.6 and 10.11** | Not run | Same |
| **Inside the three applications** | Nothing in boekhouderv3, Nutricompare or welzolekker was changed or run | See `docs/integration.md` |

## Open points

| Point | Severity | Status |
|---|---|---|
| The JavaScript and Android packages are not published to a registry; consumers install from a checkout | LOW | REPORTED |
| The passkey limit per account can be exceeded by one under two simultaneous registrations | LOW | REPORTED |
| No attestation verification (no restriction to authenticator models) | INFORMATIONAL | REPORTED |
| No Swift helper; iOS goes through `react-native-passkey` only | INFORMATIONAL | REPORTED |
| `packages/android` has no Gradle wrapper; it builds with a system Gradle 8.14 | LOW | REPORTED |
