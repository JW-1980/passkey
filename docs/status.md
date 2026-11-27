# Status

What was executed, where, and what has never run. A result here describes the commit and the
machine it ran on; run `tools/verify.sh` for a current one.

## Version

The first stable tag is **`v0.1.0`** (26 November 2026) on `main`; **`v0.1.1`** (27 November
2026) adds the Windows fixes below. The checks below were run on 20 and 21 November 2026 on Linux;
the PHP suite, PHPStan and the JavaScript and Rust checks were repeated on Windows x64 on 26 and
27 November 2026.

## Executed on 27 November 2026 (before v0.1.1)

Machine: Windows x64, PHP 8.5.3, Node 24.14.0.

| Part | What ran | Result |
|---|---|---|
| `packages/php` | PHPUnit, all suites: 202 tests, 863 assertions, SQLite; 3 skipped: 2 emulator tests (`FIREBASE_AUTH_EMULATOR_HOST` not set) and 1 `FileKeyCache` permission test (see below) | passed |
| `packages/php` | PHPStan level 8 (2.3.7) over `src`, `config`, `routes`, `database` | no errors |
| `packages/php` | Pint (1.32.3) `--test` | **clean**: `.gitattributes` forces LF on checkout, so the line-ending difference is gone |

The JavaScript, Rust and end-to-end checks were not repeated in this round; their 26 November results
below still describe the tree before `v0.1.1`, except for `FileKeyCache` and `.gitattributes`.

## Executed on 26 November 2026 (before v0.1.0)

Machine: Windows x64, PHP 8.5.3, Node 24.14.0, Rust 1.97.1. Same tree as the tag.

| Part | What ran | Result |
|---|---|---|
| `packages/php` | PHPUnit, all suites: 202 tests, 855 assertions, SQLite; 5 skipped: 2 emulator tests (`FIREBASE_AUTH_EMULATOR_HOST` not set) and 3 `FileKeyCache` tests (see below) | passed |
| `packages/php` | PHPStan level 8 (2.3.7) over `src`, `config`, `routes`, `database` | no errors |
| `packages/php` | Pint (1.32.3) `--test` | **not clean on Windows**: the checkout uses CRLF (`core.autocrlf=true`), so Pint reports `line_ending` for almost every file, plus a few brace rules on anonymous classes; the committed blobs are LF. Not reformatted, so the tag's diff stays about the version |
| `packages/js` | TypeScript 5.9 strict, Vitest, 74 tests, build | passed |
| `packages/desktop` | `cargo fmt --check`, clippy with `-D warnings`, `cargo test` (13 tests) | passed, on Windows |
| `packages/firebase` | `cargo fmt --check`, clippy with `--all-features -D warnings`, `cargo test --all-features` (21 tests) | passed, on Windows |
| Android and both end-to-end suites | Not repeated on Windows (no Android SDK; Playwright and the Firebase emulator not installed in this checkout) | not run |

**Windows and `FileKeyCache`.** `fileperms()` on Windows reports `0666` for every file, so the
group/other check would reject every cache file. Since `v0.1.1` the cache accepts a regular file on
Windows and leaves the access control to the directory's ACLs (the class comment says the caller must
choose a directory only the application's user can write). The two sharing/refetch tests now run on
Windows. The test that proves a file writable by group or others is ignored still skips on Windows:
there are no POSIX mode bits to chmod, and the ACL variant is not covered. That is one skip, not
three; the test does not pretend the POSIX check ran.

## Executed on 21 November 2026 (Firebase)

Machine: Linux x86-64 (cloud container), PHP 8.3.6, Node 22.23, Rust 1.97, headless Chromium,
Firebase Auth emulator from `firebase-tools` 15.37.0 (project `demo-boekhouder`).

| Part | What ran | Result |
|---|---|---|
| `packages/php` | PHPUnit, all suites: 196 tests (core, Firebase, Laravel 13.43 with Testbench 11), SQLite; with `FIREBASE_AUTH_EMULATOR_HOST` all 196 ran, without it the 2 emulator tests skip | passed |
| `packages/php` | `EmulatorTest` with `FIREBASE_AUTH_EMULATOR_HOST`: our RS256 custom token accepted by the emulator, ID token for the same uid, claims kept after a refresh; admin lookup, disable, revoke and delete | passed |
| `packages/php` | PHPStan 2.1.33 level 8 (phar, see below), Pint | no errors |
| `packages/js` | TypeScript strict, Vitest: 74 tests (10 new for the Firebase adapter) | passed |
| `packages/firebase` | `cargo test --all-features`: 19 tests (REST client, session manager, verifier with RS256 and a JWKS server, hub client, desktop sign-in with a fake hub) including 2 against the emulator; clippy `-D warnings`; rustfmt | passed, on Linux |
| `packages/desktop` | `cargo test` (13 tests) | passed |
| End to end | `e2e/firebase.e2e.mjs`: Chromium with a virtual authenticator, Firebase JS SDK 12 against the emulator, the PHP hub of `examples/firebase-hub`, the Rust `desktop_sign_in` example; 4 tests | passed |
| End to end | `e2e/passkey.e2e.mjs` (the passkey-only mode), 9 tests | passed |

**Security review (21 November).** A separate read-only reviewer found no token verification bypass
and seven points. Resolved: the handoff reset the sign-in time (HIGH; now `login_auth_time`), the
refetch limit for Google's keys did not hold across PHP-FPM requests (MEDIUM; now in the shared cache,
the Laravel default is the cache store), unknown middleware options were ignored (LOW), the Rust key
cache held its lock during the fetch and had no limit after expiry (LOW), the key cache file was
trusted unconditionally (LOW), the Rust hub URL check was a string prefix (LOW), time arithmetic could
overflow in Rust and `PdoRateLimiter` hid database errors as 429 (INFORMATIONAL). Reported, not
solved: ID tokens seen by a property backend can be replayed at the hub within the recent-sign-in
window (functional design §8, Q7). After the fixes: PHPUnit 201 tests (6 with the emulator), Rust 21
tests, the 4 Firebase end-to-end tests, PHPStan level 8 and Pint all passed.

Not executed on 21 November: MariaDB and MySQL (no server on the machine), Android (no SDK or NDK:
`packages/firebase` was not compiled for an Android target), a real Firebase project (no
credentials: the RS256 verification of real Google ID tokens is covered by unit tests with our own
keys only), Laravel 12. PHPStan was installed as the phar of the `phpstan/phpstan` 2.1.33 git tag,
because Composer could not download the dist archive through the proxy of the machine.

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
| **A real Firebase project** | Only the emulator ran. The emulator signs nothing, so verifying Google's RS256 ID tokens with Google's live keys never ran | Create a project, set the service account, sign in once on each platform |
| **`packages/firebase` on Android** | Not compiled for `aarch64-linux-android` | `cargo check --target aarch64-linux-android --features desktop` with the NDK, then inside the Tauri app |
| **Inside the three applications** | boekhouderv3 got a design and server code (see its `docs/FIREBASE-INLOG-FO.md`); Nutricompare and welzolekker were not changed | See `docs/integration.md` |

## Open points

| Point | Severity | Status |
|---|---|---|
| The JavaScript and Android packages are not published to a registry; consumers install from a checkout | LOW | REPORTED |
| The passkey limit per account can be exceeded by one under two simultaneous registrations | LOW | REPORTED |
| No attestation verification (no restriction to authenticator models) | INFORMATIONAL | REPORTED |
| No Swift helper; iOS goes through `react-native-passkey` only | INFORMATIONAL | REPORTED |
| `packages/android` has no Gradle wrapper; it builds with a system Gradle 8.14 | LOW | REPORTED |
