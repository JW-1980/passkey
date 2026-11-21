<?php

declare(strict_types=1);

use Jw1980\Passkey\Laravel\DefaultUserResolver;
use Jw1980\Passkey\Laravel\SessionLogin;

/** @return list<string> */
$list = static fn (?string $value): array => array_values(array_filter(array_map(trim(...), explode(',', (string) $value)), static fn (string $v): bool => $v !== ''));

return [

    /*
    | The relying party. `id` is the domain the passkeys belong to; passkeys created for it work on
    | that domain and its subdomains, and stop working when it changes. Left empty, the id is the
    | host of APP_URL, the name is APP_NAME and the only allowed origin is APP_URL.
    */
    'relying_party' => [
        'id' => env('PASSKEY_RP_ID'),
        'name' => env('PASSKEY_RP_NAME'),
        'origins' => $list(env('PASSKEY_ORIGINS')),
        /* https origins on other domains that may use these passkeys (served at /.well-known/webauthn). */
        'related_origins' => $list(env('PASSKEY_RELATED_ORIGINS')),
    ],

    /*
    | Secret (32 bytes or more) from which the opaque user handle of an account is derived. Left
    | empty, it is derived from APP_KEY.
    */
    'user_handle_secret' => env('PASSKEY_USER_HANDLE_SECRET'),

    /* Seconds a started registration or sign-in stays valid. */
    'ceremony_ttl' => 300,

    'max_passkeys' => 10,

    /* Database connection (null: the default) and table names, without the connection's prefix. */
    'connection' => null,
    'tables' => [
        'passkeys' => 'passkeys',
        'challenges' => 'passkey_challenges',
    ],

    /* Auth guard for the signed-in account (null: the default guard). */
    'guard' => null,

    'routes' => [
        'enabled' => true,
        'prefix' => 'passkey',
        /* For every route. A token API uses ['api'] here and ['auth:sanctum'] below. */
        'middleware' => ['web'],
        /* Added for registering and managing passkeys and for approving a handoff. */
        'auth_middleware' => ['auth'],
    ],

    /* Requests per minute per address on every passkey route. */
    'rate_limit' => 30,

    /* Turns the signed-in account into what the passkey prompt shows. */
    'user_resolver' => DefaultUserResolver::class,

    /*
    | What happens after a verified passkey sign-in. The default signs the account in on the session
    | guard. Replace it to issue a token, or to continue with a second factor.
    */
    'login' => SessionLogin::class,

    /*
    | Native Android app: its package name and the SHA-256 fingerprints of its signing certificates
    | (comma separated). Serves /.well-known/assetlinks.json and allows the app's origin.
    */
    'android' => [
        'package' => env('PASSKEY_ANDROID_PACKAGE'),
        'fingerprints' => $list(env('PASSKEY_ANDROID_FINGERPRINTS')),
    ],

    /* Native iOS apps as <Team ID>.<bundle id> (comma separated). Serves the association file. */
    'apple' => [
        'app_ids' => $list(env('PASSKEY_APPLE_APP_IDS')),
    ],

    /*
    | Desktop sign-in through the system browser. Needs a `completer` (a class implementing
    | Jw1980\Passkey\Laravel\Contracts\CompletesHandoff) that issues the desktop app's session.
    */
    'handoff' => [
        'enabled' => false,
        'completer' => null,
        'callback_path' => '/callback',
        'code_ttl' => 60,
        /* The exchange is called by the desktop app itself: no cookie session, no CSRF token. */
        'exchange_middleware' => [],
    ],

    /*
    | Firebase mode: this application is the auth hub of docs/functional-design.md. Signed-in routes
    | take a Firebase ID token as bearer token (no session), a passkey sign-in and the desktop
    | handoff answer a Firebase custom token, and the session routes above are not registered.
    |
    | `credentials` is the path of the service account JSON (outside the web root). With
    | `emulator_host` (host:port of the Firebase Auth emulator) and a "demo-" project, no credentials
    | are needed and unsigned emulator tokens are accepted; that combination cannot reach production.
    */
    'firebase' => [
        'enabled' => (bool) env('PASSKEY_FIREBASE', false),
        'project_id' => env('FIREBASE_PROJECT_ID'),
        'credentials' => env('FIREBASE_CREDENTIALS'),
        'emulator_host' => env('FIREBASE_AUTH_EMULATOR_HOST'),
        'recent_sign_in' => 600,
        'custom_token_ttl' => 300,
        /* Web origins whose pages may call the hub (CORS, without cookies). */
        'cors_origins' => $list(env('PASSKEY_CORS_ORIGINS')),
        /* Ask Firebase whether the user still exists before minting a token (needs credentials). */
        'check_user_exists' => true,
        /* Where Google's public keys are cached between requests (null: per process only). */
        'key_cache' => env('FIREBASE_KEY_CACHE'),
        'middleware' => [],
    ],
];
