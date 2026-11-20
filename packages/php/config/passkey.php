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

];
