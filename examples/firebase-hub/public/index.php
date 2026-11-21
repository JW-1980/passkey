<?php

declare(strict_types=1);

/*
 * Example: the auth hub with Firebase Authentication, against the Firebase Auth emulator.
 *
 *   firebase emulators:start --only auth --project demo-passkey-test     (in another terminal)
 *   FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099 php -S localhost:8766 examples/firebase-hub/public/index.php
 *
 * One process plays two roles to keep the example small:
 * - the auth hub (`/passkey/*`): passkeys for Firebase users, answering custom tokens;
 * - a property backend (`/session`): exchanges a Firebase ID token for its own PHP session.
 *
 * Production differs only in configuration: a real project ID, the service account file instead
 * of ServiceAccount::forEmulator(), IdTokenVerifier::forProject() instead of forEmulator().
 */

use Jw1980\Passkey\Firebase\AdminClient;
use Jw1980\Passkey\Firebase\CustomTokenIssuer;
use Jw1980\Passkey\Firebase\FirebaseException;
use Jw1980\Passkey\Firebase\FirebasePasskeys;
use Jw1980\Passkey\Firebase\Http\AuthHub;
use Jw1980\Passkey\Firebase\Http\HubRequest;
use Jw1980\Passkey\Firebase\IdTokenVerifier;
use Jw1980\Passkey\Firebase\ServiceAccount;
use Jw1980\Passkey\Handoff\HandoffServer;
use Jw1980\Passkey\PasskeyServer;
use Jw1980\Passkey\RelyingParty;
use Jw1980\Passkey\Storage\PdoChallengeStore;
use Jw1980\Passkey\Storage\PdoCredentialStore;
use Jw1980\Passkey\Storage\PdoRateLimiter;
use Jw1980\Passkey\Storage\Schema;

require __DIR__.'/../../../packages/php/vendor/autoload.php';

$path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

$origin = getenv('HUB_ORIGIN') ?: 'http://localhost:8766';
$project = getenv('FIREBASE_PROJECT_ID') ?: 'demo-passkey-test';
$emulator = getenv('FIREBASE_AUTH_EMULATOR_HOST') ?: '';
$database = getenv('HUB_DB') ?: sys_get_temp_dir().'/firebase-hub-example.sqlite';

if ($emulator === '') {
    http_response_code(500);
    echo 'This example runs against the Firebase Auth emulator: set FIREBASE_AUTH_EMULATOR_HOST.';

    return;
}

if ($method === 'GET' && ($path === '/' || $path === '/desktop')) {
    header('Content-Type: text/html; charset=utf-8');
    $config = htmlspecialchars((string) json_encode(['projectId' => $project, 'emulator' => 'http://'.$emulator, 'hub' => '/passkey']), ENT_QUOTES);
    echo <<<HTML
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign-in example</title>
<style>body{font:16px system-ui;margin:2rem;max-width:40rem}button,input{font:inherit;margin:.25rem 0;padding:.4rem}#status{padding:.5rem;background:#eef}</style></head>
<body data-config="{$config}">
<h1>Sign-in example</h1>
<p id="status">Loading…</p>
<section id="desktop" hidden><p>An app on this computer asks to sign in as you.</p><button id="approve">Approve</button> <button id="deny">Deny</button></section>
<section id="signed-out">
  <input id="email" type="email" placeholder="Email" autocomplete="username webauthn">
  <input id="password" type="password" placeholder="Password" autocomplete="current-password">
  <button id="sign-up">Create account</button> <button id="sign-in">Sign in</button>
  <button id="passkey-sign-in">Sign in with a passkey</button>
</section>
<section id="signed-in" hidden>
  <button id="add-passkey">Add a passkey</button> <button id="sign-out">Sign out</button>
  <ul id="passkeys"></ul>
</section>
<script type="module" src="/app.js"></script>
</body></html>
HTML;

    return;
}
if ($method === 'GET' && $path === '/app.js') {
    header('Content-Type: text/javascript; charset=utf-8');
    readfile(__DIR__.'/app.js');

    return;
}

$pdo = new PDO('sqlite:'.$database);
foreach ([...Schema::statements('sqlite'), ...PdoRateLimiter::statements('sqlite')] as $statement) {
    $pdo->exec($statement);
}
$secretFile = $database.'.secret';
if (! is_file($secretFile)) {
    file_put_contents($secretFile, bin2hex(random_bytes(32)));
    chmod($secretFile, 0600);
}
// The emulator accepts custom tokens with any signature; keep one key per database so that a
// restarted PHP process keeps signing the same way (a real hub reads its service account file).
$verifier = IdTokenVerifier::forEmulator($project);

if ($path === '/session') {
    // A property backend: exchanges the ID token for its own session (step F6 of the design).
    session_name('example_session');
    session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax']);
    session_start();
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    if ($method === 'POST') {
        try {
            $header = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? '');
            $identity = $verifier->verify(preg_replace('/^Bearer\s+/', '', $header) ?? '');
        } catch (FirebaseException $refusal) {
            http_response_code($refusal->httpStatus);
            echo json_encode($refusal->toArray());

            return;
        }
        session_regenerate_id(true);
        $_SESSION['uid'] = $identity->uid;
        $_SESSION['method'] = $identity->method();
        $_SESSION['mfa'] = $identity->isMultiFactor();
    } elseif ($method === 'DELETE') {
        $_SESSION = [];
        session_destroy();
    }
    echo json_encode(['uid' => $_SESSION['uid'] ?? null, 'method' => $_SESSION['method'] ?? null, 'mfa' => $_SESSION['mfa'] ?? false]);

    return;
}

$challenges = new PdoChallengeStore($pdo);
$hub = new AuthHub(
    new FirebasePasskeys(
        new PasskeyServer(RelyingParty::forUrl($origin, 'Sign-in example'), new PdoCredentialStore($pdo), $challenges, (string) file_get_contents($secretFile)),
        new HandoffServer($challenges),
        new CustomTokenIssuer(ServiceAccount::forEmulator($project)),
        $verifier,
        AdminClient::forEmulator($project, $emulator),
    ),
    '/passkey',
    [$origin],
    new PdoRateLimiter($pdo),
);
$response = $hub->handle(HubRequest::fromGlobals());
if ($response === null) {
    http_response_code(404);
    echo 'Not found';

    return;
}
$response->send();
