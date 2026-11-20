<?php

declare(strict_types=1);

/*
 * Example: passkeys in a PHP application without a framework.
 *
 * Run it from the repository root:
 *   php -S localhost:8080 examples/plain-php/public/index.php
 *
 * The example has one deliberate simplification: "Create demo account" stands in for the sign-up
 * and password sign-in an existing application already has. Everything about passkeys is real.
 */

use Jw1980\Passkey\Handoff\HandoffServer;
use Jw1980\Passkey\PasskeyException;
use Jw1980\Passkey\PasskeyServer;
use Jw1980\Passkey\PasskeyUser;
use Jw1980\Passkey\RelyingParty;
use Jw1980\Passkey\Storage\PdoChallengeStore;
use Jw1980\Passkey\Storage\PdoCredentialStore;
use Jw1980\Passkey\Storage\Schema;
use Jw1980\Passkey\StoredPasskey;

require __DIR__.'/../../../packages/php/vendor/autoload.php';

$path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

// Static files of the example (the bundled client).
if ($method === 'GET' && $path === '/app.js') {
    header('Content-Type: text/javascript; charset=utf-8');
    readfile(__DIR__.'/app.js');

    return;
}

// --- Setup -------------------------------------------------------------------------------------

$origin = getenv('PASSKEY_EXAMPLE_ORIGIN') ?: 'http://localhost:8080';
$database = getenv('PASSKEY_EXAMPLE_DB') ?: sys_get_temp_dir().'/passkey-example.sqlite';
$secretFile = $database.'.secret';
if (! is_file($secretFile)) {
    file_put_contents($secretFile, bin2hex(random_bytes(32)));
    chmod($secretFile, 0600);
}

$pdo = new PDO('sqlite:'.$database);
foreach (Schema::statements('sqlite') as $statement) {
    $pdo->exec($statement);
}
$pdo->exec('CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)');

$challenges = new PdoChallengeStore($pdo);
$passkeys = new PasskeyServer(
    RelyingParty::forUrl($origin, 'Passkey example'),
    new PdoCredentialStore($pdo),
    $challenges,
    (string) file_get_contents($secretFile),
);
$handoff = new HandoffServer($challenges);

session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'secure' => str_starts_with($origin, 'https://')]);
session_name('passkey_example');
session_start();
$_SESSION['csrf'] ??= bin2hex(random_bytes(32));

// --- Helpers -----------------------------------------------------------------------------------

function respond(mixed $body, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    if ($status !== 204) {
        echo json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
    exit;
}

/** @return array<string, mixed> */
function body(): array
{
    $decoded = json_decode((string) file_get_contents('php://input'), true);

    return is_array($decoded) ? $decoded : [];
}

function account(PDO $pdo): ?PasskeyUser
{
    if (! isset($_SESSION['account'])) {
        return null;
    }
    $statement = $pdo->prepare('SELECT id, name FROM accounts WHERE id = ?');
    $statement->execute([$_SESSION['account']]);
    $row = $statement->fetch(PDO::FETCH_ASSOC);

    return is_array($row) ? new PasskeyUser((string) $row['id'], $row['name'], $row['name']) : null;
}

function signedIn(PDO $pdo): PasskeyUser
{
    return account($pdo) ?? respond(['error' => ['code' => 'unauthenticated', 'message' => 'Sign in first.']], 401);
}

// --- Routes ------------------------------------------------------------------------------------

try {
    if ($method === 'GET' && in_array($path, ['/', '/desktop-sign-in'], true)) {
        header('Content-Type: text/html; charset=utf-8');
        header("Content-Security-Policy: default-src 'self'; style-src 'unsafe-inline'");
        $csrf = htmlspecialchars($_SESSION['csrf'], ENT_QUOTES);
        echo <<<HTML
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
              <meta name="csrf-token" content="{$csrf}">
              <title>Passkey example</title>
              <style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}button{margin:.25rem .25rem .25rem 0;padding:.5rem .9rem}</style>
            </head>
            <body>
              <h1>Passkey example</h1>
              <p id="status" role="status" aria-live="polite"></p>
              <section id="guest" hidden>
                <button id="sign-in" type="button">Sign in with a passkey</button>
                <form id="demo"><label>Name <input id="demo-name" required maxlength="50" autocomplete="username webauthn"></label>
                <button>Create demo account</button></form>
              </section>
              <section id="member" hidden>
                <p>Signed in as <strong id="who"></strong></p>
                <button id="add" type="button">Add a passkey</button>
                <button id="sign-out" type="button">Sign out</button>
                <ul id="list"></ul>
              </section>
              <section id="handoff" hidden>
                <p>The desktop app asks to sign in as <strong id="handoff-who"></strong>.</p>
                <button id="approve" type="button">Allow</button>
                <button id="deny" type="button">Deny</button>
              </section>
              <script type="module" src="/app.js"></script>
            </body>
            </html>
            HTML;

        return;
    }

    // The desktop app has no cookie session, so its exchange needs no CSRF token.
    if ($method === 'POST' && $path === '/passkey/handoff/exchange') {
        $input = body();
        $grant = $handoff->exchange((string) ($input['code'] ?? ''), (string) ($input['code_verifier'] ?? ''));
        // A real application issues its desktop session here.
        respond(['account' => $grant->userId, 'name' => $grant->context['name'] ?? null]);
    }

    // Every other state-changing request must carry the session's CSRF token.
    if ($method !== 'GET' && ! hash_equals($_SESSION['csrf'], (string) ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ''))) {
        respond(['error' => ['code' => 'csrf', 'message' => 'The page has expired. Reload it.']], 419);
    }

    match ("{$method} {$path}") {
        'GET /api/me' => respond(['account' => ($user = account($pdo)) === null ? null : ['id' => $user->id, 'name' => $user->name]]),

        'POST /api/demo-account' => (function () use ($pdo): void {
            $name = trim((string) (body()['name'] ?? ''));
            if ($name === '' || mb_strlen($name) > 50) {
                respond(['error' => ['code' => 'invalid_request', 'message' => 'Enter a name of at most 50 characters.']], 422);
            }
            $pdo->prepare('INSERT INTO accounts (name) VALUES (?)')->execute([$name]);
            session_regenerate_id(true);
            $_SESSION['account'] = (int) $pdo->lastInsertId();
            respond(['ok' => true], 201);
        })(),

        'POST /api/sign-out' => (function (): void {
            unset($_SESSION['account']);
            session_regenerate_id(true);
            respond(['ok' => true]);
        })(),

        'POST /passkey/register/options' => respond($passkeys->beginRegistration(signedIn($pdo))->toArray()),

        'POST /passkey/register/verify' => (function () use ($passkeys, $pdo): void {
            $input = body();
            $passkey = $passkeys->finishRegistration(
                (string) ($input['ceremony'] ?? ''),
                is_array($input['credential'] ?? null) ? $input['credential'] : [],
                signedIn($pdo),
                isset($input['name']) ? (string) $input['name'] : null,
            );
            respond(['passkey' => $passkey->toSummary()], 201);
        })(),

        'POST /passkey/login/options' => respond($passkeys->beginAuthentication(account($pdo)?->id)->toArray()),

        'POST /passkey/login/verify' => (function () use ($passkeys): void {
            $input = body();
            $result = $passkeys->finishAuthentication(
                (string) ($input['ceremony'] ?? ''),
                is_array($input['credential'] ?? null) ? $input['credential'] : [],
            );
            session_regenerate_id(true);
            $_SESSION['account'] = (int) $result->userId;
            respond(['ok' => true]);
        })(),

        'GET /passkey/passkeys' => respond(['passkeys' => array_map(
            static fn (StoredPasskey $passkey): array => $passkey->toSummary(),
            $passkeys->passkeys(signedIn($pdo)->id),
        )]),

        'POST /passkey/handoff/authorize' => (function () use ($handoff, $pdo): void {
            $input = body();
            $user = signedIn($pdo);
            respond(['redirect' => $handoff->authorize(
                $user->id,
                (string) ($input['challenge'] ?? ''),
                is_int($input['port'] ?? null) ? $input['port'] : 0,
                (string) ($input['state'] ?? ''),
                ['name' => $user->name],
            )]);
        })(),

        default => (function () use ($method, $path, $passkeys, $pdo): void {
            if (preg_match('#^/passkey/passkeys/([A-Za-z0-9_-]+)$#', $path, $match) === 1) {
                if ($method === 'PATCH') {
                    respond(['passkey' => $passkeys->rename(signedIn($pdo)->id, $match[1], (string) (body()['name'] ?? ''))->toSummary()]);
                }
                if ($method === 'DELETE') {
                    $passkeys->delete(signedIn($pdo)->id, $match[1]);
                    respond(null, 204);
                }
            }
            respond(['error' => ['code' => 'not_found', 'message' => 'No such page.']], 404);
        })(),
    };
} catch (PasskeyException $refusal) {
    // The underlying reason goes to the server log, never to the client.
    error_log('passkey refused: '.$refusal->errorCode.' '.($refusal->getPrevious()?->getMessage() ?? ''));
    respond($refusal->toArray(), $refusal->httpStatus);
}
