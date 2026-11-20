<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Handoff;

use InvalidArgumentException;
use Jw1980\Passkey\Base64Url;
use Jw1980\Passkey\Contracts\ChallengeStore;
use Jw1980\Passkey\PasskeyException;

/**
 * Server side of the desktop sign-in handoff (RFC 8252 with PKCE, RFC 7636).
 *
 * A desktop app cannot use a passkey in its own webview: the passkey belongs to the web domain.
 * So the app opens the system browser on a page of that domain. There the person signs in with the
 * passkey and approves; the page calls {@see authorize()} and sends the browser to the loopback
 * address of the app with a single-use code. The app redeems the code with {@see exchange()}.
 *
 * - The code goes only to `http://127.0.0.1:<port><callbackPath>`. The server builds that address
 *   itself; a caller cannot supply a redirect address.
 * - The code is bound to the app's PKCE challenge: without the verifier, which never leaves the
 *   app, an intercepted code is worthless.
 * - The code is single-use (also after a failed exchange) and short-lived.
 */
final class HandoffServer
{
    private const TOKEN = '/^[A-Za-z0-9_-]{43}$/';

    public function __construct(
        private readonly ChallengeStore $codes,
        private readonly string $callbackPath = '/callback',
        private readonly int $codeTtlSeconds = 60,
    ) {
        if (preg_match('#^/[A-Za-z0-9/_-]*$#', $callbackPath) !== 1) {
            throw new InvalidArgumentException('The callback path must start with "/" and hold only letters, digits, "/", "_" and "-".');
        }
        if ($codeTtlSeconds < 10 || $codeTtlSeconds > 600) {
            throw new InvalidArgumentException('The code lifetime must be 10 to 600 seconds.');
        }
    }

    /**
     * Issues a code for the signed-in account and returns the loopback address to send the browser
     * to. Call this only after the person approved on a page that showed what they approve.
     *
     * @param  string  $challenge  The app's PKCE S256 challenge (43 base64url characters).
     * @param  array<string, mixed>  $context  Handed back by {@see exchange()}, for example the
     *                                         assurance level of the browser session.
     */
    public function authorize(string $userId, string $challenge, int $port, string $state, array $context = []): string
    {
        if ($userId === '' || preg_match(self::TOKEN, $challenge) !== 1 || preg_match(self::TOKEN, $state) !== 1
            || $port < 1024 || $port > 65535) {
            throw PasskeyException::invalidRequest('The sign-in handoff request is not valid.');
        }
        $code = Base64Url::encode(random_bytes(32));
        $this->codes->put(
            self::key($code),
            json_encode(['purpose' => 'handoff', 'userId' => $userId, 'challenge' => $challenge, 'context' => $context], JSON_THROW_ON_ERROR),
            $this->codeTtlSeconds,
        );

        return "http://127.0.0.1:{$port}{$this->callbackPath}?code={$code}&state={$state}";
    }

    /** Redeems a code. Every failure gives the same refusal, and the code is spent either way. */
    public function exchange(string $code, string $codeVerifier): HandoffGrant
    {
        // RFC 7636 §4.1: 43 to 128 unreserved characters.
        if (preg_match(self::TOKEN, $code) !== 1 || preg_match('/^[A-Za-z0-9._~-]{43,128}$/', $codeVerifier) !== 1) {
            throw PasskeyException::invalidHandoff();
        }
        $payload = $this->codes->pull(self::key($code));
        $state = $payload === null ? null : json_decode($payload, true);
        if (! is_array($state) || ($state['purpose'] ?? null) !== 'handoff'
            || ! is_string($state['userId'] ?? null) || ! is_string($state['challenge'] ?? null)) {
            throw PasskeyException::invalidHandoff();
        }
        $expected = Base64Url::encode(hash('sha256', $codeVerifier, true));
        if (! hash_equals($state['challenge'], $expected)) {
            throw PasskeyException::invalidHandoff();
        }
        /** @var array<string, mixed> $context */
        $context = is_array($state['context'] ?? null) ? $state['context'] : [];

        return new HandoffGrant($state['userId'], $context);
    }

    private static function key(string $code): string
    {
        return 'handoff:'.hash('sha256', $code);
    }
}
