<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\NativeClock;

/**
 * Admin operations on Firebase users through the Identity Toolkit REST API, authenticated as the
 * service account (OAuth 2.0 JWT bearer grant, RFC 7523). Used by the auth hub and by backends that
 * check revocation.
 */
final class AdminClient
{
    private const TOKEN_URL = 'https://oauth2.googleapis.com/token';

    private const SCOPES = 'https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/cloud-platform';

    private readonly ClockInterface $clock;

    private ?string $accessToken = null;

    private int $accessTokenExpiresAt = 0;

    private function __construct(
        private readonly string $projectId,
        private readonly ?ServiceAccount $account,
        private readonly string $baseUrl,
        private readonly HttpClient $http,
        ?ClockInterface $clock,
    ) {
        $this->clock = $clock ?? new NativeClock;
    }

    public static function forServiceAccount(ServiceAccount $account, HttpClient $http = new CurlHttpClient, ?ClockInterface $clock = null): self
    {
        return new self($account->projectId, $account, 'https://identitytoolkit.googleapis.com', $http, $clock);
    }

    /**
     * For the Firebase Auth emulator (`host:port`), which accepts the fixed bearer `owner` for admin
     * calls. Only for `demo-` projects.
     */
    public static function forEmulator(string $projectId, string $emulatorHost, HttpClient $http = new CurlHttpClient): self
    {
        if (! ProjectId::isDemo($projectId)) {
            throw new InvalidArgumentException('The emulator admin client is only allowed for a "demo-" project.');
        }
        if (preg_match('/^[A-Za-z0-9.-]+:\d{1,5}$/', $emulatorHost) !== 1) {
            throw new InvalidArgumentException('The emulator host must be host:port.');
        }

        return new self($projectId, null, 'http://'.$emulatorHost.'/identitytoolkit.googleapis.com', $http, null);
    }

    /**
     * The user record, or null when no such user exists.
     *
     * @return array{uid: string, email: ?string, disabled: bool, validSince: ?int}|null
     */
    public function lookup(string $uid): ?array
    {
        $answer = $this->call('accounts:lookup', ['localId' => [$uid]]);
        $users = $answer['users'] ?? null;
        if (! is_array($users) || $users === [] || ! is_array($users[0])) {
            return null;
        }
        $user = $users[0];
        $validSince = $user['validSince'] ?? null;

        return [
            'uid' => is_string($user['localId'] ?? null) ? $user['localId'] : $uid,
            'email' => is_string($user['email'] ?? null) ? $user['email'] : null,
            'disabled' => ($user['disabled'] ?? false) === true,
            'validSince' => is_numeric($validSince) ? (int) $validSince : null,
        ];
    }

    /**
     * True when the identity's tokens are still accepted: the user exists, is not disabled, and
     * signed in at or after the last revocation.
     */
    public function isActive(FirebaseIdentity $identity): bool
    {
        $user = $this->lookup($identity->uid);

        return $user !== null && ! $user['disabled'] && ($user['validSince'] === null || $identity->authTime >= $user['validSince']);
    }

    /** Ends every session: refresh tokens issued before now stop working. */
    public function revokeRefreshTokens(string $uid): void
    {
        $this->call('accounts:update', ['localId' => $uid, 'validSince' => (string) $this->clock->now()->getTimestamp()]);
    }

    public function setDisabled(string $uid, bool $disabled): void
    {
        $this->call('accounts:update', ['localId' => $uid, 'disableUser' => $disabled]);
    }

    public function delete(string $uid): void
    {
        $this->call('accounts:delete', ['localId' => $uid]);
    }

    /**
     * @param  array<string, mixed>  $body
     * @return array<string, mixed>
     */
    private function call(string $method, array $body): array
    {
        $url = $this->baseUrl.'/v1/projects/'.rawurlencode($this->projectId).'/'.$method;
        $response = $this->http->request('POST', $url, [
            'Authorization' => 'Bearer '.$this->accessToken(),
            'Content-Type' => 'application/json',
        ], json_encode($body, JSON_THROW_ON_ERROR));
        $data = json_decode($response->body, true);
        if ($response->status !== 200 || ! is_array($data)) {
            $code = is_array($data) && is_array($data['error'] ?? null) && is_string($data['error']['message'] ?? null)
                ? $data['error']['message'] : 'HTTP '.$response->status;
            if ($response->status >= 500) {
                throw FirebaseException::unavailable('Identity Toolkit, '.$code);
            }
            throw FirebaseException::adminRefused($code);
        }

        /** @var array<string, mixed> $data */
        return $data;
    }

    private function accessToken(): string
    {
        if ($this->account === null) {
            return 'owner';
        }
        $now = $this->clock->now()->getTimestamp();
        if ($this->accessToken !== null && $this->accessTokenExpiresAt - 60 > $now) {
            return $this->accessToken;
        }
        $assertion = $this->account->sign([
            'iss' => $this->account->clientEmail,
            'scope' => self::SCOPES,
            'aud' => self::TOKEN_URL,
            'iat' => $now,
            'exp' => $now + 3600,
        ]);
        $response = $this->http->request('POST', self::TOKEN_URL, ['Content-Type' => 'application/x-www-form-urlencoded'], http_build_query([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion' => $assertion,
        ]));
        $data = json_decode($response->body, true);
        if ($response->status !== 200 || ! is_array($data) || ! is_string($data['access_token'] ?? null)) {
            if ($response->status >= 500) {
                throw FirebaseException::unavailable('Google OAuth');
            }
            throw FirebaseException::configuration('Google refused the service account (OAuth HTTP '.$response->status.').');
        }
        $this->accessToken = $data['access_token'];
        $this->accessTokenExpiresAt = $now + (is_int($data['expires_in'] ?? null) ? $data['expires_in'] : 3600);

        return $this->accessToken;
    }
}
