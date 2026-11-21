<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\NativeClock;

/**
 * Mints Firebase custom tokens: a JWT signed by the service account that a client exchanges at
 * Firebase (`signInWithCustomToken`) for an ID token of the named user.
 *
 * Format (Firebase "Create custom tokens using a third-party JWT library"): RS256; `iss` and `sub`
 * the service account email; `aud` the Identity Toolkit audience; `iat`; `exp` at most one hour
 * later; `uid` 1 to 128 characters; optional `claims`, which end up in the ID token.
 */
final class CustomTokenIssuer
{
    public const AUDIENCE = 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit';

    /** Claim names Firebase reserves (they may not appear in `claims`). */
    private const RESERVED = [
        'acr', 'amr', 'at_hash', 'aud', 'auth_time', 'azp', 'cnf', 'c_hash', 'exp', 'firebase', 'iat',
        'iss', 'jti', 'nbf', 'nonce', 'sub',
    ];

    private readonly ClockInterface $clock;

    public function __construct(
        private readonly ServiceAccount $account,
        private readonly int $ttlSeconds = 300,
        ?ClockInterface $clock = null,
    ) {
        if ($ttlSeconds < 60 || $ttlSeconds > 3600) {
            throw new InvalidArgumentException('A custom token lives 60 to 3600 seconds.');
        }
        $this->clock = $clock ?? new NativeClock;
    }

    public function ttlSeconds(): int
    {
        return $this->ttlSeconds;
    }

    public function projectId(): string
    {
        return $this->account->projectId;
    }

    /**
     * @param  array<string, scalar|list<scalar>>  $claims  Developer claims for the ID token.
     */
    public function issue(string $uid, array $claims = []): string
    {
        if ($uid === '' || strlen($uid) > 128) {
            throw new InvalidArgumentException('A Firebase uid is 1 to 128 characters.');
        }
        foreach (array_keys($claims) as $name) {
            if (in_array($name, self::RESERVED, true)) {
                throw new InvalidArgumentException("The claim '{$name}' is reserved by Firebase.");
            }
        }
        $now = $this->clock->now()->getTimestamp();
        $payload = [
            'iss' => $this->account->clientEmail,
            'sub' => $this->account->clientEmail,
            'aud' => self::AUDIENCE,
            'iat' => $now,
            'exp' => $now + $this->ttlSeconds,
            'uid' => $uid,
        ];
        if ($claims !== []) {
            if (strlen(json_encode($claims, JSON_THROW_ON_ERROR)) > 1000) {
                throw new InvalidArgumentException('Developer claims may be at most 1000 bytes.');
            }
            $payload['claims'] = $claims;
        }

        return $this->account->sign($payload);
    }
}
