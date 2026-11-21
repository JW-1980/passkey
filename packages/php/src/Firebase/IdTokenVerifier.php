<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\NativeClock;

/**
 * Verifies Firebase ID tokens locally, following Firebase's "Verify ID tokens using a third-party
 * JWT library": RS256 with a current Google key, `iss` = `https://securetoken.google.com/<project>`,
 * `aud` = `<project>`, `exp` in the future, `iat` and `auth_time` in the past, `sub` 1–128
 * characters. A clock skew of 60 seconds is allowed.
 *
 * Revocation is not checked here (it needs a call to Google); see {@see AdminClient::validSince()}.
 */
final class IdTokenVerifier
{
    private const SKEW = 60;

    private readonly ClockInterface $clock;

    private function __construct(
        private readonly string $projectId,
        private readonly ?KeySource $keys,
        ?ClockInterface $clock,
    ) {
        $this->clock = $clock ?? new NativeClock;
    }

    public static function forProject(string $projectId, KeySource $keys = new GoogleKeySource, ?ClockInterface $clock = null): self
    {
        if (! ProjectId::isValid($projectId)) {
            throw new InvalidArgumentException('Not a valid Firebase project ID.');
        }

        return new self($projectId, $keys, $clock);
    }

    /**
     * For the Firebase Auth emulator, which issues **unsigned** tokens. Allowed only for `demo-`
     * projects: such a project cannot exist outside the emulator, so a production configuration can
     * never accept unsigned tokens by mistake.
     */
    public static function forEmulator(string $projectId, ?ClockInterface $clock = null): self
    {
        if (! ProjectId::isDemo($projectId)) {
            throw new InvalidArgumentException('The emulator verifier is only allowed for a "demo-" project.');
        }

        return new self($projectId, null, $clock);
    }

    public function projectId(): string
    {
        return $this->projectId;
    }

    /** @throws FirebaseException `unauthenticated` for every refusal, `unavailable` without keys */
    public function verify(string $idToken): FirebaseIdentity
    {
        $jwt = Jwt::decode($idToken);
        $header = $jwt['header'];
        $claims = $jwt['payload'];

        if ($this->keys === null) {
            // The emulator signs nothing; there is no signature to check.
            if (($header['alg'] ?? null) !== 'none') {
                throw FirebaseException::invalidToken('emulator tokens are unsigned');
            }
        } else {
            if (($header['alg'] ?? null) !== 'RS256') {
                throw FirebaseException::invalidToken('alg is not RS256');
            }
            $kid = $header['kid'] ?? null;
            if (! is_string($kid) || $kid === '') {
                throw FirebaseException::invalidToken('no kid');
            }
            $pem = $this->keys->key($kid);
            if ($pem === null) {
                throw FirebaseException::invalidToken('unknown kid');
            }
            if (! Jwt::verifyRs256($jwt['input'], $jwt['signature'], $pem)) {
                throw FirebaseException::invalidToken('bad signature');
            }
        }

        $now = $this->clock->now()->getTimestamp();
        $exp = self::int($claims, 'exp');
        $iat = self::int($claims, 'iat');
        $authTime = self::int($claims, 'auth_time');
        $sub = $claims['sub'] ?? null;

        if (($claims['iss'] ?? null) !== 'https://securetoken.google.com/'.$this->projectId) {
            throw FirebaseException::invalidToken('wrong iss');
        }
        if (($claims['aud'] ?? null) !== $this->projectId) {
            throw FirebaseException::invalidToken('wrong aud');
        }
        if ($exp + self::SKEW <= $now) {
            throw FirebaseException::invalidToken('expired');
        }
        if ($iat - self::SKEW > $now || $authTime - self::SKEW > $now || $authTime > $iat + self::SKEW) {
            throw FirebaseException::invalidToken('issued in the future');
        }
        if (! is_string($sub) || $sub === '' || strlen($sub) > 128) {
            throw FirebaseException::invalidToken('bad sub');
        }
        if (isset($claims['user_id']) && $claims['user_id'] !== $sub) {
            throw FirebaseException::invalidToken('user_id differs from sub');
        }

        $firebase = is_array($claims['firebase'] ?? null) ? $claims['firebase'] : [];
        $provider = $firebase['sign_in_provider'] ?? null;
        if (! is_string($provider) || $provider === '') {
            throw FirebaseException::invalidToken('no sign_in_provider');
        }
        $secondFactor = $firebase['sign_in_second_factor'] ?? null;

        return new FirebaseIdentity(
            $sub,
            is_string($claims['email'] ?? null) ? $claims['email'] : null,
            ($claims['email_verified'] ?? false) === true,
            is_string($claims['name'] ?? null) ? $claims['name'] : null,
            is_string($claims['picture'] ?? null) ? $claims['picture'] : null,
            $provider,
            is_string($secondFactor) && $secondFactor !== '' ? $secondFactor : null,
            $authTime,
            $iat,
            $exp,
            $claims,
            $now,
        );
    }

    /** @param array<string, mixed> $claims */
    private static function int(array $claims, string $name): int
    {
        $value = $claims[$name] ?? null;
        if (! is_int($value)) {
            throw FirebaseException::invalidToken("{$name} is not an integer");
        }

        return $value;
    }
}
