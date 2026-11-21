<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

/**
 * A verified Firebase ID token: who signed in, how and when. Built only by {@see IdTokenVerifier}.
 */
final class FirebaseIdentity
{
    /** @param array<string, mixed> $claims All claims of the token. */
    public function __construct(
        public readonly string $uid,
        public readonly ?string $email,
        public readonly bool $emailVerified,
        public readonly ?string $name,
        public readonly ?string $picture,
        public readonly string $signInProvider,
        public readonly ?string $secondFactor,
        public readonly int $authTime,
        public readonly int $issuedAt,
        public readonly int $expiresAt,
        public readonly array $claims,
        private readonly int $now,
    ) {}

    /**
     * How the hub authenticated a custom-token sign-in (`passkey` or `handoff`), or null for a
     * Firebase method. Trusted only for `sign_in_provider = custom`, because only the holder of the
     * service account key can mint custom tokens.
     */
    public function loginMethod(): ?string
    {
        if ($this->signInProvider !== 'custom') {
            return null;
        }
        $method = $this->claims['login_method'] ?? null;

        return is_string($method) ? $method : null;
    }

    /**
     * The method behind the sign-in, the same vocabulary for every route: `passkey`, `password`,
     * `google.com`, `emailLink`, … For a desktop handoff, the method used in the browser.
     */
    public function method(): string
    {
        $login = $this->loginMethod();
        if ($login === 'passkey') {
            return 'passkey';
        }
        if ($login === 'handoff' && is_string($this->claims['login_via'] ?? null)) {
            return $this->claims['login_via'];
        }

        return $this->signInProvider;
    }

    /**
     * True when the sign-in proved more than one factor: a passkey (possession plus biometric or
     * PIN), Firebase multi-factor authentication, or a handoff from such a browser session.
     */
    public function isMultiFactor(): bool
    {
        if ($this->secondFactor !== null) {
            return true;
        }
        $login = $this->loginMethod();

        return $login === 'passkey' || ($login === 'handoff' && ($this->claims['login_mfa'] ?? false) === true);
    }

    /** True when the person signed in (not refreshed) at most this many seconds ago. */
    public function isRecent(int $seconds): bool
    {
        return $this->now - $this->authTime <= $seconds;
    }

    /** A display name for the passkey prompt: the email address, else the name, else the uid. */
    public function label(): string
    {
        return $this->email ?? $this->name ?? $this->uid;
    }
}
