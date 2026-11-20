<?php

declare(strict_types=1);

namespace Jw1980\Passkey;

/** A verified sign-in: which account, and with which passkey (already updated in the store). */
final class AuthenticationResult
{
    public function __construct(
        public readonly string $userId,
        public readonly StoredPasskey $passkey,
    ) {}
}
